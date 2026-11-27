//! Phase A of the DLC batcher on Bitcoin Core 31.1 regtest: eight collateral accounts settled in
//! one transaction from real venue V3 batches.
//!
//! 1. The venue batches (`artifacts/venue_batches.json`, from `ops/venue-bench/dlc_batch/fills.mjs`)
//!    are converted to the relation's `Batch`es (each digest checked against `shz_dex`).
//! 2. One funding transaction creates the eight accounts (`account_output`: settle leaf
//!    `<T_i> CHECKSIGVERIFY <B> CHECKSIG`, refund leaf `<h> CLTV DROP <T_i> CHECKSIG`, NUMS internal
//!    key) and the operator's liquidity output. `T_i` is the account's venue owner key.
//! 3. The settlement spends all eight accounts and the liquidity: output `i` pays account `i`
//!    `collateral + sum(net)`, output 8 is `OP_RETURN SHZB || manifest_hash`, output 9 is the
//!    operator's change. Each trader signs its own input with SIGHASH_SINGLE|ANYONECANPAY (input `i`
//!    with output `i`); the batcher signs every account input with SIGHASH_DEFAULT; the operator
//!    signs its liquidity input.
//! 4. Checked on Core: account 0's refund is `non-final` before its height and accepted at it; a
//!    settlement that moves one sat from account 3's payout to the operator is refused (account 3's
//!    signature covers its output); the honest settlement is accepted and mined; the refund is then
//!    refused (input spent). The relation (`check_settlement`) accepts the settlement and rejects
//!    the tampered one.
//!
//! The node's datadir is kept (`LIGHTNINGER_DLC_BATCH_DATADIR`, default
//! `D:/shz/tmp/dlc-batch/regtest-node`) so phase B (`dlc-batcher claim-graph`) runs on the same chain.
//!
//! Run: `LIGHTNINGER_BITCOIND=<bitcoind.exe> cargo test --release --test core_batch -- --ignored --nocapture`
use lightninger_bitvm3_clearing::tapsighash_step::Tx;
use lightninger_dlc_batch_relation as rel;
use lightninger_dlc_batcher::*;
use m17_nova_script::sigcheck::flags as mf;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const FLAGS: u32 = mf::P2SH | mf::DERSIG | mf::CHECKLOCKTIMEVERIFY | mf::CHECKSEQUENCEVERIFY | mf::WITNESS | mf::NULLDUMMY | mf::TAPROOT;
const COLLATERAL: u64 = 20_000;
const LIQUIDITY: u64 = 100_000;
const FEE_RATE: u64 = 2;
/// Regtest-only keys of the batcher (settle co-signer) and the operator (liquidity, claimant).
const BATCHER_SK: [u8; 32] = [0xb1; 32];
const OPERATOR_SK: [u8; 32] = [0x0b; 32];

fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts")
}

fn keys() -> Vec<[u8; 32]> {
    let p = std::env::var("LIGHTNINGER_DLC_BATCH_KEYS").unwrap_or_else(|_| "D:/shz/tmp/dlc-batch/keys.json".into());
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap();
    v["accounts"].as_array().unwrap().iter().map(|k| hex::decode(k.as_str().unwrap()).unwrap().try_into().unwrap()).collect()
}

const REGTEST: SettleKeys = SettleKeys { collateral: COLLATERAL, liquidity: LIQUIDITY, batcher_sk: BATCHER_SK, operator_sk: OPERATOR_SK };

#[test]
#[ignore = "needs LIGHTNINGER_BITCOIND (Bitcoin Core 31.1 bitcoind) and the venue keys file"]
fn eight_accounts_settle_in_one_transaction() {
    let venue: Value = serde_json::from_str(&std::fs::read_to_string(artifacts().join("venue_batches.json")).expect("run ops/venue-bench/dlc_batch/fills.mjs")).unwrap();
    let batches = venue_batches(&venue).unwrap();
    let ks = keys();
    let traders: Vec<[u8; 32]> = ks.clone();
    let owners: Vec<[u8; 32]> = traders.iter().map(xonly).collect();
    for (i, a) in venue["accounts"].as_array().unwrap().iter().enumerate() {
        assert_eq!(a["owner"].as_str().unwrap(), hex::encode(owners[i]), "account {i}: keys file differs from the venue owner");
    }
    let datadir = PathBuf::from(std::env::var("LIGHTNINGER_DLC_BATCH_DATADIR").unwrap_or_else(|_| "D:/shz/tmp/dlc-batch/regtest-node".into()));
    let _ = std::fs::remove_dir_all(&datadir);
    let node = Node::regtest(&PathBuf::from(std::env::var("LIGHTNINGER_BITCOIND").expect("LIGHTNINGER_BITCOIND")), &datadir);
    let version = node.json(&["getnetworkinfo"])["subversion"].as_str().unwrap().to_string();
    node.cli(&["createwallet", "w"]);
    let sink = node.cli(&["getnewaddress", "", "bech32m"]);
    node.cli(&["generatetoaddress", "110", &sink]);
    let b_x = xonly(&BATCHER_SK);
    let refund_h = node.height() + 30;
    let acct_outs: Vec<TapOutput> = owners.iter().map(|t| account_output(t, &b_x, refund_h)).collect();
    let liq_out = key_output(&xonly(&OPERATOR_SK));

    // 2. funding: eight accounts and the operator's liquidity
    let mut outs = serde_json::Map::new();
    for o in &acct_outs {
        outs.insert(address(&node, &o.output_key), json!(format!("{:.8}", COLLATERAL as f64 / 1e8)));
    }
    outs.insert(address(&node, &liq_out.output_key), json!(format!("{:.8}", LIQUIDITY as f64 / 1e8)));
    let raw = node.cli(&["createrawtransaction", "[]", &Value::Object(outs).to_string()]);
    let funded = node.json(&["fundrawtransaction", &raw, r#"{"fee_rate": 2}"#]);
    let signed = node.json(&["signrawtransactionwithwallet", funded["hex"].as_str().unwrap()]);
    let funding_hex = signed["hex"].as_str().unwrap().to_string();
    let funding_txid = node.cli(&["sendrawtransaction", &funding_hex]);
    node.cli(&["generatetoaddress", "1", &sink]);
    let fd = node.json(&["getrawtransaction", &funding_txid, "true"]);
    let vout_of = |spk: &[u8]| fd["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == hex::encode(spk).as_str()).unwrap()["n"].as_u64().unwrap() as u32;
    let accts: Vec<(TapOutput, String, u32)> = acct_outs.iter().map(|o| (o.clone(), funding_txid.clone(), vout_of(&o.spk()))).collect();
    let liq = (liq_out.clone(), funding_txid.clone(), vout_of(&liq_out.spk()));
    eprintln!("funding {funding_txid}: 8 accounts x {COLLATERAL} + liquidity {LIQUIDITY}; refund height {refund_h}");

    // manifest and payouts
    let payout_outs: Vec<TapOutput> = owners.iter().map(key_output).collect();
    let manifest = rel::Manifest {
        network_code: 0,
        event_id: maturity_event(venue["status_after"]["mark"]["slot_us"].as_u64().unwrap()),
        epoch_id: batches.last().unwrap().seq,
        batcher: b_x,
        accounts: (0..8)
            .map(|i| {
                let ch = &venue["accounts"][i]["outpoint"];
                rel::Account {
                    channel_txid: hex::decode(ch["txid"].as_str().unwrap()).unwrap().try_into().unwrap(),
                    channel_vout: ch["vout"].as_u64().unwrap() as u32,
                    owner: owners[i],
                    outpoint_txid: hex::decode(&accts[i].1).unwrap().try_into().unwrap(),
                    outpoint_vout: accts[i].2,
                    collateral: COLLATERAL,
                    account_spk: accts[i].0.spk(),
                    payout_spk: payout_outs[i].spk(),
                }
            })
            .collect(),
        operator_txid: hex::decode(&liq.1).unwrap().try_into().unwrap(),
        operator_vout: liq.2,
        operator_amount: LIQUIDITY,
        operator_spk: liq.0.spk(),
    };
    let net = rel::net_per_account(&manifest, &batches).unwrap();
    let payouts: Vec<(u64, Vec<u8>)> = (0..8).map(|i| ((COLLATERAL as i64 + net[i]) as u64, payout_outs[i].spk())).collect();
    let marker = rel::marker_script(&manifest.hash());
    let change_spk = liq_out.spk();
    let total_pay: u64 = payouts.iter().map(|p| p.0).sum();
    let base_change = 8 * COLLATERAL + LIQUIDITY - total_pay;
    let draft = settlement(&REGTEST, &accts, &liq, &payouts, marker.clone(), base_change - 2000, &change_spk, &traders, None);
    let fee = FEE_RATE * vsize(&draft.tx);
    let change = base_change - fee;
    let honest = settlement(&REGTEST, &accts, &liq, &payouts, marker.clone(), change, &change_spk, &traders, None);
    let s_raw = serialize_signed(&honest.tx);
    let settled = rel::check_settlement(&s_raw, &manifest, &batches).unwrap();
    assert_eq!(settled.txid, honest.tx.txid());
    eprintln!("settlement {}: {} vB, fee {fee}, net per account {:?}, operator fronted {}", hex::encode(settled.txid), vsize(&honest.tx), net, settled.fronted);

    // 4. refund before/at its height, tampered settlement, honest settlement
    let mut refund = Tx { version: 2, inputs: vec![input(&accts[0].1, accts[0].2, 0xffff_fffe)], outputs: vec![out(COLLATERAL - 400, payout_outs[0].spk())], locktime: refund_h, witness: vec![] };
    let (sr, _) = sign_leaf(&refund, &[COLLATERAL], &[accts[0].0.spk()], 0, &accts[0].0, 1, &traders[0], 0);
    refund.witness = vec![vec![sr, accts[0].0.leaves[1].clone(), accts[0].0.control(1)]];
    let r_raw = serialize_signed(&refund);
    let r_early = node.accept(&[&r_raw]);
    assert_eq!(r_early[0]["allowed"], false);
    assert_eq!(r_early[0]["reject-reason"], "non-final", "{r_early}");
    let tampered = settlement(&REGTEST, &accts, &liq, &payouts, marker.clone(), change, &change_spk, &traders, Some((3, -1)));
    let t_raw = serialize_signed(&tampered.tx);
    let t_rel = rel::check_settlement(&t_raw, &manifest, &batches).unwrap_err();
    let t_core = node.accept(&[&t_raw]);
    assert_eq!(t_core[0]["allowed"], false, "{t_core}");
    eprintln!("tampered settlement (account 3 paid 1 sat less): Core {} / relation: {t_rel}", t_core[0]["reject-reason"]);
    let h_now = node.height();
    node.cli(&["generatetoaddress", &(refund_h - h_now).to_string(), &sink]);
    let r_at = node.accept(&[&r_raw]);
    assert_eq!(r_at[0]["allowed"], true, "refund at height {refund_h}: {r_at}");
    eprintln!("refund of account 0: non-final before {refund_h}, accepted at it (not broadcast)");
    let s_acc = node.accept(&[&s_raw]);
    assert_eq!(s_acc[0]["allowed"], true, "{s_acc}");
    let s_txid = node.cli(&["sendrawtransaction", &hex::encode(&s_raw)]);
    node.cli(&["generatetoaddress", "1", &sink]);
    let s_height = node.height();
    let r_after = node.accept(&[&r_raw]);
    assert_eq!(r_after[0]["allowed"], false);
    eprintln!("settlement {s_txid} mined at {s_height}; refund now refused ({})", r_after[0]["reject-reason"]);

    let dir = artifacts().join("regtest");
    std::fs::create_dir_all(&dir).unwrap();
    let mut amounts = vec![COLLATERAL; 8];
    amounts.push(LIQUIDITY);
    let mut spks: Vec<String> = accts.iter().map(|a| hex::encode(a.0.spk())).collect();
    spks.push(hex::encode(liq.0.spk()));
    std::fs::write(
        dir.join("txs.json"),
        serde_json::to_string_pretty(&json!([{"label": "settlement", "signed_hex": hex::encode(&s_raw), "amounts": amounts, "spks": spks, "slots": honest.slots, "m17_flags": FLAGS,
            "how_validated": format!("{version}: testmempoolaccept allowed, sendrawtransaction, mined at {s_height}")}]))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    std::fs::write(dir.join("batches.json"), serde_json::to_string_pretty(&batches).unwrap()).unwrap();
    std::fs::write(
        dir.join("receipt.json"),
        serde_json::to_string_pretty(&json!({
            "node": version, "datadir": datadir.display().to_string().replace('\\', "/"),
            "funding": {"txid": funding_txid, "hex": funding_hex},
            "accounts": (0..8).map(|i| json!({"index": i, "owner": hex::encode(owners[i]), "outpoint": format!("{}:{}", accts[i].1, accts[i].2), "collateral": COLLATERAL,
                "net": net[i], "payout": payouts[i].0, "leaves": accts[i].0.leaves.iter().map(hex::encode).collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "batcher_xonly": hex::encode(b_x), "operator_xonly": hex::encode(xonly(&OPERATOR_SK)),
            "liquidity": format!("{}:{}", liq.1, liq.2), "refund_height": refund_h,
            "tampered_settlement_hex": hex::encode(&t_raw),
            "manifest_hash": hex::encode(manifest.hash()), "event_id": manifest.event_id, "epoch_id": manifest.epoch_id,
            "settlement": {"txid": s_txid, "vsize": vsize(&honest.tx), "fee": fee, "height": s_height, "operator_change": change, "fronted": settled.fronted,
                "inputs": 9, "outputs": honest.tx.outputs.len(), "signatures": honest.slots.len()},
            "checks": {
                "refund_before_height": r_early[0], "refund_at_height": r_at[0], "refund_after_settlement": r_after[0],
                "tampered_settlement_core": t_core[0], "tampered_settlement_relation": t_rel,
                "settlement_testmempoolaccept": s_acc[0],
            },
        }))
        .unwrap(),
    )
    .unwrap();
    eprintln!("wrote {}", dir.display());
}

/// The same epoch on testnet4 with small amounts: funding from a wallet of an existing node, the
/// eight accounts, the settlement, the refund and the tampered settlement, all signed; checked with
/// package `testmempoolaccept` (funding first) and **not broadcast**. Batcher and operator keys are
/// derived from the venue keys file (outside the repo).
///
/// Run: `LIGHTNINGER_TESTNET4_ARGS="-datadir=C:\BitcoinTestnet -rpcwallet=<funded wallet>" cargo test
/// --release --test core_batch testnet4 -- --ignored --nocapture`
#[test]
#[ignore = "needs a synced testnet4 node and a funded wallet (LIGHTNINGER_TESTNET4_ARGS)"]
fn testnet4_package_signed_not_broadcast() {
    let venue: Value = serde_json::from_str(&std::fs::read_to_string(artifacts().join("venue_batches.json")).unwrap()).unwrap();
    let batches = venue_batches(&venue).unwrap();
    let traders = keys();
    let owners: Vec<[u8; 32]> = traders.iter().map(xonly).collect();
    let derive = |label: &[u8]| rel::tagged_hash(label, &traders.concat());
    let p = SettleKeys { collateral: 1_000, liquidity: 2_000, batcher_sk: derive(b"LIGHTNINGER/DLC-BATCH/TESTNET4/BATCHER"), operator_sk: derive(b"LIGHTNINGER/DLC-BATCH/TESTNET4/OPERATOR") };
    let cli = PathBuf::from(std::env::var("LIGHTNINGER_TESTNET4_CLI").unwrap_or_else(|_| "C:/Users/patri/bitcoin-core-31.1/bin/bitcoin-cli.exe".into()));
    let args: Vec<String> = std::env::var("LIGHTNINGER_TESTNET4_ARGS").expect("LIGHTNINGER_TESTNET4_ARGS").split_whitespace().map(String::from).collect();
    let node = Node::existing(cli, args);
    let info = node.json(&["getblockchaininfo"]);
    assert_eq!(info["chain"], "testnet4");
    let tip = node.height();
    let b_x = xonly(&p.batcher_sk);
    let refund_h = tip + 432;
    let acct_outs: Vec<TapOutput> = owners.iter().map(|t| account_output(t, &b_x, refund_h)).collect();
    let liq_out = key_output(&xonly(&p.operator_sk));
    let mut outs = serde_json::Map::new();
    for o in &acct_outs {
        outs.insert(address(&node, &o.output_key), json!(format!("{:.8}", p.collateral as f64 / 1e8)));
    }
    outs.insert(address(&node, &liq_out.output_key), json!(format!("{:.8}", p.liquidity as f64 / 1e8)));
    let raw = node.cli(&["createrawtransaction", "[]", &Value::Object(outs).to_string()]);
    let funded = node.json(&["fundrawtransaction", &raw, r#"{"fee_rate": 1, "lockUnspents": false}"#]);
    let signed = node.json(&["signrawtransactionwithwallet", funded["hex"].as_str().unwrap()]);
    assert_eq!(signed["complete"], true);
    let funding_raw = hex::decode(signed["hex"].as_str().unwrap()).unwrap();
    let ftx = rel::parse_tx(&funding_raw).unwrap();
    let funding_txid = hex::encode(ftx.txid);
    let vout_of = |spk: &[u8]| ftx.outputs.iter().position(|o| o.1 == spk).unwrap() as u32;
    let accts: Vec<(TapOutput, String, u32)> = acct_outs.iter().map(|o| (o.clone(), funding_txid.clone(), vout_of(&o.spk()))).collect();
    let liq = (liq_out.clone(), funding_txid.clone(), vout_of(&liq_out.spk()));
    let payout_outs: Vec<TapOutput> = owners.iter().map(key_output).collect();
    let manifest = rel::Manifest {
        network_code: 1,
        event_id: maturity_event(venue["status_after"]["mark"]["slot_us"].as_u64().unwrap()),
        epoch_id: batches.last().unwrap().seq,
        batcher: b_x,
        accounts: (0..8)
            .map(|i| {
                let ch = &venue["accounts"][i]["outpoint"];
                rel::Account {
                    channel_txid: hex::decode(ch["txid"].as_str().unwrap()).unwrap().try_into().unwrap(),
                    channel_vout: ch["vout"].as_u64().unwrap() as u32,
                    owner: owners[i],
                    outpoint_txid: ftx.txid,
                    outpoint_vout: accts[i].2,
                    collateral: p.collateral,
                    account_spk: accts[i].0.spk(),
                    payout_spk: payout_outs[i].spk(),
                }
            })
            .collect(),
        operator_txid: ftx.txid,
        operator_vout: liq.2,
        operator_amount: p.liquidity,
        operator_spk: liq.0.spk(),
    };
    let net = rel::net_per_account(&manifest, &batches).unwrap();
    let payouts: Vec<(u64, Vec<u8>)> = (0..8).map(|i| ((p.collateral as i64 + net[i]) as u64, payout_outs[i].spk())).collect();
    let marker = rel::marker_script(&manifest.hash());
    let base_change = 8 * p.collateral + p.liquidity - payouts.iter().map(|x| x.0).sum::<u64>();
    let draft = settlement(&p, &accts, &liq, &payouts, marker.clone(), base_change - 1500, &liq_out.spk(), &traders, None);
    let fee = vsize(&draft.tx);
    let change = base_change - fee;
    let honest = settlement(&p, &accts, &liq, &payouts, marker.clone(), change, &liq_out.spk(), &traders, None);
    let s_raw = serialize_signed(&honest.tx);
    let settled = rel::check_settlement(&s_raw, &manifest, &batches).unwrap();
    let tampered = settlement(&p, &accts, &liq, &payouts, marker, change, &liq_out.spk(), &traders, Some((3, -1)));
    let t_raw = serialize_signed(&tampered.tx);
    let mut refund = Tx { version: 2, inputs: vec![input(&accts[0].1, accts[0].2, 0xffff_fffe)], outputs: vec![out(p.collateral - 200, payout_outs[0].spk())], locktime: refund_h, witness: vec![] };
    let (sr, _) = sign_leaf(&refund, &[p.collateral], &[accts[0].0.spk()], 0, &accts[0].0, 1, &traders[0], 0);
    refund.witness = vec![vec![sr, accts[0].0.leaves[1].clone(), accts[0].0.control(1)]];
    let r_raw = serialize_signed(&refund);
    let acc_s = node.accept(&[&funding_raw, &s_raw]);
    let acc_t = node.accept(&[&funding_raw, &t_raw]);
    let acc_r = node.accept(&[&funding_raw, &r_raw]);
    eprintln!("package [funding, settlement]: {acc_s}\npackage [funding, tampered]: {acc_t}\npackage [funding, refund]: {acc_r}");
    assert_eq!(acc_s[0]["allowed"], true, "{acc_s}");
    assert_eq!(acc_s[1]["allowed"], true, "{acc_s}");
    assert_eq!(acc_t[1]["allowed"], false);
    assert_eq!(acc_r[1]["reject-reason"], "non-final");
    let dir = artifacts().join("testnet4");
    std::fs::create_dir_all(&dir).unwrap();
    let mut amounts = vec![p.collateral; 8];
    amounts.push(p.liquidity);
    let mut spks: Vec<String> = accts.iter().map(|a| hex::encode(a.0.spk())).collect();
    spks.push(hex::encode(liq.0.spk()));
    std::fs::write(
        dir.join("txs.json"),
        serde_json::to_string_pretty(&json!([{"label": "settlement", "signed_hex": hex::encode(&s_raw), "amounts": amounts, "spks": spks, "slots": honest.slots, "m17_flags": FLAGS,
            "how_validated": format!("testnet4 tip {tip}: package testmempoolaccept [funding, settlement] allowed; not broadcast")}]))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    std::fs::write(dir.join("batches.json"), serde_json::to_string_pretty(&batches).unwrap()).unwrap();
    std::fs::write(
        dir.join("receipt.json"),
        serde_json::to_string_pretty(&json!({
            "tip": tip, "tip_hash": info["bestblockhash"], "refund_height": refund_h,
            "funding": {"txid": funding_txid, "hex": hex::encode(&funding_raw), "fee": funded["fee"]},
            "settlement": {"txid": hex::encode(settled.txid), "hex": hex::encode(&s_raw), "vsize": vsize(&honest.tx), "fee": fee, "operator_change": change, "fronted": settled.fronted, "payouts": settled.payouts},
            "refund_account0": {"txid": hex::encode(refund.txid()), "hex": hex::encode(&r_raw)},
            "tampered_settlement_hex": hex::encode(&t_raw),
            "testmempoolaccept": {"funding_settlement": acc_s, "funding_tampered": acc_t, "funding_refund": acc_r},
            "batcher_xonly": hex::encode(b_x), "operator_xonly": hex::encode(xonly(&p.operator_sk)), "manifest_hash": hex::encode(manifest.hash()),
            "broadcast": "not broadcast",
        }))
        .unwrap(),
    )
    .unwrap();
    eprintln!("wrote {}", dir.display());
}
