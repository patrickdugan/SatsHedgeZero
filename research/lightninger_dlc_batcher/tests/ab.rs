//! A/B: the DLC batch built two ways from the same venue batches (306..313) and the same oracle
//! event (`SHZ-BTCUSD-20261127T1345Z`, attested $61,346, CET 527 of the single-trade demo).
//!
//! - **A** — script leaf: accounts `<T> CHECKSIGVERIFY <B> CHECKSIG` + refund leaf; the CET funding
//!   output `<pk0> CHECKSIGVERIFY <pk1> CHECKSIG` + refund leaf. Each trader's signature is a BIP-340
//!   adaptor signature under the outcome's anticipation point, completed with the attestation
//!   scalar; the batcher signs plainly.
//! - **B** — MuSig2 key path: accounts and the CET funding output have internal key
//!   MuSig2(trader, batcher) / MuSig2(pk0, pk1) and keep the CLTV refund leaf; each account input and
//!   the CET carry one MuSig2 adaptor signature, completed with the same scalar.
//!
//! One funding transaction creates both variants' accounts, liquidity and CET outputs, so both are
//! checked against the same chain state. Measured: vsize of the funding, both settlements at N = 8
//! and N = 7 (per-input marginal), both CETs; signing rounds and bytes per CET and per settlement;
//! wall time to sign every one of the demo's 1,022 CETs in each variant (real anticipation points);
//! Core's verdicts. Regtest mines everything; testnet4 (`testnet4_ab`) only signs and runs package
//! `testmempoolaccept` from wallet `lt-dlc-batcher`, never broadcasting.
//!
//! Run: `LIGHTNINGER_BITCOIND=<bitcoind.exe> cargo test --release --test ab regtest_ab -- --ignored --nocapture`
//!      `LIGHTNINGER_TESTNET4_ARGS="-datadir=C:\BitcoinTestnet -rpcwallet=lt-dlc-batcher" cargo test --release --test ab testnet4_ab -- --ignored --nocapture`
use k256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar};
use lightninger_bitvm3_clearing::tapsighash_step::{tap_sighash_ext, ScriptPath, Tx};
use lightninger_dlc_batch_relation as rel;
use lightninger_dlc_batcher::*;
use m17_nova_script::sigcheck::flags as mf;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

const FLAGS: u32 = mf::P2SH | mf::DERSIG | mf::CHECKLOCKTIMEVERIFY | mf::CHECKSEQUENCEVERIFY | mf::WITNESS | mf::NULLDUMMY | mf::TAPROOT;
const CET_FUND: u64 = 3_254;
const CET_FEE: u64 = 300;
const ANCHOR: u64 = 330;

fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts")
}
fn demo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../lightninger_bitvm3_clearing/artifacts/testnet4_demo")
}
fn read(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}
fn keys() -> Vec<[u8; 32]> {
    let p = std::env::var("LIGHTNINGER_DLC_BATCH_KEYS").unwrap_or_else(|_| "D:/shz/tmp/dlc-batch/keys.json".into());
    read(Path::new(&p))["accounts"].as_array().unwrap().iter().map(|k| hex::decode(k.as_str().unwrap()).unwrap().try_into().unwrap()).collect()
}
fn point(hex33: &str) -> ProjectivePoint {
    shz_dlc::decode_point_compressed(&hex::decode(hex33).unwrap().try_into().unwrap()).unwrap()
}

/// The attested outcome (CET 527) and every CET's anticipation point and payouts.
fn oracle() -> (Oracle, Vec<(ProjectivePoint, u64, u64)>, Value) {
    let ev = read(&demo().join("oracle_event.json"));
    let cets = read(&demo().join("cets.json"));
    let idx = ev["matching_cet_index"].as_u64().unwrap() as usize;
    let scalar: [u8; 32] = hex::decode(ev["attestation_scalar_for_prefix"].as_str().unwrap()).unwrap().try_into().unwrap();
    let pt = point(cets["cets"][idx]["anticipation_point"].as_str().unwrap());
    let t = Option::<Scalar>::from(Scalar::from_repr(scalar.into())).unwrap();
    assert_eq!(ProjectivePoint::GENERATOR * t, pt, "attestation scalar opens CET {idx}'s anticipation point");
    let all = cets["cets"].as_array().unwrap().iter().map(|c| (point(c["anticipation_point"].as_str().unwrap()), c["alice_sats"].as_u64().unwrap(), c["bob_sats"].as_u64().unwrap())).collect();
    (Oracle { point: pt, scalar }, all, json!({"event_id": ev["event_id"], "attested_price_usd": ev["attested_price_usd"], "cet_index": idx, "cets": cets["cets"].as_array().unwrap().len()}))
}

fn cet_leaves(pk0: &[u8; 32], pk1: &[u8; 32], h: u32) -> (Vec<u8>, Vec<u8>) {
    let two = [push32(pk0), vec![OP_CHECKSIGVERIFY], push32(pk1), vec![OP_CHECKSIG]].concat();
    let refund = [num(h), vec![OP_CLTV, OP_DROP], push32(pk0), vec![OP_CHECKSIGVERIFY], push32(pk1), vec![OP_CHECKSIG]].concat();
    (two, refund)
}

struct Run {
    out: Value,
    a_dir: (Vec<u8>, Value, rel::Manifest),
    b_dir: (Vec<u8>, Value, rel::Manifest),
    batches: Vec<rel::Batch>,
}

/// Build (and on regtest broadcast) both variants. `fee_rate` sat/vB; `regtest` mines.
fn build(node: &Node, regtest: bool, keys_: &SettleKeys, sink: Option<&str>) -> Run {
    let venue = read(&artifacts().join("venue_batches.json"));
    let batches = venue_batches(&venue).unwrap();
    let traders = keys();
    let owners: Vec<[u8; 32]> = traders.iter().map(xonly).collect();
    let (orc, all_cets, ev) = oracle();
    let fee_rate: u64 = if regtest { 2 } else { 1 };
    let tip = node.height();
    let h = tip + if regtest { 30 } else { 432 };
    let b_x = xonly(&keys_.batcher_sk);
    let (b_pk, o_x) = (plain_pk(&keys_.batcher_sk), xonly(&keys_.operator_sk));
    // A outputs
    let a_accts: Vec<TapOutput> = owners.iter().map(|t| account_output(t, &b_x, h)).collect();
    let a_liq = key_output(&o_x);
    let (two, cref) = cet_leaves(&owners[0], &owners[1], h);
    let a_cet_fund = TapOutput::new(vec![two, cref.clone()]);
    // B outputs
    let b_accts: Vec<(TapOutput, Vec<[u8; 33]>)> = traders.iter().map(|sk| account_output_b(&plain_pk(sk), &b_pk, h)).collect();
    let b_liq = keypath_output(&o_x);
    let cet_pks = shz_dlc::musig2::key_sort(&[plain_pk(&traders[0]), plain_pk(&traders[1])]);
    let b_cet_fund = TapOutput::with_internal(shz_dlc::musig2::key_agg(&cet_pks).unwrap().xonly(), vec![cref]);
    // one funding transaction for both
    let mut outs = serde_json::Map::new();
    let btc = |s: u64| json!(format!("{:.8}", s as f64 / 1e8));
    for o in a_accts.iter().chain(b_accts.iter().map(|x| &x.0)) {
        outs.insert(address(node, &o.output_key), btc(keys_.collateral));
    }
    for o in [&a_liq, &b_liq] {
        outs.insert(address(node, &o.output_key), btc(keys_.liquidity));
    }
    for o in [&a_cet_fund, &b_cet_fund] {
        outs.insert(address(node, &o.output_key), btc(CET_FUND));
    }
    let raw = node.cli(&["createrawtransaction", "[]", &Value::Object(outs).to_string()]);
    let funded = node.json(&["fundrawtransaction", &raw, &json!({"fee_rate": fee_rate, "lockUnspents": false}).to_string()]);
    let signed = node.json(&["signrawtransactionwithwallet", funded["hex"].as_str().unwrap()]);
    assert_eq!(signed["complete"], true);
    let f_raw = hex::decode(signed["hex"].as_str().unwrap()).unwrap();
    let ftx = rel::parse_tx(&f_raw).unwrap();
    let fid = hex::encode(ftx.txid);
    let vout = |o: &TapOutput| ftx.outputs.iter().position(|x| x.1 == o.spk()).unwrap() as u32;
    if regtest {
        node.cli(&["sendrawtransaction", &hex::encode(&f_raw)]);
        node.cli(&["generatetoaddress", "1", sink.unwrap()]);
    }
    let fvs = Tx::parse(&f_raw);
    let funding_vsize = vsize(&fvs);

    let net = {
        let m = rel::Manifest {
            network_code: 0,
            event_id: String::new(),
            epoch_id: 0,
            batcher: b_x,
            accounts: (0..8)
                .map(|i| {
                    let ch = &venue["accounts"][i]["outpoint"];
                    rel::Account { channel_txid: hex::decode(ch["txid"].as_str().unwrap()).unwrap().try_into().unwrap(), channel_vout: ch["vout"].as_u64().unwrap() as u32, owner: owners[i], outpoint_txid: [0; 32], outpoint_vout: 0, collateral: 0, account_spk: vec![], payout_spk: vec![], carry_in: 0 }
                })
                .collect(),
            operator_txid: [0; 32],
            operator_vout: 0,
            operator_amount: 0,
            operator_spk: vec![],
            carried: vec![],
        };
        rel::net_per_account(&m, &batches).unwrap()
    };
    let manifest = |accts: &[TapOutput], liq: &TapOutput, payouts: &[TapOutput], net_code: u8| rel::Manifest {
        network_code: net_code,
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
                    outpoint_vout: vout(&accts[i]),
                    collateral: keys_.collateral,
                    account_spk: accts[i].spk(),
                    payout_spk: payouts[i].spk(),
                    carry_in: 0,
                }
            })
            .collect(),
        operator_txid: ftx.txid,
        operator_vout: vout(liq),
        operator_amount: keys_.liquidity,
        operator_spk: liq.spk(),
        carried: vec![],
    };
    let net_code = if regtest { 0 } else { 1 };
    let a_pay: Vec<TapOutput> = owners.iter().map(key_output).collect();
    let b_pay: Vec<TapOutput> = owners.iter().map(keypath_output).collect();
    let ma = manifest(&a_accts, &a_liq, &a_pay, net_code);
    let b_outs: Vec<TapOutput> = b_accts.iter().map(|x| x.0.clone()).collect();
    let mb = manifest(&b_outs, &b_liq, &b_pay, net_code);
    let payouts = |pay: &[TapOutput], n: usize| -> Vec<(u64, Vec<u8>)> { (0..n).map(|i| ((keys_.collateral as i64 + net[i]) as u64, pay[i].spk())).collect() };
    let a_in: Vec<(TapOutput, String, u32)> = a_accts.iter().map(|o| (o.clone(), fid.clone(), vout(o))).collect();
    let b_in: Vec<(TapOutput, String, u32, Vec<[u8; 33]>)> = b_accts.iter().map(|(o, p)| (o.clone(), fid.clone(), vout(o), p.clone())).collect();
    let a_l = (a_liq.clone(), fid.clone(), vout(&a_liq));
    let b_l = (b_liq.clone(), fid.clone(), vout(&b_liq));
    let change_of = |n: usize, pay: &[TapOutput]| n as u64 * keys_.collateral + keys_.liquidity - payouts(pay, n).iter().map(|x| x.0).sum::<u64>();
    // settle A / B at N = 8 (fee from a draft) and N = 7 (size only)
    let sa = |n: usize, change: u64, tamper| settlement_a(keys_, &a_in[..n], &a_l, &payouts(&a_pay, n), rel::marker_script(&ma.hash()), change, &a_liq.spk(), &traders[..n], Some(&orc), tamper);
    let sb = |n: usize, change: u64, tamper| settlement_b(keys_, &b_in[..n], &b_l, &payouts(&b_pay, n), rel::marker_script(&mb.hash()), change, &b_liq.spk(), &traders[..n], Some(&orc), tamper);
    let t = Instant::now();
    let a_draft = sa(8, change_of(8, &a_pay) - 3000, None);
    let a8 = sa(8, change_of(8, &a_pay) - fee_rate * vsize(&a_draft.tx), None);
    let a_sign_s = t.elapsed().as_secs_f64() / 2.0;
    let t = Instant::now();
    let b_draft = sb(8, change_of(8, &b_pay) - 3000, None);
    let b8 = sb(8, change_of(8, &b_pay) - fee_rate * vsize(&b_draft.tx), None);
    let b_sign_s = t.elapsed().as_secs_f64() / 2.0;
    let a7 = sa(7, change_of(7, &a_pay) - 3000, None);
    let b7 = sb(7, change_of(7, &b_pay) - 3000, None);
    let a_raw = serialize_signed(&a8.tx);
    let b_raw = serialize_signed(&b8.tx);
    let sta = rel::check_settlement(&a_raw, &ma, &batches).unwrap();
    let stb = rel::check_settlement(&b_raw, &mb, &batches).unwrap();
    assert_eq!(sta.payouts, stb.payouts);
    let a_tam = serialize_signed(&sa(8, a8.tx.outputs[9].value, Some((3, -1))).tx);
    let b_tam = serialize_signed(&sb(8, b8.tx.outputs[9].value, Some((3, -1))).tx);

    // CETs: the demo's payouts at the attested outcome (Bob 1,629, Alice 995, anchor 330, fee 300)
    let (alice_sats, bob_sats) = (995u64, 1_629u64);
    let cet_outs = |alice: u64, bob: u64| vec![out(bob, keypath_output(&owners[1]).spk()), out(alice, keypath_output(&owners[0]).spk()), out(ANCHOR, keypath_output(&b_x).spk())];
    let mk_cet = |fund: &TapOutput, alice: u64, bob: u64| Tx { version: 2, inputs: vec![input(&fid, vout(fund), 0xffff_fffd)], outputs: cet_outs(alice, bob), locktime: 0, witness: vec![] };
    assert_eq!(alice_sats + bob_sats + ANCHOR + CET_FEE, CET_FUND);
    let mut cet_a = mk_cet(&a_cet_fund, alice_sats, bob_sats);
    let (s0, _) = sign_leaf_oracle(&cet_a, &[CET_FUND], &[a_cet_fund.spk()], 0, &a_cet_fund, 0, &traders[0], 0, Some(&orc));
    let (s1, _) = sign_leaf_oracle(&cet_a, &[CET_FUND], &[a_cet_fund.spk()], 0, &a_cet_fund, 0, &traders[1], 0, Some(&orc));
    cet_a.witness = vec![vec![s1, s0, a_cet_fund.leaves[0].clone(), a_cet_fund.control(0)]];
    let mut cet_b = mk_cet(&b_cet_fund, alice_sats, bob_sats);
    let (sj, _) = sign_musig_keypath(&cet_b, &[CET_FUND], &[b_cet_fund.spk()], 0, &b_cet_fund, &cet_pks, &[traders[0], traders[1]], 0, Some(&orc));
    cet_b.witness = vec![vec![sj]];
    let (ca_raw, cb_raw) = (serialize_signed(&cet_a), serialize_signed(&cet_b));

    // refunds of account 0 (non-final before h)
    let mut ra = Tx { version: 2, inputs: vec![input(&fid, vout(&a_accts[0]), 0xffff_fffe)], outputs: vec![out(keys_.collateral - 300, a_pay[0].spk())], locktime: h, witness: vec![] };
    let (sr, _) = sign_leaf(&ra, &[keys_.collateral], &[a_accts[0].spk()], 0, &a_accts[0], 1, &traders[0], 0);
    ra.witness = vec![vec![sr, a_accts[0].leaves[1].clone(), a_accts[0].control(1)]];
    let mut rb = Tx { version: 2, inputs: vec![input(&fid, vout(&b_accts[0].0), 0xffff_fffe)], outputs: vec![out(keys_.collateral - 300, b_pay[0].spk())], locktime: h, witness: vec![] };
    let (srb, _) = sign_leaf(&rb, &[keys_.collateral], &[b_accts[0].0.spk()], 0, &b_accts[0].0, 0, &traders[0], 0);
    rb.witness = vec![vec![srb, b_accts[0].0.leaves[0].clone(), b_accts[0].0.control(0)]];

    // Core's verdicts
    let acc = |x: &[u8]| -> Value {
        let r = if regtest { node.accept(&[x]) } else { node.accept(&[&f_raw, x]) };
        r.as_array().unwrap().last().unwrap().clone()
    };
    let verdicts = json!({
        "settlement_A": acc(&a_raw), "settlement_B": acc(&b_raw), "cet_A": acc(&ca_raw), "cet_B": acc(&cb_raw),
        "tampered_settlement_A": acc(&a_tam), "tampered_settlement_B": acc(&b_tam),
        "refund_A_account0": acc(&serialize_signed(&ra)), "refund_B_account0": acc(&serialize_signed(&rb)),
    });
    for k in ["settlement_A", "settlement_B", "cet_A", "cet_B"] {
        assert_eq!(verdicts[k]["allowed"], true, "{k}: {}", verdicts[k]);
    }
    for k in ["tampered_settlement_A", "tampered_settlement_B"] {
        assert_eq!(verdicts[k]["allowed"], false, "{k}");
    }
    for k in ["refund_A_account0", "refund_B_account0"] {
        assert_eq!(verdicts[k]["reject-reason"], "non-final", "{k}: {}", verdicts[k]);
    }
    let mut mined = Value::Null;
    if regtest {
        let ids: Vec<String> = [&a_raw, &b_raw, &ca_raw, &cb_raw].iter().map(|x| node.cli(&["sendrawtransaction", &hex::encode(x)])).collect();
        node.cli(&["generatetoaddress", "1", sink.unwrap()]);
        let conf: Vec<u64> = ids.iter().map(|i| node.json(&["getrawtransaction", i, "true"])["confirmations"].as_u64().unwrap_or(0)).collect();
        assert!(conf.iter().all(|&c| c == 1));
        mined = json!({"height": node.height(), "txids": ids});
    }

    // signing every CET of the demo grid: A two adaptor signatures + two adaptor verifications;
    // B one MuSig2 adaptor session (2 nonces, aggregation, 2 partial signatures, 2 verifications, aggregate)
    let grid: Vec<(ProjectivePoint, [u8; 32], [u8; 32])> = all_cets
        .iter()
        .map(|(pt, alice, bob)| {
            let fee = CET_FUND - ANCHOR - alice - bob;
            assert!(fee >= 1, "CET fee");
            let ta = mk_cet(&a_cet_fund, *alice, *bob);
            let e = ScriptPath { key: owners[0], tapleaf: a_cet_fund.leaf_hash(0), codesep: u32::MAX };
            let ma_ = tap_sighash_ext(&ta, &[CET_FUND], &[a_cet_fund.spk()], 0, 0, None, Some(&e)).unwrap();
            let tb = mk_cet(&b_cet_fund, *alice, *bob);
            let mb_ = tap_sighash_ext(&tb, &[CET_FUND], &[b_cet_fund.spk()], 0, 0, None, None).unwrap();
            (*pt, ma_, mb_)
        })
        .collect();
    let t = Instant::now();
    for (pt, m, _) in &grid {
        let x0 = shz_dlc::adaptor_sign(&traders[0], m, pt).unwrap();
        let x1 = shz_dlc::adaptor_sign(&traders[1], m, pt).unwrap();
        shz_dlc::adaptor_verify(&owners[0], m, pt, &x0).unwrap();
        shz_dlc::adaptor_verify(&owners[1], m, pt, &x1).unwrap();
    }
    let grid_a_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    {
        use shz_dlc::musig2 as mu;
        let tweak = b_cet_fund.tweak_bytes();
        for (pt, _, m) in &grid {
            let (mut s0, p0) = mu::nonce_gen(Some(&traders[0]), &plain_pk(&traders[0]), Some(&b_cet_fund.output_key), Some(m), None).unwrap();
            let (mut s1, p1) = mu::nonce_gen(Some(&traders[1]), &plain_pk(&traders[1]), Some(&b_cet_fund.output_key), Some(m), None).unwrap();
            let ses = mu::Session { aggnonce: mu::nonce_agg(&[p0, p1]).unwrap(), pubkeys: cet_pks.clone(), tweaks: vec![tweak], is_xonly: vec![true], msg: m.to_vec(), adaptor: Some(*pt) };
            let q0 = mu::sign(&mut s0, &traders[0], &ses).unwrap();
            let q1 = mu::sign(&mut s1, &traders[1], &ses).unwrap();
            assert!(mu::partial_sig_verify_internal(&q0, &p0, &plain_pk(&traders[0]), &ses).unwrap());
            assert!(mu::partial_sig_verify_internal(&q1, &p1, &plain_pk(&traders[1]), &ses).unwrap());
            mu::partial_sig_agg(&[q0, q1], &ses).unwrap();
        }
    }
    let grid_b_s = t.elapsed().as_secs_f64();
    let n_cets = grid.len();

    let (va8, vb8, va7, vb7) = (vsize(&a8.tx), vsize(&b8.tx), vsize(&a7.tx), vsize(&b7.tx));
    let out = json!({
        "network": if regtest { "regtest" } else { "testnet4" }, "tip": tip, "refund_height": h, "oracle": ev,
        "funding": {"txid": fid, "vsize": funding_vsize, "outputs": ftx.outputs.len(), "hex": hex::encode(&f_raw), "fee": funded["fee"]},
        "A": {"settlement": {"txid": hex::encode(sta.txid), "vsize_n8": va8, "vsize_n7": va7, "marginal_vb_per_input": va8 - va7, "weight_n8": va8 * 4, "signatures": a8.slots.len(), "hex": hex::encode(&a_raw), "sign_seconds": a_sign_s},
              "cet": {"txid": hex::encode(cet_a.txid()), "vsize": vsize(&cet_a), "signatures": 2, "hex": hex::encode(&ca_raw)},
              "settlement_rounds_per_account": 1, "settlement_bytes_per_account": ADAPTOR_SIG_BYTES,
              "cet_rounds": 1, "cet_bytes": 2 * ADAPTOR_SIG_BYTES,
              "all_cets": {"count": n_cets, "sign_and_verify_seconds": grid_a_s, "bytes": n_cets * 2 * ADAPTOR_SIG_BYTES, "rounds": 1}},
        "B": {"settlement": {"txid": hex::encode(stb.txid), "vsize_n8": vb8, "vsize_n7": vb7, "marginal_vb_per_input": vb8 - vb7, "weight_n8": vb8 * 4, "signatures": b8.slots.len(), "hex": hex::encode(&b_raw), "sign_seconds": b_sign_s},
              "cet": {"txid": hex::encode(cet_b.txid()), "vsize": vsize(&cet_b), "signatures": 1, "hex": hex::encode(&cb_raw)},
              "settlement_rounds_per_account": MUSIG2_ROUNDS, "settlement_bytes_per_account": MUSIG2_BYTES_2OF2,
              "cet_rounds": MUSIG2_ROUNDS, "cet_bytes": MUSIG2_BYTES_2OF2,
              "all_cets": {"count": n_cets, "sign_and_verify_seconds": grid_b_s, "bytes": n_cets * MUSIG2_BYTES_2OF2, "rounds": MUSIG2_ROUNDS}},
        "payouts": sta.payouts, "net": sta.net,
        "verdicts": verdicts, "mined": mined,
        "tampered_hex": {"A": hex::encode(&a_tam), "B": hex::encode(&b_tam)},
    });
    let txs_json = |raw: &[u8], built: &Built, m: &rel::Manifest| {
        let (am, sp) = m.spent();
        json!([{"label": "settlement", "signed_hex": hex::encode(raw), "amounts": am, "spks": sp.iter().map(hex::encode).collect::<Vec<_>>(), "slots": built.slots, "m17_flags": FLAGS}])
    };
    let (ja, jb) = (txs_json(&a_raw, &a8, &ma), txs_json(&b_raw, &b8, &mb));
    Run { out, a_dir: (a_raw.clone(), ja, ma), b_dir: (b_raw.clone(), jb, mb), batches }
}

fn write_dir(dir: &Path, d: &(Vec<u8>, Value, rel::Manifest), batches: &[rel::Batch]) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("txs.json"), serde_json::to_string_pretty(&d.1).unwrap()).unwrap();
    std::fs::write(dir.join("manifest.json"), serde_json::to_string_pretty(&d.2).unwrap()).unwrap();
    std::fs::write(dir.join("batches.json"), serde_json::to_string_pretty(batches).unwrap()).unwrap();
}

#[test]
#[ignore = "needs LIGHTNINGER_BITCOIND and the venue keys file"]
fn regtest_ab() {
    let datadir = PathBuf::from(std::env::var("LIGHTNINGER_DLC_AB_DATADIR").unwrap_or_else(|_| "D:/shz/tmp/dlc-batch/ab-regtest".into()));
    let _ = std::fs::remove_dir_all(&datadir);
    let node = Node::regtest(&PathBuf::from(std::env::var("LIGHTNINGER_BITCOIND").expect("LIGHTNINGER_BITCOIND")), &datadir);
    node.cli(&["createwallet", "w"]);
    let sink = node.cli(&["getnewaddress", "", "bech32m"]);
    node.cli(&["generatetoaddress", "110", &sink]);
    let k = SettleKeys { collateral: 20_000, liquidity: 100_000, batcher_sk: [0xb1; 32], operator_sk: [0x0b; 32] };
    let r = build(&node, true, &k, Some(&sink));
    let ab = artifacts().join("ab");
    write_dir(&ab.join("A"), &r.a_dir, &r.batches);
    write_dir(&ab.join("B"), &r.b_dir, &r.batches);
    std::fs::write(ab.join("regtest_receipt.json"), serde_json::to_string_pretty(&r.out).unwrap()).unwrap();
    eprintln!("{}", serde_json::to_string_pretty(&json!({"A": r.out["A"]["settlement"]["vsize_n8"], "B": r.out["B"]["settlement"]["vsize_n8"], "cetA": r.out["A"]["cet"]["vsize"], "cetB": r.out["B"]["cet"]["vsize"], "gridA": r.out["A"]["all_cets"]["sign_and_verify_seconds"], "gridB": r.out["B"]["all_cets"]["sign_and_verify_seconds"]})).unwrap());
}

#[test]
#[ignore = "needs a synced testnet4 node and wallet lt-dlc-batcher (LIGHTNINGER_TESTNET4_ARGS)"]
fn testnet4_ab() {
    let cli = PathBuf::from(std::env::var("LIGHTNINGER_TESTNET4_CLI").unwrap_or_else(|_| "C:/Users/patri/bitcoin-core-31.1/bin/bitcoin-cli.exe".into()));
    let args: Vec<String> = std::env::var("LIGHTNINGER_TESTNET4_ARGS").expect("LIGHTNINGER_TESTNET4_ARGS").split_whitespace().map(String::from).collect();
    let node = Node::existing(cli, args);
    assert_eq!(node.json(&["getblockchaininfo"])["chain"], "testnet4");
    let traders = keys();
    let derive = |label: &[u8]| rel::tagged_hash(label, &traders.concat());
    let k = SettleKeys { collateral: 1_000, liquidity: 2_000, batcher_sk: derive(b"LIGHTNINGER/DLC-BATCH/TESTNET4/BATCHER"), operator_sk: derive(b"LIGHTNINGER/DLC-BATCH/TESTNET4/OPERATOR") };
    let r = build(&node, false, &k, None);
    std::fs::write(artifacts().join("ab").join("testnet4_receipt.json"), serde_json::to_string_pretty(&r.out).unwrap()).unwrap();
    eprintln!("verdicts {}", r.out["verdicts"]);
}

/// Smoke check of the committed prover inputs (`artifacts/ab/{A,B}`) at K = 2, no compression: the
/// settlement relation holds; M17 folds inputs 0 and 8 and its deferred signatures are the signed
/// slots; the first 2 bind-mode TapSighash steps and the first 2 clearing steps satisfy their
/// circuits. The full proofs run elsewhere (`artifacts/ab/*/README.md`).
#[test]
#[ignore = "about a minute"]
fn ab_prover_inputs_smoke() {
    use lightninger_bitvm3_clearing::{
        cet::expected_slots,
        clearing_step::{check_step, steps_of},
        tapsighash_step::{bound_steps, BoundSlot, TxShape},
        trace,
    };
    use m17_nova_script::{circuit as m17c, Case};
    let venue = read(&artifacts().join("venue_batches.json"));
    let tr = trace::from_venue(&venue, 8).unwrap();
    let (csteps, cz0, _) = steps_of(8, 2, &tr.batches);
    let mut z = cz0.to_z();
    for st in &csteps[..2] {
        let (ok, which, out, _) = check_step(st, &z);
        assert!(ok, "clearing step: {which:?}");
        z = out;
    }
    let pp = m17c::setup();
    for v in ["A", "B"] {
        let dir = artifacts().join("ab").join(v);
        let txs = read(&dir.join("txs.json"));
        let c = &txs[0];
        let m: rel::Manifest = serde_json::from_value(read(&dir.join("manifest.json"))).unwrap();
        let b: Vec<rel::Batch> = serde_json::from_value(read(&dir.join("batches.json"))).unwrap();
        let raw = hex::decode(c["signed_hex"].as_str().unwrap()).unwrap();
        let st = rel::check_settlement(&raw, &m, &b).unwrap();
        let tx = Tx::parse(&raw);
        let amounts: Vec<u64> = c["amounts"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
        let spks: Vec<Vec<u8>> = c["spks"].as_array().unwrap().iter().map(|x| hex::decode(x.as_str().unwrap()).unwrap()).collect();
        let slots: Vec<BoundSlot> = serde_json::from_value(c["slots"].clone()).unwrap();
        for i in [0usize, 8] {
            let case = Case { id: format!("{v}/{i}"), category: "dlc-batch".into(), flags: String::new(), flag_bits: FLAGS, expect_valid: true, description: v.into(), tx: hex::encode(&raw), prevouts: amounts.iter().zip(&spks).map(|(a, s)| (*a as i64, hex::encode(s))).collect(), index: i };
            let f = m17c::fold_case(&pp, &case).unwrap_or_else(|e| panic!("{v} M17 input {i}: {e}"));
            let want: Vec<_> = slots.iter().filter(|s| s.slot.input == i).map(|s| (s.slot.clone(), s.script_path.clone())).collect();
            assert_eq!(expected_slots(i, &f).unwrap(), want, "{v} input {i}");
            eprintln!("{v}: input {i} M17 {} steps, {} deferred signatures", f.steps, f.deferred.len());
        }
        let all: Vec<_> = slots.iter().map(|s| (s.slot.clone(), s.script_path.clone())).collect();
        let mut shape = TxShape::of(&tx, &spks, 0);
        shape.bind = true;
        let (steps, _, _, _, _) = bound_steps(&shape, &tx, &amounts, &spks, &all);
        for (k, s) in steps.iter().take(2).enumerate() {
            let (ok, which, _, n) = check_step(s, &s.z_in());
            assert!(ok, "{v} TapSighash step {k}: {which:?}");
            eprintln!("{v}: TapSighash step {k} satisfied ({n} constraints)");
        }
        eprintln!("{v}: settlement {} relation holds, {} slots", hex::encode(st.txid), slots.len());
    }
}
