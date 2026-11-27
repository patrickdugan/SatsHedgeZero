//! `shz dlc-testnet4-demo`: one live venue fill locked in a real testnet4 MNR-02 DLC output, with
//! adaptor-signed CETs keyed to a live FROST oracle event. Nothing is broadcast.
//!
//! `originate --keys K --fill F --event E --wallet W --state S`
//!   - contract from the venue fill (`ops/venue-bench/dlc_demo/fill.mjs`): notional, entry price and
//!     both margins exactly as the venue booked them;
//!   - funding tx spending every confirmed UTXO of wallet `W` into the DLC output, signed by the
//!     wallet, inputs locked (persistent) so nothing else spends them before broadcast;
//!   - refund (pre-signed, CLTV) and one CET per compressed price range of the full 20-bit outcome
//!     domain, each adaptor-signed by Alice and Bob under the range's anticipation point from the
//!     event's announced nonces; every adaptor signature is checked with `shz_dlc::adaptor_verify`.
//!
//! `settle --keys K --state S --event E_ATTESTED --out DIR`
//!   - rebuilds the package (signing is deterministic) and checks it reproduces the state file;
//!   - completes the CET of the attested price with the attestation scalar, verifies both final
//!     BIP340 signatures, checks no other CET completes;
//!   - `testmempoolaccept [funding, cet]` as a package, refund alone (expected non-final);
//!   - writes the prover inputs to `DIR` (`txs.json`, `oracle_event.json`, `receipt.json`).
//!
//! `bitcoin-cli` comes from the same environment as `testnet4-live` (`SHZ_BITCOIN_CLI_DIRECT=1`,
//! `SHZ_WSL_BITCOIN_CLI`, `SHZ_WSL_BITCOIN_DATADIR`).

use std::path::{Path, PathBuf};

use k256::ProjectivePoint;
use serde_json::{Value, json};
use shz_dlc::{
    Bip340Signature, OracleAnnouncement, OracleAttestation, adaptor_verify, bip340_verify,
    encode_point_compressed, pubkey_x_from_secret, tagged_hash,
};
use shz_margin::{CompressedCetRange, InverseContractSpec, compress_cet_ranges, lookup_cet_for_price};
use shz_utxoref::{
    mnr02::{
        Mnr02TaprootTree, OriginationPackage, SIGHASH_DEFAULT, SIGHASH_SINGLE_ANYONECANPAY, build_origination_package,
        finalize_unilateral_fallback_tx,
    },
    signing_target::DEFAULT_CPFP_ANCHOR_SATS,
};

use crate::testnet_clearing::wsl_testnet4_cli;

/// CET and refund miner fee (each is about 256 vB).
pub const CET_FEE_SATS: u64 = 300;
/// Funding fee rate passed to `walletcreatefundedpsbt` (sat/vB); dust change goes to the fee.
pub const FUNDING_FEE_RATE_SAT_VB: f64 = 1.0;
pub const MAX_CET_ERROR_SATS: u64 = 2;
/// The unilateral CET is final one block after origination; the oracle attestation gates it.
pub const GRACE_BLOCKS: u32 = 1;
/// About three days at 10-minute blocks: room to broadcast the funding before the refund opens.
pub const REFUND_DELAY_BLOCKS: u32 = 432;
const ANNOUNCEMENT_TAG: &[u8] = b"SHZ/DLC/ANNOUNCEMENT/V1";

fn arg<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn read_json(p: &Path) -> Result<Value, String> {
    serde_json::from_str(&std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?)
        .map_err(|e| format!("{}: {e}", p.display()))
}

fn h32(v: &Value) -> Result<[u8; 32], String> {
    let s = v.as_str().ok_or("expected hex string")?;
    hex::decode(s).map_err(|e| e.to_string())?.try_into().map_err(|_| "expected 32 bytes".to_string())
}

fn cli(wallet: Option<&str>, args: &[&str]) -> Result<String, String> {
    wsl_testnet4_cli(wallet, args).map_err(|e| format!("bitcoin-cli {}: {e}", args.first().unwrap_or(&"")))
}
fn cli_json(wallet: Option<&str>, args: &[&str]) -> Result<Value, String> {
    serde_json::from_str(&cli(wallet, args)?).map_err(|e| e.to_string())
}

struct Keys {
    alice_sk: [u8; 32],
    bob_sk: [u8; 32],
    guard_pk: [u8; 32],
}

fn load_keys(p: &Path) -> Result<Keys, String> {
    let k = read_json(p)?;
    let guard_sk = h32(&k["guard_sk"])?;
    Ok(Keys {
        alice_sk: h32(&k["alice_sk"])?,
        bob_sk: h32(&k["bob_sk"])?,
        guard_pk: pubkey_x_from_secret(&guard_sk).map_err(|e| e.to_string())?,
    })
}

/// A raw `/v1/dlc/event/<id>` response: verify the threshold announcement signature over the
/// canonical core and return the announcement (and the attestation once attested).
fn load_event(p: &Path) -> Result<(Value, OracleAnnouncement, Option<OracleAttestation>), String> {
    let e = read_json(p)?;
    let ann: OracleAnnouncement =
        serde_json::from_value(e["shz_dlc_announcement"].clone()).map_err(|x| format!("announcement: {x}"))?;
    let core = serde_json::to_string(&e["core"]).map_err(|x| x.to_string())?;
    let msg = tagged_hash(ANNOUNCEMENT_TAG, core.as_bytes());
    let sig = hex::decode(e["announcement_signature"].as_str().ok_or("announcement_signature")?)
        .map_err(|x| x.to_string())?;
    if sig.len() != 64 {
        return Err("announcement_signature is not 64 bytes".into());
    }
    bip340_verify(
        &ann.oracle_pubkey_x,
        &msg,
        &Bip340Signature { r_x: sig[..32].try_into().unwrap(), s: sig[32..].try_into().unwrap() },
    )
    .map_err(|_| "announcement signature does not verify")?;
    if hex::encode(ann.oracle_pubkey_x) != e["core"]["oracle_pubkey_x"].as_str().unwrap_or("") {
        return Err("announcement oracle key differs from core".into());
    }
    let att = if e["status"] == "attested" {
        let a: OracleAttestation = serde_json::from_value(e["shz_dlc_attestation"].clone())
            .map_err(|x| format!("attestation: {x}"))?;
        a.verify_against(&ann).map_err(|x| format!("attestation does not verify: {x:?}"))?;
        Some(a)
    } else {
        None
    };
    Ok((e, ann, att))
}

/// The venue fill: Alice is the long, Bob the short; their venue owner keys are the DLC keys.
struct Fill {
    notional_usd: u64,
    price_usd: u64,
    long_lev_bps: u32,
    short_lev_bps: u32,
    batch_seq: u64,
    fill_id: String,
}

fn load_fill(p: &Path, k: &Keys) -> Result<(Value, Fill, InverseContractSpec), String> {
    let f = read_json(p)?;
    let fill = &f["fill"];
    let alice_pk = hex::encode(pubkey_x_from_secret(&k.alice_sk).unwrap());
    let bob_pk = hex::encode(pubkey_x_from_secret(&k.bob_sk).unwrap());
    let (long_owner, short_owner, long_intent, short_intent) = if fill["taker_side"] == "short" {
        (&fill["maker_owner"], &fill["taker_owner"], &f["post"]["intent"], &f["take"]["intent"])
    } else {
        (&fill["taker_owner"], &fill["maker_owner"], &f["take"]["intent"], &f["post"]["intent"])
    };
    if long_owner.as_str() != Some(&alice_pk) || short_owner.as_str() != Some(&bob_pk) {
        return Err("fill owners are not Alice (long) and Bob (short) of --keys".into());
    }
    let batch = &f["batch"]["batch"];
    if batch["phase"] != "committed" {
        return Err("fill batch is not committed".into());
    }
    let fl = Fill {
        notional_usd: fill["qty_usd"].as_u64().ok_or("qty_usd")?,
        price_usd: fill["price_usd"].as_u64().ok_or("price_usd")?,
        long_lev_bps: long_intent["leverage_bps"].as_u64().ok_or("long leverage")? as u32,
        short_lev_bps: short_intent["leverage_bps"].as_u64().ok_or("short leverage")? as u32,
        batch_seq: batch["seq"].as_u64().ok_or("batch seq")?,
        fill_id: fill["id"].as_str().ok_or("fill id")?.to_string(),
    };
    let spec = InverseContractSpec::from_leverages_v0(fl.notional_usd, fl.price_usd, fl.long_lev_bps, fl.short_lev_bps)
        .map_err(|e| format!("spec: {e:?}"))?;
    // The venue's booked leg margins are the DLC margins.
    let margin_of = |owner: &str| {
        batch["accounts"].as_array().and_then(|a| a.iter().find(|x| x["owner"] == owner)).and_then(|x| x["margin_sats"].as_u64())
    };
    if margin_of(&alice_pk) != Some(spec.long_margin_sats) || margin_of(&bob_pk) != Some(spec.short_margin_sats) {
        return Err(format!(
            "venue margins {:?}/{:?} differ from spec {}/{}",
            margin_of(&alice_pk),
            margin_of(&bob_pk),
            spec.long_margin_sats,
            spec.short_margin_sats
        ));
    }
    Ok((f, fl, spec))
}

struct Contract {
    cets: Vec<CompressedCetRange>,
    points: Vec<ProjectivePoint>,
    pkg: OriginationPackage,
}

#[allow(clippy::too_many_arguments)]
fn build_contract(
    k: &Keys,
    spec: &InverseContractSpec,
    ann: &OracleAnnouncement,
    funding_txid: &str,
    funding_vout: u32,
    maturity_height: u32,
    spks: [&[u8]; 3],
) -> Result<Contract, String> {
    let cets = compress_cet_ranges(spec, ann.num_bits(), MAX_CET_ERROR_SATS).map_err(|e| format!("cets: {e:?}"))?;
    let table = ann.precompute_digit_points().map_err(|e| format!("{e:?}"))?;
    let mut points = Vec::with_capacity(cets.len());
    let mut outcomes = Vec::with_capacity(cets.len());
    for c in &cets {
        let pt = OracleAnnouncement::anticipation_point_from_table(&table, &c.prefix_bits).map_err(|e| format!("{e:?}"))?;
        points.push(pt);
        outcomes.push(((c.min_price_usd + c.max_price_usd) / 2, pt));
    }
    let pkg = build_origination_package(
        &k.alice_sk,
        &k.bob_sk,
        k.guard_pk,
        funding_txid,
        funding_vout,
        spec.long_margin_sats,
        spec.short_margin_sats,
        spec.usd_notional,
        spec.entry_price_usd,
        CET_FEE_SATS,
        maturity_height,
        GRACE_BLOCKS,
        REFUND_DELAY_BLOCKS,
        spks[0].to_vec(),
        spks[1].to_vec(),
        spks[2].to_vec(),
        &outcomes,
    )
    .map_err(|e| format!("origination: {e:?}"))?;
    Ok(Contract { cets, points, pkg })
}

/// Re-check every adaptor signature of the package with `shz_dlc::adaptor_verify`.
fn verify_all_adaptors(c: &Contract) -> Result<usize, String> {
    let t = &c.pkg.tree;
    let mut n = 0;
    for (o, pt) in c.pkg.outcomes.iter().zip(&c.points) {
        let uni = o.unilateral_tx.bip341_sighash(0, SIGHASH_DEFAULT, Some(&t.unilateral_leaf_hash)).map_err(|e| format!("{e:?}"))?;
        adaptor_verify(&t.alice_pubkey_x, &uni, pt, &o.alice_unilateral_adaptor_sig).map_err(|_| "alice CET adaptor")?;
        adaptor_verify(&t.bob_pubkey_x, &uni, pt, &o.bob_unilateral_adaptor_sig).map_err(|_| "bob CET adaptor")?;
        let mut route = o.unilateral_tx.clone();
        route.outputs.truncate(1);
        route.locktime = t.maturity_height;
        let r = route.bip341_sighash(0, SIGHASH_SINGLE_ANYONECANPAY, Some(&t.route_leaf_hash)).map_err(|e| format!("{e:?}"))?;
        adaptor_verify(&t.bob_pubkey_x, &r, pt, &o.bob_route_0x83_adaptor_sig).map_err(|_| "bob route adaptor")?;
        n += 3;
    }
    Ok(n)
}

fn spk_of_address(wallet: &str, addr: &str) -> Result<Vec<u8>, String> {
    let i = cli_json(Some(wallet), &["getaddressinfo", addr])?;
    hex::decode(i["scriptPubKey"].as_str().ok_or("scriptPubKey")?).map_err(|e| e.to_string())
}

fn sats(btc: &Value) -> u64 {
    (btc.as_f64().unwrap() * 1e8).round() as u64
}

pub fn originate(args: &[String]) -> Result<Value, String> {
    let k = load_keys(Path::new(arg(args, "--keys")?))?;
    let (_, fill, spec) = load_fill(Path::new(arg(args, "--fill")?), &k)?;
    let (_, ann, att) = load_event(Path::new(arg(args, "--event")?))?;
    if att.is_some() {
        return Err("event is already attested: originate before the attestation".into());
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    if ann.maturity_unix <= now + 300 {
        return Err(format!("event {} matures in less than 5 minutes", ann.event_id));
    }
    let wallet = arg(args, "--wallet")?;
    if wallet == "m16" {
        return Err("the m16 wallet is reserved".into());
    }
    let state_path = PathBuf::from(arg(args, "--state")?);
    if state_path.exists() {
        return Err(format!("{} exists: one funding per state file", state_path.display()));
    }
    let chain = cli_json(None, &["getblockchaininfo"])?;
    if chain["chain"] != "testnet4" || chain["blocks"] != chain["headers"] {
        return Err(format!("node not synced testnet4: {chain}"));
    }
    let tip = chain["blocks"].as_u64().unwrap() as u32;
    let maturity_height = tip;

    let addr = |label: &str| cli(Some(wallet), &["getnewaddress", label, "bech32m"]);
    let (alice_addr, bob_addr, anchor_addr) = (addr("dlc-demo-alice-payout")?, addr("dlc-demo-bob-payout")?, addr("dlc-demo-cpfp-anchor")?);
    let (alice_spk, bob_spk, anchor_spk) =
        (spk_of_address(wallet, &alice_addr)?, spk_of_address(wallet, &bob_addr)?, spk_of_address(wallet, &anchor_addr)?);

    // The tree does not depend on the funding outpoint: build it once to get the output script.
    let dlc_spk = Mnr02TaprootTree::build(
        pubkey_x_from_secret(&k.alice_sk).unwrap(),
        pubkey_x_from_secret(&k.bob_sk).unwrap(),
        k.guard_pk,
        maturity_height,
        GRACE_BLOCKS,
        REFUND_DELAY_BLOCKS,
    )
    .map_err(|e| format!("tree: {e:?}"))?
    .script_pubkey;
    let dlc_addr = cli_json(None, &["decodescript", &hex::encode(&dlc_spk)])?["address"]
        .as_str()
        .ok_or("decodescript address")?
        .to_string();
    let funding_sats = spec.long_margin_sats + spec.short_margin_sats;

    // Every confirmed, unlocked UTXO of the wallet; none may be locked by someone else.
    if !cli_json(Some(wallet), &["listlockunspent"])?.as_array().unwrap().is_empty() {
        return Err(format!("wallet {wallet} has locked UTXOs: another flow is using it"));
    }
    let utxos = cli_json(Some(wallet), &["listunspent", "1"])?;
    let utxos = utxos.as_array().unwrap();
    let inputs: Vec<Value> = utxos.iter().map(|u| json!({"txid": u["txid"], "vout": u["vout"]})).collect();
    let total: u64 = utxos.iter().map(|u| sats(&u["amount"])).sum();
    let outputs = json!([{ dlc_addr.clone(): format!("{:.8}", funding_sats as f64 / 1e8) }]);
    let opts = json!({"add_inputs": false, "fee_rate": FUNDING_FEE_RATE_SAT_VB, "lockUnspents": true, "replaceable": true});
    let psbt = cli_json(
        Some(wallet),
        &["walletcreatefundedpsbt", &Value::Array(inputs.clone()).to_string(), &outputs.to_string(), "0", &opts.to_string()],
    )?;
    let processed = cli_json(Some(wallet), &["walletprocesspsbt", psbt["psbt"].as_str().unwrap(), "true", "DEFAULT"])?;
    if processed["complete"] != true {
        return Err("wallet did not fully sign the funding psbt".into());
    }
    let fin = cli_json(None, &["finalizepsbt", processed["psbt"].as_str().unwrap(), "true"])?;
    let funding_hex = fin["hex"].as_str().ok_or("finalizepsbt hex")?.to_string();
    let dec = cli_json(None, &["decoderawtransaction", &funding_hex])?;
    let funding_txid = dec["txid"].as_str().unwrap().to_string();
    let vouts = dec["vout"].as_array().unwrap();
    let funding_vout = vouts
        .iter()
        .position(|o| o["scriptPubKey"]["hex"].as_str() == Some(&hex::encode(&dlc_spk)))
        .ok_or("DLC output missing")? as u32;
    if sats(&vouts[funding_vout as usize]["value"]) != funding_sats {
        return Err("DLC output amount differs".into());
    }
    // Hold the inputs across restarts until the parent broadcasts or unlocks them.
    let locks: Vec<Value> = dec["vin"].as_array().unwrap().iter().map(|i| json!({"txid": i["txid"], "vout": i["vout"]})).collect();
    cli(Some(wallet), &["lockunspent", "false", &Value::Array(locks.clone()).to_string(), "true"])?;

    let c = build_contract(&k, &spec, &ann, &funding_txid, funding_vout, maturity_height, [&alice_spk, &bob_spk, &anchor_spk])?;
    let n_sigs = verify_all_adaptors(&c)?;
    let accept = cli_json(None, &["testmempoolaccept", &json!([funding_hex]).to_string()])?;
    let refund_hex = hex::encode(c.pkg.signed_refund_tx.serialize_segwit());
    let refund_accept = cli_json(None, &["testmempoolaccept", &json!([funding_hex, refund_hex]).to_string()])?;

    let prevouts: Vec<Value> = dec["vin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let u = utxos.iter().find(|u| u["txid"] == i["txid"] && u["vout"] == i["vout"]).unwrap();
            json!({"txid": i["txid"], "vout": i["vout"], "amount_sats": sats(&u["amount"]), "spk": u["scriptPubKey"]})
        })
        .collect();
    let in_sats: u64 = prevouts.iter().map(|p| p["amount_sats"].as_u64().unwrap()).sum();
    let out_sats: u64 = vouts.iter().map(|o| sats(&o["value"])).sum();
    let state = json!({
        "event_id": ann.event_id,
        "event_maturity_unix": ann.maturity_unix,
        "wallet": wallet,
        "fill": {"id": fill.fill_id, "batch_seq": fill.batch_seq, "notional_usd": fill.notional_usd, "price_usd": fill.price_usd,
                 "long_leverage_bps": fill.long_lev_bps, "short_leverage_bps": fill.short_lev_bps},
        "spec": {"long_margin_sats": spec.long_margin_sats, "short_margin_sats": spec.short_margin_sats},
        "origination_tip_height": tip,
        "maturity_height": maturity_height,
        "unilateral_cltv_height": c.pkg.tree.unilateral_cltv_height,
        "refund_cltv_height": c.pkg.tree.refund_cltv_height,
        "addresses": {"alice_payout": alice_addr, "bob_payout": bob_addr, "cpfp_anchor": anchor_addr, "dlc": dlc_addr},
        "spks": {"alice_payout": hex::encode(&alice_spk), "bob_payout": hex::encode(&bob_spk), "cpfp_anchor": hex::encode(&anchor_spk), "dlc": hex::encode(&dlc_spk)},
        "funding": {"txid": funding_txid, "vout": funding_vout, "hex": funding_hex, "prevouts": prevouts, "dlc_sats": funding_sats,
                    "fee_sats": in_sats - out_sats, "vsize": dec["vsize"], "wallet_total_sats": total, "locked_inputs": locks,
                    "testmempoolaccept": accept},
        "refund": {"txid": c.pkg.signed_refund_tx.txid_hex(), "hex": refund_hex, "vsize": c.pkg.signed_refund_tx.vsize(),
                   "testmempoolaccept_package": refund_accept},
        "cet_count": c.cets.len(),
        "adaptor_signatures_verified": n_sigs,
        "cets_sha256": cets_digest(&c),
    });
    std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).map_err(|e| e.to_string())?;
    Ok(state)
}

/// Digest over every CET (range, outputs, three adaptor signatures): `settle` checks it is reproduced.
fn cets_digest(c: &Contract) -> String {
    let mut b = Vec::new();
    for (r, o) in c.cets.iter().zip(&c.pkg.outcomes) {
        b.extend(r.min_price_usd.to_le_bytes());
        b.extend(r.max_price_usd.to_le_bytes());
        b.extend(o.unilateral_tx.serialize_unsigned());
        for s in [&o.alice_unilateral_adaptor_sig, &o.bob_unilateral_adaptor_sig, &o.bob_route_0x83_adaptor_sig] {
            b.extend(s.r_eff_x);
            b.push(s.r_eff_negated as u8);
            b.extend(s.s_adapt);
        }
    }
    hex::encode(tagged_hash(b"SHZ/DLC-DEMO/CETS/V1", &b))
}

fn cet_table(c: &Contract) -> Vec<Value> {
    c.cets
        .iter()
        .zip(&c.pkg.outcomes)
        .zip(&c.points)
        .map(|((r, o), pt)| {
            let a = |s: &shz_dlc::AdaptorSignature| format!("{}{}{}", hex::encode(s.r_eff_x), if s.r_eff_negated { "01" } else { "00" }, hex::encode(s.s_adapt));
            json!({
                "min_price_usd": r.min_price_usd, "max_price_usd": r.max_price_usd,
                "prefix": r.prefix_bits.iter().map(|b| (b'0' + b) as char).collect::<String>(),
                "anticipation_point": hex::encode(encode_point_compressed(pt).unwrap()),
                "bob_sats": o.bob_output_sats, "alice_sats": o.alice_unilateral_sats,
                "alice_adaptor": a(&o.alice_unilateral_adaptor_sig), "bob_adaptor": a(&o.bob_unilateral_adaptor_sig),
                "bob_route_0x83_adaptor": a(&o.bob_route_0x83_adaptor_sig),
            })
        })
        .collect()
}

/// `{label, signed_hex, amounts, spks, slots}` as in `artifacts/core_sighash_txs.json`; a tapscript
/// slot carries `script_path {key, tapleaf, codesep}`.
fn tx_entry(label: &str, hex_tx: &str, amounts: Vec<u64>, spks: Vec<String>, slots: Vec<Value>, how: &str) -> Value {
    json!({"label": label, "signed_hex": hex_tx, "amounts": amounts, "spks": spks, "slots": slots, "how_validated": how})
}

fn slot(input: usize, wit_sig: &[u8], script_path: Value) -> Value {
    let hash_type = if wit_sig.len() == 65 { wit_sig[64] } else { 0 };
    json!({"input": input, "hash_type": hash_type, "annex": null,
           "sig_rx": wit_sig[..32].to_vec(), "sig_s": wit_sig[32..64].to_vec(), "script_path": script_path})
}

pub fn settle(args: &[String]) -> Result<Value, String> {
    let k = load_keys(Path::new(arg(args, "--keys")?))?;
    let state = read_json(Path::new(arg(args, "--state")?))?;
    let fill_path = PathBuf::from(arg(args, "--fill")?);
    let (fill_json, _, spec) = load_fill(&fill_path, &k)?;
    let (event_raw, ann, att) = load_event(Path::new(arg(args, "--event")?))?;
    let att = att.ok_or("event is not attested yet")?;
    if ann.event_id != state["event_id"] {
        return Err("event differs from the originated one".into());
    }
    let out = PathBuf::from(arg(args, "--out")?);
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;

    let spk = |n: &str| hex::decode(state["spks"][n].as_str().unwrap()).unwrap();
    let (alice_spk, bob_spk, anchor_spk) = (spk("alice_payout"), spk("bob_payout"), spk("cpfp_anchor"));
    let funding = &state["funding"];
    let funding_txid = funding["txid"].as_str().unwrap();
    let funding_vout = funding["vout"].as_u64().unwrap() as u32;
    let c = build_contract(
        &k,
        &spec,
        &ann,
        funding_txid,
        funding_vout,
        state["maturity_height"].as_u64().unwrap() as u32,
        [&alice_spk, &bob_spk, &anchor_spk],
    )?;
    if cets_digest(&c) != state["cets_sha256"] || c.pkg.signed_refund_tx.txid_hex() != state["refund"]["txid"] {
        return Err("rebuilt package differs from the originated state".into());
    }
    let n_sigs = verify_all_adaptors(&c)?;

    let nb = ann.num_bits();
    let cet = lookup_cet_for_price(&c.cets, att.price_usd, nb).ok_or("no CET covers the attested price")?;
    let idx = c.cets.iter().position(|x| x == cet).unwrap();
    let t = att.secret_scalar_for_prefix(cet.prefix_bits.len()).map_err(|e| format!("{e:?}"))?;
    if ProjectivePoint::GENERATOR * t != c.points[idx] {
        return Err("attestation scalar is not the matching anticipation point's discrete log".into());
    }
    let tx = finalize_unilateral_fallback_tx(&c.pkg.tree, &c.pkg.outcomes[idx], &t).map_err(|e| format!("complete: {e:?}"))?;
    let others_rejected = c
        .pkg
        .outcomes
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != idx)
        .take(64)
        .all(|(_, o)| finalize_unilateral_fallback_tx(&c.pkg.tree, o, &t).is_err());
    if !others_rejected {
        return Err("the attestation completed a CET of another range".into());
    }

    let funding_hex = funding["hex"].as_str().unwrap();
    let cet_hex = hex::encode(tx.serialize_segwit());
    let refund_hex = c.pkg.signed_refund_tx.serialize_segwit();
    let refund_hex = hex::encode(refund_hex);
    let tip = cli_json(None, &["getblockcount"])?;
    let pkg_accept = cli_json(None, &["testmempoolaccept", &json!([funding_hex, cet_hex]).to_string()])?;
    let refund_accept = cli_json(None, &["testmempoolaccept", &json!([funding_hex, refund_hex]).to_string()])?;
    let all_allowed = pkg_accept.as_array().map(|a| a.len() == 2 && a.iter().all(|r| r["allowed"] == true)).unwrap_or(false);
    let dec_fund = cli_json(None, &["decoderawtransaction", funding_hex])?;
    let dec_cet = cli_json(None, &["decoderawtransaction", &cet_hex])?;

    // Prover inputs.
    let wit = |d: &Value, i: usize, j: usize| hex::decode(d["vin"][i]["txinwitness"][j].as_str().unwrap()).unwrap();
    let prevouts = funding["prevouts"].as_array().unwrap();
    let fund_slots = (0..prevouts.len()).map(|i| slot(i, &wit(&dec_fund, i, 0), Value::Null)).collect();
    let tree = &c.pkg.tree;
    let dlc_sats = c.pkg.funding_sats;
    let dlc_spk = hex::encode(&tree.script_pubkey);
    let sp = |key: &[u8; 32], leaf: &[u8; 32]| json!({"key": key.to_vec(), "tapleaf": leaf.to_vec(), "codesep": u32::MAX});
    // Witness `[sig(pk1), sig(pk0), script, control]`; slots in key order pk0, pk1.
    let leaf_slots = |w: &dyn Fn(usize) -> Vec<u8>, leaf: &[u8; 32]| {
        vec![slot(0, &w(1), sp(&tree.sorted_ab[0], leaf)), slot(0, &w(0), sp(&tree.sorted_ab[1], leaf))]
    };
    let cet_slots = leaf_slots(&|j| wit(&dec_cet, 0, j), &tree.unilateral_leaf_hash);
    let refund_slots = leaf_slots(&|j| c.pkg.signed_refund_tx.inputs[0].witness[j].clone(), &tree.refund_leaf_hash);
    let core = cli_json(None, &["getnetworkinfo"])?["subversion"].as_str().unwrap_or("").to_string();
    let txs = json!([
        tx_entry("funding", funding_hex,
            prevouts.iter().map(|p| p["amount_sats"].as_u64().unwrap()).collect(),
            prevouts.iter().map(|p| p["spk"].as_str().unwrap().to_string()).collect(), fund_slots,
            &format!("{core}: walletprocesspsbt key-path signatures, testmempoolaccept allowed (package with the CET); not broadcast")),
        tx_entry("cet", &cet_hex, vec![dlc_sats], vec![dlc_spk.clone()], cet_slots,
            &format!("{core}: adaptor signatures completed with the oracle attestation scalar, BIP340-verified, testmempoolaccept allowed as a package after the funding tx; not broadcast")),
        tx_entry("refund", &refund_hex, vec![dlc_sats], vec![dlc_spk.clone()], refund_slots,
            &format!("{core}: pre-signed at origination, BIP340-verified; testmempoolaccept non-final until height {}", tree.refund_cltv_height)),
    ]);
    std::fs::write(out.join("txs.json"), serde_json::to_string_pretty(&txs).unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(out.join("oracle_event.json"), serde_json::to_string_pretty(&json!({
        "event_id": ann.event_id, "relay_response": event_raw,
        "attested_price_usd": att.price_usd, "matching_cet_index": idx,
        "matching_prefix_len": cet.prefix_bits.len(),
        "attestation_scalar_for_prefix": hex::encode(t.to_bytes()),
    })).unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(out.join("cets.json"), serde_json::to_string(&json!({
        "event_id": ann.event_id, "funding_outpoint": format!("{funding_txid}:{funding_vout}"),
        "max_error_sats": MAX_CET_ERROR_SATS, "cet_fee_sats": CET_FEE_SATS, "anchor_sats": DEFAULT_CPFP_ANCHOR_SATS,
        "unilateral_leaf": hex::encode(&tree.unilateral_cet_script), "route_leaf": hex::encode(&tree.route_cet_script),
        "refund_leaf": hex::encode(&tree.refund_script), "cets_sha256": state["cets_sha256"],
        "adaptor_format": "r_eff_x(32) || r_eff_negated(1) || s_adapt(32)",
        "cets": cet_table(&c),
    })).unwrap()).map_err(|e| e.to_string())?;
    let mut fill_json = fill_json;
    fill_json["name"] = json!(format!("testnet4_batch{}", state["fill"]["batch_seq"]));
    std::fs::write(out.join("venue_fill.json"), serde_json::to_string_pretty(&fill_json).unwrap()).map_err(|e| e.to_string())?;

    let cet_vsize = tx.vsize();
    let receipt = json!({
        "network": "bitcoin-testnet4",
        "core": core,
        "tip_height_at_settle": tip,
        "wallet": state["wallet"],
        "event_id": ann.event_id,
        "attested_price_usd": att.price_usd,
        "fill": state["fill"],
        "contract": {
            "long_margin_sats": spec.long_margin_sats, "short_margin_sats": spec.short_margin_sats, "dlc_sats": dlc_sats,
            "maturity_height": tree.maturity_height, "unilateral_cltv_height": tree.unilateral_cltv_height, "refund_cltv_height": tree.refund_cltv_height,
            "internal_key": hex::encode(tree.internal_xonly), "alice_pubkey_x": hex::encode(tree.alice_pubkey_x), "bob_pubkey_x": hex::encode(tree.bob_pubkey_x),
            "router_guard_pubkey_x": hex::encode(tree.router_guard_pubkey_x), "dlc_address": state["addresses"]["dlc"],
        },
        "funding": {"txid": funding_txid, "vout": funding_vout, "vsize": state["funding"]["vsize"], "fee_sats": state["funding"]["fee_sats"],
                    "locked_inputs": state["funding"]["locked_inputs"]},
        "cet": {"txid": tx.txid_hex(), "index": idx, "range_usd": [cet.min_price_usd, cet.max_price_usd], "prefix_len": cet.prefix_bits.len(),
                "vsize": cet_vsize, "fee_sats": CET_FEE_SATS, "locktime": tx.locktime,
                "outputs": tx.outputs.iter().zip(["bob (short)", "alice (long)", "cpfp anchor"]).map(|((v, s), who)| json!({"who": who, "sats": v, "spk": hex::encode(s)})).collect::<Vec<_>>(),
                "payout_at_price": {"long_sats": spec.payout_at_price(att.price_usd).long_sats, "short_sats": spec.payout_at_price(att.price_usd).short_sats}},
        "refund": {"txid": c.pkg.signed_refund_tx.txid_hex(), "locktime": c.pkg.signed_refund_tx.locktime},
        "cet_count": c.cets.len(),
        "adaptor_signatures_verified": n_sigs,
        "other_cets_not_completable_checked": 64,
        "testmempoolaccept_funding_and_cet": pkg_accept,
        "testmempoolaccept_funding_and_refund": refund_accept,
        "broadcast": "none",
    });
    std::fs::write(out.join("receipt.json"), serde_json::to_string_pretty(&receipt).unwrap()).map_err(|e| e.to_string())?;
    if !all_allowed {
        return Err(format!("testmempoolaccept rejected the package: {pkg_accept}"));
    }
    Ok(receipt)
}

pub fn run(args: &[String]) -> Result<Value, String> {
    match args.first().map(String::as_str) {
        Some("originate") => originate(&args[1..]),
        Some("settle") => settle(&args[1..]),
        _ => Err("usage: dlc-testnet4-demo originate --keys K --fill F --event E --wallet W --state S | settle --keys K --fill F --state S --event E --out DIR".into()),
    }
}
