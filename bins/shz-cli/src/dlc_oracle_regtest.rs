//! `shz dlc-oracle-regtest`: Core regtest drill of MNR-02 contracts driven by the deployed
//! threshold (FROST 3-of-5) DLC oracle fixtures.
//!
//! A) ATTESTED: the live attestation completes the matching compressed-CET adaptor signatures and the
//!    unilateral CET confirms with the payout of the attested price.
//! B) UNATTESTED: the oracle never attests; the pre-signed refund is rejected by Core before its CLTV
//!    height, confirms at that height, and a CPFP child spends the anchor.

use std::{path::Path, process::Command};

use k256::ProjectivePoint;
use serde::Serialize;
use serde_json::{Value, json};
use shz_dlc::{
    Bip340Signature, OracleAnnouncement, OracleAttestation, bip340_sign, bip340_verify,
    pubkey_x_from_secret, tagged_hash,
};
use shz_margin::{CompressedCetRange, InverseContractSpec, compress_cet_ranges, lookup_cet_for_price};
use shz_utxoref::{
    mnr02::{
        Mnr02TaprootTree, OriginationPackage, SIGHASH_DEFAULT, SegwitTx, SegwitTxIn,
        build_origination_package, encode_taproot_witness_sig, finalize_unilateral_fallback_tx,
    },
    signing_target::DEFAULT_CPFP_ANCHOR_SATS,
};

use crate::{
    dlc_refund_plan::{
        DEFAULT_ATTEST_WINDOW_SECS, DEFAULT_BLOCK_SECS, DEFAULT_FAST_FACTOR, DEFAULT_GRACE_BLOCKS,
        DEFAULT_MIN_GAP_SECS, DEFAULT_REFUND_DELAY_BLOCKS, PlanParams, RefundPlan, compute_plan,
    },
    mnr02_regtest::{IsolatedRegtestNode, keypath_only_p2tr_spk},
};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ops/public-relay");
const NOTIONAL_USD: u64 = 1_000;
const ENTRY_PRICE_USD: u64 = 60_000;
const CET_FEE_SATS: u64 = 1_000;
const MAX_CET_ERROR_SATS: u64 = 50;

struct Fixture {
    announcement: OracleAnnouncement,
    attestation: OracleAttestation,
    name: String,
}

fn load_fixture(name: &str) -> Fixture {
    let path = format!("{FIXTURE_DIR}/{name}");
    let f: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read fixture"))
        .expect("fixture json");
    let announcement: OracleAnnouncement =
        serde_json::from_value(f["announcement"].clone()).expect("announcement");
    let attestation: OracleAttestation =
        serde_json::from_value(f["attestation"].clone()).expect("attestation");
    let oracle: [u8; 32] = hex::decode(f["oracle_pubkey_x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(announcement.oracle_pubkey_x, oracle);
    // Announcement authenticity: threshold BIP340 signature over the canonical core.
    let core = serde_json::to_string(&f["announcement_core"]).unwrap();
    let msg = tagged_hash(b"SHZ/DLC/ANNOUNCEMENT/V1", core.as_bytes());
    let sig = hex::decode(f["announcement_signature"].as_str().unwrap()).unwrap();
    bip340_verify(
        &oracle,
        &msg,
        &Bip340Signature {
            r_x: sig[..32].try_into().unwrap(),
            s: sig[32..].try_into().unwrap(),
        },
    )
    .expect("announcement signature verifies");
    Fixture { announcement, attestation, name: name.to_string() }
}

#[derive(Serialize)]
struct TxPoint {
    txid: String,
    height: u64,
    outputs_sats: Vec<u64>,
}

fn onchain_outputs(node: &IsolatedRegtestNode, txid: &str) -> (u64, Vec<u64>) {
    let info = node.cli_json(&["getrawtransaction", txid, "true"]);
    let height = {
        let bh = info["blockhash"].as_str().expect("confirmed tx has blockhash");
        node.cli_json(&["getblockheader", bh])["height"].as_u64().unwrap()
    };
    let outs = info["vout"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| (o["value"].as_f64().unwrap() * 1e8).round() as u64)
        .collect();
    (height, outs)
}

/// One contract: funded tree + origination package whose outcome points are the anticipation
/// points of every compressed CET of the inverse contract under `ann`.
struct Contract {
    spec: InverseContractSpec,
    cets: Vec<CompressedCetRange>,
    pkg: OriginationPackage,
    funding_txid: String,
    plan: RefundPlan,
}

struct Keys {
    alice_sk: [u8; 32],
    bob_sk: [u8; 32],
    guard_pk: [u8; 32],
    alice_spk: Vec<u8>,
    bob_spk: Vec<u8>,
    anchor_sk: [u8; 32],
    anchor_spk: Vec<u8>,
}

fn keys() -> Keys {
    let alice_sk = [0xA1u8; 32];
    let bob_sk = [0xB2u8; 32];
    let guard_sk = [0xD4u8; 32];
    let anchor_sk = [0xE5u8; 32];
    Keys {
        alice_sk,
        bob_sk,
        guard_pk: pubkey_x_from_secret(&guard_sk).unwrap(),
        alice_spk: keypath_only_p2tr_spk(&alice_sk),
        bob_spk: keypath_only_p2tr_spk(&bob_sk),
        anchor_sk,
        anchor_spk: keypath_only_p2tr_spk(&anchor_sk),
    }
}

fn originate(
    node: &IsolatedRegtestNode,
    miner_addr: &str,
    k: &Keys,
    ann: &OracleAnnouncement,
    refund_delay_blocks: u32,
) -> Contract {
    let spec = InverseContractSpec::from_leverages_v0(NOTIONAL_USD, ENTRY_PRICE_USD, 20_000, 20_000)
        .expect("spec");
    let nb = ann.num_bits();
    let cets = compress_cet_ranges(&spec, nb, MAX_CET_ERROR_SATS).expect("cets");

    // Heights come from the plan command's arithmetic: the chain tip is placed one hour before maturity.
    let tip_height = node.height() as u32;
    let plan = compute_plan(&PlanParams {
        event_id: ann.event_id.clone(),
        maturity_unix: ann.maturity_unix,
        tip_height,
        tip_time: ann.maturity_unix - 3_600,
        block_secs: DEFAULT_BLOCK_SECS,
        attest_window_secs: DEFAULT_ATTEST_WINDOW_SECS,
        grace_blocks: DEFAULT_GRACE_BLOCKS,
        refund_delay_blocks,
        fast_factor: DEFAULT_FAST_FACTOR,
        min_gap_secs: DEFAULT_MIN_GAP_SECS,
        force: false,
    })
    .expect("plan within the wall-clock floor");

    // One outcome per compressed CET: representative price = midpoint of the range,
    // adaptor point = anticipation point of the CET's digit prefix.
    let table = ann.precompute_digit_points().expect("digit points");
    let outcomes: Vec<(u64, ProjectivePoint)> = cets
        .iter()
        .map(|c| {
            let pt = OracleAnnouncement::anticipation_point_from_table(&table, &c.prefix_bits)
                .expect("anticipation point");
            ((c.min_price_usd + c.max_price_usd) / 2, pt)
        })
        .collect();

    let alice_pk = pubkey_x_from_secret(&k.alice_sk).unwrap();
    let bob_pk = pubkey_x_from_secret(&k.bob_sk).unwrap();
    let tree = Mnr02TaprootTree::build(
        alice_pk,
        bob_pk,
        k.guard_pk,
        plan.maturity_height,
        plan.grace_blocks,
        plan.refund_delay_blocks,
    )
    .unwrap();
    let funding_sats = spec.long_margin_sats + spec.short_margin_sats;
    let (funding_txid, funding_vout) = node.fund_raw_script(&tree.script_pubkey, funding_sats);

    let pkg = build_origination_package(
        &k.alice_sk,
        &k.bob_sk,
        k.guard_pk,
        &funding_txid,
        funding_vout,
        spec.long_margin_sats,
        spec.short_margin_sats,
        NOTIONAL_USD,
        ENTRY_PRICE_USD,
        CET_FEE_SATS,
        plan.maturity_height,
        plan.grace_blocks,
        plan.refund_delay_blocks,
        k.alice_spk.clone(),
        k.bob_spk.clone(),
        k.anchor_spk.clone(),
        &outcomes,
    )
    .expect("origination package");
    node.mine_blocks(1, miner_addr);
    Contract { spec, cets, pkg, funding_txid, plan }
}

fn mine_to(node: &IsolatedRegtestNode, miner_addr: &str, target: u32) {
    let cur = node.height();
    assert!(target as u64 >= cur, "target {target} below tip {cur}");
    if target as u64 > cur {
        node.mine_blocks(target as u64 - cur, miner_addr);
    }
}

fn scenario_attested(node: &IsolatedRegtestNode, miner_addr: &str, k: &Keys, fx: &Fixture) -> Value {
    let ann = &fx.announcement;
    let att = &fx.attestation;
    att.verify_against(ann).expect("live attestation verifies against its announcement");
    let c = originate(node, miner_addr, k, ann, DEFAULT_REFUND_DELAY_BLOCKS);
    let nb = ann.num_bits();

    let cet = lookup_cet_for_price(&c.cets, att.price_usd, nb).expect("cet for attested price");
    let idx = c.cets.iter().position(|x| x == cet).unwrap();
    let t = att.secret_scalar_for_prefix(cet.prefix_bits.len()).unwrap();
    assert_eq!(
        ProjectivePoint::GENERATOR * t,
        ann.anticipation_point(&cet.prefix_bits).unwrap(),
        "attestation reveals the matching CET adaptor secret"
    );
    let tx = finalize_unilateral_fallback_tx(&c.pkg.tree, &c.pkg.outcomes[idx], &t)
        .expect("attestation completes the adaptor signatures of the matching CET");

    // A CET of a different price range cannot be completed with this attestation.
    let other = c.cets.iter().position(|x| !x.matches_price(att.price_usd, nb)).unwrap();
    assert!(
        finalize_unilateral_fallback_tx(&c.pkg.tree, &c.pkg.outcomes[other], &t).is_err(),
        "attestation must not complete a CET of another price range"
    );

    let hex_tx = hex::encode(tx.serialize_segwit());
    // Probe: unilateral CET is non-final before maturity + grace.
    mine_to(node, miner_addr, c.plan.unilateral_cltv_height - 1);
    let (early_ok, early_reason) = node.test_mempool_accept(&hex_tx);
    assert!(!early_ok, "unilateral CET must be non-final before maturity + grace");

    mine_to(node, miner_addr, c.plan.unilateral_cltv_height);
    let (ok, reason) = node.test_mempool_accept(&hex_tx);
    assert!(ok, "attested CET rejected by Core: {reason}");
    let txid = node.cli_raw(&["sendrawtransaction", &hex_tx]).unwrap();
    node.mine_blocks(1, miner_addr);
    let (height, outs) = onchain_outputs(node, &txid);

    // Output order: bob (short), alice (long), anchor. Alice pays the CET fee and anchor.
    let exact = c.spec.payout_at_price(att.price_usd);
    let fee_and_anchor = CET_FEE_SATS + DEFAULT_CPFP_ANCHOR_SATS;
    let tolerance = 2 * MAX_CET_ERROR_SATS + 2;
    let diff = |a: u64, b: u64| a.abs_diff(b);
    assert_eq!(outs.len(), 3);
    assert_eq!(outs[2], DEFAULT_CPFP_ANCHOR_SATS);
    assert!(
        diff(outs[0], exact.short_sats) <= tolerance,
        "short payout {} vs payout_at_price {}",
        outs[0],
        exact.short_sats
    );
    assert!(
        diff(outs[1] + fee_and_anchor, exact.long_sats) <= tolerance,
        "long payout {} + fee/anchor vs payout_at_price {}",
        outs[1],
        exact.long_sats
    );
    assert_eq!(outs[0] + outs[1] + outs[2] + CET_FEE_SATS, c.pkg.funding_sats);

    json!({
        "fixture": fx.name,
        "event_id": ann.event_id,
        "oracle_pubkey_x": hex::encode(ann.oracle_pubkey_x),
        "attested_price_usd": att.price_usd,
        "compressed_cet_count": c.cets.len(),
        "matching_cet": {
            "index": idx,
            "prefix_len": cet.prefix_bits.len(),
            "min_price_usd": cet.min_price_usd,
            "max_price_usd": cet.max_price_usd,
        },
        "plan": c.plan,
        "funding_txid": c.funding_txid,
        "premature_unilateral_cet": { "tip_height": c.plan.unilateral_cltv_height - 1, "accepted": early_ok, "reject_reason": early_reason },
        "settlement": TxPoint { txid, height, outputs_sats: outs.clone() },
        "settlement_path": "unilateral CET leaf completed with the live threshold attestation",
        "payout_at_price": { "long_sats": exact.long_sats, "short_sats": exact.short_sats },
        "onchain_payout": { "short_sats": outs[0], "long_sats_plus_fee_and_anchor": outs[1] + fee_and_anchor },
        "payout_tolerance_sats": tolerance,
    })
}

fn scenario_unattested(node: &IsolatedRegtestNode, miner_addr: &str, k: &Keys, fx: &Fixture) -> Value {
    let ann = &fx.announcement;
    // The attestation in this fixture is never used: the oracle is treated as having withheld it.
    // Any scalar from a different event cannot complete this contract's CET signatures.
    let c = originate(node, miner_addr, k, ann, DEFAULT_REFUND_DELAY_BLOCKS);
    let live = load_fixture("fixture_dlc_event_live.json");
    let cet = lookup_cet_for_price(&c.cets, live.attestation.price_usd, ann.num_bits()).unwrap();
    let idx = c.cets.iter().position(|x| x == cet).unwrap();
    let foreign_t = live.attestation.secret_scalar_for_prefix(cet.prefix_bits.len()).unwrap();
    let foreign_rejected =
        finalize_unilateral_fallback_tx(&c.pkg.tree, &c.pkg.outcomes[idx], &foreign_t).is_err();
    assert!(foreign_rejected, "another event's attestation must not settle this contract");

    // Bump UTXO for the CPFP child, funded under the anchor key.
    let (bump_txid, bump_vout) = node.fund_raw_script(&k.anchor_spk, 50_000);
    node.mine_blocks(1, miner_addr);

    let refund_height = c.plan.refund_cltv_height;
    let refund_hex = hex::encode(c.pkg.signed_refund_tx.serialize_segwit());
    let refund_txid = c.pkg.signed_refund_tx.txid_hex();

    // Past maturity + grace with no attestation: nothing but the refund can spend the funding output.
    mine_to(node, miner_addr, c.plan.unilateral_cltv_height + 1);

    // (i) Premature refund rejected: a height lock N is final once the tip is at N, so tip N-1 is non-final.
    mine_to(node, miner_addr, refund_height - 1);
    let premature_tip = node.height();
    let (early_ok, early_reason) = node.test_mempool_accept(&refund_hex);
    assert!(!early_ok, "refund must be rejected before its CLTV height");
    assert!(
        early_reason.contains("non-final") || early_reason.to_lowercase().contains("locktime"),
        "unexpected premature-refund reason: {early_reason}"
    );

    // (ii) At the refund height the pre-signed refund is accepted and confirms.
    mine_to(node, miner_addr, refund_height);
    let (ok, reason) = node.test_mempool_accept(&refund_hex);
    assert!(ok, "refund rejected at its CLTV height: {reason}");
    let sent = node.cli_raw(&["sendrawtransaction", &refund_hex]).unwrap();
    assert_eq!(sent, refund_txid);

    // (iii) CPFP child spends the 330-sat anchor plus the bump UTXO.
    let mut child = SegwitTx {
        version: 2,
        inputs: vec![
            SegwitTxIn::from_display_txid(&refund_txid, 2, 0xfffffffe, DEFAULT_CPFP_ANCHOR_SATS, k.anchor_spk.clone()).unwrap(),
            SegwitTxIn::from_display_txid(&bump_txid, bump_vout, 0xfffffffe, 50_000, k.anchor_spk.clone()).unwrap(),
        ],
        outputs: vec![(45_330, k.anchor_spk.clone())],
        locktime: 0,
    };
    for i in 0..2 {
        let sh = child.bip341_sighash(i, SIGHASH_DEFAULT, None).unwrap();
        let sig = bip340_sign(&k.anchor_sk, &sh).unwrap();
        child.inputs[i].witness = vec![encode_taproot_witness_sig(&sig, SIGHASH_DEFAULT)];
    }
    let child_hex = hex::encode(child.serialize_segwit());
    let (cpfp_ok, cpfp_reason) = node.test_mempool_accept(&child_hex);
    assert!(cpfp_ok, "CPFP child rejected: {cpfp_reason}");
    let child_txid = node.cli_raw(&["sendrawtransaction", &child_hex]).unwrap();
    let mempool = node.cli_json(&["getmempoolentry", &child_txid]);
    let ancestors = mempool["ancestorcount"].as_u64().unwrap();
    node.mine_blocks(1, miner_addr);
    let (refund_conf_height, refund_outs) = onchain_outputs(node, &refund_txid);
    let (child_conf_height, child_outs) = onchain_outputs(node, &child_txid);
    assert_eq!(refund_conf_height, child_conf_height, "parent and CPFP child confirm together");
    assert_eq!(refund_conf_height, refund_height as u64 + 1);

    // (iv) Each party gets margin minus half of the shared fee and anchor.
    let half = (CET_FEE_SATS + DEFAULT_CPFP_ANCHOR_SATS) / 2;
    assert_eq!(refund_outs, vec![c.spec.short_margin_sats - half, c.spec.long_margin_sats - half, DEFAULT_CPFP_ANCHOR_SATS]);
    assert_eq!(refund_outs.iter().sum::<u64>() + CET_FEE_SATS, c.pkg.funding_sats);

    json!({
        "fixture": fx.name,
        "event_id": ann.event_id,
        "attestation_used": false,
        "foreign_attestation_rejected": foreign_rejected,
        "compressed_cet_count": c.cets.len(),
        "plan": c.plan,
        "funding_txid": c.funding_txid,
        "premature_refund": { "tip_height": premature_tip, "refund_cltv_height": refund_height, "accepted": early_ok, "reject_reason": early_reason },
        "refund": TxPoint { txid: refund_txid.clone(), height: refund_conf_height, outputs_sats: refund_outs },
        "cpfp_child": { "txid": child_txid, "height": child_conf_height, "outputs_sats": child_outs, "mempool_ancestor_count": ancestors },
        "refund_returns": { "bob_short_margin_sats": c.spec.short_margin_sats, "alice_long_margin_sats": c.spec.long_margin_sats, "each_party_deduction_sats": half },
    })
}

pub fn run_dlc_oracle_regtest(bitcoind_path: &Path) -> Value {
    let core_version = String::from_utf8_lossy(
        &Command::new(bitcoind_path).arg("-version").output().expect("bitcoind -version").stdout,
    )
    .lines()
    .next()
    .unwrap_or("Bitcoin Core")
    .trim()
    .to_string();

    let live = load_fixture("fixture_dlc_event_live.json");
    let unattested = load_fixture("fixture_dlc_event.json");
    let k = keys();

    let node = IsolatedRegtestNode::spawn(bitcoind_path);
    node.cli_raw(&["createwallet", "miner"]).unwrap();
    let miner_addr = node.cli_raw(&["getnewaddress"]).unwrap();
    node.mine_blocks(105, &miner_addr);

    let a = scenario_attested(&node, &miner_addr, &k, &live);
    let b = scenario_unattested(&node, &miner_addr, &k, &unattested);

    json!({
        "issue": "SHZ-HFT-06: threshold DLC oracle events on MNR-02 contracts (attested settlement, unattested refund)",
        "core_version": core_version,
        "network": "regtest",
        "scenario_a_attested": a,
        "scenario_b_unattested": b,
    })
}
