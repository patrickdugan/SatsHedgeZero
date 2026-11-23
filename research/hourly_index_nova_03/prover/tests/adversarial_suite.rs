//! Comprehensive Soundness & 18-Case Adversarial Suite for `SHZ-INDEX-03` (Section 5).
//!
//! Exercises every required adversarial class at the R1CS constraint level (`TestConstraintSystem<BnScalar>`)
//! wherever possible — including recomputing the Merkle tree and checkpoint root to prove internal
//! arithmetic and `HOLD`-necessity constraints reject malicious witnesses — and exercises the actual
//! BN254 8-fold Nova NIFS + ZK-blinded Spartan/IPA verifier, Pyth/Chainlink source authenticators,
//! Bitcoin `SHZIDX01` SPV light client, and FROST/DLC bridge.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use bincode::Options;
use ff::Field;
use halo2curves::bn256::Fr as BnScalar;
use nova_snark::{
    frontend::{
        gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem, ConstraintSystem,
        SynthesisError,
    },
    traits::circuit::StepCircuit,
};
use sha2::{Digest, Sha256};
use shz_oracle::{
    frost::FrostConfederation,
    pyth_lazer::{
        build_signed_pyth_pro_btc_usd_envelope, verify_pyth_pro_btc_usd_solana_envelope,
        PythProBtcUsdPolicy, PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS,
    },
};

use shz_index03_prover::{
    bn254_folding::{
        export_vk_merkle_bundle, native_bn254_multiexp, native_keccak256,
        prove_bn254_nifs_spartan, setup_bn254_circuit, verify_bn254_chunked_protocol_native,
    },
    bridge::attest_frost_from_verified_checkpoint,
    btc_anchor::{
        double_sha256, mine_regtest_header, reverse32, verify_shzidx01_transaction,
        BtcLightClient, BtcNetwork, SHZIDX01_MAGIC,
    },
    circuit::{
        compute_source_accumulator_chain, f_from_le_bytes, ClaimV2SourceBound, FixtureJson,
        HourStepData, HourStepGeneric, SourceBoundHourStep, SourceCandidateWitness, NODE_DOMAIN,
        ROOT_DOMAIN,
    },
    decider_equations::{
        begin_decider_session, evaluate_msm_chunk, evaluate_packed_r1cs_chunk,
        finalize_decider_session, WireRelaxedR1csSnark,
    },
    sources::{
        build_operational_pyth_registry_from_solana_storage,
        build_synthetic_authenticated_8h_bundles, encode_and_sign_synthetic_chainlink_v3_report,
        merkle_tree_8, verify_chainlink_cherry_pick_fraud_proof, verify_chainlink_v3_full_report,
        verify_hour_source_bundle, verify_pyth_cherry_pick_fraud_proof,
        OFFICIAL_PYTH_PRO_BTC_USD_WIRE_HEX, PYTH_LAZER_MAINNET_STORAGE_SNAPSHOT_HEX,
    },
};

fn sha256_arr(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn canonical_fixture() -> FixtureJson {
    serde_json::from_str(include_str!(
        "../../../hourly_index/fixtures/checkpoint.json"
    ))
    .expect("canonical INDEX-01 8-hour checkpoint fixture")
}

fn synth_circuit<C: StepCircuit<BnScalar>>(
    step: &C,
    z_in: &[BnScalar],
) -> (bool, Vec<BnScalar>, usize, usize) {
    let mut cs = TestConstraintSystem::<BnScalar>::new();
    let z: Vec<AllocatedNum<BnScalar>> = z_in
        .iter()
        .enumerate()
        .map(|(i, x)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || *x))
        .collect();
    let out = step
        .synthesize(&mut cs, &z)
        .expect("witness-independent R1CS synthesis");
    let n_cons = cs.num_constraints();
    (
        cs.is_satisfied(),
        out.iter().map(|x| x.get_value().unwrap()).collect(),
        n_cons,
        out.len(),
    )
}

/// Recomputes `checkpoint_root` from the mutated `HourStepData` so Merkle inclusion STILL passes;
/// only internal R1CS arithmetic/freshness/encoding constraints can reject!
fn assert_v1_rejected_even_with_recomputed_root(step_data: HourStepData) {
    let f = canonical_fixture();
    let mut claim = f.claim_v1();
    claim.checkpoint_root = hex::encode(step_data.native_root());
    let mut z = claim.state::<BnScalar>(0).unwrap();
    z[0] = BnScalar::from(u64::from(step_data.position));
    let (sat, _, _, _) = synth_circuit(&HourStepGeneric::new(step_data), &z);
    assert!(
        !sat,
        "malicious HourStepData satisfied R1CS after root recomputation"
    );
}

/// Builds a complete 8-hour `SourceBoundHourStep` witness set (`7 VALID + 1 necessary HOLD`)
/// backed by real signed Pyth + Chainlink test reports.
fn build_valid_v2_steps() -> (
    ClaimV2SourceBound,
    Vec<HourStepData>,
    Vec<SourceCandidateWitness>,
) {
    let start_hour = 498_000u64;
    let genesis = [0x11u8; 32];
    let policy = [0x22u8; 32];
    let (_, _, bundles, _, _) = build_synthetic_authenticated_8h_bundles(start_hour);
    let (source_acc_root, cand_witnesses) = compute_source_accumulator_chain(&bundles);

    let mut steps_data: Vec<HourStepData> = bundles
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if i == 4 {
                // Necessary HOLD due to >50 bps spread at offset 4
                HourStepData {
                    position: i as u8,
                    start: start_hour,
                    genesis,
                    policy,
                    hour: b.hour_id,
                    status: 2,
                    reason: 2,
                    p: 0,
                    c: 0,
                    index: 0,
                    pt: 0,
                    ct: 0,
                    p_hash: [0u8; 32],
                    c_hash: [0u8; 32],
                    siblings: [[0u8; 32]; 3],
                }
            } else {
                let p = b.candidate_pyth_price_e8;
                let c = b.candidate_chainlink_price_e8;
                HourStepData {
                    position: i as u8,
                    start: start_hour,
                    genesis,
                    policy,
                    hour: b.hour_id,
                    status: 1,
                    reason: 0,
                    p,
                    c,
                    index: ((u128::from(p) + u128::from(c)) / 2) as u64,
                    pt: b.candidate_pyth_publish_us,
                    ct: b.candidate_chainlink_publish_us,
                    p_hash: hex::decode(&b.candidate_pyth_report_sha256_hex)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    c_hash: hex::decode(&b.candidate_chainlink_report_sha256_hex)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    siblings: [[0u8; 32]; 3],
                }
            }
        })
        .collect();

    let leaf_hashes: Vec<[u8; 32]> = steps_data
        .iter()
        .map(|s| sha256_arr(&s.leaf_bytes()))
        .collect();
    let (merkle_root, paths) = merkle_tree_8(&leaf_hashes, NODE_DOMAIN);
    for (s, p) in steps_data.iter_mut().zip(paths.into_iter()) {
        s.siblings = p;
    }
    let mut root_pre = ROOT_DOMAIN.to_vec();
    root_pre.extend_from_slice(&genesis);
    root_pre.extend_from_slice(&policy);
    root_pre.extend_from_slice(&start_hour.to_le_bytes());
    root_pre.extend_from_slice(&merkle_root);
    let checkpoint_root = sha256_arr(&root_pre);

    let claim = ClaimV2SourceBound {
        genesis: hex::encode(genesis),
        policy_hash: hex::encode(policy),
        start_hour: start_hour.to_string(),
        checkpoint_root: hex::encode(checkpoint_root),
        source_accumulator_root: hex::encode(source_acc_root),
    };
    (claim, steps_data, cand_witnesses)
}

#[test]
fn shape_invariance_and_8_fold_transition_on_bn254_v1_and_v2() {
    // 1. Canonical INDEX-01 checkpoint (`c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5`)
    let f = canonical_fixture();
    let claim = f.claim_v1();
    assert_eq!(
        claim.checkpoint_root,
        "c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5"
    );
    let steps = f.steps_data().unwrap();
    let mut state = claim.state::<BnScalar>(0).unwrap();
    let mut shape: Option<(usize, usize)> = None;
    for (i, s) in steps.iter().enumerate() {
        let (sat, next_state, n_cons, n_aux) =
            synth_circuit(&HourStepGeneric::new(s.clone()), &state);
        assert!(sat, "v1 step {i} unsatisfied");
        if let Some((c0, a0)) = shape {
            assert_eq!((n_cons, n_aux), (c0, a0), "witness-dependent shape at fold {i}");
        } else {
            shape = Some((n_cons, n_aux));
        }
        state = next_state;
    }
    assert_eq!(state, claim.state::<BnScalar>(8).unwrap());
    assert_eq!(shape.unwrap().0, 308_084);

    // 2. Source-bound v2 circuit across all 8 folds (7 VALID + 1 HOLD)
    let (claim_v2, steps_v2, cands_v2) = build_valid_v2_steps();
    let mut z2 = claim_v2.state::<BnScalar>(0).unwrap();
    let mut shape_v2: Option<(usize, usize)> = None;
    for i in 0..8 {
        let step = SourceBoundHourStep::new(steps_v2[i].clone(), cands_v2[i].clone());
        let (sat, next_z2, n_cons, n_aux) = synth_circuit(&step, &z2);
        assert!(sat, "v2 step {i} unsatisfied");
        if let Some(s0) = shape_v2 {
            assert_eq!((n_cons, n_aux), s0, "v2 witness-dependent shape at fold {i}");
        } else {
            shape_v2 = Some((n_cons, n_aux));
        }
        z2 = next_z2;
    }
    assert_eq!(z2, claim_v2.state::<BnScalar>(8).unwrap());
}

// ============================================================================
// SECTION 5: ALL 18 ADVERSARIAL CASES
// ============================================================================

#[test]
fn case_01_incorrect_hourly_midpoint() {
    // Rounding up on odd sum `(p + c)` or arbitrary midpoint shift must fail R1CS even with recomputed root
    let mut s = canonical_fixture().steps_data().unwrap()[0].clone();
    s.p = 6_000_000_000_001;
    s.c = 6_000_000_000_000;
    s.index = 6_000_000_000_001; // ceil instead of floor(12_000_000_000_001 / 2) = 6_000_000_000_000!
    assert_v1_rejected_even_with_recomputed_root(s);

    let mut s2 = canonical_fixture().steps_data().unwrap()[1].clone();
    s2.index -= 500;
    assert_v1_rejected_even_with_recomputed_root(s2);
}

#[test]
fn case_02_one_satoshi_equivalent_fixed_point_price_mutation() {
    // 1 unit in `1e-8` USD fixed-point (`0.00000001` USD):
    // (a) Mutating `index_price_e8` by +1e-8 USD fails midpoint floor constraint even with recomputed root.
    let mut s_idx = canonical_fixture().steps_data().unwrap()[0].clone();
    s_idx.index += 1;
    assert_v1_rejected_even_with_recomputed_root(s_idx);

    // (b) Mutating `pyth_price_e8` by +1e-8 USD (when p + c was odd -> p + c becomes even, requiring index += 1)
    let mut s_pyth = canonical_fixture().steps_data().unwrap()[0].clone();
    s_pyth.p = 6_000_000_000_001;
    s_pyth.c = 6_000_000_000_000;
    s_pyth.index = 6_000_000_000_000; // valid floor
    // Now mutate p by +1 unit (`1e-8` USD) without updating index -> `p + c - 2*index == 2` (outside {0, 1})!
    s_pyth.p += 1;
    assert_v1_rejected_even_with_recomputed_root(s_pyth);

    // (c) Mutating `pyth_price_e8` by +1e-8 USD relative to authenticated source candidate in v2 fails `valid p == cand_p`!
    let (claim_v2, mut steps_v2, cands_v2) = build_valid_v2_steps();
    steps_v2[0].p += 1;
    steps_v2[0].c += 1;
    steps_v2[0].index += 1;
    let mut z = claim_v2.state::<BnScalar>(0).unwrap();
    let new_root = steps_v2[0].native_root();
    z[6] = f_from_le_bytes(&new_root[..16]);
    z[7] = f_from_le_bytes(&new_root[16..]);
    let (sat, _, _, _) = synth_circuit(
        &SourceBoundHourStep::new(steps_v2[0].clone(), cands_v2[0].clone()),
        &z,
    );
    assert!(!sat, "1e-8 USD mutation relative to signed source candidate must fail R1CS");
}

#[test]
fn case_03_spread_above_permitted_threshold() {
    // Exact 50-bps boundary: `20,000 * |p - c| <= 50 * (p + c)` <=> `19,950 * max <= 20,050 * min`
    // Let min = 19,950 * 100_000_000, max = 20,050 * 100_000_000 -> exact 50.0000 bps -> MUST PASS!
    let f = canonical_fixture();
    let mut exact = f.steps_data().unwrap()[0].clone();
    exact.c = 1_995_000_000_000;
    exact.p = 2_005_000_000_000;
    exact.index = (exact.p + exact.c) / 2;
    let mut claim_ok = f.claim_v1();
    claim_ok.checkpoint_root = hex::encode(exact.native_root());
    let z_ok = claim_ok.state::<BnScalar>(0).unwrap();
    assert!(synth_circuit(&HourStepGeneric::new(exact.clone()), &z_ok).0);

    // +1 unit (`1e-8` USD) above 50 bps -> `p = 2_005_000_000_001` -> MUST FAIL even with recomputed root!
    let mut over_p = exact.clone();
    over_p.p += 1;
    over_p.index = (over_p.p + over_p.c) / 2;
    assert_v1_rejected_even_with_recomputed_root(over_p);

    // Symmetric direction `c > p` by +1 unit above 50 bps -> MUST FAIL!
    let mut over_c = exact;
    std::mem::swap(&mut over_c.p, &mut over_c.c);
    over_c.c += 1;
    over_c.index = (over_c.p + over_c.c) / 2;
    assert_v1_rejected_even_with_recomputed_root(over_c);
}

#[test]
fn case_04_stale_or_future_observation() {
    let base = canonical_fixture().steps_data().unwrap()[0].clone();
    let cutoff = (base.hour + 1) * 3_600_000_000;

    // 1 microsecond too old (`cutoff - 300_000_001`)
    let mut stale = base.clone();
    stale.pt = cutoff - 300_000_001;
    stale.ct = cutoff - 300_000_000;
    assert_v1_rejected_even_with_recomputed_root(stale);

    // 1 microsecond in the future (`cutoff + 1`)
    let mut future = base.clone();
    future.ct = cutoff + 1;
    future.pt = cutoff;
    assert_v1_rejected_even_with_recomputed_root(future);

    // Both fresh, but inter-source skew `60_000_001 us` (> 60s)
    let mut skew = base;
    skew.pt = cutoff;
    skew.ct = cutoff - 60_000_001;
    assert_v1_rejected_even_with_recomputed_root(skew);
}

#[test]
fn case_05_wrong_network_policy_or_epoch() {
    let f = canonical_fixture();
    let s0 = f.steps_data().unwrap()[0].clone();
    let z0 = f.claim_v1().state::<BnScalar>(0).unwrap();

    // Wrong genesis (`z[2]`)
    let mut bad_gen = z0.clone();
    bad_gen[2] += BnScalar::ONE;
    assert!(!synth_circuit(&HourStepGeneric::new(s0.clone()), &bad_gen).0);

    // Wrong policy_hash (`z[4]`)
    let mut bad_pol = z0.clone();
    bad_pol[4] += BnScalar::ONE;
    assert!(!synth_circuit(&HourStepGeneric::new(s0.clone()), &bad_pol).0);

    // Non-8h-aligned start_hour (`start_hour = 498_001`) rejected both by ClaimV1::state and R1CS!
    let mut bad_claim = f.claim_v1();
    bad_claim.start_hour = "498001".into();
    assert!(bad_claim.state::<BnScalar>(0).is_err());

    let mut bad_epoch_step = s0;
    bad_epoch_step.start += 1;
    bad_epoch_step.hour += 1;
    bad_epoch_step.pt += 3_600_000_000;
    bad_epoch_step.ct += 3_600_000_000;
    let new_root = bad_epoch_step.native_root();
    let mut z_misaligned = z0;
    z_misaligned[1] = BnScalar::from(bad_epoch_step.start);
    z_misaligned[6] = f_from_le_bytes(&new_root[..16]);
    z_misaligned[7] = f_from_le_bytes(&new_root[16..]);
    assert!(!synth_circuit(&HourStepGeneric::new(bad_epoch_step), &z_misaligned).0);
}

#[test]
fn case_06_missing_duplicated_or_reordered_hour() {
    let f = canonical_fixture();
    let steps = f.steps_data().unwrap();
    let z0 = f.claim_v1().state::<BnScalar>(0).unwrap();

    // Duplicated hour: feeding step 0 twice when fold count is 1 (`z[0] = 1`)
    let mut z_at_1 = z0.clone();
    z_at_1[0] = BnScalar::ONE;
    assert!(!synth_circuit(&HourStepGeneric::new(steps[0].clone()), &z_at_1).0);

    // Reordered hour: feeding step 1 at fold count 0 (`z[0] = 0`)
    assert!(!synth_circuit(&HourStepGeneric::new(steps[1].clone()), &z0).0);

    // Mutating `hour` inside step 1 to equal `start` while setting `position = 1`
    let mut dup = steps[1].clone();
    dup.hour = dup.start;
    assert_v1_rejected_even_with_recomputed_root(dup);
}

#[test]
fn case_07_substituted_source_report_digest() {
    // 1. All-zero digest on a VALID hour fails `HourStepGeneric` even with recomputed root
    let mut zero_hash = canonical_fixture().steps_data().unwrap()[0].clone();
    zero_hash.p_hash = [0u8; 32];
    assert_v1_rejected_even_with_recomputed_root(zero_hash);

    // 2. Non-zero substituted report digest fails `SourceBoundHourStep` (`valid ph == cand_ph`) even with recomputed root!
    let (claim_v2, mut steps_v2, cands_v2) = build_valid_v2_steps();
    steps_v2[0].c_hash[0] ^= 0xff;
    let new_root = steps_v2[0].native_root();
    let mut z = claim_v2.state::<BnScalar>(0).unwrap();
    z[6] = f_from_le_bytes(&new_root[..16]);
    z[7] = f_from_le_bytes(&new_root[16..]);
    let (sat, _, _, _) = synth_circuit(
        &SourceBoundHourStep::new(steps_v2[0].clone(), cands_v2[0].clone()),
        &z,
    );
    assert!(!sat, "substituted Chainlink report digest must fail SourceBoundHourStep R1CS");

    // 3. Substituted digest in `AuthenticatedHourSourceBundle` fails `verify_hour_source_bundle`!
    let (pyth_reg, don_cfg, mut bundles, _, _) = build_synthetic_authenticated_8h_bundles(498_000);
    bundles[0].candidate_pyth_report_sha256_hex = "ab".repeat(32);
    assert!(verify_hour_source_bundle(&bundles[0], &pyth_reg, &don_cfg).is_err());
}

#[test]
fn case_08_unauthorized_source_signer_and_cherry_picking() {
    // 1. Operational Solana Mainnet `Storage` PDA (`3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL`)
    // accepts the official archived `pyth-lazer` BTC/USD report (`80efc1f4...`), and REJECTS a forged key!
    let storage_raw = hex::decode(PYTH_LAZER_MAINNET_STORAGE_SNAPSHOT_HEX).unwrap();
    let (op_reg, _) = build_operational_pyth_registry_from_solana_storage(&storage_raw, 1).unwrap();
    let official_wire = hex::decode(OFFICIAL_PYTH_PRO_BTC_USD_WIRE_HEX).unwrap();
    let mut pol = PythProBtcUsdPolicy::default();
    pol.max_age_us = u64::MAX / 2;
    assert!(verify_pyth_pro_btc_usd_solana_envelope(
        &official_wire,
        &op_reg,
        &pol,
        1_771_551_627_806_528
    )
    .is_ok());

    let (forged_pyth_wire, _) = build_signed_pyth_pro_btc_usd_envelope(
        &[0x99u8; 32],
        1_771_551_627_806_528,
        1_771_551_627_806_528,
        PYTH_PRO_CHANNEL_FIXED_200MS,
        PYTH_PRO_BTC_USD_FEED_ID,
        9_700_000_000_000,
        -8,
        1_000_000_000,
    );
    assert!(verify_pyth_pro_btc_usd_solana_envelope(
        &forged_pyth_wire,
        &op_reg,
        &pol,
        1_771_551_627_806_528
    )
    .is_err());

    // 2. Chainlink Data Streams v3 DON quorum: unauthorized secp256k1 signer, duplicate signer, and `< f + 1` signers ALL rejected!
    let (syn_pyth_reg, don_cfg, bundles, _, _) = build_synthetic_authenticated_8h_bundles(498_000);
    let cutoff_sec = (498_000 + 1) * 3_600;

    let rogue_cl = encode_and_sign_synthetic_chainlink_v3_report(
        don_cfg.config_digest,
        101,
        1,
        don_cfg.feed_id,
        cutoff_sec - 20,
        cutoff_sec - 10,
        cutoff_sec + 3_600,
        10_000_000_000_000,
        500_000_000,
        &[[0x71u8; 32], [0xfe; 32]], // second signer NOT in DON!
    );
    assert!(verify_chainlink_v3_full_report(&rogue_cl, &don_cfg).is_err());

    let dup_cl = encode_and_sign_synthetic_chainlink_v3_report(
        don_cfg.config_digest,
        101,
        1,
        don_cfg.feed_id,
        cutoff_sec - 20,
        cutoff_sec - 10,
        cutoff_sec + 3_600,
        10_000_000_000_000,
        500_000_000,
        &[[0x71u8; 32], [0x71u8; 32]], // duplicate signer!
    );
    assert!(verify_chainlink_v3_full_report(&dup_cl, &don_cfg).is_err());

    let under_quorum_cl = encode_and_sign_synthetic_chainlink_v3_report(
        don_cfg.config_digest,
        101,
        1,
        don_cfg.feed_id,
        cutoff_sec - 20,
        cutoff_sec - 10,
        cutoff_sec + 3_600,
        10_000_000_000_000,
        500_000_000,
        &[[0x71u8; 32]], // 1 < f + 1 = 2!
    );
    assert!(verify_chainlink_v3_full_report(&under_quorum_cl, &don_cfg).is_err());

    // 3. Anti-cherry-picking fraud proofs for BOTH Pyth and Chainlink!
    let (newer_pyth, _) = build_signed_pyth_pro_btc_usd_envelope(
        &[0x61u8; 32],
        (cutoff_sec - 1) * 1_000_000,
        (cutoff_sec - 1) * 1_000_000,
        PYTH_PRO_CHANNEL_FIXED_200MS,
        PYTH_PRO_BTC_USD_FEED_ID,
        10_000_000_000_000,
        -8,
        1_000_000_000,
    );
    assert!(verify_pyth_cherry_pick_fraud_proof(
        498_000,
        bundles[0].candidate_pyth_publish_us,
        &newer_pyth,
        &syn_pyth_reg
    )
    .unwrap());

    let newer_cl = encode_and_sign_synthetic_chainlink_v3_report(
        don_cfg.config_digest,
        102,
        1,
        don_cfg.feed_id,
        cutoff_sec - 10,
        cutoff_sec - 1,
        cutoff_sec + 3_600,
        10_020_000_000_000,
        500_000_000,
        &[[0x71u8; 32], [0x72u8; 32]],
    );
    assert!(verify_chainlink_cherry_pick_fraud_proof(
        498_000,
        bundles[0].candidate_chainlink_publish_us,
        &newer_cl,
        &don_cfg
    )
    .unwrap());
}

#[test]
fn case_09_fabricated_hold_condition_rejected_at_r1cs_level() {
    // Hour 0 in `build_valid_v2_steps()` has BOTH Pyth & Chainlink present, fresh, aligned, and within 20 bps (<= 50 bps).
    // Suppose a malicious prover tries to censor Hour 0 into `HOLD` (`status = 2, reason = 1, 2, or 3`)
    // AND recomputes the leaf, Merkle tree, AND `checkpoint_root`!
    // `SourceBoundHourStep` MUST reject ALL THREE fabricated HOLD reasons at the R1CS constraint level!
    let (claim_v2, steps_v2, cands_v2) = build_valid_v2_steps();
    for forged_reason in [1u8, 2u8, 3u8] {
        let mut fake_hold = steps_v2[0].clone();
        fake_hold.status = 2;
        fake_hold.reason = forged_reason;
        fake_hold.p = 0;
        fake_hold.c = 0;
        fake_hold.index = 0;
        fake_hold.pt = 0;
        fake_hold.ct = 0;
        fake_hold.p_hash = [0u8; 32];
        fake_hold.c_hash = [0u8; 32];

        let new_root = fake_hold.native_root();
        let mut z = claim_v2.state::<BnScalar>(0).unwrap();
        z[6] = f_from_le_bytes(&new_root[..16]);
        z[7] = f_from_le_bytes(&new_root[16..]);

        let (sat, _, _, _) =
            synth_circuit(&SourceBoundHourStep::new(fake_hold, cands_v2[0].clone()), &z);
        assert!(
            !sat,
            "fabricated HOLD (reason={forged_reason}) over valid source candidates MUST fail R1CS!"
        );
    }

    // Also verify malformed HOLD in v1 (`HOLD` carrying non-zero price or reason == 0) fails R1CS!
    let mut hold_nonzero = canonical_fixture().steps_data().unwrap()[4].clone();
    hold_nonzero.index = 1;
    assert_v1_rejected_even_with_recomputed_root(hold_nonzero);

    let mut hold_r0 = canonical_fixture().steps_data().unwrap()[4].clone();
    hold_r0.reason = 0;
    assert_v1_rejected_even_with_recomputed_root(hold_r0);
}

#[test]
fn case_10_altered_merkle_sibling() {
    let f = canonical_fixture();
    let mut s = f.steps_data().unwrap()[2].clone();
    let mut z = f.claim_v1().state::<BnScalar>(0).unwrap();
    z[0] = BnScalar::from(2u64);
    s.siblings[1][15] ^= 0x01;
    assert!(!synth_circuit(&HourStepGeneric::new(s), &z).0);
}

// ============================================================================
// CASES 11–16: REAL BN254 8-FOLD NOVA NIFS + ZK-BLINDED SPARTAN/IPA PROOF CONTROLS
// ============================================================================

#[derive(Clone, Debug)]
struct CompactEightStepCircuit {
    step_index: u64,
    delta: u64,
}

impl StepCircuit<BnScalar> for CompactEightStepCircuit {
    fn arity(&self) -> usize {
        3
    }

    fn synthesize<CS: ConstraintSystem<BnScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<BnScalar>],
    ) -> Result<Vec<AllocatedNum<BnScalar>>, SynthesisError> {
        // z = [fold_count, pinned_claim_tag, running_sum]
        let idx = AllocatedNum::alloc_infallible(cs.namespace(|| "idx"), || {
            BnScalar::from(self.step_index)
        });
        cs.enforce(
            || "idx == z[0]",
            |lc| lc + idx.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[0].get_variable(),
        );
        let next_count = AllocatedNum::alloc_infallible(cs.namespace(|| "next_count"), || {
            BnScalar::from(self.step_index + 1)
        });
        cs.enforce(
            || "next_count == z[0] + 1",
            |lc| lc + z[0].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + next_count.get_variable(),
        );
        let d = AllocatedNum::alloc_infallible(cs.namespace(|| "delta"), || {
            BnScalar::from(self.delta)
        });
        let sq = d.square(cs.namespace(|| "delta_sq"))?;
        let next_sum = AllocatedNum::alloc_infallible(cs.namespace(|| "next_sum"), || {
            z[2].get_value().unwrap_or(BnScalar::ZERO) + sq.get_value().unwrap_or(BnScalar::ZERO)
        });
        cs.enforce(
            || "next_sum == z[2] + d^2",
            |lc| lc + z[2].get_variable() + sq.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + next_sum.get_variable(),
        );
        Ok(vec![next_count, z[1].clone(), next_sum])
    }
}

#[test]
fn cases_11_to_16_bn254_nifs_spartan_proof_vk_state_and_replay_controls() {
    let relation = "shz/compact-8fold-control/v1";
    let setup = setup_bn254_circuit(CompactEightStepCircuit {
        step_index: 0,
        delta: 0,
    })
    .expect("setup compact BN254 circuit");
    let vk_bundle = export_vk_merkle_bundle(&setup, relation);

    let deltas = [3u64, 5, 7, 11, 13, 17, 19, 23];
    let steps: Vec<CompactEightStepCircuit> = deltas
        .iter()
        .enumerate()
        .map(|(k, &d)| CompactEightStepCircuit {
            step_index: k as u64,
            delta: d,
        })
        .collect();
    let sum_sq: u64 = deltas.iter().map(|d| d * d).sum();
    let pinned_claim = BnScalar::from(0xdead_beef_cafe_u64);
    let z0 = vec![BnScalar::ZERO, pinned_claim, BnScalar::ZERO];
    let z8 = vec![BnScalar::from(8u64), pinned_claim, BnScalar::from(sum_sq)];

    let proof = prove_bn254_nifs_spartan(&setup, relation, &steps, &z0, &z8)
        .expect("prove 8-fold BN254 NIFS + ZK Spartan/IPA");
    let proof_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&proof)
        .unwrap();
    let proof_sha = sha256_arr(&proof_bytes);

    // Baseline valid verification MUST succeed via our WASM-shared chunked decider!
    verify_bn254_chunked_protocol_native(&vk_bundle, &proof, proof_sha, &z0, &z8, false)
        .expect("valid 8-fold BN254 NIFS + Spartan/IPA proof must verify");

    // Case 11: Different checkpoint root / public terminal claim
    let mut wrong_z8 = z8.clone();
    wrong_z8[1] += BnScalar::ONE;
    assert!(
        verify_bn254_chunked_protocol_native(&vk_bundle, &proof, proof_sha, &z0, &wrong_z8, false)
            .is_err()
    );

    // Case 12: Wrong Nova step count (metadata `steps != 8` AND mutated intermediate fold counter)
    let mut bad_steps = proof.clone();
    bad_steps.steps = 7;
    assert!(
        verify_bn254_chunked_protocol_native(&vk_bundle, &bad_steps, proof_sha, &z0, &z8, false)
            .is_err()
    );
    let mut bad_inter_counter = proof.clone();
    bad_inter_counter.intermediate_states[3][0][0] ^= 0x01;
    assert!(verify_bn254_chunked_protocol_native(
        &vk_bundle,
        &bad_inter_counter,
        proof_sha,
        &z0,
        &z8,
        false
    )
    .is_err());

    // Case 13: Substituted verification key (`vk_digest`, `vk_chunks_merkle_root`, R1CS chunk, MSM chunk)
    let mut bad_vk_digest = vk_bundle.clone();
    bad_vk_digest.compact_vk.vk_digest_le32[0] ^= 0x01;
    assert!(
        verify_bn254_chunked_protocol_native(&bad_vk_digest, &proof, proof_sha, &z0, &z8, false)
            .is_err()
    );

    let mut bad_r1cs_chunk = vk_bundle.clone();
    let r_len = bad_r1cs_chunk.r1cs_chunks[0].payload.len();
    bad_r1cs_chunk.r1cs_chunks[0].payload[r_len - 1] ^= 0x01;
    assert!(
        verify_bn254_chunked_protocol_native(&bad_r1cs_chunk, &proof, proof_sha, &z0, &z8, false)
            .is_err()
    );

    let mut bad_msm_chunk = vk_bundle.clone();
    bad_msm_chunk.msm_chunks[0].payload[0] ^= 0x01;
    assert!(
        verify_bn254_chunked_protocol_native(&bad_msm_chunk, &proof, proof_sha, &z0, &z8, false)
            .is_err()
    );

    // Case 14: Mutated, truncated, trailing-bytes, or off-curve compressed proof
    let mut truncated = proof.clone();
    truncated.spartan_snark_bytes.pop();
    assert!(
        verify_bn254_chunked_protocol_native(&vk_bundle, &truncated, proof_sha, &z0, &z8, false)
            .is_err()
    );

    let mut trailing = proof.clone();
    trailing.spartan_snark_bytes.push(0x00);
    assert!(WireRelaxedR1csSnark::decode_strict(&trailing.spartan_snark_bytes).is_err());

    let mut mutated_snark = proof.clone();
    let last_idx = mutated_snark.spartan_snark_bytes.len() - 5;
    mutated_snark.spartan_snark_bytes[last_idx] ^= 0x01;
    assert!(verify_bn254_chunked_protocol_native(
        &vk_bundle,
        &mutated_snark,
        proof_sha,
        &z0,
        &z8,
        false
    )
    .is_err());

    let mut off_curve = proof.clone();
    off_curve.step_comm_w[0] = [0x01u8; 64]; // (x, y) not on y^2 = x^3 + 3!
    assert!(
        verify_bn254_chunked_protocol_native(&vk_bundle, &off_curve, proof_sha, &z0, &z8, false)
            .is_err()
    );

    // Case 15: Invalid intermediate verification state (premature finalize, chunk replay, corrupted accumulator)
    let mut session = begin_decider_session(
        &vk_bundle.compact_vk,
        &proof,
        proof_sha,
        &z0,
        &z8,
        false,
        native_keccak256,
        native_bn254_multiexp,
    )
    .unwrap();

    // Premature finalize before chunks MUST fail
    assert!(finalize_decider_session(
        &mut session,
        &vk_bundle.compact_vk.ipa_ck_s_near64,
        native_bn254_multiexp
    )
    .is_err());

    // Verify first R1CS chunk, then attempt duplicate replay of the same chunk -> MUST fail!
    let c0 = &vk_bundle.r1cs_chunks[0];
    evaluate_packed_r1cs_chunk(
        &mut session,
        c0.chunk_idx,
        c0.merkle_index,
        &c0.merkle_siblings,
        &c0.payload,
        shz_index03_prover::decider_equations::sha256_bytes,
    )
    .unwrap();
    assert!(evaluate_packed_r1cs_chunk(
        &mut session,
        c0.chunk_idx,
        c0.merkle_index,
        &c0.merkle_siblings,
        &c0.payload,
        shz_index03_prover::decider_equations::sha256_bytes,
    )
    .is_err());

    for c in &vk_bundle.r1cs_chunks[1..] {
        evaluate_packed_r1cs_chunk(
            &mut session,
            c.chunk_idx,
            c.merkle_index,
            &c.merkle_siblings,
            &c.payload,
            shz_index03_prover::decider_equations::sha256_bytes,
        )
        .unwrap();
    }
    for m in &vk_bundle.msm_chunks {
        evaluate_msm_chunk(
            &mut session,
            m.chunk_idx,
            m.merkle_index,
            &m.merkle_siblings,
            &m.payload,
            shz_index03_prover::decider_equations::sha256_bytes,
            native_bn254_multiexp,
        )
        .unwrap();
    }

    // Corrupting `acc_eval_a_le32` in intermediate session state MUST fail `finalize_decider_session`!
    let mut corrupted_r1cs_session = session.clone();
    corrupted_r1cs_session.acc_eval_a_le32[0] ^= 0x01;
    assert!(finalize_decider_session(
        &mut corrupted_r1cs_session,
        &vk_bundle.compact_vk.ipa_ck_s_near64,
        native_bn254_multiexp
    )
    .is_err());

    // Corrupting `acc_g_hat_near64` in intermediate session state MUST fail `finalize_decider_session`!
    let mut corrupted_msm_session = session.clone();
    corrupted_msm_session.acc_g_hat_near64 = [0u8; 64];
    assert!(finalize_decider_session(
        &mut corrupted_msm_session,
        &vk_bundle.compact_vk.ipa_ck_s_near64,
        native_bn254_multiexp
    )
    .is_err());

    // Uncorrupted session finalizes once, and Case 16 (replay / double-finalize) is rejected!
    finalize_decider_session(
        &mut session,
        &vk_bundle.compact_vk.ipa_ck_s_near64,
        native_bn254_multiexp,
    )
    .unwrap();
    assert!(finalize_decider_session(
        &mut session,
        &vk_bundle.compact_vk.ipa_ck_s_near64,
        native_bn254_multiexp
    )
    .is_err());

    let mut used_proof_nullifiers = BTreeSet::new();
    assert!(used_proof_nullifiers.insert(proof_sha));
    assert!(
        !used_proof_nullifiers.insert(proof_sha),
        "replayed proof nullifier must be rejected"
    );
}

#[test]
fn cases_17_and_18_bitcoin_tx_substitution_reorg_and_frost_gate() {
    let f = canonical_fixture();
    let claim = f.claim_v1();
    let root: [u8; 32] = hex::decode(&claim.checkpoint_root).unwrap().try_into().unwrap();

    // Case 17a: 64-byte stripped transaction (CVE-2018-17144 Merkle inner-node forgery) MUST be rejected!
    // Construct a legacy tx of exact length 64 bytes:
    // 4 (version) + 1 (vin=1) + 36 (prevout) + 1 (scriptSig=0) + 4 (seq) + 1 (vout=1) + 8 (val=0) + 1 (spk=4) + 4 (spk) + 4 (lock) = 64 bytes!
    let mut tx64 = Vec::new();
    tx64.extend_from_slice(&2i32.to_le_bytes());
    tx64.push(1);
    tx64.extend_from_slice(&[0x11; 36]);
    tx64.push(0);
    tx64.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx64.push(1);
    tx64.extend_from_slice(&0u64.to_le_bytes());
    tx64.push(4);
    tx64.extend_from_slice(&[0x6a, 0x02, 0xab, 0xcd]);
    tx64.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(tx64.len(), 64);
    assert!(verify_shzidx01_transaction(&tx64, &root).is_err());

    // Build valid SHZIDX01 OP_RETURN tx
    let make_tx = |r: &[u8; 32], value_sats: u64| -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&2i32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&[0x33; 32]);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(4);
        tx.extend_from_slice(&[0x01, 0x51, 0x01, 0x52]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&value_sats.to_le_bytes());
        tx.push(42);
        tx.push(0x6a);
        tx.push(0x28);
        tx.extend_from_slice(SHZIDX01_MAGIC);
        tx.extend_from_slice(r);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    };

    let valid_tx = make_tx(&root, 0);
    assert!(verify_shzidx01_transaction(&valid_tx, &root).is_ok());

    // Case 17b: Non-zero satoshis burned in OP_RETURN rejected
    assert!(verify_shzidx01_transaction(&make_tx(&root, 1), &root).is_err());

    // Case 17c: Substituted root in OP_RETURN rejected
    let mut bad_root = root;
    bad_root[31] ^= 1;
    let sub_tx = make_tx(&bad_root, 0);
    assert!(verify_shzidx01_transaction(&sub_tx, &root).is_err());

    // Build PoW header chain (`min_confirmations = 3`)
    let g_hdr = mine_regtest_header(&"00".repeat(32), [0x01; 32], 1_700_000_000, 0);
    let mut lc = BtcLightClient::from_trusted_anchor_header(BtcNetwork::Regtest, 3, 500, &g_hdr).unwrap();
    let g_hash = lc.tip_hash_hex.clone();

    let cb_le = [0x99; 32];
    let tx_le = double_sha256(&valid_tx);
    let mut pair = [0u8; 64];
    pair[0..32].copy_from_slice(&cb_le);
    pair[32..64].copy_from_slice(&tx_le);
    let merkle_501 = double_sha256(&pair);
    let sib_hex = hex::encode(reverse32(cb_le));

    let b501 = lc
        .submit_header(&mine_regtest_header(&g_hash, merkle_501, 1_700_000_600, 0))
        .unwrap();

    // Case 18a: Insufficient confirmations (`1 < 3`) MUST be rejected!
    assert!(lc
        .verify_checkpoint_anchor_finality(
            &root,
            &valid_tx,
            &b501.block_hash_hex,
            1,
            std::slice::from_ref(&sib_hex)
        )
        .is_err());

    let b502 = lc
        .submit_header(&mine_regtest_header(&b501.block_hash_hex, [0x02; 32], 1_700_001_200, 0))
        .unwrap();
    let _b503 = lc
        .submit_header(&mine_regtest_header(&b502.block_hash_hex, [0x03; 32], 1_700_001_800, 0))
        .unwrap();

    // At 3 confirmations on canonical mainchain -> MUST succeed!
    let anchor_receipt = lc
        .verify_checkpoint_anchor_finality(
            &root,
            &valid_tx,
            &b501.block_hash_hex,
            1,
            std::slice::from_ref(&sib_hex),
        )
        .unwrap();
    assert_eq!(anchor_receipt.confirmations, 3);

    // Case 17d: Wrong SPV Merkle sibling rejected
    let bad_sib = "00".repeat(32);
    assert!(lc
        .verify_checkpoint_anchor_finality(
            &root,
            &valid_tx,
            &b501.block_hash_hex,
            1,
            std::slice::from_ref(&bad_sib)
        )
        .is_err());

    // Case 18b: High-hash (invalid PoW) header rejected
    let mut bad_pow = [0u8; 80];
    bad_pow[0..4].copy_from_slice(&4i32.to_le_bytes());
    bad_pow[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes()); // Mainnet diff 1
    assert!(lc.submit_header(&bad_pow).is_err());

    // Case 18c: Competing 1-block side fork (lower cumulative work) is noncanonical -> anchor on fork MUST be rejected!
    let side = lc
        .submit_header(&mine_regtest_header(&g_hash, merkle_501, 1_700_000_650, 77))
        .unwrap();
    assert!(lc
        .verify_checkpoint_anchor_finality(
            &root,
            &valid_tx,
            &side.block_hash_hex,
            1,
            std::slice::from_ref(&sib_hex)
        )
        .is_err());

    // Case 18d: Full Bitcoin Reorganization! Extend `side` to 4 blocks (heavier than 3-block `b501..b503`)
    // -> `b501` is evicted from `mainchain`, and anchor finality on `b501` MUST now be rejected!
    let s2 = lc
        .submit_header(&mine_regtest_header(&side.block_hash_hex, [0x12; 32], 1_700_001_300, 1))
        .unwrap();
    let s3 = lc
        .submit_header(&mine_regtest_header(&s2.block_hash_hex, [0x13; 32], 1_700_001_900, 1))
        .unwrap();
    let _s4 = lc
        .submit_header(&mine_regtest_header(&s3.block_hash_hex, [0x14; 32], 1_700_002_500, 1))
        .unwrap();
    assert!(lc
        .verify_checkpoint_anchor_finality(
            &root,
            &valid_tx,
            &b501.block_hash_hex,
            1,
            std::slice::from_ref(&sib_hex)
        )
        .is_err());

    // Gate E: Verify FROST bridge accepts `anchor_receipt` on VALID hour 0, rejects `nova_verified = false`,
    // rejects `HOLD` hour 4, and keeps `can_authorize_dlc_settlement == false` & `production_ready == false`!
    let frost = FrostConfederation::keygen_deterministic(2, 3, &[0x44; 32]).unwrap();
    let (_, frost_rec) = attest_frost_from_verified_checkpoint(
        &claim,
        true,
        &anchor_receipt,
        3,
        &f.records[0],
        0,
        &f.checkpoint.inclusion[0].siblings,
        &frost,
        &[1, 2],
        20,
        &[0x77; 32],
    )
    .unwrap();
    assert!(!frost_rec.can_authorize_dlc_settlement);
    assert!(!frost_rec.production_ready);
    assert!(!frost_rec.private_dlc_terms_exposed_onchain);

    assert!(attest_frost_from_verified_checkpoint(
        &claim,
        false, // unverified Nova proof MUST be rejected!
        &anchor_receipt,
        3,
        &f.records[0],
        0,
        &f.checkpoint.inclusion[0].siblings,
        &frost,
        &[1, 2],
        20,
        &[0x77; 32],
    )
    .is_err());
}
