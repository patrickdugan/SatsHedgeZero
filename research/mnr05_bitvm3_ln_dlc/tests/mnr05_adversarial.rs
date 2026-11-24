//! Constraint-level (`TestConstraintSystem`) and protocol-level adversarial soundness suite
//! for `SHZ-MNR-05` (`Secq256k1` BIP-340 circuit, `Bn256EngineIPA` Unified Batch + Nullifier circuit,
//! `BitVm3AssertionTree`, and `PTLC` Lightning Double-Offline Bridge).
#![forbid(unsafe_code)]

use ff::{Field, PrimeField};
use halo2curves::{
    bn256::Fr as BnScalar,
    secp256k1::Fp as SecpBase,
    secq256k1::Fq as SecqScalar,
};
use nova_snark::{
    frontend::{
        gadgets::num::AllocatedNum,
        test_cs::TestConstraintSystem,
        ConstraintSystem,
    },
    traits::circuit::StepCircuit,
};
use shz_dlc::{bip340_sign, pubkey_x_from_secret};
use shz_mnr05_bitvm3_ln_dlc::{
    bitvm3_taproot::{derive_wire_connector_pair, hash_boundary_preimage, BitVm3AssertionTree},
    ptlc_lightning::{
        canonical_index03_clearing_oracle_witness, execute_ptlc_lightning_double_offline_clearing,
    },
    secq_schnorr_circuit::{
        compute_auth_accumulator_chain, secq_from_u128, u128_halves_le_from_digest,
        Bip340StepSlot, Mnr05SecqBip340Step,
    },
    unified_batch_circuit::{
        build_unified_batch_steps_and_claim, BatchVaultNullifierTree, Mnr05UnifiedBatchStep,
    },
};
use shz_nova_bitvm::bitvm3::BitcoinNetworkCode;
use shz_utxoref::mnr03::Mnr03ScaleParams;

fn synthesize_secq_step(
    step: &Mnr05SecqBip340Step,
    z_in: [SecqScalar; 3],
) -> (TestConstraintSystem<SecqScalar>, Vec<SecqScalar>) {
    let mut cs = TestConstraintSystem::<SecqScalar>::new();
    let z_alloc: Vec<AllocatedNum<SecqScalar>> = z_in
        .iter()
        .enumerate()
        .map(|(i, &v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z_{i}")), || v))
        .collect();
    let z_out = step.synthesize(&mut cs, &z_alloc).expect("synthesize secq");
    let vals = z_out.iter().map(|n| n.get_value().unwrap()).collect();
    (cs, vals)
}

fn synthesize_unified_step(
    step: &Mnr05UnifiedBatchStep,
    z_in: &[BnScalar],
) -> (TestConstraintSystem<BnScalar>, Vec<BnScalar>) {
    let mut cs = TestConstraintSystem::<BnScalar>::new();
    let z_alloc: Vec<AllocatedNum<BnScalar>> = z_in
        .iter()
        .enumerate()
        .map(|(i, &v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z_{i}")), || v))
        .collect();
    let z_out = step
        .synthesize(&mut cs, &z_alloc)
        .expect("synthesize unified");
    let vals = z_out.iter().map(|n| n.get_value().unwrap()).collect();
    (cs, vals)
}

#[test]
fn test_secq256k1_bip340_r1cs_honest_and_adversarial_mutations() {
    let sk = [0x33u8; 32];
    let pk_x = pubkey_x_from_secret(&sk).unwrap();
    let msg = [0x44u8; 32];
    let sig = bip340_sign(&sk, &msg).unwrap();

    let prev_acc = [0x55u8; 32];
    let slot = Bip340StepSlot {
        step_idx: 2,
        sighash_flag: 0x01,
        pubkey_x: pk_x,
        sighash32: msg,
        sig_rx: sig.r_x,
        sig_s: sig.s,
    };
    let valid_step = Mnr05SecqBip340Step::from_valid_slot(prev_acc, slot.clone()).unwrap();
    let (p_lo, p_hi) = u128_halves_le_from_digest(&prev_acc);
    let z_in = [
        SecqScalar::from(2u64),
        secq_from_u128(p_lo),
        secq_from_u128(p_hi),
    ];

    // 1. Honest BIP-340 step satisfies R1CS and witness-independent constraint count matches blank!
    let (cs_ok, z_out) = synthesize_secq_step(&valid_step, z_in);
    assert!(
        cs_ok.is_satisfied(),
        "unsatisfied honest Secq step: {:?}",
        cs_ok.which_is_unsatisfied()
    );
    let (cs_blank, _) = synthesize_secq_step(
        &Mnr05SecqBip340Step::blank(),
        [SecqScalar::ZERO, SecqScalar::ZERO, SecqScalar::ZERO],
    );
    assert!(cs_blank.is_satisfied());
    assert_eq!(
        cs_ok.num_constraints(),
        cs_blank.num_constraints(),
        "Secq circuit shape must be 100% witness-independent"
    );
    let expected_next = slot.next_accumulator(&prev_acc);
    let (n_lo, n_hi) = u128_halves_le_from_digest(&expected_next);
    assert_eq!(z_out[0], SecqScalar::from(3u64));
    assert_eq!(z_out[1], secq_from_u128(n_lo));
    assert_eq!(z_out[2], secq_from_u128(n_hi));

    // 2. Wrong `sig_s` (+1 bit flip) MUST fail R1CS!
    let mut bad_s = valid_step.clone();
    bad_s.slot.sig_s[31] ^= 0x01;
    let (cs_bad_s, _) = synthesize_secq_step(&bad_s, z_in);
    assert!(!cs_bad_s.is_satisfied(), "forged sig_s must fail R1CS");

    // 3. Non-canonical `sig_s >= n` (`s + n` would wrap mod n if unguarded, or `0xff..ff`) MUST fail `s_lt_n`!
    let mut s_ge_n = valid_step.clone();
    s_ge_n.slot.sig_s = [0xffu8; 32];
    let (cs_ge_n, _) = synthesize_secq_step(&s_ge_n, z_in);
    assert!(!cs_ge_n.is_satisfied(), "s >= n must fail canonical range check");

    // 4. Zero `sig_s == 0` MUST fail `s_nonzero`!
    let mut s_zero = valid_step.clone();
    s_zero.slot.sig_s = [0u8; 32];
    let (cs_s_zero, _) = synthesize_secq_step(&s_zero, z_in);
    assert!(!cs_s_zero.is_satisfied(), "s == 0 must fail R1CS");

    // 5. Odd-Y `R` (`p - ry` is on curve `y^2 == x^3 + 7` with SAME `rx`, but odd!) MUST fail `ry_even`!
    let mut ry_le = valid_step.ry_be;
    ry_le.reverse();
    let ry_fp = Option::<SecpBase>::from(SecpBase::from_repr(ry_le.into())).unwrap();
    let neg_ry_fp = -ry_fp;
    let mut odd_ry_be: [u8; 32] = halo2curves::ff::PrimeField::to_repr(&neg_ry_fp)
        .as_ref()
        .try_into()
        .unwrap();
    odd_ry_be.reverse();
    let mut odd_r = valid_step.clone();
    odd_r.ry_be = odd_ry_be;
    let (cs_odd_r, _) = synthesize_secq_step(&odd_r, z_in);
    assert!(!cs_odd_r.is_satisfied(), "odd-Y R must be rejected");

    // 6. Wrong `sighash32` MUST fail BIP-340 challenge check!
    let mut bad_msg = valid_step.clone();
    bad_msg.slot.sighash32[0] ^= 0x80;
    let (cs_bad_msg, _) = synthesize_secq_step(&bad_msg, z_in);
    assert!(!cs_bad_msg.is_satisfied(), "wrong sighash32 must fail R1CS");

    // 7. Wrong `pubkey_x` (valid curve point from another key) MUST fail!
    let other_pk = pubkey_x_from_secret(&[0x77u8; 32]).unwrap();
    let mut bad_pk = Mnr05SecqBip340Step::from_valid_slot(
        prev_acc,
        Bip340StepSlot {
            pubkey_x: other_pk,
            ..slot
        },
    )
    .unwrap();
    let (cs_bad_pk, _) = synthesize_secq_step(&bad_pk, z_in);
    assert!(!cs_bad_pk.is_satisfied(), "substituted pubkey_x must fail R1CS");

    // 8. Wrong `step_idx` (`z[0]` mismatch) MUST fail!
    bad_pk = valid_step;
    let (cs_bad_idx, _) = synthesize_secq_step(&bad_pk, [SecqScalar::from(1u64), z_in[1], z_in[2]]);
    assert!(!cs_bad_idx.is_satisfied(), "step index substitution must fail");
}

#[test]
fn test_ptlc_double_offline_and_unified_batch_r1cs_adversarial_suite() {
    let regtest_genesis = [0x06u8; 32];
    let oracle_witness = canonical_index03_clearing_oracle_witness(regtest_genesis);
    let params = Mnr03ScaleParams::macro_regtest_33k(150);

    let p2tr = |seed: u8| -> Vec<u8> {
        let pk = pubkey_x_from_secret(&[seed; 32]).unwrap();
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&pk);
        s
    };

    let (_orig, bundle) = execute_ptlc_lightning_double_offline_clearing(
        &params,
        [(&"11".repeat(32), 0), (&"22".repeat(32), 1), (&"33".repeat(32), 2)],
        p2tr(0x41),
        p2tr(0x42),
        p2tr(0x43),
        p2tr(0x45),
        p2tr(0x44),
        &oracle_witness,
    )
    .expect("PTLC double-offline ceremony");

    assert!(!bundle.receipt.bob_online_at_l1_clearing);
    assert!(!bundle.receipt.alice_online_at_l1_clearing);
    assert!(bundle.receipt.ptlc_secret_extracted_and_verified);
    assert!(bundle.receipt.forged_ptlc_claim_rejected);
    assert_eq!(bundle.receipt.ln_ptlc_settled_to_alice_sats, 71_498_500);

    // Verify all 8 real clearing signatures satisfy `Mnr05SecqBip340Step` R1CS!
    let (auth_acc, prevs) = compute_auth_accumulator_chain(&bundle.bip340_auth_slots);
    for (i, (prev, slot)) in prevs.into_iter().zip(bundle.bip340_auth_slots.iter()).enumerate() {
        let step = Mnr05SecqBip340Step::from_valid_slot(prev, slot.clone()).unwrap();
        let (lo, hi) = u128_halves_le_from_digest(&prev);
        let (cs, _) = synthesize_secq_step(
            &step,
            [SecqScalar::from(i as u64), secq_from_u128(lo), secq_from_u128(hi)],
        );
        assert!(cs.is_satisfied(), "real clearing sig slot {i} failed R1CS");
    }

    // Build unified 3-fold batch steps & verify R1CS across all 3 folds!
    let (steps, claim, _stmt) = build_unified_batch_steps_and_claim(
        BitcoinNetworkCode::Regtest,
        regtest_genesis,
        [0x91; 32],
        [0x92; 32],
        0,
        [0x93; 32],
        auth_acc,
        oracle_witness.hour_id,
        bundle.stripped_clearing_tx_348b,
        [99_000_000, 90_000_000, 55_000_000],
        2_670,
        [0, 1, 2],
        oracle_witness.clone(),
    )
    .expect("build unified steps");

    let (cs_blank, _) = synthesize_unified_step(&Mnr05UnifiedBatchStep::blank(), &claim.state(0));
    let mut z_cur = claim.state(0);
    for (k, step) in steps.iter().enumerate() {
        let (cs, z_next) = synthesize_unified_step(step, &z_cur);
        assert!(
            cs.is_satisfied(),
            "unified fold {k} failed R1CS: {:?}",
            cs.which_is_unsatisfied()
        );
        assert_eq!(
            cs.num_constraints(),
            cs_blank.num_constraints(),
            "Unified circuit shape must be witness-independent"
        );
        z_cur = z_next;
    }
    assert_eq!(z_cur, claim.state(3));

    // --- Adversarial Case 1: Double-consuming vault slot 0 in `BatchVaultNullifierTree` MUST fail! ---
    let mut tree = BatchVaultNullifierTree::new();
    let out0: [u8; 36] = bundle.stripped_clearing_tx_348b[5..41].try_into().unwrap();
    tree.consume_vault_slot(0, &out0).unwrap();
    assert!(tree.consume_vault_slot(0, &out0).is_err());

    // And attempting to feed `steps[0]` against an already-consumed `z[1..3]` root MUST fail R1CS!
    let mut z_replayed = claim.state(0);
    z_replayed[1] = steps[1].cur_nullifier_root[0..16]
        .try_into()
        .map(|b: [u8; 16]| shz_mnr05_bitvm3_ln_dlc::unified_batch_circuit::bn_from_u128(u128::from_le_bytes(b)))
        .unwrap();
    let (cs_replay, _) = synthesize_unified_step(&steps[0], &z_replayed);
    assert!(!cs_replay.is_satisfied(), "replayed vault nullifier must fail R1CS");

    // --- Adversarial Case 2: 1-satoshi conservation violation (`miner_fee_sats + 1`) MUST fail R1CS! ---
    let mut bad_cons = steps[0].clone();
    bad_cons.miner_fee_sats += 1;
    let (cs_cons, _) = synthesize_unified_step(&bad_cons, &claim.state(0));
    assert!(!cs_cons.is_satisfied(), "1-sat conservation mismatch must fail R1CS");

    // --- Adversarial Case 3: Mutated `stripped_tx_348b` byte MUST fail `settlement_txid` binding! ---
    let mut bad_tx = steps[0].clone();
    bad_tx.stripped_tx_348b[344] ^= 0x01; // mutate locktime byte
    let (cs_tx, _) = synthesize_unified_step(&bad_tx, &claim.state(0));
    assert!(!cs_tx.is_satisfied(), "mutated clearing tx byte must fail R1CS");

    // --- Adversarial Case 4: Oracle spread > 50 bps (`+400 USD` at `$60,000` = `66.7 bps`) MUST fail R1CS! ---
    let mut bad_spread = steps[0].clone();
    bad_spread.oracle.pyth_price_e8 = 6_020_000_000_000;
    bad_spread.oracle.chainlink_price_e8 = 5_980_000_000_000; // 66.7 bps > 50 bps!
    let (cs_spread, _) = synthesize_unified_step(&bad_spread, &claim.state(0));
    assert!(!cs_spread.is_satisfied(), "oracle spread > 50 bps must fail R1CS");

    // --- Adversarial Case 5: Terminal fold `k = 2` with wrong `commitment_hash` in `statement_304b` MUST fail! ---
    let mut bad_term = steps[2].clone();
    bad_term.statement_304b[100] ^= 0xff; // mutate commitment_hash (`final_nullifier_root`)
    let mut z_before_k2 = claim.state(0);
    for s in &steps[0..2] {
        z_before_k2 = synthesize_unified_step(s, &z_before_k2).1;
    }
    let (cs_term, _) = synthesize_unified_step(&bad_term, &z_before_k2);
    assert!(!cs_term.is_satisfied(), "forged terminal nullifier commitment must fail R1CS");

    // --- Adversarial Case 6: `BitVm3AssertionTree` rejects identical pubkeys or identical wire hashes ---
    let pk_a = pubkey_x_from_secret(&[0x51; 32]).unwrap();
    let pk_b = pubkey_x_from_secret(&[0x52; 32]).unwrap();
    let bh = hash_boundary_preimage(&[1; 32], &[2; 32]);
    let (_p0, _p1, h0, h1) = derive_wire_connector_pair(&[0x77; 32], 0);
    assert!(BitVm3AssertionTree::build(pk_a, pk_a, 10, bh, bh, h0, h1).is_err());
    assert!(BitVm3AssertionTree::build(pk_a, pk_b, 10, bh, bh, h0, h0).is_err());
}
