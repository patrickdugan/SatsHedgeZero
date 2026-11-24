//! `shz-mnr05-bitvm3-ln-dlc` CLI:
//! - `run-all <bitcoind_path> <artifacts_dir>`:
//!   Executes all 4 live `Bitcoin Core v31.1.0` regtest drills, then proves & verifies (1 prover job
//!   at a time) the 8-signature `Secq256k1` BIP-340 batch authorization proof and the 3-fold
//!   `Bn256EngineIPA` unified BitVM3 batch-clearing proof over the exact L1-confirmed transactions.
//! - `verify-persisted <artifacts_dir>`:
//!   Independently reconstructs both setup-free VKs from blank circuit definitions, checks pinned
//!   VK SHA-256 digests, verifies `secq_auth_proof.bin` and `unified_batch_proof.bin` from disk,
//!   and exercises tampered-proof / mutated-state negative controls.
#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

use bincode::Options;
use ff::Field;
use halo2curves::secq256k1::Fq as SecqScalar;
use nova_snark::{
    nova::{CompressedSNARK, PublicParams},
    provider::{ipa_pc::EvaluationEngine, Bn256EngineIPA, GrumpkinEngine, Secp256k1Engine, Secq256k1Engine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_mnr05_bitvm3_ln_dlc::{
    core_regtest::{run_mnr05_core_regtest_drills, Mnr05CoreRegtestReceipt},
    progress::Mnr05ProgressReporter,
    secq_schnorr_circuit::{
        prove_and_verify_secq_batch_auth_with_progress, secq_from_u128,
        u128_halves_le_from_digest, Mnr05SecqBip340Step, SecqBatchAuthProofReceipt,
        AUTH_STEP_COUNT,
    },
    unified_batch_circuit::{
        build_unified_batch_steps_and_claim, prove_and_verify_unified_batch_with_progress,
        Mnr05UnifiedBatchStep, UnifiedBatchProofReceipt, UnifiedBatchPublicClaim, UNIFIED_FOLDS,
    },
};
use shz_nova_bitvm::bitvm3::{BitVm3SettlementRecord, BitcoinNetworkCode};

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn peak_rss_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let num = rest.split_whitespace().next()?;
            return num.parse().ok();
        }
    }
    None
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedPublicClaims {
    pub secq_vk_sha256_hex: String,
    pub secq_proof_sha256_hex: String,
    pub auth_accumulator_root_hex: String,
    pub unified_vk_sha256_hex: String,
    pub unified_proof_sha256_hex: String,
    pub unified_claim: UnifiedBatchPublicClaim,
    pub bitvm3_statement_record: BitVm3SettlementRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndependentVerificationReceipt {
    pub secq_vk_reconstructed_match: bool,
    pub secq_proof_verified: bool,
    pub secq_tampered_proof_rejected: bool,
    pub secq_mutated_state_rejected: bool,
    pub secq_verify_seconds: f64,
    pub unified_vk_reconstructed_match: bool,
    pub unified_proof_verified: bool,
    pub unified_tampered_proof_rejected: bool,
    pub unified_mutated_state_rejected: bool,
    pub unified_verify_seconds: f64,
    pub peak_rss_kib: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Mnr05MasterSummary {
    pub milestone: &'static str,
    pub trusted_setup_ceremony: bool,
    pub bitvm3_tapscript_disprove_regtest_verified: bool,
    pub full_groth16_garbled_circuit_l1_verified: bool,
    pub nova_secq256k1_bip340_auth_verified: bool,
    pub nova_unified_batch_nullifier_verified: bool,
    pub ptlc_atomic_ln_double_offline_verified: bool,
    pub production_ready: bool,
    pub peak_rss_kib: Option<u64>,
    pub core_regtest: Mnr05CoreRegtestReceipt,
    pub secq_auth_proof: SecqBatchAuthProofReceipt,
    pub unified_batch_proof: UnifiedBatchProofReceipt,
    pub independent_verification: IndependentVerificationReceipt,
}

fn run_verify_persisted(artifacts_dir: &Path) -> Result<IndependentVerificationReceipt, String> {
    let claims_txt = fs::read_to_string(artifacts_dir.join("public_claims.json"))
        .map_err(|e| format!("read public_claims.json: {e}"))?;
    let claims: PersistedPublicClaims =
        serde_json::from_str(&claims_txt).map_err(|e| format!("parse public_claims.json: {e}"))?;

    let secq_proof_bytes = fs::read(artifacts_dir.join("secq_auth_proof.bin"))
        .map_err(|e| format!("read secq_auth_proof.bin: {e}"))?;
    let unified_proof_bytes = fs::read(artifacts_dir.join("unified_batch_proof.bin"))
        .map_err(|e| format!("read unified_batch_proof.bin: {e}"))?;

    // 1. Independently reconstruct Secq256k1 VK & verify `secq_auth_proof.bin`
    type SE1 = Secq256k1Engine;
    type SE2 = Secp256k1Engine;
    type SS1 = RelaxedR1CSSNARK<SE1, EvaluationEngine<SE1>>;
    type SS2 = RelaxedR1CSSNARK<SE2, EvaluationEngine<SE2>>;

    let t_secq = Instant::now();
    let secq_pp = PublicParams::<SE1, SE2, Mnr05SecqBip340Step>::setup(
        &Mnr05SecqBip340Step::blank(),
        &*SS1::ck_floor(),
        &*SS2::ck_floor(),
    )
    .map_err(|e| format!("reconstruct Secq PP: {e:?}"))?;
    let (_secq_pk, secq_vk) =
        CompressedSNARK::<SE1, SE2, Mnr05SecqBip340Step, SS1, SS2>::setup(&secq_pp)
            .map_err(|e| format!("reconstruct Secq VK: {e:?}"))?;
    let secq_vk_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&secq_vk)
        .map_err(|e| e.to_string())?;
    let secq_vk_match = hex::encode(sha256_bytes(&secq_vk_bytes)) == claims.secq_vk_sha256_hex;
    if !secq_vk_match {
        return Err("reconstructed Secq VK hash mismatch".into());
    }

    let secq_snark: CompressedSNARK<SE1, SE2, Mnr05SecqBip340Step, SS1, SS2> =
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&secq_proof_bytes)
            .map_err(|e| format!("deserialize secq proof: {e}"))?;
    let z0_secq = vec![SecqScalar::ZERO, SecqScalar::ZERO, SecqScalar::ZERO];
    let z8 = secq_snark
        .verify(&secq_vk, AUTH_STEP_COUNT, &z0_secq)
        .map_err(|e| format!("verify secq proof: {e:?}"))?;

    let acc_bytes: [u8; 32] = hex::decode(&claims.auth_accumulator_root_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let (acc_lo, acc_hi) = u128_halves_le_from_digest(&acc_bytes);
    let expected_z8 = vec![
        SecqScalar::from(AUTH_STEP_COUNT as u64),
        secq_from_u128(acc_lo),
        secq_from_u128(acc_hi),
    ];
    if z8 != expected_z8 {
        return Err("Secq terminal accumulator mismatch".into());
    }

    // Tampered proof byte + mutated initial state controls
    let mut bad_secq_bytes = secq_proof_bytes.clone();
    let mid_idx = bad_secq_bytes.len() / 2;
    bad_secq_bytes[mid_idx] ^= 0x01;
    let secq_tampered_rejected = match bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize::<CompressedSNARK<SE1, SE2, Mnr05SecqBip340Step, SS1, SS2>>(&bad_secq_bytes)
    {
        Ok(bad_p) => bad_p.verify(&secq_vk, AUTH_STEP_COUNT, &z0_secq).is_err(),
        Err(_) => true,
    };
    let mut bad_z0_secq = z0_secq.clone();
    bad_z0_secq[1] += SecqScalar::ONE;
    let secq_mutated_rejected = secq_snark
        .verify(&secq_vk, AUTH_STEP_COUNT, &bad_z0_secq)
        .is_err();
    let secq_verify_seconds = t_secq.elapsed().as_secs_f64();

    // 2. Independently reconstruct Bn256EngineIPA VK & verify `unified_batch_proof.bin`
    type UE1 = Bn256EngineIPA;
    type UE2 = GrumpkinEngine;
    type US1 = RelaxedR1CSSNARK<UE1, EvaluationEngine<UE1>>;
    type US2 = RelaxedR1CSSNARK<UE2, EvaluationEngine<UE2>>;

    let t_uni = Instant::now();
    let uni_pp = PublicParams::<UE1, UE2, Mnr05UnifiedBatchStep>::setup(
        &Mnr05UnifiedBatchStep::blank(),
        &*US1::ck_floor(),
        &*US2::ck_floor(),
    )
    .map_err(|e| format!("reconstruct Unified PP: {e:?}"))?;
    let (_uni_pk, uni_vk) =
        CompressedSNARK::<UE1, UE2, Mnr05UnifiedBatchStep, US1, US2>::setup(&uni_pp)
            .map_err(|e| format!("reconstruct Unified VK: {e:?}"))?;
    let uni_vk_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&uni_vk)
        .map_err(|e| e.to_string())?;
    let uni_vk_match = hex::encode(sha256_bytes(&uni_vk_bytes)) == claims.unified_vk_sha256_hex;
    if !uni_vk_match {
        return Err("reconstructed Unified VK hash mismatch".into());
    }

    let uni_snark: CompressedSNARK<UE1, UE2, Mnr05UnifiedBatchStep, US1, US2> =
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&unified_proof_bytes)
            .map_err(|e| format!("deserialize unified proof: {e}"))?;
    let z0_uni = claims.unified_claim.state(0);
    let expected_z3_uni = claims.unified_claim.state(UNIFIED_FOLDS as u64);
    let z3_uni = uni_snark
        .verify(&uni_vk, UNIFIED_FOLDS, &z0_uni)
        .map_err(|e| format!("verify unified proof: {e:?}"))?;
    if z3_uni != expected_z3_uni {
        return Err("Unified terminal state mismatch".into());
    }

    let mut bad_uni_bytes = unified_proof_bytes.clone();
    let u_mid = bad_uni_bytes.len() / 2;
    bad_uni_bytes[u_mid] ^= 0x01;
    let uni_tampered_rejected = match bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize::<CompressedSNARK<UE1, UE2, Mnr05UnifiedBatchStep, US1, US2>>(&bad_uni_bytes)
    {
        Ok(bad_p) => bad_p.verify(&uni_vk, UNIFIED_FOLDS, &z0_uni).is_err(),
        Err(_) => true,
    };
    let mut bad_z0_uni = z0_uni.clone();
    bad_z0_uni[5] += halo2curves::bn256::Fr::ONE;
    let uni_mutated_rejected = uni_snark
        .verify(&uni_vk, UNIFIED_FOLDS, &bad_z0_uni)
        .is_err();
    let unified_verify_seconds = t_uni.elapsed().as_secs_f64();

    if !secq_tampered_rejected
        || !secq_mutated_rejected
        || !uni_tampered_rejected
        || !uni_mutated_rejected
    {
        return Err("negative control failed during independent verification".into());
    }

    let receipt = IndependentVerificationReceipt {
        secq_vk_reconstructed_match: secq_vk_match,
        secq_proof_verified: true,
        secq_tampered_proof_rejected: secq_tampered_rejected,
        secq_mutated_state_rejected: secq_mutated_rejected,
        secq_verify_seconds,
        unified_vk_reconstructed_match: uni_vk_match,
        unified_proof_verified: true,
        unified_tampered_proof_rejected: uni_tampered_rejected,
        unified_mutated_state_rejected: uni_mutated_rejected,
        unified_verify_seconds,
        peak_rss_kib: peak_rss_kib(),
    };
    fs::write(
        artifacts_dir.join("independent_verification.json"),
        serde_json::to_string_pretty(&receipt).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(receipt)
}

fn run_all(bitcoind_path: &Path, artifacts_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(artifacts_dir).map_err(|e| e.to_string())?;
    let mut reporter = Mnr05ProgressReporter::new(Some(artifacts_dir));

    reporter.emit(
        "core_regtest",
        "Running Bitcoin Core v31.1.0 regtest consensus drills (SHZIDX01 + PTLC + BitVM3)",
        0,
        None,
        None,
        2.0,
    );
    println!("[1/4] Running live Bitcoin Core v31.1.0 regtest drills (Anchor + Double-Offline PTLC Clearing + BitVM3 Assert/Disprove/Timeout + Unilateral Fallback)...");
    let (
        core_receipt,
        clearing_bundle,
        oracle_witness,
        assertion_txid_be,
        assertion_vout,
        regtest_genesis,
    ) = run_mnr05_core_regtest_drills(bitcoind_path)?;
    fs::write(
        artifacts_dir.join("core_regtest_receipt.json"),
        serde_json::to_string_pretty(&core_receipt).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    reporter.emit(
        "core_regtest_done",
        "Bitcoin Core 31.1 drills passed (PTLC double-offline + BitVM3 slash verified)",
        2,
        None,
        None,
        10.0,
    );
    println!(
        "      Confirmed double-offline clearing txid={} ({} vB, {} B stripped), BitVM3 slash txids=({}, {})",
        core_receipt.double_offline_clearing_txid,
        core_receipt.double_offline_clearing_vsize,
        core_receipt.double_offline_clearing_stripped_bytes,
        core_receipt.bitvm3_taproot_drills.disprove_boundary_slash_txid,
        core_receipt.bitvm3_taproot_drills.disprove_equivocation_slash_txid,
    );

    println!("[2/4] Proving 8-signature Secq256k1 BIP-340 batch authorization SNARK (single prover job)...");
    let (secq_proof_bytes, secq_vk_sha, secq_receipt) =
        prove_and_verify_secq_batch_auth_with_progress(
            &clearing_bundle.bip340_auth_slots,
            &mut |stage, msg, fold_step, fold_tot| {
                let (steps_done, pct) = match stage {
                    "secq_setup" => (2, 12.0),
                    "secq_fold" => {
                        let k = fold_step.unwrap_or(1);
                        (2 + k, 12.0 + f64::from(k) * 4.5) // 16.5% .. 48.0%
                    }
                    "secq_compress" => (11, 52.0),
                    _ => (11, 55.0),
                };
                reporter.emit(stage, msg, steps_done, fold_step, fold_tot, pct);
            },
        )?;
    fs::write(artifacts_dir.join("secq_auth_proof.bin"), &secq_proof_bytes)
        .map_err(|e| e.to_string())?;
    fs::write(
        artifacts_dir.join("secq_auth_receipt.json"),
        serde_json::to_string_pretty(&secq_receipt).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    reporter.emit(
        "secq_verified",
        "Secq256k1 8-sig BIP-340 CompressedSNARK proved & verified",
        12,
        Some(8),
        Some(8),
        60.0,
    );
    println!(
        "      Secq256k1 proof={} B, c1={}, c2={}, fold={:.2}s, compress={:.2}s, auth_acc={}",
        secq_receipt.proof_bytes,
        secq_receipt.primary_constraints,
        secq_receipt.secondary_constraints,
        secq_receipt.fold_seconds,
        secq_receipt.compress_seconds,
        secq_receipt.auth_accumulator_root_hex
    );

    println!("[3/4] Proving 3-fold Bn256EngineIPA unified BitVM3 batch-clearing SNARK (single prover job)...");
    let auth_acc: [u8; 32] = hex::decode(&secq_receipt.auth_accumulator_root_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let contract_id = sha256_bytes(b"SHZ/MNR05/NETTING_CONTRACT_ID/BTC_USD_INVERSE_3PARTY_V1");
    let program_hash = sha256_bytes(b"shz/mnr05-unified-bitvm3-batch-clearing/v1");

    let (uni_steps, uni_claim, bitvm3_stmt) = build_unified_batch_steps_and_claim(
        BitcoinNetworkCode::Regtest,
        regtest_genesis,
        contract_id,
        assertion_txid_be,
        assertion_vout,
        program_hash,
        auth_acc,
        oracle_witness.hour_id,
        clearing_bundle.stripped_clearing_tx_348b,
        [99_000_000, 90_000_000, 55_000_000],
        2_670,
        [0, 1, 2],
        oracle_witness,
    )?;
    let (uni_proof_bytes, uni_vk_sha, uni_receipt) =
        prove_and_verify_unified_batch_with_progress(
            &uni_steps,
            &uni_claim,
            &mut |stage, msg, fold_step, fold_tot| {
                let (steps_done, pct) = match stage {
                    "unified_setup" => (13, 65.0),
                    "unified_fold" => {
                        let k = fold_step.unwrap_or(1);
                        (13 + k, 65.0 + f64::from(k) * 7.0) // 72%, 79%, 86%
                    }
                    "unified_compress" => (17, 90.0),
                    _ => (18, 93.0),
                };
                reporter.emit(stage, msg, steps_done, fold_step, fold_tot, pct);
            },
        )?;
    fs::write(artifacts_dir.join("unified_batch_proof.bin"), &uni_proof_bytes)
        .map_err(|e| e.to_string())?;
    fs::write(
        artifacts_dir.join("unified_batch_receipt.json"),
        serde_json::to_string_pretty(&uni_receipt).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    reporter.emit(
        "unified_verified",
        "BN254 3-fold Unified Batch + Nullifier CompressedSNARK proved & verified",
        18,
        Some(3),
        Some(3),
        95.0,
    );
    println!(
        "      Unified batch proof={} B, c1={}, c2={}, fold={:.2}s, compress={:.2}s, stmt_sha256={}",
        uni_receipt.proof_bytes,
        uni_receipt.primary_constraints,
        uni_receipt.secondary_constraints,
        uni_receipt.fold_seconds,
        uni_receipt.compress_seconds,
        uni_receipt.bitvm3_statement_304b_sha256_hex
    );

    let persisted_claims = PersistedPublicClaims {
        secq_vk_sha256_hex: hex::encode(secq_vk_sha),
        secq_proof_sha256_hex: secq_receipt.proof_sha256_hex.clone(),
        auth_accumulator_root_hex: secq_receipt.auth_accumulator_root_hex.clone(),
        unified_vk_sha256_hex: hex::encode(uni_vk_sha),
        unified_proof_sha256_hex: uni_receipt.proof_sha256_hex.clone(),
        unified_claim: uni_claim,
        bitvm3_statement_record: bitvm3_stmt.to_json_record(),
    };
    fs::write(
        artifacts_dir.join("public_claims.json"),
        serde_json::to_string_pretty(&persisted_claims).unwrap(),
    )
    .map_err(|e| e.to_string())?;

    reporter.emit(
        "independent_verify",
        "Reconstructing VKs from blank circuits & auditing persisted proofs",
        19,
        None,
        None,
        97.5,
    );
    println!("[4/4] Running independent persisted VK reconstruction & proof verification...");
    let indep = run_verify_persisted(artifacts_dir)?;

    let master = Mnr05MasterSummary {
        milestone: "SHZ-MNR-05: Batched BitVM3 Settlement & PTLC Lightning Clearing for Multilateral LN-DLC",
        trusted_setup_ceremony: false,
        bitvm3_tapscript_disprove_regtest_verified: true,
        full_groth16_garbled_circuit_l1_verified: false,
        nova_secq256k1_bip340_auth_verified: true,
        nova_unified_batch_nullifier_verified: true,
        ptlc_atomic_ln_double_offline_verified: true,
        production_ready: false,
        peak_rss_kib: peak_rss_kib(),
        core_regtest: core_receipt,
        secq_auth_proof: secq_receipt,
        unified_batch_proof: uni_receipt,
        independent_verification: indep,
    };
    fs::write(
        artifacts_dir.join("mnr05_summary_receipt.json"),
        serde_json::to_string_pretty(&master).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    reporter.emit(
        "completed",
        "All SHZ-MNR-05 BitVM3 + PTLC + Dual Nova proofs independently verified (100%)",
        20,
        None,
        None,
        100.0,
    );
    println!("Done! All SHZ-MNR-05 artifacts written to {}", artifacts_dir.display());
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let res = match args.get(1).map(String::as_str) {
        Some("run-all") => {
            if args.len() != 4 {
                Err("usage: shz-mnr05-bitvm3-ln-dlc run-all <bitcoind_path> <artifacts_dir>".into())
            } else {
                run_all(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]))
            }
        }
        Some("run-regtest") => {
            if args.len() != 3 {
                Err("usage: shz-mnr05-bitvm3-ln-dlc run-regtest <bitcoind_path>".into())
            } else {
                run_mnr05_core_regtest_drills(&PathBuf::from(&args[2])).map(|(r, ..)| {
                    println!(
                        "Verified all 4 live Bitcoin Core 31.1 drills: clearing_txid={}, slash_b={}, slash_eq={}",
                        r.double_offline_clearing_txid,
                        r.bitvm3_taproot_drills.disprove_boundary_slash_txid,
                        r.bitvm3_taproot_drills.disprove_equivocation_slash_txid
                    );
                })
            }
        }
        Some("verify-persisted") => {
            if args.len() != 3 {
                Err("usage: shz-mnr05-bitvm3-ln-dlc verify-persisted <artifacts_dir>".into())
            } else {
                run_verify_persisted(&PathBuf::from(&args[2])).map(|r| {
                    println!(
                        "Verified persisted MNR-05 proofs: secq_ok={}, unified_ok={}, secq_ver={:.3}s, uni_ver={:.3}s",
                        r.secq_proof_verified,
                        r.unified_proof_verified,
                        r.secq_verify_seconds,
                        r.unified_verify_seconds
                    );
                })
            }
        }
        _ => Err(
            "usage: shz-mnr05-bitvm3-ln-dlc <run-all <bitcoind> <dir> | verify-persisted <dir>>"
                .into(),
        ),
    };
    if let Err(e) = res {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}
