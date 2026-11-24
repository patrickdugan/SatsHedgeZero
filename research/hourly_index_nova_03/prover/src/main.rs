//! Independent CLI for `SHZ-INDEX-03`:
//! - `prove-bn254 <fixture.json> <out_dir>`: Generates a pure-BN254 8-fold Nova NIFS + ZK-blinded
//!   Spartan/IPA proof (`proof.bin`), compact Merkle-pinned VK (`compact_vk.json`), VK chunk stream
//!   (`vk_chunks.bin`), public claim (`claim.json`), route comparison profile (`route_profile.json`),
//!   and performance receipt (`prove_receipt.json`).
//! - `verify-bn254 <proof.bin> <vk_chunks.bin> <claim.json> [out_verification.json]`:
//!   Independently verifies a persisted proof bundle without any prover state, running the exact
//!   chunked `Route B + Route C` decider protocol + negative wrong-root / wrong-step / tampered-proof
//!   controls.
//! - `export-vk-chunks <out_vk_chunks.bin> <out_compact_vk.json>`: Deterministically regenerates
//!   the Merkle-authenticated VK chunks from the transparent `Bn256EngineIPA` commitment key & R1CS shape.
//! - `verify-evidence-gates <out_gates_report.json> <fixture.json>`: Exercises Gate C (operational
//!   Solana Mainnet Pyth Pro `Storage` + signed `Crypto.BTC/USD` report & Chainlink v3 DON `ecrecover`
//!   + cherry-picking fraud proof), Gate D (Bitcoin `SHZIDX01` SPV light-client finality + reorg defense),
//!   and Gate E (FROST/DLC bridge with private terms & `can_authorize_dlc_settlement: false`).
#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use bincode::Options;
use halo2curves::bn256::Fr as BnScalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_oracle::{
    frost::FrostConfederation,
    pyth_lazer::{verify_pyth_pro_btc_usd_solana_envelope, PythProBtcUsdPolicy},
};

use shz_index03_prover::{
    bn254_folding::{
        export_vk_merkle_bundle, prove_bn254_nifs_spartan, setup_bn254_circuit,
        verify_bn254_chunked_protocol_native, ExportedVkMerkleBundle,
    },
    bridge::{attest_frost_from_verified_checkpoint, FrostDlcFeedEligibilityReceipt},
    btc_anchor::{
        double_sha256, mine_regtest_header, reverse32, BtcLightClient, BtcNetwork,
        VerifiedBitcoinAnchorReceipt, SHZIDX01_MAGIC,
    },
    circuit::{ClaimV1, FixtureJson, HourStepData, HourStepGeneric, RELATION_V1},
    decider_equations::Bn254NifsSpartanProof,
    profiler::build_route_comparison_report,
    sources::{
        build_operational_pyth_registry_from_solana_storage,
        build_synthetic_authenticated_8h_bundles, verify_chainlink_cherry_pick_fraud_proof,
        verify_hour_source_bundle, encode_and_sign_synthetic_chainlink_v3_report,
        OFFICIAL_PYTH_PRO_BTC_USD_WIRE_HEX, PYTH_LAZER_MAINNET_STORAGE_SNAPSHOT_HEX,
    },
};

#[derive(Debug, Serialize, Deserialize)]
struct Bn254ProveReceipt {
    relation: String,
    curve_engine: String,
    trusted_setup_ceremony: bool,
    uses_groth16_or_kzg_or_starknet: bool,
    steps: usize,
    arity: usize,
    num_cons_raw: usize,
    num_vars_raw: usize,
    num_cons_padded: usize,
    num_vars_padded: usize,
    nnz_total: usize,
    num_r1cs_chunks: u32,
    num_msm_chunks: u32,
    compact_vk_bytes: usize,
    vk_chunks_stream_bytes: usize,
    vk_chunks_merkle_root_hex: String,
    vk_digest_le_hex: String,
    proof_bytes: usize,
    spartan_snark_bytes: usize,
    proof_sha256_hex: String,
    checkpoint_root: String,
    setup_seconds: f64,
    prove_seconds: f64,
    chunked_native_verify_seconds: f64,
    total_wall_seconds: f64,
    rayon_threads: usize,
    production_ready: bool,
    can_authorize_dlc_settlement: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndependentVerificationReceipt {
    relation: String,
    verified: bool,
    proof_bytes: usize,
    proof_sha256_hex: String,
    vk_chunks_merkle_root_hex: String,
    checkpoint_root: String,
    wrong_root_rejected: bool,
    wrong_step_count_rejected: bool,
    tampered_proof_rejected: bool,
    substituted_vk_chunk_rejected: bool,
    verify_wall_seconds: f64,
    production_ready: bool,
    can_authorize_dlc_settlement: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceGatesSummary {
    gate_c_operational_pyth_solana_storage_verified: bool,
    gate_c_operational_pyth_trusted_ed25519_signer: String,
    gate_c_operational_pyth_official_wire_price_e8: u64,
    gate_c_synthetic_8h_pyth_chainlink_bundles_verified: bool,
    gate_c_synthetic_claimed_operational: bool,
    gate_c_cherry_pick_fraud_proof_caught_skipped_report: bool,
    gate_d_bitcoin_anchor_receipt: VerifiedBitcoinAnchorReceipt,
    gate_d_substituted_tx_rejected: bool,
    gate_d_reorged_noncanonical_header_rejected: bool,
    gate_e_frost_dlc_receipt: FrostDlcFeedEligibilityReceipt,
    gate_e_hold_hour_rejected: bool,
    production_ready: bool,
    can_authorize_dlc_settlement: bool,
}

fn sha256_arr(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn blank_v1_step() -> HourStepGeneric<BnScalar> {
    HourStepGeneric::new(HourStepData {
        position: 0,
        start: 0,
        genesis: [0u8; 32],
        policy: [0u8; 32],
        hour: 0,
        status: 2,
        reason: 1,
        p: 0,
        c: 0,
        index: 0,
        pt: 0,
        ct: 0,
        p_hash: [0u8; 32],
        c_hash: [0u8; 32],
        siblings: [[0u8; 32]; 3],
    })
}

fn cmd_prove_bn254(fixture_path: &Path, out_dir: &Path) -> Result<(), String> {
    let t_total = Instant::now();
    fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
    let raw_fixture = fs::read_to_string(fixture_path)
        .map_err(|e| format!("read {}: {e}", fixture_path.display()))?;
    let fixture: FixtureJson =
        serde_json::from_str(&raw_fixture).map_err(|e| format!("parse fixture: {e}"))?;
    let claim = fixture.claim_v1();
    let z0 = claim.state::<BnScalar>(0)?;
    let z8 = claim.state::<BnScalar>(8)?;
    let steps_data = fixture.steps_data()?;
    let steps: Vec<HourStepGeneric<BnScalar>> =
        steps_data.into_iter().map(HourStepGeneric::new).collect();

    let t_setup = Instant::now();
    let setup = setup_bn254_circuit(blank_v1_step())?;
    let vk_bundle = export_vk_merkle_bundle(&setup, RELATION_V1);
    let setup_seconds = t_setup.elapsed().as_secs_f64();

    let t_prove = Instant::now();
    let proof = prove_bn254_nifs_spartan(&setup, RELATION_V1, &steps, &z0, &z8)?;
    let prove_seconds = t_prove.elapsed().as_secs_f64();

    let proof_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&proof)
        .map_err(|e| format!("serialize proof: {e}"))?;
    let proof_sha = sha256_arr(&proof_bytes);

    let t_verify = Instant::now();
    verify_bn254_chunked_protocol_native(&vk_bundle, &proof, proof_sha, &z0, &z8, true)?;
    let verify_seconds = t_verify.elapsed().as_secs_f64();

    let vk_chunks_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&vk_bundle)
        .map_err(|e| format!("serialize vk_bundle: {e}"))?;
    let compact_vk_json = serde_json::to_vec_pretty(&vk_bundle.compact_vk).unwrap();
    let claim_json = serde_json::to_vec_pretty(&claim).unwrap();
    let route_profile = build_route_comparison_report(&setup, &vk_bundle);
    let route_profile_json = serde_json::to_vec_pretty(&route_profile).unwrap();

    fs::write(out_dir.join("proof.bin"), &proof_bytes).map_err(|e| e.to_string())?;
    fs::write(out_dir.join("vk_chunks.bin"), &vk_chunks_bytes).map_err(|e| e.to_string())?;
    fs::write(out_dir.join("compact_vk.json"), &compact_vk_json).map_err(|e| e.to_string())?;
    fs::write(out_dir.join("claim.json"), &claim_json).map_err(|e| e.to_string())?;
    fs::write(out_dir.join("route_profile.json"), &route_profile_json).map_err(|e| e.to_string())?;

    let rayon_threads = env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let receipt = Bn254ProveReceipt {
        relation: RELATION_V1.into(),
        curve_engine: "Bn256EngineIPA (8-fold Nova NIFS + ZK-blinded RelaxedR1CSSNARK Spartan/IPA)"
            .into(),
        trusted_setup_ceremony: false,
        uses_groth16_or_kzg_or_starknet: false,
        steps: 8,
        arity: setup.arity,
        num_cons_raw: setup.shape_raw.num_cons(),
        num_vars_raw: setup.shape_raw.num_vars(),
        num_cons_padded: setup.shape_padded.num_cons(),
        num_vars_padded: setup.shape_padded.num_vars(),
        nnz_total: route_profile.nnz_total,
        num_r1cs_chunks: vk_bundle.compact_vk.num_r1cs_chunks,
        num_msm_chunks: vk_bundle.compact_vk.num_msm_chunks,
        compact_vk_bytes: compact_vk_json.len(),
        vk_chunks_stream_bytes: vk_chunks_bytes.len(),
        vk_chunks_merkle_root_hex: hex::encode(vk_bundle.compact_vk.vk_chunks_merkle_root),
        vk_digest_le_hex: hex::encode(vk_bundle.compact_vk.vk_digest_le32),
        proof_bytes: proof_bytes.len(),
        spartan_snark_bytes: proof.spartan_snark_bytes.len(),
        proof_sha256_hex: hex::encode(proof_sha),
        checkpoint_root: claim.checkpoint_root,
        setup_seconds,
        prove_seconds,
        chunked_native_verify_seconds: verify_seconds,
        total_wall_seconds: t_total.elapsed().as_secs_f64(),
        rayon_threads,
        production_ready: false,
        can_authorize_dlc_settlement: false,
    };
    let receipt_json = serde_json::to_string_pretty(&receipt).unwrap();
    fs::write(out_dir.join("prove_receipt.json"), format!("{receipt_json}\n"))
        .map_err(|e| e.to_string())?;
    println!("{receipt_json}");
    Ok(())
}

fn cmd_export_vk_chunks(
    out_chunks: &Path,
    out_compact_vk: &Path,
    out_route_profile: Option<&Path>,
) -> Result<(), String> {
    let setup = setup_bn254_circuit(blank_v1_step())?;
    let vk_bundle = export_vk_merkle_bundle(&setup, RELATION_V1);
    let vk_chunks_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&vk_bundle)
        .map_err(|e| format!("serialize vk_bundle: {e}"))?;
    if let Some(parent) = out_chunks.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if let Some(parent) = out_compact_vk.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(out_chunks, &vk_chunks_bytes).map_err(|e| e.to_string())?;
    fs::write(
        out_compact_vk,
        format!("{}\n", serde_json::to_string_pretty(&vk_bundle.compact_vk).unwrap()),
    )
    .map_err(|e| e.to_string())?;
    if let Some(rp_path) = out_route_profile {
        let rp = build_route_comparison_report(&setup, &vk_bundle);
        fs::write(
            rp_path,
            format!("{}\n", serde_json::to_string_pretty(&rp).unwrap()),
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn cmd_verify_bn254(
    proof_path: &Path,
    vk_chunks_path: &Path,
    claim_path: &Path,
    out_report: Option<&Path>,
) -> Result<(), String> {
    let t0 = Instant::now();
    let proof_bytes = fs::read(proof_path).map_err(|e| format!("read proof: {e}"))?;
    let vk_bytes = fs::read(vk_chunks_path).map_err(|e| format!("read vk_chunks: {e}"))?;
    let claim_raw = fs::read_to_string(claim_path).map_err(|e| format!("read claim: {e}"))?;

    let proof: Bn254NifsSpartanProof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(4 * 1024 * 1024)
        .reject_trailing_bytes()
        .deserialize(&proof_bytes)
        .map_err(|e| format!("decode proof: {e}"))?;
    let vk_bundle: ExportedVkMerkleBundle = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(64 * 1024 * 1024)
        .reject_trailing_bytes()
        .deserialize(&vk_bytes)
        .map_err(|e| format!("decode vk_bundle: {e}"))?;
    let claim: ClaimV1 =
        serde_json::from_str(&claim_raw).map_err(|e| format!("decode claim: {e}"))?;

    let z0 = claim.state::<BnScalar>(0)?;
    let z8 = claim.state::<BnScalar>(8)?;
    let proof_sha = sha256_arr(&proof_bytes);

    verify_bn254_chunked_protocol_native(&vk_bundle, &proof, proof_sha, &z0, &z8, true)?;

    // Negative control 1: Wrong checkpoint root
    let mut bad_claim = claim.clone();
    bad_claim.checkpoint_root = format!(
        "{}{}",
        if claim.checkpoint_root.starts_with('0') {
            "1"
        } else {
            "0"
        },
        &claim.checkpoint_root[1..]
    );
    let bad_z0 = bad_claim.state::<BnScalar>(0)?;
    let bad_z8 = bad_claim.state::<BnScalar>(8)?;
    let wrong_root_rejected =
        verify_bn254_chunked_protocol_native(&vk_bundle, &proof, proof_sha, &bad_z0, &bad_z8, true)
            .is_err();

    // Negative control 2: Wrong step count
    let mut bad_step_proof = proof.clone();
    bad_step_proof.steps = 7;
    let wrong_step_count_rejected = verify_bn254_chunked_protocol_native(
        &vk_bundle,
        &bad_step_proof,
        proof_sha,
        &z0,
        &z8,
        true,
    )
    .is_err();

    // Negative control 3: Tampered Spartan SNARK byte
    let mut bad_snark_proof = proof.clone();
    let mid = bad_snark_proof.spartan_snark_bytes.len() / 2;
    bad_snark_proof.spartan_snark_bytes[mid] ^= 0x01;
    let tampered_proof_rejected = verify_bn254_chunked_protocol_native(
        &vk_bundle,
        &bad_snark_proof,
        proof_sha,
        &z0,
        &z8,
        true,
    )
    .is_err();

    // Negative control 4: Substituted VK chunk payload
    let mut bad_vk = vk_bundle.clone();
    let last = bad_vk.r1cs_chunks[0].payload.len() - 1;
    bad_vk.r1cs_chunks[0].payload[last] ^= 0x01;
    let substituted_vk_chunk_rejected =
        verify_bn254_chunked_protocol_native(&bad_vk, &proof, proof_sha, &z0, &z8, true).is_err();

    if !wrong_root_rejected
        || !wrong_step_count_rejected
        || !tampered_proof_rejected
        || !substituted_vk_chunk_rejected
    {
        return Err("one or more independent negative controls failed to reject".into());
    }

    let receipt = IndependentVerificationReceipt {
        relation: vk_bundle.compact_vk.relation,
        verified: true,
        proof_bytes: proof_bytes.len(),
        proof_sha256_hex: hex::encode(proof_sha),
        vk_chunks_merkle_root_hex: hex::encode(vk_bundle.compact_vk.vk_chunks_merkle_root),
        checkpoint_root: claim.checkpoint_root,
        wrong_root_rejected,
        wrong_step_count_rejected,
        tampered_proof_rejected,
        substituted_vk_chunk_rejected,
        verify_wall_seconds: t0.elapsed().as_secs_f64(),
        production_ready: false,
        can_authorize_dlc_settlement: false,
    };
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    if let Some(p) = out_report {
        fs::write(p, format!("{json}\n")).map_err(|e| e.to_string())?;
    }
    println!("{json}");
    Ok(())
}

fn build_minimal_anchor_tx(checkpoint_root: &[u8; 32], extra_tag: u8) -> Vec<u8> {
    let mut tx = Vec::with_capacity(120);
    tx.extend_from_slice(&2i32.to_le_bytes()); // version 2
    tx.push(1); // 1 input
    tx.extend_from_slice(&[extra_tag; 32]); // prevout txid
    tx.extend_from_slice(&0u32.to_le_bytes()); // vout 0
    tx.push(4); // 4-byte scriptSig so stripped len > 64
    tx.extend_from_slice(&[0x01, 0x51, 0x01, extra_tag]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx.push(1); // 1 output
    tx.extend_from_slice(&0u64.to_le_bytes()); // 0 sats
    tx.push(42); // scriptPubKey len = 42
    tx.push(0x6a); // OP_RETURN
    tx.push(0x28); // OP_PUSHBYTES_40
    tx.extend_from_slice(SHZIDX01_MAGIC);
    tx.extend_from_slice(checkpoint_root);
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx
}

fn cmd_verify_evidence_gates(out_path: &Path, fixture_path: &Path) -> Result<(), String> {
    // --- Gate C: Operational Solana Mainnet Pyth Pro Storage + Official Wire Envelope ---
    let storage_raw = hex::decode(PYTH_LAZER_MAINNET_STORAGE_SNAPSHOT_HEX).unwrap();
    let (op_pyth_reg, parsed_storage) =
        build_operational_pyth_registry_from_solana_storage(&storage_raw, 1)?;
    let official_wire = hex::decode(OFFICIAL_PYTH_PRO_BTC_USD_WIRE_HEX).unwrap();
    let mut pol = PythProBtcUsdPolicy::default();
    pol.max_age_us = u64::MAX / 2;
    let op_receipt = verify_pyth_pro_btc_usd_solana_envelope(
        &official_wire,
        &op_pyth_reg,
        &pol,
        1_771_551_627_806_528,
    )
    .map_err(|e| format!("operational Pyth wire verify: {e}"))?;

    // Synthetic 8h Pyth + Chainlink v3 DON bundles + anti-cherry-picking fraud proof
    let (syn_pyth_reg, syn_don_cfg, syn_bundles, _, _) =
        build_synthetic_authenticated_8h_bundles(498_000);
    for b in &syn_bundles {
        verify_hour_source_bundle(b, &syn_pyth_reg, &syn_don_cfg)?;
    }
    let any_claimed_op = syn_bundles.iter().any(|b| b.operational_source_authenticated);

    // Build a newer eligible Chainlink report in `[cutoff - 300s, cutoff]` (`cutoff - 2s > cutoff - 20s`)
    let hour0 = syn_bundles[0].hour_id;
    let cutoff_sec = (hour0 + 1) * 3_600;
    let newer_cl = encode_and_sign_synthetic_chainlink_v3_report(
        syn_don_cfg.config_digest,
        100,
        2,
        syn_don_cfg.feed_id,
        cutoff_sec - 10,
        cutoff_sec - 2,
        cutoff_sec + 3_600,
        syn_bundles[0].candidate_chainlink_price_e8,
        500_000_000,
        &[[0x71u8; 32], [0x72u8; 32]],
    );
    let caught_cherry_pick = verify_chainlink_cherry_pick_fraud_proof(
        hour0,
        syn_bundles[0].candidate_chainlink_publish_us,
        &newer_cl,
        &syn_don_cfg,
    )?;
    if !caught_cherry_pick {
        return Err("expected cherry-pick fraud proof to catch skipped newer observation".into());
    }

    // --- Gate D: Bitcoin SHZIDX01 OP_RETURN + PoW Header Chain + Reorg Finality ---
    let fixture: FixtureJson = serde_json::from_str(
        &fs::read_to_string(fixture_path).map_err(|e| format!("read fixture: {e}"))?,
    )
    .map_err(|e| format!("parse fixture: {e}"))?;
    let claim = fixture.claim_v1();
    let root_bytes: [u8; 32] = hex::decode(&claim.checkpoint_root).unwrap().try_into().unwrap();

    let genesis_hdr = mine_regtest_header(&"00".repeat(32), [0x11; 32], 1_700_000_000, 0);
    let mut lc = BtcLightClient::from_trusted_anchor_header(BtcNetwork::Regtest, 3, 100, &genesis_hdr)?;
    let genesis_hash = lc.tip_hash_hex.clone();

    let coinbase_txid_le = [0xaa; 32];
    let anchor_tx = build_minimal_anchor_tx(&root_bytes, 0x42);
    let anchor_txid_le = double_sha256(&anchor_tx);
    let mut pair = [0u8; 64];
    pair[0..32].copy_from_slice(&coinbase_txid_le);
    pair[32..64].copy_from_slice(&anchor_txid_le);
    let blk101_merkle_le = double_sha256(&pair);

    let h101 = lc.submit_header(&mine_regtest_header(&genesis_hash, blk101_merkle_le, 1_700_000_600, 0))?;
    let h102 = lc.submit_header(&mine_regtest_header(&h101.block_hash_hex, [0x22; 32], 1_700_001_200, 0))?;
    let _h103 = lc.submit_header(&mine_regtest_header(&h102.block_hash_hex, [0x33; 32], 1_700_001_800, 0))?;

    let sib_hex = hex::encode(reverse32(coinbase_txid_le));
    let anchor_receipt = lc.verify_checkpoint_anchor_finality(
        &root_bytes,
        &anchor_tx,
        &h101.block_hash_hex,
        1,
        std::slice::from_ref(&sib_hex),
    )?;

    // Tx substitution negative control
    let mut wrong_root = root_bytes;
    wrong_root[0] ^= 0xff;
    let substituted_tx = build_minimal_anchor_tx(&wrong_root, 0x42);
    let substituted_tx_rejected = lc
        .verify_checkpoint_anchor_finality(
            &root_bytes,
            &substituted_tx,
            &h101.block_hash_hex,
            1,
            std::slice::from_ref(&sib_hex),
        )
        .is_err();

    // Bitcoin reorganization negative control: mine a heavier 4-block competing chain off `genesis_hash`
    let mut reorg_lc = lc.clone();
    let f1 = reorg_lc.submit_header(&mine_regtest_header(&genesis_hash, [0x51; 32], 1_700_000_700, 10))?;
    let f2 = reorg_lc.submit_header(&mine_regtest_header(&f1.block_hash_hex, [0x52; 32], 1_700_001_300, 10))?;
    let f3 = reorg_lc.submit_header(&mine_regtest_header(&f2.block_hash_hex, [0x53; 32], 1_700_001_900, 10))?;
    let _f4 = reorg_lc.submit_header(&mine_regtest_header(&f3.block_hash_hex, [0x54; 32], 1_700_002_500, 10))?;
    let reorged_rejected = reorg_lc
        .verify_checkpoint_anchor_finality(
            &root_bytes,
            &anchor_tx,
            &h101.block_hash_hex,
            1,
            std::slice::from_ref(&sib_hex),
        )
        .is_err();

    // --- Gate E: Safe FROST / DLC Epoch Bridge ---
    let frost = FrostConfederation::keygen_deterministic(2, 3, &[0x99; 32])
        .map_err(|e| format!("FROST keygen: {e}"))?;
    let (_, frost_receipt) = attest_frost_from_verified_checkpoint(
        &claim,
        true,
        &anchor_receipt,
        3,
        &fixture.records[0],
        0,
        &fixture.checkpoint.inclusion[0].siblings,
        &frost,
        &[1, 3],
        20,
        &[0x55; 32],
    )?;
    // Verify HOLD hour (offset 4 in INDEX-01 fixture) is strictly rejected from feeding FROST/DLC
    let hold_rejected = attest_frost_from_verified_checkpoint(
        &claim,
        true,
        &anchor_receipt,
        3,
        &fixture.records[4],
        4,
        &fixture.checkpoint.inclusion[4].siblings,
        &frost,
        &[1, 3],
        20,
        &[0x55; 32],
    )
    .is_err();

    let summary = EvidenceGatesSummary {
        gate_c_operational_pyth_solana_storage_verified: true,
        gate_c_operational_pyth_trusted_ed25519_signer: parsed_storage.trusted_ed25519_signers[0]
            .0
            .clone(),
        gate_c_operational_pyth_official_wire_price_e8: op_receipt.price_e8,
        gate_c_synthetic_8h_pyth_chainlink_bundles_verified: true,
        gate_c_synthetic_claimed_operational: any_claimed_op,
        gate_c_cherry_pick_fraud_proof_caught_skipped_report: caught_cherry_pick,
        gate_d_bitcoin_anchor_receipt: anchor_receipt,
        gate_d_substituted_tx_rejected: substituted_tx_rejected,
        gate_d_reorged_noncanonical_header_rejected: reorged_rejected,
        gate_e_frost_dlc_receipt: frost_receipt,
        gate_e_hold_hour_rejected: hold_rejected,
        production_ready: false,
        can_authorize_dlc_settlement: false,
    };
    let json = serde_json::to_string_pretty(&summary).unwrap();
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(out_path, format!("{json}\n")).map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxTestVectors {
    solana_pyth_storage_hex: String,
    official_pyth_wire_hex: String,
    official_pyth_cutoff_us: u64,
    synthetic_pyth_signer_hex: String,
    synthetic_pyth_wire_hex: String,
    synthetic_pyth_cutoff_us: u64,
    chainlink_don_json: String,
    valid_chainlink_report_hex: String,
    selected_chainlink_publish_us: u64,
    unauthorized_chainlink_report_hex: String,
    newer_cherry_pick_chainlink_report_hex: String,
    anchor_btc_height: u64,
    anchor_btc_header_hex: String,
    btc_headers_main_hex: Vec<String>,
    btc_headers_reorg_hex: Vec<String>,
    btc_anchor_block_hash_hex: String,
    valid_btc_tx_hex: String,
    substituted_btc_tx_hex: String,
    btc_merkle_branch_hex: Vec<String>,
}

fn cmd_export_sandbox_vectors(out_path: &Path, fixture_path: &Path) -> Result<(), String> {
    let fixture: FixtureJson = serde_json::from_str(
        &fs::read_to_string(fixture_path).map_err(|e| format!("read fixture: {e}"))?,
    )
    .map_err(|e| format!("parse fixture: {e}"))?;
    let claim = fixture.claim_v1();
    let root_bytes: [u8; 32] = hex::decode(&claim.checkpoint_root).unwrap().try_into().unwrap();
    let start_hour: u64 = claim.start_hour.parse().unwrap();

    let (syn_pyth_reg, syn_don_cfg, syn_bundles, _, _) =
        build_synthetic_authenticated_8h_bundles(start_hour);
    let cutoff_sec = (start_hour + 1) * 3_600;

    let unauthorized_cl = encode_and_sign_synthetic_chainlink_v3_report(
        syn_don_cfg.config_digest,
        101,
        1,
        syn_don_cfg.feed_id,
        cutoff_sec - 20,
        cutoff_sec - 10,
        cutoff_sec + 3_600,
        syn_bundles[0].candidate_chainlink_price_e8,
        500_000_000,
        &[[0x71u8; 32], [0xfe; 32]],
    );
    let newer_cl = encode_and_sign_synthetic_chainlink_v3_report(
        syn_don_cfg.config_digest,
        102,
        1,
        syn_don_cfg.feed_id,
        cutoff_sec - 10,
        cutoff_sec - 2,
        cutoff_sec + 3_600,
        syn_bundles[0].candidate_chainlink_price_e8,
        500_000_000,
        &[[0x71u8; 32], [0x72u8; 32]],
    );

    let chainlink_don_json = serde_json::to_string(&serde_json::json!({
        "profile": "synthetic_test_only",
        "config_digest_hex": hex::encode(syn_don_cfg.config_digest),
        "feed_id_hex": hex::encode(syn_don_cfg.feed_id),
        "f": syn_don_cfg.f,
        "signers_hex": syn_don_cfg.signers.iter().map(hex::encode).collect::<Vec<_>>(),
    }))
    .unwrap();

    let h100_raw = mine_regtest_header(&"00".repeat(32), [0x11; 32], 1_700_000_000, 0);
    let mut lc = BtcLightClient::from_trusted_anchor_header(BtcNetwork::Regtest, 3, 100, &h100_raw)?;
    let h100_hash = lc.tip_hash_hex.clone();

    let coinbase_le = [0xaa; 32];
    let anchor_tx = build_minimal_anchor_tx(&root_bytes, 0x42);
    let anchor_txid_le = double_sha256(&anchor_tx);
    let mut pair = [0u8; 64];
    pair[0..32].copy_from_slice(&coinbase_le);
    pair[32..64].copy_from_slice(&anchor_txid_le);
    let merkle_101 = double_sha256(&pair);
    let sib_hex = hex::encode(reverse32(coinbase_le));

    let h101_raw = mine_regtest_header(&h100_hash, merkle_101, 1_700_000_600, 0);
    let h101 = lc.submit_header(&h101_raw)?;
    let h102_raw = mine_regtest_header(&h101.block_hash_hex, [0x22; 32], 1_700_001_200, 0);
    let h102 = lc.submit_header(&h102_raw)?;
    let h103_raw = mine_regtest_header(&h102.block_hash_hex, [0x33; 32], 1_700_001_800, 0);
    let h103 = lc.submit_header(&h103_raw)?;
    let h104_raw = mine_regtest_header(&h103.block_hash_hex, [0x44; 32], 1_700_002_400, 0);
    let h104 = lc.submit_header(&h104_raw)?;
    let h105_raw = mine_regtest_header(&h104.block_hash_hex, [0x55; 32], 1_700_003_000, 0);
    let _h105 = lc.submit_header(&h105_raw)?;

    let mut fork_lc = BtcLightClient::from_trusted_anchor_header(BtcNetwork::Regtest, 3, 100, &h100_raw)?;
    let f1_raw = mine_regtest_header(&h100_hash, [0x61; 32], 1_700_000_700, 10);
    let f1 = fork_lc.submit_header(&f1_raw)?;
    let f2_raw = mine_regtest_header(&f1.block_hash_hex, [0x62; 32], 1_700_001_300, 10);
    let f2 = fork_lc.submit_header(&f2_raw)?;
    let f3_raw = mine_regtest_header(&f2.block_hash_hex, [0x63; 32], 1_700_001_900, 10);
    let f3 = fork_lc.submit_header(&f3_raw)?;
    let f4_raw = mine_regtest_header(&f3.block_hash_hex, [0x64; 32], 1_700_002_500, 10);
    let _f4 = fork_lc.submit_header(&f4_raw)?;

    let mut bad_root = root_bytes;
    bad_root[0] ^= 0xff;
    let sub_tx = build_minimal_anchor_tx(&bad_root, 0x42);

    let vectors = SandboxTestVectors {
        solana_pyth_storage_hex: PYTH_LAZER_MAINNET_STORAGE_SNAPSHOT_HEX.into(),
        official_pyth_wire_hex: OFFICIAL_PYTH_PRO_BTC_USD_WIRE_HEX.into(),
        official_pyth_cutoff_us: 1_771_551_627_806_528,
        synthetic_pyth_signer_hex: hex::encode(syn_pyth_reg.signers[0].pubkey),
        synthetic_pyth_wire_hex: syn_bundles[0].pyth_raw_envelope_hex.clone().unwrap(),
        synthetic_pyth_cutoff_us: (start_hour + 1) * 3_600_000_000,
        chainlink_don_json,
        valid_chainlink_report_hex: syn_bundles[0].chainlink_full_report_hex.clone().unwrap(),
        selected_chainlink_publish_us: syn_bundles[0].candidate_chainlink_publish_us,
        unauthorized_chainlink_report_hex: hex::encode(unauthorized_cl),
        newer_cherry_pick_chainlink_report_hex: hex::encode(newer_cl),
        anchor_btc_height: 100,
        anchor_btc_header_hex: hex::encode(h100_raw),
        btc_headers_main_hex: [h101_raw, h102_raw, h103_raw, h104_raw, h105_raw]
            .into_iter()
            .map(hex::encode)
            .collect(),
        btc_headers_reorg_hex: [f1_raw, f2_raw, f3_raw, f4_raw]
            .into_iter()
            .map(hex::encode)
            .collect(),
        btc_anchor_block_hash_hex: h101.block_hash_hex,
        valid_btc_tx_hex: hex::encode(anchor_tx),
        substituted_btc_tx_hex: hex::encode(sub_tx),
        btc_merkle_branch_hex: vec![sib_hex],
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        out_path,
        format!("{}\n", serde_json::to_string_pretty(&vectors).unwrap()),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let res = match args.get(1).map(String::as_str) {
        Some("prove-bn254") if args.len() == 4 => {
            cmd_prove_bn254(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]))
        }
        Some("export-vk-chunks") if args.len() == 4 || args.len() == 5 => cmd_export_vk_chunks(
            &PathBuf::from(&args[2]),
            &PathBuf::from(&args[3]),
            args.get(4).map(Path::new),
        ),
        Some("verify-bn254") if args.len() == 5 || args.len() == 6 => cmd_verify_bn254(
            &PathBuf::from(&args[2]),
            &PathBuf::from(&args[3]),
            &PathBuf::from(&args[4]),
            args.get(5).map(Path::new),
        ),
        Some("verify-evidence-gates") if args.len() == 4 => {
            cmd_verify_evidence_gates(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]))
        }
        Some("export-sandbox-vectors") if args.len() == 4 => {
            cmd_export_sandbox_vectors(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]))
        }
        _ => Err(
            "usage:\n  shz-index03-prover prove-bn254 <fixture.json> <out_dir>\n  shz-index03-prover export-vk-chunks <out_vk_chunks.bin> <out_compact_vk.json>\n  shz-index03-prover verify-bn254 <proof.bin> <vk_chunks.bin> <claim.json> [out_verification.json]\n  shz-index03-prover verify-evidence-gates <out_gates.json> <fixture.json>\n  shz-index03-prover export-sandbox-vectors <out_vectors.json> <fixture.json>"
                .into(),
        ),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
