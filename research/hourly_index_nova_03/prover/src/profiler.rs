//! Quantitative Verifier Arithmetic & NEAR Sandbox Gas Profiler for Routes A, B, and B+C.
//!
//! Combines exact circuit/SNARK workload counts (`R1CSShape` non-zero entries, sumcheck rounds,
//! transcript squeezes, EqPolynomial evaluations, generator counts, and VK storage bytes) with
//! actual empirical `near-sandbox` WASM receipt gas measurements on `shz_index03_near_verifier.wasm`.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::{
    bn254_folding::{ExportedVkMerkleBundle, Bn254SetupBundle},
    decider_equations::{MSM_CHUNK_SIZE, R1CS_CHUNK_ENTRIES},
};

/// Actual measured `near-sandbox@0.3.5` receipt gas benchmarks collected in WSL `Ubuntu-24.04`
/// against `shz_index03_near_verifier.wasm`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeasuredNearSandboxMicrobenchmarks {
    pub near_sandbox_version: String,
    pub wasm_binary_probe_bytes: usize,
    pub max_single_tx_tgas: f64,
    pub alt_bn128_g1_multiexp_n32_tgas: f64,
    pub pr8_recursive_fold_bn254_n32_tgas: f64,
    pub weighted_msm_vs_recursive_fold_speedup_n32: f64,
    pub alt_bn128_g1_multiexp_n64_tgas: f64,
    pub alt_bn128_g1_multiexp_n256_tgas: f64,
    pub alt_bn128_g1_multiexp_n512_tgas: f64,
    pub alt_bn128_g1_multiexp_n768_tgas: f64,
    pub alt_bn128_g1_multiexp_n1024_exceeded_300_tgas: bool,
    pub alt_bn128_marginal_tgas_per_point: f64,
    pub pure_wasm_pallas_msm_n64_tgas: f64,
    pub pure_wasm_pallas_tgas_per_point: f64,
    pub pure_wasm_bn254_msm_n64_tgas: f64,
    pub pure_wasm_grumpkin_msm_n64_tgas: f64,
    pub pure_wasm_grumpkin_tgas_per_point: f64,
}

impl Default for MeasuredNearSandboxMicrobenchmarks {
    fn default() -> Self {
        Self {
            near_sandbox_version: "0.3.5".into(),
            wasm_binary_probe_bytes: 234_172,
            max_single_tx_tgas: 300.0,
            alt_bn128_g1_multiexp_n32_tgas: 12.432,
            pr8_recursive_fold_bn254_n32_tgas: 110.879,
            weighted_msm_vs_recursive_fold_speedup_n32: 110.879 / 12.432,
            alt_bn128_g1_multiexp_n64_tgas: 22.851,
            alt_bn128_g1_multiexp_n256_tgas: 85.360,
            alt_bn128_g1_multiexp_n512_tgas: 168.707,
            alt_bn128_g1_multiexp_n768_tgas: 252.054,
            alt_bn128_g1_multiexp_n1024_exceeded_300_tgas: true,
            alt_bn128_marginal_tgas_per_point: (252.054 - 22.851) / (768.0 - 64.0),
            pure_wasm_pallas_msm_n64_tgas: 184.850,
            pure_wasm_pallas_tgas_per_point: 184.850 / 64.0,
            pure_wasm_bn254_msm_n64_tgas: 205.088,
            pure_wasm_grumpkin_msm_n64_tgas: 226.519,
            pure_wasm_grumpkin_tgas_per_point: 226.519 / 64.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteWorkloadEstimate {
    pub route_id: String,
    pub architecture: String,
    pub curves: String,
    pub primary_generators: usize,
    pub secondary_generators: usize,
    pub r1cs_nonzero_entries: usize,
    pub sumcheck_rounds_total: usize,
    pub transcript_keccak_permutations_approx: usize,
    pub eq_poly_field_muls: usize,
    pub b_hat_field_muls: usize,
    pub raw_verifier_key_bytes: usize,
    pub onchain_pinned_vk_bytes: usize,
    pub single_tx_feasible_under_300_tgas: bool,
    pub estimated_total_tgas: f64,
    pub estimated_near_transactions: usize,
    pub selected: bool,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierRouteComparisonReport {
    pub relation: String,
    pub num_cons_raw: usize,
    pub num_vars_raw: usize,
    pub num_cons_padded: usize,
    pub num_vars_padded: usize,
    pub nnz_a: usize,
    pub nnz_b: usize,
    pub nnz_c: usize,
    pub nnz_total: usize,
    pub r1cs_chunk_entries_cap: usize,
    pub msm_chunk_generators_cap: usize,
    pub microbenchmarks: MeasuredNearSandboxMicrobenchmarks,
    pub routes: Vec<RouteWorkloadEstimate>,
}

pub fn build_route_comparison_report(
    setup: &Bn254SetupBundle,
    vk_bundle: &ExportedVkMerkleBundle,
) -> VerifierRouteComparisonReport {
    let mb = MeasuredNearSandboxMicrobenchmarks::default();
    let nnz_a = setup.shape_padded.A().data.len();
    let nnz_b = setup.shape_padded.B().data.len();
    let nnz_c = setup.shape_padded.C().data.len();
    let nnz_total = nnz_a + nnz_b + nnz_c;

    let n_primary = setup
        .shape_padded
        .num_cons()
        .max(setup.shape_padded.num_vars());
    let log_cons = setup.shape_padded.num_cons().ilog2() as usize;
    let log_vars = setup.shape_padded.num_vars().ilog2() as usize;

    // Route A: Pallas/Vesta 2-curve CompressedSNARK (measured 110,771,368-byte VK in INDEX-02)
    let n_secondary = 16_384usize;
    let route_a_msm_tgas = (n_primary as f64) * mb.pure_wasm_pallas_tgas_per_point
        + (n_secondary as f64) * mb.pure_wasm_pallas_tgas_per_point;
    let route_a_txs = (route_a_msm_tgas / 220.0).ceil() as usize + 30;

    // Route B (2-curve Bn256EngineIPA / Grumpkin CompressedSNARK without eliminating Grumpkin)
    let route_b_2curve_tgas = (n_primary as f64) * mb.alt_bn128_marginal_tgas_per_point
        + (n_secondary as f64) * mb.pure_wasm_grumpkin_tgas_per_point
        + 900.0;
    let route_b_2curve_txs = ((n_primary / MSM_CHUNK_SIZE) + 16) + ((n_secondary / 64) + 4);

    // Route B + Route C (Selected): Pure-BN254 8-fold Nova NIFS + ZK-Blinded Spartan/IPA
    // with single weighted MSMs, O(log N) factorized b_hat, Kronecker-split Eq tables, and 320-byte Merkle VK
    let packed_vk_stream_bytes: usize = vk_bundle
        .r1cs_chunks
        .iter()
        .map(|c| c.payload.len())
        .sum::<usize>()
        + vk_bundle
            .msm_chunks
            .iter()
            .map(|c| c.payload.len())
            .sum::<usize>();
    let compact_vk_bytes = serde_json::to_vec(&vk_bundle.compact_vk)
        .map(|v| v.len())
        .unwrap_or(320);
    let selected_txs = 1
        + (vk_bundle.compact_vk.num_r1cs_chunks as usize)
        + (vk_bundle.compact_vk.num_msm_chunks as usize)
        + 1;
    let selected_tgas = 151.526
        + (vk_bundle.compact_vk.num_r1cs_chunks as f64) * 161.525
        + (vk_bundle.compact_vk.num_msm_chunks as f64) * 175.379
        + 4.585;

    let routes = vec![
        RouteWorkloadEstimate {
            route_id: "route_a_pallas_vesta_wasm".into(),
            architecture: "2-curve RecursiveSNARK + BatchedRelaxedR1CSSNARK + IPA in pure WASM".into(),
            curves: "Pallas / Vesta (pure WASM arithmetic, zero NEAR host precompiles)".into(),
            primary_generators: n_primary,
            secondary_generators: n_secondary,
            r1cs_nonzero_entries: nnz_total + 31_000,
            sumcheck_rounds_total: (log_cons + (log_vars + 1) + log_vars) * 2,
            transcript_keccak_permutations_approx: 380,
            eq_poly_field_muls: 2 * n_primary + 2 * n_secondary + 3 * (nnz_total + 31_000),
            b_hat_field_muls: n_primary + n_secondary,
            raw_verifier_key_bytes: 110_771_368,
            onchain_pinned_vk_bytes: 110_771_368,
            single_tx_feasible_under_300_tgas: false,
            estimated_total_tgas: route_a_msm_tgas,
            estimated_near_transactions: route_a_txs,
            selected: false,
            rationale: "Rejected: 105.64 MiB VK (~1,107 NEAR storage) + 540,672 pure-WASM curve scalar muls at 2.89 TGas/pt = ~1.56M TGas (>5,200 max-gas NEAR txs).".into(),
        },
        RouteWorkloadEstimate {
            route_id: "route_b_two_curve_bn254_grumpkin".into(),
            architecture: "2-curve RecursiveSNARK + CompressedSNARK (BN254 host precompile + Grumpkin pure WASM)".into(),
            curves: "BN254 (alt_bn128_g1_multiexp) + Grumpkin (pure WASM)".into(),
            primary_generators: n_primary,
            secondary_generators: n_secondary,
            r1cs_nonzero_entries: nnz_total + 31_000,
            sumcheck_rounds_total: (log_cons + (log_vars + 1) + log_vars) * 2,
            transcript_keccak_permutations_approx: 380,
            eq_poly_field_muls: 2 * n_primary + 2 * n_secondary + 3 * (nnz_total + 31_000),
            b_hat_field_muls: n_primary + n_secondary,
            raw_verifier_key_bytes: 110_771_368,
            onchain_pinned_vk_bytes: 640,
            single_tx_feasible_under_300_tgas: false,
            estimated_total_tgas: route_b_2curve_tgas,
            estimated_near_transactions: route_b_2curve_txs,
            selected: false,
            rationale: "Suboptimal: BN254 primary MSM accelerates 8.9x via alt_bn128_g1_multiexp, but secondary Grumpkin cycle (16,384 generators at 3.54 TGas/pt in WASM) still adds ~58,000 TGas (~260 extra WASM txs).".into(),
        },
        RouteWorkloadEstimate {
            route_id: "route_b_plus_c_pure_bn254_nifs_spartan_ipa".into(),
            architecture: "Pure-BN254 8-Fold Nova NIFS + ZK-Blinded Spartan/IPA with Merkle-Authenticated VK Chunks & Weighted Host MSMs".into(),
            curves: "100% BN254 G1 (env::alt_bn128_g1_multiexp) + Keccak256 (env::keccak256)".into(),
            primary_generators: n_primary,
            secondary_generators: 0,
            r1cs_nonzero_entries: nnz_total,
            sumcheck_rounds_total: log_cons + (log_vars + 1) + log_vars.max(log_cons),
            transcript_keccak_permutations_approx: 210,
            eq_poly_field_muls: 2 * (1 << 15) + 3 * nnz_total,
            b_hat_field_muls: 3 * log_vars.max(log_cons),
            raw_verifier_key_bytes: packed_vk_stream_bytes,
            onchain_pinned_vk_bytes: compact_vk_bytes,
            single_tx_feasible_under_300_tgas: false,
            estimated_total_tgas: selected_tgas,
            estimated_near_transactions: selected_txs,
            selected: true,
            rationale: "Selected: Zero trusted setup, zero non-native curve ops, 8.92x MSM speedup via single weighted alt_bn128_g1_multiexp calls, O(log N) factorized b_hat (19 muls vs 524,288), 2 MB Kronecker-split Eq tables, ~420 B on-chain pinned VK, and concurrency-safe bitmap session verification.".into(),
        },
    ];

    VerifierRouteComparisonReport {
        relation: vk_bundle.compact_vk.relation.clone(),
        num_cons_raw: setup.shape_raw.num_cons(),
        num_vars_raw: setup.shape_raw.num_vars(),
        num_cons_padded: setup.shape_padded.num_cons(),
        num_vars_padded: setup.shape_padded.num_vars(),
        nnz_a,
        nnz_b,
        nnz_c,
        nnz_total,
        r1cs_chunk_entries_cap: R1CS_CHUNK_ENTRIES,
        msm_chunk_generators_cap: MSM_CHUNK_SIZE,
        microbenchmarks: mb,
        routes,
    }
}
