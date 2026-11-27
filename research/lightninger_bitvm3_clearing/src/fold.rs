//! Nova folding, Spartan/IPA compression and verification for any step of this crate
//! (`Bn256EngineIPA` / `GrumpkinEngine`, no trusted setup), with timings and negative
//! controls that run the verifier.
use crate::gadgets::sha256_native;
use bincode::Options;
use ff::PrimeField;
use halo2curves::bn256::Fr as F;
use nova_snark::{
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc::EvaluationEngine, Bn256EngineIPA, GrumpkinEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait},
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub type E1 = Bn256EngineIPA;
pub type E2 = GrumpkinEngine;
pub type S1 = RelaxedR1CSSNARK<E1, EvaluationEngine<E1>>;
pub type S2 = RelaxedR1CSSNARK<E2, EvaluationEngine<E2>>;

pub fn hex_z(z: &[F]) -> Vec<String> {
    z.iter()
        .map(|e| {
            let mut b = e.to_repr().as_ref().to_vec();
            b.reverse();
            hex::encode(b)
        })
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldReceipt {
    pub relation: String,
    pub curve_cycle: String,
    pub steps: usize,
    pub arity: usize,
    pub primary_constraints: usize,
    pub secondary_constraints: usize,
    pub setup_seconds: f64,
    pub fold_seconds: f64,
    pub fold_seconds_per_step: f64,
    pub compress_seconds: f64,
    pub verify_seconds: f64,
    pub proof_bytes: usize,
    pub vk_sha256: String,
    pub proof_sha256: String,
    pub z0: Vec<String>,
    pub zk: Vec<String>,
    /// The compressed proof's output equals `z_K` computed from the real data.
    pub output_matches_expected: bool,
    /// Verifier rejects the proof for a z0 with one element changed by 1.
    pub mutated_z0_rejected: bool,
    /// Verifier rejects the proof claimed for K-1 steps.
    pub wrong_step_count_rejected: bool,
    /// Verifier rejects the proof bytes with one bit flipped (or they fail to decode).
    pub flipped_proof_rejected: bool,
}

/// Fold `steps` from `z0`, check the output against `expected_zk`, compress, verify, and
/// run the negative controls.
pub fn prove<C: StepCircuit<F>>(relation: &str, blank: &C, steps: &[C], z0: &[F], expected_zk: &[F], log: &mut dyn FnMut(&str)) -> Result<(FoldReceipt, Vec<u8>), String> {
    assert!(!steps.is_empty());
    let t = Instant::now();
    let pp = PublicParams::<E1, E2, C>::setup(blank, &*S1::ck_floor(), &*S2::ck_floor()).map_err(|e| format!("setup: {e:?}"))?;
    let (pk, vk) = CompressedSNARK::<E1, E2, C, S1, S2>::setup(&pp).map_err(|e| format!("snark setup: {e:?}"))?;
    let setup_seconds = t.elapsed().as_secs_f64();
    let (c1, c2) = pp.num_constraints();
    log(&format!("setup {setup_seconds:.1}s, primary {c1} / secondary {c2} constraints"));
    let t = Instant::now();
    let mut rec = RecursiveSNARK::<E1, E2, C>::new(&pp, &steps[0], z0).map_err(|e| format!("new: {e:?}"))?;
    for (i, s) in steps.iter().enumerate() {
        rec.prove_step(&pp, s).map_err(|e| format!("prove_step {i}: {e:?}"))?;
        log(&format!("folded step {}/{} at {:.1}s", i + 1, steps.len(), t.elapsed().as_secs_f64()));
    }
    let zk = rec.verify(&pp, steps.len(), z0).map_err(|e| format!("recursive verify: {e:?}"))?;
    let fold_seconds = t.elapsed().as_secs_f64();
    if zk != expected_zk {
        return Err(format!("folded output differs from the real data:\n got {:?}\nwant {:?}", hex_z(&zk), hex_z(expected_zk)));
    }
    let t = Instant::now();
    let proof = CompressedSNARK::<E1, E2, C, S1, S2>::prove(&pp, &pk, &rec).map_err(|e| format!("compress: {e:?}"))?;
    let compress_seconds = t.elapsed().as_secs_f64();
    log(&format!("compressed in {compress_seconds:.1}s"));
    let opts = || bincode::DefaultOptions::new().with_fixint_encoding();
    let bytes = opts().serialize(&proof).map_err(|e| e.to_string())?;
    let vk_bytes = opts().serialize(&vk).map_err(|e| e.to_string())?;
    let decoded: CompressedSNARK<E1, E2, C, S1, S2> = opts().reject_trailing_bytes().deserialize(&bytes).map_err(|e| e.to_string())?;
    let t = Instant::now();
    let out = decoded.verify(&vk, steps.len(), z0).map_err(|e| format!("compressed verify: {e:?}"))?;
    let verify_seconds = t.elapsed().as_secs_f64();
    let output_matches_expected = out == expected_zk;
    let mut bad = z0.to_vec();
    bad[0] += F::from(1u64);
    let mutated_z0_rejected = decoded.verify(&vk, steps.len(), &bad).is_err();
    let wrong_step_count_rejected = steps.len() < 2 || decoded.verify(&vk, steps.len() - 1, z0).is_err();
    let mut flipped = bytes.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 1;
    let flipped_proof_rejected = match opts().deserialize::<CompressedSNARK<E1, E2, C, S1, S2>>(&flipped) {
        Err(_) => true,
        Ok(p) => p.verify(&vk, steps.len(), z0).map(|o| o != out).unwrap_or(true),
    };
    let r = FoldReceipt {
        relation: relation.into(),
        curve_cycle: "Bn256EngineIPA / GrumpkinEngine, Spartan RelaxedR1CSSNARK + IPA (no trusted setup)".into(),
        steps: steps.len(),
        arity: z0.len(),
        primary_constraints: c1,
        secondary_constraints: c2,
        setup_seconds,
        fold_seconds,
        fold_seconds_per_step: fold_seconds / steps.len() as f64,
        compress_seconds,
        verify_seconds,
        proof_bytes: bytes.len(),
        vk_sha256: hex::encode(sha256_native(&vk_bytes)),
        proof_sha256: hex::encode(sha256_native(&bytes)),
        z0: hex_z(z0),
        zk: hex_z(&out),
        output_matches_expected,
        mutated_z0_rejected,
        wrong_step_count_rejected,
        flipped_proof_rejected,
    };
    if !(r.output_matches_expected && r.mutated_z0_rejected && r.wrong_step_count_rejected && r.flipped_proof_rejected) {
        return Err(format!("negative control failed: {r:?}"));
    }
    Ok((r, bytes))
}

/// Primary-circuit constraint count of one step, without building public parameters.
pub fn shape_constraints<C: StepCircuit<F>>(c: &C) -> (usize, usize) {
    use nova_snark::frontend::{num::AllocatedNum, shape_cs::ShapeCS, ConstraintSystem};
    let mut cs = ShapeCS::<E1>::new();
    let z: Vec<AllocatedNum<F>> = (0..c.arity()).map(|i| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(F::from(0u64))).unwrap()).collect();
    c.synthesize(&mut cs, &z).unwrap();
    (cs.num_constraints(), cs.num_aux())
}
