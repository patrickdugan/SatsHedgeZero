//! Pure-BN254 8-Fold Nova Non-Interactive Folding (`NIFS`) + ZK-Blinded Spartan/IPA
//! Prover, VK Merkle Chunk Builder, and Native Reference Verifier (`Route B + Route C`).
#![forbid(unsafe_code)]

use bincode::Options;
use ff::{Field, PrimeField};
use halo2curves::bn256::{Fr as BnScalar, G1 as BnPoint, G1Affine as BnAffine};
use halo2curves::group::prime::PrimeCurveAffine;
use nova_snark::{
    frontend::{
        r1cs::{NovaShape, NovaWitness},
        shape_cs::ShapeCS,
        solver::SatisfyingAssignment,
        Circuit, ConstraintSystem,
    },
    provider::{ipa_pc::EvaluationEngine, Bn256EngineIPA},
    r1cs::{R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness, SparseMatrix},
    spartan::{direct::DirectCircuit, snark::RelaxedR1CSSNARK},
    traits::{
        circuit::StepCircuit,
        commitment::{CommitmentEngineTrait, CommitmentTrait},
        snark::{DigestHelperTrait, RelaxedR1CSSNARKTrait},
        Engine,
    },
};

type Commitment<E> = <<E as Engine>::CE as CommitmentEngineTrait<E>>::Commitment;
type CommitmentKey<E> = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey;
type DerandKey<E> = <<E as Engine>::CE as CommitmentEngineTrait<E>>::DerandKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::decider_equations::{
    begin_decider_session, bn_affine_to_near64, bn_near64_to_affine, bn_point_to_near64,
    derive_nifs_challenge_with, evaluate_msm_chunk, evaluate_packed_r1cs_chunk,
    finalize_decider_session, scalar_from_le32, scalar_to_le32, vk_chunk_leaf_hash,
    Bn254NifsSpartanProof, CompactPinnedVerifierKey, CHUNK_KIND_MSM, CHUNK_KIND_R1CS,
    MSM_CHUNK_SIZE, R1CS_CHUNK_ENTRIES, VK_NODE_DOMAIN,
};

pub type E = Bn256EngineIPA;
pub type EE = EvaluationEngine<E>;
pub type SpartanSnark = RelaxedR1CSSNARK<E, EE>;
pub type SpartanPk = <SpartanSnark as RelaxedR1CSSNARKTrait<E>>::ProverKey;
pub type SpartanVk = <SpartanSnark as RelaxedR1CSSNARKTrait<E>>::VerifierKey;

pub fn native_keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

pub fn native_bn254_multiexp(terms: &[([u8; 64], [u8; 32])]) -> Result<[u8; 64], String> {
    if terms.is_empty() {
        return Ok([0u8; 64]);
    }
    let mut bases = Vec::with_capacity(terms.len());
    let mut scalars = Vec::with_capacity(terms.len());
    for (pt_bytes, sc_bytes) in terms {
        let s = scalar_from_le32(sc_bytes)?;
        let aff = bn_near64_to_affine(pt_bytes)?;
        if !bool::from(s.is_zero()) && !bool::from(aff.is_identity()) {
            bases.push(aff);
            scalars.push(s);
        }
    }
    if bases.is_empty() {
        return Ok([0u8; 64]);
    }
    let out = <BnPoint as nova_snark::provider::traits::DlogGroupExt>::vartime_multiscalar_mul(
        &scalars, &bases,
    );
    Ok(bn_point_to_near64(&out))
}

pub struct Bn254SetupBundle {
    pub arity: usize,
    pub shape_raw: R1CSShape<E>,
    pub shape_padded: R1CSShape<E>,
    pub ck: CommitmentKey<E>,
    pub dk: DerandKey<E>,
    pub spartan_pk: SpartanPk,
    pub spartan_vk: SpartanVk,
    pub vk_digest: BnScalar,
    pub derand_h: BnAffine,
    pub ck_ipa_s: BnAffine,
}

pub fn setup_bn254_circuit<C: StepCircuit<BnScalar> + Clone>(blank_step: C) -> Result<Bn254SetupBundle, String> {
    let arity = blank_step.arity();
    let circuit: DirectCircuit<E, C> = DirectCircuit::new(None, blank_step);
    let mut cs: ShapeCS<E> = ShapeCS::new();
    circuit
        .synthesize(&mut cs)
        .map_err(|e| format!("ShapeCS synthesize: {e:?}"))?;
    let shape_raw = cs.r1cs_shape().map_err(|e| format!("r1cs_shape: {e:?}"))?;
    let ck = R1CSShape::commitment_key(&[&shape_raw], &[&*SpartanSnark::ck_floor()])
        .map_err(|e| format!("commitment_key: {e:?}"))?;
    let (spartan_pk, spartan_vk) =
        SpartanSnark::setup(&ck, &shape_raw).map_err(|e| format!("Spartan setup: {e:?}"))?;
    let dk = <E as Engine>::CE::derand_key(&ck);
    let vk_digest = spartan_vk.digest();
    let shape_padded = shape_raw.pad();

    // Extract `derand_h`: `derandomize(dk, O, -1) == +h`!
    let zero_comm = Commitment::<E>::default();
    let plus_h_comm = <E as Engine>::CE::derandomize(&dk, &zero_comm, &(-BnScalar::ONE));
    let (hx, hy, h_inf) = plus_h_comm.to_coordinates();
    assert!(!h_inf);
    let derand_h = Option::<BnAffine>::from(halo2curves::CurveAffine::from_xy(hx, hy)).unwrap();

    let ck_ipa = <E as Engine>::CE::setup(b"ipa", 1).map_err(|e| format!("ck_ipa: {e:?}"))?;
    let ck_ipa_s = ck_ipa.generators()[0];

    Ok(Bn254SetupBundle {
        arity,
        shape_raw,
        shape_padded,
        ck,
        dk,
        spartan_pk,
        spartan_vk,
        vk_digest,
        derand_h,
        ck_ipa_s,
    })
}

fn comm_to_near64(c: &Commitment<E>) -> [u8; 64] {
    let (x, y, inf) = c.to_coordinates();
    if inf {
        [0u8; 64]
    } else {
        let mut b = [0u8; 64];
        b[0..32].copy_from_slice(x.to_repr().as_ref());
        b[32..64].copy_from_slice(y.to_repr().as_ref());
        b
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedVkChunk {
    pub kind: u8,
    pub chunk_idx: u32,
    pub merkle_index: u32,
    pub merkle_siblings: Vec<[u8; 32]>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportedVkMerkleBundle {
    pub compact_vk: CompactPinnedVerifierKey,
    pub r1cs_chunks: Vec<AuthenticatedVkChunk>,
    pub msm_chunks: Vec<AuthenticatedVkChunk>,
}

fn pack_sparse_matrices(shape_padded: &R1CSShape<E>) -> Vec<Vec<u8>> {
    let one = BnScalar::ONE;
    let neg_one = -BnScalar::ONE;
    let small_pos: Vec<(BnScalar, i8)> = (2i8..=64).map(|k| (BnScalar::from(k as u64), k)).collect();
    let small_neg: Vec<(BnScalar, i8)> = (2i8..=64).map(|k| (-BnScalar::from(k as u64), -k)).collect();

    let matrices: [(u8, &SparseMatrix<BnScalar>); 3] = [
        (0u8, shape_padded.A()),
        (1u8, shape_padded.B()),
        (2u8, shape_padded.C()),
    ];

    let mut chunks = Vec::new();
    let mut cur_buf = vec![0u8; 4]; // placeholder for entry count u32
    let mut cur_count = 0u32;

    for (mat_id, mat) in matrices {
        for (row_idx, ptrs) in mat.indptr.windows(2).enumerate() {
            for idx in ptrs[0]..ptrs[1] {
                let val = mat.data[idx];
                let col_idx = mat.indices[idx];
                if bool::from(val.is_zero()) {
                    continue;
                }
                if cur_count as usize == R1CS_CHUNK_ENTRIES {
                    cur_buf[0..4].copy_from_slice(&cur_count.to_le_bytes());
                    chunks.push(cur_buf);
                    cur_buf = vec![0u8; 4];
                    cur_count = 0;
                }

                let (kind_bits, extra): (u8, Option<Vec<u8>>) = if val == one {
                    (0, None)
                } else if val == neg_one {
                    (1, None)
                } else if let Some((_, k)) = small_pos.iter().find(|(v, _)| *v == val) {
                    (2, Some(vec![*k as u8]))
                } else if let Some((_, k)) = small_neg.iter().find(|(v, _)| *v == val) {
                    (2, Some(vec![*k as u8]))
                } else {
                    (3, Some(val.to_repr().as_ref().to_vec()))
                };

                let tag = (mat_id & 0x03) | ((kind_bits & 0x03) << 2);
                cur_buf.push(tag);
                cur_buf.extend_from_slice(&(row_idx as u32).to_le_bytes());
                cur_buf.extend_from_slice(&(col_idx as u32).to_le_bytes());
                if let Some(ext) = extra {
                    cur_buf.extend_from_slice(&ext);
                }
                cur_count += 1;
            }
        }
    }
    if cur_count > 0 || chunks.is_empty() {
        cur_buf[0..4].copy_from_slice(&cur_count.to_le_bytes());
        chunks.push(cur_buf);
    }
    chunks
}

pub fn export_vk_merkle_bundle(
    setup: &Bn254SetupBundle,
    relation: &str,
) -> ExportedVkMerkleBundle {
    let r1cs_payloads = pack_sparse_matrices(&setup.shape_padded);
    let n_ipa = setup.shape_padded.num_cons().max(setup.shape_padded.num_vars());
    let gens = &setup.ck.generators()[..n_ipa];
    let msm_payloads: Vec<Vec<u8>> = gens
        .chunks(MSM_CHUNK_SIZE)
        .map(|slice| {
            let mut b = Vec::with_capacity(slice.len() * 64);
            for g in slice {
                b.extend_from_slice(&bn_affine_to_near64(g));
            }
            b
        })
        .collect();

    let num_r1cs = r1cs_payloads.len() as u32;
    let num_msm = msm_payloads.len() as u32;
    let total_real_leaves = (num_r1cs + num_msm) as usize;
    let tree_size = total_real_leaves.next_power_of_two().max(2);

    let mut leaves = vec![[0u8; 32]; tree_size];
    for (i, p) in r1cs_payloads.iter().enumerate() {
        leaves[i] = vk_chunk_leaf_hash(CHUNK_KIND_R1CS, i as u32, p);
    }
    for (i, p) in msm_payloads.iter().enumerate() {
        let m_idx = (num_r1cs as usize) + i;
        leaves[m_idx] = vk_chunk_leaf_hash(CHUNK_KIND_MSM, i as u32, p);
    }

    // Build balanced binary Merkle tree over `tree_size` leaves
    let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let next: Vec<[u8; 32]> = (0..prev.len() / 2)
            .map(|i| {
                let mut h = Sha256::new();
                h.update(VK_NODE_DOMAIN);
                h.update(prev[2 * i]);
                h.update(prev[2 * i + 1]);
                h.finalize().into()
            })
            .collect();
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];

    let build_branch = |merkle_idx: usize| -> Vec<[u8; 32]> {
        let mut idx = merkle_idx;
        let mut sibs = Vec::with_capacity(levels.len() - 1);
        for lvl in &levels[..levels.len() - 1] {
            sibs.push(lvl[idx ^ 1]);
            idx >>= 1;
        }
        sibs
    };

    let r1cs_chunks = r1cs_payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| AuthenticatedVkChunk {
            kind: CHUNK_KIND_R1CS,
            chunk_idx: i as u32,
            merkle_index: i as u32,
            merkle_siblings: build_branch(i),
            payload,
        })
        .collect();

    let msm_chunks = msm_payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let m_idx = (num_r1cs as usize) + i;
            AuthenticatedVkChunk {
                kind: CHUNK_KIND_MSM,
                chunk_idx: i as u32,
                merkle_index: m_idx as u32,
                merkle_siblings: build_branch(m_idx),
                payload,
            }
        })
        .collect();

    let compact_vk = CompactPinnedVerifierKey {
        relation: relation.to_owned(),
        arity: setup.arity,
        num_cons_padded: setup.shape_padded.num_cons(),
        num_vars_padded: setup.shape_padded.num_vars(),
        num_io: setup.shape_padded.num_io(),
        vk_digest_le32: scalar_to_le32(&setup.vk_digest),
        derand_h_near64: bn_affine_to_near64(&setup.derand_h),
        ipa_ck_s_near64: bn_affine_to_near64(&setup.ck_ipa_s),
        num_r1cs_chunks: num_r1cs,
        num_msm_chunks: num_msm,
        vk_chunks_merkle_root: root,
    };

    ExportedVkMerkleBundle {
        compact_vk,
        r1cs_chunks,
        msm_chunks,
    }
}

pub fn prove_bn254_nifs_spartan<C: StepCircuit<BnScalar> + Clone>(
    setup: &Bn254SetupBundle,
    relation: &str,
    steps: &[C],
    z0: &[BnScalar],
    expected_z8: &[BnScalar],
) -> Result<Bn254NifsSpartanProof, String> {
    if steps.len() != 8 {
        return Err("expected exactly 8 hourly step circuits".into());
    }
    let arity = setup.arity;
    if z0.len() != arity || expected_z8.len() != arity {
        return Err("arity mismatch on z0 / expected_z8".into());
    }
    let vk_digest_le = scalar_to_le32(&setup.vk_digest);

    let mut step_instances: Vec<R1CSInstance<E>> = Vec::with_capacity(8);
    let mut step_witnesses: Vec<R1CSWitness<E>> = Vec::with_capacity(8);
    let mut step_comm_w: Vec<[u8; 64]> = Vec::with_capacity(8);
    let mut intermediate_states: Vec<Vec<[u8; 32]>> = Vec::with_capacity(7);

    let mut cur_z = z0.to_vec();
    for (k, step) in steps.iter().enumerate() {
        let mut cs = SatisfyingAssignment::<E>::new();
        let dc: DirectCircuit<E, C> = DirectCircuit::new(Some(cur_z.clone()), step.clone());
        dc.synthesize(&mut cs)
            .map_err(|e| format!("step {k} synthesize: {e:?}"))?;
        let (u, w) = cs
            .r1cs_instance_and_witness(&setup.shape_raw, &setup.ck, &mut OsRng)
            .map_err(|e| format!("step {k} witness: {e:?}"))?;
        if u.X().len() != 2 * arity || &u.X()[0..arity] != cur_z.as_slice() {
            return Err(format!("step {k} public input binding mismatch"));
        }
        let next_z = u.X()[arity..2 * arity].to_vec();
        if k < 7 {
            intermediate_states.push(next_z.iter().map(scalar_to_le32).collect());
        } else if next_z != expected_z8 {
            return Err("step 7 terminal state does not match expected z8".into());
        }
        cur_z = next_z;
        step_comm_w.push(comm_to_near64(u.comm_W()));
        step_instances.push(u);
        step_witnesses.push(w);
    }

    let mut acc_u = RelaxedR1CSInstance::from_r1cs_instance(
        &setup.ck,
        &setup.shape_raw,
        &step_instances[0],
    );
    let mut acc_w = RelaxedR1CSWitness::from_r1cs_witness(&setup.shape_raw, &step_witnesses[0]);
    let mut nifs_comm_t = Vec::with_capacity(7);
    let one_le = scalar_to_le32(&BnScalar::ONE);

    for k in 1..8 {
        let r_t = BnScalar::random(&mut OsRng);
        let (t_vec, comm_t) = setup
            .shape_raw
            .commit_T(
                &setup.ck,
                &acc_u,
                &acc_w,
                &step_instances[k],
                &step_witnesses[k],
                &r_t,
            )
            .map_err(|e| format!("NIFS commit_T fold {k}: {e:?}"))?;
        let comm_t_near = comm_to_near64(&comm_t);
        let acc_x_le: Vec<[u8; 32]> = acc_u.X().iter().map(scalar_to_le32).collect();
        let inc_x_le: Vec<[u8; 32]> = step_instances[k].X().iter().map(scalar_to_le32).collect();
        let chal = derive_nifs_challenge_with(
            &native_keccak256,
            &vk_digest_le,
            k as u64,
            &comm_to_near64(acc_u.comm_W()),
            &comm_to_near64(acc_u.comm_E()),
            &scalar_to_le32(&acc_u.u()),
            &acc_x_le,
            &step_comm_w[k],
            &[0u8; 64],
            &one_le,
            &inc_x_le,
            &comm_t_near,
        );
        acc_u = acc_u.fold(&step_instances[k], &comm_t, &chal);
        acc_w = acc_w
            .fold(&step_witnesses[k], &t_vec, &r_t, &chal)
            .map_err(|e| format!("NIFS witness fold {k}: {e:?}"))?;
        nifs_comm_t.push(comm_t_near);
    }

    let (rand_u, rand_w) = setup
        .shape_raw
        .sample_random_instance_witness(&setup.ck)
        .map_err(|e| format!("sample_random_instance_witness: {e:?}"))?;
    let r_t_zk = BnScalar::random(&mut OsRng);
    let (t_zk, comm_t_zk) = setup
        .shape_raw
        .commit_T_relaxed(&setup.ck, &acc_u, &acc_w, &rand_u, &rand_w, &r_t_zk)
        .map_err(|e| format!("commit_T_relaxed: {e:?}"))?;
    let comm_t_zk_near = comm_to_near64(&comm_t_zk);
    let rand_comm_w_near = comm_to_near64(rand_u.comm_W());
    let rand_comm_e_near = comm_to_near64(rand_u.comm_E());
    let rand_u_le = scalar_to_le32(&rand_u.u());
    let rand_x_le: Vec<[u8; 32]> = rand_u.X().iter().map(scalar_to_le32).collect();
    let acc_x_le: Vec<[u8; 32]> = acc_u.X().iter().map(scalar_to_le32).collect();

    let chal_zk = derive_nifs_challenge_with(
        &native_keccak256,
        &vk_digest_le,
        8,
        &comm_to_near64(acc_u.comm_W()),
        &comm_to_near64(acc_u.comm_E()),
        &scalar_to_le32(&acc_u.u()),
        &acc_x_le,
        &rand_comm_w_near,
        &rand_comm_e_near,
        &rand_u_le,
        &rand_x_le,
        &comm_t_zk_near,
    );
    let folded_u = acc_u.fold_relaxed(&rand_u, &comm_t_zk, &chal_zk);
    let folded_w = acc_w
        .fold_relaxed(&rand_w, &t_zk, &r_t_zk, &chal_zk)
        .map_err(|e| format!("fold_relaxed witness: {e:?}"))?;

    setup
        .shape_raw
        .is_sat_relaxed(&setup.ck, &folded_u, &folded_w)
        .map_err(|e| format!("folded instance failed is_sat_relaxed: {e:?}"))?;

    let (derand_w, wit_blind, err_blind) = folded_w.derandomize();
    let derand_u = folded_u.derandomize(&setup.dk, &wit_blind, &err_blind);
    let snark = SpartanSnark::prove(
        &setup.ck,
        &setup.spartan_pk,
        &setup.shape_raw,
        &derand_u,
        &derand_w,
    )
    .map_err(|e| format!("SpartanSnark::prove: {e:?}"))?;

    snark
        .verify(&setup.spartan_vk, &derand_u)
        .map_err(|e| format!("SpartanSnark::verify self-check failed: {e:?}"))?;

    let spartan_snark_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&snark)
        .map_err(|e| format!("serialize SpartanSnark: {e}"))?;

    Ok(Bn254NifsSpartanProof {
        relation: relation.to_owned(),
        steps: 8,
        step_comm_w,
        intermediate_states,
        nifs_comm_t,
        randomizer_comm_w: rand_comm_w_near,
        randomizer_comm_e: rand_comm_e_near,
        randomizer_u: rand_u_le,
        randomizer_x: rand_x_le,
        nifs_zk_comm_t: comm_t_zk_near,
        wit_blind: scalar_to_le32(&wit_blind),
        err_blind: scalar_to_le32(&err_blind),
        spartan_snark_bytes,
    })
}

/// Runs the exact chunked `Route B + Route C` verification protocol natively (exercising
/// the exact same functions compiled into the NEAR WASM contract!).
pub fn verify_bn254_chunked_protocol_native(
    vk_bundle: &ExportedVkMerkleBundle,
    proof: &Bn254NifsSpartanProof,
    proof_sha256: [u8; 32],
    expected_z0: &[BnScalar],
    expected_z8: &[BnScalar],
    enforce_constant_claim_tail: bool,
) -> Result<(), String> {
    let mut session = begin_decider_session(
        &vk_bundle.compact_vk,
        proof,
        proof_sha256,
        expected_z0,
        expected_z8,
        enforce_constant_claim_tail,
        native_keccak256,
        native_bn254_multiexp,
    )?;
    for chunk in &vk_bundle.r1cs_chunks {
        evaluate_packed_r1cs_chunk(
            &mut session,
            chunk.chunk_idx,
            chunk.merkle_index,
            &chunk.merkle_siblings,
            &chunk.payload,
            crate::decider_equations::sha256_bytes,
        )?;
    }
    for chunk in &vk_bundle.msm_chunks {
        evaluate_msm_chunk(
            &mut session,
            chunk.chunk_idx,
            chunk.merkle_index,
            &chunk.merkle_siblings,
            &chunk.payload,
            crate::decider_equations::sha256_bytes,
            native_bn254_multiexp,
        )?;
    }
    finalize_decider_session(
        &mut session,
        &vk_bundle.compact_vk.ipa_ck_s_near64,
        native_bn254_multiexp,
    )
}
