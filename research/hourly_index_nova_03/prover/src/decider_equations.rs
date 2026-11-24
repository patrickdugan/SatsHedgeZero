//! Shared, self-contained transparent Nova NIFS + Spartan/IPA Decider Equations (`Route B + C`).
//!
//! Compiled BOTH natively inside `shz-index03-prover` AND to `wasm32-unknown-unknown` inside
//! `shz-index03-near-verifier` with ZERO `nova-snark` crate dependency on WASM, parameterized
//! over pluggable `keccak256` and `bn254_g1_multiexp` callbacks so NEAR WASM invokes native
//! `env::keccak256` and `env::alt_bn128_g1_multiexp` host precompiles directly.
#![forbid(unsafe_code)]

use bincode::Options;
use ff::{Field, FromUniformBytes, PrimeField};
use halo2curves::{
    bn256::{Fq as BnBase, Fr as BnScalar, G1 as BnPoint, G1Affine as BnAffine},
    group::{prime::PrimeCurveAffine, Curve},
    CurveAffine,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const NIFS_DOMAIN_TAG: &[u8] = b"SHZ/BN254-NOVA-NIFS-8H/V1";
pub const VK_LEAF_DOMAIN: &[u8] = b"SHZ/VK-CHUNK-LEAF/V1";
pub const VK_NODE_DOMAIN: &[u8] = b"SHZ/VK-CHUNK-NODE/V1";
pub const CHUNK_KIND_R1CS: u8 = 1;
pub const CHUNK_KIND_MSM: u8 = 2;

/// Power-of-two BN254 generator chunk size (`512 = 2^9`, ~176 TGas per NEAR tx via `alt_bn128_g1_multiexp`).
pub const MSM_CHUNK_SIZE: usize = 512;

/// Maximum sparse R1CS entries per chunk (`16,384`, ~125 TGas per NEAR tx).
pub const R1CS_CHUNK_ENTRIES: usize = 16_384;

mod serde_bytes64 {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let mut pair = [[0u8; 32]; 2];
        pair[0].copy_from_slice(&v[0..32]);
        pair[1].copy_from_slice(&v[32..64]);
        pair.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let pair = <[[u8; 32]; 2]>::deserialize(d)?;
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&pair[0]);
        out[32..64].copy_from_slice(&pair[1]);
        Ok(out)
    }
}

mod serde_vec_bytes64 {
    use super::*;
    pub fn serialize<S: Serializer>(list: &[[u8; 64]], s: S) -> Result<S::Ok, S::Error> {
        let pairs: Vec<[[u8; 32]; 2]> = list
            .iter()
            .map(|v| {
                let mut p = [[0u8; 32]; 2];
                p[0].copy_from_slice(&v[0..32]);
                p[1].copy_from_slice(&v[32..64]);
                p
            })
            .collect();
        pairs.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 64]>, D::Error> {
        let pairs = <Vec<[[u8; 32]; 2]>>::deserialize(d)?;
        Ok(pairs
            .into_iter()
            .map(|p| {
                let mut out = [0u8; 64];
                out[0..32].copy_from_slice(&p[0]);
                out[32..64].copy_from_slice(&p[1]);
                out
            })
            .collect())
    }
}

const PERSONA_TAG: &[u8] = b"NoTR";
const DOM_SEP_TAG: &[u8] = b"NoDS";
const KECCAK_STATE_SIZE: usize = 64;

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn scalar_to_le32(s: &BnScalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(s.to_repr().as_ref());
    out
}

pub fn scalar_from_le32(bytes: &[u8; 32]) -> Result<BnScalar, String> {
    Option::<BnScalar>::from(BnScalar::from_repr((*bytes).into()))
        .ok_or_else(|| "noncanonical BN254 Fr scalar".into())
}

pub fn bn_affine_to_near64(p: &BnAffine) -> [u8; 64] {
    if bool::from(p.is_identity()) {
        return [0u8; 64];
    }
    let coords = p.coordinates().unwrap();
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(coords.x().to_repr().as_ref());
    out[32..64].copy_from_slice(coords.y().to_repr().as_ref());
    out
}

pub fn bn_point_to_near64(p: &BnPoint) -> [u8; 64] {
    bn_affine_to_near64(&p.to_affine())
}

pub fn bn_near64_to_affine(bytes: &[u8; 64]) -> Result<BnAffine, String> {
    if bytes.iter().all(|&b| b == 0) {
        return Ok(BnAffine::identity());
    }
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&bytes[0..32]);
    yb.copy_from_slice(&bytes[32..64]);
    let x = Option::<BnBase>::from(BnBase::from_repr(xb.into()))
        .ok_or("noncanonical BN254 Fq x")?;
    let y = Option::<BnBase>::from(BnBase::from_repr(yb.into()))
        .ok_or("noncanonical BN254 Fq y")?;
    Option::<BnAffine>::from(BnAffine::from_xy(x, y)).ok_or_else(|| "point not on BN254 G1".into())
}

pub fn commitment_transcript_bytes(near64: &[u8; 64]) -> [u8; 65] {
    let mut out = [0u8; 65];
    if near64.iter().all(|&b| b == 0) {
        out[64] = 1;
    } else {
        out[0..64].copy_from_slice(near64);
        out[64] = 0;
    }
    out
}

/// Exact bit-compatible `Keccak256Transcript<Bn256EngineIPA>` matching `nova-snark =0.76.0`.
pub struct KeccakTranscript<K: Fn(&[u8]) -> [u8; 32]> {
    round: u64,
    state: [u8; KECCAK_STATE_SIZE],
    buf: Vec<u8>,
    keccak: K,
}

impl<K: Fn(&[u8]) -> [u8; 32]> KeccakTranscript<K> {
    fn compute_updated_state(keccak: &K, prefix: &[u8], suffix: &[u8]) -> [u8; KECCAK_STATE_SIZE] {
        let mut msg = Vec::with_capacity(prefix.len() + suffix.len() + 1);
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(suffix);
        msg.push(0u8);
        let lo = keccak(&msg);
        *msg.last_mut().unwrap() = 1u8;
        let hi = keccak(&msg);
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&lo);
        out[32..64].copy_from_slice(&hi);
        out
    }

    pub fn new(label: &[u8], keccak: K) -> Self {
        let mut init = Vec::with_capacity(PERSONA_TAG.len() + label.len());
        init.extend_from_slice(PERSONA_TAG);
        init.extend_from_slice(label);
        let state = Self::compute_updated_state(&keccak, &[], &init);
        Self {
            round: 0,
            state,
            buf: Vec::new(),
            keccak,
        }
    }

    pub fn dom_sep(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(DOM_SEP_TAG);
        self.buf.extend_from_slice(bytes);
    }

    pub fn absorb_raw(&mut self, label: &[u8], repr: &[u8]) {
        self.buf.extend_from_slice(label);
        self.buf.extend_from_slice(repr);
    }

    pub fn absorb_scalar(&mut self, label: &[u8], s: &BnScalar) {
        self.absorb_raw(label, s.to_repr().as_ref());
    }

    pub fn absorb_scalar_slice(&mut self, label: &[u8], list: &[BnScalar]) {
        let mut bytes = Vec::with_capacity(list.len() * 32);
        for s in list {
            bytes.extend_from_slice(s.to_repr().as_ref());
        }
        self.absorb_raw(label, &bytes);
    }

    pub fn absorb_commitment_near64(&mut self, label: &[u8], comm64: &[u8; 64]) {
        let repr = commitment_transcript_bytes(comm64);
        self.absorb_raw(label, &repr);
    }

    pub fn absorb_relaxed_u(&mut self, label: &[u8], comm_w: &[u8; 64], comm_e: &[u8; 64], u: &BnScalar, x: &[BnScalar]) {
        let mut repr = Vec::with_capacity(65 + 65 + 32 + x.len() * 32);
        repr.extend_from_slice(&commitment_transcript_bytes(comm_w));
        repr.extend_from_slice(&commitment_transcript_bytes(comm_e));
        repr.extend_from_slice(u.to_repr().as_ref());
        for xi in x {
            repr.extend_from_slice(xi.to_repr().as_ref());
        }
        self.absorb_raw(label, &repr);
    }

    pub fn squeeze(&mut self, label: &[u8]) -> Result<BnScalar, String> {
        let round_bytes = self.round.to_le_bytes();
        let mut suffix = Vec::with_capacity(DOM_SEP_TAG.len() + 8 + KECCAK_STATE_SIZE + label.len());
        suffix.extend_from_slice(DOM_SEP_TAG);
        suffix.extend_from_slice(&round_bytes);
        suffix.extend_from_slice(&self.state);
        suffix.extend_from_slice(label);

        let out = Self::compute_updated_state(&self.keccak, &self.buf, &suffix);
        self.round = self.round.checked_add(1).ok_or("transcript round overflow")?;
        self.state = out;
        self.buf.clear();
        Ok(BnScalar::from_uniform_bytes(&out))
    }
}

pub fn derive_nifs_challenge_with<K: Fn(&[u8]) -> [u8; 32]>(
    keccak: &K,
    vk_digest: &[u8; 32],
    step_idx: u64,
    u_acc_comm_w: &[u8; 64],
    u_acc_comm_e: &[u8; 64],
    u_acc_u: &[u8; 32],
    u_acc_x: &[[u8; 32]],
    inc_comm_w: &[u8; 64],
    inc_comm_e: &[u8; 64],
    inc_u: &[u8; 32],
    inc_x: &[[u8; 32]],
    comm_t: &[u8; 64],
) -> BnScalar {
    let mut pre = Vec::with_capacity(512);
    pre.extend_from_slice(NIFS_DOMAIN_TAG);
    pre.extend_from_slice(vk_digest);
    pre.extend_from_slice(&step_idx.to_le_bytes());
    pre.extend_from_slice(u_acc_comm_w);
    pre.extend_from_slice(u_acc_comm_e);
    pre.extend_from_slice(u_acc_u);
    pre.extend_from_slice(&(u_acc_x.len() as u64).to_le_bytes());
    for x in u_acc_x {
        pre.extend_from_slice(x);
    }
    pre.extend_from_slice(inc_comm_w);
    pre.extend_from_slice(inc_comm_e);
    pre.extend_from_slice(inc_u);
    pre.extend_from_slice(&(inc_x.len() as u64).to_le_bytes());
    for x in inc_x {
        pre.extend_from_slice(x);
    }
    pre.extend_from_slice(comm_t);
    pre.push(0u8);
    let lo = keccak(&pre);
    *pre.last_mut().unwrap() = 1u8;
    let hi = keccak(&pre);
    let mut wide = [0u8; 64];
    wide[0..32].copy_from_slice(&lo);
    wide[32..64].copy_from_slice(&hi);
    BnScalar::from_uniform_bytes(&wide)
}

/// Wire mirror of `nova_snark::spartan::polys::univariate::CompressedUniPoly<BnScalar>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCompressedUniPoly {
    pub coeffs_except_linear_term: Vec<BnScalar>,
}

impl WireCompressedUniPoly {
    pub fn decompress_and_eval(
        &self,
        hint: &BnScalar,
        degree_bound: usize,
        transcript: &mut KeccakTranscript<impl Fn(&[u8]) -> [u8; 32]>,
    ) -> Result<(BnScalar, BnScalar), String> {
        if self.coeffs_except_linear_term.is_empty() || self.coeffs_except_linear_term.len() > degree_bound {
            return Err("InvalidSumcheckProof: degree bound exceeded or empty CompressedUniPoly".into());
        }
        let c0 = self.coeffs_except_linear_term[0];
        let mut linear = *hint - c0 - c0;
        for c in &self.coeffs_except_linear_term[1..] {
            linear -= *c;
        }
        let mut coeffs = Vec::with_capacity(self.coeffs_except_linear_term.len() + 1);
        coeffs.push(c0);
        coeffs.push(linear);
        coeffs.extend_from_slice(&self.coeffs_except_linear_term[1..]);

        // TranscriptReprTrait for UniPoly absorbs `self.compress().coeffs_except_linear_term`!
        let compressed_for_transcript = [&coeffs[0..1], &coeffs[2..]].concat();
        transcript.absorb_scalar_slice(b"p", &compressed_for_transcript);
        let r_i = transcript.squeeze(b"c")?;

        let mut eval = coeffs[0];
        let mut pow = r_i;
        for c in &coeffs[1..] {
            eval += pow * c;
            pow *= r_i;
        }
        Ok((eval, r_i))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSumcheckProof {
    pub compressed_polys: Vec<WireCompressedUniPoly>,
}

impl WireSumcheckProof {
    pub fn verify(
        &self,
        claim: BnScalar,
        num_rounds: usize,
        degree_bound: usize,
        transcript: &mut KeccakTranscript<impl Fn(&[u8]) -> [u8; 32]>,
    ) -> Result<(BnScalar, Vec<BnScalar>), String> {
        if self.compressed_polys.len() != num_rounds {
            return Err("InvalidSumcheckProof: round count mismatch".into());
        }
        let mut e = claim;
        let mut r = Vec::with_capacity(num_rounds);
        for poly in &self.compressed_polys {
            let (next_e, r_i) = poly.decompress_and_eval(&e, degree_bound, transcript)?;
            e = next_e;
            r.push(r_i);
        }
        Ok((e, r))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCommitment {
    pub comm: BnPoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireIpaArgument {
    pub l_vec: Vec<WireCommitment>,
    pub r_vec: Vec<WireCommitment>,
    pub a_hat: BnScalar,
}

/// Exact `bincode` wire mirror of `nova_snark::spartan::snark::RelaxedR1CSSNARK<Bn256EngineIPA, EvaluationEngine<Bn256EngineIPA>>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRelaxedR1csSnark {
    pub sc_proof_outer: WireSumcheckProof,
    pub claims_outer: (BnScalar, BnScalar, BnScalar),
    pub eval_e: BnScalar,
    pub sc_proof_inner: WireSumcheckProof,
    pub eval_w: BnScalar,
    pub sc_proof_batch: WireSumcheckProof,
    pub evals_batch: Vec<BnScalar>,
    pub eval_arg: WireIpaArgument,
}

impl WireRelaxedR1csSnark {
    pub fn decode_strict(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("Spartan SNARK exceeds byte cap".into());
        }
        let decoded: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(2 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| format!("Spartan SNARK decode failed: {e}"))?;
        let reencoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&decoded)
            .map_err(|e| format!("Spartan SNARK re-encode failed: {e}"))?;
        if reencoded != bytes {
            return Err("non-canonical Spartan SNARK serialization".into());
        }
        Ok(decoded)
    }
}

/// Wire proof bundle shared by prover CLI and NEAR WASM contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bn254NifsSpartanProof {
    pub relation: String,
    pub steps: usize,
    #[serde(with = "serde_vec_bytes64")]
    pub step_comm_w: Vec<[u8; 64]>,
    pub intermediate_states: Vec<Vec<[u8; 32]>>,
    #[serde(with = "serde_vec_bytes64")]
    pub nifs_comm_t: Vec<[u8; 64]>,
    #[serde(with = "serde_bytes64")]
    pub randomizer_comm_w: [u8; 64],
    #[serde(with = "serde_bytes64")]
    pub randomizer_comm_e: [u8; 64],
    pub randomizer_u: [u8; 32],
    pub randomizer_x: Vec<[u8; 32]>,
    #[serde(with = "serde_bytes64")]
    pub nifs_zk_comm_t: [u8; 64],
    pub wit_blind: [u8; 32],
    pub err_blind: [u8; 32],
    pub spartan_snark_bytes: Vec<u8>,
}

/// Compact pinned Verifier Key metadata stored on-chain in NEAR (~420 bytes!).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactPinnedVerifierKey {
    pub relation: String,
    pub arity: usize,
    pub num_cons_padded: usize,
    pub num_vars_padded: usize,
    pub num_io: usize,
    pub vk_digest_le32: [u8; 32],
    #[serde(with = "serde_bytes64")]
    pub derand_h_near64: [u8; 64],
    #[serde(with = "serde_bytes64")]
    pub ipa_ck_s_near64: [u8; 64],
    pub num_r1cs_chunks: u32,
    pub num_msm_chunks: u32,
    pub vk_chunks_merkle_root: [u8; 32],
}

/// Authenticated intermediate verification state (`Route C`) produced by `begin_decider_session`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedVerificationSession {
    pub relation: String,
    pub proof_sha256: [u8; 32],
    pub vk_chunks_merkle_root: [u8; 32],
    pub z0_le32: Vec<[u8; 32]>,
    pub z8_le32: Vec<[u8; 32]>,
    pub num_cons_padded: usize,
    pub num_vars_padded: usize,
    // Locked Spartan inner R1CS matrix check targets:
    pub r_x_le32: Vec<[u8; 32]>,
    pub r_y_le32: Vec<[u8; 32]>,
    pub r_inner_le32: [u8; 32],
    pub eval_z_le32: [u8; 32],
    pub claim_inner_final_le32: [u8; 32],
    pub acc_eval_a_le32: [u8; 32],
    pub acc_eval_b_le32: [u8; 32],
    pub acc_eval_c_le32: [u8; 32],
    // Locked IPA generator MSM check targets:
    pub ipa_r_le32: Vec<[u8; 32]>,
    pub ipa_r_inv_le32: Vec<[u8; 32]>,
    pub a_hat_le32: [u8; 32],
    pub b_hat_le32: [u8; 32],
    pub r_ipa_le32: [u8; 32],
    #[serde(with = "serde_bytes64")]
    pub p_hat_near64: [u8; 64],
    #[serde(with = "serde_bytes64")]
    pub acc_g_hat_near64: [u8; 64],
    // Replay-free chunk completion bitmaps:
    pub num_r1cs_chunks: u32,
    pub verified_r1cs_chunks: u32,
    pub r1cs_bitmap: Vec<u64>,
    pub num_msm_chunks: u32,
    pub verified_msm_chunks: u32,
    pub msm_bitmap: Vec<u64>,
    pub finalized: bool,
}

pub fn eq_poly_evaluate(rx: &[BnScalar], ry: &[BnScalar]) -> BnScalar {
    assert_eq!(rx.len(), ry.len());
    rx.iter()
        .zip(ry.iter())
        .map(|(x, y)| *x * *y + (BnScalar::ONE - *x) * (BnScalar::ONE - *y))
        .fold(BnScalar::ONE, |acc, v| acc * v)
}

pub fn eq_evals_from_points(r: &[BnScalar]) -> Vec<BnScalar> {
    let mut evals = vec![BnScalar::ZERO; 1usize << r.len()];
    evals[0] = BnScalar::ONE;
    let mut size = 1usize;
    for point in r.iter().rev() {
        let (left, right) = evals.split_at_mut(size);
        let (right, _) = right.split_at_mut(size);
        for (x, y) in left.iter_mut().zip(right.iter_mut()) {
            *y = *x * *point;
            *x -= &*y;
        }
        size <<= 1;
    }
    evals
}

/// Evaluates `SparsePolynomial(num_vars_log2, Z)` at `r` matching `nova-snark`'s `SparsePolynomial::evaluate`.
pub fn sparse_poly_evaluate(num_vars: usize, z: &[BnScalar], r: &[BnScalar]) -> BnScalar {
    assert_eq!(num_vars, r.len());
    let mut acc = BnScalar::ZERO;
    for (idx, coeff) in z.iter().enumerate() {
        if bool::from(coeff.is_zero()) {
            continue;
        }
        let mut term = *coeff;
        for (bit_pos, r_j) in r.iter().enumerate() {
            let bit = (idx >> (num_vars - 1 - bit_pos)) & 1;
            if bit == 1 {
                term *= *r_j;
            } else {
                term *= BnScalar::ONE - *r_j;
            }
        }
        acc += term;
    }
    acc
}

pub fn batch_invert_scalars(v: &[BnScalar]) -> Result<Vec<BnScalar>, String> {
    let mut products = vec![BnScalar::ZERO; v.len()];
    let mut acc = BnScalar::ONE;
    for (i, x) in v.iter().enumerate() {
        products[i] = acc;
        acc *= *x;
    }
    let inv_opt = acc.invert();
    if bool::from(inv_opt.is_none()) {
        return Err("zero challenge in IPA batch_invert".into());
    }
    let mut acc_inv = inv_opt.unwrap();
    let mut out = vec![BnScalar::ZERO; v.len()];
    for i in (0..v.len()).rev() {
        let tmp = acc_inv * v[i];
        out[i] = products[i] * acc_inv;
        acc_inv = tmp;
    }
    Ok(out)
}

/// Executes Phase 1 of `Route B + Route C`:
/// Verifies all 8 step transitions, batched NIFS + ZK folding + unblinding, all 3 Spartan
/// sumchecks, IPA Fiat-Shamir challenges, $O(\log N)$ factorized $\hat{b}$, and weighted $P_{\text{hat}}$!
pub fn begin_decider_session<K, M>(
    vk: &CompactPinnedVerifierKey,
    proof: &Bn254NifsSpartanProof,
    proof_sha256: [u8; 32],
    expected_z0: &[BnScalar],
    expected_z8: &[BnScalar],
    enforce_constant_claim_tail: bool,
    keccak: K,
    multiexp: M,
) -> Result<AuthenticatedVerificationSession, String>
where
    K: Fn(&[u8]) -> [u8; 32],
    M: Fn(&[([u8; 64], [u8; 32])]) -> Result<[u8; 64], String>,
{
    if proof.relation != vk.relation || proof.steps != 8 {
        return Err("proof relation or step count (expected 8) mismatch".into());
    }
    if expected_z0.len() != vk.arity
        || expected_z8.len() != vk.arity
        || vk.num_io != 2 * vk.arity
    {
        return Err("public state arity mismatch".into());
    }
    if proof.step_comm_w.len() != 8
        || proof.intermediate_states.len() != 7
        || proof.nifs_comm_t.len() != 7
        || proof.randomizer_x.len() != vk.num_io
    {
        return Err("malformed NIFS proof vector lengths".into());
    }

    // Validate every curve point in the NIFS envelope is on BN254 G1!
    for pt in proof
        .step_comm_w
        .iter()
        .chain(proof.nifs_comm_t.iter())
        .chain([
            &proof.randomizer_comm_w,
            &proof.randomizer_comm_e,
            &proof.nifs_zk_comm_t,
        ])
    {
        bn_near64_to_affine(pt)?;
    }

    // Reconstruct and validate all 8 step public IO transitions z_0 -> z_1 -> ... -> z_8!
    let mut z_states: Vec<Vec<BnScalar>> = Vec::with_capacity(9);
    z_states.push(expected_z0.to_vec());
    for (k, raw_z) in proof.intermediate_states.iter().enumerate() {
        if raw_z.len() != vk.arity {
            return Err("intermediate state arity mismatch".into());
        }
        let parsed: Vec<BnScalar> = raw_z
            .iter()
            .map(scalar_from_le32)
            .collect::<Result<_, _>>()?;
        // Enforce monotonic fold counter `z_k[0] == k + 1` and invariant pinned header `z_k[1..8] == z_0[1..8]`!
        if parsed[0] != BnScalar::from((k + 1) as u64) {
            return Err(format!("intermediate step {} count != {}", k + 1, k + 1));
        }
        let tail_end = vk.arity.min(8);
        if enforce_constant_claim_tail && tail_end > 1 && parsed[1..tail_end] != expected_z0[1..tail_end] {
            return Err("intermediate state mutated pinned checkpoint claim".into());
        }
        z_states.push(parsed);
    }
    z_states.push(expected_z8.to_vec());

    let step_ios: Vec<Vec<BnScalar>> = (0..8)
        .map(|k| {
            let mut io = Vec::with_capacity(2 * vk.arity);
            io.extend_from_slice(&z_states[k]);
            io.extend_from_slice(&z_states[k + 1]);
            io
        })
        .collect();

    // Replay NIFS challenges `chal[1..8]`!
    // Notice `derive_nifs_challenge` depends on `acc_u.comm_W` and `acc_u.comm_E` at each step,
    // which are 2-point / 3-point BN254 multiexps (`7 * 2 = 14` tiny multiexps or computed sequentially).
    let mut acc_comm_w = proof.step_comm_w[0];
    let mut acc_comm_e = [0u8; 64];
    let mut acc_u = BnScalar::ONE;
    let mut acc_x = step_ios[0].clone();
    let one_le = scalar_to_le32(&BnScalar::ONE);

    for k in 1..8 {
        let acc_x_le: Vec<[u8; 32]> = acc_x.iter().map(scalar_to_le32).collect();
        let inc_x_le: Vec<[u8; 32]> = step_ios[k].iter().map(scalar_to_le32).collect();
        let chal = derive_nifs_challenge_with(
            &keccak,
            &vk.vk_digest_le32,
            k as u64,
            &acc_comm_w,
            &acc_comm_e,
            &scalar_to_le32(&acc_u),
            &acc_x_le,
            &proof.step_comm_w[k],
            &[0u8; 64],
            &one_le,
            &inc_x_le,
            &proof.nifs_comm_t[k - 1],
        );
        let chal_le = scalar_to_le32(&chal);
        acc_comm_w = multiexp(&[(acc_comm_w, one_le), (proof.step_comm_w[k], chal_le)])?;
        acc_comm_e = multiexp(&[(acc_comm_e, one_le), (proof.nifs_comm_t[k - 1], chal_le)])?;
        acc_u += chal;
        for (a, b) in acc_x.iter_mut().zip(step_ios[k].iter()) {
            *a += chal * *b;
        }
    }

    // Fold ZK randomizer instance + unblind commitments in ONE batched multiexp per commitment!
    let rand_u = scalar_from_le32(&proof.randomizer_u)?;
    let rand_x: Vec<BnScalar> = proof
        .randomizer_x
        .iter()
        .map(scalar_from_le32)
        .collect::<Result<_, _>>()?;
    let wit_blind = scalar_from_le32(&proof.wit_blind)?;
    let err_blind = scalar_from_le32(&proof.err_blind)?;

    let acc_x_le: Vec<[u8; 32]> = acc_x.iter().map(scalar_to_le32).collect();
    let chal_zk = derive_nifs_challenge_with(
        &keccak,
        &vk.vk_digest_le32,
        8,
        &acc_comm_w,
        &acc_comm_e,
        &scalar_to_le32(&acc_u),
        &acc_x_le,
        &proof.randomizer_comm_w,
        &proof.randomizer_comm_e,
        &proof.randomizer_u,
        &proof.randomizer_x,
        &proof.nifs_zk_comm_t,
    );
    let chal_zk_sq = chal_zk.square();
    let neg_wit_blind = -wit_blind;
    let neg_err_blind = -err_blind;

    let derand_comm_w = multiexp(&[
        (acc_comm_w, one_le),
        (proof.randomizer_comm_w, scalar_to_le32(&chal_zk)),
        (vk.derand_h_near64, scalar_to_le32(&neg_wit_blind)),
    ])?;
    let derand_comm_e = multiexp(&[
        (acc_comm_e, one_le),
        (proof.nifs_zk_comm_t, scalar_to_le32(&chal_zk)),
        (proof.randomizer_comm_e, scalar_to_le32(&chal_zk_sq)),
        (vk.derand_h_near64, scalar_to_le32(&neg_err_blind)),
    ])?;
    let derand_u = acc_u + chal_zk * rand_u;
    let derand_x: Vec<BnScalar> = acc_x
        .iter()
        .zip(rand_x.iter())
        .map(|(a, b)| *a + chal_zk * *b)
        .collect();

    // Decode Spartan SNARK strictly and replay exact RelaxedR1CSSNARK::verify!
    let snark = WireRelaxedR1csSnark::decode_strict(&proof.spartan_snark_bytes)?;
    let vk_digest = scalar_from_le32(&vk.vk_digest_le32)?;

    if !vk.num_cons_padded.is_power_of_two() || !vk.num_vars_padded.is_power_of_two() {
        return Err("non-power-of-two padded shape".into());
    }
    let num_rounds_x = vk.num_cons_padded.ilog2() as usize;
    let num_rounds_y = (vk.num_vars_padded.ilog2() as usize) + 1;

    let mut transcript = KeccakTranscript::new(b"RelaxedR1CSSNARK", keccak);
    transcript.absorb_scalar(b"vk", &vk_digest);
    transcript.absorb_relaxed_u(b"U", &derand_comm_w, &derand_comm_e, &derand_u, &derand_x);

    // 1. Outer cubic sumcheck (`num_rounds_x` rounds)
    let tau: Vec<BnScalar> = (0..num_rounds_x)
        .map(|_| transcript.squeeze(b"t"))
        .collect::<Result<_, _>>()?;
    let (claim_outer_final, r_x) =
        snark
            .sc_proof_outer
            .verify(BnScalar::ZERO, num_rounds_x, 3, &mut transcript)?;
    let (claim_az, claim_bz, claim_cz) = snark.claims_outer;
    let taus_bound_rx = eq_poly_evaluate(&tau, &r_x);
    let claim_outer_expected =
        taus_bound_rx * (claim_az * claim_bz - derand_u * claim_cz - snark.eval_e);
    if claim_outer_final != claim_outer_expected {
        return Err("InvalidSumcheckProof: outer sumcheck final claim mismatch".into());
    }

    transcript.absorb_scalar_slice(
        b"claims_outer",
        &[claim_az, claim_bz, claim_cz, snark.eval_e],
    );

    // 2. Inner quadratic sumcheck (`num_rounds_y` rounds)
    let r_inner = transcript.squeeze(b"r")?;
    let claim_inner_joint = claim_az + r_inner * claim_bz + r_inner * r_inner * claim_cz;
    let (claim_inner_final, r_y) =
        snark
            .sc_proof_inner
            .verify(claim_inner_joint, num_rounds_y, 2, &mut transcript)?;

    let mut public_z = Vec::with_capacity(1 + derand_x.len());
    public_z.push(derand_u);
    public_z.extend_from_slice(&derand_x);
    let eval_x = sparse_poly_evaluate(vk.num_vars_padded.ilog2() as usize, &public_z, &r_y[1..]);
    let eval_z = (BnScalar::ONE - r_y[0]) * snark.eval_w + r_y[0] * eval_x;

    // Note: R1CS sparse matrix evaluation `(eval_A + r * eval_B + r^2 * eval_C) * eval_Z == claim_inner_final`
    // is locked into `AuthenticatedVerificationSession` and verified across the Merkle-authenticated R1CS chunks!
    transcript.absorb_scalar_slice(b"w", &[snark.eval_w]);

    // 3. Batch evaluation sumcheck (`batch_eval_verify` in `spartan/mod.rs` lines 436–483)
    if snark.evals_batch.len() != 2 {
        return Err("InvalidSumcheckProof: expected 2 evals_batch entries".into());
    }
    let rho = transcript.squeeze(b"r")?;
    let powers_of_rho = [BnScalar::ONE, rho];
    let x_w = r_y[1..].to_vec(); // len = log2(num_vars)
    let x_e = r_x.clone(); // len = log2(num_cons)
    let batch_rounds = [x_w.len(), x_e.len()];
    let batch_rounds_max = batch_rounds[0].max(batch_rounds[1]);
    let scale_0 = BnScalar::from(2u64).pow_vartime([(batch_rounds_max - batch_rounds[0]) as u64]);
    let scale_1 = BnScalar::from(2u64).pow_vartime([(batch_rounds_max - batch_rounds[1]) as u64]);
    let batch_init_claim =
        snark.eval_w * scale_0 * powers_of_rho[0] + snark.eval_e * scale_1 * powers_of_rho[1];

    let (claim_batch_final, r_batch) = snark.sc_proof_batch.verify(
        batch_init_claim,
        batch_rounds_max,
        2,
        &mut transcript,
    )?;

    let eq_0 = {
        let (_, r_hi) = r_batch.split_at(batch_rounds_max - x_w.len());
        eq_poly_evaluate(r_hi, &x_w)
    };
    let eq_1 = {
        let (_, r_hi) = r_batch.split_at(batch_rounds_max - x_e.len());
        eq_poly_evaluate(r_hi, &x_e)
    };
    let claim_batch_expected = eq_0 * snark.evals_batch[0] * powers_of_rho[0]
        + eq_1 * snark.evals_batch[1] * powers_of_rho[1];
    if claim_batch_final != claim_batch_expected {
        return Err("InvalidSumcheckProof: batch_eval_verify final claim mismatch".into());
    }

    transcript.absorb_scalar_slice(b"l", &snark.evals_batch);
    let c_batch = transcript.squeeze(b"c")?;

    // `PolyEvalInstance::batch_diff_size`
    let lagrange_0 = r_batch[..batch_rounds_max - batch_rounds[0]]
        .iter()
        .fold(BnScalar::ONE, |acc, r| acc * (BnScalar::ONE - *r));
    let lagrange_1 = r_batch[..batch_rounds_max - batch_rounds[1]]
        .iter()
        .fold(BnScalar::ONE, |acc, r| acc * (BnScalar::ONE - *r));
    let batched_eval = lagrange_0 * snark.evals_batch[0] + c_batch * (lagrange_1 * snark.evals_batch[1]);
    let batched_comm = multiexp(&[
        (derand_comm_w, one_le),
        (derand_comm_e, scalar_to_le32(&c_batch)),
    ])?;

    // 4. InnerProductArgument (`ipa_pc.rs` lines 286–388) with O(log N) factorized b_hat & single weighted P_hat!
    let k_ipa = r_batch.len();
    let n_ipa = 1usize << k_ipa;
    if snark.eval_arg.l_vec.len() != k_ipa
        || snark.eval_arg.r_vec.len() != k_ipa
        || k_ipa >= 32
    {
        return Err("InvalidPCS: IPA round count mismatch".into());
    }

    transcript.dom_sep(b"IPA");
    let mut u_repr = Vec::with_capacity(65 + 32);
    u_repr.extend_from_slice(&commitment_transcript_bytes(&batched_comm));
    u_repr.extend_from_slice(batched_eval.to_repr().as_ref());
    transcript.absorb_raw(b"U", &u_repr);

    let r_ipa = transcript.squeeze(b"r")?;

    let mut l_near = Vec::with_capacity(k_ipa);
    let mut r_near = Vec::with_capacity(k_ipa);
    let mut ipa_r = Vec::with_capacity(k_ipa);
    for i in 0..k_ipa {
        let ln = bn_point_to_near64(&snark.eval_arg.l_vec[i].comm);
        let rn = bn_point_to_near64(&snark.eval_arg.r_vec[i].comm);
        transcript.absorb_commitment_near64(b"L", &ln);
        transcript.absorb_commitment_near64(b"R", &rn);
        ipa_r.push(transcript.squeeze(b"r")?);
        l_near.push(ln);
        r_near.push(rn);
    }
    let ipa_r_inv = batch_invert_scalars(&ipa_r)?;

    // O(log N) tensor inner-product identity:
    // b_hat = <EqPolynomial(r_batch).evals(), s> = prod_{j=0}^{k-1} ((1 - r_batch[j]) * ipa_r_inv[j] + r_batch[j] * ipa_r[j])
    let b_hat = r_batch
        .iter()
        .zip(ipa_r.iter().zip(ipa_r_inv.iter()))
        .fold(BnScalar::ONE, |acc, (x_j, (rj, rj_inv))| {
            acc * ((BnScalar::ONE - *x_j) * *rj_inv + *x_j * *rj)
        });

    // Single weighted BN254 multiexponentiation for `P_hat`:
    // P_hat = batched_comm + (batched_eval * r_ipa) * ck_s + sum_j (r_j^2 * L_j + r_j^{-2} * R_j)
    let mut p_hat_terms: Vec<([u8; 64], [u8; 32])> = Vec::with_capacity(2 + 2 * k_ipa);
    p_hat_terms.push((batched_comm, one_le));
    p_hat_terms.push((vk.ipa_ck_s_near64, scalar_to_le32(&(batched_eval * r_ipa))));
    for i in 0..k_ipa {
        p_hat_terms.push((l_near[i], scalar_to_le32(&ipa_r[i].square())));
        p_hat_terms.push((r_near[i], scalar_to_le32(&ipa_r_inv[i].square())));
    }
    let p_hat_near64 = multiexp(&p_hat_terms)?;

    if vk.num_msm_chunks as usize != n_ipa.div_ceil(MSM_CHUNK_SIZE) {
        return Err("VK num_msm_chunks does not match n_ipa / MSM_CHUNK_SIZE".into());
    }

    let r1cs_words = (vk.num_r1cs_chunks as usize).div_ceil(64);
    let msm_words = (vk.num_msm_chunks as usize).div_ceil(64);

    Ok(AuthenticatedVerificationSession {
        relation: vk.relation.clone(),
        proof_sha256,
        vk_chunks_merkle_root: vk.vk_chunks_merkle_root,
        z0_le32: expected_z0.iter().map(scalar_to_le32).collect(),
        z8_le32: expected_z8.iter().map(scalar_to_le32).collect(),
        num_cons_padded: vk.num_cons_padded,
        num_vars_padded: vk.num_vars_padded,
        r_x_le32: r_x.iter().map(scalar_to_le32).collect(),
        r_y_le32: r_y.iter().map(scalar_to_le32).collect(),
        r_inner_le32: scalar_to_le32(&r_inner),
        eval_z_le32: scalar_to_le32(&eval_z),
        claim_inner_final_le32: scalar_to_le32(&claim_inner_final),
        acc_eval_a_le32: [0u8; 32],
        acc_eval_b_le32: [0u8; 32],
        acc_eval_c_le32: [0u8; 32],
        ipa_r_le32: ipa_r.iter().map(scalar_to_le32).collect(),
        ipa_r_inv_le32: ipa_r_inv.iter().map(scalar_to_le32).collect(),
        a_hat_le32: scalar_to_le32(&snark.eval_arg.a_hat),
        b_hat_le32: scalar_to_le32(&b_hat),
        r_ipa_le32: scalar_to_le32(&r_ipa),
        p_hat_near64,
        acc_g_hat_near64: [0u8; 64],
        num_r1cs_chunks: vk.num_r1cs_chunks,
        verified_r1cs_chunks: 0,
        r1cs_bitmap: vec![0u64; r1cs_words],
        num_msm_chunks: vk.num_msm_chunks,
        verified_msm_chunks: 0,
        msm_bitmap: vec![0u64; msm_words],
        finalized: false,
    })
}

/// Computes SHA-256 Merkle leaf for a VK chunk `(kind_u8, chunk_idx_u32, payload)`.
pub fn vk_chunk_leaf_hash(kind: u8, chunk_idx: u32, payload: &[u8]) -> [u8; 32] {
    vk_chunk_leaf_hash_with(kind, chunk_idx, payload, &sha256_bytes)
}

pub fn vk_chunk_leaf_hash_with<H: Fn(&[u8]) -> [u8; 32]>(
    kind: u8,
    chunk_idx: u32,
    payload: &[u8],
    sha256_fn: &H,
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(VK_LEAF_DOMAIN.len() + 9 + payload.len());
    pre.extend_from_slice(VK_LEAF_DOMAIN);
    pre.push(kind);
    pre.extend_from_slice(&chunk_idx.to_le_bytes());
    pre.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    pre.extend_from_slice(payload);
    sha256_fn(&pre)
}

pub fn verify_vk_merkle_branch_with<H: Fn(&[u8]) -> [u8; 32]>(
    leaf_hash: [u8; 32],
    merkle_index: u32,
    siblings: &[[u8; 32]],
    expected_root: &[u8; 32],
    sha256_fn: &H,
) -> bool {
    let mut cur = leaf_hash;
    let mut idx = merkle_index;
    let mut buf = Vec::with_capacity(VK_NODE_DOMAIN.len() + 64);
    for sib in siblings {
        buf.clear();
        buf.extend_from_slice(VK_NODE_DOMAIN);
        if (idx & 1) == 0 {
            buf.extend_from_slice(&cur);
            buf.extend_from_slice(sib);
        } else {
            buf.extend_from_slice(sib);
            buf.extend_from_slice(&cur);
        }
        cur = sha256_fn(&buf);
        idx >>= 1;
    }
    idx == 0 && &cur == expected_root
}

/// Compact packed R1CS sparse chunk entry encoding:
/// Each entry starts with `tag_byte`:
/// - `bits 0..2`: `matrix_id` (`0 = A, 1 = B, 2 = C`)
/// - `bits 2..4`: `coeff_kind` (`0 = +1`, `1 = -1`, `2 = small signed i8`, `3 = full 32B Fr`)
/// followed by `row: u32 LE`, `col: u32 LE`, and `0`, `1`, or `32` value bytes!
pub fn evaluate_packed_r1cs_chunk<H: Fn(&[u8]) -> [u8; 32]>(
    session: &mut AuthenticatedVerificationSession,
    chunk_idx: u32,
    merkle_index: u32,
    merkle_siblings: &[[u8; 32]],
    packed_bytes: &[u8],
    sha256_fn: H,
) -> Result<(), String> {
    if session.finalized {
        return Err("verification session already finalized".into());
    }
    if chunk_idx >= session.num_r1cs_chunks || merkle_index != chunk_idx {
        return Err("R1CS chunk_idx out of bounds or merkle_index mismatch".into());
    }
    let word = (chunk_idx as usize) / 64;
    let bit = 1u64 << ((chunk_idx as usize) % 64);
    if (session.r1cs_bitmap[word] & bit) != 0 {
        return Err("duplicate R1CS chunk replay".into());
    }
    let leaf = vk_chunk_leaf_hash_with(CHUNK_KIND_R1CS, chunk_idx, packed_bytes, &sha256_fn);
    if !verify_vk_merkle_branch_with(
        leaf,
        merkle_index,
        merkle_siblings,
        &session.vk_chunks_merkle_root,
        &sha256_fn,
    ) {
        return Err("R1CS chunk failed VK Merkle authentication".into());
    }

    // Build half-bit Kronecker-split EqPolynomial lookup tables (`~3,584` muls / `114 KB` RAM)!
    let r_x: Vec<BnScalar> = session.r_x_le32.iter().map(scalar_from_le32).collect::<Result<_, _>>()?;
    let r_y: Vec<BnScalar> = session.r_y_le32.iter().map(scalar_from_le32).collect::<Result<_, _>>()?;

    let split_x = r_x.len() / 2;
    let tx_hi = eq_evals_from_points(&r_x[..split_x]);
    let tx_lo = eq_evals_from_points(&r_x[split_x..]);
    let shift_x = r_x.len() - split_x;
    let mask_x = (1usize << shift_x) - 1;

    let split_y = r_y.len() / 2;
    let ty_hi = eq_evals_from_points(&r_y[..split_y]);
    let ty_lo = eq_evals_from_points(&r_y[split_y..]);
    let shift_y = r_y.len() - split_y;
    let mask_y = (1usize << shift_y) - 1;

    if packed_bytes.len() < 4 {
        return Err("truncated packed R1CS chunk header".into());
    }
    let count = u32::from_le_bytes(packed_bytes[0..4].try_into().unwrap()) as usize;
    if count > R1CS_CHUNK_ENTRIES {
        return Err("packed R1CS chunk exceeds entry cap".into());
    }
    let mut off = 4usize;
    let mut sum_a = BnScalar::ZERO;
    let mut sum_b = BnScalar::ZERO;
    let mut sum_c = BnScalar::ZERO;

    let mut cur_key: Option<(u8, usize)> = None;
    let mut row_acc = BnScalar::ZERO;
    let flush_row = |key: Option<(u8, usize)>,
                     acc: BnScalar,
                     sa: &mut BnScalar,
                     sb: &mut BnScalar,
                     sc: &mut BnScalar|
     -> Result<(), String> {
        if let Some((mat_id, r)) = key {
            let tx = tx_hi[r >> shift_x] * tx_lo[r & mask_x];
            let weighted = acc * tx;
            match mat_id {
                0 => *sa += weighted,
                1 => *sb += weighted,
                2 => *sc += weighted,
                _ => return Err("invalid matrix_id in R1CS chunk".into()),
            }
        }
        Ok(())
    };

    for _ in 0..count {
        if off + 9 > packed_bytes.len() {
            return Err("truncated packed R1CS entry".into());
        }
        let tag = packed_bytes[off];
        let mat_id = tag & 0x03;
        if mat_id > 2 {
            return Err("invalid matrix_id in R1CS chunk".into());
        }
        let row = u32::from_le_bytes(packed_bytes[off + 1..off + 5].try_into().unwrap()) as usize;
        let col = u32::from_le_bytes(packed_bytes[off + 5..off + 9].try_into().unwrap()) as usize;
        off += 9;
        if row >= session.num_cons_padded || col >= 2 * session.num_vars_padded {
            return Err("R1CS row/col out of padded bounds".into());
        }
        if cur_key != Some((mat_id, row)) {
            flush_row(cur_key, row_acc, &mut sum_a, &mut sum_b, &mut sum_c)?;
            cur_key = Some((mat_id, row));
            row_acc = BnScalar::ZERO;
        }
        let ty = ty_hi[col >> shift_y] * ty_lo[col & mask_y];

        let col_term = match (tag >> 2) & 0x03 {
            0 => ty,
            1 => -ty,
            2 => {
                if off >= packed_bytes.len() {
                    return Err("truncated small coeff".into());
                }
                let sv = packed_bytes[off] as i8;
                off += 1;
                let mag = BnScalar::from(u64::from(sv.unsigned_abs()));
                if sv < 0 { -(ty * mag) } else { ty * mag }
            }
            3 => {
                if off + 32 > packed_bytes.len() {
                    return Err("truncated scalar coeff".into());
                }
                let mut sb = [0u8; 32];
                sb.copy_from_slice(&packed_bytes[off..off + 32]);
                off += 32;
                let s = scalar_from_le32(&sb)?;
                ty * s
            }
            _ => unreachable!(),
        };
        row_acc += col_term;
    }
    flush_row(cur_key, row_acc, &mut sum_a, &mut sum_b, &mut sum_c)?;
    if off != packed_bytes.len() {
        return Err("trailing bytes in packed R1CS chunk".into());
    }

    session.acc_eval_a_le32 = scalar_to_le32(&(scalar_from_le32(&session.acc_eval_a_le32)? + sum_a));
    session.acc_eval_b_le32 = scalar_to_le32(&(scalar_from_le32(&session.acc_eval_b_le32)? + sum_b));
    session.acc_eval_c_le32 = scalar_to_le32(&(scalar_from_le32(&session.acc_eval_c_le32)? + sum_c));
    session.r1cs_bitmap[word] |= bit;
    session.verified_r1cs_chunks += 1;
    Ok(())
}

/// Evaluates a Merkle-authenticated chunk of `MSM_CHUNK_SIZE = 512` BN254 generators using
/// Kronecker prefix-split tensor scalars ($O(B)$ field muls!) + 1 `alt_bn128_g1_multiexp` host call!
pub fn evaluate_msm_chunk<H, M>(
    session: &mut AuthenticatedVerificationSession,
    chunk_idx: u32,
    merkle_index: u32,
    merkle_siblings: &[[u8; 32]],
    generators_bytes: &[u8],
    sha256_fn: H,
    multiexp: M,
) -> Result<(), String>
where
    H: Fn(&[u8]) -> [u8; 32],
    M: Fn(&[([u8; 64], [u8; 32])]) -> Result<[u8; 64], String>,
{
    if session.finalized {
        return Err("verification session already finalized".into());
    }
    if chunk_idx >= session.num_msm_chunks
        || merkle_index != session.num_r1cs_chunks + chunk_idx
    {
        return Err("MSM chunk_idx out of bounds or merkle_index mismatch".into());
    }
    let word = (chunk_idx as usize) / 64;
    let bit = 1u64 << ((chunk_idx as usize) % 64);
    if (session.msm_bitmap[word] & bit) != 0 {
        return Err("duplicate MSM chunk replay".into());
    }
    if generators_bytes.is_empty()
        || generators_bytes.len() % 64 != 0
        || generators_bytes.len() / 64 > MSM_CHUNK_SIZE
    {
        return Err("invalid MSM generator chunk byte length".into());
    }
    let leaf = vk_chunk_leaf_hash_with(CHUNK_KIND_MSM, chunk_idx, generators_bytes, &sha256_fn);
    if !verify_vk_merkle_branch_with(
        leaf,
        merkle_index,
        merkle_siblings,
        &session.vk_chunks_merkle_root,
        &sha256_fn,
    ) {
        return Err("MSM generator chunk failed VK Merkle authentication".into());
    }

    let ipa_r: Vec<BnScalar> = session.ipa_r_le32.iter().map(scalar_from_le32).collect::<Result<_, _>>()?;
    let ipa_r_inv: Vec<BnScalar> = session
        .ipa_r_inv_le32
        .iter()
        .map(scalar_from_le32)
        .collect::<Result<_, _>>()?;
    let k = ipa_r.len();
    let count = generators_bytes.len() / 64;
    let start_idx = (chunk_idx as usize) * MSM_CHUNK_SIZE;

    // Exact Kronecker tensor expansion for `[start_idx .. start_idx + count)`:
    // Note in `ipa_pc.rs` lines 335–349:
    // For index `idx`, bit `b` (`0..k` from LSB `b=0` to MSB `b=k-1`) multiplies `r[(k - 1) - b]`
    // if `(idx >> b) & 1 == 1` else `r_inv[(k - 1) - b]`!
    let low_bits = MSM_CHUNK_SIZE.ilog2() as usize; // 9
    let mut prefix_scalar = BnScalar::ONE;
    for b in low_bits..k {
        let r_pos = (k - 1) - b;
        if ((start_idx >> b) & 1) == 1 {
            prefix_scalar *= ipa_r[r_pos];
        } else {
            prefix_scalar *= ipa_r_inv[r_pos];
        }
    }

    let r_sq: Vec<BnScalar> = ipa_r.iter().map(|x| x.square()).collect();
    let mut local_s = vec![BnScalar::ZERO; count];
    local_s[0] = {
        let mut v = prefix_scalar;
        for b in 0..low_bits.min(k) {
            v *= ipa_r_inv[(k - 1) - b];
        }
        v
    };
    for u in 1..count {
        let pos_in_r = (31 - (u as u32).leading_zeros()) as usize;
        local_s[u] = local_s[u - (1 << pos_in_r)] * r_sq[(k - 1) - pos_in_r];
    }

    // Batch chunk MSM + running accumulator `acc_g_hat` into ONE single `multiexp` call!
    let has_prev = session.acc_g_hat_near64.iter().any(|&b| b != 0);
    let mut terms: Vec<([u8; 64], [u8; 32])> = Vec::with_capacity(count + usize::from(has_prev));
    if has_prev {
        terms.push((session.acc_g_hat_near64, scalar_to_le32(&BnScalar::ONE)));
    }
    for u in 0..count {
        let mut pt = [0u8; 64];
        pt.copy_from_slice(&generators_bytes[u * 64..(u + 1) * 64]);
        terms.push((pt, scalar_to_le32(&local_s[u])));
    }
    session.acc_g_hat_near64 = multiexp(&terms)?;
    session.msm_bitmap[word] |= bit;
    session.verified_msm_chunks += 1;
    Ok(())
}

/// Finalizes the `AuthenticatedVerificationSession` once ALL R1CS and MSM chunks are verified.
pub fn finalize_decider_session<M>(
    session: &mut AuthenticatedVerificationSession,
    ipa_ck_s_near64: &[u8; 64],
    multiexp: M,
) -> Result<(), String>
where
    M: Fn(&[([u8; 64], [u8; 32])]) -> Result<[u8; 64], String>,
{
    if session.finalized {
        return Err("session already finalized".into());
    }
    if session.verified_r1cs_chunks != session.num_r1cs_chunks {
        return Err(format!(
            "incomplete R1CS matrix verification: {}/{}",
            session.verified_r1cs_chunks, session.num_r1cs_chunks
        ));
    }
    if session.verified_msm_chunks != session.num_msm_chunks {
        return Err(format!(
            "incomplete BN254 generator MSM verification: {}/{}",
            session.verified_msm_chunks, session.num_msm_chunks
        ));
    }

    // 1. Check Spartan inner R1CS identity: `(eval_A + r * eval_B + r^2 * eval_C) * eval_Z == claim_inner_final`
    let eval_a = scalar_from_le32(&session.acc_eval_a_le32)?;
    let eval_b = scalar_from_le32(&session.acc_eval_b_le32)?;
    let eval_c = scalar_from_le32(&session.acc_eval_c_le32)?;
    let r_inner = scalar_from_le32(&session.r_inner_le32)?;
    let eval_z = scalar_from_le32(&session.eval_z_le32)?;
    let claim_inner_final = scalar_from_le32(&session.claim_inner_final_le32)?;

    let expected_inner = (eval_a + r_inner * eval_b + r_inner.square() * eval_c) * eval_z;
    if expected_inner != claim_inner_final {
        return Err("InvalidSumcheckProof: accumulated R1CS matrix evaluation mismatch".into());
    }

    // 2. Check IPA polynomial commitment identity: `a_hat * G_hat + (a_hat * b_hat * r_ipa) * ck_s == P_hat`
    let a_hat = scalar_from_le32(&session.a_hat_le32)?;
    let b_hat = scalar_from_le32(&session.b_hat_le32)?;
    let r_ipa = scalar_from_le32(&session.r_ipa_le32)?;
    let rhs = multiexp(&[
        (session.acc_g_hat_near64, scalar_to_le32(&a_hat)),
        (*ipa_ck_s_near64, scalar_to_le32(&(a_hat * b_hat * r_ipa))),
    ])?;
    if rhs != session.p_hat_near64 {
        return Err("InvalidPCS: accumulated BN254 IPA commitment check failed".into());
    }

    session.finalized = true;
    Ok(())
}
