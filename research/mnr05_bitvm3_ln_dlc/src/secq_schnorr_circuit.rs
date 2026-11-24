//! `Gate 2a`: Constrained In-Circuit BIP-340 Schnorr Batch Authorization over
//! `Secq256k1Engine` / `Secp256k1Engine` (`shz/mnr05-secq256k1-bip340-batch-auth/v1`).
//!
//! Because `<Secq256k1Engine as Engine>::Scalar` is `halo2curves::secq256k1::Fq` — whose modulus
//! `0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f` IS the exact 256-bit base
//! field `Fp` of Bitcoin's `secp256k1` curve — this step circuit verifies full BIP-340 Schnorr
//! signatures (`s * G - e * P == R`, `lift_x` even-Y `P`, even-Y `R`, `s < n`, and in-circuit
//! `SHA256("BIP0340/challenge", R_x || P_x || sighash32)`) directly in native R1CS field arithmetic
//! with ZERO foreign-field limb emulation and ZERO trusted setup!
//!
//! Across 8 folds, it authenticates all 8 Taproot signatures authorizing the 3-input, 5-output
//! multilateral LN-DLC clearing transaction (`U_AB`: Bob `0x83` + Guard `0x01` + Alice `0x01`;
//! `U_BC`: Bob `0x83` + Guard `0x01` + Carol `0x01`; `U_CA`: Carol `0x00` + Alice `0x00`) and
//! outputs a binding SHA-256 `auth_accumulator_root32` consumed by [`crate::unified_batch_circuit`].
#![forbid(unsafe_code)]

use bincode::Options;
use ff::{Field, PrimeField};
use halo2curves::{
    group::{prime::PrimeCurveAffine, Curve, Group},
    secp256k1::{Fp as SecpBase, Secp256k1, Secp256k1Affine},
    secq256k1::Fq as SecqScalar,
    CurveAffine,
};
use nova_snark::{
    frontend::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            num::AllocatedNum,
            sha256::sha256,
        },
        ConstraintSystem, LinearCombination, SynthesisError,
    },
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc::EvaluationEngine, Secp256k1Engine, Secq256k1Engine},
    spartan::snark::RelaxedR1CSSNARK as BatchedRelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RELATION_SECQ_BIP340_V1: &str = "shz/mnr05-secq256k1-bip340-batch-auth/v1";
pub const AUTH_ACC_DOMAIN: &[u8] = b"SHZ/MNR05/AUTH_ACC/V1";
pub const BIP340_CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";
pub const AUTH_STEP_COUNT: usize = 8;

/// `secp256k1` base field modulus `p = 2^256 - 2^32 - 977` split into big-endian 128-bit halves:
/// `P_HI = 0xffffffffffffffffffffffffffffffff`, `P_LO = 0xfffffffffffffffffffffffefffffc2f`.
const P_HI: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
const P_LO: u128 = 0xffff_ffff_ffff_ffff_ffff_fffe_ffff_fc2f;

/// `secp256k1` scalar group order `n` split into big-endian 128-bit halves:
/// `N_HI = 0xfffffffffffffffffffffffffffffffe`, `N_LO = 0xbaaedce6af48a03bbfd25e8cd0364141`.
const N_HI: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe;
const N_LO: u128 = 0xbaae_dce6_af48_a03b_bfd2_5e8c_d036_4141;

pub type E1 = Secq256k1Engine;
pub type E2 = Secp256k1Engine;
type EE1 = EvaluationEngine<E1>;
type EE2 = EvaluationEngine<E2>;
type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Converts a 32-byte big-endian `secp256k1` base-field element into `SecqScalar` (`Fp`).
pub fn secq_from_be32(be: &[u8; 32]) -> Result<SecqScalar, String> {
    let mut le = *be;
    le.reverse();
    Option::<SecqScalar>::from(SecqScalar::from_repr(le.into()))
        .ok_or_else(|| "bytes >= secp256k1 base modulus p".to_owned())
}

pub fn secq_to_be32(s: &SecqScalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(s.to_repr().as_ref());
    out.reverse();
    out
}

pub fn secq_from_u128(v: u128) -> SecqScalar {
    let mut le = [0u8; 32];
    le[0..16].copy_from_slice(&v.to_le_bytes());
    SecqScalar::from_repr(le.into()).unwrap()
}

pub fn u128_halves_le_from_digest(d: &[u8; 32]) -> (u128, u128) {
    let lo = u128::from_le_bytes(d[0..16].try_into().unwrap());
    let hi = u128::from_le_bytes(d[16..32].try_into().unwrap());
    (lo, hi)
}

/// Deterministically derives NUMS offset point `Q_0` on `secp256k1` and `-2^256 * Q_0`!
pub fn nums_offset_points() -> ((SecqScalar, SecqScalar), (SecqScalar, SecqScalar)) {
    let mut q0_opt: Option<Secp256k1Affine> = None;
    for ctr in 0u32..1024 {
        let mut msg = b"SHZ/MNR05/SECQ_EC_OFFSET/V1:".to_vec();
        msg.extend_from_slice(&ctr.to_le_bytes());
        let x_be = sha256_bytes(&msg);
        let mut x_le = x_be;
        x_le.reverse();
        if let Some(x_fp) = Option::<SecpBase>::from(SecpBase::from_repr(x_le.into())) {
            // Try SEC1 compressed even-Y `0x02 || x_le`? Note halo2curves Secp256k1Affine::from_xy:
            let rhs = x_fp.square() * x_fp + SecpBase::from(7u64);
            if let Some(y_raw) = Option::<SecpBase>::from(rhs.sqrt()) {
                let y_even = if (y_raw.to_repr().as_ref()[0] & 1) == 1 {
                    -y_raw
                } else {
                    y_raw
                };
                if let Some(aff) = Option::<Secp256k1Affine>::from(Secp256k1Affine::from_xy(x_fp, y_even)) {
                    q0_opt = Some(aff);
                    break;
                }
            }
        }
    }
    let q0 = q0_opt.expect("NUMS Q0 on secp256k1");
    let mut cur: Secp256k1 = q0.to_curve();
    for _ in 0..256 {
        cur = cur.double();
    }
    let neg_shifted = (-cur).to_affine();

    let to_secq_pair = |aff: &Secp256k1Affine| -> (SecqScalar, SecqScalar) {
        let coords = aff.coordinates().unwrap();
        let x_le: [u8; 32] = coords.x().to_repr().as_ref().try_into().unwrap();
        let y_le: [u8; 32] = coords.y().to_repr().as_ref().try_into().unwrap();
        (
            SecqScalar::from_repr(x_le.into()).unwrap(),
            SecqScalar::from_repr(y_le.into()).unwrap(),
        )
    };
    (to_secq_pair(&q0), to_secq_pair(&neg_shifted))
}

pub fn secp_generator_coords() -> (SecqScalar, SecqScalar) {
    let g = Secp256k1Affine::generator();
    let coords = g.coordinates().unwrap();
    let x_le: [u8; 32] = coords.x().to_repr().as_ref().try_into().unwrap();
    let y_le: [u8; 32] = coords.y().to_repr().as_ref().try_into().unwrap();
    (
        SecqScalar::from_repr(x_le.into()).unwrap(),
        SecqScalar::from_repr(y_le.into()).unwrap(),
    )
}

/// Lifts a big-endian 32-byte BIP-340 x-coordinate to its unique even-Y `y` big-endian bytes on `secp256k1`.
pub fn lift_x_even_be32(x_be: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut x_le = *x_be;
    x_le.reverse();
    let x = Option::<SecpBase>::from(SecpBase::from_repr(x_le.into()))
        .ok_or_else(|| "x >= p".to_owned())?;
    let rhs = x.square() * x + SecpBase::from(7u64);
    let y_raw = Option::<SecpBase>::from(rhs.sqrt()).ok_or_else(|| "x^3 + 7 not a square".to_owned())?;
    let y_even = if (y_raw.to_repr().as_ref()[0] & 1) == 1 {
        -y_raw
    } else {
        y_raw
    };
    let mut y_be: [u8; 32] = y_even.to_repr().as_ref().try_into().unwrap();
    y_be.reverse();
    Ok(y_be)
}

/// Single BIP-340 signature slot authenticated in step `step_idx` (`0..8`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip340StepSlot {
    pub step_idx: u8,
    /// `0x83` (Bob offline `SIGHASH_SINGLE|ANYONECANPAY`), `0x01` (`SIGHASH_ALL`), or `0x00` (`SIGHASH_DEFAULT`).
    pub sighash_flag: u8,
    pub pubkey_x: [u8; 32],
    pub sighash32: [u8; 32],
    pub sig_rx: [u8; 32],
    pub sig_s: [u8; 32],
}

impl Bip340StepSlot {
    pub fn next_accumulator(&self, prev_acc: &[u8; 32]) -> [u8; 32] {
        let mut pre = Vec::with_capacity(AUTH_ACC_DOMAIN.len() + 32 + 2 + 128);
        pre.extend_from_slice(AUTH_ACC_DOMAIN);
        pre.extend_from_slice(prev_acc);
        pre.push(self.step_idx);
        pre.push(self.sighash_flag);
        pre.extend_from_slice(&self.pubkey_x);
        pre.extend_from_slice(&self.sighash32);
        pre.extend_from_slice(&self.sig_rx);
        pre.extend_from_slice(&self.sig_s);
        sha256_bytes(&pre)
    }
}

pub fn compute_auth_accumulator_chain(slots: &[Bip340StepSlot]) -> ([u8; 32], Vec<[u8; 32]>) {
    assert_eq!(slots.len(), AUTH_STEP_COUNT);
    let mut acc = [0u8; 32];
    let mut prevs = Vec::with_capacity(AUTH_STEP_COUNT);
    for (i, s) in slots.iter().enumerate() {
        assert_eq!(s.step_idx as usize, i);
        prevs.push(acc);
        acc = s.next_accumulator(&acc);
    }
    (acc, prevs)
}

#[derive(Clone, Debug)]
pub struct Mnr05SecqBip340Step {
    pub prev_acc: [u8; 32],
    pub slot: Bip340StepSlot,
    pub py_be: [u8; 32],
    pub ry_be: [u8; 32],
}

impl Mnr05SecqBip340Step {
    pub fn from_valid_slot(prev_acc: [u8; 32], slot: Bip340StepSlot) -> Result<Self, String> {
        let py_be = lift_x_even_be32(&slot.pubkey_x)?;
        let ry_be = lift_x_even_be32(&slot.sig_rx)?;
        Ok(Self {
            prev_acc,
            slot,
            py_be,
            ry_be,
        })
    }

    /// Blank shape-synthesis witness (uses generator `G` signed dummy values; circuit shape is 100% witness-independent!).
    pub fn blank() -> Self {
        let sk = [0x11u8; 32];
        let pk_x = shz_dlc::pubkey_x_from_secret(&sk).unwrap();
        let msg = [0x22u8; 32];
        let sig = shz_dlc::bip340_sign(&sk, &msg).unwrap();
        Self::from_valid_slot(
            [0u8; 32],
            Bip340StepSlot {
                step_idx: 0,
                sighash_flag: 0x00,
                pubkey_x: pk_x,
                sighash32: msg,
                sig_rx: sig.r_x,
                sig_s: sig.s,
            },
        )
        .unwrap()
    }
}

fn constant_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|v| (0..8).rev().map(move |j| Boolean::constant((v >> j) & 1 != 0)))
        .collect()
}

fn alloc_bytes_bits<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    bytes: &[u8],
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for (i, b) in bytes.iter().enumerate() {
        for j in (0..8).rev() {
            out.push(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("b{i}_{j}")),
                Some((b >> j) & 1 != 0),
            )?));
        }
    }
    Ok(out)
}

/// Big-endian linear combination over `bits` (`bits[0]` = MSB, `bits[len-1]` = LSB).
fn be_lc<CS: ConstraintSystem<SecqScalar>>(bits: &[Boolean]) -> LinearCombination<SecqScalar> {
    let mut lc = LinearCombination::zero();
    let mut w = SecqScalar::ONE;
    for b in bits.iter().rev() {
        lc = lc + &b.lc(CS::one(), w);
        w = w.double();
    }
    lc
}

/// Little-endian byte linear combination (`8`-bit MSB-first bytes, byte `0` = least-significant byte).
fn le_bytes_lc<CS: ConstraintSystem<SecqScalar>>(bits: &[Boolean]) -> LinearCombination<SecqScalar> {
    assert_eq!(bits.len() % 8, 0);
    let mut lc = LinearCombination::zero();
    let mut w = SecqScalar::ONE;
    for byte in bits.as_chunks::<8>().0 {
        for b in byte.iter().rev() {
            lc = lc + &b.lc(CS::one(), w);
            w = w.double();
        }
    }
    lc
}

fn alloc_nonneg_u128<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    gate: &Boolean,
    expr: LinearCombination<SecqScalar>,
    witness_val: u128,
) -> Result<(), SynthesisError> {
    let v = if gate.get_value() == Some(true) {
        witness_val
    } else {
        0
    };
    let mut rhs = LinearCombination::zero();
    let mut w = SecqScalar::ONE;
    for i in 0..128 {
        let bit = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("u128_{i}")),
            Some((v >> i) & 1 != 0),
        )?);
        rhs = rhs + &bit.lc(CS::one(), w);
        w = w.double();
    }
    cs.enforce(
        || "gated u128 range",
        |_| gate.lc(CS::one(), SecqScalar::ONE),
        |_| expr,
        |_| rhs,
    );
    Ok(())
}

/// Enforces `0 <= BE_256(bits) < (bound_hi << 128) | bound_lo` with zero field wraparound!
fn enforce_be256_lt_u256<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    bits256: &[Boolean],
    raw_bytes: &[u8; 32],
    bound_hi: u128,
    bound_lo: u128,
) -> Result<(), SynthesisError> {
    assert_eq!(bits256.len(), 256);
    let x_hi = u128::from_be_bytes(raw_bytes[0..16].try_into().unwrap());
    let x_lo = u128::from_be_bytes(raw_bytes[16..32].try_into().unwrap());
    let hi_is_lt = x_hi < bound_hi;

    let flag_hi_lt = Boolean::from(AllocatedBit::alloc(
        cs.namespace(|| "hi_lt"),
        Some(hi_is_lt),
    )?);
    let flag_hi_eq = flag_hi_lt.not();

    let lc_hi = be_lc::<CS>(&bits256[0..128]);
    let lc_lo = be_lc::<CS>(&bits256[128..256]);
    let c_bhi = secq_from_u128(bound_hi);
    let c_blo = secq_from_u128(bound_lo);

    // Case 1 (`flag_hi_lt == 1`): `bound_hi - x_hi - 1 >= 0` in 128 bits
    alloc_nonneg_u128(
        cs.namespace(|| "hi_lt_slack"),
        &flag_hi_lt,
        LinearCombination::zero() + (c_bhi, CS::one()) - &lc_hi - &(LinearCombination::zero() + CS::one()),
        bound_hi.wrapping_sub(x_hi).wrapping_sub(1),
    )?;

    // Case 2 (`flag_hi_eq == 1`): `x_hi == bound_hi` AND `bound_lo - x_lo - 1 >= 0` in 128 bits
    cs.enforce(
        || "hi_eq check",
        |_| flag_hi_eq.lc(CS::one(), SecqScalar::ONE),
        |_| LinearCombination::zero() + (c_bhi, CS::one()) - &lc_hi,
        |lc| lc,
    );
    alloc_nonneg_u128(
        cs.namespace(|| "lo_lt_slack"),
        &flag_hi_eq,
        LinearCombination::zero() + (c_blo, CS::one()) - &lc_lo - &(LinearCombination::zero() + CS::one()),
        bound_lo.wrapping_sub(x_lo).wrapping_sub(1),
    )?;
    Ok(())
}

/// Allocates an exact `AllocatedNum` bound to `be_lc(bits256)` in `Fp` (safe because `bits256 < p` is enforced!).
fn alloc_fp_from_be_bits<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    bits256: &[Boolean],
    raw_be: &[u8; 32],
) -> Result<AllocatedNum<SecqScalar>, SynthesisError> {
    let val = secq_from_be32(raw_be).unwrap_or(SecqScalar::ZERO);
    let n = AllocatedNum::alloc_infallible(cs.namespace(|| "fp"), || val);
    cs.enforce(
        || "bind be256 == fp",
        |_| be_lc::<CS>(bits256),
        |lc| lc + CS::one(),
        |lc| lc + n.get_variable(),
    );
    Ok(n)
}

/// Enforces `y^2 == x^3 + 7 (mod p)`.
fn enforce_on_secp256k1<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    x: &AllocatedNum<SecqScalar>,
    y: &AllocatedNum<SecqScalar>,
) -> Result<(), SynthesisError> {
    let x2 = x.square(cs.namespace(|| "x2"))?;
    let x3 = x2.mul(cs.namespace(|| "x3"), x)?;
    let y2 = y.square(cs.namespace(|| "y2"))?;
    cs.enforce(
        || "y^2 == x^3 + 7",
        |lc| lc + x3.get_variable() + (SecqScalar::from(7u64), CS::one()),
        |lc| lc + CS::one(),
        |lc| lc + y2.get_variable(),
    );
    Ok(())
}

/// Point doubling `(x_d, y_d) = 2 * (x_a, y_a)` on `y^2 = x^3 + 7` (`3` R1CS constraints!).
fn ec_double<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    xa: &AllocatedNum<SecqScalar>,
    ya: &AllocatedNum<SecqScalar>,
) -> Result<(AllocatedNum<SecqScalar>, AllocatedNum<SecqScalar>), SynthesisError> {
    let (lam_v, xd_v, yd_v) = match (xa.get_value(), ya.get_value()) {
        (Some(x), Some(y)) => {
            let num = SecqScalar::from(3u64) * x.square();
            let den_inv = (y.double()).invert().unwrap_or(SecqScalar::ZERO);
            let lam = num * den_inv;
            let xd = lam.square() - x.double();
            let yd = lam * (x - xd) - y;
            (lam, xd, yd)
        }
        _ => (SecqScalar::ZERO, SecqScalar::ZERO, SecqScalar::ZERO),
    };
    let xa2 = xa.square(cs.namespace(|| "xa2"))?;
    let lam = AllocatedNum::alloc_infallible(cs.namespace(|| "lam"), || lam_v);
    let xd = AllocatedNum::alloc_infallible(cs.namespace(|| "xd"), || xd_v);
    let yd = AllocatedNum::alloc_infallible(cs.namespace(|| "yd"), || yd_v);

    cs.enforce(
        || "(2*ya)*lam == 3*xa^2",
        |lc| lc + (SecqScalar::from(2u64), ya.get_variable()),
        |lc| lc + lam.get_variable(),
        |lc| lc + (SecqScalar::from(3u64), xa2.get_variable()),
    );
    cs.enforce(
        || "lam^2 == xd + 2*xa",
        |lc| lc + lam.get_variable(),
        |lc| lc + lam.get_variable(),
        |lc| lc + xd.get_variable() + (SecqScalar::from(2u64), xa.get_variable()),
    );
    cs.enforce(
        || "lam*(xa - xd) == yd + ya",
        |lc| lc + lam.get_variable(),
        |lc| lc + xa.get_variable() - xd.get_variable(),
        |lc| lc + yd.get_variable() + ya.get_variable(),
    );
    Ok((xd, yd))
}

/// Complete chord addition `(xs, ys) = (x1, y1) + (x2, y2)` with `x1 != x2` (`3` R1CS constraints!).
fn ec_chord_add<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    x1: &AllocatedNum<SecqScalar>,
    y1: &AllocatedNum<SecqScalar>,
    x2_lc: LinearCombination<SecqScalar>,
    x2_val: Option<SecqScalar>,
    y2_lc: LinearCombination<SecqScalar>,
    y2_val: Option<SecqScalar>,
) -> Result<(AllocatedNum<SecqScalar>, AllocatedNum<SecqScalar>), SynthesisError> {
    let (lam_v, xs_v, ys_v) = match (x1.get_value(), y1.get_value(), x2_val, y2_val) {
        (Some(ax), Some(ay), Some(bx), Some(by)) => {
            let dx_inv = (bx - ax).invert().unwrap_or(SecqScalar::ZERO);
            let lam = (by - ay) * dx_inv;
            let xs = lam.square() - ax - bx;
            let ys = lam * (ax - xs) - ay;
            (lam, xs, ys)
        }
        _ => (SecqScalar::ZERO, SecqScalar::ZERO, SecqScalar::ZERO),
    };
    let lam = AllocatedNum::alloc_infallible(cs.namespace(|| "lam"), || lam_v);
    let xs = AllocatedNum::alloc_infallible(cs.namespace(|| "xs"), || xs_v);
    let ys = AllocatedNum::alloc_infallible(cs.namespace(|| "ys"), || ys_v);

    cs.enforce(
        || "(x2 - x1)*lam == y2 - y1",
        |_| x2_lc.clone() - x1.get_variable(),
        |lc| lc + lam.get_variable(),
        |_| y2_lc - y1.get_variable(),
    );
    cs.enforce(
        || "lam^2 == xs + x1 + x2",
        |lc| lc + lam.get_variable(),
        |lc| lc + lam.get_variable(),
        |_| LinearCombination::zero() + xs.get_variable() + x1.get_variable() + &x2_lc,
    );
    cs.enforce(
        || "lam*(x1 - xs) == ys + y1",
        |lc| lc + lam.get_variable(),
        |lc| lc + x1.get_variable() - xs.get_variable(),
        |lc| lc + ys.get_variable() + y1.get_variable(),
    );
    Ok((xs, ys))
}

fn ec_select<CS: ConstraintSystem<SecqScalar>>(
    mut cs: CS,
    cond: &Boolean,
    x_false: &AllocatedNum<SecqScalar>,
    y_false: &AllocatedNum<SecqScalar>,
    x_true: &AllocatedNum<SecqScalar>,
    y_true: &AllocatedNum<SecqScalar>,
) -> Result<(AllocatedNum<SecqScalar>, AllocatedNum<SecqScalar>), SynthesisError> {
    let (xo_v, yo_v) = if cond.get_value() == Some(true) {
        (
            x_true.get_value().unwrap_or(SecqScalar::ZERO),
            y_true.get_value().unwrap_or(SecqScalar::ZERO),
        )
    } else {
        (
            x_false.get_value().unwrap_or(SecqScalar::ZERO),
            y_false.get_value().unwrap_or(SecqScalar::ZERO),
        )
    };
    let xo = AllocatedNum::alloc_infallible(cs.namespace(|| "xo"), || xo_v);
    let yo = AllocatedNum::alloc_infallible(cs.namespace(|| "yo"), || yo_v);

    cs.enforce(
        || "sel_x",
        |_| cond.lc(CS::one(), SecqScalar::ONE),
        |lc| lc + x_true.get_variable() - x_false.get_variable(),
        |lc| lc + xo.get_variable() - x_false.get_variable(),
    );
    cs.enforce(
        || "sel_y",
        |_| cond.lc(CS::one(), SecqScalar::ONE),
        |lc| lc + y_true.get_variable() - y_false.get_variable(),
        |lc| lc + yo.get_variable() - y_false.get_variable(),
    );
    Ok((xo, yo))
}

impl StepCircuit<SecqScalar> for Mnr05SecqBip340Step {
    fn arity(&self) -> usize {
        3 // z = [step_count, auth_acc_lo128_le, auth_acc_hi128_le]
    }

    fn synthesize<CS: ConstraintSystem<SecqScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<SecqScalar>],
    ) -> Result<Vec<AllocatedNum<SecqScalar>>, SynthesisError> {
        assert_eq!(z.len(), 3);
        // 1. Bind `prev_acc` and `step_idx`
        let prev_acc_bits = alloc_bytes_bits(cs.namespace(|| "prev_acc"), &self.prev_acc)?;
        cs.enforce(
            || "prev_acc_lo",
            |_| le_bytes_lc::<CS>(&prev_acc_bits[0..128]),
            |lc| lc + CS::one(),
            |lc| lc + z[1].get_variable(),
        );
        cs.enforce(
            || "prev_acc_hi",
            |_| le_bytes_lc::<CS>(&prev_acc_bits[128..256]),
            |lc| lc + CS::one(),
            |lc| lc + z[2].get_variable(),
        );

        let step_idx_bits = alloc_bytes_bits(cs.namespace(|| "step_idx"), &[self.slot.step_idx])?;
        cs.enforce(
            || "step_idx == z[0]",
            |_| le_bytes_lc::<CS>(&step_idx_bits),
            |lc| lc + CS::one(),
            |lc| lc + z[0].get_variable(),
        );
        let flag_bits = alloc_bytes_bits(cs.namespace(|| "sighash_flag"), &[self.slot.sighash_flag])?;

        // 2. Allocate `pubkey_x`, `sighash32`, `sig_rx`, `sig_s`, `py`, `ry`
        let px_bits = alloc_bytes_bits(cs.namespace(|| "px"), &self.slot.pubkey_x)?;
        let msg_bits = alloc_bytes_bits(cs.namespace(|| "msg"), &self.slot.sighash32)?;
        let rx_bits = alloc_bytes_bits(cs.namespace(|| "rx"), &self.slot.sig_rx)?;
        let s_bits = alloc_bytes_bits(cs.namespace(|| "s"), &self.slot.sig_s)?;
        let py_bits = alloc_bytes_bits(cs.namespace(|| "py"), &self.py_be)?;
        let ry_bits = alloc_bytes_bits(cs.namespace(|| "ry"), &self.ry_be)?;

        // 3. Canonical bounds `< p` on `px, py, rx, ry` and `< n` + non-zero on `s`!
        enforce_be256_lt_u256(cs.namespace(|| "px_lt_p"), &px_bits, &self.slot.pubkey_x, P_HI, P_LO)?;
        enforce_be256_lt_u256(cs.namespace(|| "py_lt_p"), &py_bits, &self.py_be, P_HI, P_LO)?;
        enforce_be256_lt_u256(cs.namespace(|| "rx_lt_p"), &rx_bits, &self.slot.sig_rx, P_HI, P_LO)?;
        enforce_be256_lt_u256(cs.namespace(|| "ry_lt_p"), &ry_bits, &self.ry_be, P_HI, P_LO)?;
        enforce_be256_lt_u256(cs.namespace(|| "s_lt_n"), &s_bits, &self.slot.sig_s, N_HI, N_LO)?;

        // Enforce even-Y (`LSB == 0`) on BOTH `P` (`lift_x`) and `R` (`BIP-340`)!
        cs.enforce(
            || "py_even",
            |_| py_bits[255].lc(CS::one(), SecqScalar::ONE),
            |lc| lc + CS::one(),
            |lc| lc,
        );
        cs.enforce(
            || "ry_even",
            |_| ry_bits[255].lc(CS::one(), SecqScalar::ONE),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // Enforce `s != 0` via bit-sum `>= 1` (8-bit slack over `[0..255]`)
        let s_ones = self.slot.sig_s.iter().map(|b| b.count_ones()).sum::<u32>();
        let mut s_sum_lc = LinearCombination::zero();
        for b in &s_bits {
            s_sum_lc = s_sum_lc + &b.lc(CS::one(), SecqScalar::ONE);
        }
        alloc_nonneg_u128(
            cs.namespace(|| "s_nonzero"),
            &Boolean::constant(true),
            s_sum_lc - &(LinearCombination::zero() + CS::one()),
            u128::from(s_ones.saturating_sub(1)),
        )?;

        let px = alloc_fp_from_be_bits(cs.namespace(|| "px_fp"), &px_bits, &self.slot.pubkey_x)?;
        let py = alloc_fp_from_be_bits(cs.namespace(|| "py_fp"), &py_bits, &self.py_be)?;
        let rx = alloc_fp_from_be_bits(cs.namespace(|| "rx_fp"), &rx_bits, &self.slot.sig_rx)?;
        let ry = alloc_fp_from_be_bits(cs.namespace(|| "ry_fp"), &ry_bits, &self.ry_be)?;

        enforce_on_secp256k1(cs.namespace(|| "P_on_curve"), &px, &py)?;
        enforce_on_secp256k1(cs.namespace(|| "R_on_curve"), &rx, &ry)?;

        // 4. Compute `e_bits = SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || rx || px || msg)`
        let tag_hash = sha256_bytes(BIP340_CHALLENGE_TAG);
        let mut chal_pre = constant_bits(&tag_hash);
        chal_pre.extend(constant_bits(&tag_hash));
        chal_pre.extend(rx_bits.iter().cloned());
        chal_pre.extend(px_bits.iter().cloned());
        chal_pre.extend(msg_bits.iter().cloned());
        let e_bits = sha256(cs.namespace(|| "bip340_chal_sha256"), &chal_pre)?;

        // 5. Exception-free 256-bit `s * G - E_raw * P == R` via NUMS offset `Q0`!
        let ((q0_x, q0_y), (neg_c_x, neg_c_y)) = nums_offset_points();
        let (gx, gy) = secp_generator_coords();

        let mut acc_x = AllocatedNum::alloc_infallible(cs.namespace(|| "a0_x"), || q0_x);
        let mut acc_y = AllocatedNum::alloc_infallible(cs.namespace(|| "a0_y"), || q0_y);
        cs.enforce(
            || "pin a0_x",
            |lc| lc + acc_x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (q0_x, CS::one()),
        );
        cs.enforce(
            || "pin a0_y",
            |lc| lc + acc_y.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (q0_y, CS::one()),
        );

        for i in 0..256 {
            let mut ns = cs.namespace(|| format!("ec_bit_{i}"));
            let (dx, dy) = ec_double(ns.namespace(|| "dbl"), &acc_x, &acc_y)?;

            let (sx, sy) = ec_chord_add(
                ns.namespace(|| "add_g"),
                &dx,
                &dy,
                LinearCombination::zero() + (gx, CS::one()),
                Some(gx),
                LinearCombination::zero() + (gy, CS::one()),
                Some(gy),
            )?;
            let (ax1, ay1) = ec_select(ns.namespace(|| "sel_g"), &s_bits[i], &dx, &dy, &sx, &sy)?;

            let (tx, ty) = ec_chord_add(
                ns.namespace(|| "sub_p"),
                &ax1,
                &ay1,
                LinearCombination::zero() + px.get_variable(),
                px.get_value(),
                LinearCombination::zero() - py.get_variable(),
                py.get_value().map(|v| -v),
            )?;
            let (ax2, ay2) = ec_select(ns.namespace(|| "sel_p"), &e_bits[i], &ax1, &ay1, &tx, &ty)?;
            acc_x = ax2;
            acc_y = ay2;
        }

        // Subtract `2^256 * Q0` (`+ (-2^256 * Q0)`) and bind directly to `(rx, ry)`!
        let (fx, fy) = ec_chord_add(
            cs.namespace(|| "unbias_q0"),
            &acc_x,
            &acc_y,
            LinearCombination::zero() + (neg_c_x, CS::one()),
            Some(neg_c_x),
            LinearCombination::zero() + (neg_c_y, CS::one()),
            Some(neg_c_y),
        )?;
        cs.enforce(
            || "fx == rx",
            |lc| lc + fx.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + rx.get_variable(),
        );
        cs.enforce(
            || "fy == ry",
            |lc| lc + fy.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + ry.get_variable(),
        );

        // 6. Compute next `auth_accumulator_root32` over the exact verified wire bits!
        let mut acc_pre = constant_bits(AUTH_ACC_DOMAIN);
        acc_pre.extend(prev_acc_bits);
        acc_pre.extend(step_idx_bits);
        acc_pre.extend(flag_bits);
        acc_pre.extend(px_bits);
        acc_pre.extend(msg_bits);
        acc_pre.extend(rx_bits);
        acc_pre.extend(s_bits);
        let next_acc_bits = sha256(cs.namespace(|| "next_auth_acc_sha256"), &acc_pre)?;

        let expected_next = self.slot.next_accumulator(&self.prev_acc);
        let (next_lo_u, next_hi_u) = u128_halves_le_from_digest(&expected_next);
        let next_lo = AllocatedNum::alloc_infallible(cs.namespace(|| "next_acc_lo"), || {
            secq_from_u128(next_lo_u)
        });
        let next_hi = AllocatedNum::alloc_infallible(cs.namespace(|| "next_acc_hi"), || {
            secq_from_u128(next_hi_u)
        });
        cs.enforce(
            || "bind next_acc_lo",
            |_| le_bytes_lc::<CS>(&next_acc_bits[0..128]),
            |lc| lc + CS::one(),
            |lc| lc + next_lo.get_variable(),
        );
        cs.enforce(
            || "bind next_acc_hi",
            |_| le_bytes_lc::<CS>(&next_acc_bits[128..256]),
            |lc| lc + CS::one(),
            |lc| lc + next_hi.get_variable(),
        );

        let next_count = AllocatedNum::alloc_infallible(cs.namespace(|| "next_count"), || {
            SecqScalar::from(u64::from(self.slot.step_idx) + 1)
        });
        cs.enforce(
            || "next_count == z[0] + 1",
            |lc| lc + z[0].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + next_count.get_variable(),
        );

        Ok(vec![next_count, next_lo, next_hi])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecqBatchAuthProofReceipt {
    pub relation: String,
    pub curve_cycle: String,
    pub trusted_setup_ceremony: bool,
    pub signature_steps: usize,
    pub primary_constraints: usize,
    pub secondary_constraints: usize,
    pub auth_accumulator_root_hex: String,
    pub vk_sha256_hex: String,
    pub proof_bytes: usize,
    pub proof_sha256_hex: String,
    pub setup_seconds: f64,
    pub fold_seconds: f64,
    pub compress_seconds: f64,
    pub verify_seconds: f64,
    pub wrong_accumulator_rejected: bool,
    pub nova_authorization_verified: bool,
}

pub fn prove_and_verify_secq_batch_auth(
    slots: &[Bip340StepSlot],
) -> Result<(Vec<u8>, [u8; 32], SecqBatchAuthProofReceipt), String> {
    prove_and_verify_secq_batch_auth_with_progress(slots, &mut |_, _, _, _| {})
}

pub fn prove_and_verify_secq_batch_auth_with_progress<F>(
    slots: &[Bip340StepSlot],
    on_progress: &mut F,
) -> Result<(Vec<u8>, [u8; 32], SecqBatchAuthProofReceipt), String>
where
    F: FnMut(&str, String, Option<u32>, Option<u32>),
{
    if slots.len() != AUTH_STEP_COUNT {
        return Err("expected 8 BIP-340 authorization slots".into());
    }
    let (final_acc, prevs) = compute_auth_accumulator_chain(slots);
    let steps: Vec<Mnr05SecqBip340Step> = prevs
        .into_iter()
        .zip(slots.iter().cloned())
        .map(|(p, s)| Mnr05SecqBip340Step::from_valid_slot(p, s))
        .collect::<Result<_, _>>()?;

    on_progress(
        "secq_setup",
        "Deriving Secq256k1/Secp256k1 IPA public params & Spartan keys".into(),
        None,
        None,
    );
    let t_setup = std::time::Instant::now();
    let blank = Mnr05SecqBip340Step::blank();
    let pp = PublicParams::<E1, E2, Mnr05SecqBip340Step>::setup(&blank, &*S1::ck_floor(), &*S2::ck_floor())
        .map_err(|e| format!("Secq PublicParams::setup: {e:?}"))?;
    let (pk, vk) = CompressedSNARK::<E1, E2, Mnr05SecqBip340Step, S1, S2>::setup(&pp)
        .map_err(|e| format!("Secq CompressedSNARK::setup: {e:?}"))?;
    let setup_seconds = t_setup.elapsed().as_secs_f64();

    let z0 = vec![SecqScalar::ZERO, SecqScalar::ZERO, SecqScalar::ZERO];
    let (final_lo, final_hi) = u128_halves_le_from_digest(&final_acc);
    let expected_z8 = vec![
        SecqScalar::from(AUTH_STEP_COUNT as u64),
        secq_from_u128(final_lo),
        secq_from_u128(final_hi),
    ];

    let t_fold = std::time::Instant::now();
    let mut rec = RecursiveSNARK::new(&pp, &steps[0], &z0)
        .map_err(|e| format!("Secq RecursiveSNARK::new: {e:?}"))?;
    for (idx, s) in steps.iter().enumerate() {
        on_progress(
            "secq_fold",
            format!(
                "Secq256k1 BIP-340 Schnorr fold {} / {} (flag 0x{:02x})",
                idx + 1,
                AUTH_STEP_COUNT,
                s.slot.sighash_flag
            ),
            Some((idx + 1) as u32),
            Some(AUTH_STEP_COUNT as u32),
        );
        rec.prove_step(&pp, s)
            .map_err(|e| format!("Secq prove_step: {e:?}"))?;
    }
    let zn = rec
        .verify(&pp, AUTH_STEP_COUNT, &z0)
        .map_err(|e| format!("Secq RecursiveSNARK::verify: {e:?}"))?;
    if zn != expected_z8 {
        return Err("Secq terminal state mismatch".into());
    }
    let fold_seconds = t_fold.elapsed().as_secs_f64();

    on_progress(
        "secq_compress",
        "Compressing 8-step Secq256k1 RecursiveSNARK via Spartan/IPA".into(),
        Some(AUTH_STEP_COUNT as u32),
        Some(AUTH_STEP_COUNT as u32),
    );
    let t_comp = std::time::Instant::now();
    let compressed = CompressedSNARK::<E1, E2, Mnr05SecqBip340Step, S1, S2>::prove(&pp, &pk, &rec)
        .map_err(|e| format!("Secq CompressedSNARK::prove: {e:?}"))?;
    let compress_seconds = t_comp.elapsed().as_secs_f64();

    let proof_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&compressed)
        .map_err(|e| format!("serialize Secq proof: {e}"))?;
    let vk_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&vk)
        .map_err(|e| format!("serialize Secq VK: {e}"))?;
    let vk_sha = sha256_bytes(&vk_bytes);
    let proof_sha = sha256_bytes(&proof_bytes);

    // Independent deserialization & verification + negative control
    let t_ver = std::time::Instant::now();
    let decoded_proof: CompressedSNARK<E1, E2, Mnr05SecqBip340Step, S1, S2> =
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&proof_bytes)
            .map_err(|e| format!("deserialize Secq proof: {e}"))?;
    let verified_zn = decoded_proof
        .verify(&vk, AUTH_STEP_COUNT, &z0)
        .map_err(|e| format!("independent Secq verify: {e:?}"))?;
    if verified_zn != expected_z8 {
        return Err("independent Secq verified state mismatch".into());
    }
    let mut bad_z0 = z0.clone();
    bad_z0[1] += SecqScalar::ONE;
    let wrong_acc_rejected = decoded_proof.verify(&vk, AUTH_STEP_COUNT, &bad_z0).is_err();
    if !wrong_acc_rejected {
        return Err("Secq verifier accepted mutated initial accumulator".into());
    }
    let verify_seconds = t_ver.elapsed().as_secs_f64();

    let (c1, c2) = pp.num_constraints();
    let receipt = SecqBatchAuthProofReceipt {
        relation: RELATION_SECQ_BIP340_V1.into(),
        curve_cycle: "Secq256k1Engine / Secp256k1Engine (Spartan + IPA, zero trusted setup)".into(),
        trusted_setup_ceremony: false,
        signature_steps: AUTH_STEP_COUNT,
        primary_constraints: c1,
        secondary_constraints: c2,
        auth_accumulator_root_hex: hex::encode(final_acc),
        vk_sha256_hex: hex::encode(vk_sha),
        proof_bytes: proof_bytes.len(),
        proof_sha256_hex: hex::encode(proof_sha),
        setup_seconds,
        fold_seconds,
        compress_seconds,
        verify_seconds,
        wrong_accumulator_rejected: wrong_acc_rejected,
        nova_authorization_verified: true,
    };
    Ok((proof_bytes, vk_sha, receipt))
}
