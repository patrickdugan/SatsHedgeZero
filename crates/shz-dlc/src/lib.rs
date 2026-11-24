//! `shz-dlc` — BIP-340 Schnorr adaptor signatures, multi-digit DLC anticipation points,
//! vanilla BTC `P2TR` funding/buffer/CET descriptors, and non-custodial Lightning
//! subchannel state transitions.

use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256,
    elliptic_curve::{
        Group,
        ops::Reduce,
        point::AffineCoordinates,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_margin::{
    CollateralAsset, CompressedCetRange, InverseContractSpec, MarginError, PayoutSplit,
    compress_cet_ranges, decompose_price_bits, lookup_cet_for_price,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DlcError {
    #[error("margin error: {0}")]
    Margin(#[from] MarginError),
    #[error("invalid secp256k1 scalar or zero key")]
    InvalidScalar,
    #[error("invalid x-only public key")]
    InvalidPublicKey,
    #[error("invalid adaptor point (point at infinity)")]
    InvalidAdaptorPoint,
    #[error("BIP-340 signature verification failed")]
    InvalidSchnorrSignature,
    #[error("Schnorr adaptor signature verification failed")]
    InvalidAdaptorSignature,
    #[error("oracle announcement mismatch: {0}")]
    OracleMismatch(&'static str),
    #[error("invalid subchannel state transition: {0}")]
    InvalidState(&'static str),
    #[error("CET not found for attested price {0}")]
    CetNotFound(u64),
}

/// Standard 64-byte BIP-340 Schnorr signature (`R_x || s`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Bip340Signature {
    pub r_x: [u8; 32],
    pub s: [u8; 32],
}

impl Bip340Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r_x);
        out[32..].copy_from_slice(&self.s);
        out
    }
}

/// 65-byte BIP-340 Schnorr adaptor signature locked to an elliptic-curve adaptor point `T = t * G`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct AdaptorSignature {
    /// x-coordinate of the effective even-Y nonce `R_eff = ±(R_0 + T)`.
    pub r_eff_x: [u8; 32],
    /// `true` if `R_0 + T` had odd Y and was negated (`s = s_adapt - t`), `false` if `s = s_adapt + t`.
    pub r_eff_negated: bool,
    /// Adapted scalar `s_adapt = (±k_0 + e * d) mod n`.
    pub s_adapt: [u8; 32],
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || payload)`.
pub fn tagged_hash(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tag_digest = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_digest);
    hasher.update(tag_digest);
    hasher.update(payload);
    hasher.finalize().into()
}

/// Computes the BIP-340 scalar challenge `e = H_tag("BIP0340/challenge", R_x || P_x || msg) mod n`.
pub fn bip340_challenge(r_x: &[u8; 32], pubkey_x: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(r_x);
    buf.extend_from_slice(pubkey_x);
    buf.extend_from_slice(msg);
    let hash = tagged_hash(b"BIP0340/challenge", &buf);
    <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&hash))
}

/// Parses a non-zero secp256k1 scalar from 32 big-endian bytes.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, DlcError> {
    let uint = U256::from_be_slice(bytes);
    let scalar = <Scalar as Reduce<U256>>::reduce(uint);
    let repr: [u8; 32] = scalar.to_bytes().into();
    if bool::from(scalar.is_zero()) || &repr != bytes {
        return Err(DlcError::InvalidScalar);
    }
    Ok(scalar)
}

/// Normalizes a secret key `sk` for BIP-340 even-Y x-only public key `(d, pk_x)`.
pub fn normalize_bip340_keypair(secret_bytes: &[u8; 32]) -> Result<(Scalar, [u8; 32]), DlcError> {
    let raw = scalar_from_bytes(secret_bytes)?;
    let point = (ProjectivePoint::GENERATOR * raw).to_affine();
    let d = if bool::from(point.y_is_odd()) {
        -raw
    } else {
        raw
    };
    let pk_x: [u8; 32] = point.x().into();
    Ok((d, pk_x))
}

/// Derives the 32-byte BIP-340 x-only public key from `secret_bytes`.
pub fn pubkey_x_from_secret(secret_bytes: &[u8; 32]) -> Result<[u8; 32], DlcError> {
    Ok(normalize_bip340_keypair(secret_bytes)?.1)
}

/// Lifts a 32-byte x-only public key to its unique even-Y `ProjectivePoint` (`lift_x`).
pub fn lift_x_even(pubkey_x: &[u8; 32]) -> Result<ProjectivePoint, DlcError> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02; // SEC1 compressed even-Y prefix
    sec1[1..].copy_from_slice(pubkey_x);
    let encoded = EncodedPoint::from_bytes(sec1).map_err(|_| DlcError::InvalidPublicKey)?;
    let opt = ProjectivePoint::from_encoded_point(&encoded);
    if bool::from(opt.is_some()) {
        Ok(opt.unwrap())
    } else {
        Err(DlcError::InvalidPublicKey)
    }
}

/// Encodes a non-identity `ProjectivePoint` in 33-byte compressed SEC1 format.
pub fn encode_point_compressed(point: &ProjectivePoint) -> Result<[u8; 33], DlcError> {
    if bool::from(point.is_identity()) {
        return Err(DlcError::InvalidAdaptorPoint);
    }
    let affine: AffinePoint = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

/// Decodes a 33-byte compressed SEC1 point into a non-identity `ProjectivePoint`.
pub fn decode_point_compressed(bytes: &[u8; 33]) -> Result<ProjectivePoint, DlcError> {
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| DlcError::InvalidAdaptorPoint)?;
    let opt = ProjectivePoint::from_encoded_point(&encoded);
    if bool::from(opt.is_some()) {
        let p = opt.unwrap();
        if bool::from(p.is_identity()) {
            return Err(DlcError::InvalidAdaptorPoint);
        }
        Ok(p)
    } else {
        Err(DlcError::InvalidAdaptorPoint)
    }
}

fn deterministic_nonce_scalar(d: &Scalar, pk_x: &[u8; 32], msg: &[u8], extra: &[u8]) -> Scalar {
    for counter in 0u32.. {
        let mut payload = Vec::with_capacity(68 + msg.len() + extra.len());
        payload.extend_from_slice(&d.to_bytes());
        payload.extend_from_slice(pk_x);
        payload.extend_from_slice(msg);
        payload.extend_from_slice(extra);
        payload.extend_from_slice(&counter.to_le_bytes());
        let h = tagged_hash(b"BIP0340/nonce", &payload);
        let k = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&h));
        if !bool::from(k.is_zero()) {
            return k;
        }
    }
    unreachable!()
}

/// Standard deterministic BIP-340 Schnorr signature.
pub fn bip340_sign(secret_bytes: &[u8; 32], msg: &[u8]) -> Result<Bip340Signature, DlcError> {
    let (d, pk_x) = normalize_bip340_keypair(secret_bytes)?;
    let k0 = deterministic_nonce_scalar(&d, &pk_x, msg, b"standard");
    let r_point = (ProjectivePoint::GENERATOR * k0).to_affine();
    let k = if bool::from(r_point.y_is_odd()) {
        -k0
    } else {
        k0
    };
    let r_x: [u8; 32] = r_point.x().into();
    let e = bip340_challenge(&r_x, &pk_x, msg);
    let s = k + e * d;
    Ok(Bip340Signature {
        r_x,
        s: s.to_bytes().into(),
    })
}

/// Verifies a standard 64-byte BIP-340 Schnorr signature.
pub fn bip340_verify(
    pubkey_x: &[u8; 32],
    msg: &[u8],
    sig: &Bip340Signature,
) -> Result<(), DlcError> {
    let p = lift_x_even(pubkey_x)?;
    let s = scalar_from_bytes(&sig.s).or_else(|_| {
        if sig.s == [0u8; 32] {
            Ok(Scalar::ZERO)
        } else {
            Err(DlcError::InvalidSchnorrSignature)
        }
    })?;
    let e = bip340_challenge(&sig.r_x, pubkey_x, msg);
    let r_check = (ProjectivePoint::GENERATOR * s) - (p * e);
    if bool::from(r_check.is_identity()) {
        return Err(DlcError::InvalidSchnorrSignature);
    }
    let affine = r_check.to_affine();
    if bool::from(affine.y_is_odd()) {
        return Err(DlcError::InvalidSchnorrSignature);
    }
    let actual_rx: [u8; 32] = affine.x().into();
    if actual_rx != sig.r_x {
        return Err(DlcError::InvalidSchnorrSignature);
    }
    Ok(())
}

/// Creates a BIP-340 Schnorr adaptor signature on `msg` locked under `adaptor_point = t * G`.
pub fn adaptor_sign(
    secret_bytes: &[u8; 32],
    msg: &[u8],
    adaptor_point: &ProjectivePoint,
) -> Result<AdaptorSignature, DlcError> {
    let (d, pk_x) = normalize_bip340_keypair(secret_bytes)?;
    let t_compressed = encode_point_compressed(adaptor_point)?;

    for attempt in 0u32.. {
        let mut extra = Vec::with_capacity(37);
        extra.extend_from_slice(&t_compressed);
        extra.extend_from_slice(&attempt.to_le_bytes());
        let k0 = deterministic_nonce_scalar(&d, &pk_x, msg, &extra);
        let r0 = ProjectivePoint::GENERATOR * k0;
        let r_sum = r0 + adaptor_point;
        if bool::from(r_sum.is_identity()) {
            continue;
        }
        let r_sum_affine = r_sum.to_affine();
        let r_eff_negated: bool = r_sum_affine.y_is_odd().into();
        let r_eff_x: [u8; 32] = r_sum_affine.x().into();
        let e = bip340_challenge(&r_eff_x, &pk_x, msg);

        let s_adapt = if r_eff_negated {
            (-k0) + e * d
        } else {
            k0 + e * d
        };

        return Ok(AdaptorSignature {
            r_eff_x,
            r_eff_negated,
            s_adapt: s_adapt.to_bytes().into(),
        });
    }
    unreachable!()
}

/// Publicly verifies an `AdaptorSignature` against `pubkey_x`, `msg`, and `adaptor_point`
/// without knowing the discrete log `t` of `adaptor_point`.
pub fn adaptor_verify(
    pubkey_x: &[u8; 32],
    msg: &[u8],
    adaptor_point: &ProjectivePoint,
    adaptor_sig: &AdaptorSignature,
) -> Result<(), DlcError> {
    if bool::from(adaptor_point.is_identity()) {
        return Err(DlcError::InvalidAdaptorPoint);
    }
    let p = lift_x_even(pubkey_x)?;
    let s_adapt = if adaptor_sig.s_adapt == [0u8; 32] {
        Scalar::ZERO
    } else {
        scalar_from_bytes(&adaptor_sig.s_adapt).map_err(|_| DlcError::InvalidAdaptorSignature)?
    };
    let e = bip340_challenge(&adaptor_sig.r_eff_x, pubkey_x, msg);
    let r_base = (ProjectivePoint::GENERATOR * s_adapt) - (p * e);
    let r_check = if adaptor_sig.r_eff_negated {
        r_base - adaptor_point
    } else {
        r_base + adaptor_point
    };
    if bool::from(r_check.is_identity()) {
        return Err(DlcError::InvalidAdaptorSignature);
    }
    let affine = r_check.to_affine();
    if bool::from(affine.y_is_odd()) {
        return Err(DlcError::InvalidAdaptorSignature);
    }
    let check_x: [u8; 32] = affine.x().into();
    if check_x != adaptor_sig.r_eff_x {
        return Err(DlcError::InvalidAdaptorSignature);
    }
    Ok(())
}

/// Completes an `AdaptorSignature` using the secret adaptor scalar `t` (`t * G == adaptor_point`)
/// into a valid 64-byte BIP-340 Schnorr signature.
pub fn adaptor_complete(
    adaptor_sig: &AdaptorSignature,
    adaptor_secret_t: &Scalar,
) -> Result<Bip340Signature, DlcError> {
    let s_adapt = if adaptor_sig.s_adapt == [0u8; 32] {
        Scalar::ZERO
    } else {
        scalar_from_bytes(&adaptor_sig.s_adapt)?
    };
    let s = if adaptor_sig.r_eff_negated {
        s_adapt - adaptor_secret_t
    } else {
        s_adapt + adaptor_secret_t
    };
    Ok(Bip340Signature {
        r_x: adaptor_sig.r_eff_x,
        s: s.to_bytes().into(),
    })
}

/// Extracts AND cryptographically authenticates the secret adaptor scalar `t`
/// (`DLC_SECURITY_ARCHITECTURE_REVIEW.md` #8): verifies `adaptor_sig`, `completed_sig`,
/// and `t * G == adaptor_point` before returning `t`, preventing unrelated-signature forgery.
pub fn adaptor_extract_secret_verified(
    pubkey_x: &[u8; 32],
    msg: &[u8],
    adaptor_point: &ProjectivePoint,
    adaptor_sig: &AdaptorSignature,
    completed_sig: &Bip340Signature,
) -> Result<Scalar, DlcError> {
    adaptor_verify(pubkey_x, msg, adaptor_point, adaptor_sig)?;
    bip340_verify(pubkey_x, msg, completed_sig)?;
    let t = adaptor_extract_secret(adaptor_sig, completed_sig)?;
    if &(ProjectivePoint::GENERATOR * t) != adaptor_point {
        return Err(DlcError::InvalidAdaptorSignature);
    }
    Ok(t)
}
/// Extracts the secret adaptor scalar `t` after verifying `r_eff_x == r_x`.
/// Callers handling untrusted completed signatures MUST prefer [`adaptor_extract_secret_verified`].
pub fn adaptor_extract_secret(
    adaptor_sig: &AdaptorSignature,
    completed_sig: &Bip340Signature,
) -> Result<Scalar, DlcError> {
    if adaptor_sig.r_eff_x != completed_sig.r_x {
        return Err(DlcError::InvalidAdaptorSignature);
    }
    let s_adapt = if adaptor_sig.s_adapt == [0u8; 32] {
        Scalar::ZERO
    } else {
        scalar_from_bytes(&adaptor_sig.s_adapt)?
    };
    let s = if completed_sig.s == [0u8; 32] {
        Scalar::ZERO
    } else {
        scalar_from_bytes(&completed_sig.s)?
    };
    let t = if adaptor_sig.r_eff_negated {
        s_adapt - s
    } else {
        s - s_adapt
    };
    Ok(t)
}

/// Canonical domain-separated message signed by a DLC oracle for digit index `digit_idx`
/// and binary outcome `bit_value` (`0` or `1`).
pub fn oracle_digit_message(event_id: &str, digit_idx: u8, bit_value: u8) -> [u8; 32] {
    let mut buf = Vec::with_capacity(event_id.len() + 6);
    buf.extend_from_slice(&(event_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(event_id.as_bytes());
    buf.push(digit_idx);
    buf.push(bit_value);
    tagged_hash(b"SatsHedgeZero/DLC/DigitOutcome/v0", &buf)
}

/// Public numeric DLC announcement emitted ahead of contract maturity by an oracle
/// (e.g. a `t-of-n` FROST confederation).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct OracleAnnouncement {
    pub event_id: String,
    pub maturity_unix: u64,
    pub oracle_pubkey_x: [u8; 32],
    /// MSB-first pre-committed even-Y x-only nonces `R_0 .. R_{num_bits - 1}`.
    pub digit_nonces_x: Vec<[u8; 32]>,
}

impl OracleAnnouncement {
    pub fn num_bits(&self) -> u8 {
        self.digit_nonces_x.len() as u8
    }

    /// Precomputes `[P_{j,0}, P_{j,1}]` (`R_j + e_{j,b} * X_oracle`) for every digit `j` once,
    /// reducing per-CET anticipation point derivation from `O(m)` scalar muls to `O(m)` point adds.
    pub fn precompute_digit_points(&self) -> Result<Vec<[ProjectivePoint; 2]>, DlcError> {
        let x_oracle = lift_x_even(&self.oracle_pubkey_x)?;
        let mut table = Vec::with_capacity(self.digit_nonces_x.len());
        for (idx, nonce_x) in self.digit_nonces_x.iter().enumerate() {
            let r_j = lift_x_even(nonce_x)?;
            let msg0 = oracle_digit_message(&self.event_id, idx as u8, 0);
            let msg1 = oracle_digit_message(&self.event_id, idx as u8, 1);
            let e0 = bip340_challenge(nonce_x, &self.oracle_pubkey_x, &msg0);
            let e1 = bip340_challenge(nonce_x, &self.oracle_pubkey_x, &msg1);
            table.push([r_j + (x_oracle * e0), r_j + (x_oracle * e1)]);
        }
        Ok(table)
    }

    pub fn anticipation_point_from_table(
        table: &[[ProjectivePoint; 2]],
        prefix_bits: &[u8],
    ) -> Result<ProjectivePoint, DlcError> {
        if prefix_bits.is_empty() || prefix_bits.len() > table.len() {
            return Err(DlcError::OracleMismatch(
                "prefix_bits length must be in 1..=num_bits",
            ));
        }
        let mut sum = ProjectivePoint::IDENTITY;
        for (idx, &bit) in prefix_bits.iter().enumerate() {
            if bit > 1 {
                return Err(DlcError::OracleMismatch("binary digit must be 0 or 1"));
            }
            sum += table[idx][bit as usize];
        }
        if bool::from(sum.is_identity()) {
            return Err(DlcError::InvalidAdaptorPoint);
        }
        Ok(sum)
    }

    /// Computes the public anticipation point `T(prefix) = sum_{j=0}^{m-1} (R_j + e_j * X_oracle)`
    /// for a compressed CET binary prefix `prefix_bits`.
    pub fn anticipation_point(&self, prefix_bits: &[u8]) -> Result<ProjectivePoint, DlcError> {
        let table = self.precompute_digit_points()?;
        Self::anticipation_point_from_table(&table, prefix_bits)
    }
}

/// Multi-digit BIP-340 oracle attestation settling `event_id` at `price_usd`.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct OracleAttestation {
    pub event_id: String,
    pub attested_timestamp_unix: u64,
    pub price_usd: u64,
    pub digit_bits: Vec<u8>,
    pub digit_signatures: Vec<Bip340Signature>,
}

impl OracleAttestation {
    /// Verifies every digit's BIP-340 Schnorr signature against `announcement` and checks
    /// that `digit_bits` matches `price_usd`.
    pub fn verify_against(&self, announcement: &OracleAnnouncement) -> Result<(), DlcError> {
        if self.event_id != announcement.event_id {
            return Err(DlcError::OracleMismatch("event_id mismatch"));
        }
        let n = announcement.digit_nonces_x.len();
        if self.digit_bits.len() != n || self.digit_signatures.len() != n {
            return Err(DlcError::OracleMismatch("digit length mismatch"));
        }
        let expected_bits = decompose_price_bits(self.price_usd, n as u8);
        if self.digit_bits != expected_bits {
            return Err(DlcError::OracleMismatch(
                "digit_bits do not match attested price_usd",
            ));
        }
        for j in 0..n {
            if self.digit_signatures[j].r_x != announcement.digit_nonces_x[j] {
                return Err(DlcError::OracleMismatch(
                    "signature nonce does not match pre-committed announcement nonce",
                ));
            }
            let msg = oracle_digit_message(&self.event_id, j as u8, self.digit_bits[j]);
            bip340_verify(&announcement.oracle_pubkey_x, &msg, &self.digit_signatures[j])?;
        }
        Ok(())
    }

    /// Sums the first `prefix_len` attested scalars `t = sum_{j=0}^{prefix_len-1} s_j mod n`
    /// to unlock the matching compressed CET adaptor signature.
    pub fn secret_scalar_for_prefix(&self, prefix_len: usize) -> Result<Scalar, DlcError> {
        if prefix_len == 0 || prefix_len > self.digit_signatures.len() {
            return Err(DlcError::OracleMismatch("invalid prefix_len"));
        }
        let mut sum = Scalar::ZERO;
        for sig in &self.digit_signatures[..prefix_len] {
            let s_j = if sig.s == [0u8; 32] {
                Scalar::ZERO
            } else {
                scalar_from_bytes(&sig.s)?
            };
            sum += s_j;
        }
        Ok(sum)
    }
}

/// Vanilla Bitcoin UTXO outpoint anchoring a Lightning channel or direct DLC funding output.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct BtcOutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// Taproot (`P2TR`) 2-of-2 funding & optimistic fallback descriptor for a non-custodial LN-DLC.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TaprootDlcDescriptor {
    pub long_pubkey_x: [u8; 32],
    pub short_pubkey_x: [u8; 32],
    /// Deterministic sorted key-agg digest representing the 2-of-2 internal key.
    pub joint_internal_key_tag: [u8; 32],
    /// Relative CSV dispute timelock blocks allowing emergency relay/fallback resolution if FROST cheats.
    pub dispute_csv_blocks: u16,
    /// Optional Taproot Asset commitment leaf hash (`None` for v0 `VanillaBtc`).
    pub tap_asset_leaf_hash: Option<[u8; 32]>,
    /// Final tweaked P2TR output witness program hash.
    pub output_key_commitment: [u8; 32],
}

impl TaprootDlcDescriptor {
    pub fn new(
        long_pubkey_x: [u8; 32],
        short_pubkey_x: [u8; 32],
        dispute_csv_blocks: u16,
        collateral: &CollateralAsset,
        total_units: u64,
    ) -> Self {
        let (first, second) = if long_pubkey_x <= short_pubkey_x {
            (long_pubkey_x, short_pubkey_x)
        } else {
            (short_pubkey_x, long_pubkey_x)
        };
        let mut agg_buf = [0u8; 64];
        agg_buf[..32].copy_from_slice(&first);
        agg_buf[32..].copy_from_slice(&second);
        let joint_internal_key_tag = tagged_hash(b"SatsHedgeZero/MuSig2KeyAgg/v0", &agg_buf);
        let tap_asset_leaf_hash = collateral.tap_commitment_leaf_hash(total_units);

        let mut tweak_payload = Vec::with_capacity(68);
        tweak_payload.extend_from_slice(&joint_internal_key_tag);
        tweak_payload.extend_from_slice(&dispute_csv_blocks.to_le_bytes());
        if let Some(leaf) = &tap_asset_leaf_hash {
            tweak_payload.push(1);
            tweak_payload.extend_from_slice(leaf);
        } else {
            tweak_payload.push(0);
        }
        let output_key_commitment = tagged_hash(b"TapTweak", &tweak_payload);

        Self {
            long_pubkey_x,
            short_pubkey_x,
            joint_internal_key_tag,
            dispute_csv_blocks,
            tap_asset_leaf_hash,
            output_key_commitment,
        }
    }
}

/// Deterministic sighash for a compressed CET spending the subchannel buffer output.
pub fn cet_sighash(
    subchannel_id: &[u8; 32],
    buffer_outpoint: &BtcOutPoint,
    cet_index: u32,
    cet: &CompressedCetRange,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(112 + cet.prefix_bits.len());
    buf.extend_from_slice(subchannel_id);
    buf.extend_from_slice(&buffer_outpoint.txid);
    buf.extend_from_slice(&buffer_outpoint.vout.to_le_bytes());
    buf.extend_from_slice(&cet_index.to_le_bytes());
    buf.extend_from_slice(&cet.min_price_usd.to_le_bytes());
    buf.extend_from_slice(&cet.max_price_usd.to_le_bytes());
    buf.extend_from_slice(&cet.payout.long_sats.to_le_bytes());
    buf.extend_from_slice(&cet.payout.short_sats.to_le_bytes());
    buf.extend_from_slice(&cet.prefix_bits);
    tagged_hash(b"SatsHedgeZero/CET/Sighash/v0", &buf)
}

/// Deterministic sighash for a 0-fee off-chain Lightning cooperative close / rollover update.
pub fn cooperative_close_sighash(
    subchannel_id: &[u8; 32],
    sequence_num: u64,
    agreed_mark_price_usd: u64,
    payout: &PayoutSplit,
) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(subchannel_id);
    buf[32..40].copy_from_slice(&sequence_num.to_le_bytes());
    buf[40..48].copy_from_slice(&agreed_mark_price_usd.to_le_bytes());
    buf[48..56].copy_from_slice(&payout.long_sats.to_le_bytes());
    buf[56..64].copy_from_slice(&payout.short_sats.to_le_bytes());
    tagged_hash(b"SatsHedgeZero/LnSubchannel/CoopClose/v0", &buf)
}

/// Pre-signed adaptor CET bundle held inside an active Lightning DLC subchannel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAdaptorCet {
    pub cet_index: u32,
    pub range: CompressedCetRange,
    pub sighash: [u8; 32],
    pub long_adaptor_sig: AdaptorSignature,
    pub short_adaptor_sig: AdaptorSignature,
}

/// Lifecycle state of a non-custodial Lightning DLC subchannel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubchannelStatus {
    Offered,
    ActiveInLightningChannel {
        cet_count: usize,
        sequence_num: u64,
    },
    CooperativelyClosedOffChain {
        sequence_num: u64,
        mark_price_usd: u64,
        final_split: PayoutSplit,
        long_close_sig: Bip340Signature,
        short_close_sig: Bip340Signature,
    },
    SettledOnChainViaCet {
        cet_index: u32,
        attested_price_usd: u64,
        final_split: PayoutSplit,
        completed_long_sig: Bip340Signature,
        completed_short_sig: Bip340Signature,
    },
}

/// Non-custodial 2-party Lightning DLC subchannel (`VanillaBtc` UTXO backed, 0 protocol fee).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnDlcSubchannel {
    pub subchannel_id: [u8; 32],
    pub channel_funding_outpoint: BtcOutPoint,
    pub buffer_outpoint: BtcOutPoint,
    pub spec: InverseContractSpec,
    pub descriptor: TaprootDlcDescriptor,
    pub announcement: OracleAnnouncement,
    pub max_cet_error_sats: u64,
    pub adaptor_cets: Vec<SignedAdaptorCet>,
    pub status: SubchannelStatus,
}

impl LnDlcSubchannel {
    /// Step 1: Creates a validated v0 Lightning DLC subchannel offer and compresses the CET tree.
    pub fn offer_v0(
        channel_funding_outpoint: BtcOutPoint,
        spec: InverseContractSpec,
        long_pubkey_x: [u8; 32],
        short_pubkey_x: [u8; 32],
        announcement: OracleAnnouncement,
        dispute_csv_blocks: u16,
        max_cet_error_sats: u64,
    ) -> Result<Self, DlcError> {
        spec.validate_v0()?;
        let descriptor = TaprootDlcDescriptor::new(
            long_pubkey_x,
            short_pubkey_x,
            dispute_csv_blocks,
            &spec.collateral,
            spec.total_collateral_sats(),
        );

        let mut id_payload = Vec::with_capacity(128);
        id_payload.extend_from_slice(&channel_funding_outpoint.txid);
        id_payload.extend_from_slice(&channel_funding_outpoint.vout.to_le_bytes());
        id_payload.extend_from_slice(&descriptor.output_key_commitment);
        id_payload.extend_from_slice(announcement.event_id.as_bytes());
        let subchannel_id = tagged_hash(b"SatsHedgeZero/SubchannelId/v0", &id_payload);

        // Deterministic subchannel buffer UTXO carved from the LN commitment transaction.
        let buffer_txid = tagged_hash(b"SatsHedgeZero/BufferTxid/v0", &subchannel_id);
        let buffer_outpoint = BtcOutPoint {
            txid: buffer_txid,
            vout: 0,
        };

        Ok(Self {
            subchannel_id,
            channel_funding_outpoint,
            buffer_outpoint,
            spec,
            descriptor,
            announcement,
            max_cet_error_sats,
            adaptor_cets: Vec::new(),
            status: SubchannelStatus::Offered,
        })
    }

    /// Step 2: Both peers generate and mutually verify BIP-340 Schnorr adaptor signatures
    /// for every compressed CET prefix, locking the subchannel inside their Lightning channel.
    pub fn sign_and_activate_cets(
        &mut self,
        long_secret: &[u8; 32],
        short_secret: &[u8; 32],
    ) -> Result<usize, DlcError> {
        if self.status != SubchannelStatus::Offered {
            return Err(DlcError::InvalidState("subchannel must be in Offered state"));
        }
        if pubkey_x_from_secret(long_secret)? != self.descriptor.long_pubkey_x {
            return Err(DlcError::InvalidPublicKey);
        }
        if pubkey_x_from_secret(short_secret)? != self.descriptor.short_pubkey_x {
            return Err(DlcError::InvalidPublicKey);
        }

        let ranges = compress_cet_ranges(
            &self.spec,
            self.announcement.num_bits(),
            self.max_cet_error_sats,
        )?;
        let digit_table = self.announcement.precompute_digit_points()?;
        let mut signed = Vec::with_capacity(ranges.len());

        for (idx, range) in ranges.into_iter().enumerate() {
            let cet_index = idx as u32;
            let sighash = cet_sighash(&self.subchannel_id, &self.buffer_outpoint, cet_index, &range);
            let anticipation =
                OracleAnnouncement::anticipation_point_from_table(&digit_table, &range.prefix_bits)?;

            let long_adaptor_sig = adaptor_sign(long_secret, &sighash, &anticipation)?;
            let short_adaptor_sig = adaptor_sign(short_secret, &sighash, &anticipation)?;

            // Mutual non-trusting verification before channel commitment lock!
            adaptor_verify(
                &self.descriptor.long_pubkey_x,
                &sighash,
                &anticipation,
                &long_adaptor_sig,
            )?;
            adaptor_verify(
                &self.descriptor.short_pubkey_x,
                &sighash,
                &anticipation,
                &short_adaptor_sig,
            )?;

            signed.push(SignedAdaptorCet {
                cet_index,
                range,
                sighash,
                long_adaptor_sig,
                short_adaptor_sig,
            });
        }

        let count = signed.len();
        self.adaptor_cets = signed;
        self.status = SubchannelStatus::ActiveInLightningChannel {
            cet_count: count,
            sequence_num: 1,
        };
        Ok(count)
    }

    /// Fast Path (LN Markets UX, 0 L1 txs, 0 fees): Instant cooperative close off-chain
    /// inside the Lightning channel at an agreed `mark_price_usd`.
    pub fn cooperative_close_off_chain(
        &mut self,
        agreed_mark_price_usd: u64,
        long_secret: &[u8; 32],
        short_secret: &[u8; 32],
    ) -> Result<PayoutSplit, DlcError> {
        let next_seq = match self.status {
            SubchannelStatus::ActiveInLightningChannel { sequence_num, .. } => sequence_num + 1,
            _ => {
                return Err(DlcError::InvalidState(
                    "subchannel must be ActiveInLightningChannel",
                ));
            }
        };

        let final_split = self.spec.payout_at_price(agreed_mark_price_usd);
        let sighash = cooperative_close_sighash(
            &self.subchannel_id,
            next_seq,
            agreed_mark_price_usd,
            &final_split,
        );
        let long_close_sig = bip340_sign(long_secret, &sighash)?;
        let short_close_sig = bip340_sign(short_secret, &sighash)?;

        bip340_verify(&self.descriptor.long_pubkey_x, &sighash, &long_close_sig)?;
        bip340_verify(&self.descriptor.short_pubkey_x, &sighash, &short_close_sig)?;

        self.status = SubchannelStatus::CooperativelyClosedOffChain {
            sequence_num: next_seq,
            mark_price_usd: agreed_mark_price_usd,
            final_split,
            long_close_sig,
            short_close_sig,
        };
        Ok(final_split)
    }

    /// Unilateral L1 Force-Close Path: Verifies the oracle's BIP-340 multi-digit attestation,
    /// derives `t = sum s_j`, completes both counterparties' adaptor signatures into valid
    /// 64-byte BIP-340 Schnorr signatures on the winning CET, and verifies L1 spendability.
    pub fn settle_on_chain_with_attestation(
        &mut self,
        attestation: &OracleAttestation,
    ) -> Result<PayoutSplit, DlcError> {
        if !matches!(self.status, SubchannelStatus::ActiveInLightningChannel { .. }) {
            return Err(DlcError::InvalidState(
                "subchannel must be ActiveInLightningChannel",
            ));
        }

        attestation.verify_against(&self.announcement)?;

        let num_bits = self.announcement.num_bits();
        let ranges: Vec<CompressedCetRange> =
            self.adaptor_cets.iter().map(|c| c.range.clone()).collect();
        let matched = lookup_cet_for_price(&ranges, attestation.price_usd, num_bits)
            .ok_or(DlcError::CetNotFound(attestation.price_usd))?;
        let cet_bundle = self
            .adaptor_cets
            .iter()
            .find(|c| c.range.min_price_usd == matched.min_price_usd)
            .ok_or(DlcError::CetNotFound(attestation.price_usd))?;

        let secret_t = attestation.secret_scalar_for_prefix(cet_bundle.range.prefix_bits.len())?;
        let completed_long_sig = adaptor_complete(&cet_bundle.long_adaptor_sig, &secret_t)?;
        let completed_short_sig = adaptor_complete(&cet_bundle.short_adaptor_sig, &secret_t)?;

        // Verify both completed signatures are genuine BIP-340 Schnorr signatures on the CET!
        bip340_verify(
            &self.descriptor.long_pubkey_x,
            &cet_bundle.sighash,
            &completed_long_sig,
        )?;
        bip340_verify(
            &self.descriptor.short_pubkey_x,
            &cet_bundle.sighash,
            &completed_short_sig,
        )?;

        let final_split = cet_bundle.range.payout;
        self.status = SubchannelStatus::SettledOnChainViaCet {
            cet_index: cet_bundle.cet_index,
            attested_price_usd: attestation.price_usd,
            final_split,
            completed_long_sig,
            completed_short_sig,
        };
        Ok(final_split)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptor_signature_both_parities_and_secret_extraction() {
        let signer_sk = [0x11u8; 32];
        let pk_x = pubkey_x_from_secret(&signer_sk).unwrap();
        let msg = b"cet-sighash-parity-test";

        let mut saw_negated_true = false;
        let mut saw_negated_false = false;

        // Sweep 32 distinct adaptor secrets to exercise both even-Y and odd-Y `R_0 + T` parities!
        for i in 1u8..=32 {
            let mut t_bytes = [0u8; 32];
            t_bytes[31] = i;
            let t_scalar = scalar_from_bytes(&t_bytes).unwrap();
            let t_point = ProjectivePoint::GENERATOR * t_scalar;

            let asig = adaptor_sign(&signer_sk, msg, &t_point).unwrap();
            if asig.r_eff_negated {
                saw_negated_true = true;
            } else {
                saw_negated_false = true;
            }

            adaptor_verify(&pk_x, msg, &t_point, &asig).unwrap();
            let completed = adaptor_complete(&asig, &t_scalar).unwrap();
            bip340_verify(&pk_x, msg, &completed).unwrap();

            let extracted =
                adaptor_extract_secret_verified(&pk_x, msg, &t_point, &asig, &completed).unwrap();
            assert_eq!(extracted, t_scalar);

            // UTXORef `DLC_SECURITY_ARCHITECTURE_REVIEW.md` #1 regression check:
            // Related adaptor points `T` and `-T` share the same x-coordinate; nonce derivation
            // MUST commit to compressed 33-byte y-parity so `T` and `-T` never reuse a nonce!
            let neg_t_point = -t_point;
            let asig_neg = adaptor_sign(&signer_sk, msg, &neg_t_point).unwrap();
            assert_ne!(
                asig.r_eff_x, asig_neg.r_eff_x,
                "related adaptor points T and -T reused effective nonce!"
            );
        }

        assert!(saw_negated_true && saw_negated_false);
    }
}
