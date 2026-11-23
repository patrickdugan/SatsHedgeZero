//! `t-of-n` FROST-style Threshold Schnorr State Oracle Confederation over `secp256k1`.
//!
//! Uses Shamir secret sharing with Feldman VSS verification commitments and threshold-shared
//! per-digit nonces so ANY `t-of-n` subset of confederation signers can attest at maturity
//! even if `n - t` nodes go offline after publishing the `OracleAnnouncement`.
//! Each signer's partial signature is individually verifiable prior to aggregation.

use k256::{
    ProjectivePoint, Scalar, U256,
    elliptic_curve::{ops::Reduce, point::AffineCoordinates},
};
use shz_dlc::{
    Bip340Signature, OracleAnnouncement, OracleAttestation, bip340_challenge, bip340_verify,
    normalize_bip340_keypair, oracle_digit_message, tagged_hash,
};
use shz_margin::decompose_price_bits;

use crate::OracleError;

/// Individual confederation node holding Shamir secret share `(signer_id, key_share)`
/// and public verification share `pubkey_share = key_share * G`.
#[derive(Debug, Clone)]
pub struct FrostSignerNode {
    pub signer_id: u16,
    key_share: Scalar,
    pub pubkey_share: ProjectivePoint,
}

/// Pre-committed threshold-shared digit nonces for an announced DLC event.
#[derive(Debug, Clone)]
pub struct FrostEventNonceState {
    pub announcement: OracleAnnouncement,
    /// Per digit `j`: whether `R_sum,j` had odd Y and was negated for BIP-340 even-Y.
    nonce_negated: Vec<bool>,
    /// `per_signer_nonce_shares[signer_idx][digit_j]` (`k_{i,j}`).
    per_signer_nonce_shares: Vec<Vec<Scalar>>,
    /// Public verification commitments `K_{i,j} = k_{i,j} * G`.
    pub per_signer_nonce_commitments: Vec<Vec<ProjectivePoint>>,
}

/// Partial signature share produced by a single confederation node for one digit.
#[derive(Debug, Clone, Copy)]
pub struct FrostPartialDigitSig {
    pub signer_id: u16,
    pub digit_idx: u8,
    pub z_share: Scalar,
}

/// `t-of-n` Threshold BIP-340 Schnorr State Oracle Confederation.
#[derive(Debug, Clone)]
pub struct FrostConfederation {
    pub threshold_t: usize,
    pub total_n: usize,
    pub group_pubkey_x: [u8; 32],
    pub feldman_commitments: Vec<ProjectivePoint>,
    pub signers: Vec<FrostSignerNode>,
}

fn eval_polynomial(coeffs: &[Scalar], x: u64) -> Scalar {
    let x_scalar = Scalar::from(x);
    let mut pow = Scalar::ONE;
    let mut acc = Scalar::ZERO;
    for coeff in coeffs {
        acc += (*coeff) * pow;
        pow *= x_scalar;
    }
    acc
}

fn derive_deterministic_scalar(seed: &[u8; 32], label: &[u8], idx_a: u32, idx_b: u32) -> Scalar {
    for ctr in 0u32.. {
        let mut buf = Vec::with_capacity(48 + label.len());
        buf.extend_from_slice(seed);
        buf.extend_from_slice(label);
        buf.extend_from_slice(&idx_a.to_le_bytes());
        buf.extend_from_slice(&idx_b.to_le_bytes());
        buf.extend_from_slice(&ctr.to_le_bytes());
        let digest = tagged_hash(b"SatsHedgeZero/FROST/DeterministicPoly/v0", &buf);
        let s = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&digest));
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
    unreachable!()
}

/// Computes the Lagrange interpolation coefficient `\lambda_i(0)` for `signer_id` inside `active_ids`.
pub fn lagrange_coeff_at_zero(signer_id: u16, active_ids: &[u16]) -> Result<Scalar, OracleError> {
    let x_i = Scalar::from(signer_id as u64);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &other in active_ids {
        if other == signer_id {
            continue;
        }
        let x_j = Scalar::from(other as u64);
        num *= x_j;
        den *= x_j - x_i;
    }
    let den_inv_opt = den.invert();
    if bool::from(den_inv_opt.is_none()) {
        return Err(OracleError::InvalidFrostSigningSet(
            "duplicate signer_id in quorum",
        ));
    }
    Ok(num * den_inv_opt.unwrap())
}

impl FrostConfederation {
    /// Initializes a `t-of-n` FROST confederation from `master_seed`, verifying every share
    /// against Feldman VSS commitments `C_m = a_m * G`.
    pub fn keygen_deterministic(
        threshold_t: usize,
        total_n: usize,
        master_seed: &[u8; 32],
    ) -> Result<Self, OracleError> {
        if threshold_t < 2 || threshold_t > total_n || total_n > 255 {
            return Err(OracleError::InvalidFrostSigningSet(
                "require 2 <= threshold_t <= total_n <= 255",
            ));
        }

        let (group_secret_d, group_pubkey_x) = normalize_bip340_keypair(master_seed)?;
        let mut coeffs = Vec::with_capacity(threshold_t);
        coeffs.push(group_secret_d);
        for m in 1..threshold_t {
            coeffs.push(derive_deterministic_scalar(
                master_seed,
                b"dkg-coeff",
                m as u32,
                0,
            ));
        }

        let feldman_commitments: Vec<ProjectivePoint> = coeffs
            .iter()
            .map(|a_m| ProjectivePoint::GENERATOR * (*a_m))
            .collect();

        let mut signers = Vec::with_capacity(total_n);
        for idx in 1..=total_n {
            let signer_id = idx as u16;
            let key_share = eval_polynomial(&coeffs, signer_id as u64);
            let pubkey_share = ProjectivePoint::GENERATOR * key_share;

            // Verify Feldman VSS commitment: sum_{m=0}^{t-1} (i^m) * C_m == Y_i
            let x_scalar = Scalar::from(signer_id as u64);
            let mut pow = Scalar::ONE;
            let mut expected_point = ProjectivePoint::IDENTITY;
            for c_m in &feldman_commitments {
                expected_point += (*c_m) * pow;
                pow *= x_scalar;
            }
            if expected_point != pubkey_share {
                return Err(OracleError::InvalidFrostSigningSet(
                    "Feldman VSS share verification failed",
                ));
            }

            signers.push(FrostSignerNode {
                signer_id,
                key_share,
                pubkey_share,
            });
        }

        Ok(Self {
            threshold_t,
            total_n,
            group_pubkey_x,
            feldman_commitments,
            signers,
        })
    }

    /// Pre-commits `num_bits` threshold-shared nonces for `event_id` and returns the
    /// public `OracleAnnouncement` + confederation nonce state.
    pub fn announce_event(
        &self,
        event_id: &str,
        maturity_unix: u64,
        num_bits: u8,
        nonce_epoch_seed: &[u8; 32],
    ) -> Result<FrostEventNonceState, OracleError> {
        if !(4..=30).contains(&num_bits) {
            return Err(OracleError::InvalidFrostSigningSet(
                "num_bits must be in 4..=30",
            ));
        }

        let mut digit_nonces_x = Vec::with_capacity(num_bits as usize);
        let mut nonce_negated = Vec::with_capacity(num_bits as usize);
        let mut per_signer_nonce_shares = vec![Vec::with_capacity(num_bits as usize); self.total_n];
        let mut per_signer_nonce_commitments =
            vec![Vec::with_capacity(num_bits as usize); self.total_n];

        for j in 0..num_bits {
            let mut poly = Vec::with_capacity(self.threshold_t);
            for m in 0..self.threshold_t {
                poly.push(derive_deterministic_scalar(
                    nonce_epoch_seed,
                    event_id.as_bytes(),
                    j as u32,
                    m as u32,
                ));
            }
            let r_point = (ProjectivePoint::GENERATOR * poly[0]).to_affine();
            let negated: bool = r_point.y_is_odd().into();
            let r_x: [u8; 32] = r_point.x().into();

            digit_nonces_x.push(r_x);
            nonce_negated.push(negated);

            for (s_idx, signer) in self.signers.iter().enumerate() {
                let k_ij = eval_polynomial(&poly, signer.signer_id as u64);
                per_signer_nonce_shares[s_idx].push(k_ij);
                per_signer_nonce_commitments[s_idx].push(ProjectivePoint::GENERATOR * k_ij);
            }
        }

        let announcement = OracleAnnouncement {
            event_id: event_id.to_string(),
            maturity_unix,
            oracle_pubkey_x: self.group_pubkey_x,
            digit_nonces_x,
        };

        Ok(FrostEventNonceState {
            announcement,
            nonce_negated,
            per_signer_nonce_shares,
            per_signer_nonce_commitments,
        })
    }

    /// Produces and individually verifies partial signature shares from `participating_signer_ids`
    /// (`len >= threshold_t`) for a single digit `(digit_idx, bit_value)` and aggregates them
    /// into a standard 64-byte BIP-340 signature!
    pub fn threshold_sign_digit(
        &self,
        nonce_state: &FrostEventNonceState,
        participating_signer_ids: &[u16],
        digit_idx: u8,
        bit_value: u8,
    ) -> Result<Bip340Signature, OracleError> {
        if participating_signer_ids.len() < self.threshold_t {
            return Err(OracleError::InsufficientQuorum {
                got: participating_signer_ids.len(),
                required: self.threshold_t,
            });
        }
        let active_ids = &participating_signer_ids[..self.threshold_t];
        let j = digit_idx as usize;
        let r_x = nonce_state.announcement.digit_nonces_x[j];
        let msg = oracle_digit_message(&nonce_state.announcement.event_id, digit_idx, bit_value);
        let e = bip340_challenge(&r_x, &self.group_pubkey_x, &msg);
        let negated = nonce_state.nonce_negated[j];

        let mut partials = Vec::with_capacity(self.threshold_t);
        for &sid in active_ids {
            if sid == 0 || (sid as usize) > self.total_n {
                return Err(OracleError::InvalidFrostSigningSet(
                    "signer_id out of bounds",
                ));
            }
            let s_idx = (sid - 1) as usize;
            let signer = &self.signers[s_idx];
            let lambda_i = lagrange_coeff_at_zero(sid, active_ids)?;
            let k_ij = nonce_state.per_signer_nonce_shares[s_idx][j];
            let eff_k_ij = if negated { -k_ij } else { k_ij };
            let z_share = lambda_i * (eff_k_ij + e * signer.key_share);

            // Identifiable-abort partial share verification:
            // z_share * G == lambda_i * (±K_{i,j} + e * Y_i)
            let k_comm = nonce_state.per_signer_nonce_commitments[s_idx][j];
            let eff_k_comm = if negated { -k_comm } else { k_comm };
            let lhs = ProjectivePoint::GENERATOR * z_share;
            let rhs = (eff_k_comm + (signer.pubkey_share * e)) * lambda_i;
            if lhs != rhs {
                return Err(OracleError::ByzantineFrostShare { signer_id: sid });
            }

            partials.push(FrostPartialDigitSig {
                signer_id: sid,
                digit_idx,
                z_share,
            });
        }

        let mut s_sum = Scalar::ZERO;
        for part in partials {
            s_sum += part.z_share;
        }
        let sig = Bip340Signature {
            r_x,
            s: s_sum.to_bytes().into(),
        };
        bip340_verify(&self.group_pubkey_x, &msg, &sig)?;
        Ok(sig)
    }

    /// Threshold-signs all `num_bits` digits of `price_usd` using `participating_signer_ids` (`>= t`).
    pub fn threshold_attest_price(
        &self,
        nonce_state: &FrostEventNonceState,
        participating_signer_ids: &[u16],
        attested_timestamp_unix: u64,
        price_usd: u64,
    ) -> Result<OracleAttestation, OracleError> {
        let num_bits = nonce_state.announcement.num_bits();
        let digit_bits = decompose_price_bits(price_usd, num_bits);
        let mut digit_signatures = Vec::with_capacity(num_bits as usize);

        for (j, &bit) in digit_bits.iter().enumerate() {
            let sig =
                self.threshold_sign_digit(nonce_state, participating_signer_ids, j as u8, bit)?;
            digit_signatures.push(sig);
        }

        let attestation = OracleAttestation {
            event_id: nonce_state.announcement.event_id.clone(),
            attested_timestamp_unix,
            price_usd,
            digit_bits,
            digit_signatures,
        };
        attestation.verify_against(&nonce_state.announcement)?;
        Ok(attestation)
    }
}
