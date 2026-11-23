//! NEAR-compatible Borsh Bonded Fraud Proof Verifier (`NearBondedOracleVault`).
//!
//! Slashes a cheating FROST state oracle confederation under two cryptographically
//! verified fraud-proof regimes:
//! 1. `EquivocationFraudProof` — Double-signing two distinct outcomes (`0` and `1`) under
//!    the same pre-committed digit nonce `R_j`. Algebraically extracts the confederation's
//!    secp256k1 private key `d` (`d * G == X_confed`) to sweep L1 BTC slash bonds + 100% NEAR stake!
//! 2. `DeviationFraudProof` — Collusive single-price attestation `P_frost` that deviates beyond
//!    `max_deviation_bps` from canonical multi-provider `Pyth` NEAR relay envelopes and/or
//!    Merkle-committed `TradeLayer` VWAP window proofs. Slashes NEAR bond, rewards challenger,
//!    and computes exact satoshi restitution for defrauded DLC counterparties!

use borsh::{BorshDeserialize, BorshSerialize};
use k256::{ProjectivePoint, Scalar, elliptic_curve::point::AffineCoordinates};
use serde::{Deserialize, Serialize};
use shz_dlc::{
    Bip340Signature, OracleAnnouncement, OracleAttestation, bip340_challenge, bip340_verify,
    oracle_digit_message, scalar_from_bytes,
};
use shz_margin::InverseContractSpec;

use crate::{
    OracleError,
    pyth_near_relay::{NearRelayEnvelope, RelayProviderKind, RelayQuorumPolicy},
    tradelayer::TradeLayerVwapProof,
};

/// Canonical external truth submitted to prove FROST confederation price manipulation.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum CanonicalReferenceEvidence {
    /// Multi-provider Pyth + secondary oracle Borsh relay envelope.
    NearPythRelay(NearRelayEnvelope),
    /// Block-anchored TradeLayer L1 DEX VWAP proof.
    TradeLayerWindow(TradeLayerVwapProof),
    /// Dual-consensus proof where both Pyth relay and TradeLayer VWAP confirm the honest price.
    DualConsensus {
        relay: NearRelayEnvelope,
        tradelayer: TradeLayerVwapProof,
    },
}

/// Optional claim submitted alongside a `DeviationFraudProof` to compensate a trader
/// harmed by the dishonest FROST attestation.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct VictimRestitutionClaim {
    pub victim_near_account: String,
    pub victim_is_long: bool,
    pub contract_spec: InverseContractSpec,
}

/// Fraud Proof Type 1: Double-signing two distinct bits (`0` and `1`) on the same digit nonce `R_j`.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct EquivocationFraudProof {
    pub announcement: OracleAnnouncement,
    pub digit_idx: u8,
    pub sig_bit_zero: Bip340Signature,
    pub sig_bit_one: Bip340Signature,
    pub challenger_near_account: String,
}

/// Fraud Proof Type 2: Collusive FROST price diverging from canonical Pyth Relay / TradeLayer VWAP.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct DeviationFraudProof {
    pub announcement: OracleAnnouncement,
    pub dishonest_attestation: OracleAttestation,
    pub reference_evidence: CanonicalReferenceEvidence,
    pub challenger_near_account: String,
    pub victim_claim: Option<VictimRestitutionClaim>,
}

/// Deterministic slash & restitution receipt emitted by the NEAR-compatible verifier.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SlashVerdict {
    pub event_id: String,
    pub slashed_yocto_near: u128,
    pub challenger_reward_yocto_near: u128,
    pub victim_restitution_yocto_near: u128,
    pub treasury_burn_yocto_near: u128,
    /// Present on `EquivocationFraudProof`: exact extracted secp256k1 secret key scalar `d`
    /// allowing permissionless L1 sweep of the confederation's Bitcoin slash-bond UTXO!
    pub extracted_btc_slash_secret_key: Option<[u8; 32]>,
    pub victim_shortfall_sats: u64,
    pub attested_price_usd: u64,
    pub canonical_price_usd: u64,
    pub deviation_bps: u64,
}

/// Borsh-serializable state of the NEAR Bonded Oracle Vault.
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct NearBondedOracleVault {
    pub confed_pubkey_x: [u8; 32],
    pub bonded_yocto_near: u128,
    pub btc_slash_bond_sats: u64,
    /// Maximum tolerated deviation (in bps) before slashing triggers (e.g. `150` = 1.50%).
    pub max_deviation_bps: u64,
    /// Maximum timestamp drift (seconds) between DLC maturity and reference evidence.
    pub max_reference_drift_secs: u64,
    /// Conversion rate (`yoctoNEAR` per satoshi) for compensating defrauded DLC traders on NEAR.
    pub yocto_near_per_sat: u128,
    /// `DLCAdaptor` quorum leverage factor `L` (`TVL_max <= L * stake_in_sats`).
    pub tvl_leverage_cap_x: u64,
    /// Active open DLC collateral (sats) covered by this confederation.
    pub active_tvl_sats: u64,
    /// Registered DLC IDs to block `DOUBLE_USE_DLC` across epochs (`DLCAdaptor` v2 rule).
    pub registered_dlc_ids: Vec<String>,
    pub is_slashed: bool,
}

impl NearBondedOracleVault {
    pub fn new(
        confed_pubkey_x: [u8; 32],
        bonded_yocto_near: u128,
        btc_slash_bond_sats: u64,
        max_deviation_bps: u64,
        max_reference_drift_secs: u64,
        yocto_near_per_sat: u128,
    ) -> Self {
        Self {
            confed_pubkey_x,
            bonded_yocto_near,
            btc_slash_bond_sats,
            max_deviation_bps,
            max_reference_drift_secs,
            yocto_near_per_sat,
            tvl_leverage_cap_x: 10,
            active_tvl_sats: 0,
            registered_dlc_ids: Vec::new(),
            is_slashed: false,
        }
    }

    /// Registers a DLC against the confederation's NEAR TVL cap (`TVL <= L * Stake`)
    /// and rejects `DOUBLE_USE_DLC` across epochs (`UTXO-Ref/DLCAdaptor/oracle-contract.ts`).
    pub fn register_dlc_coverage(
        &mut self,
        dlc_id: &str,
        collateral_sats: u64,
    ) -> Result<(), OracleError> {
        if self.is_slashed {
            return Err(OracleError::VaultAlreadySlashed);
        }
        if self.registered_dlc_ids.iter().any(|id| id == dlc_id) {
            return Err(OracleError::FraudProofRejected("DOUBLE_USE_DLC: dlc_id already registered"));
        }
        let near_equiv_sats = self
            .bonded_yocto_near
            .checked_div(self.yocto_near_per_sat)
            .unwrap_or(0) as u64;
        let total_stake_sats = near_equiv_sats.saturating_add(self.btc_slash_bond_sats);
        let max_tvl = total_stake_sats.saturating_mul(self.tvl_leverage_cap_x);
        let next_tvl = self.active_tvl_sats.saturating_add(collateral_sats);
        if next_tvl > max_tvl {
            return Err(OracleError::FraudProofRejected(
                "TVL_CAP_EXCEEDED: open DLC collateral exceeds L * Stake",
            ));
        }
        self.active_tvl_sats = next_tvl;
        self.registered_dlc_ids.push(dlc_id.to_string());
        Ok(())
    }

    /// Verifies a Borsh-serializable `EquivocationFraudProof`, algebraically extracts the
    /// FROST confederation's private key `d = (s_0 - s_1) * (e_0 - e_1)^(-1) mod n`,
    /// verifies `d * G == X_confed`, and slashes 100% of the bonded vault!
    pub fn submit_equivocation_fraud_proof(
        &mut self,
        proof: &EquivocationFraudProof,
    ) -> Result<SlashVerdict, OracleError> {
        if self.is_slashed {
            return Err(OracleError::VaultAlreadySlashed);
        }
        if proof.announcement.oracle_pubkey_x != self.confed_pubkey_x {
            return Err(OracleError::FraudProofRejected(
                "announcement pubkey does not match bonded confederation",
            ));
        }
        let j = proof.digit_idx as usize;
        if j >= proof.announcement.digit_nonces_x.len() {
            return Err(OracleError::FraudProofRejected("digit_idx out of range"));
        }
        let committed_rx = proof.announcement.digit_nonces_x[j];
        if proof.sig_bit_zero.r_x != committed_rx || proof.sig_bit_one.r_x != committed_rx {
            return Err(OracleError::FraudProofRejected(
                "signatures do not reuse pre-committed announcement nonce",
            ));
        }

        let msg_0 = oracle_digit_message(&proof.announcement.event_id, proof.digit_idx, 0);
        let msg_1 = oracle_digit_message(&proof.announcement.event_id, proof.digit_idx, 1);
        bip340_verify(&self.confed_pubkey_x, &msg_0, &proof.sig_bit_zero)?;
        bip340_verify(&self.confed_pubkey_x, &msg_1, &proof.sig_bit_one)?;

        let s0 = scalar_from_bytes(&proof.sig_bit_zero.s)?;
        let s1 = scalar_from_bytes(&proof.sig_bit_one.s)?;
        let e0 = bip340_challenge(&committed_rx, &self.confed_pubkey_x, &msg_0);
        let e1 = bip340_challenge(&committed_rx, &self.confed_pubkey_x, &msg_1);

        let delta_e_inv_opt = (e0 - e1).invert();
        if bool::from(delta_e_inv_opt.is_none()) {
            return Err(OracleError::FraudProofRejected("degenerate challenge delta"));
        }
        let extracted_d: Scalar = (s0 - s1) * delta_e_inv_opt.unwrap();
        let derived_pub = (ProjectivePoint::GENERATOR * extracted_d).to_affine();
        let derived_x: [u8; 32] = derived_pub.x().into();
        if derived_x != self.confed_pubkey_x {
            return Err(OracleError::FraudProofRejected(
                "extracted scalar does not match confederation pubkey",
            ));
        }

        let slashed = self.bonded_yocto_near;
        let challenger_reward = slashed / 2; // 50% bounty for key-extraction equivocation catch
        let treasury_burn = slashed - challenger_reward;
        self.bonded_yocto_near = 0;
        self.is_slashed = true;

        Ok(SlashVerdict {
            event_id: proof.announcement.event_id.clone(),
            slashed_yocto_near: slashed,
            challenger_reward_yocto_near: challenger_reward,
            victim_restitution_yocto_near: 0,
            treasury_burn_yocto_near: treasury_burn,
            extracted_btc_slash_secret_key: Some(extracted_d.to_bytes().into()),
            victim_shortfall_sats: 0,
            attested_price_usd: 0,
            canonical_price_usd: 0,
            deviation_bps: 10_000,
        })
    }

    /// Verifies a Borsh-serializable `DeviationFraudProof` where the FROST confederation
    /// signed an off-market price `P_frost` contradicted by `Pyth` NEAR relay quorum and/or
    /// `TradeLayer` L1 VWAP proofs.
    pub fn submit_deviation_fraud_proof(
        &mut self,
        proof: &DeviationFraudProof,
        trusted_relay_guardians: &[(RelayProviderKind, [u8; 32])],
        relay_policy: &RelayQuorumPolicy,
        trusted_tl_witnesses: &[[u8; 32]],
        min_tl_witnesses: usize,
    ) -> Result<SlashVerdict, OracleError> {
        if self.is_slashed {
            return Err(OracleError::VaultAlreadySlashed);
        }
        if proof.announcement.oracle_pubkey_x != self.confed_pubkey_x {
            return Err(OracleError::FraudProofRejected(
                "announcement pubkey does not match bonded confederation",
            ));
        }

        // 1. Verify the dishonest FROST attestation actually came from the confederation!
        proof
            .dishonest_attestation
            .verify_against(&proof.announcement)?;

        // 2. Cryptographically verify canonical reference price & timestamp alignment.
        let (canonical_price_usd, extra_conf_bps) = match &proof.reference_evidence {
            CanonicalReferenceEvidence::NearPythRelay(env) => {
                if env
                    .reference_timestamp_unix
                    .abs_diff(proof.announcement.maturity_unix)
                    > self.max_reference_drift_secs
                {
                    return Err(OracleError::StaleObservation);
                }
                env.verify(trusted_relay_guardians, relay_policy)?
            }
            CanonicalReferenceEvidence::TradeLayerWindow(tl) => {
                if tl
                    .window_close_unix
                    .abs_diff(proof.announcement.maturity_unix)
                    > self.max_reference_drift_secs
                {
                    return Err(OracleError::StaleObservation);
                }
                tl.verify_witness_quorum(trusted_tl_witnesses, min_tl_witnesses)?;
                (tl.vwap_price_usd, 0)
            }
            CanonicalReferenceEvidence::DualConsensus { relay, tradelayer } => {
                if relay
                    .reference_timestamp_unix
                    .abs_diff(proof.announcement.maturity_unix)
                    > self.max_reference_drift_secs
                    || tradelayer
                        .window_close_unix
                        .abs_diff(proof.announcement.maturity_unix)
                        > self.max_reference_drift_secs
                {
                    return Err(OracleError::StaleObservation);
                }
                let (relay_p, relay_conf) =
                    relay.verify(trusted_relay_guardians, relay_policy)?;
                tradelayer.verify_witness_quorum(trusted_tl_witnesses, min_tl_witnesses)?;
                let avg = ((relay_p as u128 + tradelayer.vwap_price_usd as u128) / 2) as u64;
                (avg, relay_conf)
            }
        };

        if canonical_price_usd == 0 {
            return Err(OracleError::FraudProofRejected("zero canonical price"));
        }

        let attested_price_usd = proof.dishonest_attestation.price_usd;
        let diff = attested_price_usd.abs_diff(canonical_price_usd) as u128;
        let deviation_bps = ((diff * 10_000) / (canonical_price_usd as u128)) as u64;
        let threshold_bps = self.max_deviation_bps + extra_conf_bps;

        if deviation_bps <= threshold_bps {
            return Err(OracleError::FraudProofRejected(
                "attested price is within tolerated deviation + confidence band",
            ));
        }

        // 3. Compute exact DLC trader shortfall if a victim restitution claim is attached.
        let victim_shortfall_sats = if let Some(claim) = &proof.victim_claim {
            claim
                .contract_spec
                .validate_v0()
                .map_err(|_| OracleError::FraudProofRejected("invalid victim contract spec"))?;
            let honest_split = claim.contract_spec.payout_at_price(canonical_price_usd);
            let cheated_split = claim.contract_spec.payout_at_price(attested_price_usd);
            if claim.victim_is_long {
                honest_split.long_sats.saturating_sub(cheated_split.long_sats)
            } else {
                honest_split
                    .short_sats
                    .saturating_sub(cheated_split.short_sats)
            }
        } else {
            0
        };

        let slashed = self.bonded_yocto_near;
        let challenger_reward = slashed / 5; // 20% challenger bounty
        let remaining_after_bounty = slashed - challenger_reward;
        let requested_restitution = (victim_shortfall_sats as u128) * self.yocto_near_per_sat;
        let victim_restitution = requested_restitution.min(remaining_after_bounty);
        let treasury_burn = remaining_after_bounty - victim_restitution;

        self.bonded_yocto_near = 0;
        self.is_slashed = true;

        Ok(SlashVerdict {
            event_id: proof.announcement.event_id.clone(),
            slashed_yocto_near: slashed,
            challenger_reward_yocto_near: challenger_reward,
            victim_restitution_yocto_near: victim_restitution,
            treasury_burn_yocto_near: treasury_burn,
            extracted_btc_slash_secret_key: None,
            victim_shortfall_sats,
            attested_price_usd,
            canonical_price_usd,
            deviation_bps,
        })
    }
}
