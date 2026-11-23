//! Safe FROST / DLC Settlement Epoch Consumer (`Gate E`).
//!
//! Consumes an accepted, Nova-verified, and Bitcoin-anchored 8-hour SHZ checkpoint together
//! with a `VALID` hourly opening (`status == 1`, rejecting `HOLD` unconditionally) and drives
//! `shz_oracle::frost::FrostConfederation` (`t-of-n` threshold BIP-340 digit attestation) while:
//! 1. Keeping individual bilateral DLC contract terms (`collateral_sats`, `strike_usd`,
//!    `payout_curve`, `counterparty_pubkeys`, `adaptor_points`) 100% private and off-chain.
//! 2. Enforcing domain separation between the public Bitcoin `SHZIDX01` anchor commitment and
//!    the oracle's threshold Schnorr attestation / BIP-341 adaptor settlement signatures.
//! 3. Retaining `can_authorize_dlc_settlement: false` and `production_ready: false`.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dlc::OracleAttestation;
use shz_oracle::frost::FrostConfederation;

use crate::{
    btc_anchor::VerifiedBitcoinAnchorReceipt,
    circuit::{ClaimV1, HourStepData, RecordJson},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostDlcFeedEligibilityReceipt {
    pub event_id: String,
    pub start_hour: u64,
    pub selected_hour_id: u64,
    pub maturity_unix: u64,
    pub checkpoint_root_hex: String,
    pub bitcoin_anchor_txid_hex: String,
    pub bitcoin_anchor_block_hash_hex: String,
    pub bitcoin_confirmations: u64,
    pub index_price_e8: u64,
    pub attested_price_usd: u64,
    pub frost_threshold_t: usize,
    pub frost_total_n: usize,
    pub frost_group_pubkey_x_hex: String,
    pub frost_num_bits: u8,
    pub frost_attestation_sha256_hex: String,
    pub private_dlc_terms_exposed_onchain: bool,
    pub near_nova_verified: bool,
    pub bitcoin_anchor_finality_verified: bool,
    pub can_authorize_dlc_settlement: bool,
    pub production_ready: bool,
}

pub fn derive_frost_checkpoint_event_id(hour_id: u64, checkpoint_root_hex: &str) -> String {
    format!("SHZ-INDEX03-BTCUSD-H{hour_id}-{}", &checkpoint_root_hex[..16])
}

/// Validates that an 8-hour checkpoint has BOTH verified Nova proof acceptance and verified
/// canonical Bitcoin `SHZIDX01` anchor finality, verifies the selected `VALID` hourly opening
/// (`HOLD` is unconditionally rejected!), and produces a verifiable `t-of-n` FROST BIP-340
/// price attestation without touching or exposing private DLC contract terms.
#[allow(clippy::too_many_arguments)]
pub fn attest_frost_from_verified_checkpoint(
    claim: &ClaimV1,
    nova_verified: bool,
    btc_anchor: &VerifiedBitcoinAnchorReceipt,
    min_required_confirmations: u64,
    selected_record: &RecordJson,
    selected_position: u8,
    merkle_siblings: &[String],
    frost: &FrostConfederation,
    participating_signer_ids: &[u16],
    num_bits: u8,
    nonce_epoch_seed: &[u8; 32],
) -> Result<(OracleAttestation, FrostDlcFeedEligibilityReceipt), String> {
    if !nova_verified {
        return Err("refusing FROST feed: checkpoint lacks cryptographic Nova verification".into());
    }
    if !btc_anchor.canonical_mainchain_verified
        || btc_anchor.confirmations < min_required_confirmations
    {
        return Err("refusing FROST feed: Bitcoin anchor lacks canonical-chain finality".into());
    }
    if btc_anchor.checkpoint_root_hex != claim.checkpoint_root {
        return Err("refusing FROST feed: Bitcoin anchor root differs from Nova checkpoint root".into());
    }
    if selected_position >= 8 {
        return Err("selected hour position out of 0..=7 range".into());
    }
    if selected_record.status != 1 || selected_record.hold_reason != 0 {
        return Err("HOLD or malformed hourly record can NEVER feed FROST/DLC attestation".into());
    }

    let start_hour = claim
        .start_hour
        .parse::<u64>()
        .map_err(|_| "invalid start_hour")?;
    let step = HourStepData::from_record(
        selected_record,
        start_hour,
        selected_position,
        merkle_siblings,
    )?;
    if step.hour != start_hour + u64::from(selected_position) {
        return Err("selected hour_id does not match start_hour + position".into());
    }
    if selected_record.genesis != claim.genesis || selected_record.policy_hash != claim.policy_hash {
        return Err("selected hour genesis/policy mismatch".into());
    }

    // Re-verify arithmetic policy & Merkle root binding natively as defense-in-depth
    if step.p == 0
        || step.c == 0
        || step.index == 0
        || (u128::from(step.p) + u128::from(step.c)) / 2 != u128::from(step.index)
        || u128::from(step.p.abs_diff(step.c)) * 20_000
            > 50 * (u128::from(step.p) + u128::from(step.c))
    {
        return Err("selected hourly record failed midpoint/spread invariant".into());
    }
    let recomputed_root = hex::encode(step.native_root());
    if recomputed_root != claim.checkpoint_root {
        return Err("selected hourly opening does not match verified checkpoint_root".into());
    }

    let maturity_unix = (step.hour + 1) * 3_600;
    let attested_price_usd = step.index / 100_000_000;
    if attested_price_usd == 0 || attested_price_usd >= (1u64 << num_bits) {
        return Err("attested USD price exceeds FROST digit bit-width".into());
    }

    let event_id = derive_frost_checkpoint_event_id(step.hour, &claim.checkpoint_root);
    let nonce_state = frost
        .announce_event(&event_id, maturity_unix, num_bits, nonce_epoch_seed)
        .map_err(|e| format!("FROST announce failed: {e}"))?;
    let attestation = frost
        .threshold_attest_price(
            &nonce_state,
            participating_signer_ids,
            maturity_unix,
            attested_price_usd,
        )
        .map_err(|e| format!("FROST threshold sign failed: {e}"))?;
    attestation
        .verify_against(&nonce_state.announcement)
        .map_err(|e| format!("FROST verification failed: {e}"))?;

    let mut att_hasher = Sha256::new();
    att_hasher.update(event_id.as_bytes());
    att_hasher.update(attested_price_usd.to_le_bytes());
    for sig in &attestation.digit_signatures {
        att_hasher.update(sig.r_x);
        att_hasher.update(sig.s);
    }
    let att_sha_hex = hex::encode(att_hasher.finalize());

    let receipt = FrostDlcFeedEligibilityReceipt {
        event_id,
        start_hour,
        selected_hour_id: step.hour,
        maturity_unix,
        checkpoint_root_hex: claim.checkpoint_root.clone(),
        bitcoin_anchor_txid_hex: btc_anchor.txid_hex.clone(),
        bitcoin_anchor_block_hash_hex: btc_anchor.block_hash_hex.clone(),
        bitcoin_confirmations: btc_anchor.confirmations,
        index_price_e8: step.index,
        attested_price_usd,
        frost_threshold_t: frost.threshold_t,
        frost_total_n: frost.total_n,
        frost_group_pubkey_x_hex: hex::encode(frost.group_pubkey_x),
        frost_num_bits: num_bits,
        frost_attestation_sha256_hex: att_sha_hex,
        private_dlc_terms_exposed_onchain: false,
        near_nova_verified: nova_verified,
        bitcoin_anchor_finality_verified: true,
        can_authorize_dlc_settlement: false,
        production_ready: false,
    };

    Ok((attestation, receipt))
}
