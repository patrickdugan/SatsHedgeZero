//! Secq BIP-340 3-field signature claim binder (`[1, low128_le, high128_le]`) with
//! strict `Row` party/oracle slot authorization checks.
//!
//! Specification reference: `LNMarkets/nova/SOUNDNESS.md` ("Separate BIP340 experiment").
//! The Secq circuit proves one BIP-340 signature and commits to `SHA256(pubkey_x || msg32 || sig64)`
//! as a 3-field public state `[1, low128_le, high128_le]`. Because the claimant supplies the public
//! key in isolation, this module binds the claim to an exact authorized `RowSignatureSlot`
//! (trader/maker summary signature, trader/maker batch consent signature, or pinned oracle
//! attestation signature).

use serde::{Deserialize, Serialize};

use crate::error::{NovaBitvmError, Result, VerificationHonestyFlags};
use crate::nova::sha256_to_le_u128_halves;
use crate::statement::{
    BatchContext, Hash, Row, Sig, batch_consent_message, oracle_message, sha256, summary_digest,
    verify_bip340,
};

/// Exact authorized signer slot within a verified `Row`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RowSignatureSlot {
    SummaryTrader,
    SummaryMaker,
    BatchConsentTrader,
    BatchConsentMaker,
    /// `0` or `1` indexing `row.oracle_attestations[slot_idx]`.
    OracleAttestation(usize),
}

impl RowSignatureSlot {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SummaryTrader => "summary.trader",
            Self::SummaryMaker => "summary.maker",
            Self::BatchConsentTrader => "batch_consent.trader",
            Self::BatchConsentMaker => "batch_consent.maker",
            Self::OracleAttestation(0) => "oracle_attestation[0]",
            Self::OracleAttestation(1) => "oracle_attestation[1]",
            Self::OracleAttestation(_) => "oracle_attestation[invalid]",
        }
    }
}

/// Computes the 128-byte preimage SHA-256 digest `SHA256(pubkey_x || msg32 || sig64)`
/// and its little-endian 128-bit field halves `(low128_le, high128_le)`.
pub fn secq_claim_digest_and_halves(
    pubkey_x: &Hash,
    message: &Hash,
    signature: &Sig,
) -> (Hash, u128, u128) {
    let mut preimage = [0u8; 128];
    preimage[0..32].copy_from_slice(pubkey_x);
    preimage[32..64].copy_from_slice(message);
    preimage[64..128].copy_from_slice(signature);
    let digest = sha256(&preimage);
    let (low, high) = sha256_to_le_u128_halves(&digest);
    (digest, low, high)
}

/// Extracts the exact `(authorized_pubkey_x, expected_msg32, expected_sig64)` for a `RowSignatureSlot`.
pub fn expected_row_slot_material(
    context: &BatchContext,
    row: &Row,
    slot: RowSignatureSlot,
) -> Result<(Hash, Hash, Sig)> {
    match slot {
        RowSignatureSlot::SummaryTrader => Ok((
            row.summary.trader_key,
            summary_digest(&row.summary),
            row.summary_signatures[0],
        )),
        RowSignatureSlot::SummaryMaker => Ok((
            row.summary.maker_key,
            summary_digest(&row.summary),
            row.summary_signatures[1],
        )),
        RowSignatureSlot::BatchConsentTrader => Ok((
            row.summary.trader_key,
            batch_consent_message(context, &row.summary),
            row.batch_signatures[0],
        )),
        RowSignatureSlot::BatchConsentMaker => Ok((
            row.summary.maker_key,
            batch_consent_message(context, &row.summary),
            row.batch_signatures[1],
        )),
        RowSignatureSlot::OracleAttestation(idx) => {
            if idx >= 2 {
                return Err(NovaBitvmError::SecqClaim(
                    "oracle attestation slot index must be 0 or 1".to_owned(),
                ));
            }
            let att = &row.oracle_attestations[idx];
            if att.oracle_index >= 3 {
                return Err(NovaBitvmError::SecqClaim(
                    "oracle_index must be in 0..3".to_owned(),
                ));
            }
            let pubkey_x = row.summary.oracle_keys[att.oracle_index as usize];
            let msg = oracle_message(&row.summary, &row.outcome);
            Ok((pubkey_x, msg, att.signature))
        }
    }
}

/// Secq BIP-340 3-field public claim (`[1, low128_le, high128_le]`) bound to a `RowSignatureSlot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecqBip340Claim {
    pub step_count: u64,
    pub pubkey_x_hex: String,
    pub message_hex: String,
    pub signature_hex: String,
    pub claim_digest_hex: String,
    pub claim_low128_le: String,
    pub claim_high128_le: String,
    /// Exact 3-field Secq final state: `["1", claim_low128_le, claim_high128_le]`.
    pub state_3_fields: [String; 3],
    pub bound_slot: Option<String>,
    pub honesty: VerificationHonestyFlags,
}

impl SecqBip340Claim {
    /// Builds and natively verifies a standalone Secq BIP-340 3-field claim.
    pub fn from_raw(pubkey_x: &Hash, message: &Hash, signature: &Sig) -> Result<Self> {
        verify_bip340(pubkey_x, message, signature)?;
        let (digest, low, high) = secq_claim_digest_and_halves(pubkey_x, message, signature);
        let low_s = low.to_string();
        let high_s = high.to_string();
        Ok(Self {
            step_count: 1,
            pubkey_x_hex: hex::encode(pubkey_x),
            message_hex: hex::encode(message),
            signature_hex: hex::encode(signature),
            claim_digest_hex: hex::encode(digest),
            state_3_fields: ["1".to_owned(), low_s.clone(), high_s.clone()],
            claim_low128_le: low_s,
            claim_high128_le: high_s,
            bound_slot: None,
            honesty: VerificationHonestyFlags::native_only(),
        })
    }

    /// Builds and verifies a Secq BIP-340 claim bound to an exact `RowSignatureSlot`.
    pub fn from_row_slot(
        context: &BatchContext,
        row: &Row,
        slot: RowSignatureSlot,
    ) -> Result<Self> {
        let (pubkey_x, message, signature) = expected_row_slot_material(context, row, slot)?;
        let mut claim = Self::from_raw(&pubkey_x, &message, &signature)?;
        claim.bound_slot = Some(slot.label().to_owned());
        Ok(claim)
    }

    fn decode_materials(&self) -> Result<(Hash, Hash, Sig)> {
        let pk: Hash = hex::decode(&self.pubkey_x_hex)
            .map_err(|_| NovaBitvmError::SecqClaim("invalid pubkey_x_hex".to_owned()))?
            .try_into()
            .map_err(|_| NovaBitvmError::SecqClaim("pubkey_x must be 32 bytes".to_owned()))?;
        let msg: Hash = hex::decode(&self.message_hex)
            .map_err(|_| NovaBitvmError::SecqClaim("invalid message_hex".to_owned()))?
            .try_into()
            .map_err(|_| NovaBitvmError::SecqClaim("message must be 32 bytes".to_owned()))?;
        let sig: Sig = hex::decode(&self.signature_hex)
            .map_err(|_| NovaBitvmError::SecqClaim("invalid signature_hex".to_owned()))?
            .try_into()
            .map_err(|_| NovaBitvmError::SecqClaim("signature must be 64 bytes".to_owned()))?;
        Ok((pk, msg, sig))
    }

    /// Verifies standalone cryptographic and 3-field state integrity of this Secq claim.
    pub fn verify_standalone(&self) -> Result<()> {
        if self.step_count != 1 {
            return Err(NovaBitvmError::SecqClaim(
                "Secq BIP-340 claim step_count must be exactly 1".to_owned(),
            ));
        }
        let (pk, msg, sig) = self.decode_materials()?;
        verify_bip340(&pk, &msg, &sig)?;
        let (digest, low, high) = secq_claim_digest_and_halves(&pk, &msg, &sig);
        let low_s = low.to_string();
        let high_s = high.to_string();
        if self.claim_digest_hex != hex::encode(digest)
            || self.claim_low128_le != low_s
            || self.claim_high128_le != high_s
            || self.state_3_fields != ["1".to_owned(), low_s, high_s]
        {
            return Err(NovaBitvmError::SecqClaim(
                "Secq 3-field claim digest or state limbs mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verifies both the standalone Secq BIP-340 claim AND that its `(pubkey_x, message, signature)`
    /// matches the exact authorized trader/maker/oracle slot of `row` under `context`.
    pub fn verify_against_row_slot(
        &self,
        context: &BatchContext,
        row: &Row,
        slot: RowSignatureSlot,
    ) -> Result<()> {
        self.verify_standalone()?;
        let (pk, msg, sig) = self.decode_materials()?;
        let (expected_pk, expected_msg, expected_sig) =
            expected_row_slot_material(context, row, slot)?;
        if pk != expected_pk {
            return Err(NovaBitvmError::SecqClaim(format!(
                "claim pubkey_x is not authorized for slot {}",
                slot.label()
            )));
        }
        if msg != expected_msg {
            return Err(NovaBitvmError::SecqClaim(format!(
                "claim message does not match derived digest for slot {}",
                slot.label()
            )));
        }
        if sig != expected_sig {
            return Err(NovaBitvmError::SecqClaim(format!(
                "claim signature does not match committed signature for slot {}",
                slot.label()
            )));
        }
        Ok(())
    }
}

/// Builds and verifies all 6 authorized Secq BIP-340 claims for a single `Row`
/// (2 summary sigs, 2 batch-consent sigs, 2 pinned oracle attestations).
pub fn build_and_verify_all_6_row_claims(
    context: &BatchContext,
    row: &Row,
) -> Result<[SecqBip340Claim; 6]> {
    let slots = [
        RowSignatureSlot::SummaryTrader,
        RowSignatureSlot::SummaryMaker,
        RowSignatureSlot::BatchConsentTrader,
        RowSignatureSlot::BatchConsentMaker,
        RowSignatureSlot::OracleAttestation(0),
        RowSignatureSlot::OracleAttestation(1),
    ];
    let mut claims = Vec::with_capacity(6);
    for slot in slots {
        let claim = SecqBip340Claim::from_row_slot(context, row, slot)?;
        claim.verify_against_row_slot(context, row, slot)?;
        claims.push(claim);
    }
    claims
        .try_into()
        .map_err(|_| NovaBitvmError::SecqClaim("expected exactly 6 claims".to_owned()))
}
