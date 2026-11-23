//! Clean-room MIT encoder and verifier for the Nova v2 signed-row transcript
//! (`lnmarkets/sha256-transcript-accounting/v2`) and 8-field `expected.json` expectation builder.
//!
//! Specification reference: `LNMarkets/nova/SOUNDNESS.md` (`patrickdugan/zk-rusto-no-bitcoino` @ `f6a8d12`).
//! Contains zero GPL-3.0 R1CS/M18 code; produces byte-exact inputs and expectation pins for
//! out-of-process `lnm-nova prepare` / `lnm-nova verify`.

use serde::{Deserialize, Serialize};

use crate::codec::{decode_journal, encode_journal};
use crate::error::{NovaBitvmError, Result, VerificationHonestyFlags};
use crate::statement::{
    BatchContext, BatchWitness, Hash, JOURNAL_LEN, Journal, MAX_ROWS, Row, batch_consent_message,
    sha256, summary_digest, tagged_hash, verify_batch,
};

pub const NOVA_RELATION_VERSION: &str = "lnmarkets/sha256-transcript-accounting/v2";
pub const NOVA_TRANSCRIPT_PREFIX: &[u8; 46] = b"UTXORef/LNMarkets/Nova/validated-signed-row/v1";
pub const NOVA_TRANSCRIPT_LEN: usize = 600;

/// Nova v2 per-row amount width bound: strictly `< 2^51`.
pub const NOVA_ROW_AMOUNT_BITS: u32 = 51;
pub const NOVA_ROW_AMOUNT_LIMIT: u64 = 1u64 << NOVA_ROW_AMOUNT_BITS;

/// Nova v2 cumulative accounting width bound: strictly `< 2^56`.
pub const NOVA_CUMULATIVE_AMOUNT_BITS: u32 = 56;
pub const NOVA_CUMULATIVE_AMOUNT_LIMIT: u64 = 1u64 << NOVA_CUMULATIVE_AMOUNT_BITS;

/// Nova v2 5-bit input step counter bound (`0..32`, permitting `1..=32` total rows).
pub const NOVA_MAX_STEPS: u64 = MAX_ROWS as u64;

/// Splits a 32-byte SHA-256 digest into two little-endian 128-bit field values as specified
/// by `lnmarkets/sha256-transcript-accounting/v2`.
pub fn sha256_to_le_u128_halves(digest: &Hash) -> (u128, u128) {
    let low = u128::from_le_bytes(digest[0..16].try_into().expect("16-byte low half"));
    let high = u128::from_le_bytes(digest[16..32].try_into().expect("16-byte high half"));
    (low, high)
}

/// Checks that a single row amount satisfies the 51-bit Nova circuit bound (`< 2^51`).
pub fn check_row_amount_51bit(value: u64, label: &str) -> Result<()> {
    if value >= NOVA_ROW_AMOUNT_LIMIT {
        return Err(NovaBitvmError::Nova(format!(
            "{label} ({value}) violates Nova v2 51-bit row bound (< {})",
            NOVA_ROW_AMOUNT_LIMIT
        )));
    }
    Ok(())
}

/// Checks that a cumulative accounting total satisfies the 56-bit Nova circuit bound (`< 2^56`).
pub fn check_cumulative_amount_56bit(value: u64, label: &str) -> Result<()> {
    if value >= NOVA_CUMULATIVE_AMOUNT_LIMIT {
        return Err(NovaBitvmError::Nova(format!(
            "{label} ({value}) violates Nova v2 56-bit cumulative bound (< {})",
            NOVA_CUMULATIVE_AMOUNT_LIMIT
        )));
    }
    Ok(())
}

/// Encodes the exact 600-byte Nova v2 signed-row transcript (`0..600`) for one batch row,
/// enforcing 51-bit per-row amount bounds and exact payout/collateral conservation.
///
/// Exact byte layout (all numeric fields little-endian):
/// - `0..46`:   `"UTXORef/LNMarkets/Nova/validated-signed-row/v1"` (`46B`)
/// - `46..78`:  `summary_digest` (`32B`)
/// - `78..110`: `batch_consent_digest` (`32B`)
/// - `110..238`: `summary_signatures[0] || summary_signatures[1]` (`128B`)
/// - `238..366`: `batch_signatures[0] || batch_signatures[1]` (`128B`)
/// - `366..431`: `oracle_attestations[0].oracle_index (u8) || signature (64B)` (`65B`)
/// - `431..496`: `oracle_attestations[1].oracle_index (u8) || signature (64B)` (`65B`)
/// - `496..500`: `outcome.index` (`u32le`, `4B`)
/// - `500..532`: `outcome.message` (`32B`)
/// - `532..564`: `trader_sats, maker_sats, anchor_sats, fee_sats` (`4 x u64le = 32B`)
/// - `564..596`: `funding_txid` in display order (`32B`)
/// - `596..600`: `funding_vout` (`u32le`, `4B`)
pub fn encode_signed_row_transcript(
    context: &BatchContext,
    row: &Row,
) -> Result<[u8; NOVA_TRANSCRIPT_LEN]> {
    let o = &row.outcome;
    check_row_amount_51bit(o.trader_sats, "trader_sats")?;
    check_row_amount_51bit(o.maker_sats, "maker_sats")?;
    check_row_amount_51bit(o.anchor_sats, "anchor_sats")?;
    check_row_amount_51bit(o.fee_sats, "fee_sats")?;

    let payout = o
        .trader_sats
        .checked_add(o.maker_sats)
        .and_then(|v| v.checked_add(o.anchor_sats))
        .ok_or_else(|| NovaBitvmError::Nova("row payout overflow".to_owned()))?;
    check_row_amount_51bit(payout, "row_payout_sats")?;

    let collateral = payout
        .checked_add(o.fee_sats)
        .ok_or_else(|| NovaBitvmError::Nova("row collateral overflow".to_owned()))?;
    check_row_amount_51bit(collateral, "row_collateral_sats")?;

    if collateral != row.summary.collateral_sats {
        return Err(NovaBitvmError::Nova(
            "row payout + fee does not equal summary.collateral_sats".to_owned(),
        ));
    }

    let s_digest = summary_digest(&row.summary);
    let c_digest = batch_consent_message(context, &row.summary);

    let mut buf = [0u8; NOVA_TRANSCRIPT_LEN];
    buf[0..46].copy_from_slice(NOVA_TRANSCRIPT_PREFIX);
    buf[46..78].copy_from_slice(&s_digest);
    buf[78..110].copy_from_slice(&c_digest);
    buf[110..174].copy_from_slice(&row.summary_signatures[0]);
    buf[174..238].copy_from_slice(&row.summary_signatures[1]);
    buf[238..302].copy_from_slice(&row.batch_signatures[0]);
    buf[302..366].copy_from_slice(&row.batch_signatures[1]);
    buf[366] = row.oracle_attestations[0].oracle_index;
    buf[367..431].copy_from_slice(&row.oracle_attestations[0].signature);
    buf[431] = row.oracle_attestations[1].oracle_index;
    buf[432..496].copy_from_slice(&row.oracle_attestations[1].signature);
    buf[496..500].copy_from_slice(&o.index.to_le_bytes());
    buf[500..532].copy_from_slice(&o.message);
    buf[532..540].copy_from_slice(&o.trader_sats.to_le_bytes());
    buf[540..548].copy_from_slice(&o.maker_sats.to_le_bytes());
    buf[548..556].copy_from_slice(&o.anchor_sats.to_le_bytes());
    buf[556..564].copy_from_slice(&o.fee_sats.to_le_bytes());
    buf[564..596].copy_from_slice(&row.summary.funding_txid);
    buf[596..600].copy_from_slice(&row.summary.funding_vout.to_le_bytes());

    Ok(buf)
}

/// Verifies an external 600-byte transcript byte-for-byte against `context` and `row`,
/// checking exact prefix, field offsets, and 51-bit bounds, and returns `SHA256(transcript)`.
pub fn verify_signed_row_transcript(
    transcript: &[u8],
    context: &BatchContext,
    row: &Row,
) -> Result<Hash> {
    if transcript.len() != NOVA_TRANSCRIPT_LEN {
        return Err(NovaBitvmError::Nova(format!(
            "signed-row transcript must be exactly {NOVA_TRANSCRIPT_LEN} bytes, got {}",
            transcript.len()
        )));
    }
    if &transcript[0..46] != NOVA_TRANSCRIPT_PREFIX {
        return Err(NovaBitvmError::Nova(
            "signed-row transcript prefix mismatch".to_owned(),
        ));
    }
    let expected = encode_signed_row_transcript(context, row)?;
    if transcript != expected.as_slice() {
        return Err(NovaBitvmError::Nova(
            "signed-row transcript bytes do not tie out to row digests, signatures, amounts, or outpoint"
                .to_owned(),
        ));
    }
    Ok(sha256(transcript))
}

fn initial_transcript_chain_digest(journal_sha256: &Hash, epoch: u64) -> Hash {
    let mut preimage = Vec::with_capacity(40);
    preimage.extend_from_slice(journal_sha256);
    preimage.extend_from_slice(&epoch.to_le_bytes());
    tagged_hash("nova-v2-transcript-chain-init", &preimage)
}

fn step_transcript_chain_digest(
    prev_digest: &Hash,
    transcript_sha256: &Hash,
    row: &Row,
) -> Hash {
    let mut preimage = Vec::with_capacity(136);
    preimage.extend_from_slice(prev_digest);
    preimage.extend_from_slice(transcript_sha256);
    preimage.extend_from_slice(&row.summary.funding_txid);
    preimage.extend_from_slice(&row.summary.funding_vout.to_le_bytes());
    preimage.extend_from_slice(&row.outcome.index.to_le_bytes());
    preimage.extend_from_slice(&row.outcome.trader_sats.to_le_bytes());
    preimage.extend_from_slice(&row.outcome.maker_sats.to_le_bytes());
    preimage.extend_from_slice(&row.outcome.anchor_sats.to_le_bytes());
    preimage.extend_from_slice(&row.outcome.fee_sats.to_le_bytes());
    tagged_hash("nova-v2-transcript-chain-step", &preimage)
}

/// 8-field Nova v2 folded state vector:
/// `[count, total_collateral, total_payout, total_fee, transcript_chain_digest_hex, journal_sha_low128_le, journal_sha_high128_le, epoch]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NovaFoldedState {
    pub count: u64,
    pub total_collateral: u64,
    pub total_payout: u64,
    pub total_fee: u64,
    pub transcript_chain_digest_hex: String,
    pub journal_sha_low128_le: String,
    pub journal_sha_high128_le: String,
    pub epoch: u64,
}

impl NovaFoldedState {
    /// Initializes step 0 state for a given 276-byte journal SHA-256 digest and epoch.
    pub fn initial(journal_sha256: &Hash, epoch: u64) -> Self {
        let (low, high) = sha256_to_le_u128_halves(journal_sha256);
        let init_chain = initial_transcript_chain_digest(journal_sha256, epoch);
        Self {
            count: 0,
            total_collateral: 0,
            total_payout: 0,
            total_fee: 0,
            transcript_chain_digest_hex: hex::encode(init_chain),
            journal_sha_low128_le: low.to_string(),
            journal_sha_high128_le: high.to_string(),
            epoch,
        }
    }

    /// Advances the 8-field folded state by exactly one verified row, enforcing the 5-bit input
    /// count bound (`count < 32`), 51-bit row bounds, 56-bit cumulative bounds, and exact
    /// 600-byte transcript tie-out.
    pub fn step(
        &self,
        context: &BatchContext,
        row: &Row,
        transcript: &[u8],
    ) -> Result<(Self, Hash)> {
        if self.count >= NOVA_MAX_STEPS {
            return Err(NovaBitvmError::Nova(format!(
                "input count ({}) violates 5-bit bound (< {NOVA_MAX_STEPS}); cannot fold past 32nd row",
                self.count
            )));
        }
        if context.epoch != self.epoch {
            return Err(NovaBitvmError::Nova(
                "row batch context epoch differs from folded state epoch".to_owned(),
            ));
        }
        check_cumulative_amount_56bit(self.total_collateral, "input total_collateral")?;
        check_cumulative_amount_56bit(self.total_payout, "input total_payout")?;
        check_cumulative_amount_56bit(self.total_fee, "input total_fee")?;

        let transcript_digest = verify_signed_row_transcript(transcript, context, row)?;

        let row_payout = row
            .outcome
            .trader_sats
            .checked_add(row.outcome.maker_sats)
            .and_then(|v| v.checked_add(row.outcome.anchor_sats))
            .ok_or_else(|| NovaBitvmError::Nova("row payout overflow".to_owned()))?;
        let row_fee = row.outcome.fee_sats;
        let row_collateral = row_payout
            .checked_add(row_fee)
            .ok_or_else(|| NovaBitvmError::Nova("row collateral overflow".to_owned()))?;

        let next_collateral = self
            .total_collateral
            .checked_add(row_collateral)
            .ok_or_else(|| NovaBitvmError::Nova("cumulative collateral u64 overflow".to_owned()))?;
        let next_payout = self
            .total_payout
            .checked_add(row_payout)
            .ok_or_else(|| NovaBitvmError::Nova("cumulative payout u64 overflow".to_owned()))?;
        let next_fee = self
            .total_fee
            .checked_add(row_fee)
            .ok_or_else(|| NovaBitvmError::Nova("cumulative fee u64 overflow".to_owned()))?;

        check_cumulative_amount_56bit(next_collateral, "output total_collateral")?;
        check_cumulative_amount_56bit(next_payout, "output total_payout")?;
        check_cumulative_amount_56bit(next_fee, "output total_fee")?;

        let prev_chain_bytes: Hash = hex::decode(&self.transcript_chain_digest_hex)
            .map_err(|_| NovaBitvmError::Nova("invalid transcript_chain_digest_hex".to_owned()))?
            .try_into()
            .map_err(|_| {
                NovaBitvmError::Nova("transcript_chain_digest_hex must be 32 bytes".to_owned())
            })?;
        let next_chain = step_transcript_chain_digest(&prev_chain_bytes, &transcript_digest, row);

        let next_state = Self {
            count: self.count + 1,
            total_collateral: next_collateral,
            total_payout: next_payout,
            total_fee: next_fee,
            transcript_chain_digest_hex: hex::encode(next_chain),
            journal_sha_low128_le: self.journal_sha_low128_le.clone(),
            journal_sha_high128_le: self.journal_sha_high128_le.clone(),
            epoch: self.epoch,
        };
        Ok((next_state, transcript_digest))
    }

    /// Returns the canonical 8-element string tuple in exact Nova v2 state order:
    /// `[count, total_collateral, total_payout, total_fee, transcript_chain_digest_hex, journal_sha_low128_le, journal_sha_high128_le, epoch]`.
    pub fn to_8_fields(&self) -> [String; 8] {
        [
            self.count.to_string(),
            self.total_collateral.to_string(),
            self.total_payout.to_string(),
            self.total_fee.to_string(),
            self.transcript_chain_digest_hex.clone(),
            self.journal_sha_low128_le.clone(),
            self.journal_sha_high128_le.clone(),
            self.epoch.to_string(),
        ]
    }

    pub fn journal_sha_halves_u128(&self) -> Result<(u128, u128)> {
        let low = self
            .journal_sha_low128_le
            .parse::<u128>()
            .map_err(|_| NovaBitvmError::Nova("invalid journal_sha_low128_le".to_owned()))?;
        let high = self
            .journal_sha_high128_le
            .parse::<u128>()
            .map_err(|_| NovaBitvmError::Nova("invalid journal_sha_high128_le".to_owned()))?;
        Ok((low, high))
    }
}

/// Out-of-process `expected.json` expectation payload ready for external `lnm-nova prepare/verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NovaExpectedStatement {
    pub relation_version: String,
    pub step_count: u32,
    pub journal_len: usize,
    pub journal_sha256_hex: String,
    pub initial_state: NovaFoldedState,
    pub final_state: NovaFoldedState,
    pub initial_state_fields: [String; 8],
    pub final_state_fields: [String; 8],
    pub row_transcript_digests_hex: Vec<String>,
    /// Populated externally once `lnm-nova prepare` derives and pins the compressed Spartan VK.
    pub verifier_key_pin_hex: Option<String>,
    pub honesty: VerificationHonestyFlags,
}

impl NovaExpectedStatement {
    /// Natively verifies `batch`, encodes all 600-byte signed-row transcripts, folds the 8-field
    /// Nova state from step 0 to `rows.len()`, checks final accounting against the 276-byte
    /// journal, and returns `(journal, transcripts, expected_statement)`.
    pub fn from_verified_batch(
        batch: &BatchWitness,
    ) -> Result<(Journal, Vec<[u8; NOVA_TRANSCRIPT_LEN]>, Self)> {
        let journal = verify_batch(batch)?;
        let journal_bytes = encode_journal(&journal);
        let journal_sha = sha256(&journal_bytes);

        let initial_state = NovaFoldedState::initial(&journal_sha, journal.epoch);
        let mut current = initial_state.clone();
        let mut transcripts = Vec::with_capacity(batch.rows.len());
        let mut digests_hex = Vec::with_capacity(batch.rows.len());

        for row in &batch.rows {
            let transcript = encode_signed_row_transcript(&batch.context, row)?;
            let (next_state, digest) = current.step(&batch.context, row, &transcript)?;
            current = next_state;
            transcripts.push(transcript);
            digests_hex.push(hex::encode(digest));
        }

        let expected = Self {
            relation_version: NOVA_RELATION_VERSION.to_owned(),
            step_count: journal.row_count,
            journal_len: JOURNAL_LEN,
            journal_sha256_hex: hex::encode(journal_sha),
            initial_state_fields: initial_state.to_8_fields(),
            final_state_fields: current.to_8_fields(),
            initial_state,
            final_state: current,
            row_transcript_digests_hex: digests_hex,
            verifier_key_pin_hex: None,
            honesty: VerificationHonestyFlags::native_only(),
        };
        expected.verify_against_journal_bytes(&journal_bytes)?;
        Ok((journal, transcripts, expected))
    }

    /// Checks that this expectation matches a concrete 276-byte `LNMJNL01` journal.
    pub fn verify_against_journal_bytes(&self, journal_bytes: &[u8]) -> Result<()> {
        if self.relation_version != NOVA_RELATION_VERSION {
            return Err(NovaBitvmError::Nova(
                "unsupported Nova relation version".to_owned(),
            ));
        }
        if self.journal_len != JOURNAL_LEN || journal_bytes.len() != JOURNAL_LEN {
            return Err(NovaBitvmError::Nova(
                "journal must be exactly 276 bytes".to_owned(),
            ));
        }
        let journal = decode_journal(journal_bytes)?;
        let journal_sha = sha256(journal_bytes);
        let journal_sha_hex = hex::encode(journal_sha);
        if self.journal_sha256_hex != journal_sha_hex {
            return Err(NovaBitvmError::Nova(
                "journal SHA-256 mismatch against expected.json".to_owned(),
            ));
        }
        if self.step_count == 0
            || self.step_count as usize > MAX_ROWS
            || self.step_count != journal.row_count
            || self.final_state.count != journal.row_count as u64
            || self.row_transcript_digests_hex.len() != journal.row_count as usize
        {
            return Err(NovaBitvmError::Nova(
                "step_count does not match journal row_count".to_owned(),
            ));
        }
        if self.initial_state != NovaFoldedState::initial(&journal_sha, journal.epoch) {
            return Err(NovaBitvmError::Nova(
                "initial_state does not match reconstructed journal initial state".to_owned(),
            ));
        }
        if self.initial_state_fields != self.initial_state.to_8_fields()
            || self.final_state_fields != self.final_state.to_8_fields()
        {
            return Err(NovaBitvmError::Nova(
                "8-field tuple array disagrees with structured state".to_owned(),
            ));
        }
        if self.final_state.total_collateral != journal.total_collateral_sats
            || self.final_state.total_payout != journal.total_payout_sats
            || self.final_state.total_fee != journal.total_fee_sats
            || self.final_state.epoch != journal.epoch
        {
            return Err(NovaBitvmError::Nova(
                "final folded accounting disagrees with 276-byte journal".to_owned(),
            ));
        }
        let (exp_low, exp_high) = sha256_to_le_u128_halves(&journal_sha);
        if self.final_state.journal_sha_halves_u128()? != (exp_low, exp_high) {
            return Err(NovaBitvmError::Nova(
                "final folded journal SHA-256 LE halves mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_expected_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| NovaBitvmError::Nova(format!("serialize expected.json failed: {e}")))
    }

    /// Strictly parses `expected.json` rejecting unknown fields.
    pub fn from_expected_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| NovaBitvmError::Nova(format!("parse expected.json failed: {e}")))
    }
}
