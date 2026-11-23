//! Native Pyth Pro (`pyth-lazer`) Solana Ed25519 Wire Verifier, Strict Little-Endian
//! `PayloadData` Parser, and Governance-Pinned Signer Rotation Registry.
//!
//! # Specification & Provenance Boundary
//! - Pyth Core retired NEAR support on 2026-08-26. Pyth Pro (`pyth-lazer`) emits Ed25519-signed
//!   Solana-format binary envelopes (`PYTH_SOLANA_FORMAT_MAGIC = 2_182_742_457`) wrapping
//!   standard little-endian `PayloadData` (`PAYLOAD_FORMAT_MAGIC = 2_479_346_549`), where
//!   `Crypto.BTC/USD` is numeric `u32` feed ID **`1`** (distinct from 32-byte Hermes IDs).
//! - This module verifies the outer Ed25519 signature strictly before trusting any inner field,
//!   enforces an epoch-bounded [`PinnedPythSignerRegistry`] (with threshold-signed governance
//!   key rotation and revocation), and parses exact `i64`/`i16`/`u64` integer mantissa, exponent,
//!   confidence, and `feed_update_timestamp` fields with zero floating-point arithmetic.
//! - Emitted [`VerifiedPythProBtcUsdReceipt`] records carry explicit honesty flags:
//!   `native_pyth_signature_verified: true`, `price_fields_parsed_and_bound: true`,
//!   `near_finality_verified: false`, `bitcoin_spend_enforced: false`.

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OracleError;

/// Outer Pyth Lazer Solana Ed25519 envelope magic (`u32` little-endian).
pub const PYTH_SOLANA_FORMAT_MAGIC: u32 = 2_182_742_457;

/// Inner Pyth Lazer standard little-endian `PayloadData` magic (`u32` little-endian).
pub const PYTH_PAYLOAD_FORMAT_MAGIC: u32 = 2_479_346_549;

/// Pyth Pro numeric `u32` feed identifier for `Crypto.BTC/USD`.
pub const PYTH_PRO_BTC_USD_FEED_ID: u32 = 1;

/// Canonical Pyth Pro `fixed_rate@200ms` channel identifier.
pub const PYTH_PRO_CHANNEL_FIXED_200MS: u8 = 3;

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Decoded property map for a single numeric feed inside a Pyth Lazer `PayloadData` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythDecodedFeed {
    pub feed_id: u32,
    pub property_count: u8,
    pub price: Option<i64>,
    pub best_bid_price: Option<i64>,
    pub best_ask_price: Option<i64>,
    pub publisher_count: Option<u16>,
    pub exponent: Option<i16>,
    pub confidence: Option<i64>,
    pub funding_rate: Option<i64>,
    pub funding_timestamp: Option<u64>,
    pub funding_rate_interval: Option<u64>,
    pub market_session: Option<i16>,
    pub ema_price: Option<i64>,
    pub ema_confidence: Option<i64>,
    pub feed_update_timestamp_us: Option<u64>,
}

/// Decoded inner standard little-endian `PayloadData` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythDecodedPayload {
    pub timestamp_us: u64,
    pub channel_id: u8,
    pub feeds: Vec<PythDecodedFeed>,
}

struct LeReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> LeReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], OracleError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(OracleError::InvalidObservation("Pyth PayloadData cursor overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(OracleError::InvalidObservation("truncated Pyth PayloadData"))?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, OracleError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, OracleError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn read_i16(&mut self) -> Result<i16, OracleError> {
        Ok(i16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32, OracleError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64, OracleError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn read_i64(&mut self) -> Result<i64, OracleError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn read_optional_nonzero_i64(&mut self) -> Result<Option<i64>, OracleError> {
        let v = self.read_i64()?;
        Ok(if v == 0 { None } else { Some(v) })
    }

    fn read_flagged_u64(&mut self) -> Result<Option<u64>, OracleError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64()?)),
            _ => Err(OracleError::InvalidObservation(
                "invalid Pyth optional property presence flag",
            )),
        }
    }

    fn read_flagged_i64(&mut self) -> Result<Option<i64>, OracleError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_i64()?)),
            _ => Err(OracleError::InvalidObservation(
                "invalid Pyth optional rate presence flag",
            )),
        }
    }
}

/// Strictly decodes standard little-endian `PayloadData` matching
/// `pyth-network/pyth-lazer-public/sdk/rust/protocol/src/payload/standard.rs`.
///
/// Rejects unknown or duplicate tags, duplicate feed IDs, unsupported channel IDs,
/// truncated frames, and any trailing bytes.
pub fn decode_pyth_standard_payload(payload: &[u8]) -> Result<PythDecodedPayload, OracleError> {
    if !(14..=8_192).contains(&payload.len()) {
        return Err(OracleError::InvalidObservation(
            "invalid Pyth PayloadData length",
        ));
    }
    let mut r = LeReader::new(payload);
    if r.read_u32()? != PYTH_PAYLOAD_FORMAT_MAGIC {
        return Err(OracleError::InvalidObservation(
            "wrong Pyth inner payload magic",
        ));
    }
    let timestamp_us = r.read_u64()?;
    let channel_id = r.read_u8()?;
    if !(1..=4).contains(&channel_id) {
        return Err(OracleError::InvalidObservation("invalid Pyth channel ID"));
    }
    let feed_count = r.read_u8()?;
    if !(1..=32).contains(&feed_count) {
        return Err(OracleError::InvalidObservation("invalid Pyth feed count"));
    }

    let mut seen_feeds = BTreeSet::new();
    let mut feeds = Vec::with_capacity(feed_count as usize);

    for _ in 0..feed_count {
        let feed_id = r.read_u32()?;
        if !seen_feeds.insert(feed_id) {
            return Err(OracleError::InvalidObservation("duplicate Pyth feed ID"));
        }
        let prop_count = r.read_u8()?;
        if !(1..=13).contains(&prop_count) {
            return Err(OracleError::InvalidObservation(
                "invalid Pyth property count",
            ));
        }
        let mut seen_tags_mask = 0u16;
        let mut decoded = PythDecodedFeed {
            feed_id,
            property_count: prop_count,
            price: None,
            best_bid_price: None,
            best_ask_price: None,
            publisher_count: None,
            exponent: None,
            confidence: None,
            funding_rate: None,
            funding_timestamp: None,
            funding_rate_interval: None,
            market_session: None,
            ema_price: None,
            ema_confidence: None,
            feed_update_timestamp_us: None,
        };

        for _ in 0..prop_count {
            let tag = r.read_u8()?;
            if tag > 12 {
                return Err(OracleError::InvalidObservation(
                    "unknown Pyth property tag",
                ));
            }
            if (seen_tags_mask & (1u16 << tag)) != 0 {
                return Err(OracleError::InvalidObservation(
                    "duplicate Pyth property tag",
                ));
            }
            seen_tags_mask |= 1u16 << tag;

            match tag {
                0 => decoded.price = r.read_optional_nonzero_i64()?,
                1 => decoded.best_bid_price = r.read_optional_nonzero_i64()?,
                2 => decoded.best_ask_price = r.read_optional_nonzero_i64()?,
                3 => decoded.publisher_count = Some(r.read_u16()?),
                4 => decoded.exponent = Some(r.read_i16()?),
                5 => decoded.confidence = r.read_optional_nonzero_i64()?,
                6 => decoded.funding_rate = r.read_flagged_i64()?,
                7 => decoded.funding_timestamp = r.read_flagged_u64()?,
                8 => decoded.funding_rate_interval = r.read_flagged_u64()?,
                9 => {
                    let s = r.read_i16()?;
                    if !(0..=4).contains(&s) {
                        return Err(OracleError::InvalidObservation(
                            "invalid Pyth market session",
                        ));
                    }
                    decoded.market_session = Some(s);
                }
                10 => decoded.ema_price = r.read_optional_nonzero_i64()?,
                11 => decoded.ema_confidence = r.read_optional_nonzero_i64()?,
                12 => decoded.feed_update_timestamp_us = r.read_flagged_u64()?,
                _ => unreachable!(),
            }
        }
        feeds.push(decoded);
    }

    if r.pos != payload.len() {
        return Err(OracleError::InvalidObservation(
            "trailing bytes after Pyth PayloadData",
        ));
    }

    Ok(PythDecodedPayload {
        timestamp_us,
        channel_id,
        feeds,
    })
}

/// Epoch-bounded Ed25519 Pyth Pro signer entry inside a governance-pinned registry.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct PinnedPythSignerEntry {
    pub pubkey: [u8; 32],
    pub valid_from_us: u64,
    pub valid_until_us: Option<u64>,
    pub revoked: bool,
}

/// Governance-signed rotation update adding/retiring Pyth Ed25519 signers.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SignedPythRegistryRotation {
    pub next_epoch: u64,
    pub updated_signers: Vec<PinnedPythSignerEntry>,
    /// `(guardian_index, ed25519_sig_64)` sorted strictly by `guardian_index`.
    pub guardian_approvals: Vec<(u16, Vec<u8>)>,
}

/// Governance-pinned Pyth Pro Ed25519 signer registry with replay-protected epoch rotation.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct PinnedPythSignerRegistry {
    pub registry_epoch: u64,
    pub governance_threshold: usize,
    pub governance_guardians: Vec<[u8; 32]>,
    pub signers: Vec<PinnedPythSignerEntry>,
}

impl PinnedPythSignerRegistry {
    pub fn new_static(signers: Vec<[u8; 32]>) -> Result<Self, OracleError> {
        if signers.is_empty() {
            return Err(OracleError::UntrustedFeedSigner);
        }
        for pk in &signers {
            VerifyingKey::from_bytes(pk).map_err(|_| OracleError::UntrustedFeedSigner)?;
        }
        Ok(Self {
            registry_epoch: 1,
            governance_threshold: 1,
            governance_guardians: Vec::new(),
            signers: signers
                .into_iter()
                .map(|pubkey| PinnedPythSignerEntry {
                    pubkey,
                    valid_from_us: 0,
                    valid_until_us: None,
                    revoked: false,
                })
                .collect(),
        })
    }

    pub fn new_governed(
        governance_threshold: usize,
        governance_guardians: Vec<[u8; 32]>,
        initial_signers: Vec<PinnedPythSignerEntry>,
    ) -> Result<Self, OracleError> {
        if governance_threshold == 0
            || governance_threshold > governance_guardians.len()
            || initial_signers.is_empty()
        {
            return Err(OracleError::InvalidObservation(
                "invalid Pyth signer registry governance threshold or empty signers",
            ));
        }
        for g in &governance_guardians {
            VerifyingKey::from_bytes(g).map_err(|_| OracleError::UntrustedFeedSigner)?;
        }
        for s in &initial_signers {
            VerifyingKey::from_bytes(&s.pubkey).map_err(|_| OracleError::UntrustedFeedSigner)?;
        }
        Ok(Self {
            registry_epoch: 1,
            governance_threshold,
            governance_guardians,
            signers: initial_signers,
        })
    }

    pub fn is_authorized_at(&self, pubkey: &[u8; 32], publish_time_us: u64) -> bool {
        self.signers.iter().any(|entry| {
            !entry.revoked
                && &entry.pubkey == pubkey
                && publish_time_us >= entry.valid_from_us
                && entry.valid_until_us.is_none_or(|until| publish_time_us <= until)
        })
    }

    pub fn rotation_signing_message(current_epoch: u64, next_epoch: u64, entries: &[PinnedPythSignerEntry]) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SHZ/PYTH-SIGNER-ROTATION/V1");
        buf.extend_from_slice(&current_epoch.to_le_bytes());
        buf.extend_from_slice(&next_epoch.to_le_bytes());
        buf.extend_from_slice(&borsh::to_vec(entries).expect("Borsh entries"));
        sha256_bytes(&buf)
    }

    /// Applies a threshold-signed governance key rotation, advancing `registry_epoch` monotonically.
    pub fn apply_rotation(&mut self, rotation: &SignedPythRegistryRotation) -> Result<(), OracleError> {
        if rotation.next_epoch <= self.registry_epoch || rotation.updated_signers.is_empty() {
            return Err(OracleError::InvalidObservation(
                "non-monotonic Pyth registry rotation epoch or empty signer set",
            ));
        }
        if rotation.guardian_approvals.len() < self.governance_threshold {
            return Err(OracleError::InsufficientQuorum {
                got: rotation.guardian_approvals.len(),
                required: self.governance_threshold,
            });
        }
        for entry in &rotation.updated_signers {
            VerifyingKey::from_bytes(&entry.pubkey).map_err(|_| OracleError::UntrustedFeedSigner)?;
        }

        let digest = Self::rotation_signing_message(
            self.registry_epoch,
            rotation.next_epoch,
            &rotation.updated_signers,
        );
        let mut prev_idx: Option<u16> = None;
        for (g_idx, sig_bytes) in &rotation.guardian_approvals {
            let g_idx = *g_idx;
            if prev_idx.is_some_and(|p| g_idx <= p) {
                return Err(OracleError::UntrustedFeedSigner);
            }
            prev_idx = Some(g_idx);
            let guardian_pk = self
                .governance_guardians
                .get(g_idx as usize)
                .ok_or(OracleError::UntrustedFeedSigner)?;
            let vk = VerifyingKey::from_bytes(guardian_pk)
                .map_err(|_| OracleError::UntrustedFeedSigner)?;
            let sig_arr: [u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| OracleError::UntrustedFeedSigner)?;
            let sig = Signature::from_bytes(&sig_arr);
            vk.verify(&digest, &sig)
                .map_err(|_| OracleError::UntrustedFeedSigner)?;
        }

        self.registry_epoch = rotation.next_epoch;
        self.signers = rotation.updated_signers.clone();
        Ok(())
    }
}

/// Validation policy for native Pyth Pro BTC/USD Solana envelopes.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct PythProBtcUsdPolicy {
    pub expected_feed_id: u32,
    pub allowed_channel_ids: Vec<u8>,
    pub max_age_us: u64,
    pub max_carry_forward_us: u64,
    pub max_future_skew_us: u64,
    pub max_conf_bps: u64,
}

impl Default for PythProBtcUsdPolicy {
    fn default() -> Self {
        Self {
            expected_feed_id: PYTH_PRO_BTC_USD_FEED_ID,
            allowed_channel_ids: vec![PYTH_PRO_CHANNEL_FIXED_200MS],
            max_age_us: 5_000_000,
            max_carry_forward_us: 2_000_000,
            max_future_skew_us: 100_000,
            max_conf_bps: 100,
        }
    }
}

/// Provenance-verified native Pyth Pro BTC/USD receipt with explicit trust-boundary flags.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct VerifiedPythProBtcUsdReceipt {
    pub provenance_grade: String,
    pub feed_id: u32,
    pub channel_id: u8,
    pub signer_pubkey_hex: String,
    pub registry_epoch: u64,
    pub publish_time_us: u64,
    pub feed_update_time_us: u64,
    pub raw_price_mantissa: i64,
    pub exponent: i16,
    pub confidence_mantissa: i64,
    pub price_e8: u64,
    pub whole_price_usd: u64,
    pub confidence_bps: u64,
    pub signed_payload_sha256: [u8; 32],
    pub receipt_hash: [u8; 32],
    pub native_pyth_signature_verified: bool,
    pub price_fields_parsed_and_bound: bool,
    pub near_finality_verified: bool,
    pub bitcoin_spend_enforced: bool,
}

/// Authenticates the outer Pyth Pro Solana Ed25519 envelope against `registry` BEFORE parsing
/// inner `PayloadData` fields, then enforces `policy` at `now_us` using checked integer math.
pub fn verify_pyth_pro_btc_usd_solana_envelope(
    raw_envelope: &[u8],
    registry: &PinnedPythSignerRegistry,
    policy: &PythProBtcUsdPolicy,
    now_us: u64,
) -> Result<VerifiedPythProBtcUsdReceipt, OracleError> {
    if policy.expected_feed_id != PYTH_PRO_BTC_USD_FEED_ID || policy.allowed_channel_ids.is_empty()
    {
        return Err(OracleError::InvalidObservation(
            "unexpected Pyth BTC/USD feed policy",
        ));
    }
    if !(103..=16_384).contains(&raw_envelope.len()) {
        return Err(OracleError::InvalidObservation(
            "invalid Pyth Solana envelope length",
        ));
    }
    let magic = u32::from_le_bytes(raw_envelope[0..4].try_into().unwrap());
    if magic != PYTH_SOLANA_FORMAT_MAGIC {
        return Err(OracleError::InvalidObservation(
            "wrong Pyth Solana outer envelope magic",
        ));
    }
    let payload_len = u16::from_le_bytes(raw_envelope[100..102].try_into().unwrap()) as usize;
    if payload_len == 0 || raw_envelope.len() != 102 + payload_len {
        return Err(OracleError::InvalidObservation(
            "Pyth Solana envelope payload length mismatch",
        ));
    }

    let sig_bytes: [u8; 64] = raw_envelope[4..68].try_into().unwrap();
    let signer_bytes: [u8; 32] = raw_envelope[68..100].try_into().unwrap();
    let signed_payload = &raw_envelope[102..];

    // 1. Verify Ed25519 signature over `signed_payload` BEFORE parsing any payload bytes!
    let vk = VerifyingKey::from_bytes(&signer_bytes).map_err(|_| OracleError::UntrustedFeedSigner)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(signed_payload, &sig)
        .map_err(|_| OracleError::InvalidObservation("invalid Pyth Ed25519 signature"))?;

    // 2. Decode strict LE PayloadData & check signer authorization at `timestamp_us`
    let decoded = decode_pyth_standard_payload(signed_payload)?;
    if !registry.is_authorized_at(&signer_bytes, decoded.timestamp_us) {
        return Err(OracleError::UntrustedFeedSigner);
    }
    if !policy.allowed_channel_ids.contains(&decoded.channel_id) {
        return Err(OracleError::InvalidObservation(
            "Pyth channel policy mismatch",
        ));
    }

    let feed = decoded
        .feeds
        .iter()
        .find(|f| f.feed_id == policy.expected_feed_id)
        .ok_or(OracleError::InvalidObservation(
            "BTC/USD feed is absent from signed Pyth payload",
        ))?;

    let raw_price = feed.price.ok_or(OracleError::InvalidObservation(
        "missing valid signed BTC/USD price",
    ))?;
    let expo = feed.exponent.ok_or(OracleError::InvalidObservation(
        "missing signed BTC/USD exponent",
    ))?;
    let conf = feed.confidence.ok_or(OracleError::InvalidObservation(
        "missing signed BTC/USD confidence",
    ))?;
    let feed_update_us = feed
        .feed_update_timestamp_us
        .ok_or(OracleError::InvalidObservation(
            "missing signed BTC/USD feed_update_timestamp",
        ))?;

    if raw_price <= 0 || conf < 0 || !(-18..=12).contains(&expo) {
        return Err(OracleError::InvalidObservation(
            "invalid signed BTC/USD mantissa or exponent",
        ));
    }
    if feed_update_us > decoded.timestamp_us {
        return Err(OracleError::InvalidObservation(
            "feed_update_timestamp exceeds publish timestamp",
        ));
    }
    if decoded.timestamp_us > now_us.saturating_add(policy.max_future_skew_us) {
        return Err(OracleError::StaleObservation);
    }
    if now_us.saturating_sub(decoded.timestamp_us) > policy.max_age_us {
        return Err(OracleError::StaleObservation);
    }
    if decoded.timestamp_us.saturating_sub(feed_update_us) > policy.max_carry_forward_us {
        return Err(OracleError::StaleObservation);
    }

    let raw_u128 = raw_price as u128;
    let power = (expo as i32) + 8;
    let price_e8_u128 = if power >= 0 {
        let mul = 10u128
            .checked_pow(power as u32)
            .ok_or(OracleError::InvalidObservation("Pyth price scale overflow"))?;
        raw_u128
            .checked_mul(mul)
            .ok_or(OracleError::InvalidObservation("Pyth price_e8 overflow"))?
    } else {
        let den = 10u128
            .checked_pow((-power) as u32)
            .ok_or(OracleError::InvalidObservation("Pyth price scale underflow"))?;
        raw_u128
            .checked_add(den / 2)
            .ok_or(OracleError::InvalidObservation("Pyth rounding overflow"))?
            / den
    };
    if price_e8_u128 == 0 || price_e8_u128 > u64::MAX as u128 {
        return Err(OracleError::InvalidObservation("Pyth price_e8 out of u64 range"));
    }
    let price_e8 = price_e8_u128 as u64;
    let whole_price_usd = (price_e8 + 50_000_000) / 100_000_000;

    let conf_bps_u128 = (conf as u128)
        .checked_mul(10_000)
        .and_then(|v| v.checked_add(raw_u128 - 1))
        .ok_or(OracleError::InvalidObservation("Pyth conf_bps overflow"))?
        / raw_u128;
    let confidence_bps = u64::try_from(conf_bps_u128)
        .map_err(|_| OracleError::InvalidObservation("Pyth conf_bps u64 overflow"))?;
    if confidence_bps > policy.max_conf_bps {
        return Err(OracleError::ConfidenceTooWide {
            conf_bps: confidence_bps,
            max_bps: policy.max_conf_bps,
        });
    }

    let signed_payload_sha256 = sha256_bytes(signed_payload);
    let mut receipt_preimage = Vec::with_capacity(128);
    receipt_preimage.extend_from_slice(b"SHZ/NATIVE-PYTH-PRO-RECEIPT/V1");
    receipt_preimage.extend_from_slice(&signer_bytes);
    receipt_preimage.extend_from_slice(&signed_payload_sha256);
    receipt_preimage.extend_from_slice(&decoded.timestamp_us.to_le_bytes());
    receipt_preimage.extend_from_slice(&feed_update_us.to_le_bytes());
    receipt_preimage.extend_from_slice(&price_e8.to_le_bytes());
    receipt_preimage.extend_from_slice(&confidence_bps.to_le_bytes());
    let receipt_hash = sha256_bytes(&receipt_preimage);

    Ok(VerifiedPythProBtcUsdReceipt {
        provenance_grade: "NATIVE_PYTH_ED25519_WITH_SIGNED_PRICE".to_owned(),
        feed_id: feed.feed_id,
        channel_id: decoded.channel_id,
        signer_pubkey_hex: hex::encode(signer_bytes),
        registry_epoch: registry.registry_epoch,
        publish_time_us: decoded.timestamp_us,
        feed_update_time_us: feed_update_us,
        raw_price_mantissa: raw_price,
        exponent: expo,
        confidence_mantissa: conf,
        price_e8,
        whole_price_usd,
        confidence_bps,
        signed_payload_sha256,
        receipt_hash,
        native_pyth_signature_verified: true,
        price_fields_parsed_and_bound: true,
        near_finality_verified: false,
        bitcoin_spend_enforced: false,
    })
}

/// Deterministic test/harness helper encoding & Ed25519-signing a canonical Pyth Pro Solana BTC/USD envelope.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_pyth_pro_btc_usd_envelope(
    ed25519_secret: &[u8; 32],
    publish_time_us: u64,
    feed_update_time_us: u64,
    channel_id: u8,
    feed_id: u32,
    raw_price: i64,
    exponent: i16,
    confidence: i64,
) -> (Vec<u8>, [u8; 32]) {
    let mut payload = Vec::with_capacity(48);
    payload.extend_from_slice(&PYTH_PAYLOAD_FORMAT_MAGIC.to_le_bytes());
    payload.extend_from_slice(&publish_time_us.to_le_bytes());
    payload.push(channel_id);
    payload.push(1u8); // 1 feed
    payload.extend_from_slice(&feed_id.to_le_bytes());
    payload.push(4u8); // 4 properties: Price(0), Exponent(4), Confidence(5), FeedUpdateTimestamp(12)
    payload.push(0u8);
    payload.extend_from_slice(&raw_price.to_le_bytes());
    payload.push(4u8);
    payload.extend_from_slice(&exponent.to_le_bytes());
    payload.push(5u8);
    payload.extend_from_slice(&confidence.to_le_bytes());
    payload.push(12u8);
    payload.push(1u8); // Some(feed_update_time_us)
    payload.extend_from_slice(&feed_update_time_us.to_le_bytes());

    let sk = SigningKey::from_bytes(ed25519_secret);
    let pk_bytes = sk.verifying_key().to_bytes();
    let sig = sk.sign(&payload);

    let mut frame = Vec::with_capacity(102 + payload.len());
    frame.extend_from_slice(&PYTH_SOLANA_FORMAT_MAGIC.to_le_bytes());
    frame.extend_from_slice(&sig.to_bytes());
    frame.extend_from_slice(&pk_bytes);
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(&payload);
    (frame, pk_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFICIAL_LAZER_WIRE_SAMPLE_HEX: &str = concat!(
        "b9011a82c7887f3aaa5845b20d6bf5ca6609953b57650fa4579a4b4d34a4980ba608a9f76a825a446",
        "f3d6c1fd9daca1c5e3fc46980f14ef89c1a886c6e9e5c510872d30f80efc1f480c5615af3fb673d422",
        "87e993da9fbc3506b6e41dfa32950820c2e6c620075d3c7934077d115064b06000301010000000d009",
        "032fc171b060000014e3a0cff1a06000002bcda8a211b06000003120004f8ff05fc0b7159000000000",
        "600070008000900000aa06616362e0600000b804f93312e0600000c014077d115064b0600"
    );

    #[test]
    fn test_official_pyth_lazer_wire_sample_parity() {
        let full = hex::decode(OFFICIAL_LAZER_WIRE_SAMPLE_HEX).unwrap();
        let decoded = decode_pyth_standard_payload(&full[102..]).unwrap();
        assert_eq!(decoded.timestamp_us, 1_771_339_368_200_000);
        assert_eq!(decoded.channel_id, 3);
        assert_eq!(decoded.feeds.len(), 1);
        let f = &decoded.feeds[0];
        assert_eq!(f.feed_id, 1);
        assert_eq!(f.property_count, 13);
        assert_eq!(f.price, Some(6_713_436_287_632));
        assert_eq!(f.exponent, Some(-8));
        assert_eq!(f.confidence, Some(1_500_580_860));
        assert_eq!(f.feed_update_timestamp_us, Some(1_771_339_368_200_000));

        // Verify the archived outer Ed25519 signature under the sample's embedded signer key!
        let embedded_signer: [u8; 32] = full[68..100].try_into().unwrap();
        let reg = PinnedPythSignerRegistry::new_static(vec![embedded_signer]).unwrap();
        let receipt = verify_pyth_pro_btc_usd_solana_envelope(
            &full,
            &reg,
            &PythProBtcUsdPolicy::default(),
            1_771_339_368_500_000,
        )
        .unwrap();
        assert_eq!(receipt.price_e8, 6_713_436_287_632);
        assert_eq!(receipt.whole_price_usd, 67_134);
        assert!(receipt.native_pyth_signature_verified);
        assert!(receipt.price_fields_parsed_and_bound);
        assert!(!receipt.near_finality_verified);
        assert!(!receipt.bitcoin_spend_enforced);
    }

    #[test]
    fn test_governed_pyth_signer_rotation_and_revocation() {
        let g1 = SigningKey::from_bytes(&[0x11; 32]);
        let g2 = SigningKey::from_bytes(&[0x12; 32]);
        let g3 = SigningKey::from_bytes(&[0x13; 32]);

        let old_pyth_sk = [0x21u8; 32];
        let new_pyth_sk = [0x22u8; 32];
        let old_pyth_pk = SigningKey::from_bytes(&old_pyth_sk).verifying_key().to_bytes();
        let new_pyth_pk = SigningKey::from_bytes(&new_pyth_sk).verifying_key().to_bytes();

        let mut reg = PinnedPythSignerRegistry::new_governed(
            2,
            vec![
                g1.verifying_key().to_bytes(),
                g2.verifying_key().to_bytes(),
                g3.verifying_key().to_bytes(),
            ],
            vec![PinnedPythSignerEntry {
                pubkey: old_pyth_pk,
                valid_from_us: 1_795_000_000_000_000,
                valid_until_us: Some(1_795_000_010_000_000),
                revoked: false,
            }],
        )
        .unwrap();

        let (env_old, _) = build_signed_pyth_pro_btc_usd_envelope(
            &old_pyth_sk,
            1_795_000_005_000_000,
            1_795_000_005_000_000,
            3,
            1,
            12_500_000_000_000,
            -8,
            1_500_000_000,
        );
        assert!(
            verify_pyth_pro_btc_usd_solana_envelope(
                &env_old,
                &reg,
                &PythProBtcUsdPolicy::default(),
                1_795_000_006_000_000,
            )
            .is_ok()
        );

        // Rotate: revoke `old_pyth_pk` and activate `new_pyth_pk` via 2-of-3 guardians {0, 2}
        let next_entries = vec![
            PinnedPythSignerEntry {
                pubkey: old_pyth_pk,
                valid_from_us: 1_795_000_000_000_000,
                valid_until_us: Some(1_795_000_010_000_000),
                revoked: true,
            },
            PinnedPythSignerEntry {
                pubkey: new_pyth_pk,
                valid_from_us: 1_795_000_010_000_000,
                valid_until_us: None,
                revoked: false,
            },
        ];
        let msg = PinnedPythSignerRegistry::rotation_signing_message(1, 2, &next_entries);
        let rot = SignedPythRegistryRotation {
            next_epoch: 2,
            updated_signers: next_entries,
            guardian_approvals: vec![
                (0, g1.sign(&msg).to_bytes().to_vec()),
                (2, g3.sign(&msg).to_bytes().to_vec()),
            ],
        };
        reg.apply_rotation(&rot).unwrap();
        assert_eq!(reg.registry_epoch, 2);

        // Revoked key is immediately rejected even within its old time window!
        assert_eq!(
            verify_pyth_pro_btc_usd_solana_envelope(
                &env_old,
                &reg,
                &PythProBtcUsdPolicy::default(),
                1_795_000_006_000_000,
            )
            .unwrap_err(),
            OracleError::UntrustedFeedSigner
        );

        // Newly rotated Pyth signer succeeds!
        let (env_new, _) = build_signed_pyth_pro_btc_usd_envelope(
            &new_pyth_sk,
            1_795_000_012_000_000,
            1_795_000_012_000_000,
            3,
            1,
            12_500_000_000_000,
            -8,
            1_500_000_000,
        );
        let verified = verify_pyth_pro_btc_usd_solana_envelope(
            &env_new,
            &reg,
            &PythProBtcUsdPolicy::default(),
            1_795_000_013_000_000,
        )
        .unwrap();
        assert_eq!(verified.whole_price_usd, 125_000);
        assert_eq!(verified.registry_epoch, 2);
    }
}
