//! HFT-06 native Chainlink Data Streams report verifier (schema v3, crypto streams).
//!
//! The pre-existing crate had no Chainlink authentication: HFT-04 packets
//! carried a Chainlink `report` digest that no code had verified. This module
//! closes that inventory gap offchain:
//!
//! * strict ABI decoding of the `fullReport` envelope
//!   `abi.encode(bytes32[3] reportContext, bytes reportBlob, bytes32[] rs, bytes32[] ss, bytes32 rawVs)`;
//! * the DON signature rule of the on-chain `Verifier`:
//!   `h = keccak256(keccak256(reportBlob) || reportContext[0..3])`,
//!   exactly `f + 1` distinct ECDSA secp256k1 signers recovered with
//!   `ecrecover(h, rawVs[i] + 27, rs[i], ss[i])`, each in the pinned signer
//!   set of the configuration named by `reportContext[0]` (the config digest);
//! * strict v3 report-blob decoding with sign-extension, upper-bit and
//!   expiry checks, then integer normalization of the 18-decimal
//!   `benchmarkPrice` to `price_e8`.
//!
//! Stricter than the EVM precompile: high-`s` signatures are rejected.
//! The pinned [`PinnedDonRegistry`] must be loaded from the deployed Verifier
//! contract's configuration (`ConfigSet` events) by the operator; this module
//! does not read chain state. Schema v3 timestamps have one-second resolution.
//! Receipts carry `native_chainlink_signature_verified: true` and
//! `onchain_config_verified: false`.

use std::collections::{BTreeMap, BTreeSet};

use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::OracleError;

/// Schema version prefix (first two bytes of the feed ID) for v3 crypto reports.
pub const CHAINLINK_SCHEMA_V3: u16 = 3;
/// Decimal places of v3 crypto `benchmarkPrice`, `bid` and `ask`.
pub const CHAINLINK_V3_DECIMALS: u32 = 18;
const WORD: usize = 32;
const MAX_FULL_REPORT: usize = 8_192;
const MAX_SIGNERS: usize = 31;

pub type EthAddress = [u8; 20];

fn bad(msg: &'static str) -> OracleError {
    OracleError::InvalidObservation(msg)
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Ethereum address of an uncompressed secp256k1 public key.
pub fn eth_address(vk: &VerifyingKey) -> EthAddress {
    let point = vk.to_encoded_point(false);
    let h = keccak256(&point.as_bytes()[1..]);
    h[12..].try_into().unwrap()
}

struct Abi<'a> {
    data: &'a [u8],
}

impl<'a> Abi<'a> {
    fn word(&self, at: usize) -> Result<&'a [u8; 32], OracleError> {
        let end = at.checked_add(WORD).ok_or(bad("ABI offset overflow"))?;
        self.data
            .get(at..end)
            .map(|w| w.try_into().unwrap())
            .ok_or(bad("ABI word out of bounds"))
    }
    /// Unsigned integer that must fit in `usize` and a small bound.
    fn small(&self, at: usize, max: usize) -> Result<usize, OracleError> {
        let w = self.word(at)?;
        if w[..24].iter().any(|&b| b != 0) {
            return Err(bad("ABI integer exceeds bound"));
        }
        let v = u64::from_be_bytes(w[24..].try_into().unwrap()) as usize;
        if v > max {
            return Err(bad("ABI integer exceeds bound"));
        }
        Ok(v)
    }
    /// Dynamic `bytes` at head slot `slot`; canonical (zero-padded) encoding only.
    fn bytes(&self, slot: usize) -> Result<(usize, &'a [u8]), OracleError> {
        let off = self.small(slot, self.data.len())?;
        if off % WORD != 0 {
            return Err(bad("unaligned ABI offset"));
        }
        let len = self.small(off, self.data.len())?;
        let start = off + WORD;
        let padded = len.div_ceil(WORD) * WORD;
        let tail = self
            .data
            .get(start..start.checked_add(padded).ok_or(bad("ABI overflow"))?)
            .ok_or(bad("ABI bytes out of bounds"))?;
        if tail[len..].iter().any(|&b| b != 0) {
            return Err(bad("non-canonical ABI padding"));
        }
        Ok((start + padded, &tail[..len]))
    }
    fn words(&self, slot: usize) -> Result<(usize, Vec<[u8; 32]>), OracleError> {
        let off = self.small(slot, self.data.len())?;
        if off % WORD != 0 {
            return Err(bad("unaligned ABI offset"));
        }
        let len = self.small(off, MAX_SIGNERS)?;
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push(*self.word(off + WORD * (i + 1))?);
        }
        Ok((off + WORD * (len + 1), out))
    }
}

/// Decoded, not yet authenticated, `fullReport` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainlinkFullReport {
    pub report_context: [[u8; 32]; 3],
    pub report_blob: Vec<u8>,
    pub rs: Vec<[u8; 32]>,
    pub ss: Vec<[u8; 32]>,
    pub raw_vs: [u8; 32],
}

impl ChainlinkFullReport {
    pub fn decode(full: &[u8]) -> Result<Self, OracleError> {
        if full.len() < 7 * WORD || full.len() > MAX_FULL_REPORT || !full.len().is_multiple_of(WORD) {
            return Err(bad("invalid Chainlink fullReport length"));
        }
        let abi = Abi { data: full };
        let report_context = [*abi.word(0)?, *abi.word(32)?, *abi.word(64)?];
        // Canonical head: offsets strictly follow the 7-word head in order, and
        // the encoding ends exactly at the last dynamic element.
        let blob_off = abi.small(96, full.len())?;
        if blob_off != 7 * WORD {
            return Err(bad("non-canonical Chainlink ABI head"));
        }
        let (blob_end, blob) = abi.bytes(96)?;
        let rs_off = abi.small(128, full.len())?;
        if rs_off != blob_end {
            return Err(bad("non-canonical Chainlink ABI head"));
        }
        let (rs_end, rs) = abi.words(128)?;
        let ss_off = abi.small(160, full.len())?;
        if ss_off != rs_end {
            return Err(bad("non-canonical Chainlink ABI head"));
        }
        let (ss_end, ss) = abi.words(160)?;
        if ss_end != full.len() {
            return Err(bad("trailing bytes after Chainlink fullReport"));
        }
        Ok(Self {
            report_context,
            report_blob: blob.to_vec(),
            rs,
            ss,
            raw_vs: *abi.word(192)?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        fn uint(b: &mut Vec<u8>, v: usize) {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&(v as u64).to_be_bytes());
            b.extend(w);
        }
        let padded = self.report_blob.len().div_ceil(WORD) * WORD;
        let blob_off = 7 * WORD;
        let rs_off = blob_off + WORD + padded;
        let ss_off = rs_off + WORD * (1 + self.rs.len());
        let mut b = Vec::new();
        for c in &self.report_context {
            b.extend(c);
        }
        uint(&mut b, blob_off);
        uint(&mut b, rs_off);
        uint(&mut b, ss_off);
        b.extend(self.raw_vs);
        uint(&mut b, self.report_blob.len());
        b.extend(&self.report_blob);
        b.resize(b.len() + padded - self.report_blob.len(), 0);
        uint(&mut b, self.rs.len());
        for r in &self.rs {
            b.extend(r);
        }
        uint(&mut b, self.ss.len());
        for s in &self.ss {
            b.extend(s);
        }
        b
    }

    /// The exact 32-byte message the DON signs.
    pub fn signed_hash(&self) -> [u8; 32] {
        let mut b = Vec::with_capacity(128);
        b.extend(keccak256(&self.report_blob));
        for c in &self.report_context {
            b.extend(c);
        }
        keccak256(&b)
    }

    pub fn config_digest(&self) -> [u8; 32] {
        self.report_context[0]
    }
}

/// One pinned DON configuration (`configDigest -> (f, signers)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DonConfig {
    pub config_digest: [u8; 32],
    pub f: u8,
    pub signers: Vec<EthAddress>,
    /// Inclusive validity window on `observationsTimestamp` (seconds). The
    /// operator closes a window when the Verifier deactivates the config.
    pub active_from_s: u32,
    pub active_until_s: u32,
}

/// Operator-pinned set of active DON configurations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedDonRegistry {
    configs: BTreeMap<[u8; 32], DonConfig>,
}

impl PinnedDonRegistry {
    pub fn new(configs: Vec<DonConfig>) -> Result<Self, OracleError> {
        let mut map = BTreeMap::new();
        for c in configs {
            let distinct: BTreeSet<_> = c.signers.iter().collect();
            if c.config_digest == [0; 32]
                || c.f == 0
                || c.signers.len() > MAX_SIGNERS
                || distinct.len() != c.signers.len()
                || c.signers.len() <= 3 * c.f as usize
                || c.signers.contains(&[0; 20])
                || c.active_from_s > c.active_until_s
                || map.insert(c.config_digest, c).is_some()
            {
                return Err(bad("invalid pinned Chainlink DON configuration"));
            }
        }
        if map.is_empty() {
            return Err(bad("empty pinned Chainlink DON registry"));
        }
        Ok(Self { configs: map })
    }
    pub fn config(&self, digest: &[u8; 32]) -> Option<&DonConfig> {
        self.configs.get(digest)
    }
}

/// Decoded v3 crypto report blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainlinkV3Report {
    pub feed_id: [u8; 32],
    pub valid_from_s: u32,
    pub observations_s: u32,
    pub native_fee: u128,
    pub link_fee: u128,
    pub expires_at_s: u32,
    pub benchmark_price: i128,
    pub bid: i128,
    pub ask: i128,
}

fn u32_word(w: &[u8; 32]) -> Result<u32, OracleError> {
    if w[..28].iter().any(|&b| b != 0) {
        return Err(bad("uint32 field has high bits"));
    }
    Ok(u32::from_be_bytes(w[28..].try_into().unwrap()))
}
fn u192_word(w: &[u8; 32]) -> Result<u128, OracleError> {
    if w[..8].iter().any(|&b| b != 0) {
        return Err(bad("uint192 field has high bits"));
    }
    if w[8..16].iter().any(|&b| b != 0) {
        return Err(bad("uint192 fee exceeds supported range"));
    }
    Ok(u128::from_be_bytes(w[16..].try_into().unwrap()))
}
/// int192 sign-extended to 256 bits; values outside i128 are rejected.
fn i192_word(w: &[u8; 32]) -> Result<i128, OracleError> {
    let fill = if w[16] & 0x80 != 0 { 0xff } else { 0x00 };
    if w[..16].iter().any(|&b| b != fill) {
        return Err(bad("int192 field not sign-extended or out of range"));
    }
    Ok(i128::from_be_bytes(w[16..].try_into().unwrap()))
}

impl ChainlinkV3Report {
    pub fn decode(blob: &[u8]) -> Result<Self, OracleError> {
        if blob.len() != 9 * WORD {
            return Err(bad("invalid Chainlink v3 report length"));
        }
        let w = |i: usize| -> &[u8; 32] { blob[i * WORD..(i + 1) * WORD].try_into().unwrap() };
        let feed_id = *w(0);
        if u16::from_be_bytes([feed_id[0], feed_id[1]]) != CHAINLINK_SCHEMA_V3 {
            return Err(bad("Chainlink feed is not schema v3"));
        }
        Ok(Self {
            feed_id,
            valid_from_s: u32_word(w(1))?,
            observations_s: u32_word(w(2))?,
            native_fee: u192_word(w(3))?,
            link_fee: u192_word(w(4))?,
            expires_at_s: u32_word(w(5))?,
            benchmark_price: i192_word(w(6))?,
            bid: i192_word(w(7))?,
            ask: i192_word(w(8))?,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(9 * WORD);
        let u = |b: &mut Vec<u8>, v: u128| {
            b.extend([0u8; 16]);
            b.extend(v.to_be_bytes());
        };
        let i = |b: &mut Vec<u8>, v: i128| {
            b.extend(if v < 0 { [0xffu8; 16] } else { [0u8; 16] });
            b.extend(v.to_be_bytes());
        };
        b.extend(self.feed_id);
        u(&mut b, self.valid_from_s as u128);
        u(&mut b, self.observations_s as u128);
        u(&mut b, self.native_fee);
        u(&mut b, self.link_fee);
        u(&mut b, self.expires_at_s as u128);
        i(&mut b, self.benchmark_price);
        i(&mut b, self.bid);
        i(&mut b, self.ask);
        b
    }
}

/// Acceptance policy for one Chainlink crypto stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainlinkStreamPolicy {
    pub feed_id: [u8; 32],
    /// Maximum `now - observationsTimestamp`, microseconds (second-granular source).
    pub max_age_us: u64,
    pub max_future_skew_us: u64,
    /// Maximum (ask - bid) / benchmark spread, basis points.
    pub max_spread_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedChainlinkReport {
    pub feed_id: [u8; 32],
    pub config_digest: [u8; 32],
    pub signers: Vec<EthAddress>,
    pub observations_us: u64,
    pub valid_from_us: u64,
    pub expires_at_us: u64,
    pub benchmark_price_e18: i128,
    pub price_e8: u64,
    pub spread_bps: u64,
    /// SHA256 of the exact `fullReport` bytes.
    pub full_report_sha256: [u8; 32],
    /// DON-signed message hash.
    pub signed_hash: [u8; 32],
    pub native_chainlink_signature_verified: bool,
    pub onchain_config_verified: bool,
}

/// Authenticate the DON signatures BEFORE trusting any report field, then
/// apply the policy at `now_us` with checked integer arithmetic.
pub fn verify_chainlink_v3_report(
    full: &[u8],
    registry: &PinnedDonRegistry,
    policy: &ChainlinkStreamPolicy,
    now_us: u64,
) -> Result<VerifiedChainlinkReport, OracleError> {
    let env = ChainlinkFullReport::decode(full)?;
    let cfg = registry
        .config(&env.config_digest())
        .ok_or(OracleError::UntrustedFeedSigner)?;
    let need = cfg.f as usize + 1;
    if env.rs.len() != need || env.ss.len() != need {
        return Err(OracleError::InsufficientQuorum { got: env.rs.len().min(env.ss.len()), required: need });
    }
    if env.raw_vs[need..].iter().any(|&b| b != 0) {
        return Err(bad("unused Chainlink rawVs bytes must be zero"));
    }
    let h = env.signed_hash();
    let mut signers = Vec::with_capacity(need);
    let mut seen = BTreeSet::new();
    for i in 0..need {
        let sig = Signature::from_scalars(env.rs[i], env.ss[i]).map_err(|_| bad("invalid ECDSA scalar"))?;
        if sig.normalize_s().is_some() {
            return Err(bad("high-s Chainlink signature"));
        }
        let rec = RecoveryId::from_byte(env.raw_vs[i]).filter(|r| !r.is_x_reduced()).ok_or(bad("invalid recovery id"))?;
        let vk = VerifyingKey::recover_from_prehash(&h, &sig, rec).map_err(|_| bad("ECDSA recovery failed"))?;
        let addr = eth_address(&vk);
        if !cfg.signers.contains(&addr) || !seen.insert(addr) {
            return Err(OracleError::UntrustedFeedSigner);
        }
        signers.push(addr);
    }
    let r = ChainlinkV3Report::decode(&env.report_blob)?;
    if r.feed_id != policy.feed_id {
        return Err(bad("unexpected Chainlink feed ID"));
    }
    if !(cfg.active_from_s..=cfg.active_until_s).contains(&r.observations_s) {
        return Err(OracleError::UntrustedFeedSigner);
    }
    let obs_us = r.observations_s as u64 * 1_000_000;
    let now_s = now_us / 1_000_000;
    if r.valid_from_s > r.observations_s || r.expires_at_s < r.observations_s || (r.expires_at_s as u64) < now_s {
        return Err(OracleError::StaleObservation);
    }
    if obs_us > now_us.saturating_add(policy.max_future_skew_us) || now_us.saturating_sub(obs_us) > policy.max_age_us {
        return Err(OracleError::StaleObservation);
    }
    if r.benchmark_price <= 0 || r.bid <= 0 || r.ask < r.bid || r.bid > r.benchmark_price || r.ask < r.benchmark_price {
        return Err(bad("invalid Chainlink price/bid/ask ordering"));
    }
    let scale = 10i128.pow(CHAINLINK_V3_DECIMALS - 8);
    let price_e8 = u64::try_from(r.benchmark_price / scale).map_err(|_| bad("Chainlink price out of range"))?;
    if price_e8 == 0 || price_e8 > 10_000_000_000_000_000 {
        return Err(bad("Chainlink price out of range"));
    }
    let spread_bps = u64::try_from(((r.ask - r.bid) as u128 * 10_000).div_ceil(r.benchmark_price as u128))
        .map_err(|_| bad("Chainlink spread out of range"))?;
    if spread_bps > policy.max_spread_bps {
        return Err(OracleError::ConfidenceTooWide { conf_bps: spread_bps, max_bps: policy.max_spread_bps });
    }
    Ok(VerifiedChainlinkReport {
        feed_id: r.feed_id,
        config_digest: env.config_digest(),
        signers,
        observations_us: obs_us,
        valid_from_us: r.valid_from_s as u64 * 1_000_000,
        expires_at_us: r.expires_at_s as u64 * 1_000_000,
        benchmark_price_e18: r.benchmark_price,
        price_e8,
        spread_bps,
        full_report_sha256: Sha256::digest(full).into(),
        signed_hash: h,
        native_chainlink_signature_verified: true,
        onchain_config_verified: false,
    })
}

/// Deterministic harness helper: sign a v3 report with the given DON member
/// secrets (`secrets.len()` must equal `f + 1` for a verifiable report).
pub fn build_signed_v3_report(
    report: &ChainlinkV3Report,
    config_digest: [u8; 32],
    epoch_round: [u8; 32],
    extra: [u8; 32],
    secrets: &[[u8; 32]],
) -> Vec<u8> {
    use k256::ecdsa::SigningKey;
    let mut env = ChainlinkFullReport {
        report_context: [config_digest, epoch_round, extra],
        report_blob: report.encode(),
        rs: Vec::new(),
        ss: Vec::new(),
        raw_vs: [0; 32],
    };
    let h = env.signed_hash();
    for (i, sk) in secrets.iter().enumerate() {
        let key = SigningKey::from_bytes(sk.into()).expect("valid test key");
        let (sig, rec) = key.sign_prehash_recoverable(&h).expect("sign");
        let (sig, rec) = match sig.normalize_s() {
            Some(n) => (n, RecoveryId::new(!rec.is_y_odd(), rec.is_x_reduced())),
            None => (sig, rec),
        };
        env.rs.push(sig.r().to_bytes().into());
        env.ss.push(sig.s().to_bytes().into());
        env.raw_vs[i] = rec.to_byte();
    }
    env.encode()
}

/// Address of a DON member secret (harness helper).
pub fn address_of_secret(sk: &[u8; 32]) -> EthAddress {
    let key = k256::ecdsa::SigningKey::from_bytes(sk.into()).expect("valid key");
    eth_address(key.verifying_key())
}

/// Chainlink Data Streams API HMAC headers:
/// `Authorization: <client id>`, `X-Authorization-Timestamp: <ms>`,
/// `X-Authorization-Signature-SHA256: hex(HMAC_SHA256(secret,
/// "<METHOD> <path?query> <hex(sha256(body))> <client id> <ms>"))`.
pub fn data_streams_auth_signature(
    method: &str,
    path_and_query: &str,
    body: &[u8],
    client_id: &str,
    timestamp_ms: u64,
    secret: &[u8],
) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    let msg = format!("{method} {path_and_query} {body_hash} {client_id} {timestamp_ms}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Synthetic BTC/USD v3 feed ID used only by fixtures (schema prefix 0x0003).
pub const SYNTHETIC_BTC_USD_V3_FEED_ID: [u8; 32] = {
    let mut f = [0x5au8; 32];
    f[0] = 0;
    f[1] = 3;
    f
};

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: [u8; 32] = [0x07; 32];
    fn secrets() -> Vec<[u8; 32]> {
        (1..=4u8).map(|i| [i + 0x40; 32]).collect()
    }
    fn registry() -> PinnedDonRegistry {
        PinnedDonRegistry::new(vec![DonConfig {
            config_digest: DIGEST,
            f: 1,
            signers: secrets().iter().map(address_of_secret).collect(),
            active_from_s: 0,
            active_until_s: u32::MAX,
        }])
        .unwrap()
    }
    fn policy() -> ChainlinkStreamPolicy {
        ChainlinkStreamPolicy { feed_id: SYNTHETIC_BTC_USD_V3_FEED_ID, max_age_us: 2_000_000, max_future_skew_us: 100_000, max_spread_bps: 50 }
    }
    fn report(obs: u32) -> ChainlinkV3Report {
        let p = 100_000i128 * 10i128.pow(18);
        ChainlinkV3Report {
            feed_id: SYNTHETIC_BTC_USD_V3_FEED_ID,
            valid_from_s: obs,
            observations_s: obs,
            native_fee: 1,
            link_fee: 2,
            expires_at_s: obs + 86_400,
            benchmark_price: p,
            bid: p - 10i128.pow(18),
            ask: p + 10i128.pow(18),
        }
    }

    #[test]
    fn abi_round_trip_and_valid_two_signer_report() {
        let full = build_signed_v3_report(&report(1_800_000_000), DIGEST, [1; 32], [0; 32], &secrets()[..2]);
        let env = ChainlinkFullReport::decode(&full).unwrap();
        assert_eq!(env.encode(), full);
        let v = verify_chainlink_v3_report(&full, &registry(), &policy(), 1_800_000_000_500_000).unwrap();
        assert_eq!(v.price_e8, 10_000_000_000_000);
        assert_eq!(v.spread_bps, 1);
        assert_eq!(v.signers.len(), 2);
        assert!(v.native_chainlink_signature_verified && !v.onchain_config_verified);
    }

    #[test]
    fn rejects_wrong_count_duplicate_unknown_and_tampered() {
        let r = report(1_800_000_000);
        let now = 1_800_000_000_500_000;
        // f + 1 = 2 exactly: one or three signatures fail.
        for n in [1usize, 3] {
            let full = build_signed_v3_report(&r, DIGEST, [1; 32], [0; 32], &secrets()[..n]);
            assert!(matches!(verify_chainlink_v3_report(&full, &registry(), &policy(), now), Err(OracleError::InsufficientQuorum { .. })));
        }
        // Duplicate signer.
        let s = secrets();
        let full = build_signed_v3_report(&r, DIGEST, [1; 32], [0; 32], &[s[0], s[0]]);
        assert_eq!(verify_chainlink_v3_report(&full, &registry(), &policy(), now), Err(OracleError::UntrustedFeedSigner));
        // Signer outside the DON.
        let full = build_signed_v3_report(&r, DIGEST, [1; 32], [0; 32], &[s[0], [0x77; 32]]);
        assert_eq!(verify_chainlink_v3_report(&full, &registry(), &policy(), now), Err(OracleError::UntrustedFeedSigner));
        // Unknown config digest.
        let full = build_signed_v3_report(&r, [9; 32], [1; 32], [0; 32], &s[..2]);
        assert_eq!(verify_chainlink_v3_report(&full, &registry(), &policy(), now), Err(OracleError::UntrustedFeedSigner));
        // Tamper with the price word after signing: recovery yields other addresses.
        let mut full = build_signed_v3_report(&r, DIGEST, [1; 32], [0; 32], &s[..2]);
        let blob_start = 8 * 32;
        full[blob_start + 6 * 32 + 31] ^= 1;
        assert!(verify_chainlink_v3_report(&full, &registry(), &policy(), now).is_err());
        // Tamper with report context (epoch/round) after signing.
        let mut full = build_signed_v3_report(&r, DIGEST, [1; 32], [0; 32], &s[..2]);
        full[32] ^= 1;
        assert!(verify_chainlink_v3_report(&full, &registry(), &policy(), now).is_err());
    }

    #[test]
    fn malformed_abi_is_rejected() {
        let full = build_signed_v3_report(&report(1_800_000_000), DIGEST, [1; 32], [0; 32], &secrets()[..2]);
        let now = 1_800_000_000_500_000;
        for cut in [0usize, 31, 224, full.len() - 32, full.len() - 1] {
            assert!(verify_chainlink_v3_report(&full[..cut], &registry(), &policy(), now).is_err());
        }
        let mut longer = full.clone();
        longer.extend([0u8; 32]);
        assert!(verify_chainlink_v3_report(&longer, &registry(), &policy(), now).is_err());
        let mut odd = full.clone();
        odd[3 * 32 + 31] = 0xe8; // blob offset 232: non-canonical head
        assert!(verify_chainlink_v3_report(&odd, &registry(), &policy(), now).is_err());
        let mut huge = full.clone();
        huge[4 * 32] = 0xff; // rs offset high bits
        assert!(verify_chainlink_v3_report(&huge, &registry(), &policy(), now).is_err());
        let mut vs = full.clone();
        vs[6 * 32 + 5] = 1; // unused rawVs byte
        assert!(verify_chainlink_v3_report(&vs, &registry(), &policy(), now).is_err());
    }

    #[test]
    fn freshness_expiry_spread_and_schema() {
        let s = secrets();
        let mut r = report(1_800_000_000);
        let ok = |r: &ChainlinkV3Report, now: u64| {
            let full = build_signed_v3_report(r, DIGEST, [1; 32], [0; 32], &s[..2]);
            verify_chainlink_v3_report(&full, &registry(), &policy(), now)
        };
        assert_eq!(ok(&r, 1_800_000_002_000_001), Err(OracleError::StaleObservation));
        assert_eq!(ok(&r, 1_799_999_999_899_999), Err(OracleError::StaleObservation));
        r.expires_at_s = r.observations_s - 1;
        assert_eq!(ok(&r, 1_800_000_000_000_000), Err(OracleError::StaleObservation));
        let mut r = report(1_800_000_000);
        r.ask = r.benchmark_price + r.benchmark_price / 100;
        assert!(matches!(ok(&r, 1_800_000_000_000_000), Err(OracleError::ConfidenceTooWide { .. })));
        let mut r = report(1_800_000_000);
        r.feed_id[1] = 2;
        assert!(ok(&r, 1_800_000_000_000_000).is_err());
        let mut r = report(1_800_000_000);
        r.benchmark_price = -1;
        assert!(ok(&r, 1_800_000_000_000_000).is_err());
    }

    #[test]
    fn high_s_rejected_even_though_ecrecover_accepts_it() {
        let s = secrets();
        let full = build_signed_v3_report(&report(1_800_000_000), DIGEST, [1; 32], [0; 32], &s[..2]);
        let mut env = ChainlinkFullReport::decode(&full).unwrap();
        let sig = Signature::from_scalars(env.rs[0], env.ss[0]).unwrap();
        let neg = -*sig.s();
        env.ss[0] = neg.to_bytes().into();
        env.raw_vs[0] ^= 1;
        assert!(verify_chainlink_v3_report(&env.encode(), &registry(), &policy(), 1_800_000_000_000_000).is_err());
    }

    #[test]
    fn registry_requires_byzantine_bound() {
        let addrs: Vec<_> = secrets().iter().map(address_of_secret).collect();
        let mk = |f, signers: Vec<EthAddress>| PinnedDonRegistry::new(vec![DonConfig { config_digest: DIGEST, f, signers, active_from_s: 0, active_until_s: 1 }]);
        assert!(mk(1, addrs[..3].to_vec()).is_err());
        assert!(mk(1, vec![addrs[0], addrs[0], addrs[1], addrs[2]]).is_err());
        assert!(mk(1, addrs.clone()).is_ok());
    }

    #[test]
    fn hmac_header_is_stable() {
        let a = data_streams_auth_signature("GET", "/api/v1/reports/latest?feedID=0x00", b"", "client", 1_700_000_000_000, b"secret");
        let b = data_streams_auth_signature("GET", "/api/v1/reports/latest?feedID=0x00", b"", "client", 1_700_000_000_001, b"secret");
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
