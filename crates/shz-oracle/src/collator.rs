//! HFT-06 deterministic oracle collator.
//!
//! Inputs are raw signed provider reports with a local arrival timestamp
//! (live socket receive time, or the recorded value in replay mode). Each
//! report is authenticated by the native verifier of its source BEFORE any
//! field is used, normalized to `price_e8`, and retained verbatim with its
//! SHA256 digest, source timestamp and arrival timestamp.
//!
//! Slot `k` closes at `T_k = origin + (k-1) * 200 ms` (the HFT-04 packet
//! schedule). The slot sees exactly the reports that *arrived* at or before
//! `T_k`; replay of the same arrival-ordered recording therefore yields the
//! same packet chain bit-for-bit. Each slot is an explicit VALID or HOLD
//! [`Packet`]. HOLD reasons: 1 missing/stale source, 2 cross-source
//! skew/dispersion, 3 operator emergency HOLD. TradeLayer VWAP is not a slot
//! input: [`audit_against_tradelayer`] compares closed slots with a slower
//! witness-signed VWAP window.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use shz_dlc::tagged_hash;

use crate::{
    OracleError,
    chainlink_streams::{ChainlinkStreamPolicy, PinnedDonRegistry, verify_chainlink_v3_report},
    hft_packets::{MAX_SOURCE_AGE_US, MAX_SOURCE_SKEW_US, Mark, Packet, Policy, Source},
    pyth_lazer::{PinnedPythSignerRegistry, PythProBtcUsdPolicy, verify_pyth_pro_btc_usd_solana_envelope},
    tradelayer::TradeLayerVwapProof,
};

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    PythPro,
    ChainlinkStreams,
}
impl SourceKind {
    pub const ALL: [SourceKind; 2] = [SourceKind::PythPro, SourceKind::ChainlinkStreams];
    fn idx(self) -> usize {
        match self {
            Self::PythPro => 0,
            Self::ChainlinkStreams => 1,
        }
    }
    fn tag(self) -> u8 {
        self.idx() as u8 + 1
    }
}

/// One raw provider frame and its local arrival time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawReport {
    pub source: SourceKind,
    pub arrival_us: u64,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
}

/// Retained, authenticated and normalized observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub source: SourceKind,
    /// Domain-separated digest of (source, raw bytes). Packet `report` field.
    pub report_digest: Hash,
    /// Plain SHA256 of the raw signed bytes (provider-native identity).
    pub raw_sha256: Hash,
    pub price_e8: u64,
    pub source_us: u64,
    pub arrival_us: u64,
    /// Signer identity: Pyth Ed25519 key, or sorted concatenation of DON addresses.
    #[serde(with = "hex_bytes")]
    pub signer: Vec<u8>,
    /// Confidence (Pyth) or bid/ask spread (Chainlink), bps.
    pub uncertainty_bps: u64,
}

pub fn report_digest(source: SourceKind, raw: &[u8]) -> Hash {
    let mut b = Vec::with_capacity(raw.len() + 1);
    b.push(source.tag());
    b.extend(raw);
    tagged_hash(b"SHZ/HFT06/SOURCE-REPORT/V1", &b)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollatorConfig {
    pub pyth_registry: PinnedPythSignerRegistry,
    pub pyth_policy: PythProBtcUsdPolicy,
    pub chainlink_registry: PinnedDonRegistry,
    pub chainlink_policy: ChainlinkStreamPolicy,
    /// Bound on (source timestamp - arrival). Reports from the future are rejected.
    pub max_future_skew_us: u64,
    /// Number of closed slots retained in memory (raw reports go to the archive sink).
    pub retain_slots: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    MissingOrStale = 1,
    SkewOrDispersion = 2,
    Emergency = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotRecord {
    pub seq: u64,
    pub boundary_us: u64,
    pub digest: Hash,
    pub previous: Hash,
    pub hold: Option<HoldReason>,
    pub mid_e8: Option<u64>,
    /// Report digests used (VALID) or the latest visible ones (HOLD), per source.
    pub inputs: [Option<Hash>; 2],
    #[serde(skip)]
    pub packet: Option<Packet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// Arrival time went backwards relative to the collator clock.
    ClockRegression,
    /// Exact report already ingested (replay); not an error for the stream.
    Duplicate,
    /// Source timestamp not strictly increasing for this source.
    NonMonotone,
    /// Report claims to be from the future relative to its arrival.
    FutureDated,
    /// Native authentication or policy failure.
    Rejected(OracleError),
}

/// Ingest statistics per source (accepted, duplicate, non-monotone, rejected).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceStats {
    pub accepted: u64,
    pub duplicate: u64,
    pub non_monotone: u64,
    pub future_dated: u64,
    pub rejected: u64,
}

pub struct Collator {
    cfg: CollatorConfig,
    policy: Policy,
    policy_id: Hash,
    clock_us: u64,
    latest: [Option<Observation>; 2],
    seen: BTreeSet<Hash>,
    next_seq: u64,
    previous: Hash,
    emergency: bool,
    closed: std::collections::VecDeque<SlotRecord>,
    pub stats: [SourceStats; 2],
}

impl Collator {
    pub fn new(cfg: CollatorConfig, policy: Policy) -> Result<Self, OracleError> {
        let policy_id = policy.id().map_err(|_| OracleError::InvalidObservation("invalid packet policy"))?;
        if cfg.retain_slots == 0 || cfg.max_future_skew_us > MAX_SOURCE_SKEW_US {
            return Err(OracleError::InvalidObservation("invalid collator configuration"));
        }
        Ok(Self {
            cfg,
            policy,
            policy_id,
            clock_us: 0,
            latest: [None, None],
            seen: BTreeSet::new(),
            next_seq: 1,
            previous: [0; 32],
            emergency: false,
            closed: Default::default(),
            stats: Default::default(),
        })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn next_boundary_us(&self) -> u64 {
        self.policy.fast_at(self.next_seq).expect("bounded schedule")
    }
    pub fn latest(&self, s: SourceKind) -> Option<&Observation> {
        self.latest[s.idx()].as_ref()
    }
    pub fn closed(&self) -> impl Iterator<Item = &SlotRecord> {
        self.closed.iter()
    }
    /// Operator emergency HOLD: every slot closed while set is HOLD(3).
    pub fn set_emergency(&mut self, on: bool) {
        self.emergency = on;
    }

    /// Authenticate and normalize; slots whose boundary precedes this arrival
    /// are closed first, so the report can only affect later slots.
    pub fn ingest(&mut self, r: &RawReport) -> (Vec<SlotRecord>, Result<Observation, IngestError>) {
        if r.arrival_us < self.clock_us {
            return (Vec::new(), Err(IngestError::ClockRegression));
        }
        // A report arriving exactly at T_k is visible to slot k.
        let closed = self.advance_before(r.arrival_us);
        self.clock_us = r.arrival_us;
        let res = self.accept(r);
        let st = &mut self.stats[r.source.idx()];
        match &res {
            Ok(_) => st.accepted += 1,
            Err(IngestError::Duplicate) => st.duplicate += 1,
            Err(IngestError::NonMonotone) => st.non_monotone += 1,
            Err(IngestError::FutureDated) => st.future_dated += 1,
            Err(_) => st.rejected += 1,
        }
        (closed, res)
    }

    fn accept(&mut self, r: &RawReport) -> Result<Observation, IngestError> {
        let digest = report_digest(r.source, &r.bytes);
        if self.seen.contains(&digest) {
            return Err(IngestError::Duplicate);
        }
        let obs = match r.source {
            SourceKind::PythPro => {
                let v = verify_pyth_pro_btc_usd_solana_envelope(&r.bytes, &self.cfg.pyth_registry, &self.cfg.pyth_policy, r.arrival_us)
                    .map_err(IngestError::Rejected)?;
                Observation {
                    source: r.source,
                    report_digest: digest,
                    raw_sha256: sha256(&r.bytes),
                    price_e8: v.price_e8,
                    source_us: v.feed_update_time_us,
                    arrival_us: r.arrival_us,
                    signer: hex::decode(&v.signer_pubkey_hex).unwrap_or_default(),
                    uncertainty_bps: v.confidence_bps,
                }
            }
            SourceKind::ChainlinkStreams => {
                let v = verify_chainlink_v3_report(&r.bytes, &self.cfg.chainlink_registry, &self.cfg.chainlink_policy, r.arrival_us)
                    .map_err(IngestError::Rejected)?;
                let mut signers = v.signers.clone();
                signers.sort();
                Observation {
                    source: r.source,
                    report_digest: digest,
                    raw_sha256: v.full_report_sha256,
                    price_e8: v.price_e8,
                    source_us: v.observations_us,
                    arrival_us: r.arrival_us,
                    signer: signers.concat(),
                    uncertainty_bps: v.spread_bps,
                }
            }
        };
        if obs.source_us > r.arrival_us.saturating_add(self.cfg.max_future_skew_us) {
            return Err(IngestError::FutureDated);
        }
        if let Some(prev) = &self.latest[r.source.idx()] {
            // Second-granular Chainlink v3 may repeat a second with a new
            // report; only strictly newer source time replaces the latest.
            if obs.source_us <= prev.source_us {
                self.seen.insert(digest);
                return Err(IngestError::NonMonotone);
            }
        }
        self.seen.insert(digest);
        self.latest[r.source.idx()] = Some(obs.clone());
        Ok(obs)
    }

    fn advance_before(&mut self, arrival_us: u64) -> Vec<SlotRecord> {
        let mut out = Vec::new();
        while self.next_boundary_us() < arrival_us {
            out.push(self.close_next());
        }
        out
    }

    /// Close every slot with boundary <= `now_us` (timer-driven close; an
    /// arrival exactly at `now_us` that has not been ingested yet would be
    /// excluded, so live callers close only after draining the socket).
    pub fn close_through(&mut self, now_us: u64) -> Result<Vec<SlotRecord>, IngestError> {
        if now_us < self.clock_us {
            return Err(IngestError::ClockRegression);
        }
        self.clock_us = now_us;
        let mut out = Vec::new();
        while self.next_boundary_us() <= now_us {
            out.push(self.close_next());
        }
        Ok(out)
    }

    fn close_next(&mut self) -> SlotRecord {
        let seq = self.next_seq;
        let t = self.next_boundary_us();
        let [p, c] = &self.latest;
        let inputs = [p.as_ref().map(|o| o.report_digest), c.as_ref().map(|o| o.report_digest)];
        let decide = || -> Result<(Source, Source), HoldReason> {
            if self.emergency {
                return Err(HoldReason::Emergency);
            }
            let (Some(p), Some(c)) = (p, c) else { return Err(HoldReason::MissingOrStale) };
            for o in [p, c] {
                if o.source_us > t || t - o.source_us > MAX_SOURCE_AGE_US {
                    return Err(HoldReason::MissingOrStale);
                }
            }
            if p.source_us.abs_diff(c.source_us) > MAX_SOURCE_SKEW_US
                || p.price_e8.abs_diff(c.price_e8) as u128 * 20_000 > 50 * (p.price_e8 as u128 + c.price_e8 as u128)
            {
                return Err(HoldReason::SkewOrDispersion);
            }
            let s = |o: &Observation| Source { report: o.report_digest, published_us: o.source_us, price_e8: o.price_e8 };
            Ok((s(p), s(c)))
        };
        let (mark, hold) = match decide() {
            Ok((pyth, chainlink)) => (Mark::Valid { pyth, chainlink }, None),
            Err(r) => (Mark::Hold { reason: r as u8 }, Some(r)),
        };
        let packet = Packet { policy: self.policy_id, seq, previous: self.previous, mark };
        let digest = packet.digest();
        let rec = SlotRecord {
            seq,
            boundary_us: t,
            digest,
            previous: self.previous,
            hold,
            mid_e8: packet.price(),
            inputs,
            packet: Some(packet),
        };
        self.previous = digest;
        self.next_seq += 1;
        self.closed.push_back(rec.clone());
        while self.closed.len() > self.cfg.retain_slots {
            self.closed.pop_front();
        }
        rec
    }
}

fn sha256(b: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).into()
}

/// Rolling digest over a closed-slot sequence: replay determinism receipt.
pub fn chain_receipt(slots: &[SlotRecord]) -> Hash {
    let mut b = Vec::with_capacity(slots.len() * 40);
    for s in slots {
        b.extend(s.seq.to_le_bytes());
        b.extend(s.digest);
    }
    tagged_hash(b"SHZ/HFT06/SLOT-CHAIN/V1", &b)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub window_close_unix: u64,
    pub tradelayer_vwap_usd: u64,
    pub valid_slots: u64,
    pub hold_slots: u64,
    /// Integer mean of VALID slot mids inside the window, whole USD.
    pub fast_mean_usd: Option<u64>,
    pub deviation_bps: Option<u64>,
    pub breach: bool,
}

/// Slow independent audit: compare the fast VALID marks over
/// `[window_close - window_s, window_close)` with a witness-quorum
/// TradeLayer VWAP. A breach is an operator alarm (and grounds for
/// emergency HOLD), never an automatic price substitution.
pub fn audit_against_tradelayer(
    slots: &[SlotRecord],
    proof: &TradeLayerVwapProof,
    trusted_witnesses: &[[u8; 32]],
    min_witnesses: usize,
    window_s: u64,
    max_deviation_bps: u64,
) -> Result<AuditReport, OracleError> {
    proof.verify_witness_quorum(trusted_witnesses, min_witnesses)?;
    let end = proof.window_close_unix.checked_mul(1_000_000).ok_or(OracleError::InvalidObservation("window overflow"))?;
    let start = end.saturating_sub(window_s.saturating_mul(1_000_000));
    let mut sum = 0u128;
    let (mut valid, mut hold) = (0u64, 0u64);
    for s in slots.iter().filter(|s| (start..end).contains(&s.boundary_us)) {
        match s.mid_e8 {
            Some(m) => {
                sum += m as u128;
                valid += 1
            }
            None => hold += 1,
        }
    }
    let fast_mean_usd = (valid > 0).then(|| (sum / valid as u128 / 100_000_000) as u64);
    let deviation_bps = fast_mean_usd.map(|m| {
        (m.abs_diff(proof.vwap_price_usd) as u128 * 10_000).div_ceil(proof.vwap_price_usd.max(1) as u128) as u64
    });
    Ok(AuditReport {
        window_close_unix: proof.window_close_unix,
        tradelayer_vwap_usd: proof.vwap_price_usd,
        valid_slots: valid,
        hold_slots: hold,
        fast_mean_usd,
        deviation_bps,
        breach: deviation_bps.is_some_and(|d| d > max_deviation_bps),
    })
}

/// Deterministic synthetic recording for CI and local development.
/// Keys are fixed test secrets; prices follow a bounded integer walk.
/// Nothing here is provider data.
pub mod fixture {
    use super::*;
    use crate::{
        chainlink_streams::{ChainlinkV3Report, DonConfig, SYNTHETIC_BTC_USD_V3_FEED_ID, address_of_secret, build_signed_v3_report},
        pyth_lazer::{PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS, build_signed_pyth_pro_btc_usd_envelope},
    };
    use shz_dlc::pubkey_x_from_secret;

    pub const PYTH_SECRET: [u8; 32] = [0x71; 32];
    pub const DON_SECRETS: [[u8; 32]; 4] = [[0x41; 32], [0x42; 32], [0x43; 32], [0x44; 32]];
    pub const DON_DIGEST: [u8; 32] = [0x07; 32];
    pub const FEDERATION_SECRETS: [[u8; 32]; 5] = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];

    pub fn config() -> CollatorConfig {
        let (_, pyth_pk) = build_signed_pyth_pro_btc_usd_envelope(&PYTH_SECRET, 1, 1, 3, 1, 1, -8, 0);
        CollatorConfig {
            pyth_registry: PinnedPythSignerRegistry::new_static(vec![pyth_pk]).unwrap(),
            pyth_policy: PythProBtcUsdPolicy { max_age_us: 2_000_000, ..Default::default() },
            chainlink_registry: PinnedDonRegistry::new(vec![DonConfig {
                config_digest: DON_DIGEST,
                f: 1,
                signers: DON_SECRETS.iter().map(address_of_secret).collect(),
                active_from_s: 0,
                active_until_s: u32::MAX,
            }])
            .unwrap(),
            chainlink_policy: ChainlinkStreamPolicy {
                feed_id: SYNTHETIC_BTC_USD_V3_FEED_ID,
                max_age_us: 3_000_000,
                max_future_skew_us: 100_000,
                max_spread_bps: 50,
            },
            max_future_skew_us: 100_000,
            retain_slots: 100_000,
        }
    }

    pub fn policy(origin_us: u64) -> Policy {
        Policy {
            network: [9; 32],
            market: [8; 32],
            epoch: 1,
            origin_us,
            members: std::array::from_fn(|i| pubkey_x_from_secret(&FEDERATION_SECRETS[i]).unwrap()),
        }
    }

    fn mix(mut x: u64) -> u64 {
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51afd7ed558ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
        x ^ (x >> 33)
    }

    /// Deterministic price path: a triangle wave (+/- $600 over 120 s) plus
    /// bounded per-tick noise; a pure function of (seed, t), so chunks join
    /// continuously.
    pub fn price_e8(seed: u64, t_us: u64) -> i64 {
        let phase = (t_us / 1_000) % 120_000;
        let tri = if phase < 60_000 { phase as i64 } else { 120_000 - phase as i64 } - 30_000;
        let noise = (mix(seed ^ t_us) % 2_001) as i64 - 1_000;
        10_000_000_000_000 + tri * 2_000_000 + noise * 1_000_000
    }

    /// Synthetic traffic for `[from_us, to_us)` on the 200 ms grid. Pyth
    /// every 200 ms (+2..42 ms network jitter), Chainlink every 400 ms with
    /// second-granular observation time. Fault cycle every 30 s (relative to
    /// `origin_us`): exact replay of a Pyth frame at +5 s, tampered Pyth
    /// frame at +7 s, 1.5 s Chainlink outage at +10 s, 60 bps Chainlink
    /// dispersion at +20 s.
    pub fn recording_range(origin_us: u64, from_us: u64, to_us: u64, seed: u64) -> Vec<RawReport> {
        let mut out = Vec::new();
        let mut t = from_us.div_ceil(200_000) * 200_000;
        while t < to_us {
            let price = price_e8(seed, t);
            let in_cycle = t.wrapping_sub(origin_us) % 30_000_000;
            let jitter = mix(seed.wrapping_add(t)) % 40_000;
            let (raw, _) = build_signed_pyth_pro_btc_usd_envelope(
                &PYTH_SECRET,
                t,
                t,
                PYTH_PRO_CHANNEL_FIXED_200MS,
                PYTH_PRO_BTC_USD_FEED_ID,
                price,
                -8,
                price / 20_000,
            );
            let arrival = t + 2_000 + jitter;
            if in_cycle == 5_000_000 {
                out.push(RawReport { source: SourceKind::PythPro, arrival_us: arrival + 1, bytes: raw.clone() });
            }
            if in_cycle == 7_000_000 {
                let mut bad = raw.clone();
                let n = bad.len();
                bad[n - 1] ^= 0x55;
                out.push(RawReport { source: SourceKind::PythPro, arrival_us: arrival, bytes: bad });
            }
            out.push(RawReport { source: SourceKind::PythPro, arrival_us: arrival, bytes: raw });
            if t % 400_000 == 0 && !(10_000_000..11_500_000).contains(&in_cycle) {
                let obs_s = (t / 1_000_000) as u32;
                let dispersion = if (20_000_000..20_400_000).contains(&in_cycle) { 60 } else { 1 };
                let p = (price as i128 + price as i128 * (dispersion - 1) / 10_000) * 10_000_000_000;
                let half = p / 20_000;
                let rep = ChainlinkV3Report {
                    feed_id: SYNTHETIC_BTC_USD_V3_FEED_ID,
                    valid_from_s: obs_s,
                    observations_s: obs_s,
                    native_fee: 0,
                    link_fee: 0,
                    expires_at_s: obs_s + 86_400,
                    benchmark_price: p,
                    bid: p - half,
                    ask: p + half,
                };
                let mut ctx = [0u8; 32];
                ctx[24..].copy_from_slice(&t.to_be_bytes());
                let full = build_signed_v3_report(&rep, DON_DIGEST, ctx, [0; 32], &DON_SECRETS[..2]);
                out.push(RawReport { source: SourceKind::ChainlinkStreams, arrival_us: t + 15_000 + mix(seed ^ t ^ 0xc1) % 30_000, bytes: full });
            }
            t += 200_000;
        }
        out.sort_by_key(|r| r.arrival_us);
        out
    }

    /// `seconds` of traffic from 400 ms before `origin_us`.
    pub fn recording(origin_us: u64, seconds: u64, seed: u64) -> Vec<RawReport> {
        recording_range(origin_us, origin_us.saturating_sub(400_000), origin_us + seconds * 1_000_000, seed)
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hft_packets::{CADENCE_US, Certificate, Signer};

    const ORIGIN: u64 = 1_800_000_000_000_000;

    fn run(rec: &[RawReport]) -> (Collator, Vec<SlotRecord>) {
        let mut c = Collator::new(fixture::config(), fixture::policy(ORIGIN)).unwrap();
        let mut slots = Vec::new();
        for r in rec {
            slots.extend(c.ingest(r).0);
        }
        let last = rec.last().unwrap().arrival_us;
        slots.extend(c.close_through(last).unwrap());
        (c, slots)
    }

    #[test]
    fn replay_is_deterministic_and_every_slot_is_explicit() {
        let rec = fixture::recording(ORIGIN, 60, 7);
        let (c, a) = run(&rec);
        let (_, b) = run(&rec);
        assert_eq!(chain_receipt(&a), chain_receipt(&b));
        assert!(a.len() >= 295, "{}", a.len());
        for w in a.windows(2) {
            assert_eq!(w[1].seq, w[0].seq + 1);
            assert_eq!(w[1].previous, w[0].digest);
            assert_eq!(w[1].boundary_us - w[0].boundary_us, CADENCE_US);
        }
        let valid = a.iter().filter(|s| s.hold.is_none()).count();
        let stale = a.iter().filter(|s| s.hold == Some(HoldReason::MissingOrStale)).count();
        let disp = a.iter().filter(|s| s.hold == Some(HoldReason::SkewOrDispersion)).count();
        // Chainlink v3 observation timestamps are whole seconds, so the HFT-04
        // 500 ms cross-source skew bound HOLDs a large share of slots even with
        // healthy feeds (documented calibration finding, not a fixture bug).
        assert!(valid > a.len() / 3, "valid={valid}");
        assert!(stale > 0 && disp > 0, "stale={stale} disp={disp}");
        assert_eq!(c.stats[0].duplicate + c.stats[1].duplicate, 2);
        assert_eq!(c.stats[0].rejected + c.stats[1].rejected, 2);
    }

    #[test]
    fn valid_and_hold_packets_are_votable_by_federation_signers() {
        let rec = fixture::recording(ORIGIN, 10, 3);
        let (c, slots) = run(&rec);
        let mut signers: Vec<_> =
            (0..5).map(|i| Signer::new(c.policy(), i, fixture::FEDERATION_SECRETS[i as usize]).unwrap()).collect();
        for s in &slots {
            let p = s.packet.clone().unwrap();
            let votes = signers.iter_mut().take(4).map(|x| x.vote(c.policy(), &p).unwrap()).collect();
            assert_eq!(Certificate { packet: p, votes }.verify(c.policy()).unwrap(), s.digest);
        }
    }

    #[test]
    fn arrival_at_boundary_is_visible_after_is_not() {
        let rec = fixture::recording(ORIGIN, 3, 11);
        let mut c = Collator::new(fixture::config(), fixture::policy(ORIGIN)).unwrap();
        for r in rec.iter().filter(|r| r.arrival_us < ORIGIN) {
            let _ = c.ingest(r);
        }
        let before = c.latest(SourceKind::PythPro).cloned();
        // A late-arriving fresh report at T_1 + 1 must not influence slot 1.
        let late = rec.iter().find(|r| r.arrival_us > ORIGIN && r.source == SourceKind::PythPro).unwrap().clone();
        let (closed, res) = c.ingest(&RawReport { arrival_us: ORIGIN + 1, ..late });
        assert!(res.is_ok());
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].inputs[0], before.map(|o| o.report_digest));
        assert_eq!(c.ingest(&RawReport { arrival_us: ORIGIN, ..rec[0].clone() }).1, Err(IngestError::ClockRegression));
    }

    #[test]
    fn emergency_hold_and_non_monotone_source() {
        let rec = fixture::recording(ORIGIN, 4, 5);
        let mut c = Collator::new(fixture::config(), fixture::policy(ORIGIN)).unwrap();
        c.set_emergency(true);
        let mut slots = Vec::new();
        let mut nonmono = 0;
        for r in &rec {
            let (s, res) = c.ingest(r);
            slots.extend(s);
            if res == Err(IngestError::NonMonotone) {
                nonmono += 1;
            }
        }
        assert!(slots.iter().all(|s| s.hold == Some(HoldReason::Emergency)));
        // Chainlink reports every 500 ms with second-granular timestamps:
        // the second report in each second is retained as non-monotone.
        assert!(nonmono > 0);
    }

    #[test]
    fn tradelayer_audit_flags_divergence() {
        use crate::tradelayer::{TradeLayerFill, TradeLayerVwapConfig, build_tradelayer_vwap_proof};
        use shz_dlc::pubkey_x_from_secret;
        let rec = fixture::recording(ORIGIN, 20, 9);
        let (_, slots) = run(&rec);
        let w = [[0x31u8; 32], [0x32u8; 32]];
        let trusted = [pubkey_x_from_secret(&w[0]).unwrap(), pubkey_x_from_secret(&w[1]).unwrap()];
        let close = ORIGIN / 1_000_000 + 20;
        let fills = |p: u64| -> Vec<TradeLayerFill> {
            (0..3u8)
                .map(|i| TradeLayerFill {
                    txid: [i + 1; 32],
                    block_height: 1 + i as u64,
                    property_pair: "TL-BTC/USD".into(),
                    price_usd: p,
                    volume_sats: 1_000_000,
                    maker_id: [i * 2 + 1; 20],
                    taker_id: [i * 2 + 2; 20],
                })
                .collect()
        };
        let mean = slots.iter().filter_map(|s| s.mid_e8).map(|m| m as u128).sum::<u128>()
            / slots.iter().filter(|s| s.mid_e8.is_some()).count() as u128
            / 100_000_000;
        let (good, _) = build_tradelayer_vwap_proof("TL-BTC/USD", 1, 3, close, &fills(mean as u64), &TradeLayerVwapConfig::default(), &w).unwrap();
        let a = audit_against_tradelayer(&slots, &good, &trusted, 2, 30, 100).unwrap();
        assert!(!a.breach && a.valid_slots > 0, "{a:?}");
        let (bad, _) = build_tradelayer_vwap_proof("TL-BTC/USD", 1, 3, close, &fills(mean as u64 * 103 / 100), &TradeLayerVwapConfig::default(), &w).unwrap();
        assert!(audit_against_tradelayer(&slots, &bad, &trusted, 2, 30, 100).unwrap().breach);
        assert!(audit_against_tradelayer(&slots, &good, &trusted[..1], 2, 30, 100).is_err());
    }

    #[test]
    fn recording_round_trips_as_jsonl() {
        let rec = fixture::recording(ORIGIN, 2, 1);
        let text: String = rec.iter().map(|r| serde_json::to_string(r).unwrap() + "\n").collect();
        let back: Vec<RawReport> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(back, rec);
    }
}
