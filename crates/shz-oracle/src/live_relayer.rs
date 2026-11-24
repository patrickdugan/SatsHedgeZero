//! Continuous `200 ms` Multi-Source Rolling Oracle Relayer (`Pyth Pro` + `Chainlink` -> `1h` -> `8h` `SHZIDX01`).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleTickSourceMode {
    LiveExternalFeed,
    DeterministicSignedSim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSourceOracleTick {
    pub tick_seq: u64,
    pub timestamp_ms: u64,
    pub source_mode: OracleTickSourceMode,
    pub pyth_price_e8: u64,
    pub chainlink_price_e8: u64,
    pub midpoint_price_e8: u64,
    pub midpoint_price_usd: u64,
    pub spread_bps: u32,
    pub status_valid: bool,
    pub pyth_report_hash_hex: String,
    pub chainlink_report_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedCheckpointSummary {
    pub start_hour: u64,
    pub checkpoint_root_hex: String,
    pub shzidx01_payload_hex: String,
    pub closing_midpoint_usd: u64,
    pub valid_hours: u8,
    pub hold_hours: u8,
}

/// Stateful `200 ms` rolling aggregator maintaining live marks, `<= 50 bps` spread gating,
/// hourly leaf commitments, and 8-hour `SHZIDX01` Bitcoin anchor payloads.
#[derive(Debug, Clone)]
pub struct RollingOracleAggregator {
    pub genesis_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub max_spread_bps: u32,
    pub tick_seq: u64,
    pub latest_tick: Option<MultiSourceOracleTick>,
    hourly_records: Vec<(u64, bool, u64, [u8; 32])>,
    pub sealed_checkpoints: Vec<SealedCheckpointSummary>,
}

impl RollingOracleAggregator {
    pub fn new(genesis_hash: [u8; 32], max_spread_bps: u32) -> Self {
        Self {
            genesis_hash,
            policy_hash: sha256_bytes(b"SHZ/INDEX03/POLICY/PYTH_CHAINLINK_50BPS/V1"),
            max_spread_bps,
            tick_seq: 0,
            latest_tick: None,
            hourly_records: Vec::new(),
            sealed_checkpoints: Vec::new(),
        }
    }

    /// Ingests a `200 ms` Pyth + Chainlink observation pair and enforces the `<= max_spread_bps` gate.
    pub fn ingest_tick(
        &mut self,
        timestamp_ms: u64,
        pyth_price_e8: u64,
        chainlink_price_e8: u64,
        source_mode: OracleTickSourceMode,
    ) -> MultiSourceOracleTick {
        self.tick_seq += 1;
        let mid_e8 = ((pyth_price_e8 as u128 + chainlink_price_e8 as u128) / 2) as u64;
        let diff_e8 = pyth_price_e8.abs_diff(chainlink_price_e8) as u128;
        let spread_bps = if mid_e8 > 0 {
            ((diff_e8 * 10_000) / (mid_e8 as u128)) as u32
        } else {
            10_000
        };
        let status_valid = mid_e8 > 0 && spread_bps <= self.max_spread_bps;

        let mut p_pre = b"SHZ/PYTH_TICK/V1:".to_vec();
        p_pre.extend_from_slice(&timestamp_ms.to_le_bytes());
        p_pre.extend_from_slice(&pyth_price_e8.to_le_bytes());
        let p_hash = sha256_bytes(&p_pre);

        let mut c_pre = b"SHZ/CL_TICK/V1:".to_vec();
        c_pre.extend_from_slice(&timestamp_ms.to_le_bytes());
        c_pre.extend_from_slice(&chainlink_price_e8.to_le_bytes());
        let c_hash = sha256_bytes(&c_pre);

        let tick = MultiSourceOracleTick {
            tick_seq: self.tick_seq,
            timestamp_ms,
            source_mode,
            pyth_price_e8,
            chainlink_price_e8,
            midpoint_price_e8: mid_e8,
            midpoint_price_usd: (mid_e8 / 100_000_000).max(1),
            spread_bps,
            status_valid,
            pyth_report_hash_hex: hex::encode(p_hash),
            chainlink_report_hash_hex: hex::encode(c_hash),
        };
        self.latest_tick = Some(tick.clone());
        tick
    }

    /// Seals one hourly leaf (`hour_id`), automatically emitting an 8-hour `SHZIDX01` checkpoint every 8 hours!
    pub fn seal_hour_from_latest(&mut self, hour_id: u64) -> Option<SealedCheckpointSummary> {
        let tick = self.latest_tick.as_ref()?;
        let p_hash: [u8; 32] = hex::decode(&tick.pyth_report_hash_hex).ok()?.try_into().ok()?;
        let c_hash: [u8; 32] = hex::decode(&tick.chainlink_report_hash_hex).ok()?.try_into().ok()?;
        let ts_us = tick.timestamp_ms * 1_000;

        let mut leaf = b"SHZ/HOUR/LEAF/V1".to_vec();
        leaf.extend_from_slice(&self.genesis_hash);
        leaf.extend_from_slice(&self.policy_hash);
        leaf.extend_from_slice(&hour_id.to_le_bytes());
        if tick.status_valid {
            leaf.extend_from_slice(&[1u8, 0u8]);
        } else {
            leaf.extend_from_slice(&[0u8, 1u8]); // HOLD
        }
        for v in [
            tick.pyth_price_e8,
            tick.chainlink_price_e8,
            tick.midpoint_price_e8,
            ts_us,
            ts_us,
        ] {
            leaf.extend_from_slice(&v.to_le_bytes());
        }
        leaf.extend_from_slice(&p_hash);
        leaf.extend_from_slice(&c_hash);
        let leaf_hash = sha256_bytes(&leaf);

        self.hourly_records
            .push((hour_id, tick.status_valid, tick.midpoint_price_usd, leaf_hash));
        if !self.hourly_records.len().is_multiple_of(8) {
            return None;
        }

        let window = &self.hourly_records[self.hourly_records.len() - 8..];
        let start_hour = window[0].0;
        let hash_node = |l: &[u8; 32], r: &[u8; 32]| -> [u8; 32] {
            let mut n = b"SHZ/HOUR/NODE/V1".to_vec();
            n.extend_from_slice(l);
            n.extend_from_slice(r);
            sha256_bytes(&n)
        };
        let l1: Vec<[u8; 32]> = (0..4)
            .map(|i| hash_node(&window[2 * i].3, &window[2 * i + 1].3))
            .collect();
        let l2: Vec<[u8; 32]> = (0..2)
            .map(|i| hash_node(&l1[2 * i], &l1[2 * i + 1]))
            .collect();
        let tree_root = hash_node(&l2[0], &l2[1]);

        let mut root_pre = b"SHZ/8H/ROOT/V1".to_vec();
        root_pre.extend_from_slice(&self.genesis_hash);
        root_pre.extend_from_slice(&self.policy_hash);
        root_pre.extend_from_slice(&start_hour.to_le_bytes());
        root_pre.extend_from_slice(&tree_root);
        let ckpt_root = sha256_bytes(&root_pre);

        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(b"SHZIDX01");
        payload.extend_from_slice(&ckpt_root);

        let valid_hours = window.iter().filter(|x| x.1).count() as u8;
        let summary = SealedCheckpointSummary {
            start_hour,
            checkpoint_root_hex: hex::encode(ckpt_root),
            shzidx01_payload_hex: hex::encode(payload),
            closing_midpoint_usd: window[7].2,
            valid_hours,
            hold_hours: 8 - valid_hours,
        };
        self.sealed_checkpoints.push(summary.clone());
        Some(summary)
    }
}
