//! `shz dlc-refund-plan`: derives the maturity and refund CLTV heights of an MNR-02 contract
//! from a threshold-oracle DLC event, and refuses refund heights that could arrive too soon
//! after the oracle's attestation window if blocks run faster than expected.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

pub const DEFAULT_BLOCK_SECS: u64 = 600;
pub const DEFAULT_ATTEST_WINDOW_SECS: u64 = 30;
pub const DEFAULT_GRACE_BLOCKS: u32 = 6;
pub const DEFAULT_REFUND_DELAY_BLOCKS: u32 = 144;
pub const DEFAULT_FAST_FACTOR: u64 = 2;
pub const DEFAULT_MIN_GAP_SECS: u64 = 6 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanParams {
    pub event_id: String,
    pub maturity_unix: u64,
    pub tip_height: u32,
    pub tip_time: u64,
    pub block_secs: u64,
    pub attest_window_secs: u64,
    pub grace_blocks: u32,
    pub refund_delay_blocks: u32,
    /// Assumed worst-case block speed-up (blocks arrive `fast_factor` times faster than `block_secs`).
    pub fast_factor: u64,
    pub min_gap_secs: u64,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefundPlan {
    pub event_id: String,
    pub maturity_unix: u64,
    pub attestation_due_unix: u64,
    pub tip_height: u32,
    pub tip_time: u64,
    pub block_secs: u64,
    pub maturity_height: u32,
    pub unilateral_cltv_height: u32,
    pub refund_cltv_height: u32,
    pub grace_blocks: u32,
    pub refund_delay_blocks: u32,
    pub expected_refund_unix_at_nominal_speed: u64,
    pub fast_factor: u64,
    pub expected_refund_unix_at_fast_speed: u64,
    /// Refund time at `fast_factor` speed minus the oracle attestation due time (maturity + window).
    pub min_gap_secs_at_fast_speed: i64,
    pub min_gap_floor_secs: u64,
    pub forced: bool,
    pub reasoning: Vec<String>,
}

pub fn compute_plan(p: &PlanParams) -> Result<RefundPlan, String> {
    if p.block_secs == 0 {
        return Err("block_secs must be > 0".into());
    }
    if p.fast_factor == 0 {
        return Err("fast_factor must be > 0".into());
    }
    if p.grace_blocks == 0 || p.refund_delay_blocks <= p.grace_blocks {
        return Err("require 0 < grace_blocks < refund_delay_blocks".into());
    }
    let due = p
        .maturity_unix
        .checked_add(p.attest_window_secs)
        .ok_or("maturity overflow")?;
    // First height whose expected time is >= due: tip + ceil((due - tip_time) / block_secs), at least tip + 1.
    let blocks_ahead = if due > p.tip_time {
        (due - p.tip_time).div_ceil(p.block_secs).max(1)
    } else {
        1
    };
    let maturity_height = u32::try_from(p.tip_height as u64 + blocks_ahead)
        .map_err(|_| "maturity height overflows u32".to_string())?;
    let refund_cltv_height = maturity_height
        .checked_add(p.refund_delay_blocks)
        .ok_or("refund height overflow")?;
    let unilateral_cltv_height = maturity_height + p.grace_blocks;

    let blocks_to_refund = (refund_cltv_height - p.tip_height) as u128;
    let nominal = p.tip_time as u128 + blocks_to_refund * p.block_secs as u128;
    // Floor division keeps the fast-speed estimate on the early (conservative) side.
    let fast = p.tip_time as u128 + blocks_to_refund * p.block_secs as u128 / p.fast_factor as u128;
    let gap = fast as i128 - due as i128;
    let gap = i64::try_from(gap).map_err(|_| "gap overflow".to_string())?;

    let mut reasoning = vec![
        format!(
            "maturity_height {maturity_height} = tip {} + ceil(({due} - {}) / {}) blocks: the first height expected at or after maturity_unix {} + attestation window {}s.",
            p.tip_height, p.tip_time, p.block_secs, p.maturity_unix, p.attest_window_secs
        ),
        format!(
            "refund_cltv_height {refund_cltv_height} = maturity_height + {} refund-delay blocks; the refund leaf is a height lock, so faster blocks bring it earlier in wall time.",
            p.refund_delay_blocks
        ),
        format!(
            "At {}x block speed the refund height arrives at unix {fast}, {gap}s after the attestation due time {due} (floor {}s).",
            p.fast_factor, p.min_gap_secs
        ),
    ];
    let violates = gap < p.min_gap_secs as i64;
    if violates {
        let msg = format!(
            "refund height {refund_cltv_height} can arrive only {gap}s after attestation due time at {}x block speed; floor is {}s. Increase --refund-delay-blocks.",
            p.fast_factor, p.min_gap_secs
        );
        if !p.force {
            return Err(msg);
        }
        reasoning.push(format!("FORCED despite: {msg}"));
    }

    Ok(RefundPlan {
        event_id: p.event_id.clone(),
        maturity_unix: p.maturity_unix,
        attestation_due_unix: due,
        tip_height: p.tip_height,
        tip_time: p.tip_time,
        block_secs: p.block_secs,
        maturity_height,
        unilateral_cltv_height,
        refund_cltv_height,
        grace_blocks: p.grace_blocks,
        refund_delay_blocks: p.refund_delay_blocks,
        expected_refund_unix_at_nominal_speed: nominal as u64,
        fast_factor: p.fast_factor,
        expected_refund_unix_at_fast_speed: fast as u64,
        min_gap_secs_at_fast_speed: gap,
        min_gap_floor_secs: p.min_gap_secs,
        forced: p.force && violates,
        reasoning,
    })
}

/// Extracts `(event_id, maturity_unix)` from a fixture (`announcement_core` / `announcement`)
/// or a raw `/v1/dlc/event` response (`core`), or a bare core object.
pub fn event_core(v: &Value) -> Result<(String, u64), String> {
    let core = ["announcement_core", "core", "announcement"]
        .iter()
        .find_map(|k| v.get(*k).filter(|c| c.get("maturity_unix").is_some()))
        .unwrap_or(v);
    let id = core
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or("event_id missing")?;
    let mat = core
        .get("maturity_unix")
        .and_then(Value::as_u64)
        .ok_or("maturity_unix missing")?;
    Ok((id.to_string(), mat))
}

pub fn load_event_core(path: &Path) -> Result<(String, u64), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    event_core(&v)
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn num<T: std::str::FromStr>(args: &[String], name: &str, default: Option<T>) -> Result<T, String> {
    match flag(args, name) {
        Some(s) => s.parse().map_err(|_| format!("invalid value for {name}: {s}")),
        None => default.ok_or_else(|| format!("{name} is required")),
    }
}

pub fn run_dlc_refund_plan(args: &[String]) -> Result<RefundPlan, String> {
    let event = flag(args, "--event").ok_or("--event FILE is required")?;
    let (event_id, maturity_unix) = load_event_core(Path::new(event))?;
    compute_plan(&PlanParams {
        event_id,
        maturity_unix,
        tip_height: num(args, "--tip-height", None)?,
        tip_time: num(args, "--tip-time", None)?,
        block_secs: num(args, "--block-secs", Some(DEFAULT_BLOCK_SECS))?,
        attest_window_secs: num(args, "--attest-window-secs", Some(DEFAULT_ATTEST_WINDOW_SECS))?,
        grace_blocks: num(args, "--grace-blocks", Some(DEFAULT_GRACE_BLOCKS))?,
        refund_delay_blocks: num(args, "--refund-delay-blocks", Some(DEFAULT_REFUND_DELAY_BLOCKS))?,
        fast_factor: num(args, "--fast-factor", Some(DEFAULT_FAST_FACTOR))?,
        min_gap_secs: num(args, "--min-gap-secs", Some(DEFAULT_MIN_GAP_SECS))?,
        force: args.iter().any(|a| a == "--force"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> PlanParams {
        PlanParams {
            event_id: "E".into(),
            maturity_unix: 1_000_000,
            tip_height: 800_000,
            tip_time: 1_000_000 - 3_600,
            block_secs: 600,
            attest_window_secs: 30,
            grace_blocks: 6,
            refund_delay_blocks: 144,
            fast_factor: 2,
            min_gap_secs: DEFAULT_MIN_GAP_SECS,
            force: false,
        }
    }

    #[test]
    fn maturity_height_is_ceiling_of_expected_blocks() {
        // (3600 + 30) / 600 = 6.05 -> 7 blocks.
        let plan = compute_plan(&params()).unwrap();
        assert_eq!(plan.maturity_height, 800_007);
        assert_eq!(plan.unilateral_cltv_height, 800_013);
        assert_eq!(plan.refund_cltv_height, 800_151);
        assert_eq!(plan.attestation_due_unix, 1_000_030);
    }

    #[test]
    fn exact_multiple_does_not_round_up() {
        let mut p = params();
        p.attest_window_secs = 0;
        p.tip_time = p.maturity_unix - 3_600;
        assert_eq!(compute_plan(&p).unwrap().maturity_height, 800_006);
    }

    #[test]
    fn already_matured_event_uses_next_block() {
        let mut p = params();
        p.tip_time = p.maturity_unix + 10_000;
        assert_eq!(compute_plan(&p).unwrap().maturity_height, 800_001);
    }

    #[test]
    fn fast_block_gap_is_computed_from_attestation_due_time() {
        let plan = compute_plan(&params()).unwrap();
        // 151 blocks * 600 / 2 = 45,300 s after tip_time; due = tip_time + 3,630.
        assert_eq!(plan.min_gap_secs_at_fast_speed, 45_300 - 3_630);
        assert_eq!(plan.expected_refund_unix_at_nominal_speed, params().tip_time + 151 * 600);
    }

    #[test]
    fn refuses_short_delay_unless_forced() {
        let mut p = params();
        p.refund_delay_blocks = 20;
        let err = compute_plan(&p).unwrap_err();
        assert!(err.contains("Increase --refund-delay-blocks"), "{err}");
        p.force = true;
        let plan = compute_plan(&p).unwrap();
        assert!(plan.forced);
        assert!(plan.min_gap_secs_at_fast_speed < DEFAULT_MIN_GAP_SECS as i64);
    }

    #[test]
    fn rejects_invalid_grace() {
        let mut p = params();
        p.refund_delay_blocks = 6;
        assert!(compute_plan(&p).is_err());
    }

    #[test]
    fn event_core_reads_fixture_and_raw_relay_shapes() {
        let fixture: Value = serde_json::json!({"announcement_core": {"event_id": "A", "maturity_unix": 7}, "announcement": {"event_id": "A", "maturity_unix": 7}});
        assert_eq!(event_core(&fixture).unwrap(), ("A".to_string(), 7));
        let raw: Value = serde_json::json!({"status": "announced", "core": {"event_id": "B", "maturity_unix": 9}});
        assert_eq!(event_core(&raw).unwrap(), ("B".to_string(), 9));
    }

    #[test]
    fn cli_parses_flags_against_live_fixture() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ops/public-relay/fixture_dlc_event_live.json");
        let args: Vec<String> = ["--event", path, "--tip-height", "100", "--tip-time", "1795594500"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let plan = run_dlc_refund_plan(&args).unwrap();
        assert_eq!(plan.event_id, "SHZ-BTCUSD-20261125T0915Z");
        assert_eq!(plan.maturity_height, 107);
    }
}
