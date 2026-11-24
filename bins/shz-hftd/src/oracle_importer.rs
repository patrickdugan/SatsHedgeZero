//! Live Two-Index Pyth + Chainlink BTC/USD Fiat Importer (`shz-hftd`).
//!
//! Fetches real-time on-chain **Pyth (`Crypto.BTC/USD`)** and **Chainlink (`BTC / USD`)** index
//! observations on Arbitrum One in a single JSON-RPC batch call every `1.5s`, normalizes both to
//! `1e8` fixed-point USD, computes the 50/50 two-index midpoint + real basis-point spread, and
//! feeds `HftEngine` directly in fiat-trusted mode (no 50-bps HOLD halt or per-tick SNARK gate).
#![forbid(unsafe_code)]

use std::process::Command;

use serde::{Deserialize, Serialize};

const PYTH_ARB_CONTRACT: &str = "0xff1a0f4744e8582DF1aE09D5611b887B6a12925C";
const PYTH_GET_PRICE_UNSAFE_BTCUSD: &str =
    "0x96834ad3e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43";
const CHAINLINK_ARB_BTCUSD: &str = "0x6ce185860a4963106506C203335A2910413708e9";
const CHAINLINK_LATEST_ROUND_DATA: &str = "0xfeaf968c";

const ARB_RPC_ENDPOINTS: &[&str] = &[
    "https://arbitrum-one-rpc.publicnode.com",
    "https://1rpc.io/arb",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveTwoIndexObservation {
    pub rpc_endpoint: String,
    pub pyth_price_e8: u64,
    pub pyth_conf_e8: u64,
    pub pyth_conf_bps: u32,
    pub pyth_publish_ts: u64,
    pub chainlink_price_e8: u64,
    pub chainlink_round_id_hex: String,
    pub chainlink_updated_ts: u64,
    pub midpoint_price_e8: u64,
    pub midpoint_price_usd: u64,
    pub spread_bps: u32,
}

fn parse_abi_word_u64(hex_no_0x: &str, word_index: usize) -> Option<u64> {
    let start = word_index.checked_mul(64)?;
    let end = start.checked_add(64)?;
    let word = hex_no_0x.get(start..end)?;
    // Take low 8 bytes (last 16 hex chars) as big-endian u64:
    u64::from_str_radix(&word[48..64], 16).ok()
}

fn parse_abi_word_i32(hex_no_0x: &str, word_index: usize) -> Option<i32> {
    let start = word_index.checked_mul(64)?;
    let end = start.checked_add(64)?;
    let word = hex_no_0x.get(start..end)?;
    let bits = u32::from_str_radix(&word[56..64], 16).ok()?;
    Some(bits as i32)
}

fn decode_pyth_result(res_hex: &str) -> Option<(u64, u64, u64)> {
    let clean = res_hex.strip_prefix("0x").unwrap_or(res_hex);
    if clean.len() < 256 {
        return None;
    }
    let raw_px = parse_abi_word_u64(clean, 0)?;
    let raw_conf = parse_abi_word_u64(clean, 1)?;
    let expo = parse_abi_word_i32(clean, 2)?;
    let pub_ts = parse_abi_word_u64(clean, 3)?;

    let scale_shift = 8i32 + expo;
    let (px_e8, conf_e8) = if scale_shift == 0 {
        (raw_px, raw_conf)
    } else if scale_shift > 0 {
        let mul = 10u64.checked_pow(scale_shift as u32)?;
        (raw_px.saturating_mul(mul), raw_conf.saturating_mul(mul))
    } else {
        let div = 10u64.checked_pow((-scale_shift) as u32)?.max(1);
        (raw_px / div, raw_conf / div)
    };
    if px_e8 < 10_000_000_000 {
        return None;
    }
    Some((px_e8, conf_e8, pub_ts))
}

fn decode_chainlink_result(res_hex: &str) -> Option<(String, u64, u64)> {
    let clean = res_hex.strip_prefix("0x").unwrap_or(res_hex);
    if clean.len() < 320 {
        return None;
    }
    let round_word = clean.get(0..64)?.trim_start_matches('0');
    let round_hex = if round_word.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{round_word}")
    };
    let answer_e8 = parse_abi_word_u64(clean, 1)?;
    let updated_ts = parse_abi_word_u64(clean, 3)?;
    if answer_e8 < 10_000_000_000 {
        return None;
    }
    Some((round_hex, answer_e8, updated_ts))
}

/// Fetches a live `[Pyth Crypto.BTC/USD, Chainlink BTC/USD]` batch observation via system `curl`.
pub fn fetch_live_pyth_chainlink_btcusd() -> Result<LiveTwoIndexObservation, String> {
    if std::env::var("SHZ_ORACLE_OFFLINE").as_deref() == Ok("1") {
        return Err("SHZ_ORACLE_OFFLINE=1".into());
    }

    let batch_body = serde_json::json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{ "to": PYTH_ARB_CONTRACT, "data": PYTH_GET_PRICE_UNSAFE_BTCUSD }, "latest"]
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_call",
            "params": [{ "to": CHAINLINK_ARB_BTCUSD, "data": CHAINLINK_LATEST_ROUND_DATA }, "latest"]
        }
    ])
    .to_string();

    let curl_bin = if cfg!(windows) { "curl.exe" } else { "curl" };

    for &endpoint in ARB_RPC_ENDPOINTS {
        let Ok(out) = Command::new(curl_bin)
            .args([
                "-sS",
                "--max-time",
                "4",
                "-H",
                "Content-Type: application/json",
                "-H",
                "User-Agent: shz-hftd-two-index/0.2",
                "-d",
                &batch_body,
                endpoint,
            ])
            .output()
        else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) else {
            continue;
        };
        let pyth_hex = arr
            .iter()
            .find(|v| v["id"].as_u64() == Some(1))
            .and_then(|v| v["result"].as_str());
        let cl_hex = arr
            .iter()
            .find(|v| v["id"].as_u64() == Some(2))
            .and_then(|v| v["result"].as_str());

        if let (Some(ph), Some(ch)) = (pyth_hex, cl_hex)
            && let (Some((pyth_e8, pyth_conf_e8, pyth_ts)), Some((round_hex, cl_e8, cl_ts))) =
                (decode_pyth_result(ph), decode_chainlink_result(ch))
        {
            let mid_e8 = ((pyth_e8 as u128 + cl_e8 as u128) / 2) as u64;
            let mid_usd = ((mid_e8 + 50_000_000) / 100_000_000).max(1);
            let spread_bps = ((pyth_e8.abs_diff(cl_e8) as u128 * 10_000) / (mid_e8.max(1) as u128))
                as u32;
            let pyth_conf_bps =
                ((pyth_conf_e8 as u128 * 10_000) / (pyth_e8.max(1) as u128)).max(1) as u32;

            return Ok(LiveTwoIndexObservation {
                rpc_endpoint: endpoint.to_owned(),
                pyth_price_e8: pyth_e8,
                pyth_conf_e8,
                pyth_conf_bps,
                pyth_publish_ts: pyth_ts,
                chainlink_price_e8: cl_e8,
                chainlink_round_id_hex: round_hex,
                chainlink_updated_ts: cl_ts,
                midpoint_price_e8: mid_e8,
                midpoint_price_usd: mid_usd,
                spread_bps,
            });
        }
    }

    Err("all live Pyth+Chainlink RPC endpoints unreachable".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_real_arbitrum_pyth_and_chainlink_vectors() {
        let pyth_raw = "0x00000000000000000000000000000000000000000000000000000572236c7540000000000000000000000000000000000000000000000000000000011f129580fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000000000000000000000000000000000000000000006b0560b1";
        let (px, conf, ts) = decode_pyth_result(pyth_raw).unwrap();
        assert_eq!(px, 0x0572_236c_7540);
        assert_eq!(conf, 0x0001_1f12_9580);
        assert_eq!(ts, 0x6b05_60b1);

        let cl_raw = "0x000000000000000000000000000000000000000000000002000000000001b6a5000000000000000000000000000000000000000000000000000005738ee9089b000000000000000000000000000000000000000000000000000000006b05617b000000000000000000000000000000000000000000000000000000006b056188000000000000000000000000000000000000000000000002000000000001b6a5";
        let (rnd, cl_px, cl_ts) = decode_chainlink_result(cl_raw).unwrap();
        assert_eq!(rnd, "0x2000000000001b6a5");
        assert_eq!(cl_px, 0x0573_8ee9_089b);
        assert_eq!(cl_ts, 0x6b05_6188);
    }
}
