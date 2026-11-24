//! Operator CLI for the HFT-06 collator.
//!
//!   shz-collator gen-fixture --origin-us N --seconds S [--seed X] --out rec.jsonl
//!   shz-collator replay --recording rec.jsonl --origin-us N [--slots slots.jsonl] [--archive obs.jsonl]
//!
//! `replay` is deterministic: the same recording yields the same slot chain
//! receipt. Synthetic fixtures use fixed test keys and are not provider data.

use std::{collections::BTreeMap, io::Write};

use shz_oracle::collator::{HoldReason, chain_receipt, fixture};
use shz_relay::service::{load_recording, replay};

fn args() -> BTreeMap<String, String> {
    let v: Vec<String> = std::env::args().skip(2).collect();
    v.chunks(2).filter_map(|c| Some((c.first()?.trim_start_matches("--").to_string(), c.get(1).cloned().unwrap_or_default()))).collect()
}
fn need<T: std::str::FromStr>(a: &BTreeMap<String, String>, k: &str) -> T {
    a.get(k).and_then(|v| v.parse().ok()).unwrap_or_else(|| {
        eprintln!("missing or invalid --{k}");
        std::process::exit(2)
    })
}
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let a = args();
    match cmd.as_str() {
        "gen-fixture" => {
            let seed = a.get("seed").and_then(|s| s.parse().ok()).unwrap_or(20261124);
            let rec = fixture::recording(need(&a, "origin-us"), need(&a, "seconds"), seed);
            let mut f = std::fs::File::create(need::<String>(&a, "out")).unwrap_or_else(|e| die(e));
            for r in &rec {
                writeln!(f, "{}", serde_json::to_string(r).unwrap()).unwrap();
            }
            println!("{{\"reports\":{},\"synthetic\":true}}", rec.len());
        }
        "replay" => {
            let origin: u64 = need(&a, "origin-us");
            let rec = load_recording(std::path::Path::new(&need::<String>(&a, "recording"))).unwrap_or_else(|e| die(e));
            let (slots, c) = replay(fixture::config(), fixture::policy(origin), &rec).unwrap_or_else(|e| die(e));
            if let Some(p) = a.get("slots") {
                let mut f = std::fs::File::create(p).unwrap_or_else(|e| die(e));
                for s in &slots {
                    writeln!(f, "{}", serde_json::to_string(s).unwrap()).unwrap();
                }
            }
            if let Some(p) = a.get("archive") {
                // Retained evidence: original signed bytes, digest, normalized
                // fixed-point value, source and arrival timestamps.
                let mut cc = shz_oracle::collator::Collator::new(fixture::config(), fixture::policy(origin)).unwrap();
                let mut f = std::fs::File::create(p).unwrap_or_else(|e| die(e));
                for r in &rec {
                    if let (_, Ok(o)) = cc.ingest(r) {
                        let line = serde_json::json!({"observation": o, "raw_hex": hex::encode(&r.bytes)});
                        writeln!(f, "{line}").unwrap();
                    }
                }
            }
            let count = |r: Option<HoldReason>| slots.iter().filter(|s| s.hold == r).count();
            let out = serde_json::json!({
                "schema": "shz-hft06-collator-replay/v1",
                "synthetic": true,
                "reports": rec.len(),
                "slots": slots.len(),
                "valid": count(None),
                "hold_missing_or_stale": count(Some(HoldReason::MissingOrStale)),
                "hold_skew_or_dispersion": count(Some(HoldReason::SkewOrDispersion)),
                "hold_emergency": count(Some(HoldReason::Emergency)),
                "source_stats": {"pyth_pro": c.stats[0], "chainlink_streams": c.stats[1]},
                "chain_receipt": hex::encode(chain_receipt(&slots)),
                "first_digest": slots.first().map(|s| hex::encode(s.digest)),
                "last_digest": slots.last().map(|s| hex::encode(s.digest)),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        _ => die("usage: shz-collator gen-fixture|replay (see source header)"),
    }
}
