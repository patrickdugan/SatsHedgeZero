//! CBM-CACHE-03 clearing gym benchmark (CPU only; synthetic workloads, no live funds).
//!
//! `cargo run --release --locked -p shz-utxoref --example cbm03_gym -- --accounts 128 --conn sparse
//!   --regime rotating --windows 8 --cands 24 --seed 1 --budgets 65536,1048576 --check-every 1`
//!
//! Prints one JSON line per (arm, budget) plus one `trace` line. Builds the reference trace
//! (cold verdicts, compared against the canonical solver every `--check-every` candidates and
//! on every window's final batch), then replays it through each cache arm and checks every
//! verdict against the cold one. A false acceptance exits with status 3.
use std::time::Instant;

use serde_json::json;
use shz_utxoref::clearing_gym::*;
use shz_utxoref::flow_cert::*;

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| default.to_string())
}
fn pct(v: &mut [u64], p: f64) -> u64 {
    if v.is_empty() { return 0; }
    v.sort_unstable();
    let i = ((p / 100.0) * v.len() as f64).ceil() as usize;
    v[i.clamp(1, v.len()) - 1]
}
#[cfg(windows)]
fn peak_rss_bytes() -> u64 {
    #[repr(C)]
    struct Pmc { cb: u32, faults: u32, peak_ws: usize, ws: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize }
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(h: isize, p: *mut Pmc, cb: u32) -> i32;
    }
    let mut m = Pmc { cb: std::mem::size_of::<Pmc>() as u32, faults: 0, peak_ws: 0, ws: 0, a: 0, b: 0, c: 0, d: 0, e: 0, f: 0 };
    // SAFETY: documented Win32 call writing into a correctly sized PROCESS_MEMORY_COUNTERS.
    unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut m, m.cb) };
    m.peak_ws as u64
}
#[cfg(not(windows))]
fn peak_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.split_whitespace().nth(1).unwrap_or("0").parse::<u64>().unwrap_or(0) * 1024))
        .unwrap_or(0)
}

struct Arm { name: &'static str, policy: Policy, repair: bool, retrieval: usize }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let accounts: usize = arg(&args, "--accounts", "32").parse().unwrap();
    let connectivity = match arg(&args, "--conn", "sparse").as_str() { "dense" => Connectivity::Dense, _ => Connectivity::Sparse };
    let regime = match arg(&args, "--regime", "stable").as_str() { "rotating" => Regime::Rotating, "churn" => Regime::HighChurn, _ => Regime::Stable };
    let windows: usize = arg(&args, "--windows", "8").parse().unwrap();
    let candidates: usize = arg(&args, "--cands", "24").parse().unwrap();
    let seed: u64 = arg(&args, "--seed", "1").parse().unwrap();
    let check_every: usize = arg(&args, "--check-every", "1").parse().unwrap();
    let budgets: Vec<usize> = arg(&args, "--budgets", "65536,1048576,8388608,67108864").split(',').map(|x| x.parse().unwrap()).collect();
    let only = arg(&args, "--arms", "all");
    let cfg = GymConfig { accounts, connectivity, regime, windows, candidates, seed };
    let label = json!({"accounts": accounts, "conn": arg(&args, "--conn", "sparse"), "regime": arg(&args, "--regime", "stable"), "windows": windows, "cands": candidates, "seed": seed});

    let t0 = Instant::now();
    let trace = reference_trace(&cfg, check_every).expect("gym snapshots are valid");
    let ref_ms = t0.elapsed().as_secs_f64() * 1e3;
    let infeasible = trace.queries.iter().filter(|q| matches!(q.verdict, Verdict::Infeasible { .. })).count();
    let edges: Vec<usize> = trace.queries.iter().map(|q| q.problem.edges.len()).collect();
    println!("{}", json!({"kind": "trace", "cfg": label, "queries": trace.queries.len(), "infeasible": infeasible,
        "accepted_obligations": trace.accepted_obligations, "canonical_checked": trace.canonical_checked,
        "max_edges": edges.iter().max(), "max_nodes": trace.queries.iter().map(|q| q.problem.nodes.len()).max(),
        "reference_ms": ref_ms, "roots_hash": hex(&trace.window_roots)}));

    // Offline bound: unbounded structural cache with repair, logging every reuse.
    let mut unbounded = CertCache::new(Policy::Lru, usize::MAX / 4, true, usize::MAX);
    unbounded.reuse_log = Some(Vec::new());
    for q in &trace.queries { unbounded.cold_hint = q.cold_work.edge_inspections; unbounded.screen(&q.problem); }
    let reuses = unbounded.reuse_log.take().unwrap();
    let cold_total: u64 = trace.queries.iter().map(|q| q.cold_work.edge_inspections).sum();

    let arms = [
        Arm { name: "cold", policy: Policy::Cold, repair: false, retrieval: 0 },
        Arm { name: "memo", policy: Policy::ExactMemo, repair: false, retrieval: 0 },
        Arm { name: "lru", policy: Policy::Lru, repair: false, retrieval: 4 },
        Arm { name: "freq", policy: Policy::Frequency, repair: false, retrieval: 4 },
        Arm { name: "utility", policy: Policy::Utility, repair: false, retrieval: 4 },
        Arm { name: "causal", policy: Policy::Causal, repair: false, retrieval: 4 },
        Arm { name: "repair_only", policy: Policy::Lru, repair: true, retrieval: 0 },
        Arm { name: "lru_repair", policy: Policy::Lru, repair: true, retrieval: 4 },
        Arm { name: "utility_repair", policy: Policy::Utility, repair: true, retrieval: 4 },
        Arm { name: "causal_repair", policy: Policy::Causal, repair: true, retrieval: 4 },
    ];
    // Warm the allocator and caches with one untimed cold pass.
    for q in &trace.queries { std::hint::black_box(cold_solve(&q.problem)); }
    let mut false_accepts = 0u64;
    for arm in arms.iter().filter(|a| only == "all" || only.split(',').any(|x| x == a.name)) {
        let arm_budgets: Vec<usize> = if arm.policy == Policy::Cold { vec![0] } else { budgets.clone() };
        for &budget in &arm_budgets {
            let mut cache = CertCache::new(arm.policy, budget, arm.repair, arm.retrieval);
            let (mut per_q, mut per_w) = (Vec::new(), vec![0u64; windows]);
            let mut work = Work::default();
            let mut paths = std::collections::BTreeMap::new();
            let (mut wrong, mut lb_inexact) = (0u64, 0u64);
            for q in &trace.queries {
                let t = Instant::now();
                let s = cache.screen(&q.problem);
                let ns = t.elapsed().as_nanos() as u64;
                per_q.push(ns);
                per_w[q.window] += ns + q.build_ns;
                work.add(&s.work);
                *paths.entry(format!("{:?}", s.path)).or_insert(0u64) += 1;
                match (q.verdict, s.verdict) {
                    (Verdict::Feasible, Verdict::Feasible) => {}
                    (Verdict::Infeasible { deficit_at_least: e }, Verdict::Infeasible { deficit_at_least: l }) => {
                        if l > e || l == 0 { wrong += 1; }
                        if l < e { lb_inexact += 1; }
                    }
                    (Verdict::Infeasible { .. }, Verdict::Feasible) => { false_accepts += 1; wrong += 1; }
                    (Verdict::Feasible, Verdict::Infeasible { .. }) => { wrong += 1; }
                }
            }
            for (w, x) in per_w.iter_mut().enumerate() { *x += trace.canonical_ns.get(w).copied().unwrap_or(0); }
            let bound = if arm.policy == Policy::Cold { 0 } else { oracle::fractional_bound(&reuses, budget) };
            let greedy = if arm.policy == Policy::Cold { 0 } else { oracle::greedy_schedule(&reuses, budget) };
            let screen_total: u64 = per_q.iter().sum();
            println!("{}", json!({"kind": "arm", "cfg": label, "arm": arm.name, "budget_bytes": budget,
                "wrong_verdicts": wrong, "inexact_deficit_bounds": lb_inexact, "paths": paths,
                "augmenting_paths": work.augmenting_paths, "edge_inspections": work.edge_inspections, "cancellations": work.cancellations,
                "cold_edge_inspections": cold_total,
                "oracle_saved_fractional_ub": bound, "oracle_saved_greedy_lb": greedy, "unbounded_reuses": reuses.len(),
                "cache_peak_bytes": cache.peak_bytes, "evictions": cache.evictions, "bypasses": cache.bypasses,
                "screen_ms_total": screen_total as f64 / 1e6,
                "screen_us_p50": pct(&mut per_q.clone(), 50.0) as f64 / 1e3, "screen_us_p95": pct(&mut per_q.clone(), 95.0) as f64 / 1e3, "screen_us_p99": pct(&mut per_q.clone(), 99.0) as f64 / 1e3,
                "window_ms_p50": pct(&mut per_w.clone(), 50.0) as f64 / 1e6, "window_ms_p95": pct(&mut per_w.clone(), 95.0) as f64 / 1e6, "window_ms_p99": pct(&mut per_w.clone(), 99.0) as f64 / 1e6,
                "window_ms_max": per_w.iter().max().copied().unwrap_or(0) as f64 / 1e6,
                "process_peak_rss_bytes": peak_rss_bytes()}));
        }
    }
    if false_accepts > 0 { eprintln!("FALSE ACCEPTANCE: {false_accepts}"); std::process::exit(3); }
}

fn hex(roots: &[[u8; 32]]) -> String {
    let mut b = Vec::new();
    for r in roots { b.extend_from_slice(r); }
    let h = shz_dlc::tagged_hash(b"cbm03/roots", &b);
    h.iter().map(|x| format!("{x:02x}")).collect()
}
