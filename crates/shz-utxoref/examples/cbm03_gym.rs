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

struct Arm { name: &'static str, policy: Policy, repair: bool, retrieval: usize, compact: bool }

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

    if args.iter().any(|a| a == "--phase5") {
        let budgets_ms: Vec<f64> = arg(&args, "--budgets-ms", "50,100,200").split(',').map(|x| x.parse().unwrap()).collect();
        phase5(&trace, &label, &budgets_ms);
        return;
    }
    // Offline bound: unbounded structural cache with repair, logging every reuse.
    let mut unbounded = CertCache::new(Policy::Lru, usize::MAX / 4, true, usize::MAX);
    unbounded.reuse_log = Some(Vec::new());
    for q in &trace.queries { unbounded.cold_hint = q.cold_work.edge_inspections; unbounded.screen(&q.problem); }
    let reuses = unbounded.reuse_log.take().unwrap();
    // Every gym trace has one node set; its frame is resident whenever any certificate is,
    // so the oracle's budget for certificate payloads is the budget minus one frame (keys, or
    // 32 bytes in compact mode). With several node sets this would not be exact.
    let node_sets: std::collections::BTreeSet<[u8; 32]> = trace.queries.iter().map(|q| q.problem.frame.node_set).collect();
    let frame_bytes = trace.queries.first().map(|q| q.problem.frame.bytes()).unwrap_or(0);
    let cold_total: u64 = trace.queries.iter().map(|q| q.cold_work.edge_inspections).sum();

    let arms = [
        Arm { name: "cold", policy: Policy::Cold, repair: false, retrieval: 0, compact: false },
        Arm { name: "memo", policy: Policy::ExactMemo, repair: false, retrieval: 0, compact: false },
        Arm { name: "lru", policy: Policy::Lru, repair: false, retrieval: 4, compact: false },
        Arm { name: "freq", policy: Policy::Frequency, repair: false, retrieval: 4, compact: false },
        Arm { name: "utility", policy: Policy::Utility, repair: false, retrieval: 4, compact: false },
        Arm { name: "causal", policy: Policy::Causal, repair: false, retrieval: 4, compact: false },
        Arm { name: "repair_only", policy: Policy::Lru, repair: true, retrieval: 0, compact: false },
        Arm { name: "lru_repair", policy: Policy::Lru, repair: true, retrieval: 4, compact: false },
        Arm { name: "utility_repair", policy: Policy::Utility, repair: true, retrieval: 4, compact: false },
        Arm { name: "causal_repair", policy: Policy::Causal, repair: true, retrieval: 4, compact: false },
        Arm { name: "repair_compact", policy: Policy::Lru, repair: true, retrieval: 0, compact: true },
        Arm { name: "lru_repair_compact", policy: Policy::Lru, repair: true, retrieval: 4, compact: true },
    ];
    // Warm the allocator and caches with one untimed cold pass.
    for q in &trace.queries { std::hint::black_box(cold_solve(&q.problem)); }
    let mut false_accepts = 0u64;
    for arm in arms.iter().filter(|a| only == "all" || only.split(',').any(|x| x == a.name)) {
        let arm_budgets: Vec<usize> = if arm.policy == Policy::Cold { vec![0] } else { budgets.clone() };
        for &budget in &arm_budgets {
            let mut cache = CertCache::new(arm.policy, budget, arm.repair, arm.retrieval);
            cache.compact_frames = arm.compact;
            let (mut per_q, mut per_w) = (Vec::new(), vec![0u64; windows]);
            let mut work = Work::default();
            let mut paths = std::collections::BTreeMap::new();
            let (mut wrong, mut lb_inexact) = (0u64, 0u64);
            let mut hit_saved_total = 0u64;
            for q in &trace.queries {
                let t = Instant::now();
                let s = cache.screen(&q.problem);
                let ns = t.elapsed().as_nanos() as u64;
                per_q.push(ns);
                per_w[q.window] += ns + q.build_ns;
                work.add(&s.work);
                if matches!(s.path, Path::ExactMemo | Path::TransportFlow | Path::TransportCut) {
                    hit_saved_total += q.cold_work.edge_inspections.saturating_sub(s.work.edge_inspections);
                }
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
            let usable = budget.saturating_sub(if arm.compact { 32 } else { frame_bytes });
            let bound = if arm.policy == Policy::Cold { 0 } else { oracle::fractional_bound(&reuses, usable) };
            let greedy = if arm.policy == Policy::Cold { 0 } else { oracle::greedy_schedule(&reuses, usable) };
            let hit_saved: u64 = if arm.policy == Policy::Cold { 0 } else { hit_saved_total };
            let screen_total: u64 = per_q.iter().sum();
            println!("{}", json!({"kind": "arm", "cfg": label, "arm": arm.name, "budget_bytes": budget,
                "wrong_verdicts": wrong, "inexact_deficit_bounds": lb_inexact, "paths": paths,
                "augmenting_paths": work.augmenting_paths, "edge_inspections": work.edge_inspections, "cancellations": work.cancellations,
                "cold_edge_inspections": cold_total,
                "oracle_saved_fractional_ub": bound, "oracle_saved_greedy_lb": greedy, "unbounded_reuses": reuses.len(),
                "hit_saved_inspections": hit_saved, "node_sets": node_sets.len(), "frame_bytes": frame_bytes,
                "cache_peak_bytes": cache.peak_bytes, "evictions": cache.evictions, "bypasses": cache.bypasses,
                "screen_ms_total": screen_total as f64 / 1e6,
                "screen_us_p50": pct(&mut per_q.clone(), 50.0) as f64 / 1e3, "screen_us_p95": pct(&mut per_q.clone(), 95.0) as f64 / 1e3, "screen_us_p99": pct(&mut per_q.clone(), 99.0) as f64 / 1e3,
                "window_ms_p50": pct(&mut per_w.clone(), 50.0) as f64 / 1e6, "window_ms_p95": pct(&mut per_w.clone(), 95.0) as f64 / 1e6, "window_ms_p99": pct(&mut per_w.clone(), 99.0) as f64 / 1e6,
                "window_ms_max": per_w.iter().max().copied().unwrap_or(0) as f64 / 1e6,
                "window_ms": per_w.iter().map(|&x| x as f64 / 1e6).collect::<Vec<_>>(),
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

/// Phase 5: per window, how much of the candidate stream each arm can clear within a fixed
/// compute budget (candidate construction + screening + the canonical settlement solve), and
/// what that batch nets. Capital-time is reported in components, so any cadence and
/// confirmation assumption can be applied afterwards:
/// `CT = lp_advance_sats * (t_compute + t_confirm) + deferred_sats * t_cadence`.
fn phase5(trace: &Trace, label: &serde_json::Value, budgets_ms: &[f64]) {
    use shz_utxoref::pnl_batch::{RouteTarget, solve_and_verify_pnl_batch};
    let arms = [("cold", Policy::Cold, false, 0usize), ("repair_only", Policy::Lru, true, 0), ("lru_repair", Policy::Lru, true, 4)];
    for (name, policy, repair, retrieval) in arms {
        let mut cache = CertCache::new(policy, 64 << 20, repair, retrieval);
        let mut cost = Vec::with_capacity(trace.queries.len());
        for q in &trace.queries {
            let t = Instant::now();
            let s = cache.screen(&q.problem);
            cost.push(t.elapsed().as_nanos() as u64 + q.build_ns);
            assert_eq!(s.verdict == Verdict::Feasible, q.verdict == Verdict::Feasible, "verdict differs from cold");
        }
        for &b_ms in budgets_ms {
            let budget_ns = (b_ms * 1e6) as u64;
            let (mut tot_gross, mut tot_full, mut tot_net, mut tot_lp, mut tot_locked, mut tot_ct_compute, mut over) = (0u128, 0u128, 0u128, 0u128, 0u128, 0f64, 0u64);
            let mut cleared_q = 0usize;
            for (w, d) in trace.windows_detail.iter().enumerate() {
                let idx: Vec<usize> = (0..trace.queries.len()).filter(|&i| trace.queries[i].window == w).collect();
                let reserve = trace.canonical_ns.get(w).copied().unwrap_or(0);
                let mut spent = 0u64;
                let mut cutoff: Option<usize> = None;
                for &i in &idx {
                    if spent + cost[i] + reserve > budget_ns { break; }
                    spent += cost[i];
                    cutoff = Some(i);
                }
                let obs = cutoff.map(|q| d.accepted_through(q)).unwrap_or_default();
                let full = idx.last().map(|&q| d.accepted_through(q)).unwrap_or_default();
                cleared_q += cutoff.map(|q| idx.iter().position(|&i| i == q).unwrap() + 1).unwrap_or(0);
                let mut snap = d.base.clone();
                snap.obligations = obs.clone();
                let t = Instant::now();
                let batch = solve_and_verify_pnl_batch(&snap, &snap.snapshot_hash()).expect("an accepted prefix settles");
                let canon = t.elapsed().as_nanos() as u64;
                if spent + canon > budget_ns { over += 1; }
                let gross: u128 = obs.iter().map(|o| o.sats as u128).sum();
                let net: u128 = batch.net_account_deltas.values().filter(|&&x| x > 0).map(|&x| x as u128).sum();
                let lp: u128 = batch.route_allocations.iter().filter(|(f, t, _)| match t { RouteTarget::Vault(v) => v != f, RouteTarget::Payout(_) => true }).map(|x| x.2 as u128).sum();
                tot_gross += gross;
                tot_full += full.iter().map(|o| o.sats as u128).sum::<u128>();
                tot_net += net;
                tot_lp += lp;
                tot_locked += batch.total_input_sats as u128;
                tot_ct_compute += lp as f64 * ((spent + canon) as f64 / 1e9);
            }
            println!("{}", json!({"kind": "phase5", "cfg": label, "arm": name, "budget_ms": b_ms,
                "candidates_cleared": cleared_q, "candidates_total": trace.queries.len(),
                "gross_cleared_sats": tot_gross as u64, "gross_full_window_sats": tot_full as u64, "deferred_sats": (tot_full.saturating_sub(tot_gross)) as u64,
                "net_positive_sats": tot_net as u64, "netting_efficiency": if tot_gross > 0 { 1.0 - tot_net as f64 / tot_gross as f64 } else { 0.0 },
                "lp_advance_sats": tot_lp as u64, "locked_input_sats": tot_locked as u64,
                "capital_time_compute_sat_s": tot_ct_compute, "windows_over_budget": over}));
        }
    }
}
