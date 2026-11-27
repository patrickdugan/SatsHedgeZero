"""Summarize CBM-CACHE-03 sweep receipts into the Markdown tables of CBM_CACHE_03_RESULTS.md.

python research/utxoref_verification_cache/cbm03_summarize.py research/utxoref_verification_cache/cbm03_receipts/sweep_heldout.jsonl

Window latencies are pooled across seeds (every window of every run), nearest-rank
percentiles. Screen totals and work counters are summed across seeds.
"""
import json, math, sys
from collections import defaultdict

def pct(v, p):
    v = sorted(v)
    if not v:
        return 0.0
    return v[max(1, math.ceil(p / 100 * len(v))) - 1]

def main(path, budget=1048576):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    arms = [r for r in rows if r["kind"] == "arm"]
    traces = [r for r in rows if r["kind"] == "trace"]
    key = lambda r: (r["cfg"]["accounts"], r["cfg"]["conn"], r["cfg"]["regime"])
    wrong = sum(r["wrong_verdicts"] for r in arms)
    queries = sum(t["queries"] for t in traces)
    canon = sum(t["canonical_checked"] for t in traces)
    infeasible = sum(t["infeasible"] for t in traces)
    print(f"runs {len(traces)}, candidates {queries} ({infeasible} infeasible), canonical comparisons {canon}, "
          f"arm replays {len(arms)}, wrong verdicts {wrong}, inexact deficit bounds {sum(r['inexact_deficit_bounds'] for r in arms)}\n")
    g = defaultdict(list)
    for r in arms:
        if r["arm"] == "cold" or r["budget_bytes"] == budget:
            g[(key(r), r["arm"])].append(r)
    configs = sorted({key(r) for r in arms})
    show = ["cold", "memo", "lru", "utility", "causal", "repair_only", "lru_repair", "causal_repair"]
    print(f"### Screening at a {budget // 1024} KiB certificate budget (sums over seeds)\n")
    print("| accounts | routes | regime | arm | screen ms | vs cold | edge insp. vs cold | aug. paths | transported | repaired | window p50 / p95 / p99 ms | >200 ms |")
    print("|---:|---|---|---|---:|---:|---:|---:|---:|---:|---|---:|")
    for c in configs:
        cold = g.get((c, "cold"))
        if not cold:
            continue
        cold_ms = sum(r["screen_ms_total"] for r in cold)
        for a in show:
            rs = g.get((c, a))
            if not rs:
                continue
            ms = sum(r["screen_ms_total"] for r in rs)
            insp = sum(r["edge_inspections"] for r in rs) / max(1, sum(r["cold_edge_inspections"] for r in rs))
            aug = sum(r["augmenting_paths"] for r in rs)
            paths = defaultdict(int)
            for r in rs:
                for k, v in r["paths"].items():
                    paths[k] += v
            n = sum(paths.values())
            tr = (paths["TransportFlow"] + paths["TransportCut"] + paths["ExactMemo"]) / n
            rep = paths["Repair"] / n
            win = [x for r in rs for x in r["window_ms"]]
            over = sum(x > 200 for x in win)
            print(f"| {c[0]} | {c[1]} | {c[2]} | {a} | {ms:.2f} | {cold_ms / ms if ms else 0:.2f}x | {insp:.3f} | {aug} | {tr:.1%} | {rep:.1%} | "
                  f"{pct(win, 50):.2f} / {pct(win, 95):.2f} / {pct(win, 99):.2f} | {over}/{len(win)} |")
    print("\n### Budget sweep at the largest size (sums over seeds and configs)\n")
    big = max(c[0] for c in configs)
    print("| arm | budget | screen ms | edge insp. vs cold | hits (memo+transport) | saved by hits (insp.) | offline greedy LB | offline LP UB | evictions | bypasses | cache peak KiB |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    agg = defaultdict(list)
    for r in arms:
        if r["cfg"]["accounts"] == big:
            agg[(r["arm"], r["budget_bytes"])].append(r)
    order = show + ["freq", "utility_repair", "repair_compact", "lru_repair_compact"]
    for (a, b), rs in sorted(agg.items(), key=lambda x: (order.index(x[0][0]) if x[0][0] in order else 99, x[0][1])):
        ms = sum(r["screen_ms_total"] for r in rs)
        insp = sum(r["edge_inspections"] for r in rs) / max(1, sum(r["cold_edge_inspections"] for r in rs))
        hits = sum(r["paths"].get("TransportFlow", 0) + r["paths"].get("TransportCut", 0) + r["paths"].get("ExactMemo", 0) for r in rs)
        hs = sum(r.get("hit_saved_inspections", 0) for r in rs)
        print(f"| {a} | {b // 1024} KiB | {ms:.1f} | {insp:.3f} | {hits} | {hs} | {sum(r['oracle_saved_greedy_lb'] for r in rs)} | "
              f"{sum(r['oracle_saved_fractional_ub'] for r in rs)} | {sum(r['evictions'] for r in rs)} | {sum(r['bypasses'] for r in rs)} | "
              f"{max(r['cache_peak_bytes'] for r in rs) / 1024:.0f} |")
    rss = [r["process_peak_rss_bytes"] for r in arms if r["cfg"]["accounts"] == big]
    print(f"\nProcess peak RSS at {big} accounts (whole process, trace included): max {max(rss) / 2**20:.1f} MiB")

def phase5(path):
    rows = [json.loads(l) for l in open(path) if l.strip() and '"phase5"' in l]
    g = defaultdict(list)
    for r in rows:
        g[(r["cfg"]["accounts"], r["cfg"]["conn"], r["arm"], r["budget_ms"])].append(r)
    print("| accounts | routes | arm | budget ms | candidates cleared | gross cleared (Msat) | deferred (Msat) | netting eff. | LP advance (Msat) | compute capital-time (sat s) | windows over budget |")
    print("|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for k in sorted(g):
        rs = g[k]
        sm = lambda f: sum(r[f] for r in rs)
        gross, net = sm("gross_cleared_sats"), sm("net_positive_sats")
        print(f"| {k[0]} | {k[1]} | {k[2]} | {k[3]:.0f} | {sm('candidates_cleared')}/{sm('candidates_total')} | {gross / 1e6:.2f} | "
              f"{sm('deferred_sats') / 1e6:.2f} | {1 - net / gross if gross else 0:.3f} | {sm('lp_advance_sats') / 1e6:.2f} | "
              f"{sm('capital_time_compute_sat_s'):.0f} | {sm('windows_over_budget')} |")

if __name__ == "__main__":
    if sys.argv[1] == "--phase5":
        phase5(sys.argv[2])
    else:
        main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1048576)
