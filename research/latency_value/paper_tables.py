#!/usr/bin/env python3
"""CSV tables for the RTG paper, generated only from committed results."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
SYMS = ("BTC", "ETH", "SOL")


def load(n):
    return json.loads((RES / n).read_text())


def ci(x, scale=100, nd=3):
    if not x:
        return ""
    return f"{x['point']*scale:.{nd}f} [{x['lo95']*scale:.{nd}f}, {x['hi95']*scale:.{nd}f}]"


def write(path, header, rows):
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    an = {s: load(f"analysis_{s}.json") for s in SYMS}
    inv = json.loads((HERE / "manifests" / "l2_inventory.json").read_text())
    rows = []
    for s in SYMS:
        z = an[s]
        cov = z["coverage"]
        rows.append([s, z["days"][0], z["days"][-1], len(cov), sum(v["clean"] for v in cov.values()),
                     sum(len(v["dirty"]) for v in cov.values()), sum(len(v["missing"]) for v in cov.values()),
                     z["wall_seconds"], z["valid_seconds"], f"{z['book']['spread_bps']['0.5']:.3f}",
                     f"{z['book']['depth10_usd']['0.5']/1e6:.2f}", f"{z['book']['rv60_bps']['0.5']:.3f}",
                     inv["summary"][s]["cross_hour_breaks"]])
    write(a.out / "t1_coverage.csv", ["market", "first_day", "last_day", "days", "clean_hours", "dirty_hours", "missing_hours",
                                       "wall_seconds", "valid_seconds", "median_spread_bp", "median_depth10_usd_m", "median_rv60_bp",
                                       "cross_hour_native_breaks"], rows)
    rows = []
    for s in SYMS:
        for ts in ("shz_candidate", "lighter_list", "lighter_staked_max"):
            for key in ("momentum/1000", "momentum/10000", "both/1000", "both/100000"):
                x = an[s]["tiersets"][ts].get(key)
                if not x:
                    continue
                for tier in list(x["win_share_of_covered_time"])[1:]:
                    if tier == "plus":
                        continue
                    rows.append([s, ts, key, tier, ci(x["win_share_of_covered_time"][tier]), ci(x["total_volume_share_in_win_seconds"][tier]),
                                 f"{x['volume_concentration_ratio'][tier]:.2f}" if x["volume_concentration_ratio"][tier] else "",
                                 ci(x["paid_taker_share_in_win_seconds"][tier]), ci(x["win_share_completion"][tier]),
                                 f"{x['mean_net_saving_vs_standard_common'][tier]['point']:.4f}",
                                 f"{x['wtp_gross_bps_quantiles'][tier]['0.99']:.3f}", f"{x['wtp_gross_bps_quantiles'][tier]['0.999']:.3f}",
                                 f"{x['wtp_gross_bps_quantiles'][tier]['0.9999']:.3f}", x["fast_only"].get(tier, ""), x["decisions"]])
    write(a.out / "t2_tier_shares.csv", ["market", "tierset", "cohort/size", "tier", "time_share_pct_ci", "volume_share_pct_ci",
                                         "volume_over_time", "paid_taker_volume_share_pct_ci", "time_share_completion_pct_ci",
                                         "mean_net_saving_bp", "wtp_p99_bp", "wtp_p999_bp", "wtp_p9999_bp", "fast_only_fills", "decisions"], rows)
    rows = []
    for s in SYMS:
        for rn, r in an[s]["tiersets"]["shz_candidate"]["momentum/1000"]["regimes"].items():
            w = r["wtp_quantiles"]
            rows.append([s, rn, r["decisions"], f"{r['win_share']['intermediate']*100:.3f}", f"{r['win_share']['premium']*100:.4f}",
                         f"{w['intermediate']['0.9']:.3f}", f"{w['intermediate']['0.99']:.3f}", f"{w['premium']['0.9']:.3f}", f"{w['premium']['0.99']:.3f}"])
    write(a.out / "t3_regime_wtp.csv", ["market", "rv60_regime", "decisions", "intermediate_wins_pct", "premium_wins_pct",
                                        "wtp_int_p90_bp", "wtp_int_p99_bp", "wtp_prem_p90_bp", "wtp_prem_p99_bp"], rows)
    rows = []
    for p in sorted(RES.glob("policy_*.json")):
        z = json.loads(p.read_text())
        for name, v in z["policies"].items():
            m = v["mean_net_saving_bps_common"]
            rows.append([z["label"], z["train_days"][0], z["train_days"][-1], z["test_days"][0], z["test_days"][-1],
                         z["heldout_is_out_of_sample"], name, f"{m['point']:.5f}", f"{m['lo95']:.5f}", f"{m['hi95']:.5f}",
                         v["paid_choices"], v["paid_choices_positive"], z["test_decisions"]])
    write(a.out / "t4_policies.csv", ["split", "train_first", "train_last", "test_first", "test_last", "out_of_sample", "policy",
                                      "heldout_mean_net_bp", "lo95", "hi95", "paid_choices", "paid_choices_positive", "test_decisions"], rows)
    rows = []
    for s in SYMS:
        d = load(f"diagnostics_{s}.json")
        b = d["best_cell_net_bps"]
        rows.append([s, f"{d['unconditional']['intermediate']:.4f}", f"{d['unconditional']['premium']:.4f}",
                     b["intermediate"]["cell"], f"{b['intermediate']['net']:.3f}", b["premium"]["cell"], f"{b['premium']['net']:.3f}",
                     d["cells"][b["premium"]["cell"]]["n"]])
    write(a.out / "t5_best_causal_cell.csv", ["market", "mean_saving_int_bp", "mean_saving_prem_bp", "best_int_cell", "best_int_net_bp",
                                               "best_prem_cell", "best_prem_net_bp", "best_prem_cell_n"], rows)
    rev = load("revenue.json")
    write(a.out / "t6_daily_revenue.csv", ["day", "perps_volume_usd", "perps_trade_fees_usd", "llama_perps_fees_usd", "llama_perps_revenue_usd",
                                           "effective_fee_bp", "taker_paid_share", "maker_paid_share", "taker_premium_ladder_share",
                                           "taker_plus_rate_share"],
          [[r["day"], f"{r['perps_notional_usd']:.0f}", f"{r['perps_trade_fees_usd']:.0f}", r["llama_perps_fees_usd"], r["llama_perps_revenue_usd"],
            f"{r['effective_fee_bps']:.4f}", f"{r['taker_paid_share']:.4f}", f"{r['maker_paid_share']:.4f}",
            f"{r['taker_premium_ladder_share']:.4f}", f"{r['taker_plus_rate_share']:.4f}"] for r in rev["daily"]])
    rows = []
    for s in SYMS:
        for rn, r in an[s]["observed_fee_revenue_by_regime"].items():
            rows.append([s, rn, f"{r['shares']['seconds']*100:.2f}", f"{r['shares']['volume_usd']*100:.2f}",
                         f"{(r['taker_fee_usd']+r['maker_fee_usd'])/sum(x['taker_fee_usd']+x['maker_fee_usd'] for x in an[s]['observed_fee_revenue_by_regime'].values())*100:.2f}",
                         f"{r['shares']['taker_fee_usd']*100:.2f}", f"{r['effective_fee_bps']:.3f}", f"{r['paid_taker_share']*100:.2f}"])
    write(a.out / "t7_observed_regime_fees.csv", ["market", "rv60_regime", "time_pct", "volume_pct", "fee_revenue_pct", "taker_fee_pct",
                                                  "effective_fee_bp", "paid_taker_volume_pct"], rows)
    shz = load("shz_economics.json")
    rows = []
    for s, rr in shz["oracle_lead"].items():
        for k, v in rr.items():
            lead = an[s]["oracle_lead"][k]
            rows.append([s, k.split("/")[0], k.split("fee")[1], ci(lead["time_share"]), ci(lead["volume_share"]), f"{v['mean_edge_bps']:.3f}",
                         f"{v['pickoff_usd_per_day_upper']:.0f}", f"{v['max_maker_loss_coverage_by_full_rebate']:.3f}" if v["max_maker_loss_coverage_by_full_rebate"] is not None else ""])
    write(a.out / "t8_oracle_lead.csv", ["market", "lead", "fee_bp", "time_share_pct_ci", "volume_share_pct_ci", "mean_net_edge_bp",
                                         "pickoff_usd_per_day_upper", "max_maker_loss_coverage_full_rebate"], rows)
    rows = []
    for r in shz["breakeven"]:
        b = r["breakeven_daily_volume_usd"]
        rows.append([r["adoption"], r["cost"], r["routers"], f"{r['fee_rate_bps_on_all_volume']:.4f}",
                     f"{b['system']:.4g}" if b["system"] else "", f"{b['federation']:.4g}" if b.get("federation") else "",
                     f"{b['per_router']:.4g}" if b.get("per_router") else "", b.get("fed_cost"), f"{b.get('router_cost', 0):.1f}",
                     b.get("binding", ""), f"{b['federation_share_minimising_breakeven']:.3f}" if b.get("federation_share_minimising_breakeven") else "",
                     f"{b['system_at_optimal_split']:.4g}" if b.get("system_at_optimal_split") else ""])
    write(a.out / "t9_breakeven.csv", ["adoption", "cost", "routers", "blended_fee_bp", "system_breakeven_usd_day", "federation_breakeven_usd_day",
                                       "per_router_breakeven_usd_day", "federation_cost_usd_day", "router_cost_usd_day", "binding_side",
                                       "federation_share_minimising_breakeven", "system_breakeven_at_that_share"], rows)
    rows = []
    for k, v in shz["elasticities"].items():
        for dk, dv in v.items():
            if not dk.startswith("delta"):
                continue
            rows.append([k, dk, f"{dv['revenue_max_fee_bps']:.3f}", f"{dv['revenue_max_bps_per_volume']:.4f}",
                         f"{dv['at']['0.5']['share']:.4f}", dv["at"]["0.5"]["fee_elasticity_of_revenue"] and f"{dv['at']['0.5']['fee_elasticity_of_revenue']:.3f}",
                         f"{dv['at']['2.0']['share']:.4f}", dv["at"]["2.0"]["fee_elasticity_of_revenue"] and f"{dv['at']['2.0']['fee_elasticity_of_revenue']:.3f}",
                         v.get("latency_elasticity_at_0.5bp") and f"{v['latency_elasticity_at_0.5bp']:.3f}",
                         v.get("latency_elasticity_at_2.0bp") and f"{v['latency_elasticity_at_2.0bp']:.3f}"])
    write(a.out / "t10_elasticities.csv", ["market/cohort/size", "latency_advantage", "revenue_max_fee_bp", "revenue_max_bp_per_volume",
                                           "share_at_0.5bp", "fee_elasticity_R_at_0.5bp", "share_at_2bp", "fee_elasticity_R_at_2bp",
                                           "latency_elasticity_s_at_0.5bp", "latency_elasticity_s_at_2bp"], rows)
    print("tables written to", a.out)


if __name__ == "__main__":
    main()
