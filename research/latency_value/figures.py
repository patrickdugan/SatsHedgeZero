#!/usr/bin/env python3
"""Paper figures from committed aggregate results (no raw data needed)."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
FIG = HERE / "figures"
# Reference palette, light surface; three categorical slots max per chart.
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
MARKET_COLOR = {"BTC": SERIES[0], "ETH": SERIES[1], "SOL": SERIES[2]}
SYMS = ("BTC", "ETH", "SOL")


def style(ax, title=None, xlabel=None, ylabel=None):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(AXIS)
    ax.tick_params(colors=MUTED, labelsize=8)
    ax.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    if title:
        ax.set_title(title, color=INK, fontsize=10, loc="left")
    if xlabel:
        ax.set_xlabel(xlabel, color=INK2, fontsize=8)
    if ylabel:
        ax.set_ylabel(ylabel, color=INK2, fontsize=8)


def fig_new(w=7.0, h=3.4, n=1):
    f, ax = plt.subplots(1, n, figsize=(w, h), dpi=160)
    f.patch.set_facecolor(SURFACE)
    return f, ax


def load(name):
    p = RES / name
    return json.loads(p.read_text()) if p.exists() else None


def rare_event():
    """Time share vs volume share of ex-post paid-tier seconds."""
    f, axes = fig_new(7.2, 3.4, 2)
    for ax, tier, ref in zip(axes, ("intermediate", "premium"), (0.02, 0.001)):
        for i, sym in enumerate(SYMS):
            an = load(f"analysis_{sym}.json")
            if not an:
                continue
            for j, size in enumerate((1000, 10000)):
                s = an["tiersets"]["shz_candidate"].get(f"momentum/{size}")
                if not s:
                    continue
                t = s["win_share_of_covered_time"][tier]; v = s["total_volume_share_in_win_seconds"][tier]
                if not t or t["point"] <= 0:
                    continue
                x = i * 3 + j
                ax.errorbar([x - 0.15], [t["point"]], yerr=[[t["point"] - t["lo95"]], [t["hi95"] - t["point"]]], fmt="o",
                            color=MARKET_COLOR[sym], mfc=SURFACE, ms=5, lw=1.2)
                ax.errorbar([x + 0.15], [v["point"]], yerr=[[v["point"] - v["lo95"]], [v["hi95"] - v["point"]]], fmt="o",
                            color=MARKET_COLOR[sym], ms=5, lw=1.2)
        ax.axhline(ref, color=MUTED, lw=1, ls="--")
        ax.text(7.6, ref * 1.15, f"hypothesis {ref:.1%}", color=INK2, fontsize=7, ha="right")
        ax.set_yscale("log")
        ax.set_xticks([0, 1, 3, 4, 6, 7], ["BTC\n$1k", "$10k", "ETH\n$1k", "$10k", "SOL\n$1k", "$10k"])
        style(ax, f"{tier.capitalize()} tier ex-post optimal", None, "share (log)")
    h1, = axes[0].plot([], [], "o", color=INK2, mfc=SURFACE)
    h2, = axes[0].plot([], [], "o", color=INK2)
    f.legend([h1, h2], ["share of covered time (open)", "share of matched volume (filled)"], fontsize=7, frameon=False,
             loc="lower center", ncol=2)
    f.tight_layout(rect=(0, 0.06, 1, 1))
    f.savefig(FIG / "fig1_rare_event_time_vs_volume.png", facecolor=SURFACE)
    plt.close(f)


def demand():
    """Ex-post demand CCDF: share of decisions whose gross saving exceeds fee f."""
    f, axes = fig_new(7.2, 3.4, 2)
    for ax, dl, lab in zip(axes, (100, 200), ("300→100 ms", "300→200 ms")):
        for sym in SYMS:
            an = load(f"analysis_{sym}.json")
            if not an:
                continue
            c = an["demand_curves"][f"momentum/1000/{dl}"]
            x = np.array(c["fee_grid_bps"]); y = np.array(c["volume_share"])
            ok = y > 0
            ax.plot(x[ok], y[ok], color=MARKET_COLOR[sym], lw=2, label=sym)
        ax.set_xscale("log"); ax.set_yscale("log")
        lo = ax.get_ylim()[0]
        for fee, nm in ((0.5, "0.5 bp"), (2.0, "2 bp")):
            ax.axvline(fee, color=MUTED, lw=1, ls="--")
            ax.text(fee * 1.06, lo * 2, nm, color=INK2, fontsize=7)
        style(ax, lab, "fee f (bp)", "volume share with saving > f" if dl == 100 else None)
    axes[0].legend(fontsize=7, frameon=False)
    f.suptitle("Ex-post demand for a latency advantage, $1k momentum taker", color=INK, fontsize=10, x=0.02, ha="left")
    f.tight_layout()
    f.savefig(FIG / "fig2_expost_demand_ccdf.png", facecolor=SURFACE)
    plt.close(f)


def revenue_curve():
    f, ax = fig_new(4.6, 3.4)
    for sym in SYMS:
        an = load(f"analysis_{sym}.json")
        if not an:
            continue
        c = an["demand_curves"]["momentum/1000/100"]
        x = np.array(c["fee_grid_bps"]); r = np.array(c["volume_share"]) * x
        ax.plot(x, r, color=MARKET_COLOR[sym], lw=2, label=sym)
        k = int(np.argmax(r))
        ax.plot([x[k]], [r[k]], "o", color=MARKET_COLOR[sym], ms=6, mec=SURFACE, mew=2)
    ax.set_xscale("log")
    style(ax, "Upper-bound fee yield f·s(f), 300→100 ms", "fee f (bp)", "bp per unit of momentum volume")
    ax.legend(fontsize=7, frameon=False)
    f.tight_layout()
    f.savefig(FIG / "fig3_fee_yield_upper_bound.png", facecolor=SURFACE)
    plt.close(f)


def regime_revenue():
    f, axes = fig_new(7.2, 3.2, 3)
    for ax, sym in zip(axes, SYMS):
        an = load(f"analysis_{sym}.json")
        if not an:
            continue
        rr = an["observed_fee_revenue_by_regime"]
        names = list(rr)
        vs = [rr[n]["shares"]["volume_usd"] for n in names]
        fs = [(rr[n]["taker_fee_usd"] + rr[n]["maker_fee_usd"]) / max(sum(rr[m]["taker_fee_usd"] + rr[m]["maker_fee_usd"] for m in names), 1e-9) for n in names]
        x = np.arange(len(names))
        ax.bar(x - 0.2, vs, 0.38, color=SERIES[0], label="volume")
        ax.bar(x + 0.2, fs, 0.38, color=SERIES[1], label="fee revenue")
        ax.set_xticks(x, [n.replace("rv", "") for n in names], rotation=35, fontsize=6)
        style(ax, sym, None, "share" if sym == "BTC" else None)
    axes[0].legend(fontsize=7, frameon=False)
    f.suptitle("Observed Lighter fees by causal 60 s volatility regime", color=INK, fontsize=10, x=0.02, ha="left")
    f.tight_layout()
    f.savefig(FIG / "fig4_observed_fees_by_regime.png", facecolor=SURFACE)
    plt.close(f)


def policies():
    labels = ["BTC_oct11_1k", "BTC_dev_1k", "BTC_dev_10k", "ETH_dev_1k", "ETH_dev_10k", "SOL_dev_1k", "SOL_dev_10k"]
    names = ["pr30_score_bins", "threshold", "gbm", "ex_post_oracle"]
    f, ax = fig_new(7.2, 3.6)
    cols = [SERIES[0], SERIES[1], SERIES[2], MUTED]
    for li, lab in enumerate(labels):
        z = load(f"policy_{lab}.json")
        if not z:
            continue
        for k, nm in enumerate(names):
            m = z["policies"][nm]["mean_net_saving_bps_common"]
            if not m:
                continue
            x = li + (k - 1.5) * 0.18
            ax.errorbar([x], [m["point"]], yerr=[[m["point"] - m["lo95"]], [m["hi95"] - m["point"]]], fmt="o", ms=4,
                        color=cols[k], lw=1.2, label=nm if li == 0 else None)
    ax.axhline(0, color=AXIS, lw=1)
    ax.set_xticks(range(len(labels)), [l.replace("_", "\n") for l in labels], fontsize=7)
    style(ax, "Held-out mean net saving vs free-only (bp per common decision)", None, "bp")
    ax.legend(fontsize=7, frameon=False, ncol=4, loc="upper left")
    f.tight_layout()
    f.savefig(FIG / "fig5_policy_heldout.png", facecolor=SURFACE)
    plt.close(f)


def markouts():
    f, axes = fig_new(7.2, 3.2, 3)
    hs = (200, 1000, 5000, 30000)
    for ax, sym in zip(axes, SYMS):
        an = load(f"analysis_{sym}.json")
        if not an:
            continue
        s = an["tiersets"]["shz_candidate"]["momentum/1000"]["markouts"]
        for j, tier in enumerate(("standard", "intermediate", "premium")):
            y = [s[f"{tier}_{h}ms"]["mean_bps"] for h in hs]
            ax.plot(range(4), y, color=SERIES[j], lw=2, marker="o", ms=4, label=tier)
        ax.axhline(0, color=AXIS, lw=1)
        ax.set_xticks(range(4), ["200ms", "1s", "5s", "30s"], fontsize=7)
        style(ax, sym, None, "taker markout, bp" if sym == "BTC" else None)
    axes[0].legend(fontsize=7, frameon=False)
    f.suptitle("Gross taker markout after IOC fill, $1k momentum (maker adverse selection = negative)", color=INK, fontsize=9, x=0.02, ha="left")
    f.tight_layout()
    f.savefig(FIG / "fig6_markouts.png", facecolor=SURFACE)
    plt.close(f)


def breakeven():
    z = load("shz_economics.json")
    if not z:
        return
    f, ax = fig_new(5.6, 3.6)
    x = [r["fee_rate_bps"] for r in z["sensitivity_system_breakeven_vs_rate"]]
    for j, lab in enumerate(("low", "base", "high")):
        ax.plot(x, [r[lab] for r in z["sensitivity_system_breakeven_vs_rate"]], color=SERIES[j], lw=2, label=f"{lab} cost")
    for name, sc in z["adoption_scenarios"].items():
        if not name.startswith(("lighter_observed", "latency_optimal_BTC")):
            continue
        rate = (sc["taker_int"] * 50 + sc["taker_prem"] * 200 + sc["maker_prem"] * 20) / 100
        ax.axvline(rate, color=MUTED, lw=1, ls="--")
        ax.text(rate * 1.05, 2e9, name.replace("_", " "), color=INK2, fontsize=6, rotation=90, va="top")
    ax.set_xscale("log"); ax.set_yscale("log")
    style(ax, "SHZ system break-even daily volume (3 routers)", "blended fee on all volume (bp)", "USD per day")
    ax.legend(fontsize=7, frameon=False)
    f.tight_layout()
    f.savefig(FIG / "fig7_shz_breakeven.png", facecolor=SURFACE)
    plt.close(f)


def daily_fees():
    z = load("revenue.json")
    if not z:
        return
    d = z["daily"]
    f, axes = fig_new(7.2, 4.6, 1)
    plt.close(f)
    f, (a1, a2) = plt.subplots(2, 1, figsize=(7.2, 4.8), dpi=160, sharex=True)
    f.patch.set_facecolor(SURFACE)
    x = np.arange(len(d))
    a1.plot(x, [r["perps_trade_fees_usd"] / 1e3 for r in d], color=SERIES[0], lw=2, label="sum of per-trade fees (public trades)")
    a1.plot(x, [(r["llama_perps_fees_usd"] or np.nan) / 1e3 for r in d], color=SERIES[1], lw=2, ls="--", label="DefiLlama lighter-perps dailyFees")
    style(a1, "Lighter perpetuals: daily fees, two sources", None, "USD thousands")
    a1.legend(fontsize=7, frameon=False)
    a2.plot(x, [r["effective_fee_bps"] for r in d], color=SERIES[0], lw=2, label="all fees / volume")
    a2.plot(x, [r["effective_taker_fee_bps"] for r in d], color=SERIES[1], lw=2, label="taker fees / volume")
    a2.plot(x, [r["effective_maker_fee_bps"] for r in d], color=SERIES[2], lw=2, label="maker fees / volume")
    style(a2, "Effective realised fee rate", None, "bp of matched notional")
    a2.legend(fontsize=7, frameon=False, ncol=3)
    ticks = x[::7]
    a2.set_xticks(ticks, [d[i]["day"][5:] for i in ticks], fontsize=7)
    f.tight_layout()
    f.savefig(FIG / "fig8_daily_fees.png", facecolor=SURFACE)
    plt.close(f)


def main():
    FIG.mkdir(exist_ok=True)
    for fn in (rare_event, demand, revenue_curve, regime_revenue, policies, markouts, breakeven, daily_fees):
        fn()
        print("figure", fn.__name__)


if __name__ == "__main__":
    main()
