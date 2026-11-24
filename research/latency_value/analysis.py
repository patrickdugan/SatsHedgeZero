#!/usr/bin/env python3
"""Counterfactual IOC tier economics, rare-event test and willingness to pay.

Inputs: market-days assembled by features.cached_day (local cache).
Outputs: aggregate JSON only (no prices, no per-second rows).

Definitions (all in bp of arrival mid, per decision = one second x one side):
  net cost of tier T   = VWAP cost at the tier's delay + tier taker fee
  "common"             = every tier in the set fully fills at its delay
  ex-post winner       = argmin net cost over the set, among common decisions;
                         ties go to the cheaper tier
  completion variant   = an unfilled remainder is charged at the IOC limit
                         (LIMIT_BPS), a conservative cost of missing a fill
  WTP(T vs standard)   = gross cost(standard) - gross cost(T), i.e. the
                         largest fee at which T would not lose to standard
  taker markout(h)     = side * (mid(t+d+h) - VWAP) / mid(t), gross of fees;
                         the passive counterparty's markout is its negative
Cohorts: momentum (side = sign of the last 1 s mid move, the PR #30 cohort),
flow (side = sign of lagged 1 s signed trade flow), both (two decisions per
second, an uninformed taker).
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np

from common import DELAYS_MS, HORIZONS_MS, LIGHTER_TIERS, LIMIT_BPS, SHZ_TIERS, SIZES_USD
from features import FEATURES, cached_day

TIERSETS = {
    "shz_candidate": SHZ_TIERS,
    "lighter_list": LIGHTER_TIERS,
    "lighter_staked_max": (("standard", 300, 0.0), ("plus", 300, 0.5), ("premium", 140, 1.96)),
}
FI = {k: i for i, k in enumerate(FEATURES)}
DI = {d: i for i, d in enumerate(DELAYS_MS)}
RNG = np.random.default_rng(20261125)


def decisions(day, cohort):
    """Return (second index, side index 0=buy 1=sell, side sign) arrays."""
    n = len(day["valid"])
    v = day["valid"]
    if cohort == "both":
        t = np.flatnonzero(v)
        return np.concatenate([t, t]), np.concatenate([np.zeros(len(t), int), np.ones(len(t), int)])
    if cohort == "momentum":
        s = np.sign(day["feat"][:, FI["r1"]])
    elif cohort == "flow":
        s = np.sign(day["feat"][:, FI["flow1_signed"]])
    else:
        raise ValueError(cohort)
    s = np.nan_to_num(s)
    t = np.flatnonzero(v & (s != 0))
    return t, np.where(s[t] > 0, 0, 1)


def tier_matrix(day, t, si, size_idx, tiers, completion=False):
    """Net cost (n,T), gross cost (n,T), full-fill flag (n,T), known flag (n,T)."""
    T = len(tiers)
    gross = np.empty((len(t), T)); full = np.empty((len(t), T), bool); known = np.empty((len(t), T), bool)
    fee = np.array([f for _, _, f in tiers])
    for j, (_, d, _) in enumerate(tiers):
        fr = day["frac"][t, si, DI[d], size_idx].astype(float)
        c = day["cost"][t, si, DI[d], size_idx].astype(float)
        known[:, j] = ~np.isnan(fr)
        full[:, j] = fr >= 1 - 1e-9
        if completion:
            c = np.where(fr > 0, np.nan_to_num(c) * fr + (1 - fr) * LIMIT_BPS, LIMIT_BPS)
            c[~known[:, j]] = np.nan
        gross[:, j] = np.where(full[:, j] | completion, c, np.nan)
    return gross + fee, gross, full, known


def winners(net, ok):
    w = np.full(len(net), -1)
    x = np.where(np.isnan(net), np.inf, net)
    # ties -> lowest index (tiers are listed in ascending fee order)
    w[ok] = np.argmin(x[ok] + np.arange(net.shape[1]) * 1e-12, axis=1)
    return w


def q(x, qs=(0.5, 0.9, 0.99, 0.999)):
    x = x[np.isfinite(x)]
    return {str(k): float(np.quantile(x, k)) for k in qs} if len(x) else None


def boot_ratio(num_by_day, den_by_day, B=2000):
    num, den = np.asarray(num_by_day, float), np.asarray(den_by_day, float)
    if den.sum() == 0:
        return None
    k = len(num)
    idx = RNG.integers(0, k, (B, k))
    r = num[idx].sum(1) / np.maximum(den[idx].sum(1), 1e-300)
    return dict(point=float(num.sum() / den.sum()), lo95=float(np.quantile(r, 0.025)), hi95=float(np.quantile(r, 0.975)))


FEE_GRID = tuple(float(x) for x in np.round(np.geomspace(0.05, 20, 25), 4))


def demand_curves(loaded):
    """Ex-post demand for a latency advantage at a per-trade fee f (bp):
    share of decisions (and of realised same-side volume) whose gross saving
    from moving 300 ms -> d exceeds f, among decisions where both delays fully
    fill. Also the fast-only rate (d fills fully, 300 ms does not). These are
    upper bounds on demand: they assume perfect foresight of the saving."""
    out = {}
    for cohort in ("momentum", "both"):
        for s_idx, size in enumerate(SIZES_USD):
            for dl in (200, 140, 100):
                n = 0; nvol = 0.0; fast_only = 0; known = 0
                cnt = np.zeros(len(FEE_GRID)); vol = np.zeros(len(FEE_GRID)); rev = np.zeros(len(FEE_GRID))
                for _, d in loaded:
                    t, si = decisions(d, cohort)
                    fs = d["frac"][t, si, DI[300], s_idx].astype(float); ff = d["frac"][t, si, DI[dl], s_idx].astype(float)
                    cs = d["cost"][t, si, DI[300], s_idx].astype(float); cf = d["cost"][t, si, DI[dl], s_idx].astype(float)
                    k = ~np.isnan(fs) & ~np.isnan(ff)
                    both = k & (fs >= 1 - 1e-9) & (ff >= 1 - 1e-9)
                    w = (cs - cf)[both]
                    v = np.nan_to_num(np.where(si == 0, d["buy_usd"][t], d["sell_usd"][t]))[both]
                    known += int(k.sum()); n += int(both.sum()); nvol += float(v.sum())
                    fast_only += int((k & (ff >= 1 - 1e-9) & (fs < 1 - 1e-9)).sum())
                    for i, f in enumerate(FEE_GRID):
                        m = w > f
                        cnt[i] += m.sum(); vol[i] += v[m].sum(); rev[i] += (v[m] * f / 1e4).sum()
                out[f"{cohort}/{size}/{dl}"] = dict(
                    fee_grid_bps=FEE_GRID, decisions_common=n, decisions_known=known, fast_only=fast_only,
                    decision_share=(cnt / max(n, 1)).tolist(), volume_share=(vol / nvol if nvol else cnt * 0).tolist(),
                    volume_usd_common=nvol, fee_revenue_usd_if_all_exceeding_pay=rev.tolist())
    return out


def market_analysis(sym, days, clock="received"):
    out = dict(symbol=sym, clock=clock, days=days, coverage={}, tiersets={})
    loaded = []
    for dname in days:
        d = cached_day(sym, dname, clock)
        hours = d["hours"]
        out["coverage"][dname] = dict(clean=sum(v == "clean" for v in hours.values()),
                                      dirty=[k for k, v in hours.items() if v == "dirty"],
                                      missing=[k for k, v in hours.items() if v == "missing"],
                                      valid_seconds=int(d["valid"].sum()),
                                      trades_available=bool(d["trades_available"]))
        if d["valid"].any():
            loaded.append((dname, d))
    out["wall_seconds"] = 86_400 * len(days)
    out["valid_seconds"] = int(sum(d["valid"].sum() for _, d in loaded))
    # Book-state descriptive distributions.
    sp = np.concatenate([d["feat"][d["valid"], FI["spread_bps"]] for _, d in loaded])
    dep = np.concatenate([d["feat"][d["valid"], FI["depth10_usd"]] for _, d in loaded])
    rv = np.concatenate([d["feat"][d["valid"], FI["rv60"]] for _, d in loaded])
    out["book"] = dict(spread_bps=q(sp, (0.1, 0.5, 0.9, 0.99)), depth10_usd=q(dep, (0.01, 0.1, 0.5, 0.9)),
                       rv60_bps=q(rv, (0.5, 0.9, 0.99, 0.999)))
    rv_cuts = np.nanquantile(rv, [0.5, 0.9, 0.99, 0.999])
    out["regime_cuts_rv60_bps"] = rv_cuts.tolist()
    regime_names = ("rv<p50", "p50-p90", "p90-p99", "p99-p99.9", ">p99.9")
    for tsname, tiers in TIERSETS.items():
        res = {}
        for cohort in ("momentum", "flow", "both"):
            for s_idx, size in enumerate(SIZES_USD):
                per_day = []
                agg = dict(gross_saving={j: [] for j in range(1, 3)}, markouts={}, regimes={})
                mk = {(j, h): [0.0, 0.0, 0.0, 0] for j in range(3) for h in range(len(HORIZONS_MS))}  # sum, wsum, w, n
                reg = {r: dict(n=0, common=0, win=[0, 0, 0], wtp1=[], wtp2=[], vol=0.0) for r in regime_names}
                missed = np.zeros((3, 3))  # [tier] -> known, full, partial-or-none
                for dname, d in loaded:
                    t, si = decisions(d, cohort)
                    if len(t) == 0:
                        continue
                    net, gross, full, known = tier_matrix(d, t, si, s_idx, tiers)
                    allknown = known.all(1)
                    common = allknown & full.all(1)
                    w = winners(net, common)
                    netc, _, _, knownc = tier_matrix(d, t, si, s_idx, tiers, completion=True)
                    wc = winners(netc, knownc.all(1))
                    vol = np.nan_to_num(np.where(si == 0, d["buy_usd"][t], d["sell_usd"][t]))
                    tot_vol = np.nan_to_num(d["buy_usd"][t] + d["sell_usd"][t])
                    # Per-second union of winning decisions; denominators are all
                    # covered seconds of the day (valid book or not).
                    sec_vol = np.nan_to_num(d["buy_usd"] + d["sell_usd"]) * d["covered"]
                    sec_paid = np.nan_to_num(d["paid_taker_usd"]) * d["covered"]
                    win_sec = []
                    for j in range(3):
                        m_ = np.zeros(len(d["valid"]), bool)
                        m_[t[w == j]] = True
                        win_sec.append(m_)
                    for j in range(3):
                        missed[j, 0] += known[:, j].sum(); missed[j, 1] += (known[:, j] & full[:, j]).sum()
                    row = dict(day=dname, decisions=int(len(t)), all_known=int(allknown.sum()), common=int(common.sum()),
                               win=[int((w == j).sum()) for j in range(3)],
                               win_completion=[int((wc == j).sum()) for j in range(3)],
                               completion_known=int(knownc.all(1).sum()),
                               side_vol_win=[float(vol[w == j].sum()) for j in range(3)],
                               side_vol_common=float(vol[common].sum()), side_vol_all=float(vol.sum()),
                               win_seconds=[int(m_.sum()) for m_ in win_sec],
                               covered_seconds=int(d["covered"].sum()),
                               tot_vol_win=[float(sec_vol[m_].sum()) for m_ in win_sec],
                               tot_vol_all=float(sec_vol.sum()),
                               paid_taker_win=[float(sec_paid[m_].sum()) for m_ in win_sec],
                               paid_taker_all=float(sec_paid.sum()),
                               fast_only=[int((known[:, 0] & known[:, j] & full[:, j] & ~full[:, 0]).sum()) for j in range(3)],
                               slow_only=[int((known[:, 0] & known[:, j] & ~full[:, j] & full[:, 0]).sum()) for j in range(3)],
                               net_saving_sum=[float(np.nansum((net[:, 0] - net[:, j])[common])) for j in range(3)])
                    per_day.append(row)
                    for j in (1, 2):
                        agg["gross_saving"][j].append((gross[:, 0] - gross[:, j])[common])
                    # markouts per tier over decisions that fully fill at that tier
                    fut = d["fut"][t]  # (n, D, H)
                    sign = np.where(si == 0, 1.0, -1.0)
                    for j, (_, dl, fee) in enumerate(tiers):
                        ok = full[:, j]
                        for hi in range(len(HORIZONS_MS)):
                            m = sign * fut[:, DI[dl], hi] - gross[:, j]
                            g = ok & np.isfinite(m)
                            acc = mk[j, hi]
                            acc[0] += m[g].sum(); acc[1] += (m[g] * vol[g]).sum(); acc[2] += vol[g].sum(); acc[3] += g.sum()
                    rvt = d["feat"][t, FI["rv60"]]
                    rid = np.searchsorted(rv_cuts, rvt)
                    for r_i, rname in enumerate(regime_names):
                        sel = (rid == r_i) & np.isfinite(rvt)
                        rr = reg[rname]
                        rr["n"] += int(sel.sum()); rr["common"] += int((sel & common).sum())
                        for j in range(3):
                            rr["win"][j] += int((sel & (w == j)).sum())
                        rr["wtp1"].append((gross[:, 0] - gross[:, 1])[sel & common])
                        rr["wtp2"].append((gross[:, 0] - gross[:, 2])[sel & common])
                        rr["vol"] += float(vol[sel].sum())
                if not per_day:
                    continue
                dec = [r["decisions"] for r in per_day]
                summary = dict(
                    decisions=int(sum(dec)), common=int(sum(r["common"] for r in per_day)),
                    all_known=int(sum(r["all_known"] for r in per_day)),
                    win_share_of_decisions={tiers[j][0]: boot_ratio([r["win"][j] for r in per_day], dec) for j in range(3)},
                    win_share_completion={tiers[j][0]: boot_ratio([r["win_completion"][j] for r in per_day], dec) for j in range(3)},
                    win_share_of_wall_time={tiers[j][0]: boot_ratio([r["win_seconds"][j] for r in per_day], [86_400] * len(per_day)) for j in range(3)},
                    win_share_of_covered_time={tiers[j][0]: boot_ratio([r["win_seconds"][j] for r in per_day], [r["covered_seconds"] for r in per_day]) for j in range(3)},
                    side_volume_share_in_win_seconds={tiers[j][0]: boot_ratio([r["side_vol_win"][j] for r in per_day], [r["side_vol_all"] for r in per_day]) for j in range(3)},
                    total_volume_share_in_win_seconds={tiers[j][0]: boot_ratio([r["tot_vol_win"][j] for r in per_day], [r["tot_vol_all"] for r in per_day]) for j in range(3)},
                    volume_concentration_ratio={tiers[j][0]: (lambda v, s: v["point"] / s["point"] if v and s and s["point"] else None)(
                        boot_ratio([r["tot_vol_win"][j] for r in per_day], [r["tot_vol_all"] for r in per_day]),
                        boot_ratio([r["win_seconds"][j] for r in per_day], [r["covered_seconds"] for r in per_day])) for j in range(3)},
                    paid_taker_share_in_win_seconds={tiers[j][0]: boot_ratio([r["paid_taker_win"][j] for r in per_day], [r["paid_taker_all"] for r in per_day]) for j in range(3)},
                    fast_only={tiers[j][0]: int(sum(r["fast_only"][j] for r in per_day)) for j in range(1, 3)},
                    slow_only={tiers[j][0]: int(sum(r["slow_only"][j] for r in per_day)) for j in range(1, 3)},
                    full_fill_rate={tiers[j][0]: float(missed[j, 1] / max(missed[j, 0], 1)) for j in range(3)},
                    mean_net_saving_vs_standard_common={tiers[j][0]: boot_ratio([r["net_saving_sum"][j] for r in per_day], [r["common"] for r in per_day]) for j in (1, 2)},
                    wtp_gross_bps_quantiles={tiers[j][0]: q(np.concatenate(agg["gross_saving"][j]), (0.5, 0.9, 0.99, 0.999, 0.9999)) for j in (1, 2)},
                    wtp_exceeds_fee_share={tiers[j][0]: float(np.mean(np.concatenate(agg["gross_saving"][j]) > tiers[j][2])) if len(np.concatenate(agg["gross_saving"][j])) else None for j in (1, 2)},
                    markouts={f"{tiers[j][0]}_{HORIZONS_MS[h]}ms": dict(
                        mean_bps=mk[j, h][0] / mk[j, h][3] if mk[j, h][3] else None,
                        volume_weighted_bps=mk[j, h][1] / mk[j, h][2] if mk[j, h][2] else None, n=mk[j, h][3])
                        for j in range(3) for h in range(len(HORIZONS_MS))},
                    regimes={rn: dict(decisions=rr["n"], common=rr["common"],
                                      win_share={tiers[j][0]: rr["win"][j] / rr["n"] if rr["n"] else None for j in range(3)},
                                      wtp_quantiles={tiers[1][0]: q(np.concatenate(rr["wtp1"]) if rr["wtp1"] else np.array([]), (0.5, 0.9, 0.99)),
                                                     tiers[2][0]: q(np.concatenate(rr["wtp2"]) if rr["wtp2"] else np.array([]), (0.5, 0.9, 0.99))},
                                      volume_usd=rr["vol"])
                             for rn, rr in reg.items()},
                    per_day=per_day)
                res[f"{cohort}/{size}"] = summary
        out["tiersets"][tsname] = res
    # Feed-only arm: value of seeing the mark L ms before the public stream.
    # A subscriber who knows mid(t+L) can take a stale public quote at the
    # touch; gross edge = |mid move| - half spread, net of the paid taker fee.
    # Capacity is the displayed touch-side depth within 10 bp, capped at $100k.
    lead_out = {}
    for li, L in enumerate((100, 200)):
        for fee in (0.0, 0.5, 2.0):
            per_day = []
            for dname, d in loaded:
                v = d["valid"]
                a = np.abs(d["lead"][v, li].astype(float))
                hs = d["feat"][v, FI["spread_bps"]] / 2
                up = d["lead"][v, li] > 0
                cap = np.minimum(np.where(up, d["depth"][v, 1], d["depth"][v, 0]).astype(float), 100_000)
                e = a - hs - fee
                ok = np.isfinite(e)
                pos = ok & (e > 0)
                secvol = np.nan_to_num(d["buy_usd"][v] + d["sell_usd"][v])
                per_day.append(dict(day=dname, seconds=int(ok.sum()), positive=int(pos.sum()),
                                    edge_usd=float(np.nansum(e[pos] * cap[pos] / 1e4)),
                                    vol_pos=float(secvol[pos].sum()), vol_all=float(secvol[ok].sum()),
                                    edge_bps_sum=float(e[pos].sum())))
            lead_out[f"{L}ms/fee{fee}"] = dict(
                time_share=boot_ratio([p["positive"] for p in per_day], [p["seconds"] for p in per_day]),
                volume_share=boot_ratio([p["vol_pos"] for p in per_day], [p["vol_all"] for p in per_day]),
                mean_edge_bps_when_positive=(sum(p["edge_bps_sum"] for p in per_day) / max(sum(p["positive"] for p in per_day), 1)),
                pickoff_usd_per_day_upper=sum(p["edge_usd"] for p in per_day) / max(len(per_day), 1))
    out["oracle_lead"] = lead_out
    # Observed Lighter fee revenue by causal volatility regime (trade-level fee
    # fields summed per second; no account attribution).
    rr = {r: dict(seconds=0, volume_usd=0.0, paid_taker_usd=0.0, taker_fee_usd=0.0, maker_fee_usd=0.0) for r in regime_names}
    for _, d in loaded:
        v = d["valid"]
        rid = np.searchsorted(rv_cuts, d["feat"][:, FI["rv60"]])
        fin = v & np.isfinite(d["feat"][:, FI["rv60"]])
        for r_i, rname in enumerate(regime_names):
            sel = fin & (rid == r_i)
            x = rr[rname]
            x["seconds"] += int(sel.sum())
            x["volume_usd"] += float(np.nansum(d["buy_usd"][sel] + d["sell_usd"][sel]))
            x["paid_taker_usd"] += float(np.nansum(d["paid_taker_usd"][sel]))
            x["taker_fee_usd"] += float(np.nansum(d["taker_fee_usd"][sel]))
            x["maker_fee_usd"] += float(np.nansum(d["maker_fee_usd"][sel]))
    tot = {k: sum(x[k] for x in rr.values()) for k in rr[regime_names[0]]}
    for x in rr.values():
        x["shares"] = {k: x[k] / tot[k] if tot[k] else None for k in tot}
        x["effective_fee_bps"] = (x["taker_fee_usd"] + x["maker_fee_usd"]) / x["volume_usd"] * 1e4 if x["volume_usd"] else None
        x["paid_taker_share"] = x["paid_taker_usd"] / x["volume_usd"] if x["volume_usd"] else None
    out["observed_fee_revenue_by_regime"] = rr
    out["demand_curves"] = demand_curves(loaded)
    # Delay-by-size fill and cost table (both sides, no fees).
    table = {}
    for s_idx, size in enumerate(SIZES_USD):
        for dl in DELAYS_MS:
            fr = np.concatenate([d["frac"][d["valid"], :, DI[dl], s_idx].ravel() for _, d in loaded]).astype(float)
            c = np.concatenate([d["cost"][d["valid"], :, DI[dl], s_idx].ravel() for _, d in loaded]).astype(float)
            sp_rep = np.concatenate([np.repeat(d["feat"][d["valid"], FI["spread_bps"]], 2) for _, d in loaded])
            k = ~np.isnan(fr)
            full = fr >= 1 - 1e-9
            table[f"{size}/{dl}"] = dict(known=int(k.sum()), full_rate=float(full[k].mean()) if k.any() else None,
                                         partial_rate=float(((fr > 0) & ~full)[k].mean()) if k.any() else None,
                                         mean_cost_bps_full=float(np.nanmean(c[full])) if full.any() else None,
                                         mean_half_spread_bps=float(np.nanmean(sp_rep[full] / 2)) if full.any() else None,
                                         mean_slippage_beyond_mid_touch_bps=float(np.nanmean(c[full] - sp_rep[full] / 2)) if full.any() else None)
    out["fill_cost_table"] = table
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--symbol", required=True)
    ap.add_argument("--first", required=True)
    ap.add_argument("--last", required=True)
    ap.add_argument("--clock", default="received")
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    days = [str(x) for x in np.arange(np.datetime64(a.first), np.datetime64(a.last) + np.timedelta64(1, "D"))]
    z = market_analysis(a.symbol, days, a.clock)
    a.output.write_text(json.dumps(z, indent=1, allow_nan=False, default=float) + "\n")
    s = z["tiersets"]["shz_candidate"].get("momentum/1000")
    if s:
        print(a.symbol, "valid", z["valid_seconds"], "of", z["wall_seconds"],
              json.dumps({k: v and round(v["point"], 6) for k, v in s["win_share_of_wall_time"].items()}),
              json.dumps({k: v and round(v["point"], 4) for k, v in s["side_volume_share_in_win_seconds"].items()}))


if __name__ == "__main__":
    main()
