#!/usr/bin/env python3
"""SHZ federated-market economics on top of the empirical Lighter results.

Architecture modelled: R independently operated private order books
(routers) share one oracle federation (5 signers, 4-of-5 BIP340, 200 ms slot,
paid early release at T_k, public at T_k + 200 ms), exact per-leg DLC
settlement with a zero settlement fee, and HFT-03's 100 ms Lightning
coalescer for fee and margin commitments. Fees follow HFT-06's candidate
tariff (ppm): Standard 0/0, Intermediate taker 50, Premium maker 20 / taker
200, split 70% federation / 30% router.

Everything empirical comes from analysis/revenue JSON produced in this study.
Everything else is an explicit parameter with low/base/high values; the
output is a set of conditional statements ("if adoption is x, then ..."),
not a forecast. No SHZ demand is observed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

TARIFF_PPM = dict(standard=(0, 0), intermediate=(0, 50), premium=(20, 200))
SPLIT_FEDERATION = 0.70

# Daily operating cost parameters in USD (low, base, high). Assumptions, not data.
COSTS = {
    "market_data_licensing": (100.0, 700.0, 3300.0),     # ~$3k/$20k/$100k per month for redistributable low-latency feeds
    "oracle_signers_compute_bandwidth": (25.0, 75.0, 250.0),  # 5 signer hosts + relay egress
    "public_mirrors_and_archive": (5.0, 20.0, 60.0),
    "proof_generation": (5.0, 40.0, 200.0),              # hourly packet-root/fee-transcript proofs, GPU-hours
    "watchtowers": (3.0, 15.0, 50.0),
    "router_compute_bandwidth_per_router": (10.0, 40.0, 150.0),
}
LN = dict(liquidity_per_router_usd=(2e5, 1e6, 5e6), cost_of_capital_annual=(0.05, 0.10, 0.20),
          ln_fees_rebalancing_bps_of_fee_flow=(10.0, 50.0, 200.0))


def daily_costs(scn: int, routers: int):
    fed = sum(COSTS[k][scn] for k in ("market_data_licensing", "oracle_signers_compute_bandwidth",
                                      "public_mirrors_and_archive", "proof_generation", "watchtowers"))
    liq = LN["liquidity_per_router_usd"][scn] * LN["cost_of_capital_annual"][scn] / 365
    per_router = COSTS["router_compute_bandwidth_per_router"][scn] + liq
    return fed, per_router


def fee_rate_bps(paid_taker_share_int, paid_taker_share_prem, paid_maker_share_prem):
    return (paid_taker_share_int * TARIFF_PPM["intermediate"][1] + paid_taker_share_prem * TARIFF_PPM["premium"][1]
            + paid_maker_share_prem * TARIFF_PPM["premium"][0]) / 100.0


def breakeven(rate_bps, scn, routers):
    fed_cost, router_cost = daily_costs(scn, routers)
    ln_drag = LN["ln_fees_rebalancing_bps_of_fee_flow"][scn] / 1e4
    net = rate_bps / 1e4 * (1 - ln_drag)
    if net <= 0:
        return dict(federation=None, per_router=None, system=None)
    v_fed = fed_cost / (SPLIT_FEDERATION * net)
    v_router_each = router_cost / ((1 - SPLIT_FEDERATION) * net)  # volume one router must carry
    v_sys = (fed_cost + routers * router_cost) / net
    return dict(federation=v_fed, per_router=v_router_each, routers_total=v_router_each * routers,
                system=max(v_fed, v_router_each * routers, v_sys), fed_cost=fed_cost, router_cost=router_cost)


def adoption_scenarios(analyses, revenue):
    """Paid-share scenarios, each with its provenance."""
    sc = {}
    # (A) Latency-optimal ex-post shares on displayed depth (upper bound on
    # latency-motivated taker adoption at the SHZ tariff): volume share of
    # seconds whose ex-post winner is the paid tier, momentum cohort, $10k.
    for sym, an in analyses.items():
        s = an["tiersets"]["shz_candidate"].get("momentum/10000") or an["tiersets"]["shz_candidate"]["momentum/1000"]
        vi = s["total_volume_share_in_win_seconds"]["intermediate"]
        vp = s["total_volume_share_in_win_seconds"]["premium"]
        sc[f"latency_optimal_{sym}"] = dict(taker_int=vi["point"] if vi else 0.0, taker_prem=vp["point"] if vp else 0.0,
                                           maker_prem=0.0, provenance="ex-post latency-optimal volume share, displayed depth")
    # (B) Lighter observed trade-level paid shares, mapped onto the SHZ tariff
    # (Plus-rate taker volume -> intermediate, Premium-ladder taker volume ->
    # premium, Premium-ladder maker volume -> paid maker). An analog of a
    # mature venue's mix, not an SHZ forecast.
    d = revenue["daily"]
    v = np.array([r["perps_notional_usd"] for r in d])
    w = lambda k: float(np.sum(np.array([r[k] or 0 for r in d]) * v) / v.sum())
    sc["lighter_observed_mix"] = dict(taker_int=w("taker_plus_rate_share"), taker_prem=w("taker_premium_ladder_share"),
                                      maker_prem=w("maker_premium_ladder_share"),
                                      provenance="Lighter public trades, volume-weighted trade-level fee-rate shares")
    sc["no_maker_fees"] = dict(sc["lighter_observed_mix"], maker_prem=0.0, provenance="Lighter taker mix, makers free")
    return sc


def oracle_lead_economics(analyses):
    """Feed-only arm. The early packet's taker value is a transfer from makers
    quoting against the public stream. With maker opt-in, makers join the
    early window only if compensated: maker rebate share rho of the taker fee
    must cover their adverse selection per unit of opted-in volume."""
    out = {}
    for sym, an in analyses.items():
        lead = an.get("oracle_lead", {})
        row = {}
        for k, v in lead.items():
            fee = float(k.split("fee")[1])
            e = v["mean_edge_bps_when_positive"]
            row[k] = dict(
                # In a pick-off fill the maker loses (taker edge + fee) gross of
                # the fee; even a 100% fee rebate covers only fee/(edge+fee).
                max_maker_loss_coverage_by_full_rebate=fee / (e + fee) if (e + fee) > 0 else None,
                time_share=v["time_share"]["point"] if v["time_share"] else None,
                          volume_share=v["volume_share"]["point"] if v["volume_share"] else None,
                          mean_edge_bps=v["mean_edge_bps_when_positive"],
                          pickoff_usd_per_day_upper=v["pickoff_usd_per_day_upper"])
        out[sym] = row
    return out


def router_competition(rate_bps, routers_list=(1, 2, 3, 5, 8, 13), alpha=0.5, logit_beta=4.0):
    """Stylised fragmentation and fee competition.

    Depth per book scales as N^-alpha of pooled depth (alpha=0.5 for
    partially overlapping maker inventories, 1 for full splitting). For a
    square-root impact law, taker cost of a fixed order rises by N^(alpha/2).
    Router fee share under symmetric logit competition with price sensitivity
    beta per bp: markup over marginal cost = 1 / (beta * (1 - 1/N)) bp.
    """
    rows = []
    for n in routers_list:
        markup = np.inf if n == 1 else 1.0 / (logit_beta * (1 - 1 / n))
        rows.append(dict(routers=n, depth_per_book_rel=n ** -alpha, impact_cost_multiplier=n ** (alpha / 2),
                         router_markup_bps=None if not np.isfinite(markup) else markup))
    return dict(alpha=alpha, logit_beta=logit_beta, rows=rows)


def elasticities(analyses):
    """Upper-bound revenue R(f, Δ) = f · s_Δ(f) per unit of momentum volume.

    s_Δ is the ex-post volume share whose gross saving from moving 300 ms to
    300-Δ ms exceeds f. Reports the revenue-maximising fee, the fee elasticity
    d ln R / d ln f = 1 + d ln s / d ln f at 0.5 and 2 bp, and the latency
    elasticity d ln s / d ln Δ between Δ = 100, 160 and 200 ms.
    """
    out = {}
    for sym, an in analyses.items():
        for key in ("momentum/1000", "momentum/10000", "both/100000"):
            curves = {}
            for dl in (200, 140, 100):
                c = an["demand_curves"].get(f"{key}/{dl}")
                if c:
                    curves[300 - dl] = (np.array(c["fee_grid_bps"]), np.array(c["volume_share"]))
            if not curves:
                continue
            row = {}
            for delta, (f, s) in curves.items():
                r = f * s
                k = int(np.argmax(r))
                ls = np.log(np.maximum(s, 1e-12))
                lf = np.log(f)
                el = {}
                for f0 in (0.5, 2.0):
                    i = int(np.clip(np.searchsorted(f, f0), 1, len(f) - 1))
                    el[str(f0)] = dict(share=float(np.interp(f0, f, s)),
                                       fee_elasticity_of_revenue=float(1 + (ls[i] - ls[i - 1]) / (lf[i] - lf[i - 1])) if s[i] > 0 and s[i - 1] > 0 else None)
                row[f"delta_{delta}ms"] = dict(revenue_max_fee_bps=float(f[k]), revenue_max_bps_per_volume=float(r[k]),
                                               share_at_max=float(s[k]), at=el)
            for f0 in (0.5, 2.0):
                pts = [(d, float(np.interp(f0, *curves[d]))) for d in sorted(curves)]
                if len(pts) >= 2 and all(p[1] > 0 for p in pts):
                    (d0, s0), (d1, s1) = pts[0], pts[-1]
                    row[f"latency_elasticity_at_{f0}bp"] = float(np.log(s1 / s0) / np.log(d1 / d0))
            out[f"{sym}/{key}"] = row
    return out


def regime_revenue(analyses, scen_rate_bps):
    """SHZ fee revenue attributable to volatility regimes under two explicit
    adoption assumptions, per unit of total matched volume:
      A  adoption = Lighter's observed paid-taker share in the regime, all at
         the SHZ premium taker rate (an upper analog);
      B  adoption = ex-post latency-optimal win share in the regime ($1k
         momentum), at the winning tier's SHZ rate."""
    out = {}
    for sym, an in analyses.items():
        obs = an["observed_fee_revenue_by_regime"]
        reg = an["tiersets"]["shz_candidate"]["momentum/1000"]["regimes"]
        tot = sum(v["volume_usd"] for v in obs.values())
        rows = {}
        for name, v in obs.items():
            vs = v["volume_usd"] / tot if tot else 0
            a = vs * (v["paid_taker_share"] or 0) * TARIFF_PPM["premium"][1] / 100
            ws = reg[name]["win_share"]
            b = vs * ((ws.get("intermediate") or 0) * 0.5 + (ws.get("premium") or 0) * 2.0)
            rows[name] = dict(volume_share=vs, bps_A=a, bps_B=b)
        ta = sum(r["bps_A"] for r in rows.values()); tb = sum(r["bps_B"] for r in rows.values())
        for r in rows.values():
            r["share_of_revenue_A"] = r["bps_A"] / ta if ta else None
            r["share_of_revenue_B"] = r["bps_B"] / tb if tb else None
        out[sym] = dict(regimes=rows, blended_bps_A=ta, blended_bps_B=tb)
    return out


def subscription_scenarios():
    """Flat subscriptions (early packet feed or higher API throughput). Pure
    assumptions; Lighter's documented rate-limit ladder (sendTx/min 4,000 to
    72,000 by staked LIT) is the only external anchor and carries no price."""
    rows = []
    for subs in (10, 50, 200):
        for monthly in (100.0, 500.0, 2000.0):
            day = subs * monthly * 12 / 365
            rows.append(dict(subscribers=subs, monthly_usd=monthly, revenue_usd_per_day=day,
                             federation_usd_per_day=SPLIT_FEDERATION * day))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--analysis", type=Path, nargs="+", required=True)
    ap.add_argument("--revenue", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    analyses = {}
    for p in a.analysis:
        z = json.loads(p.read_text())
        analyses[z["symbol"]] = z
    revenue = json.loads(a.revenue.read_text())
    scen = adoption_scenarios(analyses, revenue)
    table = []
    for name, s in scen.items():
        rate = fee_rate_bps(s["taker_int"], s["taker_prem"], s["maker_prem"])
        for scn, label in enumerate(("low_cost", "base_cost", "high_cost")):
            for routers in (1, 3, 5):
                be = breakeven(rate, scn, routers)
                table.append(dict(adoption=name, cost=label, routers=routers, fee_rate_bps_on_all_volume=rate,
                                  breakeven_daily_volume_usd=be))
    # Sensitivity: break-even system volume vs blended fee rate, base cost, 3 routers.
    grid = np.round(np.geomspace(0.01, 2.0, 30), 5)
    sens = [dict(fee_rate_bps=float(r), **{f"{lab}": breakeven(float(r), i, 3)["system"] for i, lab in enumerate(("low", "base", "high"))}) for r in grid]
    lighter_eff = revenue["summary"]["effective_fee_bps"]["volume_weighted"]
    doc = dict(schema="shz-lv/shz-economics/v1", tariff_ppm=TARIFF_PPM, split_federation=SPLIT_FEDERATION,
               cost_parameters_usd_per_day=COSTS, lightning_parameters=LN, adoption_scenarios=scen,
               breakeven=table, sensitivity_system_breakeven_vs_rate=sens,
               lighter_effective_fee_bps_reference=lighter_eff,
               revenue_at_volume={f"{v:.0e}": {k: fee_rate_bps(s["taker_int"], s["taker_prem"], s["maker_prem"]) / 1e4 * v
                                               for k, s in scen.items()} for v in (1e6, 1e7, 1e8, 1e9)},
               oracle_lead=oracle_lead_economics(analyses), router_competition=router_competition(lighter_eff),
               elasticities=elasticities(analyses), regime_revenue=regime_revenue(analyses, None),
               subscription_scenarios=subscription_scenarios(),
               subscription_breakeven_note="flat revenue covers base federation cost when subscribers*monthly*12/365*0.7 >= federation cost",
               production_ready=False, demand_observed=False)
    a.output.write_text(json.dumps(doc, indent=1, allow_nan=False, default=float) + "\n")
    for row in table:
        if row["routers"] == 3 and row["cost"] == "base_cost":
            print(row["adoption"], round(row["fee_rate_bps_on_all_volume"], 4), f"{row['breakeven_daily_volume_usd']['system']:.3g}"
                  if row["breakeven_daily_volume_usd"]["system"] else None)


if __name__ == "__main__":
    main()
