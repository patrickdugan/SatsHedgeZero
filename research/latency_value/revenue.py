#!/usr/bin/env python3
"""Calibrate against published Lighter revenue (DefiLlama) and the public
trades dataset, with consistent scopes and exact UTC dates.

Scopes:
  * DefiLlama `lighter-perps` dailyFees / dailyRevenue  <->  trades with
    market_id < 2048 (perpetuals), maker_fee + taker_fee in ppm of notional.
  * DefiLlama `lighter` (parent: perps + spot + other instances) is reported
    separately and never mixed into perps ratios.
DefiLlama's free API no longer serves /summary/derivatives (paid plan), so
perpetual volume comes from the trades dataset itself, which is the same
public source of record. A missing value stays missing, never zero.

The per-trade fee fields identify the fee charged on each trade. They do not
identify which account or account tier paid it, and this module never groups
by account. Volume at a fee rate is a trade-level statistic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, UTC
from pathlib import Path
from urllib.request import Request, urlopen

import numpy as np

SOURCES = (("lighter-perps", "dailyFees"), ("lighter-perps", "dailyRevenue"), ("lighter-perps", "dailyHoldersRevenue"),
           ("lighter", "dailyFees"), ("lighter", "dailyRevenue"))
# Documented Premium taker ladder (ppm) by staked LIT, list 280 ppm down to 196 ppm.
PREMIUM_TAKER_PPM = (280, 273, 266, 252, 238, 224, 210, 196)
PREMIUM_MAKER_PPM = (40, 39, 38, 36, 34, 32, 30, 28)
PLUS_PPM = 50


def fetch(slug, dtype):
    url = f"https://api.llama.fi/summary/fees/{slug}?dataType={dtype}"
    row = dict(slug=slug, data_type=dtype, url=url)
    try:
        with urlopen(Request(url, headers={"User-Agent": "research-client/1"}), timeout=60) as f:
            raw = f.read(50 * 1024 * 1024)
        d = json.loads(raw)
        if d.get("slug") != slug:
            raise ValueError("slug mismatch")
        vals = {}
        for ts, v in d["totalDataChart"]:
            if ts % 86400:
                raise ValueError("non-midnight timestamp")
            vals[datetime.fromtimestamp(ts, UTC).date().isoformat()] = v
        row.update(sha256=hashlib.sha256(raw).hexdigest(), methodology=d.get("methodology"), values=vals,
                   fetched_utc=datetime.now(UTC).isoformat(timespec="seconds"))
    except Exception as e:
        row["error"] = f"{type(e).__name__}: {e}"
    return row


def bucket_share(top, total, rates):
    return sum(x["notional_usd"] for x in top if x["rate_ppm"] in rates) / total if total else None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trades-daily", type=Path, required=True)
    ap.add_argument("--llama-cache", type=Path, required=True, help="write/read fetched series here")
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    if a.refresh or not a.llama_cache.exists():
        a.llama_cache.write_text(json.dumps([fetch(*s) for s in SOURCES], indent=1) + "\n")
    llama = {(r["slug"], r["data_type"]): r for r in json.loads(a.llama_cache.read_text())}
    td = json.loads(a.trades_daily.read_text())
    rows = []
    for day in td["days"]:
        p = day.get("perps")
        if p is None:
            raise ValueError("trades_daily lacks perps scope; rerun trades_daily.py")
        fees = p["maker_fee_usd"] + p["taker_fee_usd"]
        v = p["notional_usd"]
        lv = lambda s, t: llama.get((s, t), {}).get("values", {}).get(day["day"])
        r = dict(day=day["day"], perps_notional_usd=v, perps_trade_fees_usd=fees,
                 perps_maker_fee_usd=p["maker_fee_usd"], perps_taker_fee_usd=p["taker_fee_usd"],
                 llama_perps_fees_usd=lv("lighter-perps", "dailyFees"), llama_perps_revenue_usd=lv("lighter-perps", "dailyRevenue"),
                 llama_perps_holders_revenue_usd=lv("lighter-perps", "dailyHoldersRevenue"),
                 llama_parent_fees_usd=lv("lighter", "dailyFees"), llama_parent_revenue_usd=lv("lighter", "dailyRevenue"),
                 effective_fee_bps=fees / v * 1e4 if v else None,
                 effective_taker_fee_bps=p["taker_fee_usd"] / v * 1e4 if v else None,
                 effective_maker_fee_bps=p["maker_fee_usd"] / v * 1e4 if v else None,
                 taker_paid_share=p["taker_paid_notional_usd"] / v if v else None,
                 maker_paid_share=p["maker_paid_notional_usd"] / v if v else None,
                 taker_premium_ladder_share=bucket_share(p["taker_rate_volume_top"], v, PREMIUM_TAKER_PPM),
                 taker_plus_rate_share=bucket_share(p["taker_rate_volume_top"], v, (PLUS_PPM,)),
                 maker_premium_ladder_share=bucket_share(p["maker_rate_volume_top"], v, PREMIUM_MAKER_PPM),
                 maker_plus_rate_share=bucket_share(p["maker_rate_volume_top"], v, (PLUS_PPM,)),
                 liquidation_share=p["liquidation_notional_usd"] / v if v else None,
                 spot_notional_usd=day["spot"]["notional_usd"])
        r["trades_over_llama_fees"] = fees / r["llama_perps_fees_usd"] if r["llama_perps_fees_usd"] else None
        rows.append(r)
    ratio = np.array([r["trades_over_llama_fees"] for r in rows if r["trades_over_llama_fees"]])
    eff = np.array([r["effective_fee_bps"] for r in rows])
    summary = dict(
        days=len(rows), first=rows[0]["day"], last=rows[-1]["day"],
        fee_unit_check=dict(days_compared=int(len(ratio)), median_trades_over_llama=float(np.median(ratio)) if len(ratio) else None,
                            p10=float(np.quantile(ratio, .1)) if len(ratio) else None, p90=float(np.quantile(ratio, .9)) if len(ratio) else None,
                            interpretation="ratio near 1 supports ppm-of-notional units and matching perps scope"),
        effective_fee_bps=dict(mean=float(eff.mean()), min=float(eff.min()), max=float(eff.max()),
                               volume_weighted=float(sum(r["perps_trade_fees_usd"] for r in rows) / sum(r["perps_notional_usd"] for r in rows) * 1e4)),
        taker_paid_share_volume_weighted=float(sum(r["taker_paid_share"] * r["perps_notional_usd"] for r in rows) / sum(r["perps_notional_usd"] for r in rows)),
        maker_paid_share_volume_weighted=float(sum(r["maker_paid_share"] * r["perps_notional_usd"] for r in rows) / sum(r["perps_notional_usd"] for r in rows)),
        maker_fee_share_of_trade_fees=float(sum(r["perps_maker_fee_usd"] for r in rows) / sum(r["perps_trade_fees_usd"] for r in rows)),
        corr_daily_volume_vs_effective_fee=float(np.corrcoef([r["perps_notional_usd"] for r in rows], eff)[0, 1]),
        corr_daily_volume_vs_taker_paid_share=float(np.corrcoef([r["perps_notional_usd"] for r in rows], [r["taker_paid_share"] for r in rows])[0, 1]))
    doc = dict(schema="shz-lv/lighter-revenue-calibration/v1", scope_note=__doc__.split("\n\n")[1],
               llama_sources=[{k: v for k, v in r.items() if k != "values"} for r in llama.values()],
               summary=summary, daily=rows, account_level_inference=False)
    a.output.write_text(json.dumps(doc, indent=1, allow_nan=False) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
