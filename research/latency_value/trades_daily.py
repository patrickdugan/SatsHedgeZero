#!/usr/bin/env python3
"""Daily aggregates of the public Lighter trades dataset (all markets).

Reads only market, time, integer price/size, USDC notional, trade type, taker
side and the per-trade fee-rate fields. Account identifiers are never loaded.
Fee fields are treated as rates in parts per million of notional; that unit is
checked against DefiLlama's published daily fees in revenue.py, not assumed.

Outputs:
  * a committed per-day JSON of per-market aggregates (no rows, no prices);
  * a local per-second cache (npz) for BTC/ETH/SOL used as replay weights and
    causal flow features. The cache stays outside the repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pyarrow.compute as pc
import pyarrow.parquet as pq

from common import CACHE, MARKETS, utc_ms

COLS = ["id", "timestamp", "market_id", "trade_type", "is_maker_ask", "size", "price", "usdc_amount",
        "maker_fee", "taker_fee", "integrator_taker_fee", "integrator_maker_fee"]
RATE_EDGES_PPM = (0, 1, 40, 41, 50, 51, 100, 196, 197, 200, 201, 280, 281, 1_000_000)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def day_aggregate(path: str) -> dict:
    p = Path(path)
    day = p.stem
    start = utc_ms(day)
    t = pq.read_table(p, columns=COLS)
    if pc.count_distinct(t["id"]).as_py() != t.num_rows:
        raise ValueError(f"{day}: duplicate trade ids")
    a = {c: t[c].to_numpy(zero_copy_only=False) for c in COLS if c not in ("trade_type", "id")}
    kinds = t["trade_type"].unique().to_pylist()
    codes = np.zeros(t.num_rows, np.int8)
    for i, k in enumerate(kinds):
        codes[pc.equal(t["trade_type"], k).to_numpy(zero_copy_only=False)] = i
    ttype = np.array(kinds, dtype=object)[codes]
    nrows = t.num_rows
    del t
    for c in ("timestamp", "market_id", "size", "price", "usdc_amount", "maker_fee", "taker_fee"):
        if np.isnan(a[c].astype(float)).any() if a[c].dtype.kind == "f" else False:
            raise ValueError(f"{day}: null {c}")
    ts = a["timestamp"].astype(np.int64)
    outside = int(((ts < start) | (ts >= start + 86_400_000)).sum())
    usd = a["usdc_amount"].astype(np.float64) / 1e6
    mf = np.nan_to_num(a["maker_fee"].astype(np.float64))
    tf = np.nan_to_num(a["taker_fee"].astype(np.float64))
    itf = np.nan_to_num(a["integrator_taker_fee"].astype(np.float64))
    imf = np.nan_to_num(a["integrator_maker_fee"].astype(np.float64))
    mk = a["market_id"].astype(np.int64)
    buy = a["is_maker_ask"].astype(bool)  # maker is the ask => taker bought
    out = dict(day=day, file_sha256=sha256(p), rows=nrows, rows_outside_utc_day=outside,
               trade_type_counts={k: int((ttype == k).sum()) for k in np.unique(ttype)})
    trade = ttype != "market-settlement"
    out["all_markets"] = dict(
        notional_usd=float(usd[trade].sum()),
        notional_usd_by_type={k: float(usd[ttype == k].sum()) for k in np.unique(ttype)},
        maker_fee_usd=float((usd * mf)[trade].sum() / 1e6), taker_fee_usd=float((usd * tf)[trade].sum() / 1e6),
        integrator_fee_usd=float((usd * (itf + imf))[trade].sum() / 1e6),
        taker_paid_notional_usd=float(usd[trade & (tf > 0)].sum()),
        maker_paid_notional_usd=float(usd[trade & (mf > 0)].sum()),
        negative_fee_notional_usd=float(usd[trade & ((mf < 0) | (tf < 0))].sum()),
        markets_traded=int(len(np.unique(mk[trade]))))
    # Volume by observed per-trade rate (ppm). Trade-level observation only:
    # no account-level aggregation or tier attribution.
    def rate_hist(rate, sel):
        vals, inv = np.unique(rate[sel], return_inverse=True)
        vol = np.bincount(inv, weights=usd[sel])
        order = np.argsort(-vol)[:25]
        return [dict(rate_ppm=float(vals[i]), notional_usd=float(vol[i])) for i in order]
    out["all_markets"]["taker_rate_volume_top"] = rate_hist(tf, trade)
    out["all_markets"]["maker_rate_volume_top"] = rate_hist(mf, trade)
    # Scope split: Lighter numbers spot markets from 2048 upward; perps below.
    for scope, sel in (("perps", trade & (mk < 2048)), ("spot", trade & (mk >= 2048))):
        out[scope] = dict(notional_usd=float(usd[sel].sum()), markets=int(len(np.unique(mk[sel]))),
                          maker_fee_usd=float((usd * mf)[sel].sum() / 1e6), taker_fee_usd=float((usd * tf)[sel].sum() / 1e6),
                          integrator_fee_usd=float((usd * (itf + imf))[sel].sum() / 1e6),
                          liquidation_notional_usd=float(usd[sel & np.isin(ttype, ("liquidation", "deleverage"))].sum()),
                          taker_paid_notional_usd=float(usd[sel & (tf > 0)].sum()),
                          maker_paid_notional_usd=float(usd[sel & (mf > 0)].sum()),
                          taker_rate_volume_top=rate_hist(tf, sel), maker_rate_volume_top=rate_hist(mf, sel))
    per = {}
    CACHE.mkdir(parents=True, exist_ok=True)
    for sym, cfg in MARKETS.items():
        sel = trade & (mk == cfg["market_id"])
        if not sel.any():
            per[sym] = None
            continue
        # Integer scaling check: price*size / 10^(pd+sd-6) == usdc_amount (+/- 1 unit rounding).
        implied = a["price"][sel].astype(np.float64) * a["size"][sel].astype(np.float64) / 10 ** (cfg["price_decimals"] + cfg["size_decimals"] - 6)
        scale_err = float(np.max(np.abs(implied - a["usdc_amount"][sel])) if sel.any() else 0)
        in_day = sel & (ts >= start) & (ts < start + 86_400_000)
        sec = ((ts[in_day] - start) // 1000).astype(np.int64)
        def per_sec(w):
            return np.bincount(sec, weights=w, minlength=86_400)[:86_400]
        u = usd[in_day]; b = buy[in_day]; tt = ttype[in_day]
        liq = np.isin(tt, ("liquidation", "deleverage"))
        price = a["price"][in_day].astype(np.float64) / 10 ** cfg["price_decimals"]
        # last trade price in each second (cache only; never published)
        last_px = np.full(86_400, np.nan)
        last_ms = np.full(86_400, -1, np.int64)
        order = np.argsort(ts[in_day], kind="stable")
        last_px[sec[order]] = price[order]
        last_ms[sec[order]] = ts[in_day][order]
        np.savez_compressed(CACHE / f"trades_{sym}_{day}.npz",
                            buy_usd=per_sec(u * b), sell_usd=per_sec(u * ~b),
                            paid_taker_usd=per_sec(u * (tf[in_day] > 0)),
                            taker_fee_usd=per_sec(u * tf[in_day] / 1e6), maker_fee_usd=per_sec(u * mf[in_day] / 1e6),
                            liq_usd=per_sec(u * liq), count=per_sec(np.ones_like(u)),
                            last_px=last_px, last_ms=last_ms)
        # Millisecond-resolution flow is kept for causal features at sub-second lag.
        np.savez_compressed(CACHE / f"tradesms_{sym}_{day}.npz", ts=ts[in_day][order],
                            signed_usd=(u * np.where(b, 1.0, -1.0))[order], liq=liq[order])
        per[sym] = dict(market_id=cfg["market_id"], trades=int(sel.sum()), notional_usd=float(usd[sel].sum()),
                        taker_buy_notional_usd=float(usd[sel & buy].sum()),
                        liquidation_notional_usd=float(usd[sel & np.isin(ttype, ("liquidation", "deleverage"))].sum()),
                        maker_fee_usd=float((usd * mf)[sel].sum() / 1e6), taker_fee_usd=float((usd * tf)[sel].sum() / 1e6),
                        taker_paid_notional_usd=float(usd[sel & (tf > 0)].sum()),
                        maker_paid_notional_usd=float(usd[sel & (mf > 0)].sum()),
                        taker_rate_volume_top=rate_hist(tf, sel), maker_rate_volume_top=rate_hist(mf, sel),
                        max_scale_error_units=scale_err)
    out["markets"] = per
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trades-dir", type=Path, required=True)
    ap.add_argument("--first", required=True)
    ap.add_argument("--last", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    files = sorted(p for p in a.trades_dir.glob("*.parquet") if a.first <= p.stem <= a.last)
    with ProcessPoolExecutor(a.workers) as ex:
        rows = list(ex.map(day_aggregate, map(str, files)))
    doc = dict(schema="shz-lv/lighter-trades-daily/v1", source="AWS public blockchain Lighter core mainnet trades (local copy)",
               fee_unit_hypothesis="maker_fee/taker_fee = parts per million of notional (checked in revenue.py)",
               account_fields_loaded=False, days=rows)
    a.output.write_text(json.dumps(doc, indent=1) + "\n")
    for r in rows:
        x = r["all_markets"]
        print(r["day"], f"vol={x['notional_usd']/1e9:.3f}bn fees={(x['maker_fee_usd']+x['taker_fee_usd'])/1e3:.1f}k "
              f"paid_taker_share={x['taker_paid_notional_usd']/x['notional_usd']:.3f}")


if __name__ == "__main__":
    main()
