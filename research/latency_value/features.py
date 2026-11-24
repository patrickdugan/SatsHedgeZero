#!/usr/bin/env python3
"""Assemble one market-day from hourly replays and compute causal features.

Every feature at decision time t uses only (a) book state built from messages
with effective clock strictly before t, and (b) public trades whose venue
timestamp is at least TRADE_VISIBILITY_LAG_MS before t. Ex-post quantities
(fills at t+d, future mids, realised volume in [t, t+1s)) are kept in separate
fields and never enter a policy's inputs.

Dirty hours (any native sequence break or unseeded update) are dropped in
full, as in PR #30, and counted as missing coverage.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from common import CACHE, DELAYS_MS, FINE_MS, HORIZONS_MS, MARKETS, TRADE_VISIBILITY_LAG_MS, utc_ms

REFERENCE = {"BTC": "ETH", "ETH": "BTC", "SOL": "BTC"}
FEATURES = ("r1", "r5", "r30", "vol_score", "rv60", "spread_bps", "depth10_usd", "imb10", "depletion",
            "flow1_signed", "flow5_usd", "flow60_usd", "flow_accel", "liq60_usd", "xdiv5", "abs_r1")


def _load_hour(sym, day, hh, clock):
    p = CACHE / "hours" / clock / sym / f"{day}-{hh:02d}.npz"
    if not p.exists():
        return None
    z = np.load(p, allow_pickle=False)
    return {k: z[k] for k in z.files}


def _trailing_sum(x, w):
    c = np.concatenate([[0.0], np.cumsum(np.nan_to_num(x))])
    out = c[w:] - c[:-w]
    return np.concatenate([np.full(w - 1, np.nan), out])


def assemble_day(sym: str, day: str, clock: str = "received", use_next_day=True):
    start = utc_ms(day)
    n = 86_400
    nf = 86_400_000 // FINE_MS
    pad = 31_000 // FINE_MS + 1
    D, S = len(DELAYS_MS), 4
    mid_fine = np.full(nf + pad, np.nan)
    valid = np.zeros(n, bool)
    mid = np.full(n, np.nan)
    spread = np.full(n, np.nan)
    depth = np.full((n, 4), np.nan, np.float32)
    frac = np.full((n, 2, D, S), np.nan, np.float32)
    cost = np.full((n, 2, D, S), np.nan, np.float32)
    hours = {}
    for hh in range(24):
        z = _load_hour(sym, day, hh, clock)
        key = f"{day}T{hh:02d}"
        if z is None:
            hours[key] = "missing"
            continue
        if not bool(z["clean"]):
            hours[key] = "dirty"
            continue
        hours[key] = "clean"
        s = slice(hh * 3600, (hh + 1) * 3600)
        valid[s] = z["arr_valid"]; mid[s] = z["arr_mid"]; spread[s] = z["spread_bps"]
        depth[s] = z["depth_usd"]; frac[s] = z["fill_frac"]; cost[s] = z["cost_bps"]
        mid_fine[hh * 180_000:(hh + 1) * 180_000] = z["mid_fine"]
    if use_next_day:
        nxt = np.datetime64(day) + np.timedelta64(1, "D")
        z = _load_hour(sym, str(nxt), 0, clock)
        if z is not None and bool(z["clean"]):
            mid_fine[nf:] = z["mid_fine"][:pad]
    # Future mid returns relative to arrival mid: shape (n, D, H). Ex-post only.
    H = len(HORIZONS_MS)
    fut = np.full((n, D, H), np.nan, np.float32)
    base = np.arange(n) * (1000 // FINE_MS)
    for i, d in enumerate(DELAYS_MS):
        for j, h in enumerate(HORIZONS_MS):
            idx = base + (d + h) // FINE_MS
            fut[:, i, j] = (mid_fine[idx] / mid - 1) * 1e4
    # Mid change over the next L ms from t (ex-post): the information a
    # subscriber receiving the oracle mark L ms before the public would hold.
    lead = np.stack([(mid_fine[base + L // FINE_MS] / mid - 1) * 1e4 for L in (100, 200)], 1).astype(np.float32)
    # Causal book features.
    lm = np.log(mid)
    def lag(x, k):
        return np.concatenate([np.full(k, np.nan), x[:-k]])
    r1 = (lm - lag(lm, 1)) * 1e4
    r5 = (lm - lag(lm, 5)) * 1e4
    r30 = (lm - lag(lm, 30)) * 1e4
    vol_score = np.fmax(np.abs(r1), np.fmax(np.abs(r5) / np.sqrt(5), np.abs(r30) / np.sqrt(30)))
    vol_score[np.isnan(r1) | np.isnan(r5) | np.isnan(r30)] = np.nan
    r1z = np.where(np.isnan(r1), 0, r1)
    cnt = _trailing_sum(~np.isnan(r1), 60)
    s1 = _trailing_sum(r1z, 60); s2 = _trailing_sum(r1z ** 2, 60)
    rv60 = np.sqrt(np.maximum(s2 / np.maximum(cnt, 1) - (s1 / np.maximum(cnt, 1)) ** 2, 0))
    rv60[cnt < 45] = np.nan
    d10 = depth[:, 0].astype(float) + depth[:, 1]
    imb10 = (depth[:, 0] - depth[:, 1]) / np.where(d10 > 0, d10, np.nan)
    d10_prev = np.concatenate([[np.nan], d10[:-1]])
    m60 = _trailing_sum(d10_prev, 60) / np.maximum(_trailing_sum(~np.isnan(d10_prev), 60), 1)
    with np.errstate(divide="ignore", invalid="ignore"):
        depletion = np.where(m60 > 0, d10 / m60, np.nan)
    # Causal trade-flow features from millisecond trades (venue timestamps).
    tp = CACHE / f"tradesms_{sym}_{day}.npz"
    feats_ok = tp.exists()
    flow = {k: np.full(n, np.nan) for k in ("flow1_signed", "flow5_usd", "flow60_usd", "liq60_usd")}
    if feats_ok:
        tz = np.load(tp)
        ts, su, lq = tz["ts"], tz["signed_usd"], tz["liq"]
        cs = np.concatenate([[0.0], np.cumsum(su)])
        ca = np.concatenate([[0.0], np.cumsum(np.abs(su))])
        cl = np.concatenate([[0.0], np.cumsum(np.abs(su) * lq)])
        tq = start + np.arange(n) * 1000 - TRADE_VISIBILITY_LAG_MS
        def win(c, w):
            hi = np.searchsorted(ts, tq, side="right")
            lo = np.searchsorted(ts, tq - w, side="right")
            return c[hi] - c[lo]
        flow["flow1_signed"] = win(cs, 1000)
        flow["flow5_usd"] = win(ca, 5000)
        flow["flow60_usd"] = win(ca, 60_000)
        flow["liq60_usd"] = win(cl, 60_000)
        # The first minute of the UTC day lacks the previous day's trades.
        for k in flow:
            flow[k][:61] = np.nan
    accel = flow["flow5_usd"] / np.where(flow["flow60_usd"] > 0, flow["flow60_usd"] / 12, np.nan)
    # Cross-market divergence vs reference market last trade price (lagged one full second).
    xdiv = np.full(n, np.nan)
    rp = CACHE / f"trades_{REFERENCE[sym]}_{day}.npz"
    if rp.exists():
        px = np.load(rp)["last_px"]
        ok = ~np.isnan(px)
        idx = np.where(ok, np.arange(n), -1)
        np.maximum.accumulate(idx, out=idx)
        pxf = np.where(idx >= 0, px[np.maximum(idx, 0)], np.nan)   # forward fill
        lp = np.log(pxf)
        # Last trade of second s is visible at t only if (s+1)*1000 <= t - lag.
        sref = np.arange(n) - 1 - int(np.ceil(TRADE_VISIBILITY_LAG_MS / 1000))
        good = sref >= 5
        ref5 = np.full(n, np.nan)
        ref5[good] = (lp[sref[good]] - lp[sref[good] - 5]) * 1e4
        xdiv = r5 - ref5
    # Ex-post realised volume in [t, t+1s), per taker side.
    wp = CACHE / f"trades_{sym}_{day}.npz"
    vol = dict(buy_usd=np.full(n, np.nan), sell_usd=np.full(n, np.nan), paid_taker_usd=np.full(n, np.nan),
               taker_fee_usd=np.full(n, np.nan), maker_fee_usd=np.full(n, np.nan))
    if wp.exists():
        w = np.load(wp)
        for k in vol:
            vol[k] = w[k]
    F = dict(r1=r1, r5=r5, r30=r30, vol_score=vol_score, rv60=rv60, spread_bps=spread, depth10_usd=d10,
             imb10=imb10, depletion=depletion, flow_accel=accel, xdiv5=xdiv, abs_r1=np.abs(r1), **flow)
    feat = np.stack([F[k] for k in FEATURES], axis=1).astype(np.float32)
    clean_hours = [k for k, v in hours.items() if v == "clean"]
    in_cov = np.zeros(n, bool)
    for k in clean_hours:
        hh = int(k[-2:])
        in_cov[hh * 3600:(hh + 1) * 3600] = True
    return dict(symbol=sym, day=day, clock=clock, hours=hours, covered=in_cov, valid=valid & in_cov,
                mid=mid, feat=feat, frac=frac, cost=cost, fut=fut, lead=lead, depth=depth, trades_available=feats_ok,
                **{k: v for k, v in vol.items()})


def cached_day(sym, day, clock="received", rebuild=False):
    out = CACHE / "days" / clock / f"{sym}_{day}.npz"
    if out.exists() and not rebuild:
        z = np.load(out, allow_pickle=False)
        d = {k: z[k] for k in z.files}
        d["hours"] = json.loads(str(d["hours"]))
        return d
    d = assemble_day(sym, day, clock)
    out.parent.mkdir(parents=True, exist_ok=True)
    save = {k: v for k, v in d.items() if isinstance(v, np.ndarray)}
    save["hours"] = np.array(json.dumps(d["hours"]))
    save["trades_available"] = np.array(bool(d["trades_available"]))
    np.savez(out, **save)
    return d
