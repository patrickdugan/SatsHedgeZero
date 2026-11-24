#!/usr/bin/env python3
"""Causal displayed-depth replay of one Lighter L2 hour (SHZ-LV engine).

For every one-second decision time t in the hour the engine records, from the
book reconstructed from messages strictly before each query time:

* arrival state at t: validity, mid, spread, displayed USD depth within 10 and
  50 bp per side;
* for each taker side, each delay d in DELAYS_MS and each notional in
  SIZES_USD: the fraction an IOC limited at arrival mid +/- LIMIT_BPS would
  fill against displayed depth at t+d, and the VWAP cost of the filled part in
  bp of arrival mid (positive = worse for the taker);
* a 20 ms mid series for the whole hour, used downstream for markouts.

The book is per-hour: it starts at the file's first snapshot. A native sequence
break (prev_final_update_id != last final_update_id) invalidates the book
until the next snapshot. A book older than MAX_AGE_MS since its last message is
stale. Nothing here sees trades; trade flow enters only in features.py.

The output npz contains derived quantities and prices; it is a local cache
and must not be published (archive licence).
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pyarrow.compute as pc
import pyarrow.parquet as pq
from sortedcontainers import SortedDict

from common import DELAYS_MS, FINE_MS, GRID_MS, LIMIT_BPS, MAX_AGE_MS, SIZES_USD, utc_ms

COLS = ["received_time", "event_time", "symbol", "event_type", "final_update_id", "prev_final_update_id",
        "side", "price", "quantity"]


def load_messages(path, symbol: str, hour_ms: int, clock: str):
    """Return arrays describing messages and their level rows (vectorised)."""
    t = pq.read_table(path, columns=COLS)
    syms = t["symbol"].unique().to_pylist()
    if syms != [symbol]:
        raise ValueError(f"wrong market {syms}")
    rx = t["received_time"].to_numpy()
    ev = t["event_time"].to_numpy()
    snap = pc.equal(t["event_type"], "snapshot").to_numpy(zero_copy_only=False)
    upd = pc.equal(t["event_type"], "update").to_numpy(zero_copy_only=False)
    if not (snap | upd).all():
        raise ValueError("unknown message kind")
    fin = t["final_update_id"].to_numpy(zero_copy_only=False)
    prev = t["prev_final_update_id"].to_numpy(zero_copy_only=False)
    bid = pc.equal(t["side"], "bid").to_numpy(zero_copy_only=False)
    ask = pc.equal(t["side"], "ask").to_numpy(zero_copy_only=False)
    if not (bid | ask).all():
        raise ValueError("bad side")
    px = pc.cast(t["price"], "float64").to_numpy()
    qty = pc.cast(t["quantity"], "float64").to_numpy()
    if not (np.isfinite(px).all() and np.isfinite(qty).all()) or (px < 0).any() or (qty < 0).any():
        raise ValueError("invalid depth")
    if np.isnan(fin.astype(float)).any():
        raise ValueError("native sequence missing")
    if ((ev < hour_ms - 86_400_000) | (ev >= hour_ms + 86_400_000)).any():
        raise ValueError("unexpected event ms units")
    n = len(rx)
    brk = np.ones(n, bool)
    brk[1:] = (rx[1:] != rx[:-1]) | (ev[1:] != ev[:-1]) | (fin[1:] != fin[:-1]) | (snap[1:] != snap[:-1])
    starts = np.flatnonzero(brk)
    ends = np.append(starts[1:], n)
    m_ev = ev[starts]
    m_rx = (rx[starts] + 999_999) // 1_000_000
    if clock == "received":
        raw = np.maximum(m_ev, m_rx)
    elif clock == "publication":
        raw = m_ev.copy()
    else:
        raise ValueError(clock)
    eff = np.maximum.accumulate(np.maximum(raw, hour_ms))
    m_prev = prev[starts]
    if np.isnan(m_prev[~snap[starts]].astype(float)).any():
        raise ValueError("update without previous id")
    return dict(eff=eff, snap=snap[starts], fin=fin[starts].astype(np.int64),
                prev=np.nan_to_num(m_prev.astype(float), nan=-1).astype(np.int64),
                starts=starts, ends=ends, bid=bid, px=px, qty=qty,
                recorder_lag_ms=(m_rx - m_ev))


class Book:
    def __init__(self, msgs):
        self.m = msgs
        self.i = 0
        self.n = len(msgs["eff"])
        self.bids = SortedDict()   # key -price
        self.asks = SortedDict()   # key  price
        self.seq = None
        self.last = None
        self.counts = dict(messages=0, snapshots=0, updates=0, gaps=0, unseeded=0)

    def advance(self, t):
        """Apply every message with effective clock strictly before t."""
        m = self.m
        eff, snap, fin, prev = m["eff"], m["snap"], m["fin"], m["prev"]
        while self.i < self.n and eff[self.i] < t:
            i = self.i
            self.i += 1
            self.counts["messages"] += 1
            if snap[i]:
                self.counts["snapshots"] += 1
                self.bids.clear()
                self.asks.clear()
            else:
                self.counts["updates"] += 1
                if self.seq is not None and self.seq != prev[i]:
                    self.counts["gaps"] += 1
                    self.seq = None
                if self.seq is None:
                    self.counts["unseeded"] += 1
                    continue
            self.seq = fin[i]
            self.last = eff[i]
            s, e = m["starts"][i], m["ends"][i]
            for j in range(s, e):
                p = m["px"][j]
                if p == 0:
                    continue
                q = m["qty"][j]
                if m["bid"][j]:
                    if q:
                        self.bids[-p] = q
                    else:
                        self.bids.pop(-p, None)
                else:
                    if q:
                        self.asks[p] = q
                    else:
                        self.asks.pop(p, None)

    def state(self, t):
        if self.seq is None or self.last is None or t - self.last > MAX_AGE_MS:
            return None
        if not self.bids or not self.asks:
            return None
        b = -self.bids.peekitem(0)[0]
        a = self.asks.peekitem(0)[0]
        return (b, a) if b < a else None

    def depth_usd(self, mid, bps):
        out = []
        for book, sign in ((self.bids, -1), (self.asks, 1)):
            lim = mid * (1 + sign * bps / 1e4)
            tot = 0.0
            for k, q in book.items():
                p = -k if sign < 0 else k
                if (p - lim) * sign > 0:
                    break
                tot += p * q
            out.append(tot)
        return out

    def sweep(self, side, mid, sizes_usd, limit_bps):
        """IOC fill fractions and VWAP costs (bp vs mid) for several notionals."""
        book = self.asks if side > 0 else self.bids
        lim = mid * (1 + side * limit_bps / 1e4)
        targets = [n / mid for n in sizes_usd]
        qmax = targets[-1]
        levels = []
        cum = 0.0
        for k, q in book.items():
            p = -k if side < 0 else k
            if (p - lim) * side > 0:
                break
            levels.append((p, q))
            cum += q
            if cum >= qmax:
                break
        frac = np.zeros(len(sizes_usd))
        cost = np.full(len(sizes_usd), np.nan)
        for j, tq in enumerate(targets):
            rem = tq
            quote = 0.0
            for p, q in levels:
                take = q if q < rem else rem
                quote += take * p
                rem -= take
                if rem <= tq * 1e-12:
                    rem = 0.0
                    break
            filled = tq - rem
            if filled > 0:
                frac[j] = filled / tq
                vwap = quote / filled
                cost[j] = side * (vwap - mid) / mid * 1e4
        return frac, cost


def replay_hour(path, symbol, hour_ms, clock="received"):
    msgs = load_messages(path, symbol, hour_ms, clock)
    book = Book(msgs)
    end = hour_ms + 3_600_000
    nsec = 3_600
    nfine = 3_600_000 // FINE_MS
    D, S = len(DELAYS_MS), len(SIZES_USD)
    mid_fine = np.full(nfine, np.nan, np.float64)
    arr_valid = np.zeros(nsec, bool)
    arr_mid = np.full(nsec, np.nan)
    spread = np.full(nsec, np.nan)
    depth = np.full((nsec, 4), np.nan)  # bid10, ask10, bid50, ask50
    frac = np.full((nsec, 2, D, S), np.nan)
    cost = np.full((nsec, 2, D, S), np.nan)
    delay_steps = {d // FINE_MS: k for k, d in enumerate(DELAYS_MS)}
    for d in DELAYS_MS:
        assert d % FINE_MS == 0
    step_per_sec = GRID_MS // FINE_MS
    for g in range(nfine):
        t = hour_ms + g * FINE_MS
        book.advance(t)
        st = book.state(t)
        if st is not None:
            mid_fine[g] = (st[0] + st[1]) / 2
        sec, off = divmod(g, step_per_sec)
        if off == 0:
            if st is not None:
                mid = (st[0] + st[1]) / 2
                arr_valid[sec] = True
                arr_mid[sec] = mid
                spread[sec] = (st[1] - st[0]) / mid * 1e4
                depth[sec, 0:2] = book.depth_usd(mid, 10)
                depth[sec, 2:4] = book.depth_usd(mid, 50)
        elif off in delay_steps and arr_valid[sec]:
            k = delay_steps[off]
            if st is None:
                continue  # unknown at execution time: stays NaN
            for si, side in enumerate((1, -1)):
                f, c = book.sweep(side, arr_mid[sec], SIZES_USD, LIMIT_BPS)
                frac[sec, si, k] = f
                cost[sec, si, k] = c
    book.advance(end)
    lag = msgs["recorder_lag_ms"]
    return dict(mid_fine=mid_fine.astype(np.float64), arr_valid=arr_valid, arr_mid=arr_mid, spread_bps=spread,
                depth_usd=depth.astype(np.float32), fill_frac=frac.astype(np.float32), cost_bps=cost.astype(np.float32),
                counts=book.counts, clean=book.counts["gaps"] == 0 and book.counts["unseeded"] == 0,
                recorder_lag_q=np.quantile(lag, [0.5, 0.9, 0.99, 0.999]) if len(lag) else np.full(4, np.nan))


def selftest():
    # Synthetic message arrays: snapshot at 0, update at 150 removes best ask,
    # gap at 2500 invalidates until snapshot at 2900.
    rows = [  # eff, snap, fin, prev, levels
        (0, True, 1, -1, [(True, 99.99, 10.0), (False, 100.01, 1.0), (False, 100.05, 10.0)]),
        (150, False, 2, 1, [(False, 100.01, 0.0)]),
        (2500, False, 9, 7, [(False, 100.02, 1.0)]),
        (2900, True, 10, -1, [(True, 99.0, 1.0), (False, 101.0, 1.0)]),
    ]
    starts, ends, bid, px, qty = [], [], [], [], []
    for _, _, _, _, lv in rows:
        starts.append(len(px))
        for b, p, q in lv:
            bid.append(b); px.append(p); qty.append(q)
        ends.append(len(px))
    m = dict(eff=np.array([r[0] for r in rows]), snap=np.array([r[1] for r in rows]),
             fin=np.array([r[2] for r in rows]), prev=np.array([r[3] for r in rows]),
             starts=np.array(starts), ends=np.array(ends), bid=np.array(bid), px=np.array(px), qty=np.array(qty))
    b = Book(m)
    b.advance(0)
    assert b.state(0) is None                      # strict-before: nothing yet
    b.advance(100)
    assert b.state(100) == (99.99, 100.01)
    f, c = b.sweep(1, 100.0, (50, 500), 20)
    assert abs(f[0] - 1) < 1e-12 and abs(c[0] - 1.0) < 1e-9      # 50 USD fits the 100.01 level
    assert abs(f[1] - 1) < 1e-12 and c[1] > 1.0                  # walks to 100.05
    b.advance(151)
    assert b.state(151) == (99.99, 100.05)
    f, c = b.sweep(1, 100.0, (100_000,), 20)
    assert 0 < f[0] < 1                                          # partial IOC
    b.advance(2600)
    assert b.state(2600) is None and b.counts["gaps"] == 1       # sequence break
    b.advance(3000)
    assert b.state(3000) == (99.0, 101.0)
    assert b.state(3000 + MAX_AGE_MS + 101) is None              # stale
    print("engine selftest passed")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--book", type=Path)
    ap.add_argument("--symbol")
    ap.add_argument("--hour")
    ap.add_argument("--clock", default="received", choices=("received", "publication"))
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    h = utc_ms(a.hour)
    z = replay_hour(a.book, a.symbol, h, a.clock)
    counts = z.pop("counts")
    np.savez_compressed(a.output, **{k: v for k, v in z.items() if isinstance(v, np.ndarray)},
                        clean=np.array(z["clean"]), counts=np.array(json.dumps(counts)))
    print(json.dumps(dict(hour=a.hour, symbol=a.symbol, clock=a.clock, clean=z["clean"], counts=counts,
                          valid_seconds=int(z["arr_valid"].sum()))))


if __name__ == "__main__":
    main()
