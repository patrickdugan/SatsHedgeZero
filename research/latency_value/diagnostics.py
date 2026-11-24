#!/usr/bin/env python3
"""Why causal policies choose free: conditional mean gross saving by causal
feature quantile. For each feature, decisions in the top q of that feature's
distribution (q = 10%, 1%, 0.1%, 0.01%) and the mean gross saving of the
intermediate (300->200 ms) and premium (300->100 ms) tiers there. A causal
policy can only profit in a cell whose mean saving exceeds the fee (0.5 / 2 bp).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analysis import DI, FI, decisions
from common import SIZES_USD
from features import cached_day

FEATS = ("vol_score", "rv60", "abs_r1", "spread_bps", "flow_accel", "flow5_usd", "liq60_usd", "depletion", "abs_xdiv5", "abs_imb10")
QS = (0.9, 0.99, 0.999, 0.9999)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--symbol", required=True)
    ap.add_argument("--first", required=True)
    ap.add_argument("--last", required=True)
    ap.add_argument("--size", type=int, default=1000)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    s_idx = SIZES_USD.index(a.size)
    X, W1, W2 = [], [], []
    for d in np.arange(np.datetime64(a.first), np.datetime64(a.last) + np.timedelta64(1, "D")):
        day = cached_day(a.symbol, str(d))
        if not day["valid"].any():
            continue
        t, si = decisions(day, "momentum")
        c = {dl: day["cost"][t, si, DI[dl], s_idx].astype(float) for dl in (300, 200, 100)}
        f = {dl: day["frac"][t, si, DI[dl], s_idx].astype(float) >= 1 - 1e-9 for dl in (300, 200, 100)}
        ok = f[300] & f[200] & f[100]
        F = day["feat"][t].astype(float)
        cols = []
        for name in FEATS:
            if name == "abs_xdiv5":
                cols.append(np.abs(F[:, FI["xdiv5"]]))
            elif name == "abs_imb10":
                cols.append(np.abs(F[:, FI["imb10"]]))
            else:
                cols.append(F[:, FI[name]])
        X.append(np.stack(cols, 1)[ok]); W1.append((c[300] - c[200])[ok]); W2.append((c[300] - c[100])[ok])
    X = np.concatenate(X); W1 = np.concatenate(W1); W2 = np.concatenate(W2)
    out = dict(symbol=a.symbol, window=[a.first, a.last], size_usd=a.size, decisions=int(len(W1)),
               unconditional=dict(intermediate=float(W1.mean()), premium=float(W2.mean())), cells={})
    best = dict(intermediate=(-np.inf, None), premium=(-np.inf, None))
    for j, name in enumerate(FEATS):
        v = X[:, j]
        okv = np.isfinite(v)
        for q in QS:
            thr = np.quantile(v[okv], q)
            sel = okv & (v >= thr)
            n = int(sel.sum())
            m1, m2 = float(W1[sel].mean()), float(W2[sel].mean())
            se2 = float(W2[sel].std() / np.sqrt(max(n, 1)))
            out["cells"][f"{name}>=q{q}"] = dict(n=n, threshold=float(thr), mean_saving_intermediate_bps=m1,
                                                 mean_saving_premium_bps=m2, premium_se=se2,
                                                 net_intermediate=m1 - 0.5, net_premium=m2 - 2.0)
            if n >= 50:
                if m1 - 0.5 > best["intermediate"][0]:
                    best["intermediate"] = (m1 - 0.5, f"{name}>=q{q}")
                if m2 - 2.0 > best["premium"][0]:
                    best["premium"] = (m2 - 2.0, f"{name}>=q{q}")
    out["best_cell_net_bps"] = {k: dict(net=v[0], cell=v[1]) for k, v in best.items()}
    a.output.write_text(json.dumps(out, indent=1) + "\n")
    print(a.symbol, json.dumps(out["unconditional"]), json.dumps(out["best_cell_net_bps"]))


if __name__ == "__main__":
    main()
