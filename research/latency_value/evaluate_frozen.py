#!/usr/bin/env python3
"""Evaluate committed frozen policies on held-out market-days.

Loads every frozen/*.pkl whose training symbol matches --symbol (policies are
pickled objects of policy.py classes, committed with their sha256 in
frozen/MANIFEST.json and verified before loading), evaluates on the given
days, and writes aggregate JSON. Emits public CI annotations when run under
GitHub Actions. Prints no per-second data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
from pathlib import Path

import numpy as np

import policy
from analysis import TIERSETS, market_analysis

HERE = Path(__file__).resolve().parent


def load_frozen(symbol):
    man = json.loads((HERE / "frozen" / "MANIFEST.json").read_text())
    out = []
    for entry in man["policies"]:
        if entry["train_symbol"] != symbol:
            continue
        blob = (HERE / "frozen" / entry["file"]).read_bytes()
        if hashlib.sha256(blob).hexdigest() != entry["sha256"]:
            raise ValueError(f"frozen policy hash mismatch: {entry['file']}")
        out.append((entry, pickle.loads(blob)))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--symbol", required=True)
    ap.add_argument("--days", nargs="+", required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    res = dict(symbol=a.symbol, days=a.days, policies=[])
    for entry, pol in load_frozen(a.symbol):
        tiers = TIERSETS[entry["tierset"]]
        rows = policy.collect(a.symbol, a.days, entry["size_usd"], tiers)
        ev = policy.evaluate(pol, rows, entry["size_usd"], tiers)
        orc = policy.evaluate(None, rows, entry["size_usd"], tiers)
        r = dict(label=entry["label"], policy=entry["policy"], size_usd=entry["size_usd"],
                 heldout=ev, oracle=orc["mean_net_saving_bps_common"])
        res["policies"].append(r)
        m = ev["mean_net_saving_bps_common"]
        line = (f"{entry['label']} {entry['policy']} ${entry['size_usd']}: mean_net_bps={m and m['point']:.5f} "
                f"ci=[{m and m['lo95']:.5f},{m and m['hi95']:.5f}] paid_choices={ev['paid_choices']} "
                f"positive={ev['paid_choices_positive']} oracle_bps={orc['mean_net_saving_bps_common']['point']:.5f}") if m else f"{entry['label']} no data"
        print(line)
        if gha and entry["policy"] in ("gbm", "threshold"):  # GitHub keeps at most 10 notices per step
            print(f"::notice title=frozen {a.symbol} {','.join(a.days)}::{line}")
    an = market_analysis(a.symbol, a.days)
    res["analysis"] = an
    s = an["tiersets"]["shz_candidate"].get("momentum/1000")
    if s and gha:
        ws = s["win_share_of_covered_time"]; vs = s["total_volume_share_in_win_seconds"]
        cov = {d: v["clean"] for d, v in an["coverage"].items()}
        print(f"::notice title=heldout {a.symbol} coverage::clean_hours={cov} valid_seconds={an['valid_seconds']}")
        print(f"::notice title=heldout {a.symbol} ex-post $1k momentum::time_share int={ws['intermediate'] and ws['intermediate']['point']:.5f} "
              f"prem={ws['premium'] and ws['premium']['point']:.6f}; volume_share int={vs['intermediate'] and vs['intermediate']['point']:.4f} "
              f"prem={vs['premium'] and vs['premium']['point']:.5f}")
    a.output.write_text(json.dumps(res, indent=1, allow_nan=False, default=float) + "\n")


if __name__ == "__main__":
    main()
