#!/usr/bin/env python3
"""Replay many local hours in parallel into the local cache (resumable)."""
from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np

from common import CACHE, utc_ms
from engine import replay_hour


def one(job):
    sym, hour, path, clock, out = job
    t0 = time.time()
    try:
        z = replay_hour(path, sym, utc_ms(hour), clock)
    except Exception as e:  # recorded as missing coverage, never substituted
        return dict(symbol=sym, hour=hour, clock=clock, error=f"{type(e).__name__}: {e}")
    counts = z.pop("counts")
    tmp = Path(str(out) + ".tmp.npz")
    np.savez_compressed(tmp, **{k: v for k, v in z.items() if isinstance(v, np.ndarray)},
                        clean=np.array(z["clean"]), counts=np.array(json.dumps(counts)))
    tmp.replace(out)
    return dict(symbol=sym, hour=hour, clock=clock, clean=bool(z["clean"]), counts=counts,
                valid_seconds=int(z["arr_valid"].sum()), seconds=round(time.time() - t0, 1))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--symbol", required=True)
    ap.add_argument("--books", type=Path, required=True)
    ap.add_argument("--first", required=True, help="YYYY-MM-DD")
    ap.add_argument("--last", required=True)
    ap.add_argument("--clock", default="received")
    ap.add_argument("--workers", type=int, default=5)
    a = ap.parse_args()
    outdir = CACHE / "hours" / a.clock / a.symbol
    outdir.mkdir(parents=True, exist_ok=True)
    jobs = []
    for p in sorted(a.books.glob("*.parquet")):
        day, hh = p.stem[:10], p.stem[11:13]
        if a.first <= day <= a.last:
            out = outdir / f"{p.stem}.npz"
            if not out.exists():
                jobs.append((a.symbol, f"{day}T{hh}:00:00", str(p), a.clock, out))
    log = CACHE / f"replay_log_{a.clock}_{a.symbol}.jsonl"
    with ProcessPoolExecutor(a.workers) as ex, log.open("a") as f:
        for fut in as_completed([ex.submit(one, j) for j in jobs]):
            r = fut.result()
            f.write(json.dumps(r) + "\n")
            f.flush()
    print(f"{a.symbol} {a.clock}: {len(jobs)} hours processed; log {log}")


if __name__ == "__main__":
    main()
