#!/usr/bin/env python3
"""Inventory local Lighter L2 book caches without copying or publishing rows.

For every hourly book file: market, UTC hour, bytes, sha256, row count,
native sequence continuity inside the hour and across adjacent hours, and the
recorder-minus-venue clock distribution. Duplicates (same market, hour, bytes,
sha256) found under several directories are reported once.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pyarrow.compute as pc
import pyarrow.parquet as pq

NAME = re.compile(r"^(\d{4}-\d{2}-\d{2})-(\d{2})\.parquet$")
COLS = ["received_time", "event_time", "symbol", "event_type", "final_update_id", "prev_final_update_id"]


def scan(path: str) -> dict:
    try:
        return _scan(path)
    except Exception as e:  # unreadable or malformed file: recorded, never substituted
        m = NAME.match(Path(path).name)
        return dict(path=path, file=Path(path).name, hour=f"{m.group(1)}T{m.group(2)}:00:00", market="unreadable",
                    error=f"{type(e).__name__}: {e}", sha256=None)


def _scan(path: str) -> dict:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    t = pq.read_table(p, columns=COLS)
    sym = t["symbol"].unique().to_pylist()
    rx = t["received_time"].to_numpy()
    ev = t["event_time"].to_numpy()
    typ = np.where(pc.equal(t["event_type"], "snapshot").to_numpy(zero_copy_only=False), "snapshot", "update").astype("U8")
    t = t.drop_columns(["event_type"])
    fin = t["final_update_id"].to_numpy(zero_copy_only=False)
    prev = t["prev_final_update_id"].to_numpy(zero_copy_only=False)
    # One message = consecutive rows sharing (received, event, type, final id).
    key_change = np.ones(len(rx), bool)
    key_change[1:] = (rx[1:] != rx[:-1]) | (ev[1:] != ev[:-1]) | (fin[1:] != fin[:-1]) | (typ[1:] != typ[:-1])
    idx = np.flatnonzero(key_change)
    m_typ, m_fin, m_prev = typ[idx], fin[idx], prev[idx]
    gaps = 0
    seq = None
    first_update_prev = None
    for k in range(len(idx)):
        if m_typ[k] == "snapshot":
            seq = m_fin[k]
            continue
        if m_prev[k] != m_prev[k]:  # null previous id on an update: native continuity unknown
            gaps += 1
            seq = None
            continue
        if first_update_prev is None:
            first_update_prev = int(m_prev[k])
        if seq is not None and m_prev[k] != seq:
            gaps += 1
        seq = m_fin[k]
    lag_ms = rx[idx] / 1e6 - ev[idx]
    q = np.quantile(lag_ms, [0.5, 0.9, 0.99, 0.999]).tolist() if len(lag_ms) else None
    m = NAME.match(p.name)
    return dict(path=str(p), file=p.name, hour=f"{m.group(1)}T{m.group(2)}:00:00", market=sym[0] if len(sym) == 1 else sym,
                bytes=p.stat().st_size, sha256=h.hexdigest(), rows=t.num_rows, messages=int(len(idx)),
                snapshots=int((m_typ == "snapshot").sum()), intra_hour_gaps=gaps,
                first_update_prev_id=first_update_prev, last_final_id=int(m_fin[-1]) if len(idx) else None,
                event_time_min=int(ev.min()), event_time_max=int(ev.max()),
                recorder_minus_venue_ms_q50_q90_q99_q999=q,
                negative_recorder_lag_messages=int((lag_ms < 0).sum()))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--markets", nargs="+", default=["BTC", "ETH", "SOL"])
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--subdirs", nargs="+", default=[
        "cross-market-l2/BTC/archive/books", "cross-market-l2/SOL/archive/books", "swing-l2/books", "lighter-l2",
        "holdout/books", "warm-holdout/books", "nbx-forward-holdout/books", "shelf-holdout/books",
        "shelf-extended-holdout/books"])
    a = ap.parse_args()
    dirs = [a.root / s for s in a.subdirs]
    files = [p for d in dirs for p in d.glob("*.parquet") if NAME.match(p.name)]
    with ProcessPoolExecutor(a.workers) as ex:
        rows = list(ex.map(scan, map(str, files), chunksize=4))
    errors = [dict(file=str(Path(r["path"]).relative_to(a.root)), error=r["error"]) for r in rows if "error" in r]
    rows = [r for r in rows if r["market"] in a.markets]
    uniq = {}
    for r in rows:
        k = (r["market"], r["hour"], r["sha256"])
        uniq.setdefault(k, dict(r, copies=[]))["copies"].append(r["path"])
    conflicts = {}
    for (mk, hr, _), r in uniq.items():
        conflicts.setdefault((mk, hr), []).append(r["sha256"])
    out = []
    for r in sorted(uniq.values(), key=lambda r: (r["market"], r["hour"])):
        r = dict(r)
        r["conflicting_versions"] = len(conflicts[r["market"], r["hour"]])
        r.pop("path")
        r["copies"] = sorted(str(Path(c).relative_to(a.root)) for c in r["copies"])
        out.append(r)
    # Cross-hour native continuity for markets with unique versions.
    by = {}
    for r in out:
        if r["conflicting_versions"] == 1:
            by.setdefault(r["market"], []).append(r)
    for mk, rs in by.items():
        for a_, b_ in zip(rs, rs[1:]):
            b_["continuity_from_previous_hour"] = (
                "not_adjacent" if np.datetime64(b_["hour"]) - np.datetime64(a_["hour"]) != np.timedelta64(1, "h")
                else "continuous" if b_["first_update_prev_id"] == a_["last_final_id"]
                else "break")
    summary = {}
    for mk in a.markets:
        rs = [r for r in out if r["market"] == mk]
        days = sorted({r["hour"][:10] for r in rs})
        summary[mk] = dict(unique_hours=len(rs), days=len(days), first=rs[0]["hour"] if rs else None,
                           last=rs[-1]["hour"] if rs else None,
                           full_days=[d for d in days if sum(r["hour"].startswith(d) for r in rs) == 24],
                           partial_days={d: sum(r["hour"].startswith(d) for r in rs) for d in days
                                         if sum(r["hour"].startswith(d) for r in rs) != 24},
                           hours_with_intra_gaps=sum(r["intra_hour_gaps"] > 0 for r in rs),
                           cross_hour_breaks=sum(r.get("continuity_from_previous_hour") == "break" for r in rs),
                           conflicting_hours=sum(r["conflicting_versions"] > 1 for r in rs))
    doc = dict(schema="shz-lv/l2-inventory/v1", root_label="local TradingMoneyball/Codex offload cache (not published)",
               summary=summary, unreadable_files=errors, files=out, raw_rows_published=False)
    a.output.write_text(json.dumps(doc, indent=1) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
