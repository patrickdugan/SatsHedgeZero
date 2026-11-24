#!/usr/bin/env python3
"""Run the whole local study from cached replays to committed aggregates.

Steps (each writes into results/ unless --only selects a subset):
  analysis  per-market tier economics, rare-event test, WTP, markouts, regimes
  policy    chronological train/freeze/test splits and frozen policies
  revenue   DefiLlama x public-trades calibration
  shz       SHZ federation economics
  figures   paper figures
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
FROZEN = HERE / "frozen"
WINDOWS = {"BTC": ("2026-10-11", "2026-10-27"), "ETH": ("2026-11-01", "2026-11-21"), "SOL": ("2026-10-11", "2026-11-21")}
SPLITS = [  # label, symbol, train, test, size, freeze
    ("BTC_oct11_1k", "BTC", ("2026-10-11", "2026-10-11"), ("2026-10-12", "2026-10-27"), 1000, True),
    ("BTC_dev_1k", "BTC", ("2026-10-11", "2026-10-20"), ("2026-10-21", "2026-10-27"), 1000, False),
    ("BTC_dev_10k", "BTC", ("2026-10-11", "2026-10-20"), ("2026-10-21", "2026-10-27"), 10000, False),
    ("ETH_dev_1k", "ETH", ("2026-11-01", "2026-11-14"), ("2026-11-15", "2026-11-21"), 1000, False),
    ("ETH_dev_10k", "ETH", ("2026-11-01", "2026-11-14"), ("2026-11-15", "2026-11-21"), 10000, False),
    ("SOL_dev_1k", "SOL", ("2026-10-11", "2026-11-07"), ("2026-11-08", "2026-11-21"), 1000, False),
    ("SOL_dev_10k", "SOL", ("2026-10-11", "2026-11-07"), ("2026-11-08", "2026-11-21"), 10000, False),
    # Frozen on all local days for the CI held-out days 2026-11-22/23 (test
    # window here is the last local week, i.e. in-sample; CI is the real test).
    ("BTC_full_1k", "BTC", ("2026-10-11", "2026-10-27"), ("2026-10-21", "2026-10-27"), 1000, True),
    ("BTC_full_10k", "BTC", ("2026-10-11", "2026-10-27"), ("2026-10-21", "2026-10-27"), 10000, True),
    ("ETH_full_1k", "ETH", ("2026-11-01", "2026-11-21"), ("2026-11-15", "2026-11-21"), 1000, True),
    ("SOL_full_1k", "SOL", ("2026-10-11", "2026-11-21"), ("2026-11-08", "2026-11-21"), 1000, True),
]


def days(first, last):
    return [str(x) for x in np.arange(np.datetime64(first), np.datetime64(last) + np.timedelta64(1, "D"))]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", nargs="*", default=["analysis", "policy", "revenue", "shz", "figures"])
    ap.add_argument("--symbols", nargs="*", default=list(WINDOWS))
    a = ap.parse_args()
    RES.mkdir(exist_ok=True)
    if "analysis" in a.only:
        from analysis import market_analysis
        for sym in a.symbols:
            z = market_analysis(sym, days(*WINDOWS[sym]))
            (RES / f"analysis_{sym}.json").write_text(json.dumps(z, indent=1, allow_nan=False, default=float) + "\n")
            print("analysis", sym, z["valid_seconds"], "/", z["wall_seconds"])
    if "policy" in a.only:
        from policy import run_split
        for label, sym, tr, te, size, freeze in SPLITS:
            if sym not in a.symbols:
                continue
            z = run_split(sym, days(*tr), days(*te), size, freeze_dir=FROZEN if freeze else None, label=label)
            z["label"] = label
            z["heldout_is_out_of_sample"] = not label.split("_")[1] == "full"
            (RES / f"policy_{label}.json").write_text(json.dumps(z, indent=1, allow_nan=False, default=float) + "\n")
            for k, v in z["policies"].items():
                m = v["mean_net_saving_bps_common"]
                print(f"policy {label:14s} {k:16s} {m and round(m['point'], 5)} [{m and round(m['lo95'], 5)}, {m and round(m['hi95'], 5)}] paid={v['paid_choices']}")
    if "revenue" in a.only:
        import subprocess, sys
        subprocess.run([sys.executable, str(HERE / "revenue.py"), "--trades-daily", str(HERE / "manifests" / "lighter_trades_daily.json"),
                        "--llama-cache", str(HERE / "manifests" / "defillama_lighter.json"), "--output", str(RES / "revenue.json")], check=True)
    if "shz" in a.only:
        import subprocess, sys
        subprocess.run([sys.executable, str(HERE / "shz_model.py"), "--analysis", *[str(RES / f"analysis_{s}.json") for s in WINDOWS],
                        "--revenue", str(RES / "revenue.json"), "--output", str(RES / "shz_economics.json")], check=True)
    if "figures" in a.only:
        import figures
        figures.main()
    if "receipt" in a.only or "figures" in a.only:
        import hashlib
        files = sorted(p for p in list(RES.glob("*.json")) + list((HERE / "manifests").glob("*.json")) + list(FROZEN.glob("*"))
                       if p.name != "RECEIPT.json")
        def digest(p):  # JSON hashed with LF line endings, as stored in git
            b = p.read_bytes()
            return hashlib.sha256(b.replace(b"\r\n", b"\n") if p.suffix == ".json" else b).hexdigest()
        receipt = dict(schema="shz-lv/receipt/v1", hash_note="sha256; .json files hashed after CRLF->LF normalisation",
                       sha256={str(p.relative_to(HERE)).replace("\\", "/"): digest(p) for p in files},
                       figures=sorted(p.name for p in (HERE / "figures").glob("*.png")),
                       raw_rows_published=False, production_ready=False, live_orders=False, account_level_inference=False)
        (RES / "RECEIPT.json").write_text(json.dumps(receipt, indent=1) + "\n")
        print("receipt", len(files), "files")


if __name__ == "__main__":
    main()
