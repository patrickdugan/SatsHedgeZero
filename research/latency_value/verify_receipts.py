#!/usr/bin/env python3
"""Deterministic CI check: recompute committed receipts from committed inputs.

* results/revenue.json      <- manifests/lighter_trades_daily.json + manifests/defillama_lighter.json
* results/shz_economics.json <- results/analysis_*.json + results/revenue.json
* figures exist for every committed figure name in RECEIPT.json
Floats are compared with a relative tolerance (cross-platform libm).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"


def close(a, b, path="$", rtol=1e-9, atol=1e-12):
    if isinstance(a, dict):
        assert isinstance(b, dict) and set(a) == set(b), f"{path}: keys differ"
        for k in a:
            close(a[k], b[k], f"{path}.{k}", rtol, atol)
    elif isinstance(a, list):
        assert isinstance(b, list) and len(a) == len(b), f"{path}: length differs"
        for i, (x, y) in enumerate(zip(a, b)):
            close(x, y, f"{path}[{i}]", rtol, atol)
    elif isinstance(a, float) or isinstance(b, float):
        assert abs(a - b) <= atol + rtol * max(abs(a), abs(b)), f"{path}: {a} != {b}"
    else:
        assert a == b, f"{path}: {a!r} != {b!r}"


def main():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        subprocess.run([sys.executable, str(HERE / "revenue.py"), "--trades-daily", str(HERE / "manifests" / "lighter_trades_daily.json"),
                        "--llama-cache", str(HERE / "manifests" / "defillama_lighter.json"), "--output", str(d / "revenue.json")],
                       check=True, stdout=subprocess.DEVNULL)
        close(json.loads((RES / "revenue.json").read_text()), json.loads((d / "revenue.json").read_text()), "revenue")
        an = sorted(RES.glob("analysis_*.json"))
        subprocess.run([sys.executable, str(HERE / "shz_model.py"), "--analysis", *map(str, an), "--revenue", str(RES / "revenue.json"),
                        "--output", str(d / "shz.json")], check=True, stdout=subprocess.DEVNULL)
        close(json.loads((RES / "shz_economics.json").read_text()), json.loads((d / "shz.json").read_text()), "shz")
    receipt = json.loads((RES / "RECEIPT.json").read_text())
    import hashlib
    for rel, h in receipt["sha256"].items():
        b = (HERE / rel).read_bytes()
        if rel.endswith(".json"):
            b = b.replace(b"\r\n", b"\n")
        assert hashlib.sha256(b).hexdigest() == h, f"receipt hash mismatch: {rel}"
    for f in receipt["figures"]:
        assert (HERE / "figures" / f).exists(), f"missing figure {f}"
    print("receipts reproduce: revenue.json, shz_economics.json; figures present:", len(receipt["figures"]))


if __name__ == "__main__":
    main()
