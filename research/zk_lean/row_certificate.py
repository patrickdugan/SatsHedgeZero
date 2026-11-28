"""Emit an exact Lean row-set equivalence obligation, with no proof-run claim."""
import argparse
import hashlib
import json
from pathlib import Path

from audit import canonical, digest, lean_source, load

MAX_ROWS = 256  # quadratic reflected membership; use scalable proof backend for larger exports


def row_keys(s):
    return {json.dumps(row, separators=(",", ":")) for row in s["rows"]}


def generate(original, replacement, expected_original, expected_replacement):
    a, b = canonical(original), canonical(replacement)
    ha, hb = digest(a), digest(b)
    if (ha, hb) != (expected_original, expected_replacement):
        raise ValueError("independently pinned shape hash mismatch")
    if any(a[k] != b[k] for k in ("format", "modulus", "wires", "public")):
        raise ValueError("interface or field changed")
    if max(len(a["rows"]), len(b["rows"])) > MAX_ROWS:
        raise ValueError("row certificate cap exceeded")
    if row_keys(a) != row_keys(b):
        raise ValueError("row-set equivalence failed; requires a different theorem")
    first = lean_source(a).replace("def exportedShape : Shape", "def originalShape : Shape")
    second = lean_source(b).split("def exportedShape : Shape :=", 1)[1]
    source = first + "\ndef replacementShape : Shape :=" + second + """
set_option maxRecDepth 4096 in
set_option maxHeartbeats 2000000 in
theorem exact_row_rewrite (x : List Nat) :
    accepts originalShape x ↔ accepts replacementShape x := by
  change accepts originalShape x ↔ accepts (withRows originalShape replacementShape.rows) x
  exact checked_delete_equiv originalShape replacementShape.rows (by decide) (by decide) x

#print axioms exact_row_rewrite
"""
    receipt = {
        "schema": "zkl-row-certificate-v1",
        "original_sha256": ha,
        "replacement_sha256": hb,
        "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "original_rows": len(a["rows"]),
        "replacement_rows": len(b["rows"]),
        "distinct_rows": len(row_keys(a)),
        "structural_check_passed": True,
        "lean_replayed": False,
        "production_accepted": False,
    }
    return source, receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("replacement", type=Path)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--expected-replacement", required=True)
    parser.add_argument("--lean-out", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    args = parser.parse_args()
    source, receipt = generate(load(args.original), load(args.replacement),
                               args.expected_original, args.expected_replacement)
    # Exclusive output prevents silently replacing an earlier reviewed artifact.
    with args.lean_out.open("x", encoding="utf-8") as f:
        f.write(source)
    with args.receipt_out.open("x", encoding="utf-8") as f:
        f.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
