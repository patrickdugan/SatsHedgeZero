"""Emit ZKL-26 Lean fixtures: cross-window degree 1/2, linear substitution, dead output,
proportional duplicate, both scalar fields."""
import json
import sys
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ
from full_matrix_scan import scan
from graph_dependency import campaign26
from scan_findings import bind_dead, verify_duplicates
from local_binding import bind, scaled_pair
from test_graph_dependency import fixture
from test_local_binding import make_stream
from test_zkl26 import ONE, substitution_rows, v
from window_dependency import indexed_lean

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=False)
count = 0
for name, p in (("fr", BN254_FR), ("fq", BN254_FQ)):
    cases = {f"chain{d}": (fixture(d), len(fixture(d))-1) for d in (1, 2)}
    cases["subst"] = (substitution_rows(p), 2)
    for case, (rows, target) in cases.items():
        path = root / f"{name}_{case}.rows.jsonl"
        original = make_stream(path, p, rows)
        _, bundles = campaign26(path, digest(original), width=2, targets=[target])
        for receipt, source in bundles:
            (root / f"{name}_{case}_{receipt['arm']}.lean").write_text(source, encoding="utf-8")
            count += 1
    rows = [[v(10), v(11), v(12)], [v(12), ONE, v(13, "3")], [v(10, "2"), v(11), v(12, "2")]]
    path = root / f"{name}_scan.rows.jsonl"
    pin = digest(make_stream(path, p, rows, wires=20))
    found = scan(path, pin)
    _, ok, _ = verify_duplicates(path, pin, found["duplicate_pairs"])
    _, a, b = bind(path, pin, ok[0][0], [ok[0][1]])
    (root / f"{name}_duplicate.lean").write_text(
        indexed_lean(a, b, scaled_pair(a, b), ok[0][0], [ok[0][1]]), encoding="utf-8")
    row, ws = found["dead_output_sample"][0]
    _, source = bind_dead(path, pin, row, ws[0][0])
    (root / f"{name}_dead.lean").write_text(source, encoding="utf-8")
    count += 2
print(json.dumps({"fixtures": count}))
