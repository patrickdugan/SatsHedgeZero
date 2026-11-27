"""Emit direct high-global-ID graph search certificates at each multiplier tier."""
import sys
from pathlib import Path

from audit import BN254_FR
from audit_capture import BN254_FQ, stream_audit
from graph_dependency import Pool, local_shapes, search_local
from test_graph_dependency import rows
from test_local_binding import make_stream
from window_dependency import indexed_lean

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=False)
for name, p in (("fr", BN254_FR), ("fq", BN254_FQ)):
    stream = root / f"{name}.rows.jsonl"
    make_stream(stream, p, rows())
    pool = Pool(100)
    full = stream_audit(stream, visit=pool.visit)
    for target, keep, degree in ((2, [0, 1], 0), (5, [3, 4], 1), (8, [6, 7], 2)):
        rec = search_local(full, pool, target, keep)
        assert rec["degree"] == degree
        a, b = local_shapes(full, pool, target, keep)
        source = indexed_lean(a, b, rec["certificate"], target, keep)
        (root / f"{name}_degree{degree}.lean").write_text(source, encoding="utf-8")
