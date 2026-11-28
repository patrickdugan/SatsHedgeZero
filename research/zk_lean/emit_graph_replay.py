"""Emit degree-one/two original-index proof fixtures for both scalar fields."""
import sys
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ
from graph_dependency import campaign
from test_graph_dependency import fixture
from test_local_binding import make_stream

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=False)
for name, p in (("fr", BN254_FR), ("fq", BN254_FQ)):
    for d in (1, 2):
        rows = fixture(d)
        path = root / f"{name}_{d}.rows.jsonl"
        original = make_stream(path, p, rows)
        result, bundles = campaign(path, digest(original), width=2, targets=[len(rows)-1])
        assert len(bundles) == 1
        receipt, source = bundles[0]
        assert receipt["degree"] == d
        (root / f"{name}_{d}.lean").write_text(source, encoding="utf-8")
