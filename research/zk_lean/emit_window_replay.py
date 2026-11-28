"""Emit both-field indexed proofs for the controlled fixture."""
import sys
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ
from test_local_binding import make_stream
from test_window_dependency import fixture
from window_dependency import discover

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=False)
for name, p in (("fr", BN254_FR), ("fq", BN254_FQ)):
    path = root / f"{name}.rows.jsonl"
    original = make_stream(path, p, fixture())
    summary, cases = discover(path, digest(original))
    assert len(cases) == 3
    for receipt, source in cases:
        (root / f"{name}_{receipt['kind']}.lean").write_text(source, encoding="utf-8")
