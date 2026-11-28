"""Generate high-global-wire-ID fixtures for Lean replay."""
import sys
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ
from local_binding import discover, verify_bound
from test_local_binding import make_stream, rows

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=False)
for name, p in (("fr", BN254_FR), ("fq", BN254_FQ)):
    path = root / f"{name}.rows.jsonl"
    original = make_stream(path, p, rows())
    bundle = discover(path, digest(original))
    source, receipt = verify_bound(path, digest(original), bundle)
    assert receipt["exact_identity_checked"]
    (root / f"{name}.lean").write_text(source, encoding="utf-8")
