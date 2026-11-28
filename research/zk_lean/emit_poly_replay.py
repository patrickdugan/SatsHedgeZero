"""Write six generated certificates for independent Lean CI replay."""
import sys
from pathlib import Path

from audit import BN254_FR, digest
from poly_certificate import generate
from test_poly_certificate import fixture, search_fixture

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
for field, p in (("F7", 7), ("BN254", BN254_FR)):
    for d in range(3):
        a, b = fixture(p, f"degree{d}", 3)
        cert = search_fixture(a, b, d)
        assert cert["degree"] == d
        source, _ = generate(a, b, cert, digest(a), digest(b), d)
        (out / f"ZKL12_{field}_D{d}.lean").write_text(source, encoding="utf-8")
