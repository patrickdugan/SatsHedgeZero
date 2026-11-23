"""Fail closed on pre-advisory circuit versions in each resolved lockfile."""
import pathlib
import sys
import tomllib

EXPECTED = {
    "risc0-zkvm": "3.1.0",
    "risc0-zkp": "3.0.6",
    "risc0-groth16": "3.0.6",
    "risc0-build": "3.0.7",
    "risc0-circuit-recursion": "4.1.0",
    "risc0-circuit-recursion-control-zkrs": "4.1.0",
    "risc0-circuit-recursion-zkrs": "4.1.0",
    "risc0-circuit-recursion-sys": "4.1.0",
    "risc0-circuit-rv32im": "4.1.0",
    "risc0-circuit-rv32im-sys": "4.1.0",
    "risc0-circuit-keccak": "4.1.0",
    "risc0-circuit-keccak-sys": "4.1.0",
}
REQUIRED = {"risc0-zkvm", "risc0-zkp", "risc0-circuit-recursion", "risc0-circuit-rv32im"}
for name in sys.argv[1:]:
    pkgs = tomllib.loads(pathlib.Path(name).read_text())["package"]
    found = set()
    for p in pkgs:
        n = p["name"]
        if n in EXPECTED:
            if p["version"] != EXPECTED[n] or n in found:
                raise SystemExit(f"{name}: wrong/duplicate {n}: {p['version']}")
            found.add(n)
    if not REQUIRED <= found:
        raise SystemExit(f"{name}: missing {REQUIRED-found}")
    print(f"{name}: patched circuit family verified, {len(found)} version pins")
