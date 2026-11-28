"""ZKL-11: degree-two, constant-multiplier R1CS redundancy certificates."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from audit import BN254_FR, canonical, digest, lean_source, load

MAX_ROWS = 256
MAX_TERMS = 4096
MAX_EXPANSION = 50_000
PRIMES = {7, 11, BN254_FR}


def add(poly, other, factor=1, modulus=None):
    out = dict(poly)
    for key, value in other.items():
        v = out.get(key, 0) + factor * value
        if modulus is not None:
            v %= modulus
        if v:
            out[key] = v
        else:
            out.pop(key, None)
    if len(out) > MAX_TERMS:
        raise ValueError("polynomial support cap exceeded")
    return out


def row_poly(row):
    """Integer polynomial with C homogenized by the constant wire 0."""
    a, b, c = row
    if len(a) * len(b) + len(c) > MAX_EXPANSION:
        raise ValueError("row expansion cap exceeded")
    out = {}
    for i, v in a:
        for j, w in b:
            key = (min(i, j), max(i, j))
            out[key] = out.get(key, 0) + int(v) * int(w)
    for i, v in c:
        key = (0, i)
        out[key] = out.get(key, 0) - int(v)
    out = {k: v for k, v in out.items() if v}
    if len(out) > MAX_TERMS:
        raise ValueError("polynomial support cap exceeded")
    return out


def mod(poly, p):
    return {k: v % p for k, v in poly.items() if v % p}


def shape_pair(original, replacement, target_index, expected_original, expected_replacement):
    a, b = canonical(original), canonical(replacement)
    if (digest(a), digest(b)) != (expected_original, expected_replacement):
        raise ValueError("independently pinned shape hash mismatch")
    if any(a[k] != b[k] for k in ("format", "modulus", "wires", "public")):
        raise ValueError("interface or modulus changed")
    if len(a["rows"]) > MAX_ROWS:
        raise ValueError("row cap exceeded")
    if type(target_index) is not int or not 0 <= target_index < len(a["rows"]):
        raise ValueError("invalid target row")
    if a["rows"][:target_index] + a["rows"][target_index + 1:] != b["rows"]:
        raise ValueError("replacement must delete exactly the nominated row in place")
    expansion = sum(len(x) * len(y) + len(z) for x, y, z in a["rows"])
    if expansion > MAX_EXPANSION:
        raise ValueError("shape expansion cap exceeded")
    return a, b


def search(original, replacement, target_index, expected_original, expected_replacement):
    """Deterministic sparse Gaussian elimination; None means no span certificate."""
    a, b = shape_pair(original, replacement, target_index, expected_original, expected_replacement)
    p = int(a["modulus"])
    if p not in PRIMES:
        raise ValueError("search modulus not in reviewed prime allowlist")
    basis = {}
    for idx, row in enumerate(b["rows"]):
        v, weights = mod(row_poly(row), p), {idx: 1}
        while v:
            pivot = min(v)
            factor = v[pivot]
            if pivot not in basis:
                inv = pow(factor, -1, p)
                basis[pivot] = (mod({k: inv * x for k, x in v.items()}, p),
                                mod({k: inv * x for k, x in weights.items()}, p))
                break
            u, coeffs = basis[pivot]
            v = add(v, u, -factor, p)
            weights = add(weights, coeffs, -factor, p)
    v = mod(row_poly(a["rows"][target_index]), p)
    weights = {}
    while v:
        pivot = min(v)
        if pivot not in basis:
            return None
        factor = v[pivot]
        u, coeffs = basis[pivot]
        v = add(v, u, -factor, p)
        weights = add(weights, coeffs, factor, p)
    residual = row_poly(a["rows"][target_index])
    for i, k in weights.items():
        residual = add(residual, row_poly(b["rows"][i]), -k)
    if any(v % p for v in residual.values()):
        raise AssertionError("solver returned a nonidentity")
    cert = {
        "schema": "zkl-ideal-certificate-v1",
        "original_sha256": expected_original,
        "replacement_sha256": expected_replacement,
        "target_index": target_index,
        "weights": [[i, str(k)] for i, k in sorted(weights.items())],
        "correction": [[i, j, str(v // p)] for (i, j), v in sorted(residual.items())],
    }
    verify(a, b, cert, expected_original, expected_replacement)
    return cert


def signed(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|-?[1-9][0-9]*", value):
        raise ValueError("invalid canonical signed integer")
    if len(value) > 160:
        raise ValueError("coefficient digit cap exceeded")
    return int(value)


def verify(original, replacement, cert, expected_original, expected_replacement):
    """Check only exact integer identity, using no elimination or inversion."""
    if set(cert) != {"schema", "original_sha256", "replacement_sha256", "target_index",
                     "weights", "correction"} or cert["schema"] != "zkl-ideal-certificate-v1":
        raise ValueError("invalid certificate schema")
    if (cert["original_sha256"], cert["replacement_sha256"]) != (expected_original, expected_replacement):
        raise ValueError("certificate hash mismatch")
    a, b = shape_pair(original, replacement, cert["target_index"], expected_original, expected_replacement)
    p = int(a["modulus"])
    if len(cert["weights"]) > len(b["rows"]) or len(cert["correction"]) > MAX_TERMS:
        raise ValueError("certificate size cap exceeded")
    seen = set()
    rhs = {}
    for i, raw in cert["weights"]:
        k = signed(raw)
        if type(i) is not int or not 0 <= i < len(b["rows"]) or i in seen or not 0 < k < p:
            raise ValueError("invalid retained row or multiplier")
        seen.add(i)
        rhs = add(rhs, row_poly(b["rows"][i]), k)
    seen = set()
    correction = {}
    for i, j, raw in cert["correction"]:
        c = signed(raw)
        if (type(i) is not int or type(j) is not int or not 0 <= i <= j < a["wires"]
                or (i, j) in seen or c == 0):
            raise ValueError("invalid correction monomial")
        seen.add((i, j))
        correction[(i, j)] = c
    rhs = add(rhs, correction, p)
    if rhs != row_poly(a["rows"][cert["target_index"]]):
        raise ValueError("integer polynomial identity failed")
    return a, b


def lean_int(v):
    return f"({v})" if v.startswith("-") else v


def generate(original, replacement, cert, expected_original, expected_replacement):
    a, b = verify(original, replacement, cert, expected_original, expected_replacement)
    first = lean_source(a).replace("import MathCan.ZKLean", "import MathCan.ZKLeanAlgebra").replace(
        "def exportedShape : Shape", "def originalShape : Shape")
    second = lean_source(b).split("def exportedShape : Shape :=", 1)[1]
    target = cert["target_index"]
    weights = ", ".join(f"({lean_int(k)}, replacementShape.rows[{i}]!)" for i, k in cert["weights"])
    correction = ", ".join(f"⟨{i}, {j}, {lean_int(c)}⟩" for i, j, c in cert["correction"])
    source = first + "\ndef replacementShape : Shape :=" + second + f"""
open MathCan.ZKLean.Algebra

def targetRow : Row := originalShape.rows[{target}]!
def weights : Weights := [{weights}]
def correction : QPoly := [{correction}]

set_option maxRecDepth 4096 in
set_option maxHeartbeats 4000000 in
theorem exact_ideal_delete (hs : wellFormed originalShape) (x : List Nat) :
    accepts originalShape x ↔ accepts replacementShape x := by
  change accepts originalShape x ↔ accepts (withRows originalShape replacementShape.rows) x
  exact checked_ideal_delete originalShape replacementShape.rows targetRow weights correction hs
    (by decide) (by decide) (by decide) (by decide) x

#print axioms exact_ideal_delete
"""
    # Use explicit getElem proof-free literals instead of get! (requires Inhabited Row).
    def lean_row(row):
        return "⟨" + ", ".join("[" + ", ".join(f"⟨{i}, {c}⟩" for i, c in comb) + "]"
                               for comb in row) + "⟩"
    source = source.replace(f"originalShape.rows[{target}]!", lean_row(a["rows"][target]))
    for i, _ in cert["weights"]:
        source = source.replace(f"replacementShape.rows[{i}]!", lean_row(b["rows"][i]))
    receipt = {"certificate": cert, "exact_identity_checked": True,
               "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
               "lean_replayed": False, "production_accepted": False}
    return source, receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("replacement", type=Path)
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--expected-replacement", required=True)
    parser.add_argument("--lean-out", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    args = parser.parse_args()
    a, b = load(args.original), load(args.replacement)
    cert = search(a, b, args.target, args.expected_original, args.expected_replacement)
    if cert is None:
        raise SystemExit("INCONCLUSIVE: target is outside the retained quadratic span")
    source, receipt = generate(a, b, cert, args.expected_original, args.expected_replacement)
    with args.lean_out.open("x", encoding="utf-8") as f:
        f.write(source)
    with args.receipt_out.open("x", encoding="utf-8") as f:
        f.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
