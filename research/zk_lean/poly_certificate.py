"""ZKL-12: bounded monomial-multiplier search and exact polynomial verification."""
import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path

from audit import digest, lean_source, load
from ideal_certificate import PRIMES, MAX_TERMS, add, mod, row_poly, shape_pair, signed

MAX_DEGREE = 2
MAX_COLUMNS = 1024
MAX_ELIMINATION_STEPS = 100_000


def residual(row):
    out = {}
    for monomial, coefficient in row_poly(row).items():
        key = tuple(i for i in monomial if i)
        out = add(out, {key: coefficient})
    return out


def multiply(poly, monomial):
    return {tuple(sorted((*key, *monomial))): v for key, v in poly.items()}


def bounded_monomial(raw, wires, degree):
    if (not isinstance(raw, list) or len(raw) > degree
            or any(type(i) is not int or not 0 < i < wires for i in raw)
            or raw != sorted(raw)):
        raise ValueError("invalid monomial")
    return tuple(raw)


def limits(a, b, degree):
    if type(degree) is not int or not 0 <= degree <= MAX_DEGREE:
        raise ValueError("invalid multiplier degree")
    n = a["wires"] - 1
    columns = len(b["rows"]) * sum(math.comb(n + d - 1, d) if n else int(d == 0)
                                  for d in range(degree + 1))
    if columns > MAX_COLUMNS:
        raise ValueError("bounded monomial column cap exceeded")


def search(original, replacement, target_index, expected_original, expected_replacement, degree=2):
    a, b = shape_pair(original, replacement, target_index, expected_original, expected_replacement)
    limits(a, b, degree)
    p = int(a["modulus"])
    if p not in PRIMES:
        raise ValueError("search modulus not in reviewed prime allowlist")
    polys = [residual(row) for row in b["rows"]]
    target = residual(a["rows"][target_index])
    basis, weights = {}, {}
    remaining = mod(target, p)
    steps = 0

    def reduce(vector, coefficients, sign):
        nonlocal steps
        while vector:
            pivot = min(vector)
            if pivot not in basis:
                break
            factor = vector[pivot]
            u, v = basis[pivot]
            vector = add(vector, u, -factor, p)
            coefficients = add(coefficients, v, sign * factor, p)
            steps += 1
            if steps > MAX_ELIMINATION_STEPS:
                raise ValueError("elimination work cap exceeded")
        return vector, coefficients

    for d in range(degree + 1):
        for mon in itertools.combinations_with_replacement(range(1, a["wires"]), d):
            for i, poly in enumerate(polys):
                v, w = reduce(mod(multiply(poly, mon), p), {(i, mon): 1}, -1)
                if v:
                    pivot = min(v)
                    inv = pow(v[pivot], -1, p)
                    basis[pivot] = (mod({k: inv * x for k, x in v.items()}, p),
                                    mod({k: inv * x for k, x in w.items()}, p))
        remaining, weights = reduce(remaining, weights, 1)
        if not remaining:
            diff = target
            for (i, mon), k in weights.items():
                diff = add(diff, multiply(polys[i], mon), -k)
            if any(v % p for v in diff.values()):
                raise AssertionError("nonidentity from search")
            cert = {
                "schema": "zkl-poly-certificate-v1", "original_sha256": expected_original,
                "replacement_sha256": expected_replacement, "target_index": target_index,
                "degree": max((len(mon) for _, mon in weights), default=0),
                "multipliers": [[i, list(mon), str(k)] for (i, mon), k in sorted(weights.items())],
                "correction": [[list(mon), str(v // p)] for mon, v in sorted(diff.items())],
            }
            verify(a, b, cert, expected_original, expected_replacement, degree)
            return cert
    return None


def verify(original, replacement, cert, expected_original, expected_replacement, degree=2):
    """Independent exact integer identity; no modular elimination or field inversion."""
    if set(cert) != {"schema", "original_sha256", "replacement_sha256", "target_index",
                     "degree", "multipliers", "correction"} or cert["schema"] != "zkl-poly-certificate-v1":
        raise ValueError("invalid certificate schema")
    if (cert["original_sha256"], cert["replacement_sha256"]) != (expected_original, expected_replacement):
        raise ValueError("certificate hash mismatch")
    a, b = shape_pair(original, replacement, cert["target_index"], expected_original, expected_replacement)
    if type(degree) is not int or not 0 <= degree <= MAX_DEGREE:
        raise ValueError("invalid checker degree")
    if type(cert["degree"]) is not int or not 0 <= cert["degree"] <= degree:
        raise ValueError("invalid certificate degree")
    if len(cert["multipliers"]) > MAX_COLUMNS or len(cert["correction"]) > MAX_TERMS:
        raise ValueError("certificate size cap exceeded")
    p = int(a["modulus"])
    polys = [residual(row) for row in b["rows"]]
    rhs, seen, max_degree = {}, set(), 0
    for i, raw, k_raw in cert["multipliers"]:
        mon = bounded_monomial(raw, a["wires"], degree)
        k = signed(k_raw)
        if type(i) is not int or not 0 <= i < len(polys) or (i, mon) in seen or not 0 < k < p:
            raise ValueError("invalid retained row or multiplier")
        seen.add((i, mon))
        max_degree = max(max_degree, len(mon))
        rhs = add(rhs, multiply(polys[i], mon), k)
    if max_degree != cert["degree"]:
        raise ValueError("misreported degree")
    correction = {}
    for raw, c_raw in cert["correction"]:
        mon = bounded_monomial(raw, a["wires"], degree + 2)
        c = signed(c_raw)
        if mon in correction or c == 0:
            raise ValueError("invalid correction")
        correction[mon] = c
    if add(rhs, correction, p) != residual(a["rows"][cert["target_index"]]):
        raise ValueError("integer polynomial identity failed")
    return a, b


def lean_row(row):
    return "⟨" + ", ".join("[" + ", ".join(f"⟨{i}, {c}⟩" for i, c in lc) + "]"
                           for lc in row) + "⟩"


def generate(original, replacement, cert, expected_original, expected_replacement, degree=2):
    a, b = verify(original, replacement, cert, expected_original, expected_replacement, degree)
    first = lean_source(a).replace("import MathCan.ZKLean", "import MathCan.ZKLeanPoly").replace(
        "def exportedShape : Shape", "def originalShape : Shape")
    second = lean_source(b).split("def exportedShape : Shape :=", 1)[1]
    target = lean_row(a["rows"][cert["target_index"]])
    multipliers = ", ".join(f"⟨({k}), {mon}, {lean_row(b['rows'][i])}⟩"
                            for i, mon, k in cert["multipliers"])
    correction = ", ".join(f"⟨{mon}, ({c})⟩" for mon, c in cert["correction"])
    source = first + "\ndef replacementShape : Shape :=" + second + f"""
open MathCan.ZKLean.Poly

def targetRow : Row := {target}
def multipliers : List Multiplier := [{multipliers}]
def correction : PPoly := [{correction}]

set_option maxRecDepth 4096 in
set_option maxHeartbeats 4000000 in
theorem exact_poly_delete (hs : wellFormed originalShape) (x : List Nat) :
    accepts originalShape x ↔ accepts replacementShape x := by
  change accepts originalShape x ↔ accepts (withRows originalShape replacementShape.rows) x
  exact checked_poly_delete originalShape replacementShape.rows targetRow multipliers correction hs
    (by decide) (by decide) (by decide) (by decide) x

#print axioms exact_poly_delete
"""
    receipt = {"certificate": cert, "exact_identity_checked": True,
               "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
               "lean_replayed": False, "production_accepted": False}
    return source, receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("replacement", type=Path)
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--degree", type=int, choices=(0, 1, 2), default=2)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--expected-replacement", required=True)
    parser.add_argument("--lean-out", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    args = parser.parse_args()
    a, b = load(args.original), load(args.replacement)
    cert = search(a, b, args.target, args.expected_original, args.expected_replacement, args.degree)
    if cert is None:
        raise SystemExit("INCONCLUSIVE: target is outside the bounded monomial span")
    source, receipt = generate(a, b, cert, args.expected_original, args.expected_replacement, args.degree)
    with args.lean_out.open("x", encoding="utf-8") as f:
        f.write(source)
    with args.receipt_out.open("x", encoding="utf-8") as f:
        f.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
