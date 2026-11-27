"""ZKL-13: bounded sparse search state; candidate certificates are untrusted."""
from itertools import combinations_with_replacement

BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PRIMES = {7, 11, BN254_FR}
MAX_COLUMNS = 2048
MAX_ROWS = 64
MAX_WIRES = 16
MAX_TERMS = 4096
MAX_WORK = 2_000_000


def add(a, b, factor=1, p=None):
    out = dict(a)
    for key, value in b.items():
        v = out.get(key, 0) + factor * value
        if p is not None:
            v %= p
        if v:
            out[key] = v
        else:
            out.pop(key, None)
    if len(out) > MAX_TERMS:
        raise ValueError("support cap exceeded")
    return out


def residual(row):
    a, b, c = row
    out = {}
    for i, v in a:
        for j, w in b:
            mon = tuple(sorted(k for k in (i, j) if k))
            out = add(out, {mon: int(v) * int(w)})
    for i, v in c:
        out = add(out, {(i,) if i else (): -int(v)})
    return out


def multiply(poly, mon):
    return {tuple(sorted((*key, *mon))): v for key, v in poly.items()}


def mod(poly, p):
    return {k: v % p for k, v in poly.items() if v % p}


class Problem:
    """Small canonical-shape fixtures only; exact verifier owns acceptance."""

    def __init__(self, original, replacement, target, hashes, degree=2):
        self.p = int(original["modulus"])
        if self.p not in PRIMES or not 0 <= degree <= 2:
            raise ValueError("unsupported field or degree")
        if not 1 <= original["wires"] <= MAX_WIRES or len(original["rows"]) > MAX_ROWS:
            raise ValueError("fixture size cap exceeded")
        if type(target) is not int or not 0 <= target < len(original["rows"]):
            raise ValueError("bad target index")
        if any(original[k] != replacement[k] for k in ("format", "modulus", "wires", "public")):
            raise ValueError("interface changed")
        if original["rows"][:target] + original["rows"][target+1:] != replacement["rows"]:
            raise ValueError("not an exact deletion")
        self.original, self.replacement, self.target, self.hashes = original, replacement, target, hashes
        self.polys = [residual(row) for row in replacement["rows"]]
        self.target_poly = residual(original["rows"][target])
        active = sorted({i for poly in [*self.polys, self.target_poly] for mon in poly for i in mon})
        self.keys = [(i, mon) for d in range(degree + 1)
                     for mon in combinations_with_replacement(active, d)
                     for i in range(len(self.polys))]
        if len(self.keys) > MAX_COLUMNS:
            raise ValueError("candidate pool cap exceeded")
        self.columns = {key: mod(multiply(self.polys[key[0]], key[1]), self.p) for key in self.keys}
        self.target_support = set(mod(self.target_poly, self.p))
        self.pool_terms = sum(map(len, self.columns.values()))


class Search:
    def __init__(self, problem):
        self.problem = problem
        self.basis = {}
        self.remaining = mod(problem.target_poly, problem.p)
        self.weights = {}
        self.offered = set()
        self.input_terms = 0
        self.reductions = 0
        self.work = 0
        self.inversions = 0

    @property
    def solved(self):
        return not self.remaining

    def charge(self, count):
        self.work += count
        if self.work > MAX_WORK:
            raise ValueError("elimination work cap exceeded")

    def reduce(self, vector, weights, sign):
        p = self.problem.p
        while vector:
            pivot = min(vector)
            if pivot not in self.basis:
                break
            factor = vector[pivot]
            col, coeffs = self.basis[pivot]
            self.charge(len(vector) + len(weights) + len(col) + len(coeffs))
            vector = add(vector, col, -factor, p)
            weights = add(weights, coeffs, sign * factor, p)
            self.reductions += 1
        return vector, weights

    def offer(self, key):
        if key not in self.problem.columns or key in self.offered:
            raise ValueError("unknown or repeated candidate")
        if self.solved:
            raise ValueError("already solved")
        self.offered.add(key)
        v = self.problem.columns[key]
        self.input_terms += len(v)
        self.charge(len(v))
        v, w = self.reduce(v, {key: 1}, -1)
        if v:
            pivot = min(v)
            p = self.problem.p
            inv = pow(v[pivot], -1, p)
            self.inversions += 1
            self.charge(len(v) + len(w))
            self.basis[pivot] = (mod({k: inv * x for k, x in v.items()}, p),
                                 mod({k: inv * x for k, x in w.items()}, p))
            self.remaining, self.weights = self.reduce(self.remaining, self.weights, 1)
        return self.solved

    def certificate(self):
        if not self.solved:
            return None
        p = self.problem.p
        diff = self.problem.target_poly
        for (i, mon), k in self.weights.items():
            diff = add(diff, multiply(self.problem.polys[i], mon), -k)
        if any(v % p for v in diff.values()):
            raise AssertionError("search produced nonidentity")
        return {"schema": "zkl-poly-certificate-v1", "original_sha256": self.problem.hashes[0],
                "replacement_sha256": self.problem.hashes[1], "target_index": self.problem.target,
                "degree": max((len(mon) for _, mon in self.weights), default=0),
                "multipliers": [[i, list(mon), str(k)] for (i, mon), k in sorted(self.weights.items())],
                "correction": [[list(mon), str(v // p)] for mon, v in sorted(diff.items())]}

    def counts(self):
        return {"columns": len(self.offered), "input_terms": self.input_terms,
                "reductions": self.reductions, "coefficient_work": self.work,
                "inversions": self.inversions}
