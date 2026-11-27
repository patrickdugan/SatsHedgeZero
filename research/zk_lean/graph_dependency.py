"""ZKL-25: bounded graph-neighborhood polynomial search on captured Nova rows."""
import argparse
import bisect
import hashlib
import itertools
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace

from audit import canonical, digest
from audit_capture import BN254_FQ, BN254_FR, stream_audit
from local_binding import bind, require_pin
from neighborhood_search import LazyColumns, Search, mod
from poly_certificate import residual, verify
from window_dependency import indexed_lean

MAX_PREFIX = 65_536
MAX_POOL_TERMS = 350_000
MAX_POLY_TERMS = 350_000
MAX_ROW_TERMS = 32
MAX_ROW_SUPPORT = 64
MAX_POSTING = 128
MAX_TARGETS = 128
MAX_NEIGHBORS = 12
MAX_WIRES = 10
MAX_WORK = 50_000
ARMS = ("nearby", "graph")


class WorkCap(Exception):
    pass


class BoundedSearch(Search):
    def charge(self, count):
        self.work += count
        if self.work > MAX_WORK:
            raise WorkCap


class Pool:
    """Retain bounded canonical rows; index only nonconstant monomials and wires."""

    def __init__(self, prefix):
        if type(prefix) is not int or not 1 <= prefix <= MAX_PREFIX:
            raise ValueError("prefix cap")
        self.prefix = prefix
        self.rows = {}
        self.polys = {}
        self.wires = {}
        self.monomials = defaultdict(list)
        self.postings = defaultdict(list)
        self.counts = Counter()
        self.indices = []

    def visit(self, i, row, p):
        if i >= self.prefix:
            return
        self.counts["prefix_rows"] += 1
        size = sum(map(len, row))
        if size > MAX_ROW_TERMS:
            self.counts["size_skip"] += 1
            return
        poly = mod(residual(row), p)
        if not poly:
            self.counts["zero_skip"] += 1
            return
        if len(poly) > MAX_ROW_SUPPORT:
            self.counts["size_skip"] += 1
            return
        if (self.counts["stored_terms"]+size > MAX_POOL_TERMS
                or self.counts["stored_poly_terms"]+len(poly) > MAX_POLY_TERMS):
            self.counts["pool_skip"] += 1
            return
        wires = frozenset(w for mon in poly for w in mon)
        self.rows[i] = row
        self.polys[i] = poly
        self.wires[i] = wires
        self.indices.append(i)
        self.counts["stored_terms"] += size
        self.counts["stored_poly_terms"] += len(poly)
        self.counts["eligible"] += 1
        for mon in sorted(poly):
            if mon:
                self.insert(self.monomials, mon, i)
        for w in sorted(wires):
            self.insert(self.postings, w, i)

    @staticmethod
    def insert(index, key, i):
        # A saturated posting is unavailable to the search, rather than
        # silently choosing an arbitrary early subset of a high-degree hub.
        posting = index[key]
        if posting is not None:
            if len(posting) == MAX_POSTING:
                index[key] = None
            else:
                posting.append(i)

    def targets(self, count, seed):
        if type(count) is not int or not 2 <= count <= MAX_TARGETS:
            raise ValueError("target cap")
        buckets = [[], []]
        for i in self.indices:
            if len(self.wires[i]) <= MAX_WIRES:
                buckets[int(any(len(m) == 2 for m in self.polys[i]))].append(i)
        rng = random.Random(seed)
        targets = []
        for k, bucket in enumerate(buckets):
            take = min(len(bucket), count//2+(k < count % 2))
            targets.extend(rng.sample(bucket, take))
        return sorted(targets)

    def nearby(self, target):
        i = bisect.bisect_left(self.indices, target)
        lo, hi = max(0, i-MAX_NEIGHBORS), min(len(self.indices), i+MAX_NEIGHBORS+1)
        order = sorted((j for j in self.indices[lo:hi] if j != target),
                       key=lambda j: (abs(j-target), j))
        return sorted(order[:MAX_NEIGHBORS])

    def linked(self, sources, exclude):
        scores = Counter()
        for i in sources:
            for mon in self.polys[i]:
                if mon:
                    for j in self.monomials.get(mon) or ():
                        if j not in exclude:
                            scores[j] += 4
            for w in self.wires[i]:
                for j in self.postings.get(w) or ():
                    if j not in exclude:
                        scores[j] += 1
        return scores

    def graph(self, target):
        first = self.linked([target], {target})
        order = sorted(first, key=lambda j: (-first[j], abs(j-target), j))
        chosen = order[:8]
        second = self.linked(chosen[:4], {target, *chosen})
        rest = set(order[8:]) | set(second)
        order2 = sorted(rest, key=lambda j: (-(4*first[j]+second[j]), abs(j-target), j))
        return sorted(chosen+order2[:MAX_NEIGHBORS-len(chosen)])


def local_shapes(full, pool, target, retained):
    if target in retained or len(retained) != len(set(retained)):
        raise ValueError("invalid retained row list")
    a = canonical({"format": "zkl-r1cs-v1", "modulus": full["modulus"],
                   "wires": full["wires"], "public": full["public"],
                   "rows": [*map(pool.rows.__getitem__, retained), pool.rows[target]]})
    return a, dict(a, rows=a["rows"][:-1])


def search_local(full, pool, target, retained):
    a, b = local_shapes(full, pool, target, retained)
    p = int(full["modulus"])
    if p not in (BN254_FR, BN254_FQ):
        raise ValueError("unexpected search field")
    polys = [residual(r) for r in b["rows"]]
    target_poly = residual(a["rows"][-1])
    frequencies = Counter(w for j in retained for w in pool.wires[j])
    target_wires = sorted(pool.wires[target])
    extra = sorted(set(frequencies)-set(target_wires), key=lambda w: (-frequencies[w], w))
    wires = sorted((target_wires+extra)[:MAX_WIRES])
    keys = [(i, m) for d in range(3)
            for m in itertools.combinations_with_replacement(wires, d)
            for i in range(len(polys))]
    if len(keys) > 1024 or len(retained) > MAX_NEIGHBORS:
        raise AssertionError("candidate pool cap")
    problem = SimpleNamespace(p=p, polys=polys, target_poly=target_poly,
                              target=len(polys), hashes=(digest(a), digest(b)),
                              columns=LazyColumns(keys, polys, p))
    state = BoundedSearch(problem)
    target_support = set(mod(target_poly, p))
    # Within a degree tier, prioritize symbolic overlap with the target;
    # the exact verifier, not this proposal score, decides acceptance.
    def rank(key):
        i, mon = key
        support = {tuple(sorted((*m, *mon))) for m in pool.polys[retained[i]]}
        return (-len(support & target_support), len(support), i, mon)

    status = "INCONCLUSIVE"
    try:
        for degree in range(3):
            tier = sorted((k for k in keys if len(k[1]) == degree), key=rank)
            for key in tier:
                if state.solved:
                    break
                state.offer(key)
            if state.solved:
                status = "CERTIFIED"
                break
    except WorkCap:
        status = "WORK_CAP"
    except ValueError as exc:
        if str(exc) != "support cap exceeded":
            raise
        status = "SUPPORT_CAP"
    cert = None
    if status == "CERTIFIED":
        cert = state.certificate()
        if cert is None:
            raise AssertionError("solved state missing certificate")
        verify(a, b, cert, digest(a), digest(b))
    return {"target": target, "retained": retained, "multiplier_wires": wires,
            "status": status, "degree": None if cert is None else cert["degree"],
            "certificate": cert, **state.counts(), "pool_columns": len(keys)}


def campaign(path, pin, prefix=MAX_PREFIX, targets=64, seed=25001):
    pool = Pool(prefix)
    full = stream_audit(path, visit=pool.visit)
    require_pin(full["canonical_shape_sha256"], pin)
    chosen = pool.targets(targets, seed)
    trials = []
    candidates = {}
    for target in chosen:
        for arm in ARMS:
            retained = getattr(pool, arm)(target)
            if not retained:
                trials.append({"target": target, "arm": arm, "status": "EMPTY", "degree": None})
                continue
            rec = search_local(full, pool, target, retained)
            rec["arm"] = arm
            rec["target_kind"] = "quadratic" if any(len(m) == 2 for m in pool.polys[target]) else "linear"
            trials.append(rec)
            if rec["status"] == "CERTIFIED":
                candidates.setdefault(rec["degree"], rec)

    bundles = []
    for degree, rec in sorted(candidates.items()):
        target, retained = rec["target"], rec["retained"]
        bound, a, b = bind(path, pin, target, retained)
        cert = rec["certificate"]
        verify(a, b, cert, digest(a), digest(b))
        source = indexed_lean(a, b, cert, target, retained)
        receipt = {"schema": "zkl-graph-candidate-v1", "arm": rec["arm"], "degree": degree,
                   "target_global_index": target, "retained_global_indices": retained,
                   "original_full_sha256": pin, "replacement_full_sha256": bound["deletion_shape_sha256"],
                   "certificate": cert, "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                   "exact_identity_checked": True, "full_matrix_context_kernel_bound": False,
                   "lean_replayed": False, "production_accepted": False}
        bundles.append((receipt, source))

    stats = {}
    for arm in ARMS:
        rs = [r for r in trials if r["arm"] == arm]
        stats[arm] = {"trials": len(rs), "statuses": dict(Counter(r["status"] for r in rs)),
                      "degrees": dict(Counter(str(r["degree"]) for r in rs if r["status"] == "CERTIFIED")),
                      "offered_columns": sum(r.get("columns", 0) for r in rs),
                      "coefficient_work": sum(r.get("coefficient_work", 0) for r in rs)}
    summary = {"schema": "zkl-graph-search-v1", "original_full_sha256": pin, "seed": seed,
               "pool": dict(pool.counts), "saturated_wire_postings": sum(v is None for v in pool.postings.values()),
               "saturated_monomial_postings": sum(v is None for v in pool.monomials.values()),
               "targets": chosen, "arms": stats, "full_bound_degrees": sorted(candidates),
               "production_accepted": False}
    return summary, trials, bundles


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stream", type=Path)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--prefix", type=int, default=MAX_PREFIX)
    parser.add_argument("--targets", type=int, default=64)
    parser.add_argument("--seed", type=int, default=25001)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary, trials, bundles = campaign(args.stream, args.expected_original, args.prefix, args.targets, args.seed)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "trials.json").write_text(json.dumps(trials, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    for receipt, source in bundles:
        stem = f"degree{receipt['degree']}"
        (args.out / f"{stem}.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n", encoding="utf-8")
        (args.out / f"{stem}.lean").write_text(source, encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
