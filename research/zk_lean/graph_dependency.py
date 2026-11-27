"""ZKL-25: bounded degree-tier search in overlapping global-wire neighborhoods."""
import argparse
import hashlib
import json
import random
import time
from collections import Counter
from itertools import combinations_with_replacement
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ, stream_audit
from local_binding import bind, require_pin
from neighborhood_search import LazyColumns, Search, mod, residual
from poly_certificate import verify
from window_dependency import indexed_lean

PREFIX = 65_536
MAX_ROW_TERMS = 32
MAX_EXPANSION = 128
MAX_STORED_TERMS = 400_000
MAX_POSTING = 64
MAX_ROWS = 12
MAX_MULTIPLIER_WIRES = 10
MAX_TARGET_WORK = 100_000
MAX_TARGETS = 128
ARMS = ("window", "graph")


class BudgetExceeded(Exception):
    pass


class Corpus:
    """A bounded prefix of validated rows, with capped nonconstant-wire postings."""

    def __init__(self, prefix):
        if type(prefix) is not int or not 1 <= prefix <= PREFIX:
            raise ValueError("prefix cap")
        self.prefix = prefix
        self.rows = {}
        self.polys = {}
        self.wires = {}
        self.postings = {}
        self.counts = Counter()
        self.stored_terms = 0

    def visit(self, i, row, p):
        if i >= self.prefix:
            return
        n = sum(map(len, row))
        if n > MAX_ROW_TERMS or len(row[0])*len(row[1])+len(row[2]) > MAX_EXPANSION:
            self.counts["size_skip"] += 1
            return
        if self.stored_terms+n > MAX_STORED_TERMS:
            self.counts["storage_skip"] += 1
            return
        poly = mod(residual(row), p)
        if not poly:
            self.counts["zero"] += 1
            return
        wires = frozenset(w for mon in poly for w in mon)
        self.rows[i] = row
        self.polys[i] = poly
        self.wires[i] = wires
        self.stored_terms += n
        self.counts["eligible"] += 1
        for wire in wires:
            if wire not in self.postings:
                self.postings[wire] = []
            posting = self.postings[wire]
            if posting is None:
                continue
            if len(posting) == MAX_POSTING:
                self.postings[wire] = None
                self.counts["saturated_wires"] += 1
            else:
                posting.append(i)

    def targets(self, count, seed):
        if type(count) is not int or not 1 <= count <= MAX_TARGETS:
            raise ValueError("target cap")
        # Stratify on target residual degree. Sampling is independent of solver outcome.
        linear = [i for i, poly in self.polys.items() if max(map(len, poly)) <= 1]
        quadratic = [i for i, poly in self.polys.items() if max(map(len, poly)) == 2]
        rng = random.Random(seed)
        a = rng.sample(linear, min(len(linear), count//2))
        b = rng.sample(quadratic, min(len(quadratic), count-len(a)))
        left = sorted(set(self.rows)-set(a)-set(b))
        extra = rng.sample(left, min(len(left), count-len(a)-len(b)))
        return sorted(a+b+extra)

    def neighborhood(self, target, arm, width):
        if arm == "window":
            lo = target//width*width
            candidates = [j for j in range(lo, lo+width) if j in self.rows and j != target]
            focus = self.wires[target]
            support = self.polys[target]
            candidates.sort(key=lambda j: (-len(self.polys[j].keys() & support.keys()),
                                           -len(self.wires[j] & focus), abs(j-target), j))
            return sorted(candidates[:MAX_ROWS])
        if arm != "graph":
            raise ValueError("unknown neighborhood arm")
        # Up to four overlap hops. Saturated wires are deliberately ignored.
        # Only selected rows expand the next frontier, bounding fan-out.
        chosen = []
        visited = {target}
        focus = set(self.wires[target])
        target_support = self.polys[target].keys()
        frontier = set(focus)
        for _ in range(4):
            candidates = {j for wire in frontier for j in (self.postings.get(wire) or ())
                          if j not in visited}
            if not candidates:
                break
            ordered = sorted(candidates, key=lambda j: (
                -len(self.polys[j].keys() & target_support),
                -len(self.wires[j] & focus), abs(j-target), j))
            # Limit each hop to three additions so a high-fan-out first hop
            # cannot consume all the slots before transitive rows are seen.
            step = ordered[:min(3, MAX_ROWS-len(chosen))]
            chosen.extend(step)
            visited.update(step)
            frontier = {w for j in step for w in self.wires[j]}-focus
            focus.update(frontier)
            if len(chosen) == MAX_ROWS or not frontier:
                break
        return sorted(chosen)


def local_shapes(full, corpus, target, retained):
    if target in retained or retained != sorted(set(retained)) or len(retained) > MAX_ROWS:
        raise ValueError("invalid local positions")
    if int(full["modulus"]) not in (BN254_FR, BN254_FQ):
        raise ValueError("unexpected field")
    a = {"format": "zkl-r1cs-v1", "modulus": full["modulus"], "wires": full["wires"],
         "public": full["public"], "rows": [*[corpus.rows[j] for j in retained], corpus.rows[target]]}
    return a, dict(a, rows=a["rows"][:-1])


class LocalProblem:
    """Restricted proposal adapter retaining global IDs in both reviewed fields.

    Unlike the synthetic Problem constructor, the total wire count can be
    large. Only the selected local rows and bounded multiplier set expand.
    Independent verify() remains authoritative.
    """

    def __init__(self, a, b, multiplier_wires):
        self.p = int(a["modulus"])
        if self.p not in (BN254_FR, BN254_FQ) or len(b["rows"]) > MAX_ROWS:
            raise ValueError("local shape cap")
        if (len(multiplier_wires) > MAX_MULTIPLIER_WIRES
                or sorted(set(multiplier_wires)) != multiplier_wires
                or any(not 0 < w < a["wires"] for w in multiplier_wires)):
            raise ValueError("multiplier wire cap")
        self.original, self.replacement = a, b
        self.target = len(b["rows"])
        self.hashes = digest(a), digest(b)
        self.polys = [residual(row) for row in b["rows"]]
        self.target_poly = residual(a["rows"][-1])
        self.keys = [(i, mon) for d in range(3)
                     for mon in combinations_with_replacement(multiplier_wires, d)
                     for i in range(len(self.polys))]
        self.columns = LazyColumns(self.keys, self.polys, self.p)


class BoundedSearch(Search):
    def charge(self, count):
        if self.work+count > MAX_TARGET_WORK:
            raise BudgetExceeded("per-target coefficient-work cap")
        super().charge(count)


def attempt(full, corpus, target, retained):
    start = time.process_time_ns()
    a, b = local_shapes(full, corpus, target, retained)
    focus = corpus.wires[target]
    freq = Counter(w for j in retained for w in corpus.wires[j])
    candidates = sorted(set(freq)|set(focus), key=lambda w: (w not in focus, -freq[w], w))
    pool = sorted(candidates[:MAX_MULTIPLIER_WIRES])
    problem = LocalProblem(a, b, pool)
    state = BoundedSearch(problem)
    complete_through = -1
    cap = None
    degree_counts = {}
    for d in range(3):
        before = state.counts()
        try:
            for key in problem.keys:
                if len(key[1]) != d:
                    continue
                state.offer(key)
                if state.solved:
                    break
        except BudgetExceeded:
            cap = "work"
        except ValueError as exc:
            if str(exc) != "support cap exceeded":
                raise
            cap = "support"
        after = state.counts()
        degree_counts[str(d)] = {k: after[k]-before[k] for k in before}
        if cap is not None or state.solved:
            break
        complete_through = d
    cert = None
    if state.solved and cap is None:
        cert = state.certificate()
        verify(a, b, cert, *problem.hashes)
        if cert["degree"] != d:
            raise AssertionError("lower-degree span should have solved earlier")
    return {
        "target_global_index": target, "retained_global_indices": retained,
        "multiplier_wires": pool, "available_multiplier_wires": len(candidates),
        "pool_columns": len(problem.keys), "complete_through": complete_through,
        "cap": cap, "degree_counts": degree_counts, **state.counts(),
        "prepared_columns": len(problem.columns.cache),
        "cpu_ns": time.process_time_ns()-start, "certificate": cert,
        "exact_identity_checked": cert is not None, "production_accepted": False,
    }


def campaign(path, pin, prefix=PREFIX, target_count=64, width=256, seed=250025, targets=None):
    if type(width) is not int or not 1 <= width <= 256:
        raise ValueError("window width cap")
    corpus = Corpus(prefix)
    full = stream_audit(path, visit=corpus.visit)
    require_pin(full["canonical_shape_sha256"], pin)
    if targets is None:
        targets = corpus.targets(target_count, seed)
    elif (len(targets) > MAX_TARGETS or sorted(set(targets)) != targets
          or any(type(i) is not int or i not in corpus.rows for i in targets)):
        raise ValueError("invalid explicit target set")
    tasks = []
    for target in targets:
        arms = {}
        order = list(ARMS)
        if target % 2:
            order.reverse()
        for arm in order:
            retained = corpus.neighborhood(target, arm, width)
            arms[arm] = attempt(full, corpus, target, retained)
        tasks.append({"target": target, "degree": max(map(len, corpus.polys[target])), "arms": arms})
    # Every solved local certificate was independently checked against rows from
    # the authenticated full stream. Rebind only the first success per arm/tier
    # with an additional complete pass computing the exact deletion hash.
    bundles = []
    for arm in ARMS:
        for d in range(3):
            eligible = [t["arms"][arm] for t in tasks if t["arms"][arm]["exact_identity_checked"]
                        and t["arms"][arm]["certificate"]["degree"] == d]
            if not eligible:
                continue
            rec = eligible[0]
            target, retained = rec["target_global_index"], rec["retained_global_indices"]
            bound, a, b = bind(path, pin, target, retained)
            cert = rec["certificate"]
            verify(a, b, cert, digest(a), digest(b))
            source = indexed_lean(a, b, cert, target, retained)
            receipt = {"schema": "zkl-graph-candidate-v1", "arm": arm, "degree": d,
                       "original_full_sha256": pin,
                       "replacement_full_sha256": bound["deletion_shape_sha256"],
                       "target_global_index": target, "retained_global_indices": retained,
                       "certificate": cert, "successful_targets": len(eligible),
                       "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                       "exact_identity_checked": True, "lean_replayed": False,
                       "full_matrix_context_kernel_bound": False, "production_accepted": False}
            bundles.append((receipt, source))
    return {"schema": "zkl-neighborhood-degree-v1", "original_full_sha256": pin,
            "search_prefix": min(prefix, full["constraints"]), "window": width,
            "target_seed": seed, "targets": targets, "corpus_counts": dict(corpus.counts),
            "stored_terms": corpus.stored_terms, "tasks": tasks, "production_accepted": False}, bundles


def summarize(result):
    out = []
    for arm in ARMS:
        recs = [t["arms"][arm] for t in result["tasks"]]
        out.append({"arm": arm, "targets": len(recs),
                    "solved_by_degree": {str(d): sum(q["exact_identity_checked"]
                                                   and q["certificate"]["degree"] == d for q in recs)
                                         for d in range(3)},
                    "work_capped": sum(q["cap"] == "work" for q in recs),
                    "support_capped": sum(q["cap"] == "support" for q in recs),
                    "fully_exhausted": sum(q["complete_through"] == 2 for q in recs),
                    "columns": sum(q["columns"] for q in recs),
                    "work": sum(q["coefficient_work"] for q in recs),
                    "cpu_ns": sum(q["cpu_ns"] for q in recs)})
    return {k: v for k, v in result.items() if k != "tasks"} | {"summary": out}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stream", type=Path)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--prefix", type=int, default=PREFIX)
    parser.add_argument("--target-count", type=int, default=64)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result, bundles = campaign(args.stream, args.expected_original, args.prefix, args.target_count)
    args.out.mkdir(parents=True, exist_ok=False)
    for receipt, source in bundles:
        stem = f"{receipt['arm']}_degree{receipt['degree']}"
        (args.out / f"{stem}.lean").write_text(source, encoding="utf-8")
        (args.out / f"{stem}.json").write_text(json.dumps(receipt, sort_keys=True)+"\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
    (args.out / "campaign.json").write_text(json.dumps(result, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(summarize(result), sort_keys=True))


if __name__ == "__main__":
    main()
