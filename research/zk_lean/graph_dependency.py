"""ZKL-25/26: bounded degree-tier search in overlapping global-wire neighborhoods.

ZKL-26 adds adaptive overlap neighborhoods, directed producer slices, linear
substitution before polynomial search, motif-based target selection and
explicit local counterexamples. See campaign26().
"""
import argparse
import hashlib
import json
import random
import sys
import time
from array import array
from collections import Counter
from itertools import combinations_with_replacement
from pathlib import Path
from types import SimpleNamespace

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


def main25():
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




# ---------------------------------------------------------------------------
# ZKL-26: expanded algebraic search.
#
# All new arms share MAX_TARGET_WORK coefficient-work units per target (the
# matched budget) and are scored by four separate outcomes:
#   verified_redundancy   exact certificate, independently verified
#   counterexample        exact assignment satisfying every retained local row
#                         and violating the target: no certificate of any
#                         degree exists over that neighborhood
#   exhausted_span        every offered column used, no solution and no
#                         counterexample constructed
#   incomplete            work/CPU/support/degree cap before either result
# None of these establishes global essentiality.
# ---------------------------------------------------------------------------
ARMS26 = ("window", "graph", "adaptive", "directed")
MAX_ROWS26 = 24
MAX_MULT26 = 16
OUTCOMES = ("verified_redundancy", "counterexample", "exhausted_span", "incomplete")


CPU_BUDGET_NS = 40_000_000


class CpuExceeded(Exception):
    pass


class Work:
    """Matched per-target budget: coefficient work (deterministic) and process CPU."""

    def __init__(self, cap=MAX_TARGET_WORK, cpu_ns=CPU_BUDGET_NS):
        self.used, self.cap = 0, cap
        self.deadline = None if cpu_ns is None else time.process_time_ns()+cpu_ns

    def charge(self, n):
        if self.used+n > self.cap:
            raise BudgetExceeded("per-target coefficient-work cap")
        self.used += n
        if self.deadline is not None and time.process_time_ns() > self.deadline:
            raise CpuExceeded("per-target CPU budget")


class DegreeCap(Exception):
    pass


def motif_signature(row, p):
    wires = [w for lc in row for w, _ in lc if w]
    base = min(wires) if wires else 0

    def term(w, c):
        c = int(c)
        tag = "1" if c == 1 else "-1" if c == p-1 else "k"
        return ("one" if w == 0 else w-base, tag)
    return tuple(tuple(term(w, c) for w, c in lc) for lc in row)


class Corpus26(Corpus):
    """Adds first-occurrence producers for every wire seen in the prefix and motifs."""

    def __init__(self, prefix, wires):
        super().__init__(prefix)
        self.first = array("i", [-1])*wires
        self.motif = {}

    def visit(self, i, row, p):
        if i >= self.prefix:
            return
        for lc in row:
            for w, _ in lc:
                if w and self.first[w] < 0:
                    self.first[w] = i
        super().visit(i, row, p)
        if i in self.rows:
            self.motif[i] = motif_signature(row, p)

    def producers(self, j):
        return sorted({self.first[w] for w in self.wires[j]
                       if 0 <= self.first[w] < j and self.first[w] in self.rows})

    def motif_targets(self, count, seed):
        """One representative per motif, most repeated motifs first, then refill."""
        groups = {}
        for i, m in self.motif.items():
            groups.setdefault(m, []).append(i)
        rng = random.Random(seed)
        ordered = sorted(groups.values(), key=lambda g: (-len(g), g[0]))
        for g in ordered:
            rng.shuffle(g)
        picks, depth = [], 0
        while len(picks) < count and depth < 64:
            for g in ordered:
                if len(g) > depth and len(picks) < count:
                    picks.append(g[depth])
            depth += 1
        chosen = set(picks)
        covered = sum(len(g) for g in ordered if chosen.intersection(g))
        return sorted(picks), {"motifs": len(groups),
                               "rows_in_selected_motifs": covered,
                               "top_motif_sizes": [len(g) for g in ordered[:16]]}

    def adaptive(self, target, rows_cap, hops, per_hop):
        chosen, visited = [], {target}
        focus = set(self.wires[target])
        support = self.polys[target].keys()
        frontier = set(focus)
        for _ in range(hops):
            cands = {j for w in frontier for j in (self.postings.get(w) or ()) if j not in visited}
            # Saturated hub wires contribute their producer row only.
            cands |= {self.first[w] for w in frontier if self.postings.get(w, ()) is None
                      and self.first[w] in self.rows and self.first[w] not in visited}
            if not cands:
                break
            ordered = sorted(cands, key=lambda j: (-len(self.polys[j].keys() & support),
                                                    -len(self.wires[j] & focus), abs(j-target), j))
            step = ordered[:min(per_hop, rows_cap-len(chosen))]
            chosen.extend(step)
            visited.update(step)
            frontier = {w for j in step for w in self.wires[j]}-focus
            focus |= frontier
            if len(chosen) >= rows_cap or not frontier:
                break
        return sorted(chosen)

    def directed(self, target, rows_cap=MAX_ROWS26, depth=6):
        """Backward producer slice (definitions of the target's wires), then consumers."""
        chosen, seen = [], {target}
        layer = [target]
        for _ in range(depth):
            nxt = []
            for j in layer:
                for q in self.producers(j):
                    if q not in seen and len(chosen) < rows_cap:
                        seen.add(q)
                        chosen.append(q)
                        nxt.append(q)
            layer = nxt
            if not layer or len(chosen) >= rows_cap:
                break
        if len(chosen) < rows_cap:
            sib = sorted({j for w in self.wires[target] for j in (self.postings.get(w) or ())
                          if j not in seen}, key=lambda j: (abs(j-target), j))
            chosen.extend(sib[:rows_cap-len(chosen)])
        return sorted(chosen)


def evaluate(poly, assign, p):
    total = 0
    for m, c in poly.items():
        v = c
        for w in m:
            v = v*assign[w] % p
        total += v
    return total % p


def check_counterexample(rows, target_row, assign, p):
    """Independent exact check: every retained residual is 0 mod p, the target's is not."""
    if assign.get(0) != 1 or any(not 0 <= v < p for v in assign.values()):
        return False
    for r in rows:
        if evaluate(residual(r), assign, p):
            return False
    return evaluate(residual(target_row), assign, p) != 0


def counterexample(rows, target_row, p, first, rng, public):
    """Construct w (w0 = 1) satisfying every row in `rows` and violating the target.

    Rows are processed in increasing global order. Each solves one wire that
    occurs linearly in it and in no earlier processed row; other new wires are
    random. The result is checked exactly afterwards; failure returns None."""
    assign = {0: 1}
    used = set()
    for j, r in sorted(rows.items()):
        poly = mod(residual(r), p)
        wires = sorted({w for m in poly for w in m})
        cands = [w for w in wires if w not in assign and w not in used and w not in public
                 and all(m.count(w) <= 1 for m in poly)]
        cands.sort(key=lambda w: (first[w] != j, -w))
        v = cands[0] if cands else None
        for w in wires:
            if w not in assign and w != v:
                assign[w] = rng.randrange(p)
        if v is not None:
            alpha = beta = 0
            for m, c in poly.items():
                val = c
                for w in m:
                    if w != v:
                        val = val*assign[w] % p
                if v in m:
                    alpha = (alpha+val) % p
                else:
                    beta = (beta+val) % p
            if alpha == 0:
                return None
            assign[v] = (-beta)*pow(alpha, -1, p) % p
        used.update(wires)
    for m in mod(residual(target_row), p):
        for w in m:
            if w not in assign:
                assign[w] = rng.randrange(p)
    if not check_counterexample(list(rows.values()), target_row, assign, p):
        return None
    return assign


def times(poly, mon):
    return {tuple(sorted((*k, *mon))): v for k, v in poly.items()}


def combo_times(combo, mon):
    return {(i, tuple(sorted((*m, *mon)))): v for (i, m), v in combo.items()}


def add_mod(a, b, factor, p, work):
    work.charge(len(a)+len(b))
    out = dict(a)
    for k, v in b.items():
        x = (out.get(k, 0)+factor*v) % p
        if x:
            out[k] = x
        else:
            out.pop(k, None)
    return out


class LinearBasis:
    """Reduced row echelon basis of the local linear rows, pivot = newest wire."""

    def __init__(self, p, work):
        self.p, self.work = p, work
        self.basis = {}  # pivot wire -> (poly with pivot coefficient 1, combo)
        self.inconsistent = False

    def reduce(self, poly, combo=None):
        """Return (poly', extra) with poly = poly' + sum(extra * rows) mod p."""
        combo = {} if combo is None else combo
        while True:
            hits = [w for m in poly for w in m if w in self.basis]
            if not hits:
                return poly, combo
            v = max(hits)
            m = min(m for m in poly if v in m)
            c = poly[m]
            rest = list(m)
            rest.remove(v)
            cof = tuple(rest)
            bpoly, bcombo = self.basis[v]
            poly = add_mod(poly, times(bpoly, cof), -c, self.p, self.work)
            combo = add_mod(combo, combo_times(bcombo, cof), c, self.p, self.work)

    def add(self, poly, row):
        poly, extra = self.reduce(poly)
        combo = add_mod({(row, ()): 1}, extra, -1, self.p, self.work)
        if not poly:
            return
        wires = [w for m in poly for w in m]
        if not wires:
            self.inconsistent = True
            return
        v = max(wires)
        inv = pow(poly[(v,)], -1, self.p)
        poly = {k: x*inv % self.p for k, x in poly.items()}
        combo = {k: x*inv % self.p for k, x in combo.items()}
        for u, (bp, bc) in list(self.basis.items()):
            if (v,) in bp:
                c = bp[(v,)]
                self.basis[u] = (add_mod(bp, poly, -c, self.p, self.work),
                                 add_mod(bc, combo, -c, self.p, self.work))
        self.basis[v] = (poly, combo)


class SharedSearch(Search):
    def __init__(self, problem, work):
        super().__init__(problem)
        self.shared = work

    def charge(self, count):
        self.shared.charge(count)
        super().charge(count)


def assemble(a, b, weights):
    """Exact certificate over the original local rows; the independent verifier decides."""
    p = int(a["modulus"])
    diff = dict(residual(a["rows"][-1]))
    mults = []
    for (i, mon), k in sorted(weights.items()):
        k %= p
        if not k:
            continue
        if len(mon) > 2:
            raise DegreeCap("multiplier degree above checker cap")
        mults.append([i, list(mon), str(k)])
        for m, v in times(residual(b["rows"][i]), mon).items():
            diff[m] = diff.get(m, 0)-k*v
    diff = {m: v for m, v in diff.items() if v}
    if any(v % p for v in diff.values()):
        raise AssertionError("substitution produced nonidentity")
    cert = {"schema": "zkl-poly-certificate-v1", "original_sha256": digest(a),
            "replacement_sha256": digest(b), "target_index": len(a["rows"])-1,
            "degree": max((len(m) for _, m, _ in mults), default=0),
            "multipliers": mults,
            "correction": [[list(m), str(v//p)] for m, v in sorted(diff.items())]}
    verify(a, b, cert, cert["original_sha256"], cert["replacement_sha256"])
    return cert


def substitution_search(full, corpus, target, retained, work):
    """Linear substitution (sparse elimination of pivot wires), then degree-0/1
    multipliers over the reduced quadratic rows; translated back to original rows."""
    p = int(full["modulus"])
    a, b = local_shapes26(full, corpus, target, retained)
    polys = [mod(residual(r), p) for r in b["rows"]]
    lin = LinearBasis(p, work)
    quad = []
    for i, poly in enumerate(polys):
        if max(map(len, poly), default=0) <= 1:
            lin.add(poly, i)
        else:
            quad.append(i)
    t_red, weights = lin.reduce(mod(residual(a["rows"][-1]), p))
    info = {"linear_rows": len(polys)-len(quad), "pivots": len(lin.basis),
            "quadratic_rows": len(quad), "reduced_target_terms": len(t_red)}
    if lin.inconsistent:
        info["locally_inconsistent"] = True
        return None, info
    if t_red:
        reduced = []
        for i in quad:
            q, extra = lin.reduce(polys[i])
            reduced.append((q, add_mod({(i, ()): 1}, extra, -1, p, work)))
        focus = {w for m in t_red for w in m}
        freq = Counter(w for q, _ in reduced for m in q for w in m)
        pool = sorted(sorted(set(freq) | focus, key=lambda w: (w not in focus, -freq[w], w))[:MAX_MULT26])
        keys = [(k, mon) for d in range(2) for mon in combinations_with_replacement(pool, d)
                for k in range(len(reduced))]
        problem = SimpleNamespace(p=p, target_poly=t_red, keys=keys,
                                  columns=LazyColumns(keys, [q for q, _ in reduced], p))
        state = SharedSearch(problem, work)
        for key in keys:
            state.offer(key)
            if state.solved:
                break
        info.update(columns=len(state.offered), multiplier_wires=len(pool))
        if not state.solved:
            info["span_exhausted"] = True
            return None, info
        for (k, mon), coef in state.weights.items():
            weights = add_mod(weights, combo_times(reduced[k][1], mon), coef, p, work)
    return assemble(a, b, weights), info


def local_shapes26(full, corpus, target, retained):
    if target in retained or retained != sorted(set(retained)) or len(retained) > MAX_ROWS26:
        raise ValueError("invalid local positions")
    if int(full["modulus"]) not in (BN254_FR, BN254_FQ):
        raise ValueError("unexpected field")
    a = {"format": "zkl-r1cs-v1", "modulus": full["modulus"], "wires": full["wires"],
         "public": full["public"], "rows": [*[corpus.rows[j] for j in retained], corpus.rows[target]]}
    return a, dict(a, rows=a["rows"][:-1])


class LocalProblem26(LocalProblem):
    """The reviewed restricted adapter with the ZKL-26 caps (24 rows, 16 wires)."""

    def __init__(self, a, b, multiplier_wires):
        self.p = int(a["modulus"])
        if self.p not in (BN254_FR, BN254_FQ) or len(b["rows"]) > MAX_ROWS26:
            raise ValueError("local shape cap")
        if (len(multiplier_wires) > MAX_MULT26 or sorted(set(multiplier_wires)) != multiplier_wires
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


def tier_search(full, corpus, target, retained, work, mult_cap):
    a, b = local_shapes26(full, corpus, target, retained)
    focus = corpus.wires[target]
    freq = Counter(w for j in retained for w in corpus.wires[j])
    pool = sorted(sorted(set(freq) | set(focus), key=lambda w: (w not in focus, -freq[w], w))[:mult_cap])
    problem = LocalProblem26(a, b, pool)
    state = SharedSearch(problem, work)
    for d in range(3):
        for key in problem.keys:
            if len(key[1]) == d:
                state.offer(key)
                if state.solved:
                    cert = state.certificate()
                    verify(a, b, cert, *problem.hashes)
                    return cert, {"columns": len(state.offered), "multiplier_wires": len(pool)}
    return None, {"columns": len(state.offered), "multiplier_wires": len(pool), "span_exhausted": True}


def attempt26(full, corpus, target, arm, width, rng):
    start = time.process_time_ns()
    work = Work()
    info, cert, rounds, retained, cap = {}, None, [], [], None
    try:
        if arm == "directed":
            retained = corpus.directed(target)
            rounds.append(len(retained))
            cert, info = substitution_search(full, corpus, target, retained, work)
        else:
            if arm in ("window", "graph"):
                plan = [(corpus.neighborhood(target, arm, width), MAX_MULTIPLIER_WIRES)]
            elif arm == "adaptive":
                plan = [(corpus.adaptive(target, MAX_ROWS, 4, 3), MAX_MULTIPLIER_WIRES),
                        (corpus.adaptive(target, 18, 6, 4), 13),
                        (corpus.adaptive(target, MAX_ROWS26, 8, 6), MAX_MULT26)]
            else:
                raise ValueError("unknown arm")
            for nb, mult in plan:
                if nb == retained and rounds:
                    continue
                retained = nb
                rounds.append(len(retained))
                cert, info = tier_search(full, corpus, target, retained, work, mult)
                if cert is not None:
                    break
    except BudgetExceeded:
        cap = "work"
    except CpuExceeded:
        cap = "cpu"
    except DegreeCap:
        cap = "degree"
    except ValueError as exc:
        if str(exc) not in ("support cap exceeded", "elimination work cap exceeded"):
            raise
        cap = "support"
    ce = None
    if cert is None:
        ce = counterexample({j: corpus.rows[j] for j in retained}, corpus.rows[target],
                            int(full["modulus"]), corpus.first, rng, set(full["public"]))
    if cert is not None:
        outcome = "verified_redundancy"
    elif ce is not None:
        outcome = "counterexample"
    elif cap is None and info.get("span_exhausted"):
        outcome = "exhausted_span"
    else:
        outcome = "incomplete"
    return {"target_global_index": target, "retained_global_indices": retained, "rounds": rounds,
            "outcome": outcome, "cap": cap, "work": work.used, "info": info,
            "certificate": cert, "exact_identity_checked": cert is not None,
            "counterexample_wires": len(ce) if ce else 0,
            "counterexample_sha256": hashlib.sha256(json.dumps(sorted(ce.items())).encode()).hexdigest()
            if ce else None,
            "cpu_ns": time.process_time_ns()-start, "production_accepted": False}


def stratified(corpus, count, seed):
    linear = [i for i, poly in corpus.polys.items() if max(map(len, poly)) <= 1]
    quadratic = [i for i, poly in corpus.polys.items() if max(map(len, poly)) == 2]
    rng = random.Random(seed)
    a = rng.sample(linear, min(len(linear), count//2))
    b = rng.sample(quadratic, min(len(quadratic), count-len(a)))
    left = sorted(set(corpus.rows)-set(a)-set(b))
    return sorted(a+b+rng.sample(left, min(len(left), count-len(a)-len(b))))


def campaign26(path, pin, prefix=PREFIX, target_count=512, width=256, seed=260026, arms=ARMS26,
               targets=None):
    with path.open("rb") as f:
        header = json.loads(f.readline())
    corpus = Corpus26(prefix, header["wires"])
    full = stream_audit(path, visit=corpus.visit)
    require_pin(full["canonical_shape_sha256"], pin)
    motif_stats = None
    if targets is not None:
        if any(type(i) is not int or i not in corpus.rows for i in targets):
            raise ValueError("invalid explicit target set")
        pools = {"explicit": sorted(set(targets))}
    else:
        motif, motif_stats = corpus.motif_targets(target_count, seed+1)
        pools = {"stratified": stratified(corpus, target_count, seed), "motif": motif}
    tasks = {}
    for ts in pools.values():
        for target in ts:
            if target in tasks:
                continue
            rec = {"target": target, "degree": max(map(len, corpus.polys[target])), "arms": {}}
            order = list(arms) if target % 2 == 0 else list(reversed(arms))
            for arm in order:
                rng = random.Random(seed*1_000_003+target)
                rec["arms"][arm] = attempt26(full, corpus, target, arm, width, rng)
            tasks[target] = rec
    bundles = []
    for arm in arms:
        for d in range(3):
            ok = [t["arms"][arm] for t in tasks.values() if t["arms"][arm]["exact_identity_checked"]
                  and t["arms"][arm]["certificate"]["degree"] == d]
            if not ok:
                continue
            rec = ok[0]
            target, retained = rec["target_global_index"], rec["retained_global_indices"]
            bound, a, b = bind(path, pin, target, retained)
            verify(a, b, rec["certificate"], digest(a), digest(b))
            source = indexed_lean(a, b, rec["certificate"], target, retained)
            bundles.append(({"schema": "zkl26-candidate-v1", "arm": arm, "degree": d,
                             "original_full_sha256": pin,
                             "replacement_full_sha256": bound["deletion_shape_sha256"],
                             "target_global_index": target, "retained_global_indices": retained,
                             "certificate": rec["certificate"], "successful_targets": len(ok),
                             "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                             "exact_identity_checked": True, "lean_replayed": False,
                             "production_accepted": False}, source))
    return {"schema": "zkl26-expanded-search-v1", "original_full_sha256": pin,
            "search_prefix": min(prefix, full["constraints"]), "corpus_counts": dict(corpus.counts),
            "stored_terms": corpus.stored_terms, "pools": pools, "motif_stats": motif_stats,
            "work_cap_per_target": MAX_TARGET_WORK, "tasks": list(tasks.values()),
            "production_accepted": False}, bundles


def summarize26(result):
    out = {}
    idx = {t["target"]: t for t in result["tasks"]}
    arms = list(result["tasks"][0]["arms"]) if result["tasks"] else []
    for pool, ts in result["pools"].items():
        for arm in sorted(arms):
            recs = [idx[t]["arms"][arm] for t in ts]
            out[f"{pool}/{arm}"] = {
                "targets": len(recs), **{o: sum(r["outcome"] == o for r in recs) for o in OUTCOMES},
                "verified_by_degree": {str(d): sum(r["exact_identity_checked"]
                                                   and r["certificate"]["degree"] == d for r in recs)
                                       for d in range(3)},
                "caps": dict(Counter(str(r["cap"]) for r in recs)),
                "mean_rows": round(sum(len(r["retained_global_indices"]) for r in recs)/max(1, len(recs)), 2),
                "work": sum(r["work"] for r in recs), "cpu_ns": sum(r["cpu_ns"] for r in recs)}
    return {k: v for k, v in result.items() if k not in ("tasks", "pools")} | \
        {"pool_sizes": {k: len(v) for k, v in result["pools"].items()}, "summary": out}


def main26(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--zkl26", action="store_true")
    parser.add_argument("stream", type=Path)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--prefix", type=int, default=PREFIX)
    parser.add_argument("--target-count", type=int, default=512)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    result, bundles = campaign26(args.stream, args.expected_original, args.prefix, args.target_count)
    args.out.mkdir(parents=True, exist_ok=False)
    for receipt, source in bundles:
        stem = f"{receipt['arm']}_degree{receipt['degree']}"
        (args.out / f"{stem}.lean").write_text(source, encoding="utf-8")
        (args.out / f"{stem}.json").write_text(json.dumps(receipt, sort_keys=True)+"\n", encoding="utf-8")
    (args.out / "campaign.json").write_text(json.dumps(result, sort_keys=True)+"\n", encoding="utf-8")
    summary = summarize26(result)
    (args.out / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=1)+"\n",
                                           encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))


def main():
    if "--zkl26" in sys.argv[1:]:
        main26(sys.argv[1:])
    else:
        main25()


if __name__ == "__main__":
    main()
