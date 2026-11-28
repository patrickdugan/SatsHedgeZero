"""ZKL-24: bounded windowed degree-zero dependencies on actual ordered matrices."""
import argparse
import hashlib
import json
from pathlib import Path

from audit import digest
from audit_capture import compact, stream_audit
from ideal_certificate import add
from local_binding import bind, lean_row, require_pin
from poly_certificate import residual, verify

MAX_PREFIX = 65_536
MAX_WINDOW = 256
MAX_ROW_TERMS = 32
MAX_SUPPORT = 128
MAX_WEIGHTS = 32
MAX_WORK = 2_000_000
KINDS = ("duplicate", "proportional", "multirow")


def combine(a, b, factor, p):
    out = dict(a)
    for key, value in b.items():
        n = (out.get(key, 0)+factor*value) % p
        if n:
            out[key] = n
        else:
            out.pop(key, None)
    return out


class Window:
    def __init__(self, prefix, width):
        if type(prefix) is not int or not 1 <= prefix <= MAX_PREFIX:
            raise ValueError("prefix cap")
        if type(width) is not int or not 1 <= width <= MAX_WINDOW:
            raise ValueError("window cap")
        self.prefix, self.width = prefix, width
        self.basis, self.seen = {}, {}
        self.candidates = {}
        self.counts = dict.fromkeys((*KINDS, "examined", "zero", "size_skip", "work_skip",
                                    "reductions", "work", "windows"), 0)
        self.current = None

    def propose(self, kind, target, weights):
        self.counts[kind] += 1
        if kind not in self.candidates:
            self.candidates[kind] = (target, dict(weights))

    def visit(self, i, row, p):
        if i >= self.prefix:
            return
        window = i//self.width
        if window != self.current:
            self.current = window
            self.basis.clear()
            self.seen.clear()
            self.counts["windows"] += 1
        if sum(map(len, row)) > MAX_ROW_TERMS:
            self.counts["size_skip"] += 1
            return
        v = {m: c % p for m, c in residual(row).items() if c % p}
        if len(v) > MAX_SUPPORT:
            self.counts["size_skip"] += 1
            return
        self.counts["examined"] += 1
        if not v:
            self.counts["zero"] += 1
            return
        inv = pow(v[min(v)], -1, p)
        normalized = tuple((m, c*inv % p) for m, c in sorted(v.items()))
        row_hash = hashlib.sha256(compact(row)).digest()
        if normalized in self.seen:
            old, old_hash, old_first = self.seen[normalized]
            k = v[min(v)]*pow(old_first, -1, p) % p
            self.propose("duplicate" if old_hash == row_hash else "proportional", i, {old: k})
        else:
            self.seen[normalized] = (i, row_hash, v[min(v)])

        # Representation invariant: v = original_i - sum(weights_j * original_j).
        weights = {}
        while v:
            pivot = min(v)
            if pivot not in self.basis:
                if len(weights) >= MAX_WEIGHTS:
                    self.counts["size_skip"] += 1
                    return
                inv = pow(v[pivot], -1, p)
                representation = {i: inv, **{j: -inv*c % p for j, c in weights.items()}}
                self.basis[pivot] = ({m: c*inv % p for m, c in v.items()}, representation)
                return
            u, w = self.basis[pivot]
            charge = len(v)+len(weights)+len(u)+len(w)
            if self.counts["work"]+charge > MAX_WORK:
                self.counts["work_skip"] += 1
                return
            self.counts["work"] += charge
            self.counts["reductions"] += 1
            factor = v[pivot]
            v = combine(v, u, -factor, p)
            weights = combine(weights, w, factor, p)
            if len(v) > MAX_SUPPORT or len(weights) > MAX_WEIGHTS:
                self.counts["size_skip"] += 1
                return
        if len(weights) >= 2:
            self.propose("multirow", i, weights)


def certificate(a, b, target, retained, weights):
    if target in retained or set(retained) != set(weights):
        raise ValueError("invalid dependency positions")
    p = int(a["modulus"])
    diff = residual(a["rows"][-1])
    for j, row in zip(retained, b["rows"], strict=True):
        diff = add(diff, residual(row), -weights[j])
    if any(c % p for c in diff.values()):
        raise ValueError("candidate is not an integer identity modulo p")
    cert = {"schema": "zkl-poly-certificate-v1", "original_sha256": digest(a),
            "replacement_sha256": digest(b), "target_index": len(b["rows"]),
            "degree": 0, "multipliers": [[i, [], str(weights[j])] for i, j in enumerate(retained)],
            "correction": [[list(m), str(c//p)] for m, c in sorted(diff.items()) if c]}
    verify(a, b, cert, digest(a), digest(b))
    return cert


def indexed_lean(a, b, cert, target, retained):
    refs = ", ".join(f"({i}, {lean_row(row)})" for i, row in zip(retained, b["rows"], strict=True))
    weights = ", ".join(f"⟨({k}), {mon}, {lean_row(b['rows'][i])}⟩"
                        for i, mon, k in cert["multipliers"])
    correction = ", ".join(f"⟨{mon}, ({c})⟩" for mon, c in cert["correction"])
    return f"""import MathCan.ZKLeanLocal
open MathCan.ZKLean MathCan.ZKLean.Poly MathCan.ZKLean.Local

def targetGlobal : Nat := {target}
def targetRow : Row := {lean_row(a["rows"][-1])}
def refs : List (Nat × Row) := [{refs}]
def weights : List Multiplier := [{weights}]
def correction : PPoly := [{correction}]
def contextHeader : Shape := ⟨{a['modulus']}, {a['wires']}, {a['public']}, []⟩

set_option maxRecDepth 4096 in
set_option maxHeartbeats 4000000 in
theorem indexed_context_delete (globalRows : List Row)
    (hs : wellFormed (withRows contextHeader globalRows))
    (hi : targetGlobal < globalRows.length)
    (ht : globalRows[targetGlobal]? = some targetRow)
    (hpos : ∀ q ∈ refs, q.1 ≠ targetGlobal ∧ globalRows[q.1]? = some q.2)
    (x : List Nat) :
    accepts (withRows contextHeader globalRows) x ↔
      accepts (withRows contextHeader (globalRows.eraseIdx targetGlobal)) x := by
  exact checked_indexed_poly_delete (withRows contextHeader globalRows) targetGlobal
    targetRow refs weights correction hs hi ht hpos (by decide)\n    (by change polyCheck contextHeader.modulus targetRow weights correction = true; decide) x

#print axioms indexed_context_delete
"""


def discover(path, pin, prefix=MAX_PREFIX, width=MAX_WINDOW):
    state = Window(prefix, width)
    full = stream_audit(path, visit=state.visit)
    require_pin(full["canonical_shape_sha256"], pin)
    bundles = []
    for kind in KINDS:
        if kind not in state.candidates:
            continue
        target, weights = state.candidates[kind]
        retained = sorted(weights)
        bound, a, b = bind(path, pin, target, retained)
        cert = certificate(a, b, target, retained, weights)
        source = indexed_lean(a, b, cert, target, retained)
        receipt = {"schema": "zkl-window-candidate-v1", "kind": kind,
                   "original_full_sha256": pin,
                   "replacement_full_sha256": bound["deletion_shape_sha256"],
                   "target_global_index": target, "retained_global_indices": retained,
                   "certificate": cert, "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                   "exact_identity_checked": True, "lean_replayed": False,
                   "full_matrix_context_kernel_bound": False, "production_accepted": False}
        bundles.append((receipt, source))
    summary = {"schema": "zkl-window-search-v1", "original_full_sha256": pin,
               "search_prefix": min(prefix, full["constraints"]), "window": width,
               "counts": state.counts, "candidate_kinds": [q[0]["kind"] for q in bundles],
               "production_accepted": False}
    return summary, bundles


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stream", type=Path)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--prefix", type=int, default=MAX_PREFIX)
    parser.add_argument("--window", type=int, default=MAX_WINDOW)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary, bundles = discover(args.stream, args.expected_original, args.prefix, args.window)
    args.out.mkdir(parents=True, exist_ok=False)
    for receipt, source in bundles:
        kind = receipt["kind"]
        (args.out / f"{kind}.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n",
                                               encoding="utf-8")
        (args.out / f"{kind}.lean").write_text(source, encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n",
                                          encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
