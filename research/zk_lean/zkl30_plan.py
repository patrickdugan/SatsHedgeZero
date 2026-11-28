"""ZKL-30: deletion plan, exact expected pruned hashes and a composed Lean theorem.

For one pinned matrix: rescan (full_matrix_scan), try the explicit candidate
targets with every ZKL-26 arm, and form the deletion set D = C-only dead
outputs ∪ verified polynomial redundancies whose retained rows lie outside D.
It then streams the matrix once more to compute the exact canonical hash,
row count and nonzero counts of the matrix with all of D deleted (the value
the experimental Nova variant's captured shape must reproduce), and emits one
Lean theorem chaining the deletions in descending index order:

  accepts (original rows) x ↔ accepts (rows with D deleted) x

Each step uses MathCan checked_indexed_poly_delete or dead_output_delete.
Row lookups and single-occurrence premises are stated on the intermediate
lists and remain external (established by the scan and this binding pass).
"""
import argparse
import hashlib
import json
import random
from pathlib import Path

from audit import canonical
from audit_capture import compact, stream_audit
from full_matrix_scan import scan
from graph_dependency import ARMS26, Corpus26, PREFIX, attempt26
from local_binding import lean_row, require_pin
from poly_certificate import verify


def deletion_digest(path, pin, deleted):
    """Canonical hash of the matrix with every row in `deleted` removed."""
    deleted = set(deleted)
    rows = {}
    nonzeros = [0, 0, 0]

    def visit(i, row, _p):
        if i in deleted:
            rows[i] = row
            return
        for j in range(3):
            nonzeros[j] += len(row[j])
        enc.append(compact(row))

    enc = []
    full = stream_audit(path, visit=visit)
    require_pin(full["canonical_shape_sha256"], pin)
    shape = canonical({"format": "zkl-r1cs-v1", "modulus": full["modulus"], "wires": full["wires"],
                       "public": full["public"], "rows": []})
    h = hashlib.sha256()
    prefix = compact({"format": shape["format"], "modulus": shape["modulus"], "public": shape["public"]})
    h.update(prefix[:-1] + b',"rows":[')
    h.update(b",".join(enc))
    h.update(b'],"wires":' + compact(full["wires"]) + b"}")
    return {"pruned_sha256": h.hexdigest(), "constraints": len(enc), "canonical_nonzeros": nonzeros,
            "original_constraints": full["constraints"],
            "original_nonzeros": full["canonical_nonzeros"]}, rows, full


def lean_steps(full, steps):
    """steps: list of dicts in application order (descending original index)."""
    header = f"⟨{full['modulus']}, {full['wires']}, {full['public']}, []⟩"
    defs, hyps, proofs = [], [], []
    names = ["g0"]
    for k, st in enumerate(steps, 1):
        prev, cur = names[-1], f"g{k}"
        defs.append(f"def row{k} : Row := {lean_row(st['row'])}")
        if st["kind"] == "poly":
            refs = ", ".join(f"({q}, {lean_row(r)})" for q, r in st["refs"])
            w = ", ".join(f"⟨({c}), {m}, {lean_row(st['refs'][i][1])}⟩" for i, m, c in st["cert"]["multipliers"])
            corr = ", ".join(f"⟨{m}, ({c})⟩" for m, c in st["cert"]["correction"])
            defs += [f"def refs{k} : List (Nat × Row) := [{refs}]",
                     f"def weights{k} : List Multiplier := [{w}]",
                     f"def correction{k} : PPoly := [{corr}]"]
            hyps += [f"(hi{k} : {st['index']} < {prev}.length)",
                     f"(ht{k} : {prev}[{st['index']}]? = some row{k})",
                     f"(hpos{k} : ∀ q ∈ refs{k}, q.1 ≠ {st['index']} ∧ {prev}[q.1]? = some q.2)"]
            proofs.append(
                f"  have e{k} := checked_indexed_poly_delete (withRows H {prev}) {st['index']} row{k} refs{k}\n"
                f"    weights{k} correction{k} hs{k-1} hi{k} ht{k} hpos{k} (by decide)\n"
                f"    (by change polyCheck H.modulus row{k} weights{k} correction{k} = true; decide) x")
        else:
            defs.append(f"def dead{k} : Nat := {st['wire']}")
            hyps += [f"(ht{k} : {prev}[{st['index']}]? = some row{k})",
                     f"(hoth{k} : ∀ r ∈ {prev}.eraseIdx {st['index']}, ∀ t ∈ r.a ++ r.b ++ r.c, t.wire ≠ dead{k})"]
            proofs.append(
                f"  have e{k} : accepts (withRows H {prev}) x ↔ accepts (withRows H ({prev}.eraseIdx {st['index']})) x := by\n"
                f"    apply dead_output_delete (withRows H {prev}) {st['index']} dead{k} {st['cv']} {st['cinv']} row{k} hs{k-1} _ x\n"
                f"    unfold deadOutputCheck\n"
                f"    apply decide_eq_true\n"
                f"    refine ⟨by decide, ?_, ?_, ht{k}, by decide, by decide, by decide, ?_, hoth{k}⟩\n"
                f"    · change dead{k} ∉ H.publicWires\n      decide\n"
                f"    · change dead{k} < H.wires\n      decide\n"
                f"    · change ({st['cv']} * {st['cinv']}) % H.modulus = 1\n      decide")
        proofs.append(f"  have hs{k} : wellFormed (withRows H ({prev}.eraseIdx {st['index']})) :=\n"
                      f"    wellFormed_withRows (withRows H {prev}) _ hs{k-1} (erase_subset {prev} {st['index']})")
        names.append(f"({prev}.eraseIdx {st['index']})")
    final = names[-1]
    body = "\n".join(proofs)
    chain = "e1" if len(steps) == 1 else "".join(f"(e{k}.trans " for k in range(1, len(steps))) + \
        f"e{len(steps)}" + ")"*(len(steps)-1)
    src = f"""import MathCan.ZKLeanCompose
open MathCan.ZKLean MathCan.ZKLean.Poly MathCan.ZKLean.Local MathCan.ZKLean.Compose

def H : Shape := {header}
{chr(10).join(defs)}

set_option maxRecDepth 8192 in
set_option maxHeartbeats 8000000 in
theorem pruned_matrix_equiv (g0 : List Row) (hs0 : wellFormed (withRows H g0))
    {chr(10).join('    '+h for h in hyps).lstrip()}
    (x : List Nat) :
    accepts (withRows H g0) x ↔ accepts (withRows H {final}) x := by
{body}
  exact {chain}

#print axioms pruned_matrix_equiv
"""
    return src


def plan(path, pin, explicit, seed=300030, around=0):
    found = scan(path, pin)
    dead = [(r, w) for r, ws in found["dead_output_sample"] for w, kind in ws if kind == "c"]
    near = {r+k for r, _ in dead for k in range(-around, around+1) if k}
    explicit = sorted((set(explicit) | near) - {r for r, _ in dead})
    with path.open("rb") as f:
        header = json.loads(f.readline())
    corpus = Corpus26(PREFIX, header["wires"])
    full = stream_audit(path, visit=corpus.visit)
    require_pin(full["canonical_shape_sha256"], pin)
    tried = []
    options = {}
    for t in explicit:
        if t not in corpus.rows:
            tried.append({"target": t, "eligible": False})
            continue
        rec = {"target": t, "eligible": True, "arms": {}}
        for arm in ARMS26:
            r = attempt26(full, corpus, t, arm, 256, random.Random(seed+t))
            rec["arms"][arm] = r["outcome"]
            if r["certificate"] is not None:
                options.setdefault(t, []).append(r)
        tried.append(rec)
    # Dependency-aware greedy selection: a target joins D only if its retained
    # rows avoid D and no accepted certificate retains it (no cycles, no chains).
    D_now = {r for r, _ in dead}
    used = set()
    verified = {}
    for t in sorted(options):
        for r in sorted(options[t], key=lambda r: len(r["retained_global_indices"])):
            if t not in used and not set(r["retained_global_indices"]) & D_now:
                verified[t] = r
                D_now.add(t)
                used.update(r["retained_global_indices"])
                next(x for x in tried if x["target"] == t)["chosen_retained"] = r["retained_global_indices"]
                break
    D = sorted({r for r, _ in dead} | set(verified), reverse=True)
    expected, rows, full = deletion_digest(path, pin, D)
    # Retained rows of the poly certificates, fetched in the same pass order.
    need = {q for r in verified.values() for q in r["retained_global_indices"]}
    refrows = {}
    stream_audit(path, visit=lambda i, row, _p: refrows.__setitem__(i, row) if i in need else None)
    p = int(full["modulus"])
    steps, applied = [], []
    for d in D:
        shift = lambda q: q - sum(1 for e in applied if e < q)  # noqa: E731
        if d in verified:
            r = verified[d]
            refs = [(shift(q), refrows[q]) for q in r["retained_global_indices"]]
            a = {"format": "zkl-r1cs-v1", "modulus": full["modulus"], "wires": full["wires"],
                 "public": full["public"], "rows": [*[rr for _, rr in refs], rows[d]]}
            b = dict(a, rows=a["rows"][:-1])
            verify(a, b, r["certificate"], r["certificate"]["original_sha256"], r["certificate"]["replacement_sha256"])
            steps.append({"kind": "poly", "index": shift(d), "original_index": d, "row": rows[d],
                          "refs": refs, "cert": r["certificate"]})
        else:
            w = next(w for rr, w in dead if rr == d)
            cv = int(next(c for ww, c in rows[d][2] if ww == w))
            steps.append({"kind": "dead", "index": shift(d), "original_index": d, "row": rows[d], "wire": w,
                          "cv": cv, "cinv": pow(cv, -1, p)})
        applied.append(d)
    source = lean_steps(full, steps)
    out = {"schema": "zkl30-pilot-plan-v1", "original_full_sha256": pin, "deletion_set": D,
           "dead_outputs": [[r, w] for r, w in dead], "explicit_candidates": tried,
           "verified_polynomial": {str(t): {"retained_global_indices": r["retained_global_indices"],
                                            "degree": r["certificate"]["degree"],
                                            "multipliers": r["certificate"]["multipliers"]}
                                   for t, r in verified.items()},
           "steps": [{k: v for k, v in s.items() if k not in ("row", "refs", "cert")} | {"cinv": str(s.get("cinv", ""))}
                     for s in steps],
           "expected": expected,
           "native_aux_index_of_dead_wires": {str(w): w-1-len(full["public"]) for _, w in dead},
           "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
           "production_accepted": False}
    return out, source


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stream", type=Path)
    ap.add_argument("--expected-original", required=True)
    ap.add_argument("--candidates", default="")
    ap.add_argument("--around-dead", type=int, default=0)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    explicit = [int(x) for x in args.candidates.split(",") if x]
    out, source = plan(args.stream, args.expected_original, explicit, around=args.around_dead)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "plan.json").write_text(json.dumps(out, sort_keys=True, indent=1)+"\n", encoding="utf-8")
    (args.out / "PrunedMatrix.lean").write_text(source, encoding="utf-8")
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
