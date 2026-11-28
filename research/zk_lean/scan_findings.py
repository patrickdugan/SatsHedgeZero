"""ZKL-26: exact verification and Lean emission for full_matrix_scan findings.

Duplicate candidates are hash matches; each is re-verified here as an exact
integer proportional identity over rows streamed from the pinned matrix. The
first verified pair and the first C-only dead-output row are bound with a
full deletion hash and emitted as indexed Lean sources:

* duplicates use MathCan.ZKLeanLocal.checked_indexed_poly_delete (degree 0);
* dead outputs use MathCan.ZKLeanCompose.dead_output_delete. The premise
  that the dead wire occurs in no other row is external, like the ZKL-24
  global row lookups: it is established by this streaming scan, not by Lean.
"""
import argparse
import hashlib
import json
from pathlib import Path

from audit import digest
from audit_capture import stream_audit
from local_binding import bind, lean_row, require_pin, scaled_pair
from window_dependency import indexed_lean

MAX_VERIFY_PAIRS = 4096


def verify_duplicates(path, pin, pairs):
    pairs = [tuple(q) for q in pairs[:MAX_VERIFY_PAIRS]]
    wanted = {i for q in pairs for i in q}
    rows = {}
    full = stream_audit(path, visit=lambda i, row, _p: rows.__setitem__(i, row) if i in wanted else None)
    require_pin(full["canonical_shape_sha256"], pin)
    ok, exact = [], 0
    for target, prior in pairs:
        a = {"format": "zkl-r1cs-v1", "modulus": full["modulus"], "wires": full["wires"],
             "public": full["public"], "rows": [rows[prior], rows[target]]}
        b = dict(a, rows=a["rows"][:1])
        scaled_pair(a, b)  # raises unless an exact proportional identity
        ok.append([target, prior])
        exact += rows[prior] == rows[target]
    return full, ok, exact


def dead_lean(full, target, row, wire, cv, cinv):
    return f"""import MathCan.ZKLeanCompose
open MathCan.ZKLean MathCan.ZKLean.Compose

def targetGlobal : Nat := {target}
def targetRow : Row := {lean_row(row)}
def deadWire : Nat := {wire}
def deadCoeff : Nat := {cv}
def deadInverse : Nat := {cinv}
def contextHeader : Shape := ⟨{full['modulus']}, {full['wires']}, {full['public']}, []⟩

set_option maxRecDepth 4096 in
theorem indexed_dead_output_delete (globalRows : List Row)
    (hs : wellFormed (withRows contextHeader globalRows))
    (ht : globalRows[targetGlobal]? = some targetRow)
    (hothers : ∀ r ∈ globalRows.eraseIdx targetGlobal, ∀ t ∈ r.a ++ r.b ++ r.c, t.wire ≠ deadWire)
    (x : List Nat) :
    accepts (withRows contextHeader globalRows) x ↔
      accepts (withRows contextHeader (globalRows.eraseIdx targetGlobal)) x := by
  apply dead_output_delete (withRows contextHeader globalRows) targetGlobal deadWire deadCoeff
    deadInverse targetRow hs _ x
  unfold deadOutputCheck
  apply decide_eq_true
  refine ⟨by decide, ?_, ?_, ht, by decide, by decide, by decide, ?_, hothers⟩
  · change deadWire ∉ contextHeader.publicWires
    decide
  · change deadWire < contextHeader.wires
    decide
  change (deadCoeff * deadInverse) % contextHeader.modulus = 1
  decide

#print axioms indexed_dead_output_delete
"""


def bind_dead(path, pin, target, wire):
    rows = {}
    full = stream_audit(path, visit=lambda i, row, _p: rows.__setitem__(i, row) if i == target else None,
                        omit=target)
    require_pin(full["canonical_shape_sha256"], pin)
    row = rows[target]
    p = int(full["modulus"])
    hits = [c for w, c in row[2] if w == wire]
    if len(hits) != 1 or any(w == wire for lc in row[:2] for w, _ in lc):
        raise ValueError("not a C-only single occurrence")
    cv = int(hits[0])
    cinv = pow(cv, -1, p)
    source = dead_lean(full, target, row, wire, cv, cinv)
    return {"schema": "zkl26-dead-output-v1", "original_full_sha256": pin,
            "replacement_full_sha256": full["deletion_shape_sha256"],
            "target_global_index": target, "dead_wire": wire, "coefficient": str(cv),
            "inverse": str(cinv),
            "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "occurrence_premise": "streaming scan (external to Lean)",
            "production_accepted": False}, source


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stream", type=Path)
    ap.add_argument("--expected-original", required=True)
    ap.add_argument("--scan", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    scan = json.loads(args.scan.read_text())
    require_pin(scan["original_full_sha256"], args.expected_original)
    args.out.mkdir(parents=True, exist_ok=True)
    out = {"schema": "zkl26-scan-findings-v1", "original_full_sha256": args.expected_original}
    if scan["duplicate_pairs"]:
        _, ok, exact = verify_duplicates(args.stream, args.expected_original, scan["duplicate_pairs"])
        out.update(duplicate_pairs_verified=len(ok), duplicate_pairs_identical=exact,
                   duplicate_candidates=scan["duplicate_candidates"])
        target, prior = ok[0]
        bound, a, b = bind(args.stream, args.expected_original, target, [prior])
        cert = scaled_pair(a, b)
        source = indexed_lean(a, b, cert, target, [prior])
        (args.out / "duplicate.lean").write_text(source, encoding="utf-8")
        out["duplicate_receipt"] = {"target_global_index": target, "retained_global_indices": [prior],
                                    "replacement_full_sha256": bound["deletion_shape_sha256"],
                                    "certificate": cert,
                                    "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest()}
    c_only = [(r, w) for r, ws in scan["dead_output_sample"] for w, k in ws if k == "c"]
    if c_only:
        receipt, source = bind_dead(args.stream, args.expected_original, *c_only[0])
        (args.out / "dead_output.lean").write_text(source, encoding="utf-8")
        out["dead_output_receipt"] = receipt
    (args.out / "findings.json").write_text(json.dumps(out, sort_keys=True, indent=1)+"\n", encoding="utf-8")
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
