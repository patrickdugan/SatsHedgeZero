"""ZKL-23: bind small polynomial certificates to a full ordered row stream."""
import argparse
import hashlib
import json
from pathlib import Path

from audit import canonical, digest, load
from audit_capture import compact, stream_audit
from ideal_certificate import add
from poly_certificate import residual, verify

MAX_LOCAL_ROWS = 32
MAX_DISCOVERY_ROWS = 8192
MAX_DISCOVERY_TERMS = 32
MAX_DISCOVERY_SUPPORT = 64


def require_pin(actual, expected):
    if (not isinstance(expected, str) or len(expected) != 64
            or any(c not in "0123456789abcdef" for c in expected) or actual != expected):
        raise ValueError("full matrix hash pin mismatch")


def bind(path, expected_original, target, retained):
    """Stream all rows, retain only the selected global indices and hash the exact deletion."""
    if type(target) is not int or target < 0:
        raise ValueError("invalid target row")
    if not isinstance(retained, list) or not 1 <= len(retained) <= MAX_LOCAL_ROWS:
        raise ValueError("invalid retained subset size")
    if any(type(i) is not int or i < 0 or i == target for i in retained):
        raise ValueError("invalid retained global row")
    if retained != sorted(set(retained)):
        raise ValueError("retained rows must be unique and ordered")
    wanted = set(retained) | {target}
    selected = {}

    def visit(i, row, _p):
        if i in wanted:
            selected[i] = row

    full = stream_audit(path, visit=visit, omit=target)
    require_pin(full["canonical_shape_sha256"], expected_original)
    if set(selected) != wanted:
        raise ValueError("subset references absent global row")
    # No relabeling: keep global wire IDs and the entire public interface.
    a = canonical({"format": "zkl-r1cs-v1", "modulus": full["modulus"],
                   "wires": full["wires"], "public": full["public"],
                   "rows": [*map(selected.__getitem__, retained), selected[target]]})
    b = dict(a, rows=a["rows"][:-1])
    return full, a, b


def scaled_pair(a, b):
    p = int(a["modulus"])
    source, target = residual(b["rows"][0]), residual(a["rows"][-1])
    src = {m: v % p for m, v in source.items() if v % p}
    dst = {m: v % p for m, v in target.items() if v % p}
    if not src or set(src) != set(dst):
        raise ValueError("different polynomial supports")
    first = min(src)
    k = dst[first]*pow(src[first], -1, p) % p
    diff = add(target, source, -k)
    if not k or any(v % p for v in diff.values()):
        raise ValueError("not proportional")
    cert = {"schema": "zkl-poly-certificate-v1", "original_sha256": digest(a),
            "replacement_sha256": digest(b), "target_index": len(a["rows"])-1,
            "degree": 0, "multipliers": [[0, [], str(k)]],
            "correction": [[list(m), str(v//p)] for m, v in sorted(diff.items())]}
    verify(a, b, cert, digest(a), digest(b))
    return cert


def discover(path, expected_original, limit=MAX_DISCOVERY_ROWS):
    """Search bounded prefix for a non-identical, nonzero proportional residual pair."""
    if type(limit) is not int or not 1 <= limit <= MAX_DISCOVERY_ROWS:
        raise ValueError("invalid discovery cap")
    seen, found = {}, []
    examined = 0

    def visit(i, row, p):
        nonlocal examined
        if found or i >= limit or sum(map(len, row)) > MAX_DISCOVERY_TERMS:
            return
        poly = residual(row)
        reduced = {m: c % p for m, c in poly.items() if c % p}
        if not reduced or len(reduced) > MAX_DISCOVERY_SUPPORT:
            return
        inv = pow(reduced[min(reduced)], -1, p)
        key = tuple((m, c*inv % p) for m, c in sorted(reduced.items()))
        row_hash = hashlib.sha256(compact(row)).digest()
        examined += 1
        if key in seen:
            prior, prior_hash = seen[key]
            if prior_hash != row_hash:
                found.append((i, prior))
        else:
            seen[key] = (i, row_hash)

    full = stream_audit(path, visit=visit)
    require_pin(full["canonical_shape_sha256"], expected_original)
    if not found:
        return {"schema": "zkl-local-discovery-v1", "status": "INCONCLUSIVE",
                "examined": examined, "search_prefix": min(limit, full["constraints"]),
                "original_full_sha256": expected_original, "production_accepted": False}
    target, prior = found[0]
    full, a, b = bind(path, expected_original, target, [prior])
    cert = scaled_pair(a, b)
    return {"schema": "zkl-local-deletion-v1", "status": "CANDIDATE",
            "original_full_sha256": expected_original,
            "replacement_full_sha256": full["deletion_shape_sha256"],
            "target_global_index": target, "retained_global_indices": [prior],
            "certificate": cert, "examined": examined, "search_prefix": min(limit, full["constraints"]),
            "production_accepted": False}


def lean_row(row):
    return "⟨" + ", ".join("[" + ", ".join(f"⟨{i}, {c}⟩" for i, c in lc) + "]"
                           for lc in row) + "⟩"


def local_lean(a, b, cert):
    weights = ", ".join(f"⟨({k}), {mon}, {lean_row(b['rows'][i])}⟩"
                        for i, mon, k in cert["multipliers"])
    correction = ", ".join(f"⟨{mon}, ({c})⟩" for mon, c in cert["correction"])
    return f"""import MathCan.ZKLeanLocal
open MathCan.ZKLean MathCan.ZKLean.Poly MathCan.ZKLean.Local

def localRows : List Row := [{", ".join(map(lean_row, b["rows"]))}]
def targetRow : Row := {lean_row(a["rows"][-1])}
def weights : List Multiplier := [{weights}]
def correction : PPoly := [{correction}]
def contextHeader : Shape :=
  ⟨{a['modulus']}, {a['wires']}, {a['public']}, []⟩

set_option maxRecDepth 4096 in
set_option maxHeartbeats 4000000 in
theorem bound_context_delete (pre post : List Row)
    (hs : wellFormed (withRows contextHeader (pre ++ targetRow :: post)))
    (hsub : RowSubset localRows (pre ++ post)) (x : List Nat) :
    accepts (withRows contextHeader (pre ++ targetRow :: post)) x ↔
      accepts (withRows contextHeader (pre ++ post)) x := by
  exact checked_local_poly_delete contextHeader pre post localRows targetRow weights correction
    hs hsub (by decide) (by decide) x

#print axioms bound_context_delete
"""


def verify_bound(path, expected_original, bundle):
    if (bundle.get("schema") != "zkl-local-deletion-v1" or bundle.get("status") != "CANDIDATE"
            or bundle.get("production_accepted") is not False):
        raise ValueError("invalid local deletion bundle")
    require_pin(bundle["original_full_sha256"], expected_original)
    full, a, b = bind(path, expected_original, bundle["target_global_index"], bundle["retained_global_indices"])
    require_pin(full["deletion_shape_sha256"], bundle["replacement_full_sha256"])
    cert = bundle["certificate"]
    verify(a, b, cert, digest(a), digest(b))
    source = local_lean(a, b, cert)
    return source, {
        "schema": "zkl-local-binding-receipt-v1", "exact_identity_checked": True,
        "full_matrix_sha256": expected_original, "deletion_matrix_sha256": full["deletion_shape_sha256"],
        "target_global_index": bundle["target_global_index"],
        "retained_global_indices": bundle["retained_global_indices"],
        "constraints": full["constraints"], "retained_constraints": full["retained_constraints"],
        "local_original_sha256": digest(a), "local_replacement_sha256": digest(b),
        "lean_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "lean_replayed": False, "full_matrix_context_kernel_bound": False,
        "production_accepted": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stream", type=Path)
    parser.add_argument("--expected-original", required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    bundle = load(args.bundle) if args.bundle else discover(args.stream, args.expected_original)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    if bundle["status"] == "CANDIDATE":
        source, receipt = verify_bound(args.stream, args.expected_original, bundle)
        (args.out / "LocalDelete.lean").write_text(source, encoding="utf-8")
        (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
    elif args.bundle or bundle["status"] != "INCONCLUSIVE":
        raise ValueError("invalid input bundle")
    else:
        print(json.dumps(bundle, sort_keys=True))


if __name__ == "__main__":
    main()
