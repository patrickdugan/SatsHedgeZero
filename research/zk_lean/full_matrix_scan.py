"""ZKL-26: whole-matrix scan separating unconstrained variables from redundant rows.

One streaming pass over the pinned ordered matrix records, per wire, the
number of term occurrences, the first and last row it occurs in, and in
which of A/B/C it occurs. Per row it hashes the scale-normalized residual
polynomial. From these it reports, as separate classes:

* unconstrained wires: occur in no row at all (public wires reported apart);
* dead-output rows: a non-public wire occurs exactly once in the matrix,
  linearly (C only, or A/B against a nonzero constant), so the row can always
  be satisfied by choosing that wire; deleting the row preserves acceptance
  (witness elimination, not ideal membership; Lean: dead_output_delete);
* zero rows: residual identically zero mod p;
* global proportional duplicates: equal normalized residual hashes, later
  re-verified exactly from the bound rows.

The hash table holds 12-byte digests only. A hash match is a candidate, not
a finding, until the exact rows are rebound and the certificate verified.
"""
import argparse
import hashlib
import json
from array import array
from pathlib import Path

from audit_capture import stream_audit
from local_binding import require_pin
from neighborhood_search import mod, residual

MAX_DUPLICATE_PAIRS = 4096
MAX_DEAD_RECORDS = 4096
A_BIT, B_BIT, C_BIT = 1, 2, 4


def normalized_key(poly, p):
    inv = pow(poly[min(poly)], -1, p)
    enc = ";".join(f"{','.join(map(str, m))}:{c*inv % p}" for m, c in sorted(poly.items()))
    return hashlib.sha256(enc.encode()).digest()[:12]


def constant_only(lc):
    return len(lc) == 1 and lc[0][0] == 0


class Scan:
    def __init__(self):
        self.ready = False
        self.zero_rows = []
        self.dup_pairs = []
        self.dup_total = 0
        self.seen = {}
        self.rows = 0

    def setup(self, wires):
        self.count = array("I", bytes(4*wires))
        self.first = array("i", [-1])*wires
        self.last = array("i", [-1])*wires
        self.kind = bytearray(wires)
        # Linear single-occurrence flag: set for the occurrence that made count==1.
        self.linear = bytearray(wires)
        self.ready = True

    def visit(self, i, row, p):
        a, b, c = row
        self.rows += 1
        for bit, lc, other in ((A_BIT, a, b), (B_BIT, b, a), (C_BIT, c, None)):
            # 1: C only (Lean dead_output_delete); 2: A/B against a nonzero constant.
            lin = 1 if other is None else 2 if constant_only(other) and int(other[0][1]) % p else 0
            for w, _ in lc:
                if self.count[w] == 0:
                    self.first[w] = i
                self.count[w] += 1
                self.last[w] = i
                self.kind[w] |= bit
                self.linear[w] = lin
        poly = mod(residual(row), p)
        if not poly:
            self.zero_rows.append(i)
            return
        key = normalized_key(poly, p)
        prior = self.seen.get(key)
        if prior is None:
            self.seen[key] = i
        else:
            self.dup_total += 1
            if len(self.dup_pairs) < MAX_DUPLICATE_PAIRS:
                self.dup_pairs.append([i, prior])


def scan(path, pin):
    with path.open("rb") as f:
        header = json.loads(f.readline())
    state = Scan()
    state.setup(header["wires"])
    full = stream_audit(path, visit=state.visit)
    require_pin(full["canonical_shape_sha256"], pin)
    public = set(full["public"])
    n = full["wires"]
    unconstrained = [w for w in range(1, n) if state.count[w] == 0 and w not in public]
    public_unconstrained = [w for w in sorted(public) if state.count[w] == 0]
    dead = {}
    single_nonlinear = 0
    for w in range(1, n):
        if state.count[w] != 1 or w in public:
            continue
        if state.linear[w]:
            dead.setdefault(state.first[w], []).append([w, "c" if state.linear[w] == 1 else "ab_const"])
        else:
            single_nonlinear += 1
    dead_rows = sorted(dead)
    hist = {}
    for w in range(1, n):
        k = min(int(state.count[w]), 9)
        hist[str(k) if k < 9 else "9+"] = hist.get(str(k) if k < 9 else "9+", 0)+1
    return {
        "schema": "zkl26-full-matrix-scan-v1", "original_full_sha256": pin,
        "constraints": full["constraints"], "wires": n, "public": full["public"],
        "canonical_nonzeros": full["canonical_nonzeros"],
        "occurrence_histogram": hist,
        "unconstrained_wires": len(unconstrained),
        "unconstrained_wire_sample": unconstrained[:64],
        "public_unconstrained": public_unconstrained,
        "public_occurrences": {str(w): int(state.count[w]) for w in sorted(public)},
        "public_first_rows": {str(w): int(state.first[w]) for w in sorted(public)},
        "single_occurrence_nonlinear": single_nonlinear,
        "dead_output_rows": len(dead_rows),
        "dead_output_wires": sum(map(len, dead.values())),
        "dead_output_rows_c_only": sum(any(k == "c" for _, k in ws) for ws in dead.values()),
        "dead_output_sample": [[r, dead[r]] for r in dead_rows[:MAX_DEAD_RECORDS]],
        "zero_rows": state.zero_rows[:MAX_DEAD_RECORDS], "zero_row_count": len(state.zero_rows),
        "duplicate_candidates": state.dup_total,
        "duplicate_pairs": state.dup_pairs,
        "distinct_normalized_rows": len(state.seen),
        "production_accepted": False,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stream", type=Path)
    ap.add_argument("--expected-original", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    out = scan(args.stream, args.expected_original)
    args.out.write_text(json.dumps(out, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items()
                      if k not in ("duplicate_pairs", "dead_output_sample", "zero_rows",
                                   "unconstrained_wire_sample")}, sort_keys=True))


if __name__ == "__main__":
    main()
