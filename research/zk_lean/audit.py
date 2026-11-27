"""Independent canonical R1CS audit/import. Shape-only, development evidence."""
import argparse
import hashlib
import json
import re
from pathlib import Path

FMT = "zkl-r1cs-v1"
BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def number(value):
    if not isinstance(value, str):
        raise ValueError("field element must be a string")
    if re.fullmatch(r"0|[1-9][0-9]*", value):
        return int(value)
    if re.fullmatch(r"0x[0-9a-f]+", value):
        return int(value, 16)
    raise ValueError("invalid field integer")


def index(value, n):
    if type(value) is not int or not 0 <= value < n:
        raise ValueError("invalid wire index")
    return value


def canonical(raw):
    if set(raw) != {"format", "modulus", "wires", "public", "rows"} or raw["format"] != FMT:
        raise ValueError("unknown shape schema")
    p, n = number(raw["modulus"]), raw["wires"]
    if p < 2 or type(n) is not int or n < 1:
        raise ValueError("invalid modulus or wire count")
    public = [index(i, n) for i in raw["public"]]
    if 0 in public or len(set(public)) != len(public):
        raise ValueError("invalid public wire map")

    def lc(terms):
        acc = {}
        for i, c in terms:
            i, c = index(i, n), number(c)
            if not 0 <= c < p:
                raise ValueError("noncanonical field coefficient")
            acc[i] = (acc.get(i, 0) + c) % p
        return [[i, str(c)] for i, c in sorted(acc.items()) if c]

    rows = []
    for row in raw["rows"]:
        if len(row) != 3:
            raise ValueError("R1CS row must have A, B, C")
        rows.append([lc(l) for l in row])
    return {"format": FMT, "modulus": str(p), "wires": n, "public": public, "rows": rows}


def digest(shape):
    data = json.dumps(canonical(shape), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode("ascii")).hexdigest()


def check(shape, witness, public):
    s = canonical(shape)
    p = int(s["modulus"])
    w = list(map(number, witness))
    x = list(map(number, public))
    if len(w) != s["wires"] or w[0] != 1 or any(v >= p for v in w):
        raise ValueError("invalid complete assignment")
    if [w[i] for i in s["public"]] != x:
        raise ValueError("public assignment mismatch")

    def ev(lc):
        return sum(int(c) * w[i] for i, c in lc) % p

    return [j for j, (a, b, c) in enumerate(s["rows"]) if ev(a) * ev(b) % p != ev(c)]


def low_incidence(shape):
    s = canonical(shape)
    counts = [0] * s["wires"]
    for row in s["rows"]:
        for i in {i for lc in row for i, _ in lc}:
            counts[i] += 1
    return [i for i in range(1, len(counts)) if counts[i] < 2]


def lean_source(shape):
    s = canonical(shape)

    def lc(terms):
        return "[" + ", ".join(f"⟨{i}, {c}⟩" for i, c in terms) + "]"

    rows = ",\n    ".join("⟨" + ", ".join(lc(l) for l in row) + "⟩" for row in s["rows"])
    return (
        "import MathCan.ZKLean\nopen MathCan.ZKLean\n"
        f"-- Canonical shape SHA256: {digest(s)}\n"
        "def exportedShape : Shape := {\n"
        f"  modulus := {s['modulus']}\n  wires := {s['wires']}\n"
        f"  publicWires := {s['public']}\n  rows := [{rows}]\n"
        "}\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("shape")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--canonical-out")
    parser.add_argument("--lean-out")
    parser.add_argument("--assignment", help="JSON with witness and independently pinned public")
    args = parser.parse_args()
    s = canonical(load(args.shape))
    sha = digest(s)
    if args.expected_sha256 and args.expected_sha256 != sha:
        raise SystemExit("shape hash mismatch")
    if args.canonical_out:
        Path(args.canonical_out).write_text(json.dumps(s, sort_keys=True), encoding="utf-8")
    if args.lean_out:
        Path(args.lean_out).write_text(lean_source(s), encoding="utf-8")
    bad = None
    if args.assignment:
        a = load(args.assignment)
        bad = check(s, a["witness"], a["public"])
    print(json.dumps({
        "shape_sha256": sha, "constraints": len(s["rows"]), "wires": s["wires"],
        "public_wires": s["public"], "low_incidence": low_incidence(s),
        "unsatisfied_rows": bad, "production_accepted": False,
        "status": "DEVELOPMENT_ONLY", "modulus_matches_bn254_fr": int(s["modulus"]) == BN254_FR,
    }, sort_keys=True))
    if bad:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
