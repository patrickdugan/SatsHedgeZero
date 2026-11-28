"""Cross-repository development smoke; put DataGoblin/src on PYTHONPATH."""
import json
from audit import check, digest
from datagoblin.zk_lean_gym import campaign, lc, public_relation, shape


def main():
    counts = dict(cases=0, matching_shape_hashes=0, validated_counterexamples=0,
                  redundant_rows_removed=0, accepted_edits=0, unsound=0,
                  incomplete=0, defect_mutations=0, baseline_assignments_enumerated=0)
    for seed, split in ((7, "development"), (19, "holdout")):
        for record in campaign(seed, split, 2, True):
            s, rr, o = record["shape"], record["receipt"], record["optimization"]
            assert digest(s) == rr["shape_sha256"]
            assert digest(o["shape"]) == o["receipt"]["shape_sha256"]
            counts["cases"] += 1
            counts["matching_shape_hashes"] += 2
            if rr["counterexample"]:
                ce = rr["counterexample"]
                assert check(s, list(map(str, ce["assignment"])), list(map(str, ce["public"]))) == []
                counts["validated_counterexamples"] += 1
            counts["redundant_rows_removed"] += len(s["rows"]) - len(o["shape"]["rows"])
            counts["accepted_edits"] += len(o["edits"])
            counts["unsound"] += int(not rr["sound"])
            counts["incomplete"] += int(not rr["complete"])
            counts["defect_mutations"] += int(record["mutation"] in ("drop", "coefficient"))
            counts["baseline_assignments_enumerated"] += int(s["modulus"]) ** (s["wires"] - 1)
    # Different fields AND different encodings of the same bounded integer relation.
    a = shape(7, "range2", 1)
    p = 11
    b = {"format": "zkl-r1cs-v1", "modulus": str(p), "wires": 4, "public": [1], "rows": [
        [lc(p, (1, 1)), lc(p, (1, 1), (0, -1)), lc(p, (2, 1))],
        [lc(p, (1, 1), (0, -2)), lc(p, (1, 1), (0, -3)), lc(p, (3, 1))],
        [lc(p, (2, 1)), lc(p, (3, 1)), []],
    ]}
    assert set(public_relation(a)) == set(public_relation(b)) == {(i,) for i in range(4)}
    bad = dict(b, rows=b["rows"][:-1])
    assert set(public_relation(bad)) == {(i,) for i in range(p)}
    counts["crossfield_range2"] = {"bit_decomposition_sha256": digest(a),
                                   "vanishing_polynomial_sha256": digest(b),
                                   "accepted": [0, 1, 2, 3], "mutant_accepted": list(range(p))}
    counts["production_accepted"] = False
    counts["lean_replayed"] = False
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
