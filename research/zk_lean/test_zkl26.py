import json
import random
import tempfile
import unittest
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ
from full_matrix_scan import scan
from graph_dependency import ARMS26, campaign26, check_counterexample, counterexample
from neighborhood_search import mod, residual
from poly_certificate import verify
from test_graph_dependency import fixture
from test_local_binding import make_stream

ONE = [[0, "1"]]


def v(i, c="1"):
    return [[i, c]]


def substitution_rows(p):
    # 10: x, 11: y, 12: z, 13: u. L: x = y + z; Q: y*z = u; T: (x - z)*z = u.
    return [[v(10), ONE, [[11, "1"], [12, "1"]]],
            [v(11), v(12), v(13)],
            [[[10, "1"], [12, str(p-1)]], v(12), v(13)]]


def independent_rows():
    # T: z = 5 is not implied by x*y = z.
    return [[v(10), v(11), v(12)], [v(12), ONE, [[0, "5"]]]]


class Zkl26Tests(unittest.TestCase):
    def run_campaign(self, p, rows, target):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            original = make_stream(path, p, rows)
            return campaign26(path, digest(original), width=2, targets=[target])

    def test_directed_and_adaptive_cross_window(self):
        for p in (BN254_FR, BN254_FQ):
            for d in (1, 2):
                rows = fixture(d)
                result, bundles = self.run_campaign(p, rows, len(rows)-1)
                arms = result["tasks"][0]["arms"]
                with self.subTest(p=p, d=d):
                    self.assertEqual(arms["window"]["outcome"], "counterexample")
                    for arm in ("graph", "adaptive", "directed"):
                        self.assertEqual(arms[arm]["outcome"], "verified_redundancy", arm)
                    self.assertTrue(all(r["degree"] <= 2 for r, _ in bundles))

    def test_linear_substitution_certificate(self):
        for p in (BN254_FR, BN254_FQ):
            result, bundles = self.run_campaign(p, substitution_rows(p), 2)
            rec = result["tasks"][0]["arms"]["directed"]
            self.assertEqual(rec["outcome"], "verified_redundancy")
            self.assertEqual(rec["info"]["pivots"], 1)
            self.assertEqual(rec["certificate"]["degree"], 1)
            receipt = next(r for r, _ in bundles if r["arm"] == "directed")
            self.assertEqual(receipt["retained_global_indices"], [0, 1])

    def test_counterexample_is_exact_and_tamper_checked(self):
        p = BN254_FR
        result, _ = self.run_campaign(p, independent_rows(), 1)
        for arm in ARMS26:
            self.assertEqual(result["tasks"][0]["arms"][arm]["outcome"], "counterexample")
        rows = {0: independent_rows()[0]}
        first = [-1]*100_003
        for w in (10, 11, 12):
            first[w] = 0
        ce = counterexample(rows, independent_rows()[1], p, first, random.Random(1), {1, 2})
        self.assertTrue(check_counterexample(list(rows.values()), independent_rows()[1], ce, p))
        bad = dict(ce)
        bad[12] = 5
        self.assertFalse(check_counterexample(list(rows.values()), independent_rows()[1], bad, p))
        bad = dict(ce)
        bad[0] = 2
        self.assertFalse(check_counterexample(list(rows.values()), independent_rows()[1], bad, p))

    def test_full_matrix_scan_classes(self):
        p = BN254_FQ
        rows = [[v(10), v(11), v(12)],            # 12 used again below
                [v(12), ONE, v(13)],              # 13 occurs once, in C: dead output
                [v(10, "2"), v(11), v(12, "2")],  # proportional duplicate of row 0
                [v(10), v(11), [[12, "1"]]],      # exact duplicate of row 0
                [v(1), v(2), v(14)],              # 14 dead output; public wires used
                [v(15), ONE, v(15)]]              # zero residual row
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            original = make_stream(path, p, rows, wires=20)
            out = scan(path, digest(original))
        self.assertEqual(out["zero_row_count"], 1)
        self.assertEqual(sorted(r for r, _ in out["dead_output_sample"]), [1, 4])
        self.assertEqual(out["duplicate_candidates"], 2)
        self.assertEqual(sorted(out["duplicate_pairs"]), [[2, 0], [3, 0]])
        # Wires 3..9 and 16..19 occur nowhere (0, 1, 2 excluded).
        self.assertEqual(out["unconstrained_wires"], 11)
        self.assertEqual(out["public_unconstrained"], [])
        json.dumps(out)

    def test_certificates_verify_independently(self):
        p = BN254_FR
        result, bundles = self.run_campaign(p, substitution_rows(p), 2)
        for receipt, source in bundles:
            self.assertIn("indexed_context_delete", source)
            cert = receipt["certificate"]
            rows = substitution_rows(p)
            a = {"format": "zkl-r1cs-v1", "modulus": str(p), "wires": 100_003, "public": [1, 2],
                 "rows": [*[rows[i] for i in receipt["retained_global_indices"]], rows[2]]}
            b = dict(a, rows=a["rows"][:-1])
            verify(a, b, cert, digest(a), digest(b))
            self.assertFalse(mod(residual(rows[2]), p) == {})


if __name__ == "__main__":
    unittest.main()
