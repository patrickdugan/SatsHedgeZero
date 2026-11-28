import tempfile
import unittest
from pathlib import Path

from audit import BN254_FR, check, digest
from audit_capture import BN254_FQ
from graph_dependency import campaign
from test_local_binding import make_stream


def fixture(degree):
    # Product-chain implication; globally high IDs and gaps between related rows.
    x, y, z, u, t = ([[i, "1"]] for i in range(99995, 100000))
    one = [[0, "1"]]
    rows = [[x, one, []],
            [[[1, "1"]], one, [[2, "1"]]],
            [x, y, z],
            [[[3, "1"]], one, [[4, "1"]]]]
    if degree == 2:
        rows.extend([[z, u, t], [[[5, "1"]], one, [[6, "1"]]], [t, one, []]])
    else:
        rows.append([z, one, []])
    return rows


class GraphTests(unittest.TestCase):
    def test_cross_window_degree_one_and_two(self):
        for p in (BN254_FR, BN254_FQ):
            for d in (1, 2):
                with self.subTest(field=p, degree=d), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "rows.jsonl"
                    rows = fixture(d)
                    original = make_stream(path, p, rows)
                    target = len(rows)-1
                    result, bundles = campaign(path, digest(original), width=2, targets=[target])
                    arms = result["tasks"][0]["arms"]
                    self.assertFalse(arms["window"]["exact_identity_checked"])
                    self.assertTrue(arms["graph"]["exact_identity_checked"])
                    self.assertEqual(arms["graph"]["certificate"]["degree"], d)
                    self.assertEqual(arms["graph"]["complete_through"], d-1)
                    self.assertEqual(len(bundles), 1)
                    rec, source = bundles[0]
                    replacement = dict(original, rows=rows[:-1])
                    self.assertEqual(rec["replacement_full_sha256"], digest(replacement))
                    self.assertIn("indexed_context_delete", source)
                    self.assertFalse(rec["full_matrix_context_kernel_bound"])
                    with self.assertRaises(ValueError):
                        campaign(path, "0"*64, targets=[target])

    def test_essential_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            rows = [[[[1, "1"]], [[2, "1"]], [[3, "1"]]],
                    [[[3, "1"]], [[4, "1"]], [[5, "1"]]],
                    [[[5, "1"]], [[0, "1"]], []]]
            a = make_stream(path, BN254_FR, rows, wires=6)
            self.assertEqual(check(dict(a, rows=rows[:-1]), ["1"]*6, ["1", "1"]), [])
            self.assertEqual(check(a, ["1"]*6, ["1", "1"]), [2])
            result, bundles = campaign(path, digest(a), targets=[2])
            self.assertEqual(bundles, [])
            for rec in result["tasks"][0]["arms"].values():
                self.assertFalse(rec["exact_identity_checked"])
                self.assertEqual(rec["complete_through"], 2)


if __name__ == "__main__":
    unittest.main()
