import tempfile
import unittest
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ, stream_audit
from graph_dependency import Pool, campaign, search_local
from test_local_binding import make_stream


def rows():
    # Three independent families, all retaining original high wire IDs.
    return [
        [[[99998, "1"]], [[0, "1"]], []],
        [[[99999, "1"]], [[0, "1"]], []],
        [[[99998, "1"], [99999, "1"]], [[0, "1"]], []],
        [[[99990, "1"]], [[99991, "1"]], [[0, "1"]]],
        [[[99991, "1"]], [[99992, "1"]], [[0, "1"]]],
        [[[99990, "1"]], [[0, "1"]], [[99992, "1"]]],
        [[[99980, "1"]], [[99981, "1"]], [[99982, "1"]]],
        [[[99980, "1"]], [[99980, "1"]], []],
        [[[99982, "1"]], [[99982, "1"]], []],
        [[[1, "1"]], [[0, "1"]], [[2, "1"]]],
    ]


class GraphTests(unittest.TestCase):
    def test_degree_tiers_and_global_wire_ids(self):
        for p in (BN254_FR, BN254_FQ):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "rows.jsonl"
                original = make_stream(path, p, rows())
                pool = Pool(100)
                full = stream_audit(path, visit=pool.visit)
                self.assertEqual(full["canonical_shape_sha256"], digest(original))
                for target, keep, degree in ((2, [0, 1], 0), (5, [3, 4], 1), (8, [6, 7], 2)):
                    rec = search_local(full, pool, target, keep)
                    self.assertEqual(rec["status"], "CERTIFIED")
                    self.assertEqual(rec["degree"], degree)
                    self.assertTrue(all(w > 99900 for w in rec["multiplier_wires"]))
                    self.assertNotIn(target, rec["retained"])
                essential = search_local(full, pool, 9, [0, 1, 3, 4, 6, 7])
                self.assertIsNone(essential["certificate"])

    def test_graph_finds_noncontiguous_rows_and_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            rs = rows()
            # Interleave irrelevant short rows to separate the actual dependency.
            decoy = [[[1, "1"]], [[0, "1"]], [[2, "1"]]]
            rs = [rs[0], *[decoy]*20, rs[1], *[decoy]*20, rs[2]]
            original = make_stream(path, BN254_FR, rs)
            pool = Pool(100)
            full = stream_audit(path, visit=pool.visit)
            target = len(rs)-1
            self.assertIn(0, pool.graph(target))
            self.assertNotIn(0, pool.nearby(target))
            result = search_local(full, pool, target, pool.graph(target))
            self.assertEqual(result["degree"], 0)
            summary, trials, bundles = campaign(path, digest(original), prefix=100, targets=64)
            self.assertEqual(len(trials), 2*len(summary["targets"]))
            self.assertTrue(bundles)
            for receipt, source in bundles:
                self.assertTrue(receipt["exact_identity_checked"])
                self.assertFalse(receipt["production_accepted"])
                self.assertIn("indexed_context_delete", source)
            with self.assertRaises(ValueError):
                campaign(path, "0"*64, prefix=100)


if __name__ == "__main__":
    unittest.main()
