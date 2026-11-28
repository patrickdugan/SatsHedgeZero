import tempfile
import unittest
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ, stream_audit
from test_local_binding import make_stream
from test_zkl26 import ONE, substitution_rows, v
from zkl30_plan import deletion_digest, plan


def rows_for(p):
    # 0..2 substitution pair (rows 1 and 2 imply each other), 3 and 5 dead outputs.
    return substitution_rows(p) + [[v(20), ONE, v(21, "5")], [v(10), v(11), v(14)], [v(14), ONE, v(15)]]


class Zkl30Tests(unittest.TestCase):
    def test_multi_deletion_hash_and_plan(self):
        for p in (BN254_FR, BN254_FQ):
            with self.subTest(p=p), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "rows.jsonl"
                rows = rows_for(p)
                original = make_stream(path, p, rows, wires=30)
                pin = digest(original)
                for d in range(len(rows)):
                    self.assertEqual(deletion_digest(path, pin, [d])[0]["pruned_sha256"],
                                     stream_audit(path, omit=d)["deletion_shape_sha256"])
                for explicit, around, expected in (([2], 0, [5, 3, 2]), ([], 3, [5, 3, 1])):
                    out, source = plan(path, pin, explicit, around=around)
                    self.assertEqual(out["deletion_set"], expected)
                    kept = [r for i, r in enumerate(rows) if i not in out["deletion_set"]]
                    self.assertEqual(out["expected"]["pruned_sha256"], digest(dict(original, rows=kept)))
                    self.assertEqual(out["expected"]["constraints"], len(kept))
                    self.assertIn("pruned_matrix_equiv", source)
                    self.assertEqual(sorted(out["native_aux_index_of_dead_wires"]), ["15", "21"])

    def test_mutually_implying_rows_never_both_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            pin = digest(make_stream(path, BN254_FR, rows_for(BN254_FR), wires=30))
            out, _ = plan(path, pin, [1, 2])
            self.assertEqual(len({1, 2} & set(out["deletion_set"])), 1)


if __name__ == "__main__":
    unittest.main()
