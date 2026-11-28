import tempfile
import unittest
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ
from test_local_binding import make_stream
from window_dependency import discover


def fixture():
    # x=0, y=0, x+y=0; duplicate x; scaled y; then a zero polynomial.
    return [[[[99998, "1"]], [[0, "1"]], []],
            [[[99999, "1"]], [[0, "1"]], []],
            [[[99998, "1"], [99999, "1"]], [[0, "1"]], []],
            [[[99998, "1"]], [[0, "1"]], []],
            [[[99999, "2"]], [[0, "1"]], []],
            [[[99999, "1"]], [[0, "1"]], [[99999, "1"]]]]


class WindowTests(unittest.TestCase):
    def test_both_fields_and_global_indices(self):
        for p in (BN254_FR, BN254_FQ):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "rows.jsonl"
                original = make_stream(path, p, fixture())
                pin = digest(original)
                summary, cases = discover(path, pin)
                self.assertEqual(set(summary["candidate_kinds"]), {"duplicate", "proportional", "multirow"})
                self.assertEqual(summary["counts"]["zero"], 1)
                for receipt, source in cases:
                    target = receipt["target_global_index"]
                    self.assertEqual(receipt["replacement_full_sha256"],
                                     digest(dict(original, rows=original["rows"][:target]
                                                 + original["rows"][target+1:])))
                    self.assertIn("indexed_context_delete", source)
                    self.assertFalse(receipt["full_matrix_context_kernel_bound"])
                    self.assertTrue(receipt["exact_identity_checked"])
                    if receipt["kind"] == "multirow":
                        self.assertEqual(receipt["retained_global_indices"], [0, 1])
                with self.assertRaises(ValueError):
                    discover(path, "0"*64)

    def test_bounded_window_and_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            original = make_stream(path, BN254_FR, fixture())
            pin = digest(original)
            summary, cases = discover(path, pin, width=2)
            self.assertNotIn("multirow", summary["candidate_kinds"])
            summary, cases = discover(path, pin, prefix=2)
            self.assertEqual(cases, [])


if __name__ == "__main__":
    unittest.main()
