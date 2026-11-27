import copy
import unittest

from audit import digest
from row_certificate import generate

ROW_A = [[[1, "1"]], [[1, "1"]], [[2, "1"]]]
ROW_B = [[[2, "1"]], [[0, "1"]], [[2, "1"]]]


class RowCertificateTests(unittest.TestCase):
    def setUp(self):
        self.original = {"format": "zkl-r1cs-v1", "modulus": "7", "wires": 3,
                         "public": [1, 2], "rows": [ROW_A, ROW_B, ROW_A]}
        self.replacement = dict(self.original, rows=[ROW_B, ROW_A])

    def issue(self, a, b):
        return generate(a, b, digest(a), digest(b))

    def test_reorder_and_duplicate(self):
        source, receipt = self.issue(self.original, self.replacement)
        self.assertIn("theorem exact_row_rewrite", source)
        self.assertIn("checked_delete_equiv", source)
        self.assertEqual(receipt["distinct_rows"], 2)
        self.assertEqual(receipt["original_rows"] - receipt["replacement_rows"], 1)
        self.assertFalse(receipt["lean_replayed"])
        self.assertFalse(receipt["production_accepted"])

    def test_changed_public_map(self):
        with self.assertRaisesRegex(ValueError, "interface"):
            self.issue(self.original, dict(self.replacement, public=[2, 1]))

    def test_changed_field(self):
        with self.assertRaisesRegex(ValueError, "interface"):
            self.issue(self.original, dict(self.replacement, modulus="11"))

    def test_changed_coefficient(self):
        changed = copy.deepcopy(self.replacement)
        changed["rows"][1][0][0][1] = "2"
        with self.assertRaisesRegex(ValueError, "row-set"):
            self.issue(self.original, changed)

    def test_nonduplicate_delete(self):
        with self.assertRaisesRegex(ValueError, "row-set"):
            self.issue(self.original, dict(self.replacement, rows=[ROW_A]))

    def test_pinned_hash(self):
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            generate(self.original, self.replacement, "0" * 64, digest(self.replacement))

    def test_cap(self):
        a = dict(self.original, rows=[ROW_A] * 257)
        b = dict(self.original, rows=[ROW_A])
        with self.assertRaisesRegex(ValueError, "cap"):
            self.issue(a, b)


if __name__ == "__main__":
    unittest.main()
