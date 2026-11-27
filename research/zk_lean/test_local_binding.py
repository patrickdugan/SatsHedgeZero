import copy
import json
import tempfile
import unittest
from pathlib import Path

from audit import BN254_FR, check, digest
from audit_capture import BN254_FQ, stream_audit
from local_binding import bind, discover, verify_bound


def make_stream(path, p, rows, wires=100_003):
    header = {"format": "zkl-r1cs-stream-v1", "modulus": str(p), "wires": wires,
              "public": [1, 2], "constraints": len(rows)}
    path.write_text("\n".join(json.dumps(r) for r in [header, *rows])+"\n", encoding="utf-8")
    return {"format": "zkl-r1cs-v1", "modulus": str(p), "wires": wires,
            "public": [1, 2], "rows": rows}


def rows():
    return [[[[99998, "1"]], [[99999, "1"]], [[100000, "1"]]],
            [[[1, "1"]], [[0, "1"]], [[2, "1"]]],
            [[[99999, "2"]], [[99998, "3"]], [[100000, "6"]]],
            [[[1, "1"]], [[2, "1"]], [[1, "1"]]]]


class LocalBindingTests(unittest.TestCase):
    def test_full_ordered_hash_and_proportional_certificate(self):
        for p in (BN254_FR, BN254_FQ):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "rows.jsonl"
                original = make_stream(path, p, rows())
                pin = digest(original)
                bundle = discover(path, pin)
                self.assertEqual(bundle["target_global_index"], 2)
                self.assertEqual(bundle["retained_global_indices"], [0])
                replacement = dict(original, rows=original["rows"][:2]+original["rows"][3:])
                self.assertEqual(bundle["replacement_full_sha256"], digest(replacement))
                source, receipt = verify_bound(path, pin, bundle)
                self.assertIn("100000", source)
                self.assertIn("bound_context_delete", source)
                self.assertTrue(receipt["exact_identity_checked"])
                self.assertFalse(receipt["full_matrix_context_kernel_bound"])

    def test_position_pins_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            original = make_stream(path, BN254_FR, rows())
            pin = digest(original)
            bundle = discover(path, pin)
            for key, value in (("original_full_sha256", "0"*64),
                               ("replacement_full_sha256", "0"*64),
                               ("target_global_index", 1),
                               ("retained_global_indices", [1]),
                               ("retained_global_indices", [2]),
                               ("retained_global_indices", [0, 0]),
                               ("retained_global_indices", [99])):
                changed = copy.deepcopy(bundle)
                changed[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    verify_bound(path, pin, changed)
            changed = copy.deepcopy(bundle)
            changed["certificate"]["multipliers"][0][2] = "5"
            with self.assertRaises(ValueError):
                verify_bound(path, pin, changed)
            changed_rows = rows()
            changed_rows[3][2][0][1] = "2"
            make_stream(path, BN254_FR, changed_rows)
            with self.assertRaises(ValueError):
                verify_bound(path, pin, bundle)

    def test_no_candidate_and_omission_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            original = make_stream(path, BN254_FR, rows())
            pin = digest(original)
            self.assertEqual(discover(path, pin, limit=2)["status"], "INCONCLUSIVE")
            for i in (0, 3):
                receipt = stream_audit(path, omit=i)
                self.assertEqual(receipt["deletion_shape_sha256"],
                                 digest(dict(original, rows=original["rows"][:i]+original["rows"][i+1:])))
            with self.assertRaises(ValueError):
                bind(path, pin, 0, [0])

    def test_essential_row_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            rs = [[[[1, "1"]], [[0, "1"]], []], [[[2, "1"]], [[0, "1"]], []]]
            original = make_stream(path, BN254_FR, rs, wires=3)
            self.assertEqual(check(dict(original, rows=rs[:1]), ["1", "0", "1"], ["0", "1"]), [])
            self.assertEqual(check(original, ["1", "0", "1"], ["0", "1"]), [1])
            self.assertEqual(discover(path, digest(original))["status"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
