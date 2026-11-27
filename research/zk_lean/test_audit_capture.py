import json
import tempfile
import unittest
from pathlib import Path

from audit import BN254_FR, digest
from audit_capture import BN254_FQ, stream_audit


class CaptureTests(unittest.TestCase):
    def write(self, root, p, rows, expected=None):
        header = {"format": "zkl-r1cs-stream-v1", "modulus": str(p), "wires": 4,
                  "public": [1, 2], "constraints": len(rows) if expected is None else expected}
        path = root / "shape.jsonl"
        path.write_text("\n".join(json.dumps(x) for x in [header, *rows]) + "\n", encoding="utf-8")
        return path

    def test_stream_identity(self):
        for p in (BN254_FR, BN254_FQ):
            rows = [[[[1, "0x1"], [3, str(p-1)]], [[0, "1"]], [[2, "2"]]], [[], [], []]]
            with tempfile.TemporaryDirectory() as tmp:
                path = self.write(Path(tmp), p, rows)
                actual = stream_audit(path)
                shape = {"format": "zkl-r1cs-v1", "modulus": str(p), "wires": 4,
                         "public": [1, 2], "rows": rows}
                self.assertEqual(actual["canonical_shape_sha256"], digest(shape))
                self.assertEqual(actual["canonical_nonzeros"], [2, 1, 1])

    def test_truncation_and_noncanonical(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                stream_audit(self.write(root, BN254_FR, [], 1))
            for terms in ([[2, "1"], [1, "1"]], [[1, "1"], [1, "1"]],
                          [[4, "1"]], [[1, "0"]], [[1, str(BN254_FR)]]):
                with self.assertRaises(ValueError):
                    stream_audit(self.write(root, BN254_FR, [[terms, [], []]]))

    def test_null_and_trailing_records_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(Path(tmp), BN254_FR, [])
            with path.open("ab") as stream:
                stream.write(b"null\n")
            with self.assertRaises(ValueError):
                stream_audit(path)
            path = self.write(Path(tmp), BN254_FR, [[{}, [], []]])
            with self.assertRaises(ValueError):
                stream_audit(path)


if __name__ == "__main__":
    unittest.main()
