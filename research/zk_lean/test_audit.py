import unittest
from itertools import product

from audit import canonical, check, digest, lean_source
from clearing_spec import Lane, clear, prorata


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.shape = {"format": "zkl-r1cs-v1", "modulus": "7", "wires": 3,
                      "public": [1, 2], "rows": [[[[1, "1"]], [[1, "1"]], [[2, "1"]]]]}

    def test_assignment(self):
        self.assertEqual(check(self.shape, ["1", "2", "4"], ["2", "4"]), [])
        self.assertEqual(check(self.shape, ["1", "2", "3"], ["2", "3"]), [0])
        with self.assertRaises(ValueError):
            check(self.shape, ["1", "2", "4"], ["2", "3"])

    def test_canonical(self):
        other = canonical(self.shape)
        other["rows"][0][0] = [[1, "0x02"], [1, "6"]]
        self.assertEqual(digest(self.shape), digest(other))
        self.assertIn("def exportedShape", lean_source(self.shape))
        other["rows"][0][0] = [[1, "7"]]
        with self.assertRaises(ValueError):
            canonical(other)

    def test_prorata(self):
        for amounts in product(range(5), repeat=3):
            for n in range(sum(amounts) + 1):
                out = prorata(n, amounts)
                self.assertEqual(sum(out), n)
                self.assertTrue(all(0 <= a <= b for a, b in zip(out, amounts)))
        self.assertEqual(prorata(2, [3, 3, 3]), [2, 0, 0])

    def test_clearing_priority(self):
        a, b, c = ("a", 0), ("b", 0), ("c", 0)
        out = clear(0, 1, 0, {a: 3, c: 4}, [Lane(a, -12, 5), Lane(b, 6, 0)])
        self.assertEqual(out["rows"][0]["collected"], 5)
        self.assertEqual(out["rows"][0]["own_claim_used"], 3)
        self.assertEqual(out["fund_absorbed"], 1)
        self.assertEqual(out["haircut"], 3)
        self.assertEqual(out["claim_haircuts"], [(c, 2)])
        self.assertEqual(out["rows"][1]["paid"], 5)
        self.assertEqual(out["claims"], {c: 2})

    def test_legacy_negative_cash(self):
        a = ("a", 0)
        out = clear(-5, 0, 0, {}, [Lane(a, 2, 0)])
        self.assertEqual(out["cash"], -5)
        self.assertEqual(out["claims"], {a: 2})


if __name__ == "__main__":
    unittest.main()
