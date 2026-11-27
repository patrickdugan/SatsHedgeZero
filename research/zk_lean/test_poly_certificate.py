import itertools
import random
import unittest

from audit import BN254_FR, canonical, check, digest
from poly_certificate import generate, search, verify


def lc(p, *terms):
    acc = {}
    for i, c in terms:
        acc[i] = (acc.get(i, 0) + c) % p
    return [[i, str(c)] for i, c in sorted(acc.items()) if c]


def fixture(p, family, k=1):
    one = lc(p, (0, 1))
    x, y, z = (lc(p, (i, 1)) for i in (1, 2, 3))
    if family == "degree0":
        rows = [[x, y, z], [lc(p, (1, k)), y, lc(p, (3, k))]]
    elif family == "degree1":
        rows = [[x, one, []], [x, lc(p, (2, k)), []]]
    elif family == "degree2":
        rows = [[x, y, z], [x, x, []], [z, lc(p, (3, k)), []]]
    elif family == "essential":
        rows = [[x, y, z], [z, lc(p, (3, k)), []]]
    else:
        raise ValueError(family)
    a = canonical({"format": "zkl-r1cs-v1", "modulus": str(p), "wires": 4,
                   "public": [1, 2, 3], "rows": rows})
    b = dict(a, rows=a["rows"][:-1])
    return a, b


def search_fixture(a, b, degree=2):
    return search(a, b, len(a["rows"]) - 1, digest(a), digest(b), degree)


class PolyTests(unittest.TestCase):
    def test_tiers_and_fields(self):
        for p in (7, 11, BN254_FR):
            for degree in range(3):
                a, b = fixture(p, f"degree{degree}", 3)
                for lower in range(degree):
                    self.assertIsNone(search_fixture(a, b, lower))
                c = search_fixture(a, b, degree)
                self.assertIsNotNone(c)
                self.assertEqual(c["degree"], degree)
                verify(a, b, c, digest(a), digest(b), degree)
            a, b = fixture(p, "essential")
            self.assertIsNone(search_fixture(a, b))

    def test_randomized_scale(self):
        rng = random.Random(12027)
        for p in (7, 11, BN254_FR):
            for family in ("degree0", "degree1", "degree2", "essential"):
                for _ in range(16):
                    a, b = fixture(p, family, rng.randrange(1, p))
                    c = search_fixture(a, b)
                    if family == "essential":
                        self.assertIsNone(c)
                    else:
                        self.assertEqual(c["degree"], int(family[-1]))
                        verify(a, b, c, digest(a), digest(b))

    def test_exhaustive(self):
        for p in (7, 11):
            for family in ("degree0", "degree1", "degree2", "essential"):
                a, b = fixture(p, family)
                before, after = [], []
                for aux in itertools.product(range(p), repeat=3):
                    w = ["1", *map(str, aux)]
                    if not check(a, w, w[1:]):
                        before.append(aux)
                    if not check(b, w, w[1:]):
                        after.append(aux)
                self.assertEqual(before == after, family != "essential")

    def test_mutations(self):
        a, b = fixture(7, "degree2")
        c = search_fixture(a, b)
        i, mon, k = c["multipliers"][0]
        mutations = [
            {"original_sha256": "0"*64}, {"target_index": 0}, {"degree": 1},
            {"multipliers": []}, {"multipliers": [[len(b["rows"]), mon, k]]},
            {"multipliers": [[i, [0], k]]}, {"multipliers": [[i, [4], k]]},
            {"multipliers": [[i, [2, 1], k]]}, {"multipliers": [[i, [1, 1, 1], k]]},
            {"multipliers": [[i, mon, "0"]]}, {"multipliers": [[i, mon, k]]*2},
            {"correction": [[[], "1"]]}, {"correction": [[[0], "1"]]},
        ]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify(a, b, {**c, **change}, digest(a), digest(b))
        with self.assertRaises(ValueError):
            verify(a, b, c, digest(a), digest(b), degree=1)

    def test_source_and_caps(self):
        a, b = fixture(7, "degree2")
        c = search_fixture(a, b)
        source, receipt = generate(a, b, c, digest(a), digest(b))
        self.assertIn("checked_poly_delete", source)
        self.assertFalse(receipt["lean_replayed"])
        self.assertFalse(receipt["production_accepted"])
        huge = dict(a, wires=100)
        repl = dict(b, wires=100)
        with self.assertRaisesRegex(ValueError, "column cap"):
            search_fixture(huge, repl)


if __name__ == "__main__":
    unittest.main()
