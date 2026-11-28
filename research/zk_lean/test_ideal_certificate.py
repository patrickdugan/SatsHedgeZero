import copy
import itertools
import random
import unittest

from audit import BN254_FR, canonical, check, digest
from ideal_certificate import generate, search, verify


def shape(p, rows, wires=4):
    return canonical({"format": "zkl-r1cs-v1", "modulus": str(p), "wires": wires,
                      "public": list(range(1, wires)), "rows": rows})


def row(p, coefficients):
    return [[[i, str(c % p)] for i, c in enumerate(coefficients) if c % p], [[0, "1"]], []]


def chain(p):
    return shape(p, [row(p, [0, -1, 1, 0]), row(p, [0, 0, -1, 1]), row(p, [0, -1, 0, 1])])


def delete(a, i):
    return {**a, "rows": a["rows"][:i] + a["rows"][i + 1:]}


def certificate(a, b, i):
    return search(a, b, i, digest(a), digest(b))


def verified(a, b, cert):
    return verify(a, b, cert, digest(a), digest(b))


class IdealCertificateTests(unittest.TestCase):
    def test_transitivity_and_exhaustive_assignments(self):
        for p in (7, 11):
            a, b = chain(p), delete(chain(p), 2)
            cert = certificate(a, b, 2)
            self.assertEqual(cert["weights"], [[0, "1"], [1, "1"]])
            self.assertEqual(cert["correction"], [[0, 2, "-1"]])
            verified(a, b, cert)
            for x in itertools.product(range(p), repeat=3):
                w = ["1", *map(str, x)]
                self.assertEqual(not check(a, w, w[1:]), not check(b, w, w[1:]))

    def test_bn254_no_enumeration(self):
        a, b = chain(BN254_FR), delete(chain(BN254_FR), 2)
        cert = certificate(a, b, 2)
        verified(a, b, cert)
        self.assertEqual(cert["correction"], [[0, 2, "-1"]])

    def test_quadratic_and_commutation(self):
        a = shape(7, [[[[1,"1"]], [[2,"1"]], [[3,"1"]]],
                      [[[2,"2"]], [[1,"3"]], [[3,"6"]]]])
        b = delete(a, 1)
        cert = certificate(a, b, 1)
        self.assertEqual(cert["weights"], [[0, "6"]])
        verified(a, b, cert)

    def test_missing_span_is_inconclusive(self):
        a = shape(7, [row(7, [0, 1, 0, 0]), row(7, [0, 0, 1, 0])])
        self.assertIsNone(certificate(a, delete(a, 1), 1))

    def test_zero_residual(self):
        a = shape(7, [[[[1,"1"]], [[0,"1"]], [[1,"1"]]]])
        cert = certificate(a, delete(a, 0), 0)
        self.assertEqual(cert["weights"], [])
        self.assertEqual(cert["correction"], [])

    def test_zero_mod_p_residual(self):
        a = shape(7, [[[[1,"2"]], [[0,"4"]], [[1,"1"]]]])
        cert = certificate(a, delete(a, 0), 0)
        self.assertEqual(cert["weights"], [])
        self.assertEqual(cert["correction"], [[0,1,"1"]])

    def test_certificate_mutations(self):
        a, b = chain(7), delete(chain(7), 2)
        cert = certificate(a, b, 2)
        mutants = []
        for key, value in [("original_sha256", "0" * 64), ("target_index", 0),
                           ("weights", [[0, "1"]]), ("weights", [[0, "1"], [1, "2"]]),
                           ("weights", [[0, "1"], [1, "1"], [1, "1"]]),
                           ("weights", [[0, "1"], [2, "1"]]),
                           ("correction", []), ("correction", [[0, 2, "1"]]),
                           ("correction", [[2, 0, "-1"]]), ("correction", [[0, 4, "-1"]])]:
            mutants.append({**cert, key: value})
        for mutant in mutants:
            with self.subTest(mutant=mutant), self.assertRaises(ValueError):
                verified(a, b, mutant)

    def test_pins_and_interface(self):
        a, b = chain(7), delete(chain(7), 2)
        with self.assertRaises(ValueError):
            search(a, b, 2, "0" * 64, digest(b))
        bad = {**b, "public": [1]}
        with self.assertRaises(ValueError):
            certificate(a, bad, 2)

    def test_generated_source(self):
        a, b = chain(7), delete(chain(7), 2)
        source, receipt = generate(a, b, certificate(a, b, 2), digest(a), digest(b))
        self.assertIn("checked_ideal_delete", source)
        self.assertNotIn("]!", source)
        self.assertFalse(receipt["lean_replayed"])
        self.assertFalse(receipt["production_accepted"])

    def test_random_span(self):
        rng = random.Random(20261127)
        for p in (7, 11, BN254_FR):
            for _ in range(64):
                matrix = [[rng.randrange(p) for _ in range(4)] for _ in range(3)]
                multipliers = [rng.randrange(p) for _ in matrix]
                target = [sum(k * r[j] for k, r in zip(multipliers, matrix)) % p for j in range(4)]
                a = shape(p, [row(p, r) for r in [*matrix, target]])
                b = delete(a, 3)
                cert = certificate(a, b, 3)
                self.assertIsNotNone(cert)
                verified(a, b, cert)


if __name__ == "__main__":
    unittest.main()
