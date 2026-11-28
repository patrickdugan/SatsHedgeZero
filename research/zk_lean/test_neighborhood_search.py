import unittest

from audit import BN254_FR, digest
from neighborhood_search import Problem, Search
from poly_certificate import verify
from test_poly_certificate import fixture


class NeighborhoodTests(unittest.TestCase):
    def test_every_tier_and_field(self):
        for p in (7, 11, BN254_FR):
            for degree in range(3):
                a, b = fixture(p, f"degree{degree}", 3)
                problem = Problem(a, b, len(a["rows"]) - 1, (digest(a), digest(b)))
                state = Search(problem)
                for key in problem.keys:
                    if state.solved:
                        break
                    state.offer(key)
                cert = state.certificate()
                self.assertIsNotNone(cert)
                verify(a, b, cert, digest(a), digest(b))
                self.assertGreater(state.counts()["columns"], 0)

    def test_essential_and_invalid_actions(self):
        a, b = fixture(7, "essential")
        problem = Problem(a, b, len(a["rows"]) - 1, (digest(a), digest(b)))
        state = Search(problem)
        state.offer(problem.keys[0])
        with self.assertRaises(ValueError):
            state.offer(problem.keys[0])
        with self.assertRaises(ValueError):
            state.offer((99, ()))
        for key in problem.keys[1:]:
            state.offer(key)
        self.assertIsNone(state.certificate())


if __name__ == "__main__":
    unittest.main()
