import unittest

import spot_mm


class T(unittest.TestCase):
    def test_selftest(self):
        # Ladder sides, lot and tick rounding, exact fill amounts, and the shared Rust/JS
        # SpotIntent vector (ui/venue/test/spot_vector.json).
        spot_mm.selftest()

    def test_no_bid_below_zero(self):
        pair = {"pair": "c4" * 32, "lot_sats": 1000, "tick": 100_000, "quote": {"decimals": 6, "code": "USDT"}}
        self.assertEqual([b for b, _, _ in spot_mm.plan_quotes(0, pair, levels=1)], [False])


if __name__ == "__main__":
    unittest.main()
