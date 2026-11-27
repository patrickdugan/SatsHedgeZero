import unittest

import options_mm


class T(unittest.TestCase):
    def test_selftest(self):
        # Black-76 put-call parity, inverse/linear unit conversion, quote sides, and the shared
        # Rust/JS IntentV7 and transfer vector (ui/venue/test/options_vector.json).
        options_mm.selftest()

    def test_quotes_skip_settled_and_near_expiries(self):
        s = {"kind": "call", "strike_usd": 100_000, "maturity_unix": 1_000, "asset": {"kind": "btc"}, "asset_code": "BTC", "id": "aa" * 32, "settled_price_usd": None, "event_id": "E"}
        self.assertEqual(options_mm.plan_quotes([s], 100_000, 980), [])  # under 30 s to maturity
        self.assertEqual(options_mm.plan_quotes([dict(s, settled_price_usd=101_000)], 100_000, 0), [])
        later = dict(s, id="cc" * 32, maturity_unix=2_000, event_id="F")
        self.assertEqual({q[0] for q in options_mm.plan_quotes([s, later], 100_000, 0)}, {"aa" * 32})  # nearest expiry only


if __name__ == "__main__":
    unittest.main()
