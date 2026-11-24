"""Synthetic-fixture tests. Run: python -m unittest research/public_l2/test_immediacy.py -v"""
import copy
import math
import random
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import immediacy as im  # noqa: E402
import pilot  # noqa: E402


def levels(k, qty_bid=1000, qty_ask=1000, base=10000, gap=2):
    bid0 = base + k
    return ([("bid", (bid0 - i) / 100, qty_bid) for i in range(5)] +
            [("ask", (bid0 + gap + i) / 100, qty_ask) for i in range(5)])


def trending_messages(n, qty_bid=lambda k: 1000, no_bid=lambda k: False, jitter=None):
    """Mid rises one cent per second; update k lands 1 ms before second k."""
    msgs = [(-2, "snapshot", 1, None, levels(0, qty_bid(0)))]
    seq = 1
    for k in range(1, n + 2):
        old = levels(k - 1, qty_bid(k - 1))
        zero = [(s, p, 0) for s, p, _ in old]
        new = levels(k, qty_bid(k))
        if no_bid(k):
            new = [x for x in new if x[0] == "ask"]
        msgs.append((k * 1000 - 1, "update", seq + 1, seq, zero + new))
        seq += 1
    if jitter is not None:
        msgs = [m if m[0] < jitter else (m[0], m[1], m[2], m[3],
                [(s, p + random.uniform(-.05, .05), q * random.uniform(.2, 3)) for s, p, q in m[4]])
                for m in msgs]
    return msgs


def expected_entry(k):
    ask = (10000 + k + 2) / 100
    return ask


class Causality(unittest.TestCase):
    def test_features_ignore_future_rows(self):
        random.seed(3)
        n = 80
        base = trending_messages(n)
        t0 = 40000
        alt = trending_messages(n, jitter=t0)
        tr1, tr2 = [], []
        im.run(pilot.Book(base), 0, n * 1000, trace=tr1)
        im.run(pilot.Book(alt), 0, n * 1000, trace=tr2)
        a = {T: (s, f) for T, s, f in tr1}
        b = {T: (s, f) for T, s, f in tr2}
        checked = 0
        for T in a:
            if T <= t0:
                self.assertEqual(a[T], b[T], T)
                checked += 1
        self.assertGreater(checked, 30)
        self.assertTrue(any(T not in b or a[T] != b[T] for T in a if T > t0 + 2000))

    def test_congestion_not_a_feature(self):
        tr = []
        im.run(pilot.Book(trending_messages(40)), 0, 40000, trace=tr)
        self.assertTrue(tr)
        for _, _, f in tr:
            self.assertNotIn("client_request_congestion", f)
            self.assertIsNone(f["xmkt"])
        self.assertEqual(im.UNAVAILABLE, ("client_request_congestion",))

    def test_xmarket_beta_excludes_current_pair(self):
        xm = im.XMarket(window=300, min_pairs=3)
        for rb, re in ((2, 1), (4, 2), (6, 3)):
            xm.residual(rb, re)
        # beta from the first three pairs is exactly 2; the current outlier cannot move it
        self.assertAlmostEqual(xm.residual(100.0, 1.0), 98.0)
        self.assertIsNone(im.XMarket(min_pairs=3).residual(1, 1))


class Accounting(unittest.TestCase):
    N = 100

    def run_book(self, **kw):
        return im.run(pilot.Book(trending_messages(self.N, **kw)), 0, self.N * 1000)

    def test_savings_equal_negative_fee_when_book_static(self):
        cells = self.run_book()["all|all"]
        n = cells["common"]
        self.assertGreater(n, 80)
        # same fill price at every delay: net saving = -fee*ask/mid per decision
        self.assertAlmostEqual(cells["sum_mid"] / n, -.5, delta=.01)
        self.assertAlmostEqual(cells["sum_prem"] / n, -2.0, delta=.02)
        self.assertEqual(cells["win_free"], n)
        self.assertEqual(cells["win_prem"] + cells["win_mid"], 0)

    def test_closed_pnl_fee_and_spread(self):
        cells = self.run_book()["all|all"]
        for name, fee in (("free", 0.0), ("mid", .5), ("prem", 2.0)):
            exp_sum, exp_n = 0.0, 0
            for T in range(1000, (self.N - 1) * 1000, 1000):
                if T + 15000 >= (self.N - 1) * 1000:
                    continue
                k = T // 1000
                ep = expected_entry(k)
                xp = (10000 + k + 15) / 100          # exit hits the bid 15 s later
                exp_sum += (xp - ep) / ep * 10000 - 2 * fee
                exp_n += 1
            p = f"s_{name}_15_"
            self.assertEqual(cells[p + "closed"], exp_n)
            self.assertAlmostEqual(cells[p + "pnl"], exp_sum, places=6)
            self.assertEqual(cells[p + "unresolved"], 0)
        # paid tiers net of both legs differ from free by exactly 2*fee per entry
        d = cells["s_free_15_pnl"] / cells["s_free_15_closed"] - cells["s_prem_15_pnl"] / cells["s_prem_15_closed"]
        self.assertAlmostEqual(d, 4.0, places=6)

    def test_unresolved_exit_partial_and_missing_book(self):
        # exit at second 50: bid depth 5 units < 10 required -> partial -> unresolved with mark
        c = im.run(pilot.Book(trending_messages(self.N, qty_bid=lambda k: 1 if k == 50 else 1000)),
                   0, self.N * 1000)["all|all"]
        base = self.run_book()["all|all"]
        self.assertEqual(c["s_free_15_unresolved"], 1)
        self.assertEqual(c["s_free_15_marked"], 1)
        self.assertEqual(c["s_free_15_closed"], base["s_free_15_closed"] - 1)
        # unresolved exposure is not imputed as zero P&L
        k = 35
        ep = expected_entry(k)
        xp = (10000 + k + 15) / 100
        gone = (xp - ep) / ep * 10000
        self.assertAlmostEqual(base["s_free_15_pnl"] - c["s_free_15_pnl"], gone, places=6)
        # exit second with no bid at all: arrival state invalid -> unresolved, unmarked
        c2 = im.run(pilot.Book(trending_messages(self.N, no_bid=lambda k: k == 50)), 0, self.N * 1000)["all|all"]
        self.assertEqual(c2["s_free_15_unresolved"], 1)
        self.assertEqual(c2["s_free_15_unmarked"], 1)
        self.assertEqual(c2["s_free_15_marked"], 0)
        # entries at 50 and 51 also lose their arrival/prior state; plus the unresolved exit
        self.assertEqual(c2["s_free_15_closed"], base["s_free_15_closed"] - 3)

    def test_missed_entry_and_censoring(self):
        c = im.run(pilot.Book(trending_messages(self.N, no_bid=lambda k: k >= 90)), 0, self.N * 1000)["all|all"]
        self.assertEqual(c["s_free_15_entries"] - c["s_free_15_filled"], 0)  # asks remain
        base = self.run_book()["all|all"]
        self.assertEqual(base["s_free_60_censored"] + base["s_free_60_closed"] + base["s_free_60_unresolved"],
                         base["s_free_60_filled"])
        self.assertGreater(base["s_free_60_censored"], 0)


class PolicyAndSplits(unittest.TestCase):
    def cell(self, **kw):
        return Counter(kw)

    def test_train_policy_shrinkage_and_min_n(self):
        cells = {"f|1": self.cell(common=1000, sum_mid=300.0, sum_prem=1000.0),   # shrunk .27 / .91 -> prem
                 "f|2": self.cell(common=50, sum_mid=500.0, sum_prem=500.0),     # below min_n -> free
                 "f|3": self.cell(common=1000, sum_mid=-5.0, sum_prem=-9.0)}     # negative -> free
        pol = im.train_policy(cells, "f")
        self.assertEqual(pol["f|1"][0], "prem")
        self.assertAlmostEqual(pol["f|1"][1], 1000 / 1100)
        self.assertEqual(pol["f|2"][0], "free")
        self.assertEqual(pol["f|3"][0], "free")

    def test_fold_sets_chronological(self):
        by = {d: {h: {"all|all": Counter(common=1, tag_hour=h, tag_day=int(d[-2:]))} for h in range(24)} for d in im.DAYS}
        folds = im.fold_sets(by)
        label, train, test = folds[0]
        self.assertEqual(label, "day1_to_day2")
        self.assertEqual(train["all|all"]["tag_day"], 11 * 24)
        self.assertEqual(test["all|all"]["tag_day"], 23 * 24)
        for label, train, test in folds[1:]:
            o = int(label[-2:])
            self.assertEqual(train["all|all"]["common"], o)
            self.assertEqual(test["all|all"]["common"], im.FOLD_HOURS)
            # train hours are exactly 0..o-1, test hours o..o+5: tag_hour sums prove disjoint chronology
            self.assertEqual(train["all|all"]["tag_hour"], sum(range(o)))
            self.assertEqual(test["all|all"]["tag_hour"], sum(range(o, o + im.FOLD_HOURS)))

    def test_precision_recall_and_revenue_arithmetic(self):
        test = {"f|1": self.cell(dir=100, common=100, sum_mid=0, sum_prem=60.0, pos_prem=70,
                                 win_free=40, win_mid=10, win_prem=50, w_common=2000.0, w_dir=2500.0,
                                 ww_free=800.0, ww_mid=300.0, ww_prem=900.0),
                "f|2": self.cell(dir=50, common=50, win_free=30, win_mid=10, win_prem=10, w_common=1000.0,
                                 ww_free=600.0, ww_mid=200.0, ww_prem=200.0)}
        pol = {"f|1": ("prem", .5), "f|2": ("free", 0.0)}
        e = im.evaluate(pol, test, "f")
        z = im.finalize(e)
        a = z["achievable_policy"]
        self.assertEqual(a["selected_counts"], {"free": 50, "mid": 0, "prem": 100})
        self.assertAlmostEqual(a["paid_precision_paid_winner"], 60 / 100)          # (10+50)/100
        self.assertAlmostEqual(a["paid_recall"], 60 / 80)                         # 60 of (10+50+10+10)
        self.assertAlmostEqual(a["per_tier"]["prem"]["mean_net_saving_bps_when_selected"], .6)
        self.assertAlmostEqual(a["per_tier"]["prem"]["exact_winner_precision"], .5)
        self.assertAlmostEqual(a["policy_mean_net_saving_bps"], 60 / 150)
        r = z["oracle_revenue"]
        # retrospective: fee_w = (300+200)*0.5 + (900+200)*2 = 2450 -> /1e4 * .7
        self.assertAlmostEqual(r["retrospective_optimal_usd"], 2450 / 10000 * .7)
        # achievable: cell1 prem on 2000 -> 4000; cell2 free -> 0
        self.assertAlmostEqual(r["achievable_policy_usd"], 4000 / 10000 * .7)
        self.assertEqual(r["trade_prints_available"], False)
        # calibration bucket for pred .5 sits at bisect_left(CAL_EDGES,.5)=3
        cal = a["calibration"]
        self.assertEqual(len(cal), 1)
        self.assertAlmostEqual(cal[0]["mean_realized_bps"], .6)

    def test_strategy_report_unresolved_not_zero(self):
        e = Counter({"strat_15_entries": 10, "strat_15_filled": 8, "strat_15_closed": 5, "strat_15_unresolved": 2,
                     "strat_15_censored": 1, "strat_15_pnl": -10.0, "strat_15_pnl_sq": 30.0,
                     "strat_15_midmove": 5.0, "strat_15_mark": -7.0, "strat_15_marked": 2})
        s = im.strategy(e, 0.5)["15"]
        self.assertEqual(s["missed_entry_fills"], 2)
        self.assertAlmostEqual(s["mean_closed_net_bps"], -2.0)      # 5 closed only, 2 unresolved excluded
        self.assertEqual(s["unresolved_exits"], 2)
        self.assertAlmostEqual(s["unresolved_marked_to_mid_mean_bps"], -3.5)
        self.assertAlmostEqual(s["expected_net_usd_per_day_5"], 5 * -2.0 / 10000 * 1000)
        # (midmove - (pnl + 2*fee*closed)) / closed = (5 - (-10 + 5)) / 5
        self.assertAlmostEqual(s["mean_entry_exit_cost_ex_fee_bps"], 2.0)


if __name__ == "__main__":
    unittest.main()
