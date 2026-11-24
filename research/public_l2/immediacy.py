#!/usr/bin/env python3
"""Conditional value-of-immediacy model on public L2 replays.

Two stages, both aggregate-only (no raw rows, no price sequences leave the hour):
  hour       replay one UTC hour, emit per-cell sufficient statistics
  aggregate  chronological policy fitting/evaluation over hourly files

Every feature at decision time T uses only book states built from events with
effective time strictly before T (pilot.Book.view contract) and grid history
at T-1s ... T-30s. Targets use later views and never feed back into features.
"""
from __future__ import annotations
from bisect import bisect_left
from collections import Counter, defaultdict, deque
from datetime import datetime, UTC
from hashlib import file_digest
from pathlib import Path
import argparse
import heapq
import json
import math
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pilot  # noqa: E402

GRID_MS = pilot.GRID_MS
NOTIONAL = 1000
LIMIT = .002
DEPTH_LEVELS = 5
# (name, venue delay ms, fee bps per leg). Same shz_candidate schedule as pilot.
TIERS = (("free", 300, 0.0), ("mid", 200, 0.5), ("prem", 100, 2.0))
HORIZONS = (15, 60)
ORACLE_SHARE = 0.70
LAMBDA = 100.0      # ridge shrinkage on cell means: sum / (n + LAMBDA)
MIN_N = 100         # minimum common fills in a training cell to leave free
DAYS = ("2026-10-11", "2026-11-23")
ORIGINS = (6, 12, 18)
FOLD_HOURS = 6
UNAVAILABLE = ("client_request_congestion",)
PRIMARY = "score_imb"
CAL_EDGES = (0.0, .1, .25, .5, 1.0)

# Fixed a-priori bin edges (never fitted).
EDGES = {
    "score": pilot.SCORE_CUTS,
    "imb": (-.5, -.2, .2, .5),
    "imb_acc1": (-.2, -.05, .05, .2),
    "imb_acc5": (-.2, -.05, .05, .2),
    "depl": (1e-9, .02, .1, .3),
    "repl": (1e-9, .02, .1, .3),
    "spread": (.05, .1, .2, .5, 1.0),
    "micro": (-.3, -.05, .05, .3),
    "vol1": (.1, .25, .5, 1., 2., 5.),
    "vol5": (.2, .5, 1., 2., 5.),
    "vol30": (.5, 1., 2., 5., 10.),
    "xmkt": (-2., -.5, .5, 2.),
}
FAMILIES = tuple(["all"] + [k for k in EDGES] + [PRIMARY])


def sign(x):
    return 1 if x > 0 else -1 if x < 0 else 0


def snap(book, state):
    """Top-of-book and top-N depth for one valid state; reads current sides."""
    b, a, mid = state
    bs, as_ = book.sides["bid"], book.sides["ask"]
    bd = sum(bs.depth[k] for k in heapq.nsmallest(DEPTH_LEVELS, bs.depth))
    ad = sum(as_.depth[k] for k in heapq.nsmallest(DEPTH_LEVELS, as_.depth))
    bq, aq = bs.depth[-b], as_.depth[a]
    micro = (b * aq + a * bq) / (bq + aq)
    imb = (bd - ad) / (bd + ad) if bd + ad > 0 else 0.0
    return dict(mid=mid, bid=b, ask=a, bd=bd, ad=ad, imb=imb,
                spread=10000 * (a - b) / mid, micro=10000 * (micro - mid) / mid)


def lret(x, y):
    return 10000 * math.log(x / y)


class XMarket:
    """Causal beta of BTC 1s return on second-market 1s return."""
    def __init__(self, window=300, min_pairs=60):
        self.pairs = deque(maxlen=window)
        self.sxy = self.sxx = 0.0
        self.min_pairs = min_pairs

    def residual(self, rb, re):
        """Residual with beta from pairs strictly before this one."""
        beta = None
        if len(self.pairs) >= self.min_pairs and self.sxx > 0:
            beta = self.sxy / self.sxx
        res = None if beta is None else rb - beta * re
        if len(self.pairs) == self.pairs.maxlen:
            ob, oe = self.pairs[0]
            self.sxy -= ob * oe
            self.sxx -= oe * oe
        self.pairs.append((rb, re))
        self.sxy += rb * re
        self.sxx += re * re
        return res


def features(hist, T, side, xres):
    """Features for a decision at T on `side`, from hist[T-lag] snapshots only."""
    s = hist[T]
    f = dict.fromkeys(EDGES)
    f["spread"] = s["spread"]
    f["micro"] = side * s["micro"]
    f["imb"] = side * s["imb"]
    p1, p5 = hist.get(T - 1000), hist.get(T - 5000)
    if p1:
        f["imb_acc1"] = side * (s["imb"] - p1["imb"])
        dkey = "ad" if side == 1 else "bd"
        prev, now = p1[dkey], s[dkey]
        if prev > 0:
            f["depl"] = max(0.0, (prev - now) / prev)
            f["repl"] = max(0.0, (now - prev) / prev)
    if p5:
        f["imb_acc5"] = side * (s["imb"] - p5["imb"])
    mids = [hist.get(T - 1000 * i) for i in range(31)]
    mids = [None if m is None else m["mid"] for m in mids]
    if mids[1] is not None:
        f["vol1"] = abs(lret(mids[0], mids[1]))
    if all(m is not None for m in mids[:6]):
        f["vol5"] = math.sqrt(sum(lret(mids[i], mids[i + 1]) ** 2 for i in range(5)))
    if all(m is not None for m in mids):
        f["vol30"] = math.sqrt(sum(lret(mids[i], mids[i + 1]) ** 2 for i in range(30)))
    anchors = [mids[1], mids[5], mids[30]]
    f["score"] = None if any(x is None for x in anchors) else max(
        abs(lret(mids[0], x)) / math.sqrt(lag) for x, lag in zip(anchors, (1, 5, 30)))
    f["xmkt"] = None if xres is None else side * xres
    return f


def bin_of(name, v):
    return "na" if v is None else str(bisect_left(EDGES[name], v))


def cell_keys(f):
    bins = {k: bin_of(k, f[k]) for k in EDGES}
    keys = ["all|all"] + [f"{k}|{bins[k]}" for k in EDGES]
    keys.append(f"{PRIMARY}|{bins['score']}|{bins['imb']}")
    return keys


def net_cost(e, side, mid, fee):
    return pilot.cost(e, side, mid, fee)


def run(book, start, end, eth=None, trace=None):
    """Replay [start,end). Returns {cell: Counter} sufficient statistics."""
    cells = defaultdict(Counter)
    hist, eth_hist, pend = {}, {}, defaultdict(list)
    xm = XMarket() if eth is not None else None
    delays = tuple(sorted(d for _, d, _ in TIERS))
    last_T = end - GRID_MS
    for T in range(start, end - GRID_MS, GRID_MS):
        state = book.view(T)
        hist.pop(T - 31000, None)
        eth_hist.pop(T - 31000, None)
        s = None if state is None else snap(book, state)
        hist[T] = s
        eth_mid = None
        if eth is not None:
            es = eth.view(T)
            eth_mid = None if es is None else es[2]
            eth_hist[T] = eth_mid
        due = pend.pop(T, [])
        prev = hist.get(T - 1000)
        valid = s is not None
        side = 0
        if valid and prev is not None:
            side = sign(s["mid"] - prev["mid"])
        f = keys = None
        mid = s["mid"] if valid else None
        if side:
            xres = None
            pe = eth_hist.get(T - 1000)
            if xm is not None and eth_mid is not None and pe is not None:
                xres = xm.residual(lret(mid, prev["mid"]), lret(eth_mid, pe))
            f = features(hist, T, side, xres)
            keys = cell_keys(f)
            if trace is not None:
                trace.append((T, side, dict(f)))
            dkey = "ad" if side == 1 else "bd"
            w = max(0.0, prev[dkey] - s[dkey]) * mid
            q = math.floor(NOTIONAL / mid * 100000) / 100000
            lim = mid * (1 + side * LIMIT)
        elif xm is not None and valid and prev is not None and eth_mid is not None \
                and eth_hist.get(T - 1000) is not None:
            xm.residual(lret(mid, prev["mid"]), lret(eth_mid, eth_hist[T - 1000]))
        res = {}
        for d in delays:
            v = book.view(T + d)
            if side:
                res[d] = book.fill(v, side, q, lim)
            for rec in due:
                if rec["delay"] == d:
                    settle(cells, rec, book, v, mid)
        for rec in due:
            if rec["delay"] not in delays:
                raise AssertionError("exit delay outside view set")
        if not side:
            continue
        record_decision(cells, keys, f, side, mid, w, res)
        for name, d, fee in TIERS:
            e = res[d]
            for H in HORIZONS:
                p = f"s_{name}_{H}_"
                for k in keys:
                    cells[k][p + "entries"] += 1
                if e[0] != "full":
                    continue
                for k in keys:
                    cells[k][p + "filled"] += 1
                te = T + H * 1000
                if te >= last_T:
                    for k in keys:
                        cells[k][p + "censored"] += 1
                    continue
                pend[te].append(dict(delay=d, tier=name, H=H, fee=fee, side=side, q=q,
                                     entry=e[1], entry_mid=mid, keys=keys))
    for recs in pend.values():
        for rec in recs:
            for k in rec["keys"]:
                cells[k][f"s_{rec['tier']}_{rec['H']}_censored"] += 1
    return cells


def record_decision(cells, keys, f, side, mid, w, res):
    nets = {}
    full = all(res[d][0] == "full" for _, d, _ in TIERS)
    if full:
        c300 = net_cost(res[300], side, mid, 0.0)
        nets["mid"] = c300 - net_cost(res[200], side, mid, 0.5)
        nets["prem"] = c300 - net_cost(res[100], side, mid, 2.0)
        costs = {n: net_cost(res[d], side, mid, fee) for n, d, fee in TIERS}
        winner = min(((costs[n], fee, n) for n, _, fee in TIERS))[2]
    for k in keys:
        c = cells[k]
        c["dir"] += 1
        c["w_dir"] += w
        for name, d, _ in TIERS:
            c[f"status_{name}_{res[d][0]}"] += 1
        if not full:
            continue
        c["common"] += 1
        c["w_common"] += w
        for t in ("mid", "prem"):
            c["sum_" + t] += nets[t]
            c["sq_" + t] += nets[t] ** 2
            c["pos_" + t] += nets[t] > 0
        c["win_" + winner] += 1
        c["ww_" + winner] += w


def settle(cells, rec, book, v, exit_mid_state_mid):
    """Resolve an exit at its arrival view. Non-full exits stay unresolved."""
    p = f"s_{rec['tier']}_{rec['H']}_"
    side, ep = rec["side"], rec["entry"]
    if exit_mid_state_mid is None:
        for k in rec["keys"]:
            cells[k][p + "unresolved"] += 1
            cells[k][p + "unmarked"] += 1
        return
    xlim = exit_mid_state_mid * (1 - side * LIMIT)
    e = book.fill(v, -side, rec["q"], xlim)
    if e[0] == "full":
        pnl = side * (e[1] - ep) / ep * 10000 - 2 * rec["fee"]
        mm = side * (exit_mid_state_mid - rec["entry_mid"]) / rec["entry_mid"] * 10000
        for k in rec["keys"]:
            c = cells[k]
            c[p + "closed"] += 1
            c[p + "pnl"] += pnl
            c[p + "pnl_sq"] += pnl * pnl
            c[p + "midmove"] += mm
    else:
        mark = side * (exit_mid_state_mid - ep) / ep * 10000 - rec["fee"]
        for k in rec["keys"]:
            c = cells[k]
            c[p + "unresolved"] += 1
            c[p + "mark"] += mark
            c[p + "marked"] += 1


# ---------------------------------------------------------------- aggregation

def merge(parts):
    out = defaultdict(Counter)
    for cells in parts:
        for k, c in cells.items():
            out[k].update(c)
    return out


def train_policy(cells, family, lam=LAMBDA, min_n=MIN_N):
    """cell -> (tier, shrunk mean net saving). Default free; no future data."""
    pol = {}
    for key, c in cells.items():
        if key.split("|")[0] != family:
            continue
        n = c["common"]
        best, bv = "free", 0.0
        if n >= min_n:
            for t in ("mid", "prem"):
                v = c["sum_" + t] / (n + lam)
                if v > bv:
                    best, bv = t, v
        pol[key] = (best, bv)
    return pol


def static_policy(tier):
    return {"all|all": (tier, 0.0)}


FEE = {n: fee for n, _, fee in TIERS}


def evaluate(policy, test, family):
    """Raw additive counts for one (policy, held-out cells)."""
    e = Counter()
    for key, c in test.items():
        if key.split("|")[0] != family:
            continue
        tier, pred = policy.get(key, ("free", 0.0))
        n = c["common"]
        e["held_dir"] += c["dir"]
        e["held_common"] += n
        for t in ("free", "mid", "prem"):
            e["win_" + t] += c["win_" + t]
            e["ww_" + t] += c["ww_" + t]
        e["w_common"] += c["w_common"]
        e["w_dir"] += c["w_dir"]
        e["sel_" + tier] += n
        e["sel_" + tier + "_w"] += c["w_common"]
        e["sel_" + tier + "_win_hit"] += c["win_" + tier]
        if tier != "free":
            e["sel_" + tier + "_net_sum"] += c["sum_" + tier]
            e["sel_" + tier + "_pos"] += c["pos_" + tier]
            e["paid_sel"] += n
            e["paid_sel_paid_winner"] += c["win_mid"] + c["win_prem"]
            if n:
                b = bisect_left(CAL_EDGES, pred)
                e[f"cal_{b}_n"] += n
                e[f"cal_{b}_pred_x_n"] += pred * n
                e[f"cal_{b}_real_sum"] += c["sum_" + tier]
        e["ach_fee_w"] += c["w_common"] * FEE[tier]
        e["retro_fee_w"] += c["ww_mid"] * FEE["mid"] + c["ww_prem"] * FEE["prem"]
        for H in HORIZONS:
            p = f"s_{tier}_{H}_"
            for fld in ("entries", "filled", "censored", "closed", "unresolved", "unmarked",
                        "marked", "pnl", "pnl_sq", "midmove", "mark"):
                e[f"strat_{H}_{fld}"] += c[p + fld]
    e["paid_winner_total"] = e["win_mid"] + e["win_prem"]
    return e


def finalize(e, days=1):
    n = e["held_common"]
    sel_n = {t: e["sel_" + t] for t in ("free", "mid", "prem")}
    out = dict(
        held_directional=e["held_dir"], held_common=n,
        retrospective_optimal=dict(
            counts={t: e["win_" + t] for t in ("free", "mid", "prem")},
            fractions_of_common={t: e["win_" + t] / n if n else None for t in ("free", "mid", "prem")}),
        achievable_policy=dict(
            selected_counts=sel_n,
            selected_fractions_of_common={t: sel_n[t] / n if n else None for t in sel_n},
            paid_selected=e["paid_sel"],
            paid_precision_paid_winner=e["paid_sel_paid_winner"] / e["paid_sel"] if e["paid_sel"] else None,
            paid_recall=e["paid_sel_paid_winner"] / e["paid_winner_total"] if e["paid_winner_total"] else None,
            per_tier={t: dict(selected=sel_n[t], exact_winner_precision=e[f"sel_{t}_win_hit"] / sel_n[t] if sel_n[t] else None,
                              exact_winner_recall=e[f"sel_{t}_win_hit"] / e["win_" + t] if e["win_" + t] else None,
                              mean_net_saving_bps_when_selected=e[f"sel_{t}_net_sum"] / sel_n[t] if sel_n[t] and t != "free" else None,
                              fraction_net_positive=e[f"sel_{t}_pos"] / sel_n[t] if sel_n[t] and t != "free" else None)
                      for t in sel_n},
            policy_mean_net_saving_bps=(e["sel_mid_net_sum"] + e["sel_prem_net_sum"]) / n if n else None,
            calibration=[dict(pred_bucket=b, n=e[f"cal_{b}_n"], mean_predicted_bps=e[f"cal_{b}_pred_x_n"] / e[f"cal_{b}_n"],
                              mean_realized_bps=e[f"cal_{b}_real_sum"] / e[f"cal_{b}_n"])
                         for b in range(len(CAL_EDGES) + 1) if e[f"cal_{b}_n"]]),
        oracle_revenue=revenue(e))
    return out


def revenue(e):
    """Fee * adopted notional * oracle share; weights are a depth-consumed proxy."""
    def r(fee_w):
        return fee_w / 10000 * ORACLE_SHARE
    return dict(weight_kind="depth_reduction_proxy_usd_top5_direction_side",
                trade_prints_available=False, oracle_share=ORACLE_SHARE,
                retrospective_optimal_usd=r(e["retro_fee_w"]), achievable_policy_usd=r(e["ach_fee_w"]),
                weighted_common_notional_usd=e["w_common"],
                retrospective_effective_fee_bps=e["retro_fee_w"] / e["w_common"] if e["w_common"] else None,
                achievable_effective_fee_bps=e["ach_fee_w"] / e["w_common"] if e["w_common"] else None,
                retrospective_adoption_weight={t: e["ww_" + t] for t in ("free", "mid", "prem")},
                achievable_adoption_weight={t: e["sel_" + t + "_w"] for t in ("free", "mid", "prem")})


def strategy(e, tier_fee_mean):
    out = {}
    for H in HORIZONS:
        g = lambda k: e[f"strat_{H}_{k}"]
        c = g("closed")
        mean = g("pnl") / c if c else None
        var = (g("pnl_sq") - g("pnl") ** 2 / c) / (c - 1) if c > 1 else None
        se = math.sqrt(max(var, 0) / c) if var is not None else None
        out[str(H)] = dict(entries=g("entries"), missed_entry_fills=g("entries") - g("filled"), filled=g("filled"),
                           closed=c, unresolved_exits=g("unresolved"), censored_by_hour_end=g("censored"),
                           unresolved_marked_to_mid_mean_bps=g("mark") / g("marked") if g("marked") else None,
                           unresolved_unmarked=g("unmarked"),
                           mean_closed_net_bps=mean, se_bps=se,
                           mean_mid_to_mid_bps=g("midmove") / c if c else None,
                           mean_entry_exit_cost_ex_fee_bps=(g("midmove") - (g("pnl") + 2 * tier_fee_mean * c)) / c if c else None,
                           expected_net_usd_per_day_5=None if mean is None else 5 * mean / 10000 * NOTIONAL,
                           expected_net_usd_per_day_10=None if mean is None else 10 * mean / 10000 * NOTIONAL)
    return out


def tier_fee_mean_of(policy_e):
    n = sum(policy_e["sel_" + t] for t in ("free", "mid", "prem"))
    return sum(policy_e["sel_" + t] * FEE[t] for t in ("free", "mid", "prem")) / n if n else 0.0


def fold_sets(by_day_hour):
    """(label, train cells, test cells): chronological day split + within-day rolling origins."""
    d1, d2 = DAYS
    folds = [("day1_to_day2", merge(by_day_hour[d1].values()), merge(by_day_hour[d2].values()))]
    for day in DAYS:
        hrs = by_day_hour[day]
        for o in ORIGINS:
            tr = [c for h, c in hrs.items() if h < o]
            te = [c for h, c in hrs.items() if o <= h < o + FOLD_HOURS]
            if tr and te:
                folds.append((f"{day}_origin{o:02d}", merge(tr), merge(te)))
    return folds


def aggregate(root):
    files = {}
    for p in sorted(Path(root).rglob("*.immediacy.json")):
        x = json.loads(p.read_text())
        assert x["schema"] == "shz/public-l2-immediacy-hour/v1" and x["no_private_data"]
        assert x["hour_utc"] not in files
        files[x["hour_utc"]] = x
    by = {d: {} for d in DAYS}
    coverage = []
    xm_hours = 0
    for day in DAYS:
        missing, dirty = [], []
        for h in range(24):
            hk = f"{day}T{h:02d}:00:00"
            x = files.get(hk)
            if x is None:
                missing.append(hk)
            elif not x["clean_sequence"]:
                dirty.append(hk)
            else:
                by[day][h] = {k: Counter(v) for k, v in x["cells"].items()}
                xm_hours += bool(x["cross_market_available"])
        coverage.append(dict(day=day, clean_hours=len(by[day]), missing_hours=missing, dirty_hours=dirty))
    folds = fold_sets(by) if all(by[d] for d in DAYS) else []
    report_folds = {}
    for label, train, test in folds:
        for fam in FAMILIES:
            if fam == "all":
                continue
            pol = train_policy(train, fam)
            report_folds.setdefault(fam, []).append((label, evaluate(pol, test, fam), pol, test))
    families = {}
    for fam, items in report_folds.items():
        chron = next(x for x in items if x[0] == "day1_to_day2")
        rolling = Counter()
        for _, ev, _, _ in (x for x in items if x[0] != "day1_to_day2"):
            rolling.update(ev)
        entry = dict(chronological_day1_to_day2=finalize(chron[1]), rolling_origin_within_day=finalize(rolling),
                     selected_cells_day1=sum(1 for t, _ in chron[2].values() if t != "free"))
        if fam == PRIMARY:
            entry["strategy_day1_to_day2"] = strategy(chron[1], tier_fee_mean_of(chron[1]))
            entry["strategy_rolling_origin"] = strategy(rolling, tier_fee_mean_of(rolling))
        families[fam] = entry
    static = {}
    if folds:
        test2 = merge(by[DAYS[1]].values())
        for t in ("free", "mid", "prem"):
            ev = evaluate(static_policy(t), test2, "all")
            static[t] = dict(strategy=strategy(ev, FEE[t]), oracle_revenue=revenue(ev))
        retro_vs = finalize(evaluate(static_policy("free"), test2, "all"))["retrospective_optimal"]
    else:
        retro_vs = None
    return dict(schema="shz/public-l2-immediacy-report/v1", days=DAYS, coverage=coverage,
                full_coverage=all(len(by[d]) == 24 for d in DAYS), cross_market_hours=xm_hours,
                unavailable_features=list(UNAVAILABLE), primary_family=PRIMARY,
                shrinkage_lambda=LAMBDA, min_cell_common=MIN_N, tiers=[list(t) for t in TIERS],
                families=families, static_tier_strategies_day2=static,
                retrospective_optimal_day2_all=retro_vs,
                evidence="historical observation: public Lighter BTC L2 visible-depth replay, receive clock, $1k probes; "
                         "no actual executions, no queue position, no client congestion, no trade prints",
                production_claim=False, actual_executions=False, exploratory=True)


# ------------------------------------------------------------------------ CLI

def hour_report(book_path, hour, eth_path=None, clock="received"):
    dt = datetime.fromisoformat(hour).replace(tzinfo=UTC)
    if dt.minute or dt.second or dt.microsecond:
        raise ValueError("hour aligned UTC required")
    start = int(dt.timestamp() * 1000)
    with book_path.open("rb") as f:
        digest = file_digest(f, "sha256").hexdigest()
    book = pilot.Book(pilot.messages(book_path, "BTC", start, clock))
    eth = eth_digest = None
    if eth_path is not None:
        eth = pilot.Book(pilot.messages(eth_path, "ETH", start, clock))
        with eth_path.open("rb") as f:
            eth_digest = file_digest(f, "sha256").hexdigest()
    cells = run(book, start, start + 3600000, eth)
    assert cells["all|all"]["dir"] > 0, "empty or unusable archive"
    clean = book.count["gaps"] == 0 and book.count["unseeded"] == 0
    return dict(schema="shz/public-l2-immediacy-hour/v1", hour_utc=hour, clock=clock, sha256=digest, bytes=book_path.stat().st_size,
                eth_sha256=eth_digest, cross_market_available=eth is not None and eth.count["gaps"] == 0,
                unavailable_features=list(UNAVAILABLE), sequence_counts=dict(book.count), clean_sequence=clean,
                cells={k: dict(c) for k, c in sorted(cells.items())}, no_private_data=True, exploratory=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hour")
    h.add_argument("--book", type=Path, required=True)
    h.add_argument("--eth-book", type=Path)
    h.add_argument("--hour", required=True)
    h.add_argument("--output", type=Path, required=True)
    a = sub.add_parser("aggregate")
    a.add_argument("--root", type=Path, required=True)
    a.add_argument("--output", type=Path, required=True)
    x = p.parse_args()
    if x.cmd == "hour":
        z = hour_report(x.book, x.hour, x.eth_book)
        x.output.write_text(json.dumps(z, allow_nan=False) + "\n")
        print(json.dumps(dict(hour=x.hour, clean=z["clean_sequence"], cross_market=z["cross_market_available"],
                              directional=z["cells"]["all|all"]["dir"], common=z["cells"]["all|all"].get("common", 0))))
    else:
        z = aggregate(x.root)
        x.output.write_text(json.dumps(z, indent=2, allow_nan=False) + "\n")
        prim = z["families"].get(PRIMARY)
        print(json.dumps(dict(full_coverage=z["full_coverage"], coverage=z["coverage"],
                              primary=None if prim is None else prim["chronological_day1_to_day2"]["achievable_policy"]["selected_counts"])))


if __name__ == "__main__":
    main()
