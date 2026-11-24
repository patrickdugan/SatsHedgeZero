#!/usr/bin/env python3
"""Causal tier-selection policies: train on chronological development days,
freeze, evaluate on held-out days.

A decision is (second t, side) in the momentum cohort for a fixed notional.
Policy inputs are the causal features at t (features.FEATURES), with
directional features sign-adjusted to the decision side. The training target
for tier j is net saving vs standard = net cost(standard) - net cost(j) on
decisions where every tier fully fills ("common"). Evaluation reports mean
held-out net saving per common decision against the free-only control, the
completion variant (unfilled remainder at the IOC limit), the ex-post oracle,
and day-block bootstrap intervals. Realised volume weights are used only to
weight evaluation, never as inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import pickle
from pathlib import Path

import numpy as np

from analysis import DI, FI, TIERSETS, decisions, tier_matrix
from common import SIZES_USD
from features import FEATURES, cached_day

SCORE_CUTS = (.1, .25, .5, 1., 2., 5., 10., 20.)
DIRECTIONAL = ("r1", "r5", "r30", "flow1_signed", "imb10", "xdiv5")
THRESH_FEATURES = ("vol_score", "rv60", "abs_r1", "spread_bps", "flow_accel", "flow5_usd", "depletion", "liq60_usd")
RNG = np.random.default_rng(7)


def design(day, t, si):
    X = day["feat"][t].astype(np.float64).copy()
    sign = np.where(si == 0, 1.0, -1.0)
    for f in DIRECTIONAL:
        X[:, FI[f]] *= sign
    for f in ("depth10_usd", "flow5_usd", "flow60_usd", "liq60_usd"):
        X[:, FI[f]] = np.log1p(np.maximum(X[:, FI[f]], 0))
    return X


def collect(sym, days, size, tiers, clock="received"):
    rows = []
    for dname in days:
        d = cached_day(sym, dname, clock)
        if not d["valid"].any():
            continue
        t, si = decisions(d, "momentum")
        s_idx = SIZES_USD.index(size)
        net, gross, full, known = tier_matrix(d, t, si, s_idx, tiers)
        netc, _, _, knownc = tier_matrix(d, t, si, s_idx, tiers, completion=True)
        common = known.all(1) & full.all(1)
        vol = np.nan_to_num(np.where(si == 0, d["buy_usd"][t], d["sell_usd"][t]))
        rows.append(dict(day=dname, X=design(d, t, si), sav=net[:, :1] - net, savc=netc[:, :1] - netc,
                         common=common, ckn=knownc.all(1), vol=vol))
    return rows


def cat(rows, key):
    return np.concatenate([r[key] for r in rows])


# ---------------------------------------------------------------- policies
class FreeOnly:
    name = "free_only"
    def fit(self, rows): return self
    def choose(self, X): return np.zeros(len(X), int)
    def spec(self): return {}


class ScoreBins:
    """PR #30 policy: fixed vol_score bins, train mean net saving per bin."""
    name = "pr30_score_bins"
    def fit(self, rows):
        X, S, C = cat(rows, "X"), cat(rows, "sav"), cat(rows, "common")
        b = np.searchsorted(SCORE_CUTS, X[:, FI["vol_score"]], side="left")
        self.choice = []
        for k in range(len(SCORE_CUTS) + 1):
            sel = b == k
            n = (sel & C).sum()
            ch = 0
            if n >= 100 and n >= .95 * sel.sum():
                m = S[sel & C].mean(0)
                ch = int(np.argmax(m))
            self.choice.append(ch)
        return self
    def choose(self, X):
        v = X[:, FI["vol_score"]]
        b = np.searchsorted(SCORE_CUTS, v, side="left")
        out = np.array(self.choice)[b]
        out[np.isnan(v)] = 0
        return out
    def spec(self): return dict(cuts=SCORE_CUTS, choice=self.choice)


class Threshold:
    """Best single-feature two-level threshold rule chosen on training data."""
    name = "threshold"
    QS = (0.9, 0.97, 0.99, 0.997, 0.999, 0.9997, 0.9999)
    def fit(self, rows):
        X, S, C = cat(rows, "X"), cat(rows, "sav"), cat(rows, "common")
        Xc, Sc = X[C], S[C]
        best = (0.0, None)
        for f in THRESH_FEATURES:
            v = Xc[:, FI[f]]
            ok = np.isfinite(v)
            if ok.sum() < 1000:
                continue
            qs = np.quantile(v[ok], self.QS)
            for i, lo in enumerate(qs):
                for hi in list(qs[i:]) + [np.inf]:
                    ch = np.where(v >= hi, 2, np.where(v >= lo, 1, 0))
                    ch[~ok] = 0
                    gain = Sc[np.arange(len(Sc)), ch].mean()
                    if gain > best[0] + 1e-12:
                        best = (gain, (f, float(lo), float(hi)))
        self.rule = best[1]
        self.train_gain = best[0]
        return self
    def choose(self, X):
        if self.rule is None:
            return np.zeros(len(X), int)
        f, lo, hi = self.rule
        v = X[:, FI[f]]
        ch = np.where(v >= hi, 2, np.where(v >= lo, 1, 0))
        ch[~np.isfinite(v)] = 0
        return ch
    def spec(self): return dict(rule=self.rule, train_mean_gain_bps=self.train_gain)


class GBM:
    """Gradient-boosted net-saving regressors; margin tuned on the last 25% of
    training days (chronological), then refit on all training days."""
    name = "gbm"
    MARGINS = (0.0, 0.1, 0.25, 0.5, 1.0, 2.0)
    def _fit_models(self, rows):
        from sklearn.ensemble import HistGradientBoostingRegressor
        X, S, C = cat(rows, "X"), cat(rows, "sav"), cat(rows, "common")
        Xc, Sc = X[C], S[C]
        if len(Xc) > 600_000:
            idx = RNG.choice(len(Xc), 600_000, replace=False)
            Xc, Sc = Xc[idx], Sc[idx]
        models = []
        for j in (1, 2):
            m = HistGradientBoostingRegressor(max_iter=200, learning_rate=0.05, max_leaf_nodes=31,
                                              min_samples_leaf=200, l2_regularization=1.0, random_state=0)
            m.fit(Xc, Sc[:, j])
            models.append(m)
        return models
    def _choose(self, models, X, margin):
        p = np.stack([np.zeros(len(X))] + [m.predict(X) for m in models], 1)
        p[:, 1:] -= margin
        return np.argmax(p, 1)
    def fit(self, rows):
        k = max(1, len(rows) // 4)
        tr, va = rows[:-k], rows[-k:]
        self.margin = 0.0
        if tr:
            ms = self._fit_models(tr)
            Xv, Sv, Cv = cat(va, "X"), cat(va, "sav"), cat(va, "common")
            gains = {m: Sv[Cv][np.arange(Cv.sum()), self._choose(ms, Xv[Cv], m)].mean() for m in self.MARGINS}
            self.margin = max(gains, key=gains.get)
            self.val_gains = {str(k): float(v) for k, v in gains.items()}
        self.models = self._fit_models(rows)
        return self
    def choose(self, X):
        return self._choose(self.models, X, self.margin)
    def spec(self):
        blob = pickle.dumps(self.models)
        return dict(margin=self.margin, validation_gains=getattr(self, "val_gains", None),
                    model_sha256=hashlib.sha256(blob).hexdigest(), features=FEATURES, directional=DIRECTIONAL)


POLICIES = (FreeOnly, ScoreBins, Threshold, GBM)


def evaluate(pol, rows, size, tiers):
    per = []
    for r in rows:
        ch = pol.choose(r["X"]) if pol is not None else None
        C = r["common"]
        n = len(C)
        if pol is None:  # ex-post oracle on common decisions
            ch = np.argmax(np.nan_to_num(r["sav"], nan=-np.inf), 1)
        g = r["sav"][np.arange(n), ch]
        gc = r["savc"][np.arange(n), ch]
        per.append(dict(day=r["day"], decisions=int(n), common=int(C.sum()),
                        gain_sum=float(np.nansum(g[C])), gain_completion_sum=float(np.nansum(gc[r["ckn"]])),
                        completion_known=int(r["ckn"].sum()),
                        vol_gain=float(np.nansum((g * r["vol"])[C])), vol_common=float(r["vol"][C].sum()),
                        chosen=[int((ch == j).sum()) for j in range(3)],
                        chosen_common_positive=int(((g > 0) & C & (ch > 0)).sum()),
                        usd_gain=float(np.nansum(g[C]) * size / 1e4)))
    def boot(num, den, B=2000):
        num, den = np.array(num, float), np.array(den, float)
        if den.sum() == 0:
            return None
        idx = RNG.integers(0, len(num), (B, len(num)))
        rr = num[idx].sum(1) / np.maximum(den[idx].sum(1), 1e-300)
        return dict(point=float(num.sum() / den.sum()), lo95=float(np.quantile(rr, .025)), hi95=float(np.quantile(rr, .975)))
    return dict(mean_net_saving_bps_common=boot([p["gain_sum"] for p in per], [p["common"] for p in per]),
                mean_net_saving_bps_completion=boot([p["gain_completion_sum"] for p in per], [p["completion_known"] for p in per]),
                volume_weighted_net_saving_bps=boot([p["vol_gain"] for p in per], [p["vol_common"] for p in per]),
                chosen_share={tiers[j][0]: sum(p["chosen"][j] for p in per) / max(sum(p["decisions"] for p in per), 1) for j in range(3)},
                paid_choices=sum(p["chosen"][1] + p["chosen"][2] for p in per),
                paid_choices_positive=sum(p["chosen_common_positive"] for p in per),
                usd_gain_per_day_per_decision_stream=sum(p["usd_gain"] for p in per) / max(len(per), 1),
                per_day=per)


def run_split(sym, train_days, test_days, size, tsname="shz_candidate", test_sym=None, freeze_dir=None, label=None):
    tiers = TIERSETS[tsname]
    tr = collect(sym, train_days, size, tiers)
    te = collect(test_sym or sym, test_days, size, tiers)
    out = dict(train_symbol=sym, test_symbol=test_sym or sym, train_days=[r["day"] for r in tr],
               test_days=[r["day"] for r in te], size_usd=size, tierset=tsname,
               train_decisions=int(sum(len(r["common"]) for r in tr)), test_decisions=int(sum(len(r["common"]) for r in te)),
               policies={})
    for P in POLICIES:
        pol = P().fit(tr)
        res = evaluate(pol, te, size, tiers)
        res["frozen_spec"] = pol.spec()
        res["in_sample"] = {k: v for k, v in evaluate(pol, tr, size, tiers).items() if k != "per_day"}
        out["policies"][P.name] = res
        if freeze_dir is not None:
            freeze_dir.mkdir(parents=True, exist_ok=True)
            spec = dict(policy=P.name, label=label, train_symbol=sym, train_days=out["train_days"], size_usd=size,
                        tierset=tsname, spec=pol.spec())
            (freeze_dir / f"{label}_{P.name}.json").write_text(json.dumps(spec, indent=1, default=float) + "\n")
            blob = pickle.dumps(pol, protocol=5)
            (freeze_dir / f"{label}_{P.name}.pkl").write_bytes(blob)
            man_p = freeze_dir / "MANIFEST.json"
            man = json.loads(man_p.read_text()) if man_p.exists() else dict(schema="shz-lv/frozen-policies/v1", policies=[])
            man["policies"] = [e for e in man["policies"] if e["file"] != f"{label}_{P.name}.pkl"]
            man["policies"].append(dict(file=f"{label}_{P.name}.pkl", sha256=hashlib.sha256(blob).hexdigest(), label=label,
                                        policy=P.name, train_symbol=sym, train_days=out["train_days"], size_usd=size, tierset=tsname))
            man_p.write_text(json.dumps(man, indent=1) + "\n")
    out["policies"]["ex_post_oracle"] = evaluate(None, te, size, tiers)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--symbol", required=True)
    ap.add_argument("--train", nargs=2, required=True, metavar=("FIRST", "LAST"))
    ap.add_argument("--test", nargs=2, required=True, metavar=("FIRST", "LAST"))
    ap.add_argument("--test-symbol")
    ap.add_argument("--size", type=int, default=1000)
    ap.add_argument("--tierset", default="shz_candidate")
    ap.add_argument("--freeze-dir", type=Path)
    ap.add_argument("--label", default="split")
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    rng = lambda f, l: [str(x) for x in np.arange(np.datetime64(f), np.datetime64(l) + np.timedelta64(1, "D"))]
    z = run_split(a.symbol, rng(*a.train), rng(*a.test), a.size, a.tierset, a.test_symbol, a.freeze_dir, a.label)
    a.output.write_text(json.dumps(z, indent=1, allow_nan=False, default=float) + "\n")
    for k, v in z["policies"].items():
        m = v["mean_net_saving_bps_common"]
        print(f"{a.label:24s} {k:16s} heldout_bps={m and round(m['point'], 4)} ci=({m and round(m['lo95'], 4)},{m and round(m['hi95'], 4)}) "
              f"paid={v['paid_choices']} pos={v['paid_choices_positive']}")


if __name__ == "__main__":
    main()
