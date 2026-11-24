"""Unit tests for the SHZ-LV study (synthetic fixtures only, no archive data)."""
import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import common  # noqa: E402
import engine  # noqa: E402


def test_engine_selftest():
    engine.selftest()


def _write_hour(dirpath, day, hh, mids, rng):
    n = 3600
    nf = 180_000
    mid_fine = np.repeat(mids, 50)[:nf]
    D, S = len(common.DELAYS_MS), len(common.SIZES_USD)
    frac = np.ones((n, 2, D, S), np.float32)
    cost = (rng.random((n, 2, D, S)) * 2).astype(np.float32)
    np.savez(dirpath / f"{day}-{hh:02d}.npz", mid_fine=mid_fine, arr_valid=np.ones(n, bool), arr_mid=mids,
             spread_bps=np.full(n, 0.2), depth_usd=np.full((n, 4), 1e6, np.float32), fill_frac=frac, cost_bps=cost,
             clean=np.array(True), counts=np.array("{}"), recorder_lag_q=np.zeros(4))


@pytest.fixture
def synthetic_cache(tmp_path, monkeypatch):
    import features
    monkeypatch.setattr(features, "CACHE", tmp_path)
    rng = np.random.default_rng(1)
    d = tmp_path / "hours" / "received" / "BTC"
    d.mkdir(parents=True)
    mids = 100_000 * np.exp(np.cumsum(rng.normal(0, 1e-4, 86_400)))
    for hh in range(24):
        _write_hour(d, "2026-10-11", hh, mids[hh * 3600:(hh + 1) * 3600], rng)
    return tmp_path, mids


def test_features_are_causal(synthetic_cache, tmp_path):
    import features
    base = features.assemble_day("BTC", "2026-10-11")
    # Perturb the future (hour 12 onward) and check features before 12:00 are unchanged.
    d = tmp_path / "hours" / "received" / "BTC"
    z = dict(np.load(d / "2026-10-11-12.npz"))
    z["arr_mid"] = z["arr_mid"] * 1.01
    z["mid_fine"] = z["mid_fine"] * 1.01
    np.savez(d / "2026-10-11-12.npz", **z)
    pert = features.assemble_day("BTC", "2026-10-11")
    cut = 12 * 3600
    a, b = base["feat"][:cut], pert["feat"][:cut]
    assert np.array_equal(np.isnan(a), np.isnan(b))
    assert np.allclose(np.nan_to_num(a), np.nan_to_num(b))
    # ...while the ex-post future returns just before the cut do change.
    assert not np.allclose(np.nan_to_num(base["fut"][cut - 5]), np.nan_to_num(pert["fut"][cut - 5]))
    # r1 at the cut uses mid at the cut (book before t) and the previous second.
    assert np.isclose(pert["feat"][cut, features.FEATURES.index("r1")],
                      np.log(pert["mid"][cut] / pert["mid"][cut - 1]) * 1e4, rtol=1e-4)


def test_dirty_hour_dropped(synthetic_cache, tmp_path):
    import features
    d = tmp_path / "hours" / "received" / "BTC"
    z = dict(np.load(d / "2026-10-11-03.npz"))
    z["clean"] = np.array(False)
    np.savez(d / "2026-10-11-03.npz", **z)
    day = features.assemble_day("BTC", "2026-10-11")
    assert day["hours"]["2026-10-11T03"] == "dirty"
    assert not day["valid"][3 * 3600:4 * 3600].any() and day["valid"][4 * 3600:5 * 3600].all()


def test_tier_winners_and_completion():
    import analysis
    n = 3
    D, S = len(common.DELAYS_MS), len(common.SIZES_USD)
    day = dict(frac=np.ones((n, 2, D, S)), cost=np.zeros((n, 2, D, S)))
    di = analysis.DI
    # decision 0: premium saves 3 bp gross -> premium wins net of 2 bp fee
    day["cost"][0, 0, di[300], 1] = 3.0; day["cost"][0, 0, di[200], 1] = 3.0
    # decision 1: intermediate saves 1 bp -> intermediate (0.5 fee) beats premium (2 bp)
    day["cost"][1, 0, di[300], 1] = 1.0; day["cost"][1, 0, di[100], 1] = 1.0
    # decision 2: standard does not fully fill -> not common; completion charges the limit
    day["frac"][2, 0, di[300], 1] = 0.5; day["cost"][2, 0, di[300], 1] = 1.0
    t = np.arange(n); si = np.zeros(n, int)
    net, gross, full, known = analysis.tier_matrix(day, t, si, 1, common.SHZ_TIERS)
    common_ = known.all(1) & full.all(1)
    w = analysis.winners(net, common_)
    assert list(w) == [2, 1, -1]
    netc, *_ = analysis.tier_matrix(day, t, si, 1, common.SHZ_TIERS, completion=True)
    assert np.isclose(netc[2, 0], 0.5 * 1.0 + 0.5 * common.LIMIT_BPS)
    assert analysis.winners(netc, np.ones(n, bool))[2] == 1  # cheapest full-fill alternative after fee


def test_threshold_policy_learns_rule():
    import policy
    rng = np.random.default_rng(3)
    n = 20_000
    X = rng.normal(size=(n, len(policy.FEATURES)))
    v = np.abs(X[:, policy.FI["vol_score"]])
    sav = np.zeros((n, 3))
    sav[:, 1] = np.where(v > 2.0, 1.0, -0.5)
    sav[:, 2] = np.where(v > 3.0, 3.0, -2.0)
    X[:, policy.FI["vol_score"]] = v
    rows = [dict(day="d", X=X, sav=sav, savc=sav, common=np.ones(n, bool), ckn=np.ones(n, bool), vol=np.ones(n))]
    p = policy.Threshold().fit(rows)
    assert p.rule[0] == "vol_score"
    ch = p.choose(X)
    assert (sav[np.arange(n), ch] >= 0).mean() > 0.95
    assert policy.FreeOnly().fit(rows).choose(X).sum() == 0


def test_breakeven_monotone():
    import shz_model
    a = shz_model.breakeven(0.1, 1, 3)["system"]
    b = shz_model.breakeven(0.2, 1, 3)["system"]
    assert a > b > 0
    assert shz_model.breakeven(0.0, 1, 3)["system"] is None
    assert np.isclose(shz_model.fee_rate_bps(0, 1, 0), 2.0) and np.isclose(shz_model.fee_rate_bps(1, 0, 0), 0.5)


def test_revenue_bucket_share():
    import revenue
    top = [dict(rate_ppm=280.0, notional_usd=10), dict(rate_ppm=196.0, notional_usd=5), dict(rate_ppm=50.0, notional_usd=3)]
    assert revenue.bucket_share(top, 100, revenue.PREMIUM_TAKER_PPM) == 0.15
    assert revenue.bucket_share(top, 100, (revenue.PLUS_PPM,)) == 0.03
