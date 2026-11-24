#!/usr/bin/env python3
"""Audit and summarize registered HFT-02A CSVs."""
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from statistics import mean

out = Path(sys.argv[1])
arms = {}
for path in sorted(out.glob("replay-*.csv")):
    with path.open(newline="") as f:
        raw = list(csv.DictReader(f))
    assert len(raw) == 568
    key = tuple(raw[0][k] for k in ("seed", "regime", "shards", "adoption"))
    assert key not in arms
    rows = {}
    for row in raw:
        assert tuple(row[k] for k in ("seed", "regime", "shards", "adoption")) == key
        assert len(row["intent_id"]) == 64
        ident = (row["kind"], int(row["id"]))
        assert ident not in rows
        for k in ("router", "arrival_us", "execution_us", "arrival_mark", "execution_mark",
                  "future_mark", "quantity", "limit", "fill_price", "filled_qty", "maker_fee_sats",
                  "taker_fee_sats", "oracle_due_sats", "router_due_sats", "long_margin_sats", "short_margin_sats"):
            row[k] = int(row[k])
        assert row["maker_fee_sats"] + row["taker_fee_sats"] == row["oracle_due_sats"] + row["router_due_sats"]
        delay = (100000 if row["kind"] == "take" else 0) if row["tier"] == "priority" else (300000 if row["kind"] == "take" else 200000)
        assert row["execution_us"] - row["arrival_us"] == delay
        if row["outcome"] == "filled":
            assert row["kind"] == "take" and row["filled_qty"] == row["quantity"] > 0
            assert row["fill_price"] > 0
            assert len(row["maker_id"]) == len(row["mark_id"]) == 64
            assert row["long_margin_sats"] > 0 and row["short_margin_sats"] > 0
        else:
            assert row["maker_id"] == row["mark_id"] == ""
            assert row["long_margin_sats"] == row["short_margin_sats"] == 0
            assert all(row[k] == 0 for k in ("filled_qty","fill_price","maker_fee_sats","taker_fee_sats","oracle_due_sats","router_due_sats"))
        if key[3] == "0":
            assert row["tier"] == "free" and row["maker_fee_sats"] == row["taker_fee_sats"] == 0
        if key[3] == "100":
            assert row["tier"] == "priority"
        rows[ident] = row
    arms[key] = rows
expected = {(str(s), r, str(n), str(a)) for s in (107,109,113) for r in ("quiet","shock") for n in (1,4) for a in (0,20,100)}
assert set(arms) == expected

def bps(r, ref):
    sign = 1 if r["side"] == "buy" else -1
    return 10000 * sign * (r["fill_price"] - r[ref]) / r[ref]

def markout(r):
    sign = 1 if r["side"] == "buy" else -1
    return 10000 * sign * (r["future_mark"] - r["fill_price"]) / r["fill_price"]

def metrics(rows):
    f = [r for r in rows if r["outcome"] == "filled"]
    vol = sum(r["filled_qty"] for r in f)
    oracle_usd = sum(r["oracle_due_sats"] * r["fill_price"] / 1e8 for r in f)
    gross_usd = sum((r["maker_fee_sats"] + r["taker_fee_sats"]) * r["fill_price"] / 1e8 for r in f)
    return {
        "takes": len(rows), "fills": len(f), "fill_rate": len(f) / len(rows) if rows else None,
        "matched_usd": vol, "gross_fee_usd_at_fill": gross_usd, "oracle_usd_at_fill": oracle_usd,
        "oracle_usd_per_million_matched": oracle_usd * 1e6 / vol if vol else None,
        "arrival_cost_bps": mean(bps(r,"arrival_mark") for r in f) if f else None,
        "execution_cost_bps": mean(bps(r,"execution_mark") for r in f) if f else None,
        "forward_markout_bps_500ms": mean(markout(r) for r in f) if f else None,
        "outcomes": dict(Counter(r["outcome"] for r in rows)),
    }

def paired(base, treatment, eligible=None):
    ids = [i for i in base if i[0] == "take" and (eligible is None or eligible(treatment[i]))]
    a = [base[i] for i in ids]; b = [treatment[i] for i in ids]
    common = [(x,y) for x,y in zip(a,b) if x["outcome"] == y["outcome"] == "filled"]
    return {
        "takes": len(ids), "both_fill": len(common),
        "base_only": sum(x["outcome"] == "filled" and y["outcome"] != "filled" for x,y in zip(a,b)),
        "treatment_only": sum(y["outcome"] == "filled" and x["outcome"] != "filled" for x,y in zip(a,b)),
        "paired_arrival_cost_delta_bps": mean(bps(y,"arrival_mark")-bps(x,"arrival_mark") for x,y in common) if common else None,
        "paired_markout_delta_bps": mean(markout(y)-markout(x) for x,y in common) if common else None,
    }

results = []
for key, rows in sorted(arms.items()):
    seed, regime, shards, adoption = key
    anchor = arms[(seed,regime,"1","0")]
    assert set(rows) == set(anchor)
    for i, row in rows.items():
        for k in ("side","arrival_us","arrival_mark","quantity","limit"):
            assert row[k] == anchor[i][k], (key,i,k)
    takes = [r for (k,_),r in rows.items() if k == "take"]
    assert len(takes) == 168
    m = metrics(takes)
    baseline = arms[(seed,regime,shards,"0")]
    one_router = arms[(seed,regime,"1",adoption)]
    record = {
        "seed": int(seed), "regime": regime, "shards": int(shards), "adoption_pct": int(adoption),
        **m,
        "free_takes": metrics([r for r in takes if r["tier"] == "free"]),
        "priority_takes": metrics([r for r in takes if r["tier"] == "priority"]),
        "posts": dict(Counter(r["outcome"] for (k,_),r in rows.items() if k == "post")),
        "cancels": dict(Counter(r["outcome"] for (k,_),r in rows.items() if k == "cancel")),
        "versus_same_shards_free": paired(baseline, rows),
        "priority_cohort_versus_same_shards_free": paired(baseline, rows, lambda r:r["tier"]=="priority"),
        "versus_same_tariff_one_router": paired(one_router, rows),
    }
    if m["oracle_usd_per_million_matched"]:
        record["daily_matched_usd_needed_by_oracle_cost"] = {
            str(c): c * 1e6 / m["oracle_usd_per_million_matched"] for c in (100,1000,5000)
        }
    results.append(record)
assert any(r["fills"] for r in results)
assert all(r["gross_fee_usd_at_fill"] == 0 for r in results if r["adoption_pct"] == 0)
assert any(r["oracle_usd_at_fill"] > 0 for r in results if r["adoption_pct"] == 100)
summary = {"schema":"shz/hft-event-replay/v1", "arms": results,
           "synthetic":True,"live_settlement":False,"provider_authentication":False,
           "network_latency_measured":False,"production_ready":False}
(out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n")
for r in results:
    print("seed={seed} {regime} shards={shards} paid={adoption_pct}% fills={fills}/{takes} vol_usd={matched_usd} oracle_per_million={oracle_usd_per_million_matched} cost={arrival_cost_bps} markout={forward_markout_bps_500ms}".format(**r))
