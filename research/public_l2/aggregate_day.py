#!/usr/bin/env python3
"""Aggregate fixed two-day public L2 sample; fit only on the first day."""
from collections import Counter, defaultdict
from pathlib import Path
import argparse,json

DAYS=("2026-10-11","2026-11-23")
CLOCKS=("publication","received")
FAMILIES={"shz_candidate":("free","middle","priority"),"venue_discounted":("free","plus","priority")}
CUTS=(.1,.25,.5,1.,2.,5.,10.,20.)

def summarize(root):
    files={}
    for p in sorted(root.rglob("*.summary.json")):
        x=json.loads(p.read_text());hour=x["hour_utc"]
        assert x["schema"]=="shz/public-l2-pilot/v2" and x["no_private_data"]
        assert hour not in files and hour[:10] in DAYS
        assert x["grid_ms"]==1000
        files[hour]=x
    rows=[];bins={}
    for day in DAYS:
        for clock in CLOCKS:
            winners=defaultdict(Counter);pairs=defaultdict(Counter);cond=defaultdict(Counter)
            received=0;clean=0;valid=0;directions=0;excluded=[];missing=[]
            for i in range(24):
                hour=f"{day}T{i:02d}:00:00"
                if hour not in files:missing.append(hour);continue
                received+=1
                z=files[hour]["reports"][clock]
                if not z["clean_sequence"]:excluded.append(hour);continue
                clean+=1
                assert z["expected_wall_ticks"]==3600 and z["wall_ticks"]==3599
                assert tuple(z["score_cuts"])==CUTS
                valid+=z["arrival_valid"];directions+=z["causal_direction_ticks"]
                for w in z["winners"]:
                    if w["cohort"]=="causal_momentum" and w["usd"]==1000:
                        assert sum(w["counts"].values())<=z["wall_ticks"]
                        winners[w["family"]].update(w["counts"])
                for p in z["pairs"]:
                    if p["cohort"]=="causal_momentum" and p["usd"]==1000:
                        k=(p["fast_ms"],p["slow_ms"])
                        pairs[k].update(p["counts"])
                        for b,n in p["common_fill_exceedance_counts"].items():pairs[k]["gt_"+b]+=n
                for q in z["conditional_score_bins"]:
                    cond[(q["bin"],q["family"])].update(q["counts"])
            expected=86400
            families={}
            for family,tiers in FAMILIES.items():
                c=winners[family]
                counts={t:c[t] for t in tiers}
                counts["unknown_or_nonfull"]=expected-sum(counts.values())
                assert counts["unknown_or_nonfull"]>=0
                families[family]=dict(counts=counts,fractions={k:v/expected for k,v in counts.items()})
            row=dict(day=day,clock=clock,expected_hours=24,downloaded_hours=received,clean_hours=clean,
                     missing_hours=missing,dirty_hours=excluded,full_day_clean=clean==24,
                     wall_seconds=expected,arrival_valid=valid,causal_direction_ticks=directions,
                     families=families,pairs=[dict(fast_ms=k[0],slow_ms=k[1],counts=dict(c)) for k,c in sorted(pairs.items())])
            rows.append(row);bins[day,clock]=cond
    policies=[]
    for clock in CLOCKS:
        train,test=bins[DAYS[0],clock],bins[DAYS[1],clock]
        for family,tiers in FAMILIES.items():
            total=Counter();details=[]
            for b in range(len(CUTS)+1):
                a=train[b,family];z=test[b,family]
                n=a["common"];chosen=tiers[0]
                # Train on mean fee-adjusted savings, never ex-post test winners.
                if n>=100 and n>=.95*a["directional_ticks"]:
                    chosen=max(tiers,key=lambda name:a[name+"_net_saving_sum_bps"]/n)
                held=z["common"]
                total["heldout_common"]+=held
                total["heldout_net_saving_sum_bps"]+=z[chosen+"_net_saving_sum_bps"]
                total["heldout_"+chosen]+=held
                total["heldout_noncommon"]+=z["directional_ticks"]-held
                details.append(dict(bin=b,lower=None if b==0 else CUTS[b-1],upper=CUTS[b] if b<len(CUTS) else None,
                    training_directional=a["directional_ticks"],training_common=n,chosen=chosen,heldout_directional=z["directional_ticks"],
                    heldout_common=held,heldout_net_saving_bps=z[chosen+"_net_saving_sum_bps"]/held if held else None,
                    heldout_expost_winners={t:z["winner_"+t] for t in tiers}))
            n=total["heldout_common"]
            policies.append(dict(clock=clock,family=family,training_day=DAYS[0],evaluation_day=DAYS[1],
                common_fill_mean_net_saving_bps=total["heldout_net_saving_sum_bps"]/n if n else None,
                counts=dict(total),bins=details))
    return dict(schema="shz/public-l2-day-calibration/v1",full_coverage=all(x["full_day_clean"] for x in rows),
                days=rows,conditional_policies=policies,actual_executions=False,
                strategy_profit_measured=False,exploratory=True)
def selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        z=summarize(Path(d))
        assert not z["full_coverage"] and len(z["days"])==4
        assert all(x["families"]["shz_candidate"]["counts"]["unknown_or_nonfull"]==86400 for x in z["days"])
    print("day aggregation empty-coverage selftest passed")
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path);p.add_argument("--output",type=Path);p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:selftest();return
    z=summarize(a.root);a.output.write_text(json.dumps(z,indent=2,allow_nan=False)+"\n")
    for row in z["days"]:print(json.dumps(row))
    for row in z["conditional_policies"]:print(json.dumps({k:v for k,v in row.items() if k!="bins"}))
if __name__=="__main__":main()
