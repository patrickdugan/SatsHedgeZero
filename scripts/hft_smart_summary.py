#!/usr/bin/env python3
import csv,json,sys
from pathlib import Path
from collections import defaultdict
from statistics import mean
root=Path(sys.argv[1])
arms={}
configs=[("blind",50000,0),("affinity",50000,0)]+[(m,c,d) for m in ("presence","band") for c in (50000,200000,500000) for d in (0,100000)]
for p in sorted(root.glob("route-*.csv")):
    _,seed,regime,shards,adopt,strategy,cadence,delivery=p.stem.split("-")
    key=(int(seed),regime,int(shards),int(adopt),strategy,int(cadence),int(delivery))
    with p.open() as f: rows=list(csv.DictReader(f))
    assert len(rows)==568
    rs={}
    for r in rows:
        assert (int(r["seed"]),r["regime"],int(r["shards"]),int(r["adoption"]),r["strategy"],int(r["cadence_us"]),int(r["delivery_us"]))==key
        for k in ("router","arrival_us","execution_us","arrival_mark","execution_mark","future_mark","quantity","limit","fill_price","filled_qty","maker_fee_sats","taker_fee_sats","oracle_due_sats","router_due_sats","hint_age_us"):
            r[k]=int(r[k])
        ident=(r["kind"],int(r["id"]))
        assert ident not in rs
        rs[ident]=r
        assert 1<=r["router"]<=key[2]
        assert r["maker_fee_sats"]+r["taker_fee_sats"]==r["oracle_due_sats"]+r["router_due_sats"]
        delay=(100000 if r["kind"]=="take" else 0) if r["tier"]=="priority" else (300000 if r["kind"]=="take" else 200000)
        assert r["execution_us"]-r["arrival_us"]==delay
        if r["advertised"]=="true":
            assert r["kind"]=="take" and strategy in ("presence","band")
            assert int(delivery)<=r["hint_age_us"]<=250000
        else: assert r["hint_age_us"]==-1
        if r["outcome"]=="filled":
            assert r["kind"]=="take" and r["filled_qty"]==r["quantity"]==100
        else:
            assert r["filled_qty"]==r["fill_price"]==0
    assert sum(k[0]=="take" for k in rs)==168
    state=p.with_suffix(".state").read_text().splitlines()
    m=next(x for x in state if x.startswith("publication_count="))
    counts={k:int(v) for k,v in (x.split("=") for x in m.split(","))}
    expected_pub=(4500000//int(cadence)+1)*int(shards) if strategy in ("presence","band") else 0
    assert counts["publication_count"]==expected_pub
    assert counts["payload_bit_bound"]==expected_pub*({"presence":2,"band":42}.get(strategy,0))
    assert 0<=counts["nonempty_sides"]<=2*expected_pub
    arms[key]=(rs,counts)
expected={(s,r,4,a,m,c,d) for s in (107,109,113) for r in ("quiet","shock") for a in (0,20,100) for m,c,d in configs}
expected|={(s,r,1,a,"blind",50000,0) for s in (107,109,113) for r in ("quiet","shock") for a in (0,20,100)}
assert set(arms)==expected,(len(arms),len(expected))
def cost(r):
    return (1 if r["side"]=="buy" else -1)*10000*(r["fill_price"]-r["arrival_mark"])/r["arrival_mark"]
def markout(r):
    return (1 if r["side"]=="buy" else -1)*10000*(r["future_mark"]-r["fill_price"])/r["fill_price"]
result=[]
for k,(rs,counts) in sorted(arms.items()):
    s,reg,n,a,m,c,d=k
    baseline=arms[(s,reg,n,a,"blind",50000,0)][0]
    single=arms[(s,reg,1,a,"blind",50000,0)][0]
    assert set(rs)==set(baseline)==set(single)
    for ident,r in rs.items():
        for f in ("side","tier","arrival_us","arrival_mark","quantity","limit"):
            assert r[f]==baseline[ident][f]==single[ident][f]
        if ident[0]!="take":
            assert r["router"]==baseline[ident]["router"]
            if ident[0]=="cancel": assert r["router"]==rs[("post",ident[1])]["router"]
    takes=[(ident,r) for ident,r in rs.items() if ident[0]=="take"]
    f=[r for _,r in takes if r["outcome"]=="filled"]
    pair=[(baseline[ident],r) for ident,r in takes if baseline[ident]["outcome"]==r["outcome"]=="filled"]
    advertised=[r for _,r in takes if r["advertised"]=="true"]
    baseline_fills=sum(baseline[ident]["outcome"]=="filled" for ident,_ in takes)
    single_fills=sum(single[ident]["outcome"]=="filled" for ident,_ in takes)
    oracle=sum(r["oracle_due_sats"]*r["fill_price"]/1e8 for r in f)
    volume=sum(r["filled_qty"] for r in f)
    per_m=oracle*1e6/volume if volume else None
    result.append(dict(seed=s,regime=reg,shards=n,adoption=a,strategy=m,cadence_us=c,delivery_us=d,
        fills=len(f),takes=len(takes),base_fills=baseline_fills,single_fills=single_fills,
        recovered_fraction=(len(f)-baseline_fills)/(single_fills-baseline_fills) if single_fills>baseline_fills else None,
        baseline_only=sum(baseline[ident]["outcome"]=="filled" and r["outcome"]!="filled" for ident,r in takes),
        routed_only=sum(baseline[ident]["outcome"]!="filled" and r["outcome"]=="filled" for ident,r in takes),
        common_fills=len(pair),arrival_cost_bps=mean(map(cost,f)) if f else None,
        paired_cost_delta_bps=mean(cost(y)-cost(x) for x,y in pair) if pair else None,
        markout_bps=mean(map(markout,f)) if f else None,
        advertised_takes=len(advertised),advertised_fills=sum(r["outcome"]=="filled" for r in advertised),
        selected_hint_age_us=mean(r["hint_age_us"] for r in advertised) if advertised else None,
        matched_usd=volume,oracle_usd_at_fill=oracle,oracle_usd_per_million=per_m,
        daily_volume_for_1000_usd=1000*1e6/per_m if per_m else None,**counts))
groups=defaultdict(list)
for r in result:
    groups[(r["shards"],r["adoption"],r["strategy"],r["cadence_us"],r["delivery_us"])].append(r)
agg=[]
for k,rs in sorted(groups.items()):
    n,a,m,c,d=k
    fills=sum(r["fills"] for r in rs); base=sum(r["base_fills"] for r in rs); single=sum(r["single_fills"] for r in rs)
    takes=sum(r["takes"] for r in rs)
    adv=sum(r["advertised_takes"] for r in rs)
    volume=sum(r["matched_usd"] for r in rs)
    revenue=sum(r["oracle_usd_at_fill"] for r in rs)
    row=dict(shards=n,adoption=a,strategy=m,cadence_us=c,delivery_us=d,fills=fills,takes=takes,
             fill_rate=fills/takes,delta_fill_pp=100*(fills-base)/takes,
             recovered_fraction=(fills-base)/(single-base) if single>base else None,
             advertised=adv,advertised_fill_rate=sum(r["advertised_fills"] for r in rs)/adv if adv else None,
             payload_bit_bound=sum(r["payload_bit_bound"] for r in rs),
             oracle_usd_per_million=revenue*1e6/volume if volume else None)
    agg.append(row)
    print(json.dumps(row,sort_keys=True))
primary=next(r for r in agg if (r["shards"],r["adoption"],r["strategy"],r["cadence_us"],r["delivery_us"])==(4,20,"band",50000,100000))
(root/"summary.json").write_text(json.dumps(dict(schema="shz/smart-routing/v1",arms=result,aggregate=agg,primary=primary,
    primary_pass=primary["recovered_fraction"] is not None and primary["recovered_fraction"]>=0.5,
    native=True,synthetic=True,authenticated_hints=False,privacy_proven=False,live_settlement=False,production_ready=False),indent=2)+"\n")
assert len(result)==270 and len(agg)==45
