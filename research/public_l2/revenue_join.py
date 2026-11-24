#!/usr/bin/env python3
"""Join public Lighter BTC volume to matched L2 latency probes; no actual tier inference."""
from __future__ import annotations
import argparse, json, math
from collections import Counter, defaultdict
from datetime import datetime, UTC
from pathlib import Path
from bisect import bisect_left
from hashlib import file_digest
from pilot import Book, messages, cost, SCORE_CUTS

DAYS=("2026-10-11","2026-11-23")
TIERS=(("free",300,0.),("middle",200,.5),("premium",100,2.))
HORIZONS=(1000,5000)
USD_SCALE=10**6
GRID=1000

def write(path,obj):
    path.write_text(json.dumps(obj,allow_nan=False,sort_keys=True,indent=2)+"\n")

def utc_ms(day):
    return int(datetime.fromisoformat(day).replace(tzinfo=UTC).timestamp()*1000)

def trade_weights(day,local=None):
    import pyarrow.dataset as ds
    import pyarrow.parquet as pq
    import pyarrow.compute as pc
    import pyarrow.fs as fs
    start=utc_ms(day)
    filesystem=None if local else fs.S3FileSystem(region="us-east-2",anonymous=True)
    path=local or f"aws-public-blockchain/v1.1/lighter/core/mainnet/trades/date={day}/trades.parquet"
    schema=pq.ParquetFile(path,filesystem=filesystem).schema_arrow
    cols=["id","timestamp","price","size","is_maker_ask"]
    market=ds.field("public_market_index")
    pred=(market==1)
    if "market_id" in schema.names:
        pred=pred|(market.is_null()&(ds.field("market_id")==1))
    table=pq.read_table(path,filesystem=filesystem,columns=cols,filters=pred&(ds.field("trade_type")=="trade"))
    if not table.num_rows or any(table[c].null_count for c in cols):
        raise ValueError("Missing ordinary BTC executions or fields")
    if pc.count_distinct(table["id"]).as_py()!=table.num_rows:
        raise ValueError("Duplicate trade IDs")
    weights=defaultdict(lambda:[0,0])
    for batch in table.iter_batches():
        _,ts,price,size,side=[c.to_pylist() for c in batch.columns]
        for t,p,q,buy in zip(ts,price,size,side,strict=True):
            if type(t) is not int or not start<=t<start+86400000 or type(p) is not int or type(q) is not int or p<=0 or q<=0 or type(buy) is not bool:
                raise ValueError("Trade schema/time/scale invalid")
            weights[(t-start)//1000][0 if buy else 1]+=p*q
    return dict(schema="shz/l2-volume-weights/v1",day=day,symbol="BTC",trade_count=table.num_rows,
        source=str(path),usd_scale=USD_SCALE,clock="trade_publication_ms",
        side="is_maker_ask=true means taker buy",rows=sorted((k,*v) for k,v in weights.items()),
        matched_notional_units=sum(sum(v) for v in weights.values()))

def replay(book,start,end,weights):
    """Every side/second probed; realized trade notional is an ex-post weight only."""
    counts=defaultdict(Counter); pending={}; history={}
    for t in range(start,end,GRID):
        state=book.view(t);mid=state[2] if state else None
        history[t]=mid;history.pop(t-31000,None)
        anchors=[history.get(t-l) for l in (1000,5000,30000)]
        score=None if mid is None or any(a is None for a in anchors) else max(abs(10000*math.log(mid/a))/math.sqrt(l) for a,l in zip(anchors,(1,5,30)))
        bucket="warmup_or_unknown" if score is None else str(bisect_left(SCORE_CUTS,score))
        vols=weights.get(t,(0,0));results=defaultdict(dict)
        for tier,delay,fee in sorted(TIERS,key=lambda z:z[1]):
            v=book.view(t+delay)
            for horizon in HORIZONS:
                for key,side,arrival,entry,w,winning in pending.get(t-horizon,{}).get(tier,[]):
                    c=counts[key];prefix=f"{tier}_markout_{horizon}ms"
                    if v is None:
                        c[prefix+"_missing"]+=1;c[prefix+"_missing_weight"]+=w
                        continue
                    gross=side*(v[2]-entry)*10000/arrival
                    c[prefix+"_count"]+=1;c[prefix+"_weight"]+=w
                    c[prefix+"_weighted_gross_bps"]+=w*gross
                    c[prefix+"_weighted_net_bps"]+=w*(gross-fee*entry/arrival)
                    if winning:
                        c["winner_"+prefix+"_weight"]+=w
                        c["winner_"+prefix+"_weighted_gross_bps"]+=w*gross
            if mid is not None:
                for side in (1,-1):
                    qty=math.floor(1000/mid*100000)/100000
                    results[side][tier]=book.fill(v,side,qty,mid*(1+side*.002))
        pending[t]={}
        for side,w in zip((1,-1),vols,strict=True):
            key=(bucket,"buy" if side==1 else "sell");c=counts[key]
            c["probes"]+=1;c["volume_units"]+=w
            res=results[side]
            if mid is None or len(res)!=3 or any(e[0]!="full" for e in res.values()):
                c["unclassified"]+=1;c["unclassified_units"]+=w
                continue
            winner=min(TIERS,key=lambda x:(cost(res[x[0]],side,mid,x[2]),x[2],x[0]))[0]
            c["common"]+=1;c["common_units"]+=w
            c["winner_"+winner]+=1;c["winner_"+winner+"_units"]+=w
            for tier,_,fee in TIERS:
                entry=res[tier][1]
                c[tier+"_weighted_saving_bps"]+=w*(cost(res["free"],side,mid)-cost(res[tier],side,mid,fee))
                pending[t].setdefault(tier,[]).append((key,side,mid,entry,w,winner==tier))
        # Explicitly track evaluation horizons that extend past the captured hour.
        for tier,entries in pending[t].items():
            for horizon in HORIZONS:
                if t+horizon>=end:
                    for key,_,_,_,w,_ in entries:
                        c=counts[key];prefix=f"{tier}_markout_{horizon}ms"
                        c[prefix+"_missing"]+=1;c[prefix+"_missing_weight"]+=w
        pending.pop(t-max(HORIZONS),None)
    book.view(end)
    rows=[dict(bin=k[0],side=k[1],counts=dict(c)) for k,c in sorted(counts.items())]
    assert sum(c["volume_units"] for c in counts.values())==sum(sum(v) for t,v in weights.items() if start<=t<end)
    return dict(rows=rows,sequence_counts=dict(book.count),clean_sequence=book.count["gaps"]==book.count["unseeded"]==0)

def aggregate(root):
    rows=[];files={}
    for p in root.rglob("*.weighted.json"):
        x=json.loads(p.read_text());k=x["hour"]
        if k in files:raise ValueError("Duplicate hour")
        files[k]=x
    for day in DAYS:
        counters=defaultdict(Counter);covered=[];missing=[];dirty=[]
        for h in range(24):
            k=f"{day}T{h:02d}:00:00"
            if k not in files:missing.append(k);continue
            x=files[k]
            if not x["clean_sequence"]:dirty.append(k);continue
            covered.append(k)
            for row in x["rows"]:counters[(row["bin"],row["side"])].update(row["counts"])
        total=Counter()
        for c in counters.values():total.update(c)
        v=total["volume_units"];common=total["common_units"]
        assert v==common+total["unclassified_units"]
        assert common==sum(total["winner_"+t+"_units"] for t,_,_ in TIERS)
        implied=sum(total["winner_"+t+"_units"]*fee/10000/USD_SCALE for t,_,fee in TIERS)
        row=dict(day=day,covered_hours=len(covered),missing=missing,dirty=dirty,
            volume_usd=v/USD_SCALE,common_volume_usd=common/USD_SCALE,
            unknown_volume_usd=total["unclassified_units"]/USD_SCALE,
            winner_volume_fractions={t:total["winner_"+t+"_units"]/v if v else None for t,_,_ in TIERS},
            ex_post_scenario_taker_fee_usd=implied,implied_bps_on_covered_volume=implied/(v/USD_SCALE)*10000 if v else None,
            conditional_bins=[dict(bin=k[0],side=k[1],counts=dict(c)) for k,c in sorted(counters.items())],
            markouts=[dict(tier=t,horizon_ms=h,volume_usd=total[f"{t}_markout_{h}ms_weight"]/USD_SCALE,
                gross_bps=total[f"{t}_markout_{h}ms_weighted_gross_bps"]/total[f"{t}_markout_{h}ms_weight"] if total[f"{t}_markout_{h}ms_weight"] else None,
                net_bps=total[f"{t}_markout_{h}ms_weighted_net_bps"]/total[f"{t}_markout_{h}ms_weight"] if total[f"{t}_markout_{h}ms_weight"] else None,
                missing_weight_usd=total[f"{t}_markout_{h}ms_missing_weight"]/USD_SCALE) for t,_,_ in TIERS for h in HORIZONS])
        rows.append(row)
    return dict(schema="shz/l2-volume-revenue/v1",rows=rows,ex_post_only=True,actual_tier_observed=False,actual_fills_simulated=False)

def selftest():
    b=Book([(0,"snapshot",1,None,[("bid",99.99,1000),("ask",100.01,1000)]),
            (200,"update",2,1,[("ask",100.01,0),("ask",100.03,1000)]),
            (1400,"update",3,2,[("bid",99.99,0),("bid",100.02,1000)])])
    z=replay(b,0,2000,{0:(10*USD_SCALE,20*USD_SCALE),1000:(30*USD_SCALE,40*USD_SCALE)})
    assert z["clean_sequence"]
    assert sum(x["counts"]["volume_units"] for x in z["rows"])==100*USD_SCALE
    print("volume-weighted replay fixture passed")

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest="cmd",required=True)
    q=sub.add_parser("weights");q.add_argument("--day",choices=DAYS,required=True);q.add_argument("--trades");q.add_argument("--output",type=Path,required=True)
    q=sub.add_parser("hour");q.add_argument("--hour",required=True);q.add_argument("--book",type=Path,required=True);q.add_argument("--weights",type=Path,required=True);q.add_argument("--output",type=Path,required=True)
    q=sub.add_parser("aggregate");q.add_argument("--root",type=Path,required=True);q.add_argument("--output",type=Path,required=True)
    sub.add_parser("selftest");a=p.parse_args()
    if a.cmd=="selftest":selftest();return
    if a.cmd=="weights":
        z=trade_weights(a.day,a.trades);write(a.output,z)
        print(json.dumps({k:v for k,v in z.items() if k!="rows"}));return
    if a.cmd=="aggregate":
        z=aggregate(a.root);write(a.output,z)
        for row in z["rows"]:print(json.dumps({k:v for k,v in row.items() if k!="conditional_bins"}))
        return
    start=utc_ms(a.hour);day=a.hour[:10];w=json.loads(a.weights.read_text())
    assert w["schema"]=="shz/l2-volume-weights/v1" and w["day"]==day and w["symbol"]=="BTC" and w["usd_scale"]==USD_SCALE
    midnight=utc_ms(day);weights={midnight+i*1000:(b,s) for i,b,s in w["rows"]}
    z=replay(Book(messages(a.book,"BTC",start,"received")),start,start+3600000,weights)
    with a.book.open("rb") as f:sha=file_digest(f,"sha256").hexdigest()
    z.update(hour=a.hour,sha256=sha,clock="received",schema="shz/l2-weighted-hour/v1")
    write(a.output,z);print(json.dumps(dict(hour=a.hour,clean=z["clean_sequence"],sha256=sha)))
if __name__=="__main__":main()
