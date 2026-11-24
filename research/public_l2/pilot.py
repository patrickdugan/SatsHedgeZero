#!/usr/bin/env python3
"""Independent public-data latency calibration pilot. No account or live trades.

Read one provider Parquet hour. Reconstruct strictly causal displayed depth.
Export aggregated statistics only: no raw rows, price sequences, order details.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, UTC
from hashlib import file_digest
from itertools import groupby
from operator import itemgetter
import argparse
import heapq
import json
import math
from pathlib import Path

DELAYS=(100,140,200,300,600)
SIZES=(100,1000,10000)
GRID_MS=1000
MAX_AGE_MS=2000
FEE_FAMILIES={
 "shz_candidate":(("free",300,0),("middle",200,.5),("priority",100,2)),
 "venue_discounted":(("free",300,0),("plus",300,.5),("priority",140,1.96)),
}
PAIRS=((100,300),(140,300),(200,300),(100,200),(300,600))
THRESHOLDS=(0,.5,1,1.5,2,2.8,5,10,20)

class Side:
    def __init__(self,sign):
        self.sign=sign;self.depth={};self.keys=[]
    def update(self,p,q):
        k=p*self.sign
        if q:
            if k not in self.depth:heapq.heappush(self.keys,k)
            self.depth[k]=q
        else:self.depth.pop(k,None)
    def best(self):
        if len(self.keys)>2*len(self.depth)+256:
            self.keys=list(self.depth);heapq.heapify(self.keys)
        while self.keys and self.keys[0] not in self.depth:heapq.heappop(self.keys)
        return self.keys[0]*self.sign if self.keys else None
    def fill(self,q,limit):
        p=self.best()
        if p is None or p*self.sign>limit*self.sign:return ("no_depth",None)
        if self.depth[p*self.sign]>=q:return ("full",p)
        remaining=q;quote=0.
        for k,size in sorted(self.depth.items()):
            if k>limit*self.sign:break
            take=min(remaining,size);quote+=take*k*self.sign;remaining-=take
            if remaining<=q*1e-10:return ("full",quote/(q-remaining))
        return ("partial" if remaining<q else "no_depth",None)

def messages(path,expected,hour,clock):
    import pyarrow.parquet as pq
    f=pq.ParquetFile(path)
    names=("symbol","received_time","event_time","event_type","final_update_id","prev_final_update_id","side","price","quantity")
    if not set(names)<=set(f.schema.names):raise ValueError("required columns absent")
    def rows():
        for b in f.iter_batches(columns=list(names)):
            yield from zip(*(b[i].to_pylist() for i in range(len(names))))
    effective=hour
    for key,group in groupby(rows(),key=itemgetter(0,1,2,3,4,5)):
        symbol,rx,event,typ,seq,prev=key
        if symbol!=expected:raise ValueError("wrong market")
        if typ not in ("snapshot","update"):raise ValueError("unknown message kind")
        if seq is None or (typ=="update" and prev is None):raise ValueError("native sequence missing")
        if not isinstance(rx,int) or not isinstance(event,int):raise ValueError("missing clock")
        if not hour-86400000<=event<hour+86400000:raise ValueError("unexpected event ms units")
        receive_ms=(rx+999999)//1000000
        if not hour-86400000<=receive_ms<hour+86400000:raise ValueError("unexpected receive ns units")
        effective=max(effective,event,receive_ms if clock=="received" else hour)
        levels=[]
        for row in group:
            side,p,q=row[6:]
            if side not in ("bid","ask"):raise ValueError("bad side")
            p,q=float(p),float(q)
            if not math.isfinite(p) or not math.isfinite(q) or p<0 or q<0 or (p==0 and q!=0):
                raise ValueError("invalid depth")
            if p:levels.append((side,p,q))
        yield effective,typ,seq,prev,levels

class Book:
    def __init__(self,stream):
        self.stream=iter(stream);self.next=next(self.stream,None)
        self.sides={"bid":Side(-1),"ask":Side(1)}
        self.seq=None;self.last=None;self.query=-1;self.count=Counter()
    def view(self,t):
        if t<self.query:raise ValueError("clock rollback")
        self.query=t
        while self.next is not None and self.next[0]<t:
            tm,typ,seq,prev,levels=self.next
            self.next=next(self.stream,None)
            self.count["messages"]+=1
            if typ=="snapshot":
                self.count["snapshots"]+=1
                self.sides={"bid":Side(-1),"ask":Side(1)}
            else:
                self.count["updates"]+=1
                if self.seq is not None and self.seq!=prev:
                    self.count["gaps"]+=1;self.seq=None
                if self.seq is None:
                    self.count["unseeded"]+=1;continue
            self.seq=seq;self.last=tm
            for side,p,q in levels:self.sides[side].update(p,q)
        if self.seq is None or self.last is None or t-self.last>MAX_AGE_MS:return None
        b,a=self.sides["bid"].best(),self.sides["ask"].best()
        return (b,a,(a+b)/2) if b is not None and a is not None and b<a else None
    def fill(self,state,side,quantity,limit):
        if quantity<=0:return ("below_lot",None)
        if state is None:return ("unknown",None)
        return self.sides["ask" if side==1 else "bid"].fill(quantity,limit)

def cost(e,side,mid,fee=0):
    return (side*(e[1]-mid)*10000+fee*e[1])/mid if e[0]=="full" else None

def quantiles(xs):
    if not xs:return None
    ys=sorted(xs)
    return {str(q):ys[min(len(ys)-1,max(0,math.ceil(q*len(ys))-1))] for q in (.5,.9,.95,.98,.99,.999)}

class Aggregate:
    def __init__(self):
        self.outcomes=defaultdict(Counter);self.pairs=defaultdict(Counter);self.saving=defaultdict(list)
        self.winners=defaultdict(Counter);self.net=defaultdict(list)
    def add(self,cohort,n,side,mid,results):
        for d,e in results.items():self.outcomes[cohort,n,d][e[0]]+=1
        for f,s in PAIRS:
            a,b=results[f],results[s];k=(cohort,n,f,s);c=self.pairs[k]
            if any(e[0] in ("unknown","below_lot") for e in (a,b)):c["unknown"]+=1
            elif a[0]==b[0]=="full":
                c["common"]+=1;self.saving[k].append(cost(b,side,mid)-cost(a,side,mid))
                self.net[k].append(cost(b,side,mid)-cost(a,side,mid,2 if f==100 else 1.96 if f==140 else .5 if f==200 else 0))
            elif a[0]=="full":c["fast_only"]+=1
            elif b[0]=="full":c["slow_only"]+=1
            else:c["neither"]+=1
        for family,tiers in FEE_FAMILIES.items():
            # Common-fill winners only. Missing or failed full execution
            # stays explicit; no assumption about the cost of a missed fill.
            k=(cohort,n,family);es=[results[d] for _,d,_ in tiers]
            if any(e[0] in ("unknown","below_lot") for e in es):winner="unknown"
            elif any(e[0]!="full" for e in es):winner="not_all_full"
            else:winner=min((cost(results[d],side,mid,fee),fee,name) for name,d,fee in tiers)[2]
            self.winners[k][winner]+=1
    def report(self,total):
        return dict(
          outcomes=[dict(cohort=k[0],usd=k[1],delay_ms=k[2],counts=dict(v)) for k,v in sorted(self.outcomes.items())],
          pairs=[dict(cohort=k[0],usd=k[1],fast_ms=k[2],slow_ms=k[3],counts=dict(v),
            gross_saving_quantiles_bps=quantiles(self.saving[k]),
            common_fill_exceedance_counts={str(b):sum(x>b for x in self.saving[k]) for b in THRESHOLDS},
            mean_fee_adjusted_saving_bps=sum(self.net[k])/len(self.net[k]) if self.net[k] else None)
            for k,v in sorted(self.pairs.items())],
          winners=[dict(cohort=k[0],usd=k[1],family=k[2],wall_ticks=total,counts=dict(v),
            unclassified_ticks=total-sum(v.values()),
            wall_fractions={name:count/total for name,count in v.items()} if total else {})
            for k,v in sorted(self.winners.items())])

def replay(book,start,end):
    total=0;valid=0;momentum=0;last_mid=None;last_t=None;agg=Aggregate()
    for t in range(start,end-GRID_MS,GRID_MS):
        total+=1
        state=book.view(t)
        if state is None:last_mid=None;last_t=None;continue
        valid+=1;mid=state[2]
        direction=(1 if mid>last_mid else -1 if mid<last_mid else 0) if last_mid is not None and last_t==t-GRID_MS else 0
        last_mid=mid;last_t=t
        momentum+=direction!=0
        # BTC base lot = 1e-5; fixed +/-20bp arrival limit.
        requests={(side,n):(math.floor(n/mid*100000)/100000,mid*(1+side*.002)) for side in (1,-1) for n in SIZES}
        results=defaultdict(dict)
        for d in DELAYS:
            v=book.view(t+d)
            for k,(q,lim) in requests.items():results[k][d]=book.fill(v,k[0],q,lim)
        for (side,n),res in results.items():
            agg.add("buy" if side==1 else "sell",n,side,mid,res)
            if side==direction:agg.add("causal_momentum",n,side,mid,res)
    book.view(end)
    return dict(wall_ticks=total,arrival_valid=valid,causal_direction_ticks=momentum,
                sequence_counts=dict(book.count),clean_sequence=book.count["gaps"]==0 and book.count["unseeded"]==0,
                **agg.report(total))

def selftest():
    # A sequence discontinuity invalidates the book until a fresh snapshot;
    # strict-before visibility and non-consuming sweeps.
    b=Book([(0,"snapshot",1,None,[("bid",99.99,1),("ask",100.01,1)]),
            (200,"update",2,1,[("ask",100.01,0),("ask",100.10,1)]),
            (500,"update",4,3,[("ask",100.10,1)]),
            (700,"snapshot",5,None,[("bid",100,1),("ask",100.02,1)])])
    assert b.view(0) is None
    v=b.view(100);assert v[1]==100.01 and b.fill(v,1,.5,101)==("full",100.01)
    assert b.fill(v,1,.5,101)==("full",100.01)
    assert b.view(200)[1]==100.01 and b.view(201)[1]==100.10
    assert b.view(501) is None and b.view(701)[1]==100.02
    assert b.count["gaps"]==1 and b.count["unseeded"]==1
    a=Aggregate();r={d:("full",100.0) for d in DELAYS};r[300]=("full",100.03)
    a.add("buy",100,1,100,r)
    z=a.report(1)
    w=next(x for x in z["winners"] if x["family"]=="shz_candidate")
    assert w["counts"]=={"middle":1}
    assert next(x for x in z["winners"] if x["family"]=="venue_discounted")["counts"]=={"priority":1}
    print("public L2 pilot selftests passed")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--selftest",action="store_true");p.add_argument("--book",type=Path);p.add_argument("--hour");p.add_argument("--output",type=Path)
    a=p.parse_args()
    if a.selftest:selftest();return
    if not (a.book and a.hour and a.output):p.error("book, hour, output required")
    dt=datetime.fromisoformat(a.hour).replace(tzinfo=UTC)
    if dt.minute or dt.second or dt.microsecond:raise ValueError("hour aligned UTC required")
    start=int(dt.timestamp()*1000)
    with a.book.open("rb") as f:digest=file_digest(f,"sha256").hexdigest()
    reports={}
    for clock in ("publication","received"):
        reports[clock]=replay(Book(messages(a.book,"BTC",start,clock)),start,start+3600000)
        assert reports[clock]["arrival_valid"]>0,"empty or unusable archive"
    out=dict(schema="shz/public-l2-pilot/v1",source="CryptoHFTData Lighter public BTC L2",hour_utc=a.hour,
        sha256=digest,bytes=a.book.stat().st_size,grid_ms=GRID_MS,delays_ms=DELAYS,notionals_usd=SIZES,
        reports=reports,full_visible_depth_only=True,actual_order_execution=False,observed_fee_tier=False,
        no_private_data=True,exploratory=True)
    a.output.write_text(json.dumps(out,indent=2,allow_nan=False)+"\n")
    for clock,x in reports.items():
        print(json.dumps(dict(hour=a.hour,clock=clock,wall_ticks=x["wall_ticks"],arrival_valid=x["arrival_valid"],
            causal_direction_ticks=x["causal_direction_ticks"],sequence_counts=x["sequence_counts"],clean_sequence=x["clean_sequence"],
            primary_winners=[w for w in x["winners"] if w["cohort"]=="causal_momentum" and w["usd"]==1000],
            primary_pairs=[v for v in x["pairs"] if v["cohort"]=="causal_momentum" and v["usd"]==1000 and v["slow_ms"]==300])))
if __name__=="__main__":main()
