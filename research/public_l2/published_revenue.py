#!/usr/bin/env python3
"""Get actual historical USD values, exact UTC dates, consistent protocol scopes."""
from datetime import datetime, UTC
from urllib.request import urlopen, Request
from hashlib import sha256
from pathlib import Path
import argparse,json,math

DAYS=("2026-10-11","2026-11-23")
SOURCES=[
 ("lighter-perps","fees","dailyFees"),
 ("lighter-perps","fees","dailyRevenue"),
 ("lighter-perps","derivatives",None),
 ("lighter","fees","dailyFees"),
 ("lighter","fees","dailyRevenue"),
]
def parse(data):
    chart=data["totalDataChart"];out={}
    for ts,val in chart:
        if type(ts) is not int or ts%86400 or type(val) not in (int,float) or not math.isfinite(val) or val<0:raise ValueError("invalid day series")
        day=datetime.fromtimestamp(ts,UTC).date().isoformat()
        if day in out:raise ValueError("duplicate day")
        out[day]=val
    return out
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    rows=[]
    for slug,category,dtype in SOURCES:
        url=f"https://api.llama.fi/summary/{category}/{slug}"+(f"?dataType={dtype}" if dtype else "")
        row=dict(slug=slug,category=category,data_type=dtype,url=url,values={d:None for d in DAYS})
        try:
            with urlopen(Request(url,headers={"User-Agent":"SHZ research daily comparison/1"}),timeout=40) as f:
                raw=f.read(20*1024*1024+1)
            if len(raw)>20*1024*1024:raise ValueError("response too large")
            data=json.loads(raw);values=parse(data)
            if data.get("slug")!=slug:raise ValueError("returned protocol slug mismatch")
            row.update(sha256=sha256(raw).hexdigest(),values={d:values.get(d) for d in DAYS},returned_slug=data.get("slug"),methodology=data.get("methodology"))
        except Exception as e:row["error"]=str(e)
        rows.append(row);print(json.dumps(row))
    out=dict(schema="shz/lighter-daily-published/v1",date_basis="UTC calendar date",rows=rows,
      fetched_utc=datetime.now(UTC).isoformat(),all_dates_and_scopes_available=all(all(v is not None for v in r["values"].values()) for r in rows))
    a.output.write_text(json.dumps(out,indent=2,allow_nan=False)+"\n")
if __name__=="__main__":main()
