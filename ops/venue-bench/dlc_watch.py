#!/usr/bin/env python3
"""Watch the FROST DLC oracle and record when each event is announced and attested.

Polls GET /v1/dlc/events every --poll-ms and appends one JSON line per status
change: {"event_id", "status", "maturity_unix", "seen_us", "price_usd"}.
Run on the relay host so the poll interval, not the network, bounds the error.

    python3 dlc_watch.py --relay http://127.0.0.1:8091 --minutes 50 --out dlc_watch.jsonl
"""
import argparse
import json
import time
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay", default="http://127.0.0.1:8091")
    ap.add_argument("--poll-ms", type=int, default=250)
    ap.add_argument("--minutes", type=float, default=50)
    ap.add_argument("--out", default="dlc_watch.jsonl")
    a = ap.parse_args()
    last = {}
    end = time.time() + a.minutes * 60
    with open(a.out, "a", encoding="utf-8") as f:
        while time.time() < end:
            try:
                with urllib.request.urlopen(a.relay + "/v1/dlc/events", timeout=5) as r:
                    j = json.loads(r.read())
                seen = int(time.time() * 1e6)
                for e in j.get("events", j if isinstance(j, list) else []):
                    st = e.get("status") or e.get("state")
                    if last.get(e["event_id"]) != st:
                        first = e["event_id"] not in last
                        last[e["event_id"]] = st
                        f.write(json.dumps({"event_id": e["event_id"], "status": st, "maturity_unix": e.get("maturity_unix"),
                                            "seen_us": seen, "price_usd": e.get("price_usd"), "initial": first}) + "\n")
                        f.flush()
            except Exception as ex:  # keep watching through relay restarts
                f.write(json.dumps({"error": repr(ex), "seen_us": int(time.time() * 1e6)}) + "\n")
                f.flush()
            time.sleep(a.poll_ms / 1000)


if __name__ == "__main__":
    main()
