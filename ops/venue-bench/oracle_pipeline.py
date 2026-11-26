#!/usr/bin/env python3
"""Oracle pipeline latency from live data: relay slot -> source fetches ->
assembled body -> FROST-signed packet received and verified by the venue.

Joins the venue's retained packets (GET /api/explorer/packets, received_us is
the venue clock after BIP340 verification) with the relay's packet bodies
(GET /v1/packet/<seq>: slot_us, per-source fetched_us, assembled_us). Run on
the host that runs both, so all timestamps share one clock.

    python3 oracle_pipeline.py --venue http://127.0.0.1:8096 --relay http://127.0.0.1:8091
"""
import argparse
import json
import urllib.request


def get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--venue", default="http://127.0.0.1:8096")
    ap.add_argument("--relay", default="http://127.0.0.1:8091")
    ap.add_argument("--limit", type=int, default=600)
    ap.add_argument("--out", default="oracle_pipeline.jsonl")
    a = ap.parse_args()
    venue = get(f"{a.venue}/api/explorer/packets?limit={a.limit}")
    rows = []
    with open(a.out, "w", encoding="utf-8") as f:
        for vp in venue:
            try:
                rp = get(f"{a.relay}/v1/packet/{vp['seq']}")
            except Exception:
                continue
            b = rp["body"]
            fetched = [s["fetched_us"] for s in b.get("sources", []) if s.get("role") == "fast" and s.get("fetched_us")]
            if not fetched:
                continue
            row = {
                "seq": vp["seq"], "status": b.get("status"), "signers": rp.get("frost_signers"),
                "fetch_ms": (max(fetched) - b["slot_us"]) / 1000,
                "assemble_ms": (b["assembled_us"] - max(fetched)) / 1000,
                "frost_sign_publish_verify_ms": (vp["received_us"] - b["assembled_us"]) / 1000,
                "slot_to_venue_ms": (vp["received_us"] - b["slot_us"]) / 1000,
            }
            rows.append(row)
            f.write(json.dumps(row) + "\n")
    summary = {"summary": True, "packets": len(rows), "valid": sum(r["status"] == "VALID" for r in rows)}
    for k in ("fetch_ms", "assemble_ms", "frost_sign_publish_verify_ms", "slot_to_venue_ms"):
        xs = [r[k] for r in rows]
        summary[k] = {"median": pct(xs, 0.5), "p90": pct(xs, 0.9), "p99": pct(xs, 0.99), "max": pct(xs, 1.0)}
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
