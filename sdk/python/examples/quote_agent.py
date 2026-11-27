"""Minimal agent strategy: one small perpetual bid and ask around the mark, re-quoted when the
mark moves, inside the grant's collar and per-order notional, with the agent's own batch
acknowledgements auto-signed. Stops cleanly when the owner revokes the grant or it expires.

  python examples/quote_agent.py --venue http://127.0.0.1:8095 --agent-key agent.key --grant <id> [--seconds 60]

Testnet only. The agent key is the only key this process reads.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lightninger import Agent, Client, LightningerError, Stream  # noqa: E402

STOP_CODES = {"grant.revoked", "grant.expired", "grant.unknown"}


def log(**kw):
    print(json.dumps({"t": round(time.time(), 3), **kw}), flush=True)


def plan(mark, limits, spread_bps=20):
    """Bid/ask prices and size that fit the grant: half the collar at most, and one order's notional."""
    half = min(spread_bps, limits["collar_bps"] // 2) / 10_000
    qty = max(1, min(limits["max_order_notional_usd"] // 4, 25))
    return round(mark * (1 - half)), round(mark * (1 + half)), qty


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--venue", default="http://127.0.0.1:8095")
    ap.add_argument("--agent-key", required=True)
    ap.add_argument("--grant", required=True)
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--requote-bps", type=float, default=10)
    a = ap.parse_args()
    agent = Agent(Client(a.venue), bytes.fromhex(open(a.agent_key).read().strip()), a.grant)
    stop_acks = agent.start_autosigner()
    marks = []
    stream = Stream(a.venue)
    stream.subscribe(["mark"], lambda ch, kind, data: marks.append(data) if kind == "event" else None)
    log(ev="start", grant=a.grant, limits=agent.limits)
    quotes, quoted_at, end = [], None, time.time() + a.seconds
    try:
        while time.time() < end:
            m = agent.c.mark()["mark_usd"]
            if m and (quoted_at is None or abs(m - quoted_at) / quoted_at * 10_000 >= a.requote_bps):
                for q in quotes:
                    try:
                        agent.perp_cancel(q)
                    except LightningerError as e:
                        log(ev="cancel_refused", code=e.code)
                bid, ask, qty = plan(m, agent.limits)
                quotes = [agent.perp_post("long", qty, bid)["id"], agent.perp_post("short", qty, ask)["id"]]
                quoted_at = m
                log(ev="quoted", mark=m, bid=bid, ask=ask, qty=qty)
            time.sleep(1)
    except LightningerError as e:
        if e.code not in STOP_CODES:
            raise
        log(ev="stopped", reason=e.code)
    finally:
        stop_acks()
        stream.close()
    log(ev="done", marks_seen=len(marks), usage=agent.status()["usage"])


if __name__ == "__main__":
    main()
