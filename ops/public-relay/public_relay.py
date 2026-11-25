#!/usr/bin/env python3
"""SHZ public trusted relayer: delayed public BTC/USD data, signed and hash-chained.

Every slot (default 5 s) the relayer fetches free public sources, keeps the
raw responses privately, and publishes one BIP340-signed packet chained to
the previous packet by digest.

Trust model: ONE relay key, operated by one party (trusted relayer). The
sources are read over TLS without provider signatures being verified, and the
data is late (public REST/RPC, not a low-latency feed). Packets publish the
median, the source count, dispersion, and per-source response digests and
timestamps; per-exchange prices stay in the private raw archive.

Endpoints (plain HTTP):
  GET /v1/latest            latest signed packet
  GET /v1/packet/<seq>      packet by sequence (retained window)
  GET /v1/pubkey            relay public key and signing domain
  GET /v1/stream            Server-Sent Events, one event per packet
  GET /v1/archive/<YYYY-MM-DD>.jsonl   signed packets of one UTC day
  GET /healthz
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import gzip
import hashlib
import json
import os
import queue
import secrets
import ssl
import statistics
import sys
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bip340  # noqa: E402

SCHEMA = "shz-public-relay/v1"
SIGNING_TAG = "SHZ/PUBLIC-RELAY-PACKET/V1"
UA = {"User-Agent": "shz-public-relay/1", "Accept": "application/json"}
CHAINLINK_BTC_USD_ETH = "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c"
ETH_RPC = "https://ethereum-rpc.publicnode.com"

FAST_MAX_AGE_US = 30_000_000
AUDIT_MAX_AGE_US = 3_900_000_000  # Chainlink heartbeat 1 h plus margin
MIN_FAST_SOURCES = 3
MAX_DISPERSION_BPS = 50
MAX_AUDIT_DEVIATION_BPS = 150


def now_us() -> int:
    return time.time_ns() // 1_000


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def packet_message(body: dict) -> bytes:
    return bip340.tagged_hash(SIGNING_TAG, canonical(body))


def e8(x) -> int:
    from decimal import Decimal

    return int(Decimal(str(x)) * 100_000_000)


# --------------------------------------------------------------- sources ----

def _get(url: str, data: bytes | None = None, timeout: float = 3.0) -> bytes:
    headers = dict(UA)
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
        return r.read(1_000_000)


def src_coinbase(raw: bytes):
    j = json.loads(raw)
    ts = datetime.fromisoformat(j["time"].replace("Z", "+00:00")).timestamp()
    return e8(j["price"]), int(ts * 1_000_000)


def src_kraken(raw: bytes):
    j = json.loads(raw)
    if j.get("error"):
        raise ValueError(str(j["error"]))
    (pair,) = j["result"].values()
    return e8(pair["c"][0]), None  # no timestamp in the ticker


def src_bitstamp(raw: bytes):
    j = json.loads(raw)
    return e8(j["last"]), int(j["timestamp"]) * 1_000_000


def src_gemini(raw: bytes):
    j = json.loads(raw)
    # volume.timestamp is a minute-rounded 24 h volume bucket time, not the
    # last-trade time; the ticker carries no trade time, so use fetch time.
    return e8(j["last"]), None


def src_chainlink(raw: bytes):
    j = json.loads(raw)
    if "error" in j:
        raise ValueError(str(j["error"]))
    h = j["result"].removeprefix("0x")
    words = [int(h[i : i + 64], 16) for i in range(0, 320, 64)]
    answer, updated_at = words[1], words[3]
    if answer >= 1 << 255:
        raise ValueError("negative answer")
    return answer, updated_at * 1_000_000  # aggregator answer has 8 decimals


SOURCES = {
    "coinbase": ("fast", lambda: _get("https://api.exchange.coinbase.com/products/BTC-USD/ticker"), src_coinbase),
    "kraken": ("fast", lambda: _get("https://api.kraken.com/0/public/Ticker?pair=XBTUSD"), src_kraken),
    "bitstamp": ("fast", lambda: _get("https://www.bitstamp.net/api/v2/ticker/btcusd/"), src_bitstamp),
    "gemini": ("fast", lambda: _get("https://api.gemini.com/v1/pubticker/btcusd"), src_gemini),
    "chainlink_eth": (
        "audit",
        lambda: _get(
            ETH_RPC,
            data=canonical({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": CHAINLINK_BTC_USD_ETH, "data": "0xfeaf968c"}, "latest"]}),
        ),
        src_chainlink,
    ),
}


def fetch_all(sources=SOURCES, pool=None):
    """Return {id: (role, fetched_us, raw_bytes | None, parse_result | error_str)}."""
    out = {}

    def one(sid):
        role, fetch, parse = sources[sid]
        t0 = now_us()
        try:
            raw = fetch()
        except Exception as e:  # noqa: BLE001 - every failure becomes an explicit source error
            return sid, (role, now_us(), None, f"fetch: {type(e).__name__}")
        fetched = now_us()
        try:
            return sid, (role, fetched, raw, parse(raw))
        except Exception as e:  # noqa: BLE001
            return sid, (role, fetched, raw, f"parse: {type(e).__name__}")
        finally:
            _ = t0

    ex = pool or cf.ThreadPoolExecutor(max_workers=len(sources))
    for sid, res in ex.map(one, list(sources)):
        out[sid] = res
    return out


# ---------------------------------------------------------------- packet ----

def assemble(seq: int, previous: str, slot_us: int, interval_ms: int, results: dict) -> tuple[dict, dict]:
    """Deterministic packet body from fetch results; returns (body, private_prices)."""
    entries, fast, audit, private = [], [], None, {}
    for sid in sorted(results):
        role, fetched, raw, res = results[sid]
        e = {"id": sid, "role": role, "fetched_us": fetched, "response_sha256": hashlib.sha256(raw).hexdigest() if raw else None}
        if isinstance(res, str):
            e.update(ok=False, error=res)
        else:
            price, ts = res
            src_ts = ts if ts is not None else fetched
            age = max(0, slot_us - src_ts)
            max_age = FAST_MAX_AGE_US if role == "fast" else AUDIT_MAX_AGE_US
            fresh = 0 < price < 10**16 and age <= max_age and src_ts <= fetched + 5_000_000
            e.update(ok=fresh, source_ts_us=src_ts, ts_from_fetch=ts is None, age_us=age)
            if not fresh:
                e["error"] = "stale_or_out_of_range"
            private[sid] = price
            if fresh and role == "fast":
                fast.append(price)
            if fresh and role == "audit":
                audit = price
        entries.append(e)
    body = {
        "schema": SCHEMA,
        "market": "BTC/USD",
        "data_class": "public_delayed",
        "seq": seq,
        "previous": previous,
        "interval_ms": interval_ms,
        "slot_us": slot_us,
        "assembled_us": now_us(),
        "sources": entries,
        "fast_sources_used": len(fast),
    }
    if len(fast) < MIN_FAST_SOURCES:
        body.update(status="HOLD", hold_reason="insufficient_fresh_sources")
        return body, private
    med = int(statistics.median(fast))
    disp = (max(fast) - min(fast)) * 10_000 // med
    body.update(median_e8=med, dispersion_bps=disp)
    if disp > MAX_DISPERSION_BPS:
        body.update(status="HOLD", hold_reason="dispersion")
        return body, private
    if audit is not None:
        dev = abs(med - audit) * 10_000 // audit
        body["audit_deviation_bps"] = dev
        if dev > MAX_AUDIT_DEVIATION_BPS:
            body.update(status="HOLD", hold_reason="audit_divergence")
            return body, private
    else:
        body["audit_deviation_bps"] = None
    body["status"] = "VALID"
    return body, private


def sign_packet(body: dict, seckey: bytes) -> dict:
    msg = packet_message(body)
    return {"body": body, "digest": msg.hex(), "signature": bip340.sign(msg, seckey, secrets.token_bytes(32)).hex()}


def verify_packet(pkt: dict, pk_hex: str) -> bool:
    msg = packet_message(pkt["body"])
    return msg.hex() == pkt["digest"] and bip340.verify(msg, bytes.fromhex(pk_hex), bytes.fromhex(pkt["signature"]))


# ----------------------------------------------------------------- state ----

class Relay:
    def __init__(self, state_dir: Path, interval_ms: int, retain: int = 17_280):
        self.dir = state_dir
        self.interval_ms = interval_ms
        (self.dir / "archive").mkdir(parents=True, exist_ok=True)
        (self.dir / "raw").mkdir(parents=True, exist_ok=True)
        self.seckey = self._key()
        self.pubkey = bip340.pubkey(self.seckey).hex()
        self.ring: deque[dict] = deque(maxlen=retain)
        self.by_seq: dict[int, dict] = {}
        self.lock = threading.Lock()
        self.subscribers: set[queue.Queue] = set()
        self.seq, self.previous = self._restore()
        self.stats = {"published": 0, "valid": 0, "hold": 0, "started_us": now_us()}

    def _key(self) -> bytes:
        kp = self.dir / "relay.key"
        if not kp.exists():
            while True:
                k = secrets.token_bytes(32)
                if 1 <= int.from_bytes(k, "big") < bip340.N:
                    break
            fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(k.hex())
                f.flush()
                os.fsync(f.fileno())
        return bytes.fromhex(kp.read_text().strip())

    def _restore(self) -> tuple[int, str]:
        """Resume the chain from the newest archive line; verify it first."""
        files = sorted((self.dir / "archive").glob("*.jsonl"))
        for f in reversed(files):
            lines = [l for l in f.read_text().splitlines() if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                if not verify_packet(last, self.pubkey):
                    raise SystemExit(f"archive tail in {f} does not verify; refusing to continue the chain")
                for l in lines[-self.ring.maxlen :]:
                    p = json.loads(l)
                    self.ring.append(p)
                    self.by_seq[p["body"]["seq"]] = p
                return last["body"]["seq"], last["digest"]
        return 0, "00" * 32

    def publish(self, slot_us: int, results: dict) -> dict:
        body, private = assemble(self.seq + 1, self.previous, slot_us, self.interval_ms, results)
        pkt = sign_packet(body, self.seckey)
        day = datetime.fromtimestamp(slot_us / 1e6, timezone.utc).strftime("%Y-%m-%d")
        with open(self.dir / "archive" / f"{day}.jsonl", "a") as f:
            f.write(json.dumps(pkt, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())  # durable before anyone can see it: one packet per seq
        raw = {sid: (r[2].decode("utf-8", "replace") if r[2] else None) for sid, r in results.items()}
        hour = datetime.fromtimestamp(slot_us / 1e6, timezone.utc).strftime("%Y-%m-%dT%H")
        with gzip.open(self.dir / "raw" / f"{hour}.jsonl.gz", "at") as f:
            f.write(json.dumps({"seq": body["seq"], "digest": pkt["digest"], "prices_e8": private, "raw": raw}) + "\n")
        with self.lock:
            self.seq, self.previous = body["seq"], pkt["digest"]
            if len(self.ring) == self.ring.maxlen:
                self.by_seq.pop(self.ring[0]["body"]["seq"], None)
            self.ring.append(pkt)
            self.by_seq[body["seq"]] = pkt
            self.stats["published"] += 1
            self.stats["valid" if body["status"] == "VALID" else "hold"] += 1
            for q in list(self.subscribers):
                try:
                    q.put_nowait(pkt)
                except queue.Full:
                    self.subscribers.discard(q)
        return pkt

    def prune(self, raw_days: int = 2, archive_days: int = 30):
        cutoff = time.time()
        for sub, days in (("raw", raw_days), ("archive", archive_days)):
            for f in (self.dir / sub).iterdir():
                if cutoff - f.stat().st_mtime > days * 86_400:
                    f.unlink()

    def run(self, stop: threading.Event):
        pool = cf.ThreadPoolExecutor(max_workers=len(SOURCES))
        step = self.interval_ms * 1_000
        next_slot = (now_us() // step + 1) * step
        last_prune = 0.0
        while not stop.is_set():
            wait = (next_slot - now_us()) / 1e6
            if wait > 0 and stop.wait(wait):
                break
            slot = next_slot
            next_slot += step
            if now_us() > next_slot:  # fell behind (e.g. suspended): skip to the next boundary
                next_slot = (now_us() // step + 1) * step
            try:
                self.publish(slot, fetch_all(pool=pool))
            except Exception as e:  # noqa: BLE001 - keep the service alive; the gap is visible in seq/slot
                print(f"publish failed at slot {slot}: {e!r}", file=sys.stderr, flush=True)
            if time.time() - last_prune > 3_600:
                self.prune()
                last_prune = time.time()


# ------------------------------------------------------------------ http ----

def make_handler(relay: Relay):
    class H(BaseHTTPRequestHandler):
        server_version = "shz-public-relay/1"

        def log_message(self, *a):
            pass

        def _json(self, code: int, obj):
            b = json.dumps(obj, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = self.path.split("?")[0]
            with relay.lock:
                latest = relay.ring[-1] if relay.ring else None
            if path == "/healthz":
                age = (now_us() - latest["body"]["slot_us"]) / 1e6 if latest else None
                return self._json(200 if latest and age < 30 else 503, {
                    "status": "ok" if latest and age < 30 else "stale", "last_seq": relay.seq, "last_slot_age_s": age,
                    "stats": relay.stats, "trust_model": "single trusted relayer; public delayed sources; provider signatures not verified",
                    "production_ready": False})
            if path == "/v1/pubkey":
                return self._json(200, {"pubkey_bip340": relay.pubkey, "signing_tag": SIGNING_TAG, "schema": SCHEMA,
                                        "message": "tagged_hash(signing_tag, canonical_json(body)), canonical = sort_keys, no spaces"})
            if path == "/v1/latest":
                return self._json(200, latest) if latest else self._json(404, {"error": "no packet yet"})
            if path.startswith("/v1/packet/"):
                try:
                    seq = int(path.rsplit("/", 1)[1])
                except ValueError:
                    return self._json(400, {"error": "bad seq"})
                with relay.lock:
                    p = relay.by_seq.get(seq)
                return self._json(200, p) if p else self._json(404, {"error": "not retained"})
            if path.startswith("/v1/archive/") and path.endswith(".jsonl"):
                name = path.rsplit("/", 1)[1]
                f = relay.dir / "archive" / name
                if len(name) != 16 or not f.is_file():
                    return self._json(404, {"error": "no archive"})
                b = f.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
                return
            if path == "/v1/stream":
                q: queue.Queue = queue.Queue(maxsize=64)
                with relay.lock:
                    relay.subscribers.add(q)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                try:
                    while True:
                        try:
                            pkt = q.get(timeout=15)
                            self.wfile.write(b"event: packet\ndata: " + json.dumps(pkt, separators=(",", ":")).encode() + b"\n\n")
                        except queue.Empty:
                            self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    relay.subscribers.discard(q)
                return
            return self._json(404, {"error": "not found"})

    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default="/var/lib/shz-public-relay")
    ap.add_argument("--listen", default="0.0.0.0:8090")
    ap.add_argument("--interval-ms", type=int, default=5_000)
    ap.add_argument("--once", action="store_true", help="fetch and print one signed packet, then exit")
    a = ap.parse_args()
    relay = Relay(Path(a.state), a.interval_ms)
    print(f"shz-public-relay pubkey={relay.pubkey} resume_seq={relay.seq}", flush=True)
    if a.once:
        pkt = relay.publish((now_us() // (a.interval_ms * 1000)) * a.interval_ms * 1000, fetch_all())
        print(json.dumps(pkt, indent=1))
        return
    host, port = a.listen.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), make_handler(relay))
    srv.daemon_threads = True
    stop = threading.Event()
    threading.Thread(target=relay.run, args=(stop,), daemon=True).start()
    try:
        srv.serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
