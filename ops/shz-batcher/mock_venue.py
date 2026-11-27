#!/usr/bin/env python3
"""Mock venue for shz-batcher drills: the settlement co-sign contract
(side note shz-settlement-cosign-contract.md, ops/shz-batcher/README.md) over replayed venue batches.

Batches: real committed explorer batches (e.g. research/lightninger_dlc_batcher/artifacts/venue_batches.json,
batches 306..313) replayed under a plan that renumbers them, places each in an epoch of `epoch_secs`
after `t0`, and inserts aborted seqs. A batch appears in /api/explorer/batches once its time passes.
The V3 digest does not cover the seq, so renumbering keeps every clearing vector authentic.

Plan JSON: {"epoch_secs": 60, "batches": [{"src": 306, "seq": 1, "epoch": 0, "at": 10}, {"seq": 5,
"aborted": true, "epoch": 1, "at": 20}, ...], "unattestable": [2]}

Checks what a venue checks: X-SHZ-Batcher BIP340 over tagged_hash("SHZ/BATCHER/POST/V1", body) by the
batcher key, trader signatures against the package sighash, withdrawal signatures, the deadline.
"""
import argparse, hashlib, json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# --- BIP340 verify (pure Python) ---
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def padd(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


def pmul(p, n):
    r = None
    while n:
        if n & 1: r = padd(r, p)
        p = padd(p, p); n >>= 1
    return r


def lift_x(x):
    if x >= P: return None
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if y * y % P != (pow(x, 3, P) + 7) % P: return None
    return (x, y if y % 2 == 0 else P - y)


def tagged(tag, msg):
    t = hashlib.sha256(tag).digest()
    return hashlib.sha256(t + t + msg).digest()


def bip340_verify(pk, msg, sig):
    if len(pk) != 32 or len(sig) != 64 or len(msg) != 32: return False
    p = lift_x(int.from_bytes(pk, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if p is None or r >= P or s >= N: return False
    e = int.from_bytes(tagged(b"BIP0340/challenge", sig[:32] + pk + msg), "big") % N
    R = padd(pmul(G, s), pmul(p, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def withdraw_msg(owner, spk, time_us):
    return tagged(b"SHZ/WITHDRAW/V1", owner + len(spk).to_bytes(4, "little") + spk + time_us.to_bytes(8, "little"))


class Mock:
    def __init__(self, a):
        self.lock = threading.Lock()
        src = json.load(open(a.source))
        self.src = {b["batch"]["seq"]: b["batch"] for b in src["batches"]}
        self.status = src.get("status_before", {})
        self.plan = json.load(open(a.plan))
        self.E = self.plan["epoch_secs"]
        self.t0 = a.t0
        self.registry = json.load(open(a.registry))
        self.batcher = bytes.fromhex(a.batcher_key)
        self.packages = {}       # (epoch, segment) -> package
        self.by_owner = {}       # owner -> (epoch, segment)
        self.sigs = {}           # (epoch, segment) -> {owner: {sig, received_us}}
        self.results = []
        self.withdrawals = {}    # owner -> request
        self.closed = set()
        self.log = open(a.log, "a") if a.log else None

    def note(self, s):
        line = f"[{time.time():.3f}] {s}"
        print(line, flush=True)
        if self.log: self.log.write(line + "\n"); self.log.flush()

    def batches(self):
        now = time.time()
        out = []
        for p in self.plan["batches"]:
            t = self.t0 + p["epoch"] * self.E + p["at"]
            if t > now: continue
            us = int(t * 1e6)
            if p.get("aborted"):
                out.append({"seq": p["seq"], "phase": "aborted", "created_us": us, "committed_us": None, "clearing": None, "accounts": [], "acks": []})
            else:
                b = json.loads(json.dumps(self.src[p["src"]]))
                b["seq"] = p["seq"]; b["committed_us"] = us; b["source_seq"] = p["src"]
                out.append(b)
        return sorted(out, key=lambda b: -b["seq"])

    def events(self):
        now = time.time()
        ev = []
        i = 0
        while self.t0 + (i + 1) * self.E <= now - 1:
            m = self.t0 + (i + 1) * self.E
            ev.append({"maturity_unix": m, "status": "unattestable_no_valid_packet" if i in self.plan.get("unattestable", []) else "attested"})
            i += 1
        return {"events": ev}

    def accounts(self):
        return [dict(a, closed=a["owner"] in self.closed) for a in self.registry]


class H(BaseHTTPRequestHandler):
    m: Mock = None

    def log_message(self, *a):
        pass

    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}; m = self.m
        with m.lock:
            if u.path == "/api/explorer/batches": return self.send(200, m.batches()[: int(q.get("limit", 50))])
            if u.path == "/api/explorer/accounts": return self.send(200, m.accounts())
            if u.path == "/api/status": return self.send(200, m.status)
            if u.path == "/api/explorer/dlc": return self.send(200, m.events())
            if u.path == "/api/explorer/settlements": return self.send(200, list(reversed(m.results)))
            if u.path == "/api/settlement/withdrawals": return self.send(200, list(m.withdrawals.values()))
            if u.path == "/api/settlement/package":
                k = m.by_owner.get(q.get("owner", ""))
                if not k: return self.send(404, {"error": "no package"})
                p = m.packages[k]
                acct = next(a for a in p["accounts"] if a["owner"] == q["owner"])
                return self.send(200, {"epoch": p["epoch"], "segment": p["segment"], "deadline_us": p["deadline_us"], "tx": p["tx"], "account": acct})
            if u.path == "/api/settlement/signatures":
                k = (q.get("epoch"), int(q.get("segment", 0)))
                return self.send(200, {"signatures": [dict(owner=o, **v) for o, v in m.sigs.get(k, {}).items()]})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path); m = self.m
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            j = json.loads(body)
        except Exception:
            return self.send(400, {"error": "bad json"})
        with m.lock:
            if u.path in ("/api/settlement/package", "/api/settlement/result"):
                sig = bytes.fromhex(self.headers.get("X-SHZ-Batcher", ""))
                if not bip340_verify(m.batcher, tagged(b"SHZ/BATCHER/POST/V1", body), sig):
                    m.note(f"{u.path}: refused, X-SHZ-Batcher does not verify")
                    return self.send(401, {"error": "X-SHZ-Batcher does not verify"})
                if u.path.endswith("package"):
                    k = (j["epoch"], j["segment"])
                    m.packages[k] = j
                    for a in j["accounts"]: m.by_owner[a["owner"]] = k
                    m.note(f"package {k}: {len(j['accounts'])} accounts, deadline {j['deadline_us']}")
                    return self.send(200, {"ok": True})
                m.results.append(dict(j, received_us=int(time.time() * 1e6)))
                if j.get("status") in ("broadcast", "staged"):
                    for p in j.get("payouts", []):
                        if p["kind"] == "withdraw" and j["status"] == "broadcast":
                            m.closed.add(p["owner"]); m.withdrawals.pop(p["owner"], None)
                    k = (j["epoch"], j["segment"])
                    for o in list(m.by_owner):
                        if m.by_owner[o] == k: del m.by_owner[o]
                m.note(f"result {j.get('epoch')}#{j.get('segment')}: {j.get('status')} {j.get('txid')} statement {j.get('statement_sha256')}")
                return self.send(200, {"ok": True})
            if u.path == "/api/settlement/signature":
                k = (j.get("epoch"), j.get("segment"))
                p = m.packages.get(k)
                if not p: return self.send(404, {"error": "no such package"})
                if time.time() * 1e6 > p["deadline_us"]: return self.send(409, {"error": "past the deadline"})
                a = next((a for a in p["accounts"] if a["owner"] == j.get("owner")), None)
                sig = bytes.fromhex(j.get("sig", ""))
                if not a or len(sig) != 65 or sig[64] != 0x83 or not bip340_verify(bytes.fromhex(a["owner"]), bytes.fromhex(a["sighash"]), sig[:64]):
                    return self.send(400, {"error": "signature does not verify"})
                m.sigs.setdefault(k, {})[a["owner"]] = {"sig": j["sig"], "received_us": int(time.time() * 1e6)}
                return self.send(200, {"ok": True})
            if u.path == "/api/settlement/withdraw":
                o, spk, t, sig = bytes.fromhex(j["owner"]), bytes.fromhex(j["spk"]), int(j["time_us"]), bytes.fromhex(j["sig"])
                if not bip340_verify(o, withdraw_msg(o, spk, t), sig): return self.send(400, {"error": "withdrawal signature does not verify"})
                m.withdrawals[j["owner"]] = j
                m.note(f"withdrawal requested by {j['owner'][:8]}")
                return self.send(200, {"ok": True})
        self.send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8197)
    ap.add_argument("--source", required=True)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--batcher-key", required=True)
    ap.add_argument("--t0", type=int, required=True)
    ap.add_argument("--log")
    a = ap.parse_args()
    H.m = Mock(a)
    H.m.note(f"mock venue on 127.0.0.1:{a.port}, t0 {a.t0}, epoch {H.m.E}s")
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
