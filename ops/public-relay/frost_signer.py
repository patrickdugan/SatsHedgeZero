#!/usr/bin/env python3
"""One FROST confederation member: holds one secret share, durable nonce state.

  python3 frost_signer.py --share share.json --state DIR --listen 127.0.0.1:9101
  python3 frost_signer.py keygen --t 3 --n 5 --out DIR     (trusted dealer)

POST /commit {"seq": N}                      -> {"index", "D", "E"}
POST /sign   {"seq", "body", "parent", "commitments"}  -> {"index", "z"}
GET  /healthz

Before signing, the member recomputes the packet message from the body
itself, requires a recent slot, a strictly increasing sequence, and (when it
signed seq-1) that the body extends the chain it signed. It never sees or
needs the other shares. Continuity is checked against `parent`, the latest
packet the group signed: the body must link to its digest with a larger
sequence, so a slot that was signed but never published (coordinator crash)
cannot wedge the chain; each sequence is still signed at most once.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dlc_oracle  # noqa: E402
import frost  # noqa: E402
import public_relay as pr  # noqa: E402

MAX_SLOT_SKEW_US = 60_000_000


class Member:
    def __init__(self, share: dict, state_dir: Path):
        self.share = share
        self.index = share["index"]
        state_dir.mkdir(parents=True, exist_ok=True)
        self.state = frost.SignerState(state_dir / "nonces.json")
        self.lock = threading.Lock()
        self.signed = 0
        self.refused = 0
        self.dlc = dlc_oracle.DlcMember(share, state_dir / "dlc.json")
        self.dlc_lock = threading.Lock()
        # Earliest VALID group-signed packet seen per slot, for outcome selection.
        self.seen_valid: dict[int, dict] = {}

    def _observe(self, pkt: dict):
        """Remember group-signed VALID packets (verified by the caller)."""
        if pkt["body"].get("status") == "VALID":
            self.seen_valid[pkt["body"]["slot_us"]] = pkt
            if len(self.seen_valid) > 2_000:
                self.seen_valid.pop(min(self.seen_valid))

    def dlc_unattestable(self, req: dict) -> dict:
        event_id, signers = req["event_id"], [int(x) for x in req["signers"]]
        with self.dlc_lock:
            maturity_us = self.dlc._ev(event_id)["maturity_unix"] * 1_000_000
            if any(maturity_us <= s < maturity_us + dlc_oracle.OUTCOME_WINDOW_US for s in self.seen_valid):
                raise ValueError("a VALID packet in the outcome window exists")
            z = self.dlc.sign_unattestable(event_id, pr.now_us(), signers)
        return {"index": self.index, "z": z}

    def dlc_attest(self, req: dict) -> dict:
        """Attest only a group-signed VALID packet in [maturity, maturity + 30 s) and,
        if this member has seen an earlier VALID packet at or after maturity, only that one."""
        event_id, pkt, signers = req["event_id"], req["packet"], [int(x) for x in req["signers"]]
        if not pr.verify_packet(pkt, self.share["group"]["group_pubkey"]):
            raise ValueError("outcome packet is not group-signed")
        b = pkt["body"]
        with self.dlc_lock:
            maturity_us = self.dlc._ev(event_id)["maturity_unix"] * 1_000_000
        if b.get("status") != "VALID" or not maturity_us <= b["slot_us"] < maturity_us + dlc_oracle.OUTCOME_WINDOW_US:
            raise ValueError("outcome packet is not a VALID packet in the maturity window")
        earlier = [s for s in self.seen_valid if maturity_us <= s < b["slot_us"]]
        if earlier:
            raise ValueError("an earlier VALID packet at or after maturity exists")
        price = b["median_e8"] // 100_000_000
        with self.dlc_lock:
            zs = self.dlc.sign_outcome(event_id, price, signers)
        return {"index": self.index, "price_usd": price, "z": zs}

    def commit(self, seq: int) -> dict:
        with self.lock:
            d, e = self.state.commit(seq)
        return {"index": self.index, "D": frost.ser(frost._mul(frost.G, d)).hex(), "E": frost.ser(frost._mul(frost.G, e)).hex()}

    def sign(self, req: dict) -> dict:
        body, seq, commits = req["body"], int(req["seq"]), req["commitments"]
        if body.get("schema") != pr.SCHEMA or body.get("seq") != seq:
            raise ValueError("body does not match the requested sequence")
        if abs(pr.now_us() - int(body["slot_us"])) > MAX_SLOT_SKEW_US:
            raise ValueError("slot time not recent")
        parent = req.get("parent")
        if parent is None:
            # Genesis only for a member that has never signed.
            if body.get("previous") != "00" * 32 or self.state.s["last_seq"] != 0:
                raise ValueError("missing parent packet")
        else:
            # Continuity: the body must extend a packet the group already signed.
            if not pr.verify_packet(parent, self.share["group"]["group_pubkey"]):
                raise ValueError("parent packet is not group-signed")
            if parent["body"]["seq"] >= seq or body.get("previous") != parent["digest"]:
                raise ValueError("body does not extend the parent packet")
            self._observe(parent)
        msg = pr.packet_message(body)
        with self.lock:
            d, e = self.state.take(seq, msg)
            z = frost.partial_sign(self.share, d, e, msg, commits)
            self.signed += 1
        return {"index": self.index, "z": z.to_bytes(32, "big").hex()}


def make_handler(m: Member):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/healthz":
                return self._json(200, {"index": m.index, "last_seq": m.state.s["last_seq"], "signed": m.signed, "refused": m.refused,
                                        "group_pubkey": m.share["group"]["group_pubkey"]})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            try:
                req = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 1_000_000)))
                if self.path == "/commit":
                    return self._json(200, m.commit(int(req["seq"])))
                if self.path == "/sign":
                    return self._json(200, m.sign(req))
                if self.path == "/dlc/deal":
                    with m.dlc_lock:
                        return self._json(200, m.dlc.deal(req["event_id"], int(req["maturity_unix"]), int(req["num_bits"]), [int(x) for x in req["members"]]))
                if self.path == "/dlc/receive":
                    with m.dlc_lock:
                        return self._json(200, {"index": m.index, "R": m.dlc.receive(req["event_id"], req["deals"])})
                if self.path == "/dlc/sign-announcement":
                    with m.dlc_lock:
                        return self._json(200, {"index": m.index, "z": m.dlc.sign_announcement(req["event_id"], req["core"], [int(x) for x in req["signers"]])})
                if self.path == "/dlc/sign-outcome":
                    return self._json(200, m.dlc_attest(req))
                if self.path == "/dlc/sign-unattestable":
                    return self._json(200, m.dlc_unattestable(req))
                return self._json(404, {"error": "not found"})
            except Exception as e:  # noqa: BLE001 - every refusal is reported to the coordinator
                m.refused += 1
                return self._json(409, {"error": f"{type(e).__name__}: {e}"})

    return H


def serve(m: Member, listen: str) -> ThreadingHTTPServer:
    host, port = listen.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), make_handler(m))
    srv.daemon_threads = True
    return srv


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "keygen":
        ap = argparse.ArgumentParser()
        ap.add_argument("cmd")
        ap.add_argument("--t", type=int, default=3)
        ap.add_argument("--n", type=int, default=5)
        ap.add_argument("--out", required=True)
        a = ap.parse_args()
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        group, shares = frost.keygen(a.t, a.n)
        (out / "group.json").write_text(json.dumps(group, indent=1))
        for s in shares:
            fd = os.open(out / f"share{s['index']}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(s, f)
        print(group["group_pubkey"])
        return
    ap = argparse.ArgumentParser()
    ap.add_argument("--share", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--listen", default="127.0.0.1:9101")
    a = ap.parse_args()
    m = Member(json.loads(Path(a.share).read_text()), Path(a.state))
    print(f"frost member {m.index} group={m.share['group']['group_pubkey']} listen={a.listen}", flush=True)
    serve(m, a.listen).serve_forever()


if __name__ == "__main__":
    main()
