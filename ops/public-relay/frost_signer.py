#!/usr/bin/env python3
"""One FROST confederation member: holds one secret share, durable nonce state.

  python3 frost_signer.py --share share.json --state DIR --listen 127.0.0.1:9101
  python3 frost_signer.py keygen --t 3 --n 5 --out DIR     (trusted dealer)

POST /commit {"seq": N}                      -> {"index", "D", "E"}
POST /sign   {"seq", "body", "parent", "commitments"}  -> {"index", "z"}
GET  /healthz

Before signing, the member recomputes the packet message from the body
itself, requires a recent slot, a strictly increasing sequence, and (when it
signed seq-1) that the body extends the chain it signed. It also keeps its own
reading of the public fast sources (`SourceView`, refreshed in the background)
and signs a VALID body only when the body's median is within
`max_deviation_bps` of that reading; the coordinator assembles the packet but
cannot choose its price. It never sees or
needs the other shares. Continuity is checked against `parent`, the latest
packet the group signed: the body must link to its digest with a larger
sequence, so a slot that was signed but never published (coordinator crash)
cannot wedge the chain; each sequence is still signed at most once.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coord_auth  # noqa: E402
import dlc_oracle  # noqa: E402
import frost  # noqa: E402
import public_relay as pr  # noqa: E402

MAX_SLOT_SKEW_US = 60_000_000
MAX_SEQ = 1 << 53  # JSON-safe integer, well inside u64
MAX_SEQ_JUMP = 1 << 20  # failed signing attempts tolerated between two published packets (60 days of 5 s slots)
MAX_DEVIATION_BPS = 50  # a VALID body's median may differ this much from the member's own reading
VIEW_REFRESH_S = 15.0
VIEW_MAX_AGE_S = 35.0
NO_PRICE_CHECK = object()  # explicit opt-out for offline protocol tests; never the default


class SourceView:
    """This member's own reading of the public fast sources.

    A background thread fetches the fast sources every `refresh_s` seconds and
    applies the relay's own freshness and dispersion rules (`pr.assemble`). The
    reading is usable only when those rules give VALID. Members stagger their
    fetches by `offset_s` so five members do not hit a source at once.
    """

    def __init__(self, refresh_s: float = VIEW_REFRESH_S, offset_s: float = 0.0, sources: dict | None = None):
        self.sources = sources if sources is not None else {k: v for k, v in pr.SOURCES.items() if v[0] == "fast"}
        self.refresh_s, self.offset_s = refresh_s, offset_s
        self.lock = threading.Lock()
        self.reading: dict | None = None
        self.failures = 0
        self.pool = cf.ThreadPoolExecutor(max_workers=max(1, len(self.sources)))

    def refresh(self) -> dict:
        results = pr.fetch_all(self.sources, pool=self.pool)
        now = pr.now_us()
        body, _ = pr.assemble(0, "00" * 32, now, 0, results)
        reading = {"at_us": now, "status": body["status"], "fast_sources_used": body["fast_sources_used"],
                   "median_e8": body["median_e8"] if body["status"] == "VALID" else None}
        with self.lock:
            self.reading = reading
        return reading

    def get(self) -> dict | None:
        with self.lock:
            return self.reading

    def run(self, stop: threading.Event):
        stop.wait(self.offset_s)
        while not stop.is_set():
            try:
                self.refresh()
            except Exception:  # noqa: BLE001 - a failed refresh leaves the old reading to age out
                self.failures += 1
            stop.wait(self.refresh_s)


class StaticView:
    """A reading set by the caller (tests, drills). Always reports the current time unless `at_us` is given."""

    def __init__(self, median_e8: int | None = None):
        self.median_e8, self.at_us = median_e8, None

    def set(self, median_e8: int | None, at_us: int | None = None):
        self.median_e8, self.at_us = median_e8, at_us

    def set_from_results(self, results: dict, slot_us: int):
        fast = {k: v for k, v in results.items() if v[0] == "fast"}
        body, _ = pr.assemble(0, "00" * 32, slot_us, 0, fast)
        self.set(body["median_e8"] if body["status"] == "VALID" else None)

    def get(self) -> dict | None:
        return {"at_us": self.at_us if self.at_us is not None else pr.now_us(), "status": "VALID" if self.median_e8 else "HOLD",
                "fast_sources_used": 4 if self.median_e8 else 0, "median_e8": self.median_e8}


class Member:
    def __init__(self, share: dict, state_dir: Path, view=None, max_deviation_bps: int = MAX_DEVIATION_BPS,
                 view_max_age_s: float = VIEW_MAX_AGE_S):
        """`view` is the member's own price reading (`SourceView`, `StaticView`). With no view
        the member refuses every VALID body; `NO_PRICE_CHECK` disables the check explicitly."""
        self.share = share
        self.index = share["index"]
        self.view = view
        self.max_deviation_bps = max_deviation_bps
        self.view_max_age_us = int(view_max_age_s * 1_000_000)
        self.content_refusals = 0
        state_dir.mkdir(parents=True, exist_ok=True)
        self.state = frost.SignerState(state_dir / "nonces.json")
        self.lock = threading.Lock()
        self.signed = 0
        self.refused = 0
        self.auth_refused = 0
        self.coord_auth = False
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

    def _window_clear(self, event_id: str):
        with self.dlc_lock:
            maturity_us = self.dlc._ev(event_id)["maturity_unix"] * 1_000_000
        if any(maturity_us <= s < maturity_us + dlc_oracle.OUTCOME_WINDOW_US for s in self.seen_valid):
            raise ValueError("a VALID packet in the outcome window exists")

    def dlc_lock_unattestable(self, req: dict) -> dict:
        event_id = req["event_id"]
        self._window_clear(event_id)
        with self.dlc_lock:
            lock = self.dlc.lock_decision(event_id, dlc_oracle.UNATTESTABLE, pr.now_us())
        return {"index": self.index, "lock": lock}

    def dlc_unattestable(self, req: dict) -> dict:
        event_id, signers = req["event_id"], [int(x) for x in req["signers"]]
        self._window_clear(event_id)
        with self.dlc_lock:
            z = self.dlc.sign_unattestable(event_id, pr.now_us(), signers, req.get("locks"))
        return {"index": self.index, "z": z}

    def _outcome_price(self, event_id: str, pkt: dict) -> int:
        """Price of a group-signed VALID packet in [maturity, maturity + 30 s) that is not
        preceded by a VALID packet this member has seen at or after maturity."""
        if not pr.verify_packet(pkt, self.share["group"]["group_pubkey"]):
            raise ValueError("outcome packet is not group-signed")
        b = pkt["body"]
        with self.dlc_lock:
            maturity_us = self.dlc._ev(event_id)["maturity_unix"] * 1_000_000
        slot, median = b.get("slot_us"), b.get("median_e8")
        if b.get("status") != "VALID" or type(slot) is not int or not maturity_us <= slot < maturity_us + dlc_oracle.OUTCOME_WINDOW_US:
            raise ValueError("outcome packet is not a VALID packet in the maturity window")
        if type(median) is not int or median <= 0:
            raise ValueError("outcome packet has no positive integer median")
        if any(maturity_us <= s < slot for s in self.seen_valid):
            raise ValueError("an earlier VALID packet at or after maturity exists")
        self._observe(pkt)
        return median // 100_000_000

    def dlc_lock_outcome(self, req: dict) -> dict:
        """Phase 1: durably lock this event to the packet's price and sign the lock."""
        event_id = req["event_id"]
        price = self._outcome_price(event_id, req["packet"])
        with self.dlc_lock:
            lock = self.dlc.lock_decision(event_id, dlc_oracle.price_decision(price))
        return {"index": self.index, "price_usd": price, "lock": lock}

    def dlc_attest(self, req: dict) -> dict:
        """Phase 2: release digit partials once a quorum of members locked the same price."""
        event_id, signers = req["event_id"], [int(x) for x in req["signers"]]
        price = self._outcome_price(event_id, req["packet"])
        with self.dlc_lock:
            zs = self.dlc.sign_outcome(event_id, price, signers, req.get("locks"))
        return {"index": self.index, "price_usd": price, "z": zs}

    def _check_content(self, body: dict):
        """Refuse a body whose price this member cannot confirm from its own reading.

        HOLD bodies assert no usable price and are signed without a reading. A VALID
        body needs a positive integer median within `max_deviation_bps` of a reading
        that is itself VALID and no older than `view_max_age_us`."""
        status = body.get("status")
        if body.get("market") != "BTC/USD" or status not in ("VALID", "HOLD"):
            raise ValueError("unknown market or status")
        if status != "VALID":
            return
        median = body.get("median_e8")
        if type(median) is not int or median <= 0:
            raise ValueError("VALID body has no positive integer median")
        if self.view is NO_PRICE_CHECK:
            return
        reading = self.view.get() if self.view is not None else None
        try:
            if reading is None or reading.get("median_e8") is None:
                raise ValueError("no usable independent price reading")
            if pr.now_us() - reading["at_us"] > self.view_max_age_us:
                raise ValueError("independent price reading is stale")
            dev = abs(median - reading["median_e8"]) * 10_000 // reading["median_e8"]
            if dev > self.max_deviation_bps:
                raise ValueError(f"median is {dev} bps from this member's own reading (limit {self.max_deviation_bps})")
        except ValueError:
            self.content_refusals += 1
            raise

    def view_status(self) -> dict:
        if self.view is NO_PRICE_CHECK:
            return {"check": "disabled"}
        reading = self.view.get() if self.view is not None else None
        if reading is None:
            return {"check": "enabled", "reading": None}
        return {"check": "enabled", "status": reading["status"], "fast_sources_used": reading["fast_sources_used"],
                "median_e8": reading["median_e8"], "age_s": round((pr.now_us() - reading["at_us"]) / 1e6, 3),
                "max_deviation_bps": self.max_deviation_bps, "content_refusals": self.content_refusals}

    def commit(self, seq: int) -> dict:
        if type(seq) is not int or not 0 < seq < MAX_SEQ:
            raise ValueError("sequence out of range")
        with self.lock:
            d, e = self.state.commit(seq)
        return {"index": self.index, "D": frost.ser(frost._mul(frost.G, d)).hex(), "E": frost.ser(frost._mul(frost.G, e)).hex()}

    def sign(self, req: dict) -> dict:
        body, seq, commits = req["body"], int(req["seq"]), req["commitments"]
        if body.get("schema") != pr.SCHEMA or body.get("seq") != seq:
            raise ValueError("body does not match the requested sequence")
        slot = body.get("slot_us")
        if type(slot) is not int or abs(pr.now_us() - slot) > MAX_SLOT_SKEW_US:
            raise ValueError("slot time not recent")
        parent = req.get("parent")
        if parent is None:
            # Genesis only for a member that has never signed.
            if body.get("previous") != "00" * 32 or self.state.s["last_seq"] != 0:
                raise ValueError("missing parent packet")
            parent_seq = 0
        else:
            # Continuity: the body must extend a packet the group already signed.
            if not pr.verify_packet(parent, self.share["group"]["group_pubkey"]):
                raise ValueError("parent packet is not group-signed")
            parent_seq = parent["body"]["seq"]
            if parent_seq >= seq or body.get("previous") != parent["digest"]:
                raise ValueError("body does not extend the parent packet")
            if parent["body"]["slot_us"] >= slot:
                raise ValueError("slot does not advance past the parent packet")
            self._observe(parent)
        # A sequence is a counter of signing attempts: it cannot outrun the group-signed
        # parent by more than a bounded number of failed slots, and it stays a u64.
        if not seq < MAX_SEQ or seq - parent_seq > MAX_SEQ_JUMP:
            raise ValueError("sequence jumps too far past the parent packet")
        self._check_content(body)  # before take(): a refusal spends neither the nonce nor the sequence
        msg = pr.packet_message(body)
        with self.lock:
            # One packet per slot per member: with 2t > n two packets for the same slot
            # would need a member to sign both.
            if slot <= self.state.s.get("last_slot", 0):
                raise ValueError("slot already signed or older")
            d, e = self.state.take(seq, msg, slot)
            z = frost.partial_sign(self.share, d, e, msg, commits)
            self.signed += 1
        return {"index": self.index, "z": z.to_bytes(32, "big").hex()}


def make_handler(m: Member, verifier):
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
                                        "group_pubkey": m.share["group"]["group_pubkey"], "price_view": m.view_status(),
                                        "coord_auth": m.coord_auth, "auth_refused": m.auth_refused})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            try:
                raw = self.rfile.read(max(0, min(int(self.headers.get("Content-Length", 0)), 1_000_000)))
                if verifier is not coord_auth.UNAUTHENTICATED:
                    verifier.check(self.path, raw, self.headers.get(coord_auth.HEADER))
            except (coord_auth.AuthError, ValueError) as e:
                m.auth_refused += 1
                return self._json(401, {"error": f"unauthorized: {e}"})
            try:
                req = json.loads(raw)
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
                if self.path == "/dlc/lock-outcome":
                    return self._json(200, m.dlc_lock_outcome(req))
                if self.path == "/dlc/lock-unattestable":
                    return self._json(200, m.dlc_lock_unattestable(req))
                if self.path == "/dlc/sign-outcome":
                    return self._json(200, m.dlc_attest(req))
                if self.path == "/dlc/sign-unattestable":
                    return self._json(200, m.dlc_unattestable(req))
                return self._json(404, {"error": "not found"})
            except Exception as e:  # noqa: BLE001 - every refusal is reported to the coordinator
                m.refused += 1
                return self._json(409, {"error": f"{type(e).__name__}: {e}"})

    return H


def serve(m: Member, listen: str, verifier) -> ThreadingHTTPServer:
    """`verifier` is a `coord_auth.Verifier` for this member, or `coord_auth.UNAUTHENTICATED`
    to accept any local caller (offline drills only)."""
    if verifier is not coord_auth.UNAUTHENTICATED:
        if not isinstance(verifier, coord_auth.Verifier) or verifier.index != m.index                 or verifier.group_pubkey != m.share["group"]["group_pubkey"]:
            raise ValueError("coordinator verifier does not match this member")
    m.coord_auth = verifier is not coord_auth.UNAUTHENTICATED
    host, port = listen.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), make_handler(m, verifier))
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
    ap.add_argument("--max-deviation-bps", type=int, default=MAX_DEVIATION_BPS, help="largest accepted distance of a VALID median from this member's own reading")
    ap.add_argument("--view-refresh-s", type=float, default=VIEW_REFRESH_S, help="how often this member reads the public fast sources")
    ap.add_argument("--view-max-age-s", type=float, default=VIEW_MAX_AGE_S, help="oldest own reading a VALID body may be checked against")
    ap.add_argument("--no-price-check", action="store_true", help="sign VALID bodies without an independent reading (offline drills only)")
    ap.add_argument("--coord-auth-key", help="this member's coordinator authentication key (hex file, coord_auth.py derive)")
    ap.add_argument("--no-coord-auth", action="store_true", help="accept requests from any local caller (offline drills only)")
    a = ap.parse_args()
    if bool(a.coord_auth_key) == a.no_coord_auth:
        ap.error("give exactly one of --coord-auth-key or --no-coord-auth")
    share = json.loads(Path(a.share).read_text())
    if a.no_price_check:
        view = NO_PRICE_CHECK
    else:
        n = share["group"]["signers"]
        view = SourceView(a.view_refresh_s, offset_s=(share["index"] - 1) * a.view_refresh_s / n)
        threading.Thread(target=view.run, args=(threading.Event(),), daemon=True).start()
    m = Member(share, Path(a.state), view=view, max_deviation_bps=a.max_deviation_bps, view_max_age_s=a.view_max_age_s)
    verifier = coord_auth.UNAUTHENTICATED if a.no_coord_auth else         coord_auth.Verifier(coord_auth.read_key(a.coord_auth_key), share["group"]["group_pubkey"], share["index"])
    srv = serve(m, a.listen, verifier)
    print(f"frost member {m.index} group={m.share['group']['group_pubkey']} listen={a.listen} price_check={'off' if a.no_price_check else 'on'} "
          f"coord_auth={'on' if m.coord_auth else 'OFF'}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
