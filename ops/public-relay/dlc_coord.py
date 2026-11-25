"""DLC event scheduler for the FROST coordinator.

Every `every_min` minutes is a maturity. The coordinator keeps the next
`ahead` maturities announced: it runs the per-event nonce DKG among the
members, gets the announcement threshold-signed with the reserved nonce, and
publishes it. At maturity it takes the first VALID group-signed relay packet
in [maturity, maturity + 30 s), asks a threshold set of members to attest
the outcome (each member re-checks the packet itself), verifies every partial
and publishes the attestation in `shz_dlc` serde form.

GET /v1/dlc/events            announced events and status
GET /v1/dlc/event/<event_id>  announcement (+ attestation once attested)
"""
from __future__ import annotations

import itertools
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import dlc_oracle as dlc
import frost
import public_relay as pr


class SetupWedged(RuntimeError):
    """A member already consumed its dealing for this event (an earlier setup was
    interrupted after `receive`), so the event can never reach a full DKG again."""


def _post(url: str, obj: dict, timeout: float = 30.0) -> dict:
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def event_id_for(maturity_unix: int) -> str:
    return "SHZ-BTCUSD-" + datetime.fromtimestamp(maturity_unix, timezone.utc).strftime("%Y%m%dT%H%MZ")


class DlcCoordinator:
    def __init__(self, relay, state_dir: Path, every_min: int = 15, ahead: int = 4, num_bits: int = dlc.NUM_BITS):
        self.relay = relay
        self.group = relay.group
        self.t = self.group["threshold"]
        self.q = dlc.decision_quorum(self.t, self.group["signers"])
        self.dir = state_dir / "dlc"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.every = every_min * 60
        self.ahead = ahead
        self.num_bits = num_bits
        self.url_by_index: dict[int, str] = {}
        self.stats = {"announced": 0, "attested": 0, "setup_failures": 0, "attest_failures": 0, "unattestable": 0}
        self.lock = threading.Lock()

    # ------------------------------------------------------------ storage ----
    def _path(self, event_id: str) -> Path:
        return self.dir / f"{event_id}.json"

    def load(self, event_id: str) -> dict | None:
        p = self._path(event_id)
        return json.loads(p.read_text()) if p.exists() else None

    def _save(self, ev: dict):
        dlc._atomic_write(self._path(ev["core"]["event_id"]), ev)

    # -------------------------------------------------------------- setup ----
    def setup(self, maturity_unix: int) -> dict:
        event_id = event_id_for(maturity_unix)
        existing = self.load(event_id)
        if existing:
            return existing
        n = self.group["signers"]
        req = {"event_id": event_id, "maturity_unix": maturity_unix, "num_bits": self.num_bits, "members": list(range(1, n + 1))}
        deals = {}
        consumed = []
        for url in self.relay.signers:
            try:
                d = _post(url + "/dlc/deal", req)
            except urllib.error.HTTPError as e:
                if b"event already set up" in e.read():
                    consumed.append(url)
                continue
            except Exception:  # noqa: BLE001 - absent member is simply not a dealer
                continue
            deals[str(d["dealer"])] = d
            self.url_by_index[d["dealer"]] = url
        if consumed and len(deals) < self.q:
            raise SetupWedged(f"{len(consumed)} member(s) already consumed their dealing; {len(deals)} dealers < quorum {self.q}")
        if len(deals) < self.q:
            raise RuntimeError(f"only {len(deals)} dealers; the decision quorum is {self.q}")
        qualified = sorted(int(k) for k in deals)
        rs = {}
        for j in qualified:
            view = {k: {"commitments": v["commitments"], "enc": {str(j): v["enc"][str(j)]} if str(j) in v["enc"] else {}} for k, v in deals.items()}
            rs[j] = _post(self.url_by_index[j] + "/dlc/receive", {"event_id": event_id, "deals": view})["R"]
        r_list = rs[qualified[0]]
        if any(r != r_list for r in rs.values()):
            raise RuntimeError("members disagree on group nonces")
        negate = [bool(dlc.group_nonce(deals, d)[1] & 1) for d in range(dlc.nonce_count(self.num_bits))]
        core = dlc.canonical_core(self.group, event_id, maturity_unix, self.num_bits, r_list)
        msg = dlc.announcement_message(core)
        sig = None
        for subset in itertools.combinations(qualified, self.t):
            try:
                parts = {j: int(_post(self.url_by_index[j] + "/dlc/sign-announcement", {"event_id": event_id, "core": core, "signers": list(subset)})["z"], 16) for j in subset}
                sig = dlc.aggregate(self.group, deals, negate, self.num_bits, msg, r_list[self.num_bits], parts)
                break
            except Exception:  # noqa: BLE001 - try another set
                continue
        if sig is None:
            raise RuntimeError("announcement not signed")
        ev = {
            "core": core,
            "announcement_digest": msg.hex(),
            "announcement_signature": sig.hex(),
            "shz_dlc_announcement": dlc.shz_dlc_announcement(core),
            "nonce_commitments": {k: v["commitments"] for k, v in deals.items()},
            "negate": negate,
            "qualified": qualified,
            "status": "announced",
        }
        self._save(ev)
        self.stats["announced"] += 1
        return ev

    # ------------------------------------------------------------- attest ----
    def outcome_packet(self, maturity_unix: int) -> dict | None:
        lo = maturity_unix * 1_000_000
        with self.relay.lock:
            cands = [p for p in self.relay.ring if lo <= p["body"]["slot_us"] < lo + dlc.OUTCOME_WINDOW_US and p["body"]["status"] == "VALID"]
        return min(cands, key=lambda p: p["body"]["slot_us"]) if cands else None

    def attest(self, ev: dict) -> dict:
        core = ev["core"]
        event_id, nb = core["event_id"], core["num_bits"]
        pkt = self.outcome_packet(core["maturity_unix"])
        if pkt is None:
            if pr.now_us() > core["maturity_unix"] * 1_000_000 + dlc.OUTCOME_WINDOW_US + dlc.UNATTESTABLE_GRACE_US:
                return self.declare_unattestable(ev)
            return ev
        deals = {k: {"commitments": v} for k, v in ev["nonce_commitments"].items()}
        price = pkt["body"]["median_e8"] // 100_000_000
        bits = dlc.decompose(price, nb)
        msgs = [dlc.digit_message(event_id, d, bits[d]) for d in range(nb)]
        # Phase 1: every reachable member durably locks the event to this price. Digit
        # partials are requested only once a quorum holds the same lock.
        locks = self._collect_locks(ev, "/dlc/lock-outcome", {"event_id": event_id, "packet": pkt}, dlc.price_decision(price))
        if locks is None:
            return ev
        for subset in itertools.combinations(sorted(int(k) for k in locks), self.t):
            try:
                res = {j: _post(self.url_by_index[j] + "/dlc/sign-outcome", {"event_id": event_id, "packet": pkt, "signers": list(subset), "locks": locks}) for j in subset}
                if any(r["price_usd"] != price for r in res.values()):
                    continue
                sigs = [dlc.aggregate(self.group, deals, ev["negate"], d, msgs[d], core["digit_nonces_x"][d],
                                      {j: int(res[j]["z"][d], 16) for j in subset}) for d in range(nb)]
            except frost.CheatingSigner:
                continue
            except Exception:  # noqa: BLE001 - unreachable or refusing member: try another set
                continue
            ev.update(
                status="attested",
                attestation={"price_usd": price, "digit_bits": bits, "digit_signatures": [s.hex() for s in sigs], "signers": list(subset),
                             "decision_locks": locks,
                             "outcome_packet": {"seq": pkt["body"]["seq"], "slot_us": pkt["body"]["slot_us"], "digest": pkt["digest"]}},
                shz_dlc_attestation=dlc.shz_dlc_attestation(event_id, pkt["body"]["slot_us"] // 1_000_000, price, bits, sigs),
            )
            self._save(ev)
            self.stats["attested"] += 1
            return ev
        self.stats["attest_failures"] += 1
        return ev

    def _collect_locks(self, ev: dict, path: str, req: dict, decision: str) -> dict | None:
        """Ask every qualified member to lock `decision`; return {index: lock signature}
        once the quorum is verified, else None (counted as an attestation failure)."""
        raw = {}
        for j in ev["qualified"]:
            try:
                raw[str(j)] = _post(self.url_by_index[j] + path, req)["lock"]
            except Exception:  # noqa: BLE001 - a refusing or absent member contributes no lock
                continue
        ok = dlc.verified_lockers(self.group, ev["core"]["event_id"], decision, raw)
        if len(ok) < self.q:
            self.stats["attest_failures"] += 1
            return None
        return {str(j): raw[str(j)] for j in sorted(ok)}

    def declare_unattestable(self, ev: dict) -> dict:
        core = ev["core"]
        event_id, nb = core["event_id"], core["num_bits"]
        if "unattestable_nonce_x" not in core:
            ev["status"] = "unattestable_no_valid_packet"  # announced before the notice nonce existed
            self._save(ev)
            self.stats["unattestable"] += 1
            return ev
        deals = {k: {"commitments": v} for k, v in ev["nonce_commitments"].items()}
        msg = dlc.unattestable_message(event_id)
        locks = self._collect_locks(ev, "/dlc/lock-unattestable", {"event_id": event_id}, dlc.UNATTESTABLE)
        if locks is None:
            return ev
        for subset in itertools.combinations(sorted(int(k) for k in locks), self.t):
            try:
                parts = {j: int(_post(self.url_by_index[j] + "/dlc/sign-unattestable", {"event_id": event_id, "signers": list(subset), "locks": locks})["z"], 16) for j in subset}
                sig = dlc.aggregate(self.group, deals, ev["negate"], nb + 1, msg, core["unattestable_nonce_x"], parts)
            except Exception:  # noqa: BLE001 - refusing or absent member: try another set
                continue
            ev.update(status="unattestable", unattestable_signature=sig.hex(), unattestable_digest=msg.hex(),
                      unattestable_signers=list(subset), unattestable_at_us=pr.now_us(), decision_locks=locks)
            self._save(ev)
            self.stats["unattestable"] += 1
            return ev
        self.stats["attest_failures"] += 1
        return ev

    # -------------------------------------------------------------- loop ----
    def abandon(self, maturity_unix: int, reason: str):
        """Record a never-announced event as abandoned so it is not retried. No
        announcement was published, so no contract can depend on it."""
        event_id = event_id_for(maturity_unix)
        self._save({"core": {"event_id": event_id, "maturity_unix": maturity_unix}, "status": "setup_abandoned",
                    "reason": reason, "abandoned_at_us": pr.now_us()})
        self.stats["setup_abandoned"] = self.stats.get("setup_abandoned", 0) + 1
        print(f"dlc setup {event_id} abandoned: {reason}", flush=True)

    def tick(self):
        now = int(time.time())
        nxt = (now // self.every + 1) * self.every
        for m in range(nxt, nxt + self.every * self.ahead, self.every):
            if self.load(event_id_for(m)) is None:
                try:
                    self.setup(m)
                except SetupWedged as e:
                    self.abandon(m, str(e))
                except Exception as e:  # noqa: BLE001
                    self.stats["setup_failures"] += 1
                    print(f"dlc setup {event_id_for(m)} failed: {e!r}", flush=True)
        for p in sorted(self.dir.glob("SHZ-BTCUSD-*.json")):
            ev = json.loads(p.read_text())
            if ev["status"] == "announced" and now * 1_000_000 >= ev["core"]["maturity_unix"] * 1_000_000 + 5_000_000:
                self.attest(ev)

    def run(self, stop: threading.Event):
        while not stop.wait(5):
            if not self.url_by_index:
                # Learn member index -> URL mapping from health endpoints.
                for url in self.relay.signers:
                    try:
                        with urllib.request.urlopen(url + "/healthz", timeout=2) as r:
                            self.url_by_index[json.loads(r.read())["index"]] = url
                    except Exception:  # noqa: BLE001
                        pass
            with self.lock:
                try:
                    self.tick()
                except Exception as e:  # noqa: BLE001
                    print(f"dlc tick failed: {e!r}", flush=True)

    def extra_get(self, path: str):
        if path == "/v1/dlc/events":
            out = []
            for p in sorted(self.dir.glob("SHZ-BTCUSD-*.json"))[-200:]:
                ev = json.loads(p.read_text())
                out.append({"event_id": ev["core"]["event_id"], "maturity_unix": ev["core"]["maturity_unix"], "status": ev["status"],
                            "price_usd": ev.get("attestation", {}).get("price_usd")})
            return 200, {"oracle_pubkey_x": self.group["group_pubkey"], "events": out, "stats": self.stats}
        if path.startswith("/v1/dlc/event/"):
            eid = path.rsplit("/", 1)[1]
            if not eid.startswith("SHZ-BTCUSD-") or "/" in eid or ".." in eid:
                return 400, {"error": "bad event id"}
            ev = self.load(eid)
            if ev is None:
                return 404, {"error": "unknown event"}
            return 200, {k: v for k, v in ev.items() if k != "negate"}
        return None
