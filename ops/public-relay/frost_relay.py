#!/usr/bin/env python3
"""FROST confederation coordinator: the public relayer, signed t-of-n.

  python3 frost_relay.py --group group.json --signers http://127.0.0.1:9101,... --state DIR --listen 0.0.0.0:8091

Per slot: assemble the packet from public sources (as public_relay.py), ask
every member for nonce commitments, take the first t that answer, request
partial signatures, verify each partial against the member's verification
share (a bad partial names the cheater and the coordinator retries with
another set), and publish the aggregate BIP340 signature under the group key.
If fewer than t members answer, the slot is skipped. Sequences are reserved
durably before signing and never reused; the next packet links to the last
published one, so `seq` can jump over a skipped slot while `previous` keeps
the chain. Same HTTP API as public_relay.py.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import itertools
import json
import os
import sys
import threading
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frost  # noqa: E402
import public_relay as pr  # noqa: E402


def post(url: str, obj: dict, timeout: float = 2.0) -> dict:
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


class FrostRelay(pr.Relay):
    def __init__(self, state_dir: Path, interval_ms: int, group: dict, signers: list[str]):
        self.group = group
        self.signers = signers
        self.pool = cf.ThreadPoolExecutor(max_workers=len(signers))
        self.fstats = {"signed_slots": 0, "skipped_slots": 0, "cheaters": {}, "participation": {}}
        self.flock = threading.Lock()
        super().__init__(state_dir, interval_ms)
        rp = self.dir / "reserved_seq"
        self.reserved = int(rp.read_text()) if rp.exists() else 0

    def _reserve(self, seq: int):
        """Persist the sequence before any member can sign it, so a restart never reuses it."""
        tmp = self.dir / "reserved_seq.tmp"
        with open(tmp, "w") as f:
            f.write(str(seq))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.dir / "reserved_seq")
        self.reserved = seq

    def _member_high_water(self) -> int:
        def hw(u):
            with urllib.request.urlopen(u + "/healthz", timeout=2) as r:
                return json.loads(r.read())["last_seq"]
        vals = [v for v in self.pool.map(lambda u: self._try(hw, u), self.signers) if v is not None]
        return max(vals, default=0)

    def publish(self, slot_us: int, results: dict, seq: int | None = None) -> dict:
        seq = max(self.seq, self.reserved) + 1
        self._reserve(seq)
        try:
            return super().publish(slot_us, results, seq=seq)
        except RuntimeError:
            # Members may already hold a later signed seq (e.g. after a crash): move past it.
            self.reserved = max(self.reserved, self._member_high_water())
            raise

    def _init_keys(self):
        self.seckey = None
        self.pubkey = self.group["group_pubkey"]
        self.key_info = {
            "scheme": self.group["scheme"],
            "threshold": self.group["threshold"],
            "signers": self.group["signers"],
            "verification_shares": self.group["verification_shares"],
            "trust_model": f"FROST {self.group['threshold']}-of-{self.group['signers']} confederation, trusted-dealer keygen, all members on one host (demonstration, not independent operators); public delayed sources",
        }

    def _try(self, fn, url):
        try:
            return fn(url)
        except Exception:  # noqa: BLE001 - an unreachable or refusing member is simply absent
            return None

    def sign(self, body: dict) -> dict:
        seq = body["seq"]
        msg = pr.packet_message(body)
        t = self.group["threshold"]
        commits = {}
        for url, c in zip(self.signers, self.pool.map(lambda u: self._try(lambda x: post(x + "/commit", {"seq": seq}), u), self.signers)):
            if c is not None:
                commits[c["index"]] = (url, c)
        if len(commits) < t:
            with self.flock:
                self.fstats["skipped_slots"] += 1
            raise RuntimeError(f"only {len(commits)} of {t} required members committed")
        # Members already caught sending a bad partial are excluded from later sets.
        with self.flock:
            banned = set(self.fstats["cheaters"])
        candidates = [i for i in sorted(commits) if str(i) not in banned]
        for subset in itertools.combinations(candidates, t):
            cl = [commits[i][1] for i in subset]
            with self.lock:
                parent = self.ring[-1] if self.ring else None
            req = {"seq": seq, "body": body, "parent": parent, "commitments": cl}
            res = list(self.pool.map(lambda i: self._try(lambda u: post(u + "/sign", req), commits[i][0]), subset))
            if any(r is None for r in res):
                continue  # a member refused or vanished; its nonce is spent, try another set
            partials = {r["index"]: int(r["z"], 16) for r in res}
            try:
                sig = frost.aggregate(self.group, msg, cl, partials)
            except frost.CheatingSigner as e:
                with self.flock:
                    for i in e.indices:
                        self.fstats["cheaters"][str(i)] = self.fstats["cheaters"].get(str(i), 0) + 1
                continue
            with self.flock:
                self.fstats["signed_slots"] += 1
                for i in subset:
                    self.fstats["participation"][str(i)] = self.fstats["participation"].get(str(i), 0) + 1
            return {"body": body, "digest": msg.hex(), "signature": sig.hex(), "frost_signers": list(subset)}
        with self.flock:
            self.fstats["skipped_slots"] += 1
        raise RuntimeError("no honest responsive signing set")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group", required=True)
    ap.add_argument("--signers", required=True, help="comma-separated member base URLs")
    ap.add_argument("--state", required=True)
    ap.add_argument("--listen", default="0.0.0.0:8091")
    ap.add_argument("--interval-ms", type=int, default=5_000)
    ap.add_argument("--dlc-every-min", type=int, default=15, help="DLC maturity spacing in minutes (0 disables)")
    ap.add_argument("--dlc-ahead", type=int, default=4, help="number of future maturities kept announced")
    a = ap.parse_args()
    relay = FrostRelay(Path(a.state), a.interval_ms, json.loads(Path(a.group).read_text()), a.signers.split(","))
    relay.stats["frost"] = relay.fstats
    coord = None
    if a.dlc_every_min > 0:
        import dlc_coord
        coord = dlc_coord.DlcCoordinator(relay, Path(a.state), every_min=a.dlc_every_min, ahead=a.dlc_ahead)
        relay.extra_get = coord.extra_get
        relay.stats["dlc"] = coord.stats
    print(f"frost relay group={relay.pubkey} t={relay.group['threshold']}/{relay.group['signers']} resume_seq={relay.seq}", flush=True)
    host, port = a.listen.rsplit(":", 1)
    srv = pr.ThreadingHTTPServer((host, int(port)), pr.make_handler(relay))
    srv.daemon_threads = True
    stop = threading.Event()
    threading.Thread(target=relay.run, args=(stop,), daemon=True).start()
    if coord is not None:
        threading.Thread(target=coord.run, args=(stop,), daemon=True).start()
    try:
        srv.serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
