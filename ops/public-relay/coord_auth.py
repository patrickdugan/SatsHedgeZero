"""Coordinator -> member request authentication (review finding F-05, part 3).

Every POST from the FROST coordinator to a member carries

    X-SHZ-Auth: v1 <ts_us> <nonce_hex32> <mac_hex64>

with mac = HMAC-SHA256(K_i, "SHZ/RELAY/COORD-REQ/V1" | group_pubkey | i | path | ts_us | nonce | SHA256(body)).

K_i = HMAC-SHA256(master, "SHZ/RELAY/COORD-AUTH-KEY/V1" | group_pubkey | i). The coordinator holds the
master; member i holds only K_i, so it can verify requests to itself and cannot forge requests to any
other member. A member refuses (HTTP 401) a request whose MAC does not verify, whose timestamp is more
than WINDOW_S from its own clock, or whose nonce it has already accepted inside the window.

HMAC rather than a BIP340 signature: on the 1-vCPU witness host the pure-Python BIP340 sign takes 16 ms
and a slot makes eight member calls, while HMAC costs microseconds.

Command line (run once per deployment, as the users that own the paths):

    python3 coord_auth.py master --out /var/lib/shz-frost-relay/coord_auth.key
    python3 coord_auth.py derive --master MASTER --group group.json --index 3 --out /var/lib/shz-frost-signer-3/coord_auth.key
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.request
from pathlib import Path

HEADER = "X-SHZ-Auth"
WINDOW_S = 30
_KEY_TAG = b"SHZ/RELAY/COORD-AUTH-KEY/V1"
_REQ_TAG = b"SHZ/RELAY/COORD-REQ/V1"


UNAUTHENTICATED = object()  # explicit opt-out for offline drills; members never default to it


class AuthError(Exception):
    pass


def member_key(master: bytes, group_pubkey: str, index: int) -> bytes:
    if len(master) != 32:
        raise ValueError("master key must be 32 bytes")
    return hmac.new(master, _KEY_TAG + bytes.fromhex(group_pubkey) + index.to_bytes(4, "big"), hashlib.sha256).digest()


def _mac(key: bytes, group_pubkey: str, index: int, path: str, ts_us: int, nonce: bytes, body: bytes) -> bytes:
    p = path.encode()
    msg = (_REQ_TAG + bytes.fromhex(group_pubkey) + index.to_bytes(4, "big") + len(p).to_bytes(2, "big") + p
           + ts_us.to_bytes(8, "big") + nonce + hashlib.sha256(body).digest())
    return hmac.new(key, msg, hashlib.sha256).digest()


def header(key: bytes, group_pubkey: str, index: int, path: str, body: bytes, now_us: int | None = None) -> str:
    ts = int(time.time() * 1e6) if now_us is None else now_us
    nonce = secrets.token_bytes(16)
    return f"v1 {ts} {nonce.hex()} {_mac(key, group_pubkey, index, path, ts, nonce, body).hex()}"


class Verifier:
    """Member side. One instance per member process; thread-safe."""

    def __init__(self, key: bytes, group_pubkey: str, index: int, window_s: int = WINDOW_S):
        if len(key) != 32:
            raise ValueError("member auth key must be 32 bytes")
        self.key, self.group_pubkey, self.index, self.window_us = key, group_pubkey, index, window_s * 1_000_000
        self.seen: dict[bytes, int] = {}
        self.lock = threading.Lock()

    def check(self, path: str, body: bytes, value: str | None, now_us: int | None = None):
        if not value:
            raise AuthError("missing coordinator authentication")
        parts = value.split(" ")
        if len(parts) != 4 or parts[0] != "v1":
            raise AuthError("malformed coordinator authentication")
        try:
            ts = int(parts[1])
            nonce = bytes.fromhex(parts[2])
            mac = bytes.fromhex(parts[3])
        except ValueError:
            raise AuthError("malformed coordinator authentication") from None
        if len(nonce) != 16 or len(mac) != 32 or not 0 <= ts < 2**63:
            raise AuthError("malformed coordinator authentication")
        now = int(time.time() * 1e6) if now_us is None else now_us
        if abs(now - ts) > self.window_us:
            raise AuthError("coordinator timestamp outside the window")
        if not hmac.compare_digest(mac, _mac(self.key, self.group_pubkey, self.index, path, ts, nonce, body)):
            raise AuthError("bad coordinator MAC")
        with self.lock:
            if nonce in self.seen:
                raise AuthError("replayed coordinator request")
            self.seen = {n: t for n, t in self.seen.items() if abs(now - t) <= self.window_us}
            self.seen[nonce] = ts


class Client:
    """Coordinator side. `master=None` sends unauthenticated requests (tests against unauthenticated members)."""

    def __init__(self, master: bytes | None, group_pubkey: str):
        self.master, self.group_pubkey = master, group_pubkey
        self.index_of: dict[str, int] = {}
        self.lock = threading.Lock()

    def _index(self, base: str) -> int:
        with self.lock:
            if base in self.index_of:
                return self.index_of[base]
        # A wrong mapping only makes the member refuse: the MAC binds the member's own index.
        with urllib.request.urlopen(base + "/healthz", timeout=2) as r:
            i = int(json.loads(r.read())["index"])
        with self.lock:
            self.index_of[base] = i
        return i

    def post(self, base: str, path: str, obj: dict, timeout: float) -> dict:
        body = json.dumps(obj).encode()
        headers = {"Content-Type": "application/json"}
        if self.master is not None:
            i = self._index(base)
            headers[HEADER] = header(member_key(self.master, self.group_pubkey, i), self.group_pubkey, i, path, body)
        req = urllib.request.Request(base + path, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())


def read_key(path: str | Path) -> bytes:
    k = bytes.fromhex(Path(path).read_text().strip())
    if len(k) != 32:
        raise ValueError(f"{path}: expected 32 bytes of hex")
    return k


def _write_secret(path: str, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data.hex() + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("master")
    m.add_argument("--out", required=True)
    d = sub.add_parser("derive")
    d.add_argument("--master", required=True)
    d.add_argument("--group", required=True)
    d.add_argument("--index", type=int, required=True)
    d.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd == "master":
        _write_secret(a.out, secrets.token_bytes(32))
    else:
        group = json.loads(Path(a.group).read_text())
        if not 1 <= a.index <= int(group["signers"]):
            raise SystemExit("index outside the group")
        _write_secret(a.out, member_key(read_key(a.master), group["group_pubkey"], a.index))


if __name__ == "__main__":
    main()
