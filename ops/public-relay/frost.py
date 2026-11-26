"""Two-round FROST threshold Schnorr producing standard BIP340 signatures.

Key generation here is a trusted dealer (Shamir split of one secret); the
dealer sees the group secret at setup. Signing follows FROST: every signer
publishes a pair of nonce commitments (D_i, E_i), the coordinator picks a
signing set, each signer computes binding factors over the full commitment
list and returns a partial signature z_i, and the coordinator checks each z_i
before summing them into (R.x, s). BIP340 even-Y rules: the group key is made
even at keygen; signers negate their nonces when the group commitment R has
odd Y.
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path

import bip340
from bip340 import G, N, P, _add, _int, _lift_x, _mul, tagged_hash


# ----------------------------------------------------------- encodings ----

def ser(pt) -> bytes:
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def deser(b: bytes):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("bad point encoding")
    pt = _lift_x(_int(b[1:]))
    if pt is None:
        raise ValueError("not on curve")
    return pt if (pt[1] & 1) == (b[0] - 2) else (pt[0], P - pt[1])


def neg(pt):
    return None if pt is None else (pt[0], P - pt[1])


def rand_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


# -------------------------------------------------------------- keygen ----

def keygen(t: int, n: int) -> tuple[dict, list[dict]]:
    """Trusted-dealer t-of-n split. Returns (public group info, per-signer shares)."""
    if not 1 < t <= n < 256:
        raise ValueError("need 1 < t <= n < 256")
    coeffs = [rand_scalar() for _ in range(t)]
    y = _mul(G, coeffs[0])
    if y[1] & 1:  # BIP340 x-only key must have even Y: negate the whole polynomial
        coeffs = [N - a for a in coeffs]
    shares = []
    for i in range(1, n + 1):
        s_i = sum(a * pow(i, k, N) for k, a in enumerate(coeffs)) % N
        shares.append({"index": i, "secret_share": s_i.to_bytes(32, "big").hex()})
    group_x = _mul(G, coeffs[0])[0].to_bytes(32, "big").hex()
    verification = {str(s["index"]): ser(_mul(G, int(s["secret_share"], 16))).hex() for s in shares}
    group = {"scheme": "FROST-secp256k1-BIP340/trusted-dealer", "threshold": t, "signers": n, "group_pubkey": group_x, "verification_shares": verification}
    for s in shares:
        s.update(group=group)
    return group, shares


def lagrange(i: int, signers: list[int]) -> int:
    num, den = 1, 1
    for j in signers:
        if j != i:
            num = num * j % N
            den = den * (j - i) % N
    return num * pow(den, N - 2, N) % N


# ------------------------------------------------------------- signing ----

def encode_commitments(commits: list[dict]) -> bytes:
    out = b""
    for c in sorted(commits, key=lambda c: c["index"]):
        out += c["index"].to_bytes(4, "big") + bytes.fromhex(c["D"]) + bytes.fromhex(c["E"])
    return out


def binding_factor(group_x: bytes, msg: bytes, commits: list[dict], i: int) -> int:
    return _int(tagged_hash("SHZ/FROST/rho", group_x + msg + encode_commitments(commits) + i.to_bytes(4, "big"))) % N


def group_commitment(group_x: bytes, msg: bytes, commits: list[dict]):
    r = None
    for c in commits:
        rho = binding_factor(group_x, msg, commits, c["index"])
        r = _add(r, _add(deser(bytes.fromhex(c["D"])), _mul(deser(bytes.fromhex(c["E"])), rho)))
    if r is None:
        raise ValueError("degenerate group commitment")
    return r


def challenge(r_x: bytes, group_x: bytes, msg: bytes) -> int:
    return _int(tagged_hash("BIP0340/challenge", r_x + group_x + msg)) % N


def validate_set(commits: list[dict], t: int, n: int) -> list[int]:
    idx = [c["index"] for c in commits]
    if len(idx) < t or len(set(idx)) != len(idx) or any(not 1 <= i <= n for i in idx):
        raise ValueError("invalid signing set")
    return sorted(idx)


def partial_sign(share: dict, d: int, e: int, msg: bytes, commits: list[dict]) -> int:
    g = share["group"]
    group_x = bytes.fromhex(g["group_pubkey"])
    signers = validate_set(commits, g["threshold"], g["signers"])
    i = share["index"]
    mine = next(c for c in commits if c["index"] == i)
    if mine["D"] != ser(_mul(G, d)).hex() or mine["E"] != ser(_mul(G, e)).hex():
        raise ValueError("commitment list does not contain my commitments")
    r = group_commitment(group_x, msg, commits)
    rho = binding_factor(group_x, msg, commits, i)
    k = (d + rho * e) % N
    if r[1] & 1:
        k = N - k
    c = challenge(r[0].to_bytes(32, "big"), group_x, msg)
    return (k + lagrange(i, signers) * int(share["secret_share"], 16) * c) % N


def _context(group: dict, msg: bytes, commits: list[dict]):
    group_x = bytes.fromhex(group["group_pubkey"])
    signers = validate_set(commits, group["threshold"], group["signers"])
    r = group_commitment(group_x, msg, commits)
    return group_x, signers, r, challenge(r[0].to_bytes(32, "big"), group_x, msg)


def verify_partial(group: dict, i: int, z_i: int, msg: bytes, commits: list[dict], ctx=None) -> bool:
    group_x, signers, r, c = ctx or _context(group, msg, commits)
    c_i = next(c for c in commits if c["index"] == i)
    rho = binding_factor(group_x, msg, commits, i)
    r_i = _add(deser(bytes.fromhex(c_i["D"])), _mul(deser(bytes.fromhex(c_i["E"])), rho))
    if r[1] & 1:
        r_i = neg(r_i)
    y_i = deser(bytes.fromhex(group["verification_shares"][str(i)]))
    return _mul(G, z_i) == _add(r_i, _mul(y_i, lagrange(i, signers) * c % N))


def aggregate(group: dict, msg: bytes, commits: list[dict], partials: dict[int, int]) -> bytes:
    """Check every partial (identifiable abort) and return a BIP340 signature."""
    ctx = _context(group, msg, commits)
    group_x, signers, r, _ = ctx
    bad = [i for i, z in partials.items() if not verify_partial(group, i, z, msg, commits, ctx)]
    if bad:
        raise CheatingSigner(bad)
    if sorted(partials) != signers:
        raise ValueError("partials do not match the signing set")
    sig = r[0].to_bytes(32, "big") + (sum(partials.values()) % N).to_bytes(32, "big")
    if not bip340.verify(msg, group_x, sig):
        raise RuntimeError("aggregate does not verify")
    return sig


class CheatingSigner(Exception):
    def __init__(self, indices):
        super().__init__(f"invalid partial signature from signer(s) {indices}")
        self.indices = indices


# ------------------------------------------------------- signer state ----

class SignerState:
    """Durable per-signer state: nonces by seq, last signed seq and message.

    Nonces are persisted (fsync + atomic rename) before their commitments are
    released, and erased (persisted) before a partial signature is released,
    so a nonce pair is never used for two messages, even across restarts.
    """

    def __init__(self, path: Path):
        self.path = path
        self.s = json.loads(path.read_text()) if path.exists() else {"last_seq": 0, "last_msg": None, "nonces": {}}

    def _save(self):
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state")
        with os.fdopen(fd, "w") as f:
            json.dump(self.s, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        if os.name != "nt":
            dfd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    def commit(self, seq: int) -> tuple[int, int]:
        if seq <= self.s["last_seq"]:
            raise ValueError("sequence already signed or older")
        key = str(seq)
        if key not in self.s["nonces"]:
            # Drop stale nonces of abandoned older slots before adding a new pair.
            self.s["nonces"] = {k: v for k, v in self.s["nonces"].items() if int(k) > self.s["last_seq"] and int(k) >= seq - 64}
            self.s["nonces"][key] = [rand_scalar().to_bytes(32, "big").hex(), rand_scalar().to_bytes(32, "big").hex()]
            self._save()
        d, e = self.s["nonces"][key]
        return int(d, 16), int(e, 16)

    def take(self, seq: int, msg: bytes) -> tuple[int, int]:
        if seq <= self.s["last_seq"]:
            raise ValueError("sequence already signed or older")
        pair = self.s["nonces"].pop(str(seq), None)
        if pair is None:
            raise ValueError("no unused nonce for this sequence")
        self.s["last_seq"], self.s["last_msg"] = seq, msg.hex()
        self._save()
        return int(pair[0], 16), int(pair[1], 16)
