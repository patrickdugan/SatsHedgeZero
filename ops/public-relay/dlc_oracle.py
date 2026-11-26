"""Threshold DLC oracle on the FROST confederation's group key.

DLC oracles must commit to one nonce per outcome digit before maturity, so the
two-round FROST nonces used for packets do not apply. Per event, members run a
Feldman-VSS distributed key generation of `num_bits + 1` nonces:

* each member i picks, per nonce d, a degree t-1 polynomial f_{i,d}, publishes
  commitments C_{i,d,k} = a_{i,d,k} G, and sends f_{i,d}(j) to every member j
  encrypted with a pad derived from the ECDH secret s_i * Y_j (the
  coordinator relays the ciphertexts without learning any nonce share);
* member j checks every share against the commitments, and its nonce share is
  k_{j,d} = sum_i f_{i,d}(j); the group nonce is R_d = sum_i C_{i,d,0}, made
  even-Y by negating all shares when needed.

Nonces 0..num_bits-1 sign the digits (`shz_dlc::oracle_digit_message`, MSB
first, same as `shz_margin::decompose_price_bits`); nonce `num_bits` signs the
announcement. A member durably locks each nonce to ONE message before it
releases a partial, so a nonce never signs two messages (that would reveal the
group key). Partial z_j = lambda_j (k_{j,d} + c_d s_j); the coordinator checks
z_j G = lambda_j (K_{j,d} + c_d Y_j) before aggregating.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import bip340
import frost
from bip340 import G, N, _add, _int, _mul, tagged_hash

DIGIT_TAG = b"SatsHedgeZero/DLC/DigitOutcome/v0"
ANN_TAG = "SHZ/DLC/ANNOUNCEMENT/V1"
UNATTESTABLE_TAG = "SHZ/DLC/UNATTESTABLE/V1"
UNATTESTABLE_GRACE_US = 60_000_000
NUM_BITS = 20  # integer USD up to 1,048,575
OUTCOME_WINDOW_US = 30_000_000
OUTCOME_RULE = "floor(median_e8 / 1e8) of the first VALID FROST relay packet with slot_us >= maturity"


def digit_message(event_id: str, idx: int, bit: int) -> bytes:
    e = event_id.encode()
    return tagged_hash(DIGIT_TAG, len(e).to_bytes(4, "little") + e + bytes([idx, bit]))


def unattestable_message(event_id: str) -> bytes:
    return tagged_hash(UNATTESTABLE_TAG, event_id.encode())


def nonce_count(num_bits: int) -> int:
    """Digits, then the announcement nonce, then the unattestable-notice nonce."""
    return num_bits + 2


def decompose(price: int, n: int) -> list[int]:
    p = min(price, (1 << n) - 1)
    return [(p >> s) & 1 for s in range(n - 1, -1, -1)]


def announcement_message(core: dict) -> bytes:
    return tagged_hash(ANN_TAG, json.dumps(core, sort_keys=True, separators=(",", ":")).encode())


def _atomic_write(path: Path, obj):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".dlc")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if os.name != "nt":
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _pad(share: dict, peer: int, event_id: str, dealer: int, recipient: int, d: int) -> int:
    y_peer = frost.deser(bytes.fromhex(share["group"]["verification_shares"][str(peer)]))
    shared = _mul(y_peer, int(share["secret_share"], 16))
    data = shared[0].to_bytes(32, "big") + event_id.encode() + bytes([dealer, recipient]) + d.to_bytes(2, "big")
    return _int(tagged_hash("SHZ/DLC/SHARE-PAD/V1", data))


def _eval_commitments(commits: list[str], j: int):
    acc = None
    for k, c in enumerate(commits):
        acc = _add(acc, _mul(frost.deser(bytes.fromhex(c)), pow(j, k, N)))
    return acc


def nonce_share_point(deals: dict, d: int, j: int, negate: bool):
    """K_{j,d} = sum over dealers of f_{i,d}(j) G, from public commitments."""
    acc = None
    for dl in deals.values():
        acc = _add(acc, _eval_commitments(dl["commitments"][d], j))
    return frost.neg(acc) if negate else acc


def group_nonce(deals: dict, d: int):
    acc = None
    for dl in deals.values():
        acc = _add(acc, frost.deser(bytes.fromhex(dl["commitments"][d][0])))
    return acc


# ------------------------------------------------------------------ member ----

class DlcMember:
    def __init__(self, share: dict, state_path: Path):
        self.share = share
        self.i = share["index"]
        self.t = share["group"]["threshold"]
        self.path = state_path
        self.s = json.loads(state_path.read_text()) if state_path.exists() else {"events": {}}

    def _ev(self, event_id: str) -> dict:
        ev = self.s["events"].get(event_id)
        if ev is None:
            raise ValueError("unknown event")
        return ev

    def deal(self, event_id: str, maturity_unix: int, num_bits: int, members: list[int]) -> dict:
        ev = self.s["events"].get(event_id)
        if ev is not None:
            if ev["maturity_unix"] != maturity_unix or ev["num_bits"] != num_bits:
                raise ValueError("event redefined")
            if "deal" not in ev:
                raise ValueError("event already set up")
            return ev["deal"]
        n_nonces = nonce_count(num_bits)
        polys = [[frost.rand_scalar() for _ in range(self.t)] for _ in range(n_nonces)]
        commitments = [[frost.ser(_mul(G, a)).hex() for a in p] for p in polys]
        enc = {}
        for j in members:
            if j == self.i:
                continue
            enc[str(j)] = [
                ((sum(a * pow(j, k, N) for k, a in enumerate(p)) % N) ^ _pad(self.share, j, event_id, self.i, j, d)).to_bytes(32, "big").hex()
                for d, p in enumerate(polys)
            ]
        own = [(sum(a * pow(self.i, k, N) for k, a in enumerate(p)) % N).to_bytes(32, "big").hex() for p in polys]
        deal = {"dealer": self.i, "commitments": commitments, "enc": enc}
        self.s["events"][event_id] = {"maturity_unix": maturity_unix, "num_bits": num_bits, "n_nonces": n_nonces, "deal": deal, "own": own}
        _atomic_write(self.path, self.s)
        return deal

    def receive(self, event_id: str, deals: dict) -> list[str]:
        """deals: {dealer_index: {"commitments": [...], "enc": {...}}} for the qualified set."""
        ev = self._ev(event_id)
        if "nonce_shares" in ev:
            return ev["R"]
        if str(self.i) not in deals or len(deals) < self.t:
            raise ValueError("qualified dealer set must include me and have at least t members")
        n_nonces = ev.get("n_nonces", ev["num_bits"] + 1)
        if deals[str(self.i)]["commitments"] != ev["deal"]["commitments"]:
            raise ValueError("my own commitments were altered")
        shares = [0] * n_nonces
        for dealer, dl in deals.items():
            di = int(dealer)
            if len(dl["commitments"]) != n_nonces or any(len(c) != self.t for c in dl["commitments"]):
                raise ValueError(f"malformed deal from {di}")
            for d in range(n_nonces):
                if di == self.i:
                    sh = int(ev["own"][d], 16)
                else:
                    sh = int(dl["enc"][str(self.i)][d], 16) ^ _pad(self.share, di, event_id, di, self.i, d)
                if _mul(G, sh) != _eval_commitments(dl["commitments"][d], self.i):
                    raise ValueError(f"share from dealer {di} fails its commitments (nonce {d})")
                shares[d] = (shares[d] + sh) % N
        r_x, negate = [], []
        for d in range(n_nonces):
            r = group_nonce(deals, d)
            negate.append(bool(r[1] & 1))
            if r[1] & 1:
                shares[d] = N - shares[d]
            r_x.append(r[0].to_bytes(32, "big").hex())
        ev.update(nonce_shares=[x.to_bytes(32, "big").hex() for x in shares], R=r_x, negate=negate,
                  qualified=sorted(int(k) for k in deals), signed={})
        ev.pop("deal", None)
        ev.pop("own", None)
        _atomic_write(self.path, self.s)
        return r_x

    def _partial(self, ev: dict, d: int, msg: bytes, signers: list[int]) -> int:
        if self.i not in signers or len(signers) < self.t or not set(signers) <= set(ev["qualified"]):
            raise ValueError("invalid signing set")
        prev = ev["signed"].get(str(d))
        if prev is not None and prev != msg.hex():
            raise ValueError(f"nonce {d} already signed a different message")
        ev["signed"][str(d)] = msg.hex()
        group_x = bytes.fromhex(self.share["group"]["group_pubkey"])
        c = frost.challenge(bytes.fromhex(ev["R"][d]), group_x, msg)
        k = int(ev["nonce_shares"][d], 16)
        return frost.lagrange(self.i, signers) * (k + c * int(self.share["secret_share"], 16)) % N

    def sign_announcement(self, event_id: str, core: dict, signers: list[int]) -> str:
        ev = self._ev(event_id)
        nb = ev["num_bits"]
        if (core.get("event_id"), core.get("maturity_unix"), core.get("num_bits")) != (event_id, ev["maturity_unix"], nb) \
                or core.get("oracle_pubkey_x") != self.share["group"]["group_pubkey"] \
                or core.get("digit_nonces_x") != ev["R"][:nb] or core.get("announcement_nonce_x") != ev["R"][nb] \
                or core.get("unattestable_nonce_x") != (ev["R"][nb + 1] if len(ev["R"]) > nb + 1 else None):
            raise ValueError("announcement does not match my nonce setup")
        msg = announcement_message(core)
        z = self._partial(ev, nb, msg, signers)
        _atomic_write(self.path, self.s)  # lock is durable before the partial leaves
        return z.to_bytes(32, "big").hex()

    def sign_unattestable(self, event_id: str, now_us: int, signers: list[int]) -> str:
        """Threshold notice that this event will never be attested. Mutually exclusive
        with attesting: refused once any digit nonce has signed, and afterwards
        sign_outcome refuses."""
        ev = self._ev(event_id)
        nb = ev["num_bits"]
        if len(ev["R"]) <= nb + 1:
            raise ValueError("event was announced without an unattestable nonce")
        if now_us < ev["maturity_unix"] * 1_000_000 + OUTCOME_WINDOW_US + UNATTESTABLE_GRACE_US:
            raise ValueError("outcome window plus grace has not passed")
        if any(int(d) < nb for d in ev["signed"]):
            raise ValueError("already attested")
        ev["unattestable"] = True
        z = self._partial(ev, nb + 1, unattestable_message(event_id), signers)
        _atomic_write(self.path, self.s)
        return z.to_bytes(32, "big").hex()

    def sign_outcome(self, event_id: str, price_usd: int, signers: list[int]) -> list[str]:
        ev = self._ev(event_id)
        if ev.get("unattestable"):
            raise ValueError("event declared unattestable")
        nb = ev["num_bits"]
        bits = decompose(price_usd, nb)
        zs = [self._partial(ev, d, digit_message(event_id, d, bits[d]), signers) for d in range(nb)]
        _atomic_write(self.path, self.s)
        return [z.to_bytes(32, "big").hex() for z in zs]


# ------------------------------------------------------------- coordinator ----

def verify_partial(group: dict, deals: dict, negate: list[bool], d: int, j: int, z: int, msg: bytes, r_x: bytes, signers: list[int]) -> bool:
    group_x = bytes.fromhex(group["group_pubkey"])
    c = frost.challenge(r_x, group_x, msg)
    k_j = nonce_share_point(deals, d, j, negate[d])
    y_j = frost.deser(bytes.fromhex(group["verification_shares"][str(j)]))
    lam = frost.lagrange(j, signers)
    return _mul(G, z) == _mul(_add(k_j, _mul(y_j, c)), lam)


def aggregate(group: dict, deals: dict, negate: list[bool], d: int, msg: bytes, r_x_hex: str, partials: dict[int, int]) -> bytes:
    signers = sorted(partials)
    r_x = bytes.fromhex(r_x_hex)
    bad = [j for j, z in partials.items() if not verify_partial(group, deals, negate, d, j, z, msg, r_x, signers)]
    if bad:
        raise frost.CheatingSigner(bad)
    sig = r_x + (sum(partials.values()) % N).to_bytes(32, "big")
    if not bip340.verify(msg, bytes.fromhex(group["group_pubkey"]), sig):
        raise RuntimeError("aggregate does not verify")
    return sig


def shz_dlc_announcement(core: dict) -> dict:
    """serde form of shz_dlc::OracleAnnouncement."""
    return {"event_id": core["event_id"], "maturity_unix": core["maturity_unix"],
            "oracle_pubkey_x": list(bytes.fromhex(core["oracle_pubkey_x"])),
            "digit_nonces_x": [list(bytes.fromhex(x)) for x in core["digit_nonces_x"]]}


def shz_dlc_attestation(event_id: str, ts: int, price: int, bits: list[int], sigs: list[bytes]) -> dict:
    """serde form of shz_dlc::OracleAttestation."""
    return {"event_id": event_id, "attested_timestamp_unix": ts, "price_usd": price, "digit_bits": bits,
            "digit_signatures": [{"r_x": list(s[:32]), "s": list(s[32:])} for s in sigs]}
