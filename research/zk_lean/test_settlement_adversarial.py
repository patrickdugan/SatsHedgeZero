"""ZKL-29 adversarial regression tests for the settlement circuits.

Each attack test builds an executable reference model of the *specification* (the clearing
step of `clearing.rs` through `clearing_spec.py`, BIP-341/342 key and script path checks, the
nullifier set, the oracle Merkle pin, canonical integers, fold count) and asserts that the
specification rejects the attack. Docstrings name the implementation location, at pinned
SHA 62003a6003c9263d135b56d5cc86c1e38b9b2223, that does or does not reject the same attack,
as established in ZKL29_SETTLEMENT_AUDIT.md. Implementation-side behaviour is mirrored by
small `impl_*` models only where the audit records a gap; those models transcribe the cited
lines and run no Rust and no Nova proving.

Run: `python -m unittest test_settlement_adversarial` from research/zk_lean.
"""
import copy
import hashlib
import json
import os
import random
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clearing_spec import Lane, clear, prorata  # noqa: E402

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN254 Fr
U64 = 1 << 64
I63 = 1 << 63


class Reject(Exception):
    """The specification rejects the input."""


def sha(b):
    return hashlib.sha256(b).digest()


def tagged(tag, msg):
    t = sha(tag)
    return sha(t + t + msg)


def u32(n):
    return struct.pack("<I", n)


def u64(n):
    if not 0 <= n < U64:
        raise Reject("u64 out of range")
    return struct.pack("<Q", n)


def i64(n):
    if not -I63 <= n < I63:
        raise Reject("i64 out of range")
    return struct.pack("<q", n)


# ---------------------------------------------------------------------------------------------
# V3 clearing step: reference model (clearing.rs:160-277, clearing_step.rs:1-37)
# ---------------------------------------------------------------------------------------------
CLEAR_TAG = b"SHZ/HFT/CLEARING/V1"
CHAIN_TAG = b"LIGHTNINGER/V3CLEAR/CHAIN/V1"


def put_op(k):
    return k[0] + u32(k[1])


def put_row(r):
    b = put_op(r["key"]) + i64(r["pnl"])
    for f in ("released", "collected", "own_claim_used", "shortfall", "haircut", "claim_before", "claim_after", "paid"):
        b += u64(r[f])
    return b + i64(r["net"])


def layer_of(res):
    lay = 0
    for r in res["rows"]:
        if r["pnl"] < 0:
            lay = max(lay, 2 if r["own_claim_used"] > 0 else 1)
    if res["fund_absorbed"] > 0:
        lay = max(lay, 3)
    if res["haircut"] > 0:
        lay = max(lay, 4)
    if res["carry"] > 0:
        lay = max(lay, 5)
    return lay


def batch_digest(res, cash_before):
    """`BatchClearing::digest` (clearing.rs:160-169) from a `clear()` result."""
    b = u64(len(res["rows"]))
    for r in res["rows"]:
        b += put_row(r)
    b += u64(len(res["claim_haircuts"]))
    for k, h in res["claim_haircuts"]:
        b += put_op(k) + u64(h)
    for n in (res["shortfall"], res["fund_absorbed"], res["haircut"]):
        b += u64(n)
    b += bytes([layer_of(res)]) + i64(cash_before) + i64(res["cash"])
    for n in (res["fund"], res["carry"], sum(res["claims"].values())):
        b += u64(n)
    return tagged(CLEAR_TAG, b)


def chain_next(chain, seq, digest):
    return sha(CHAIN_TAG + chain + struct.pack("<Q", seq) + digest)


class Z:
    """Folded state of clearing_step.rs:3-14 (account table of A slots)."""

    def __init__(self, seq, cash, fund, carry, book, claims, keys, chain=b"\x00" * 32):
        self.seq, self.cash, self.fund, self.carry, self.book = seq, cash, fund, carry, book
        self.claims, self.keys, self.chain = tuple(claims), tuple(keys), chain

    def identity(self):
        return self.cash - sum(self.claims) - self.fund + self.carry - self.book

    def astuple(self):
        return (self.seq, self.cash, self.fund, self.carry, self.book, self.claims, self.keys, self.chain)

    def __eq__(self, o):
        return isinstance(o, Z) and self.astuple() == o.astuple()

    def with_(self, **kw):
        d = dict(seq=self.seq, cash=self.cash, fund=self.fund, carry=self.carry, book=self.book,
                 claims=self.claims, keys=self.keys, chain=self.chain)
        d.update(kw)
        return Z(**d)


def check_state(z):
    """Input-state checks of clearing_step.rs:259-295."""
    if not 0 <= z.seq < U64 or not -I63 <= z.cash < I63:
        raise Reject("seq or cash out of range")
    for v in (z.fund, z.carry, *z.claims):
        if not 0 <= v < U64:
            raise Reject("u64 field out of range")
    if len(z.claims) != len(z.keys):
        raise Reject("table shape")
    if any(not a < b for a, b in zip(z.keys, z.keys[1:])):
        raise Reject("account table not strictly ascending")
    if z.identity() != 0:
        raise Reject("identity_in")


def spec_step(z, rows_in):
    """One batch through `clear()` and the digest, from the state and the batch inputs only."""
    check_state(z)
    slots = [s for s, _, _ in rows_in]
    if len(set(slots)) != len(slots) or any(not 0 <= s < len(z.keys) for s in slots):
        raise Reject("row slot not in the table or repeated")
    lanes = [Lane(z.keys[s], pnl, rel) for s, pnl, rel in rows_in]
    claims = {k: c for k, c in zip(z.keys, z.claims) if c}
    res = clear(z.cash, z.fund, z.carry, claims, lanes)
    digest = batch_digest(res, z.cash)
    claims2 = tuple(res["claims"].get(k, 0) for k in z.keys)
    z2 = Z(z.seq + 1, res["cash"], res["fund"], res["carry"], z.book - sum(p for _, p, _ in rows_in),
           claims2, z.keys, chain_next(z.chain, z.seq, digest))
    if z2.identity() != 0:
        raise Reject("identity_out")
    return z2, digest, res


def spec_accepts(z, rows_in, claimed_z2, claimed_digest):
    try:
        z2, digest, _ = spec_step(z, rows_in)
    except Reject:
        return False
    return z2 == claimed_z2 and digest == claimed_digest


def key(n, vout=0):
    return (bytes([n]) * 32, vout)


KEYS6 = tuple(key(n) for n in range(1, 7))


def genesis(cash=500, fund=500, claims=None, carry=0, book=0, keys=KEYS6):
    return Z(0, cash, fund, carry, book, claims or [0] * len(keys), keys)


def sums_only_check(c, z):
    """Row and total conservation only: the checks of the draft circuit (review C3), no recomputation."""
    rows = c["rows"]
    for r in rows:
        gain, need = max(0, r["pnl"]), max(0, -r["pnl"])
        if r["pnl"] < 0 and need != r["collected"] + r["own_claim_used"] + r["shortfall"]:
            return False
        if r["claim_before"] - r["own_claim_used"] + gain != r["haircut"] + r["paid"] + r["claim_after"]:
            return False
        if r["net"] != r["paid"] - r["collected"]:
            return False
    if sum(r["shortfall"] for r in rows) != c["shortfall"]:
        return False
    if c["shortfall"] != c["fund_absorbed"] + c["haircut"] + c["carry"] - z.carry:
        return False
    if sum(r["net"] for r in rows) + c["cash"] - z.cash != 0:
        return False
    return c["cash"] - sum(c["claims"].values()) - c["fund"] + c["carry"] == z.identity() + z.book - sum(r["pnl"] for r in rows)


# ---------------------------------------------------------------------------------------------
# BIP-341 / BIP-342 model (tapsighash_step.rs:167-238), secp256k1 for the output key tweak
# ---------------------------------------------------------------------------------------------
HASH_TYPES = (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83)


def compact(n):
    assert n < 0xFD
    return bytes([n])


def parse_tx(raw):
    i = 0

    def rd(n):
        nonlocal i
        v = raw[i:i + n]
        i += n
        return v

    version = struct.unpack("<I", rd(4))[0]
    n_in = rd(1)[0]
    ins = []
    for _ in range(n_in):
        txid, vout = rd(32), struct.unpack("<I", rd(4))[0]
        sl = rd(1)[0]
        rd(sl)
        ins.append((txid, vout, struct.unpack("<I", rd(4))[0]))
    n_out = rd(1)[0]
    outs = []
    for _ in range(n_out):
        val = struct.unpack("<Q", rd(8))[0]
        ol = rd(1)[0]
        outs.append((val, rd(ol)))
    locktime = struct.unpack("<I", rd(4))[0]
    assert i == len(raw)
    return {"version": version, "ins": ins, "outs": outs, "locktime": locktime}


def out_bytes(o):
    return struct.pack("<Q", o[0]) + compact(len(o[1])) + o[1]


def sig_msg(tx, amounts, spks, idx, ht, annex=None, ext=None):
    """BIP-341 SigMsg; `ext = (tapleaf, codesep)` adds the BIP-342 extension."""
    if ht not in HASH_TYPES:
        raise Reject("invalid hash type")
    acp = ht & 0x80 != 0
    out_type = 1 if ht == 0 else ht & 3
    m = bytes([0x00, ht]) + u32(tx["version"]) + u32(tx["locktime"])
    if not acp:
        p = b"".join(t + u32(v) for t, v, _ in tx["ins"])
        a = b"".join(struct.pack("<Q", x) for x in amounts)
        s = b"".join(compact(len(k)) + k for k in spks)
        q = b"".join(u32(sq) for _, _, sq in tx["ins"])
        m += b"".join(sha(d) for d in (p, a, s, q))
    if out_type == 1:
        m += sha(b"".join(out_bytes(o) for o in tx["outs"]))
    m += bytes([2 * (ext is not None) + (annex is not None)])
    if acp:
        t, v, sq = tx["ins"][idx]
        m += t + u32(v) + struct.pack("<Q", amounts[idx]) + compact(len(spks[idx])) + spks[idx] + u32(sq)
    else:
        m += u32(idx)
    if annex is not None:
        m += sha(compact(len(annex)) + annex)
    if out_type == 3:
        if idx >= len(tx["outs"]):
            raise Reject("SIGHASH_SINGLE without a matching output")
        m += sha(out_bytes(tx["outs"][idx]))
    if ext is not None:
        m += ext[0] + b"\x00" + u32(ext[1])
    return m


def tap_sighash(*a, **k):
    return tagged(b"TapSighash", sig_msg(*a, **k))


# secp256k1, enough for the Taproot tweak
SP = 2**256 - 2**32 - 977
SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def padd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SP == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, SP) % SP
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, SP) % SP
    x = (lam * lam - a[0] - b[0]) % SP
    return (x, (lam * (a[0] - x) - a[1]) % SP)


def pmul(k, pt):
    r = None
    while k:
        if k & 1:
            r = padd(r, pt)
        pt = padd(pt, pt)
        k >>= 1
    return r


def lift_x(x):
    y = pow((pow(x, 3, SP) + 7) % SP, (SP + 1) // 4, SP)
    if y * y % SP != (pow(x, 3, SP) + 7) % SP:
        raise Reject("x is not on the curve")
    return (x, y if y % 2 == 0 else SP - y)


def xonly_of_secret(sk):
    pt = pmul(sk, SG)
    return pt[0].to_bytes(32, "big")


def tap_tweak_key(internal_x, merkle_root):
    t = int.from_bytes(tagged(b"TapTweak", internal_x + (merkle_root or b"")), "big")
    q = padd(lift_x(int.from_bytes(internal_x, "big")), pmul(t, SG))
    return q[0].to_bytes(32, "big")


def tapleaf(script):
    return tagged(b"TapLeaf", b"\xc0" + compact(len(script)) + script)


def tapbranch(a, b):
    x, y = (a, b) if a < b else (b, a)
    return tagged(b"TapBranch", x + y)


def push32(k):
    return b"\x20" + k


def script_keys(script):
    """32-byte pushes of a script of the form the batcher builds (batcher lib.rs:155-162)."""
    out, i = [], 0
    while i < len(script):
        op = script[i]
        if op == 0x20:
            out.append(script[i + 1:i + 33])
            i += 33
        else:
            i += 1
    return out


def keypath_signer_ok(spk, key32):
    """Key path: the signing key is the P2TR output key of the spent scriptPubKey."""
    return len(spk) == 34 and spk[:2] == b"\x51\x20" and key32 == spk[2:]


def scriptpath_signer_ok(spk, key32, script, internal_x, siblings):
    """Script path: the leaf is committed by the output key's tweak and the signer key is in it."""
    if len(spk) != 34 or spk[:2] != b"\x51\x20":
        return False
    h = tapleaf(script)
    for s in siblings:
        h = tapbranch(h, s)
    if tap_tweak_key(internal_x, h) != spk[2:]:
        return False
    return key32 in script_keys(script)


def plan_ok(n_inputs, plan):
    """Key-path signing plan of tapsighash_step.rs:505-521 plus completeness: each input once, all inputs."""
    return len(set(plan)) == len(plan) and sorted(plan) == list(range(n_inputs))


# ---------------------------------------------------------------------------------------------
# nullifiers (unified_batch_circuit.rs:88-169) and oracle Merkle pin (171-227)
# ---------------------------------------------------------------------------------------------
NULL_LEAF = b"SHZ/MNR05/NULL/V1"


def nullifier(outpoint36):
    return sha(NULL_LEAF + outpoint36)


class SpecNullifiers:
    def __init__(self):
        self.spent = set()

    def consume(self, outpoint36):
        n = nullifier(outpoint36)
        if n in self.spent:
            raise Reject("nullifier already spent")
        self.spent.add(n)


class ImplSlotTree:
    """Transcription of `consume_vault_slot` (unified_batch_circuit.rs:151-168): slot emptiness only."""

    def __init__(self):
        self.leaves = [None] * 8

    def consume(self, slot, outpoint36):
        if slot >= 8 or self.leaves[slot] is not None:
            raise Reject("slot consumed")
        self.leaves[slot] = nullifier(outpoint36)


IDX_LEAF, IDX_NODE, IDX_ROOT = b"SHZ/HOUR/LEAF/V1", b"SHZ/HOUR/NODE/V1", b"SHZ/8H/ROOT/V1"


def oracle_leaf(genesis_h, policy, hour, p, c, idx, tp, tc, ph, ch):
    b = IDX_LEAF + genesis_h + policy + struct.pack("<Q", hour) + bytes([1, 0])
    for v in (p, c, idx, tp, tc):
        b += struct.pack("<Q", v)
    return sha(b + ph + ch)


def oracle_root(leaf, position, siblings, genesis_h, policy, start_hour):
    d = leaf
    for lvl, s in enumerate(siblings):
        n = IDX_NODE + (d + s if (position >> lvl) & 1 == 0 else s + d)
        d = sha(n)
    return sha(IDX_ROOT + genesis_h + policy + struct.pack("<Q", start_hour) + d)


def build_oracle_tree(prices, genesis_h=b"\x01" * 32, policy=b"\x02" * 32, start=498000):
    leaves = [oracle_leaf(genesis_h, policy, start + i, p, p, p, 10**15, 10**15, b"\xaa" * 32, b"\xbb" * 32)
              for i, p in enumerate(prices)]
    level, paths = leaves, [[] for _ in leaves]
    for lvl in range(3):
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(sha(IDX_NODE + level[i] + level[i + 1]))
        for pos in range(len(leaves)):
            paths[pos].append(level[(pos >> lvl) ^ 1])
        level = nxt
    root = sha(IDX_ROOT + genesis_h + policy + struct.pack("<Q", start) + level[0])
    return leaves, paths, root


def oracle_record_ok(p, c, idx):
    """Midpoint floor and 50 bps spread of unified_batch_circuit.rs:695-730."""
    return 0 <= p + c - 2 * idx <= 1 and 20050 * c >= 19950 * p and 20050 * p >= 19950 * c


# ---------------------------------------------------------------------------------------------
# BIP-341 ground truth vector (research/lightninger_bitvm3_clearing/tests/vectors, keyPathSpending[0])
# ---------------------------------------------------------------------------------------------
VECTOR = json.loads(r'''{"raw": "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d", "utxos": [["512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", 420000000], ["5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", 462000000], ["76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", 294000000], ["5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", 504000000], ["512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", 630000000], ["00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378000000], ["512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", 672000000], ["5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", 546000000], ["512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", 588000000]], "inputs": [{"index": 0, "hash_type": 3, "internal": "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", "tweak": "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70", "sig_msg": "0003020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e0000000000d0418f0e9a36245b9a50ec87f8bf5be5bcae434337b87139c3a5b1f56e33cba0", "sig_hash": "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555"}, {"index": 1, "hash_type": 131, "internal": "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27", "tweak": "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001", "sig_msg": "0083020000000065cd1d00d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd9900000000808f891b00000000225120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3ffffffffffcef8fb4ca7efc5433f591ecfc57391811ce1e186a3793024def5c884cba51d", "sig_hash": "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d"}, {"index": 3, "hash_type": 1, "internal": "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820", "tweak": "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30", "sig_msg": "0001020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957ea2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc50003000000", "sig_hash": "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669"}, {"index": 4, "hash_type": 0, "internal": "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f", "tweak": "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4", "sig_msg": "0000020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957ea2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc50004000000", "sig_hash": "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef"}, {"index": 6, "hash_type": 2, "internal": "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d", "tweak": "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9", "sig_msg": "0002020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e0006000000", "sig_hash": "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85"}, {"index": 7, "hash_type": 130, "internal": "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592", "tweak": "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9", "sig_msg": "0082020000000065cd1d00e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf00000000804c8b2000000000225120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5ffffffff", "sig_hash": "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10"}, {"index": 8, "hash_type": 129, "internal": "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8", "tweak": "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e", "sig_msg": "0081020000000065cd1da2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc500a778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af101000000002b0c230000000022512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220ffffffff", "sig_hash": "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2"}]}''')


def vec_tx():
    return parse_tx(bytes.fromhex(VECTOR["raw"]))


def vec_spent():
    return [x[1] for x in VECTOR["utxos"]], [bytes.fromhex(x[0]) for x in VECTOR["utxos"]]


# ---------------------------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------------------------
def honest_batch():
    z = genesis()
    rows = [(0, -100, 100), (1, 60, 0), (2, 40, 0)]
    z2, d, res = spec_step(z, rows)
    return z, rows, z2, d, res


class ModelGroundTruth(unittest.TestCase):
    def test_bip341_vector_sigmsg_and_sighash(self):
        """The sighash model reproduces the BIP-341 vectors for all seven hash types (ground truth)."""
        tx = vec_tx()
        amounts, spks = vec_spent()
        seen = set()
        for v in VECTOR["inputs"]:
            m = sig_msg(tx, amounts, spks, v["index"], v["hash_type"])
            self.assertEqual(m.hex(), v["sig_msg"])
            self.assertEqual(tap_sighash(tx, amounts, spks, v["index"], v["hash_type"]).hex(), v["sig_hash"])
            seen.add(v["hash_type"])
        self.assertEqual(seen, set(HASH_TYPES))

    def test_taproot_tweak_matches_vector(self):
        """The secp256k1 tweak model reproduces the vector's output key for the first input."""
        v = VECTOR["inputs"][0]
        amounts, spks = vec_spent()
        self.assertEqual(tap_tweak_key(bytes.fromhex(v["internal"]), None), spks[0][2:])

    def test_honest_step_accepted_and_identity_holds(self):
        z, rows, z2, d, res = honest_batch()
        self.assertTrue(spec_accepts(z, rows, z2, d))
        self.assertEqual(z2.identity(), 0)
        self.assertEqual(z2.seq, 1)

    def test_random_walk_preserves_identity_and_net_zero(self):
        """P1: identity, net-zero and cash floor hold on 300 random batches (Lean: batch_preserves_identity)."""
        rng = random.Random(29)
        z = genesis(cash=2000, fund=2000)
        for _ in range(300):
            n = rng.randint(1, 4)
            slots = rng.sample(range(6), n)
            rows = [(s, rng.randint(-300, 300), rng.randint(0, 300)) for s in slots]
            z2, _, res = spec_step(z, rows)
            self.assertEqual(sum(r["net"] for r in res["rows"]) + z2.cash - z.cash, 0)
            self.assertGreaterEqual(z2.cash, min(z.cash, 0))
            z = z2
        self.assertEqual(z.seq, 300)

    def test_prorata_exact_and_capped(self):
        """P2: shares sum to the total and never exceed their amount (Lean: prorata_sum, prorata_caps)."""
        rng = random.Random(7)
        for _ in range(500):
            amounts = [rng.randint(0, 50) for _ in range(rng.randint(1, 6))]
            total = rng.randint(0, sum(amounts))
            sh = prorata(total, amounts)
            self.assertEqual(sum(sh), total)
            self.assertTrue(all(s <= a for s, a in zip(sh, amounts)))


class AttackC1FreeDigest(unittest.TestCase):
    def test_c1_free_digest_witness(self):
        """C1: a digest that is not computed from the rows must be rejected.

        Draft circuit: free 256-bit witness (review C1, draft line 544): accepted. Replacement:
        clearing_step.rs:538-618 builds the exact preimage in-circuit and hashes it
        (`sha256_var`, gadgets.rs:482-511); `digest_bit` tamper at clearing_step.rs:594-610 adds
        equality constraints, so a substituted digest is unsatisfiable. Native recomputation:
        relation lib.rs:73-101 and batcher lib.rs:262."""
        z, rows, z2, d, _ = honest_batch()
        forged = bytes([d[0] ^ 1]) + d[1:]
        self.assertFalse(spec_accepts(z, rows, z2, forged))
        self.assertFalse(spec_accepts(z, rows, z2, b"\x00" * 32))
        self.assertNotEqual(chain_next(z.chain, z.seq, forged), z2.chain)
        # digest of a different batch over the same state
        _, d_other, _ = spec_step(z, [(0, -90, 100), (1, 50, 0), (2, 40, 0)])
        self.assertFalse(spec_accepts(z, rows, z2, d_other))


class AttackC2Claims(unittest.TestCase):
    def two_steps(self):
        z = genesis(cash=0, fund=0, book=0)
        # step 1: loser with no cover, fund empty, pool cash short: winners are haircut and keep deferred claims
        r1 = [(0, -300, 100), (1, 400, 0), (2, 100, 0)]
        z1, d1, res1 = spec_step(z, r1)
        return z, r1, z1, d1, res1

    def test_c2_claim_moved_between_accounts(self):
        """C2: deferred claims are per-account state; moving A's claim to B between folds must be rejected.

        Draft circuit: only `sum(claim_before) == claims_in` (review C2, draft line 474): accepts the
        move. Replacement: claims are z[5..5+A] and re-emitted per slot (clearing_step.rs:269-272,
        459-472, 637-639), so step 2's input must equal step 1's output slot by slot (Nova z_i chaining)."""
        z, r1, z1, d1, res1 = self.two_steps()
        self.assertGreater(sum(z1.claims), 0, "scenario must leave deferred claims")
        slot = next(i for i, c in enumerate(z1.claims) if c)
        other = next(i for i in range(len(z1.claims)) if i != slot)
        moved = list(z1.claims)
        moved[other], moved[slot] = moved[slot] + moved[other], 0
        zm = z1.with_(claims=moved)
        self.assertEqual(sum(zm.claims), sum(z1.claims))
        self.assertEqual(zm.identity(), 0)
        self.assertTrue(sum(zm.claims) == sum(z1.claims))  # the sum-only check of the draft passes
        # the spec requires the folded output as the next input
        self.assertFalse(zm == z1)
        r2 = [(slot, -10, 10), (other, 10, 0)]
        z2_true, d2_true, _ = spec_step(z1, r2)
        z2_forged, d2_forged, _ = spec_step(zm, r2)
        self.assertNotEqual(d2_true, d2_forged)
        self.assertNotEqual(z2_true.chain, z2_forged.chain)
        self.assertFalse(spec_accepts(z1, r2, z2_forged, d2_forged))

    def test_c2_dropped_claim_breaks_identity(self):
        """C2: dropping one account's claim (total changes) violates the identity on input and output.

        Enforced by clearing_step.rs:291-293 (`identity_in`) and 620-623 (`identity_out`)."""
        _, _, z1, _, _ = self.two_steps()
        slot = next(i for i, c in enumerate(z1.claims) if c)
        dropped = list(z1.claims)
        dropped[slot] = 0
        with self.assertRaises(Reject):
            spec_step(z1.with_(claims=dropped), [(0, 0, 0)])


class AttackC3Waterfall(unittest.TestCase):
    def test_c3_loss_skips_margin_into_fund(self):
        """C3: a loss covered by released margin must not be pushed to the fund while every sum still balances.

        Draft: only `collected <= released` and sum equations (review C3, draft lines 397, 462): accepts.
        Replacement: collected = min(loss, released) by `min_claimed` (clearing_step.rs:341-342,
        gadgets.rs:210-214) and fund_absorbed = min(shortfall, fund) (clearing_step.rs:395-398)."""
        z = genesis(cash=500, fund=500)
        rows = [(0, -100, 100), (1, 60, 0), (2, 40, 0)]
        z2, d, res = spec_step(z, rows)
        c = copy.deepcopy(res)
        delta = c["rows"][0]["collected"]
        self.assertEqual(delta, 100)
        c["rows"][0]["collected"] = 0
        c["rows"][0]["shortfall"] += delta
        c["rows"][0]["net"] += delta
        c["shortfall"] += delta
        c["fund_absorbed"] += delta
        c["fund"] -= delta
        c["cash"] -= delta
        self.assertTrue(sums_only_check(c, z), "attack must preserve every sum")
        z2f = Z(z.seq + 1, c["cash"], c["fund"], c["carry"], z2.book, [0] * 6, z.keys,
                chain_next(z.chain, z.seq, batch_digest(c, z.cash)))
        self.assertFalse(spec_accepts(z, rows, z2f, batch_digest(c, z.cash)))

    def test_c3_haircut_shifted_between_winners(self):
        """C3: pro-rata haircut shares are exact; moving haircut between winners preserves all sums.

        Draft: haircut shares free (review C3). Replacement: `prorata` gadget (gadgets.rs:220-260,
        used at clearing_step.rs:409 and 438) fixes every share, floors then in-order remainder."""
        z = genesis(cash=1000, fund=0, book=1000)
        rows = [(0, -130, 50), (1, 60, 0), (2, 40, 0)]
        z2, d, res = spec_step(z, rows)
        self.assertEqual(res["haircut"], 80)
        c = copy.deepcopy(res)
        shift = c["rows"][2]["haircut"]
        self.assertGreater(shift, 0)
        move = min(shift, 60 - c["rows"][1]["haircut"])
        for i, sgn in ((1, 1), (2, -1)):
            c["rows"][i]["haircut"] += sgn * move
            c["rows"][i]["paid"] -= sgn * move
            c["rows"][i]["net"] -= sgn * move
        self.assertTrue(sums_only_check(c, z), "attack must preserve every sum")
        self.assertNotEqual([r["haircut"] for r in c["rows"]], [r["haircut"] for r in res["rows"]])
        dg = batch_digest(c, z.cash)
        z2f = Z(z.seq + 1, c["cash"], c["fund"], c["carry"], z2.book, z2.claims, z.keys, chain_next(z.chain, z.seq, dg))
        self.assertFalse(spec_accepts(z, rows, z2f, dg))

    def test_c3_remainder_order(self):
        """C3: the remainder goes to items in order; a reversed order has the same sum and is not the rule.

        Enforced by the in-order `rem` loop of gadgets.rs:248-258 (clearing.rs:191-192). Lean:
        prorata_priority."""
        amounts, total = [3, 3, 3], 7
        spec = prorata(total, amounts)
        rev = prorata(total, amounts[::-1])[::-1]
        self.assertEqual(sum(spec), sum(rev))
        self.assertNotEqual(spec, rev)
        self.assertEqual(spec, [3, 2, 2])


class AttackC4OutOfLane(unittest.TestCase):
    def test_c4_account_outside_the_table(self):
        """C4: a row whose account is not in the table, or a fifth account under 4 lanes, must be rejected.

        Draft: CAMPAIGN_LANES = 4 fixed (review C4). Replacement: table of A slots with sorted keys
        (clearing_step.rs:279-290), one-hot slot per row with the key taken from the table
        (309-313, 337-338). A fifth account fits a 6-slot table; a slot beyond the table is
        unsatisfiable. The table is pinned only through z_0 (open, see P3)."""
        z4 = genesis(keys=KEYS6[:4], claims=[0] * 4)
        with self.assertRaises(Reject):
            spec_step(z4, [(4, 10, 0)])
        z6 = genesis()
        rows = [(0, -20, 20), (1, 5, 0), (2, 5, 0), (3, 5, 0), (4, 5, 0)]
        z2, _, _ = spec_step(z6, rows)
        self.assertEqual(z2.seq, 1)

    def test_c4_claim_haircut_of_non_batch_account(self):
        """C4: claim haircuts on accounts outside the batch are their own list in the digest.

        Folding them into lane rows (draft venue_trace.rs:426-444) changes the digest preimage.
        Replacement: clearing_step.rs:474-512 emit the list in key order; relation lib.rs:85-90."""
        z = genesis(cash=1000, fund=0, claims=[0, 0, 0, 0, 50, 0], book=950)
        rows = [(0, -200, 0), (1, 10, 0)]
        z2, d, res = spec_step(z, rows)
        self.assertEqual([k for k, _ in res["claim_haircuts"]], [KEYS6[4]])
        folded = copy.deepcopy(res)
        folded["claim_haircuts"] = []
        self.assertNotEqual(batch_digest(folded, z.cash), d)


class AttackT1SignerBinding(unittest.TestCase):
    def accounts(self):
        t, b = xonly_of_secret(11), xonly_of_secret(12)
        settle = push32(t) + b"\xad" + push32(b) + b"\xac"
        refund = b"\x01\x64\xb1\x75" + push32(t) + b"\xac"
        internal = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        root = tapbranch(tapleaf(settle), tapleaf(refund))
        spk = b"\x51\x20" + tap_tweak_key(internal, root)
        return t, b, settle, refund, internal, spk

    def test_t1_keypath_key_must_be_spk_key(self):
        """T1 (key path): the signing key is the output key of the spent input; any other key is rejected.

        Draft: pubkey_x free witness (review T1). Replacement: tapsighash_step.rs:528-533 force the
        P2TR prefix and 546 selects `spk_x` as the key for a key-path step."""
        amounts, spks = vec_spent()
        self.assertTrue(keypath_signer_ok(spks[0], spks[0][2:]))
        self.assertFalse(keypath_signer_ok(spks[0], xonly_of_secret(99)))
        self.assertFalse(keypath_signer_ok(spks[2], spks[2][2:]), "P2PKH prevout is not a Taproot input")

    def test_t1_scriptpath_unbound_key_and_leaf(self):
        """T1 (script path): an arbitrary tapleaf or a key outside the leaf must not authorize the spend.

        PARTIAL in the implementation: bind mode takes `key`, `tapleaf` and `codesep` as free witnesses
        (tapsighash_step.rs:536-547) and carries them in the parameter accumulator (690-712); the
        accumulator is compared with M17's deferred signatures by cet.rs:64-96 outside any circuit,
        and no code at the pinned SHA checks the control block against the spent output key.
        The spec rejects: leaf must tweak to the output key and the key must occur in the leaf."""
        t, b, settle, refund, internal, spk = self.accounts()
        sib = tapleaf(refund)
        self.assertTrue(scriptpath_signer_ok(spk, t, settle, internal, [sib]))
        self.assertTrue(scriptpath_signer_ok(spk, b, settle, internal, [sib]))
        attacker = xonly_of_secret(77)
        fake = push32(attacker) + b"\xac"
        self.assertFalse(scriptpath_signer_ok(spk, attacker, fake, internal, [sib]), "fabricated leaf")
        self.assertFalse(scriptpath_signer_ok(spk, attacker, settle, internal, [sib]), "key not in leaf")
        self.assertFalse(scriptpath_signer_ok(spk, t, settle, internal, [tapleaf(fake)]), "wrong sibling")


class AttackT2InputIndex(unittest.TestCase):
    def test_t2_free_input_index_and_missing_signatures(self):
        """T2: every input is signed exactly once; all slots signing input 0 is rejected, and the index is in the message.

        Draft: input_index free per step (review T2). Replacement: one-hot input selection and a
        signed mask in z (tapsighash_step.rs:499-521): at-most-once is in-circuit. Completeness
        (final mask covers every input) and script-path inputs are not constrained in-circuit and the
        relation guest does not read the mask (relation lib.rs:573-582): OPEN."""
        self.assertFalse(plan_ok(3, [0, 0, 0]))
        self.assertFalse(plan_ok(3, [0, 1]))
        self.assertTrue(plan_ok(3, [2, 0, 1]))
        tx = vec_tx()
        amounts, spks = vec_spent()
        self.assertNotEqual(sig_msg(tx, amounts, spks, 0, 0x01), sig_msg(tx, amounts, spks, 1, 0x01))
        # ANYONECANPAY commits the input's own outpoint instead of the index
        self.assertNotEqual(sig_msg(tx, amounts, spks, 0, 0x81), sig_msg(tx, amounts, spks, 1, 0x81))


class AttackT3HashType(unittest.TestCase):
    def test_t3_wrong_or_invalid_sighash_type(self):
        """T3: only the seven BIP-341 hash types are valid and each fixes a distinct message.

        Draft: three of seven types, script path only (review T3). Replacement: `ht_one`/`ht_valid`
        (tapsighash_step.rs:552-562) restrict to HASH_TYPES; layouts 565-571 and 640-668; ground truth
        is the BIP-341 vector (artifacts/tapsighash_bip341_vector.json)."""
        tx = vec_tx()
        amounts, spks = vec_spent()
        for bad in (0x04, 0x05, 0x80, 0x84, 0xFF):
            with self.assertRaises(Reject):
                sig_msg(tx, amounts, spks, 0, bad)
        digests = {t: tap_sighash(tx, amounts, spks, 0, t) for t in HASH_TYPES}
        self.assertEqual(len(set(digests.values())), 7)
        # 0x00 and 0x01 share the ALL layout and differ only in the hash_type byte
        self.assertNotEqual(digests[0x00], digests[0x01])
        # SIGHASH_SINGLE needs a matching output: input 8 has none in the 2-output vector transaction
        with self.assertRaises(Reject):
            sig_msg(tx, amounts, spks, 8, 0x03)


class AttackNullifier(unittest.TestCase):
    OP = bytes([5]) * 32 + struct.pack("<I", 0)

    def test_duplicate_nullifier_replay(self):
        """P6: a nullifier spent once is never accepted again.

        PARTIAL in the implementation: the unified circuit's insertion checks only that the chosen
        slot is empty (unified_batch_circuit.rs:622-644, `vault_slot` free at 614-620), so the same
        outpoint in a second slot is accepted by the slot rule; uniqueness then rests on the 348-byte
        transaction having distinct inputs (txid-bound, 586-601). The lightninger clearing and DLC
        relation carry no nullifier: replay of a settlement is prevented by L1 spending of the
        account outpoints (relation lib.rs:398-399)."""
        s = SpecNullifiers()
        s.consume(self.OP)
        with self.assertRaises(Reject):
            s.consume(self.OP)
        tree = ImplSlotTree()
        tree.consume(0, self.OP)
        tree.consume(1, self.OP)  # accepted by the slot rule: documents the gap
        self.assertEqual(tree.leaves[0], tree.leaves[1])
        with self.assertRaises(Reject):
            tree.consume(0, bytes([6]) * 36)

    def test_replay_across_epochs_needs_pinned_initial_root(self):
        """P6: epoch n+1 must start from epoch n's final nullifier set, not from the empty set.

        The unified circuit takes the initial root from the verifier's z_0 (unified_batch_circuit.rs:
        242-265, 646-658), so a verifier that does not pin it to the prior final root accepts an
        empty start. The spec requires the pin."""
        prev = SpecNullifiers()
        prev.consume(self.OP)
        fresh = SpecNullifiers()
        self.assertEqual(len(fresh.spent), 0)
        self.assertNotEqual(prev.spent, fresh.spent)
        with self.assertRaises(Reject):
            nxt = SpecNullifiers()
            nxt.spent = set(prev.spent)
            nxt.consume(self.OP)


class AttackOracleRoot(unittest.TestCase):
    def test_forged_oracle_root(self):
        """P7: an opened price record must hash to the pinned checkpoint root.

        PARTIAL: the unified circuit proves Merkle inclusion into whatever root sits in z[3..4]
        (unified_batch_circuit.rs:732-779) and binds it to the statement policy_hash (818-830); the
        root's authenticity is a verifier-side pin (229-266). VALID bytes are constants (737). The
        lightninger DLC relation has no oracle root at all (relation lib.rs:159-174)."""
        genesis_h, policy = b"\x01" * 32, b"\x02" * 32
        prices = [6_000_000_000_000 + i for i in range(8)]
        leaves, paths, root = build_oracle_tree(prices)
        self.assertEqual(oracle_root(leaves[3], 3, paths[3], genesis_h, policy, 498000), root)
        forged_leaf = oracle_leaf(genesis_h, policy, 498003, 1, 1, 1, 10**15, 10**15, b"\xaa" * 32, b"\xbb" * 32)
        self.assertNotEqual(oracle_root(forged_leaf, 3, paths[3], genesis_h, policy, 498000), root)
        f_leaves, f_paths, f_root = build_oracle_tree([1] * 8)
        self.assertNotEqual(f_root, root)
        self.assertNotEqual(oracle_root(leaves[3], 4, paths[3], genesis_h, policy, 498000), root, "wrong position")
        self.assertNotEqual(oracle_root(leaves[3], 3, paths[3], genesis_h, policy, 497000), root, "wrong start hour")

    def test_oracle_record_midpoint_and_spread(self):
        """P7: the record's index must be the floor midpoint and the sources within 50 bps.

        Enforced: unified_batch_circuit.rs:695-705 (midpoint) and 706-730 (spread)."""
        p = 6_000_000_000_000
        self.assertTrue(oracle_record_ok(p, p + 2, p + 1))
        self.assertFalse(oracle_record_ok(p, p + 2, p + 5), "index off the midpoint")
        self.assertFalse(oracle_record_ok(p, p + p // 100, p + p // 200), "spread over 50 bps")


class AttackFieldWrap(unittest.TestCase):
    def test_field_wrap_value_p_plus_k(self):
        """P8: the integer p+k and k agree in the field; the specification works on integers and rejects p+k.

        Enforced in the replacement by range checks on every free value (gadgets.rs:140-154,
        `claim_u64`/`claim_i64` 158-168; clearing_step.rs:261-272, 316-319) and by linear combinations of
        bounded terms only (maximum magnitude below 2^72, far below p). Lean: wrap_counterexample,
        limbs_no_wrap, i64_wrap_free. `book` has no range check of its own: it is pinned by the identity
        (clearing_step.rs:292-293, 622-623) because every other term is bounded."""
        for k in (1, 5, 2**63, U64 - 1):
            self.assertEqual((P + k) % P, k % P)
            self.assertNotEqual(P + k, k)
            self.assertFalse(0 <= P + k < U64, "integer spec: p+k is out of u64 range")
        self.assertLess(2**72, P)
        self.assertLess((6 + 4) * (U64 - 1) + 2**66, P)

    def test_i64_two_complement_boundaries(self):
        """P8: signed 64-bit decomposition (gadgets.rs:148-154) accepts exactly [-2^63, 2^63)."""
        def i64_field_ok(f):
            return f < I63 or f >= P - I63
        self.assertTrue(i64_field_ok((-I63) % P))
        self.assertTrue(i64_field_ok(I63 - 1))
        self.assertFalse(i64_field_ok(I63))
        self.assertFalse(i64_field_ok((-I63 - 1) % P))
        self.assertEqual(I63 % U64, (-I63) % U64, "residues collide without the signed range")

    def test_fixed_width_encoding_is_canonical(self):
        """P8: fixed-width little-endian bytes are injective on range; out-of-range values must not encode."""
        self.assertNotEqual(u64(1), u64(2))
        with self.assertRaises(Reject):
            u64(U64)
        with self.assertRaises(Reject):
            i64(I63)


class AttackFoldCountAndGenesis(unittest.TestCase):
    def fold(self, z0, batches):
        z, ds = z0, []
        for rows in batches:
            z, d, _ = spec_step(z, rows)
            ds.append(d)
        return z, ds

    def impl_guest_z0_check(self, z0, first_seq, n_batches, steps, zk_seq):
        """Transcription of relation lib.rs:553-567: chain zero, seq of the first batch, one batch per step."""
        return (z0.chain == b"\x00" * 32 and z0.seq == first_seq and n_batches == steps
                and zk_seq == first_seq + n_batches)

    def test_wrong_fold_count(self):
        """P9: the number of folds equals the number of batches; the verifier's step count and z_K.seq must agree.

        Enforced: seq' = seq + 1 per step (clearing_step.rs:632) and the guest's checks
        (relation lib.rs:553-567); a proof for K steps does not verify as K-1 (fold.rs:96). Lean:
        fold_count_unique, bound_trace_steps."""
        z0 = genesis(cash=1000, fund=0, book=1000)
        batches = [[(0, -10, 10), (1, 10, 0)], [(1, -5, 5), (2, 5, 0)], [(2, -1, 1), (3, 1, 0)]]
        zk, _ = self.fold(z0, batches)
        self.assertEqual(zk.seq, z0.seq + 3)
        zk2, _ = self.fold(z0, batches[:2])
        self.assertNotEqual(zk2.seq, zk.seq)
        self.assertNotEqual(zk2, zk)
        # spec: the claimed batch count must equal the sequence advance
        self.assertNotEqual(zk2.seq - z0.seq, len(batches))
        self.assertTrue(self.impl_guest_z0_check(z0, z0.seq, 3, 3, zk.seq))
        self.assertFalse(self.impl_guest_z0_check(z0, z0.seq, 3, 3, zk2.seq))

    def test_non_genesis_initial_state(self):
        """P9: the initial state must be the venue's attested state before the first batch of the epoch.

        PARTIAL: the guest pins chain = 0 and seq = first batch (relation lib.rs:556-567) and the circuit
        pins identity_in (clearing_step.rs:291-293); cash, fund, carry, book, per-slot claims and the
        table are not compared with any attested venue state, so an inflated fund with a consistent
        identity is accepted. The spec rejects any z_0 other than the attested one."""
        attested = genesis(cash=500, fund=500, book=0)
        inflated = genesis(cash=10**9, fund=10**9, book=0)
        self.assertEqual(inflated.identity(), 0)
        self.assertTrue(self.impl_guest_z0_check(inflated, 0, 1, 1, 1), "implementation check accepts")
        self.assertNotEqual(inflated, attested)
        with self.assertRaises(Reject):
            self.spec_with_pin(attested, inflated)
        # skipping the first batch: state after batch 0 with a zero chain looks like a fresh start
        z1, _, _ = spec_step(attested, [(0, -10, 10), (1, 10, 0)])
        restarted = z1.with_(chain=b"\x00" * 32)
        self.assertTrue(self.impl_guest_z0_check(restarted, restarted.seq, 1, 1, restarted.seq + 1))
        with self.assertRaises(Reject):
            self.spec_with_pin(attested, restarted)

    @staticmethod
    def spec_with_pin(attested, z0):
        if z0 != attested:
            raise Reject("z_0 is not the attested pre-state of the first batch")


class AttackBatchInputs(unittest.TestCase):
    def test_batch_inputs_are_not_authenticated_by_the_step(self):
        """P3/P4: (slot, pnl, released) are free inputs of the step; a different pnl yields a different but valid output.

        The mutation sweep records the same fact (tests/mutation_sweep.rs header: batch inputs can satisfy
        the step but then the output differs from the router's post-state). No lane acknowledgement
        signature over the digest is checked in the circuit or in the guest (relation lib.rs:548-602).
        The spec accepts the forged batch only when it equals the venue's signed digest."""
        z = genesis()
        honest_rows = [(0, -100, 100), (1, 60, 0), (2, 40, 0)]
        forged_rows = [(0, -100, 100), (1, 90, 0), (2, 10, 0)]
        z_h, d_h, _ = spec_step(z, honest_rows)
        z_f, d_f, _ = spec_step(z, forged_rows)
        self.assertNotEqual(d_h, d_f)
        signed_digest = d_h  # what the lanes signed
        self.assertTrue(spec_accepts(z, honest_rows, z_h, signed_digest))
        self.assertFalse(spec_accepts(z, forged_rows, z_f, signed_digest))


if __name__ == "__main__":
    unittest.main()
