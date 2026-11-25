"""BIP340 Schnorr signatures over secp256k1 (stdlib only).

Follows the BIP340 reference algorithm. Used by the public trusted relayer
for one signature per 5 s slot, so affine arithmetic is fast enough.
"""
from hashlib import sha256

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def tagged_hash(tag: str | bytes, msg: bytes) -> bytes:
    t = sha256(tag.encode() if isinstance(tag, str) else tag).digest()
    return sha256(t + t + msg).digest()


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P)) % P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P)) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def _mul(pt, k: int):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
    return r


def _bytes(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _lift_x(x: int):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y & 1 == 0 else P - y)


def pubkey(seckey: bytes) -> bytes:
    d = _int(seckey)
    if not 1 <= d < N:
        raise ValueError("invalid secret key")
    return _bytes(_mul(G, d)[0])


def sign(msg: bytes, seckey: bytes, aux: bytes) -> bytes:
    if len(msg) != 32 or len(aux) != 32:
        raise ValueError("msg and aux must be 32 bytes")
    d0 = _int(seckey)
    if not 1 <= d0 < N:
        raise ValueError("invalid secret key")
    pt = _mul(G, d0)
    d = d0 if pt[1] % 2 == 0 else N - d0
    t = bytes(a ^ b for a, b in zip(_bytes(d), tagged_hash("BIP0340/aux", aux)))
    k0 = _int(tagged_hash("BIP0340/nonce", t + _bytes(pt[0]) + msg)) % N
    if k0 == 0:
        raise ValueError("nonce is zero")
    r = _mul(G, k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = _int(tagged_hash("BIP0340/challenge", _bytes(r[0]) + _bytes(pt[0]) + msg)) % N
    sig = _bytes(r[0]) + _bytes((k + e * d) % N)
    if not verify(msg, _bytes(pt[0]), sig):
        raise RuntimeError("signature self-check failed")
    return sig


def verify(msg: bytes, pk: bytes, sig: bytes) -> bool:
    if len(msg) != 32 or len(pk) != 32 or len(sig) != 64:
        return False
    pt = _lift_x(_int(pk))
    r, s = _int(sig[:32]), _int(sig[32:])
    if pt is None or r >= P or s >= N:
        return False
    e = _int(tagged_hash("BIP0340/challenge", sig[:32] + pk + msg)) % N
    rr = _add(_mul(G, s), _mul(pt, N - e))
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r
