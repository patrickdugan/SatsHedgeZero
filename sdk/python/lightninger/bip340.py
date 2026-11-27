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


def _jdouble(x, y, z):
    if y == 0:
        return (0, 1, 0)
    ysq = y * y % P
    s = 4 * x * ysq % P
    m = 3 * x * x % P
    nx = (m * m - 2 * s) % P
    return (nx, (m * (s - nx) - 8 * ysq * ysq) % P, 2 * y * z % P)


def _jadd(x1, y1, z1, x2, y2, z2):
    if z1 == 0:
        return (x2, y2, z2)
    if z2 == 0:
        return (x1, y1, z1)
    z1s, z2s = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2s % P, x2 * z1s % P
    s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
    if u1 == u2:
        return _jdouble(x1, y1, z1) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    nx = (r * r - h3 - 2 * u1h2) % P
    return (nx, (r * (u1h2 - nx) - s1 * h3) % P, h * z1 * z2 % P)


def _mul(pt, k: int):
    """Scalar multiplication in Jacobian coordinates (one inversion)."""
    if pt is None or k % N == 0:
        return None
    k %= N
    acc = (0, 1, 0)
    base = (pt[0], pt[1], 1)
    while k:
        if k & 1:
            acc = _jadd(*acc, *base)
        base = _jdouble(*base)
        k >>= 1
    x, y, z = acc
    if z == 0:
        return None
    zi = pow(z, P - 2, P)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


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
