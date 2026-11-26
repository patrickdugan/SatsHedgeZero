//! secp256k1 helpers mirroring `bip340.py` / `frost.py`, with every secret in a k256 `Scalar`
//! (constant-time field and scalar arithmetic) instead of a Python big int.

use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::subtle::{Choice, ConditionallySelectable};
use k256::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, U256};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::json::{PyErr, R};

pub type Point = ProjectivePoint;

const FIELD_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

fn fb(b: &[u8]) -> FieldBytes {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a.into()
}

pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

/// `int.from_bytes(h, "big") % N`.
pub fn reduce32(b: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&fb(b))
}

/// A big-endian integer of any length, reduced mod N (Horner over bytes).
pub fn reduce_be(b: &[u8]) -> Scalar {
    if b.len() == 32 {
        return reduce32(b.try_into().unwrap());
    }
    let base = Scalar::from(256u64);
    b.iter().fold(Scalar::ZERO, |acc, &x| acc * base + Scalar::from(x as u64))
}

/// Python `int(s, 16)` reduced mod N (sign respected).
pub fn scalar_from_py_hex(s: &str) -> R<Scalar> {
    let (neg, mag) = crate::json::py_int_hex(s)?;
    let v = reduce_be(&mag);
    Ok(if neg { -v } else { v })
}

/// `(int(s, 16) ^ pad) mod N` with Python's infinite two's-complement XOR.
pub fn xor_pad_from_py_hex(s: &str, pad: &[u8; 32]) -> R<Scalar> {
    let (neg, mag) = crate::json::py_int_hex(s)?;
    let xor = |m: &[u8]| -> Vec<u8> {
        let n = m.len().max(32);
        let mut out = vec![0u8; n];
        for (k, o) in out.iter_mut().enumerate() {
            let a = if k + m.len() >= n { m[k + m.len() - n] } else { 0 };
            let p = if k + 32 >= n { pad[k + 32 - n] } else { 0 };
            *o = a ^ p;
        }
        out
    };
    if !neg {
        return Ok(reduce_be(&xor(&mag)));
    }
    // -m ^ p == -(((m - 1) ^ p) + 1)
    let mut m1 = mag.clone();
    for b in m1.iter_mut().rev() {
        if *b == 0 {
            *b = 0xff;
        } else {
            *b -= 1;
            break;
        }
    }
    Ok(-(reduce_be(&xor(&m1)) + Scalar::ONE))
}

pub fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

pub fn scalar_hex(s: &Scalar) -> String {
    crate::json::hex(&scalar_bytes(s))
}

pub fn scalar_from_i128(v: i128) -> Scalar {
    let m = Scalar::from_repr(FieldBytes::from(u128_be32(v.unsigned_abs()))).unwrap();
    if v < 0 { -m } else { m }
}

fn u128_be32(v: u128) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..].copy_from_slice(&v.to_be_bytes());
    b
}

/// `secrets.randbelow(N - 1) + 1`.
pub fn rand_scalar() -> Scalar {
    *NonZeroScalar::random(&mut OsRng)
}

pub fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn y_odd(p: &Point) -> bool {
    p.to_affine().y_is_odd().into()
}

pub fn x_bytes(p: &Point) -> [u8; 32] {
    p.to_affine().x().into()
}

/// `frost.ser`: 33-byte compressed point.
pub fn ser(p: &Point) -> [u8; 33] {
    let e = p.to_affine().to_encoded_point(true);
    e.as_bytes().try_into().expect("non-identity point")
}

/// `frost.deser`.
pub fn deser(b: &[u8]) -> R<Point> {
    if b.len() != 33 || !(b[0] == 2 || b[0] == 3) {
        return Err(PyErr::value("bad point encoding"));
    }
    let x = &fb(&b[1..]);
    let p = AffinePoint::decompress(x, Choice::from(b[0] - 2));
    Option::<AffinePoint>::from(p).map(Point::from).ok_or_else(|| PyErr::value("not on curve"))
}

pub fn lift_x(x: &[u8]) -> Option<Point> {
    let p = AffinePoint::decompress(&fb(x), Choice::from(0));
    Option::<AffinePoint>::from(p).map(Point::from)
}

pub fn is_identity(p: &Point) -> bool {
    p.is_identity().into()
}

pub fn g_mul(s: &Scalar) -> Point {
    Point::GENERATOR * s
}

/// `bip340.verify`.
pub fn bip340_verify(msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
    if msg.len() != 32 || pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    let Some(p) = lift_x(pk) else { return false };
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    // r < P and s < N
    if r >= FIELD_P {
        return false;
    }
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(fb(&sig[32..]))) else { return false };
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&r);
    data.extend_from_slice(pk);
    data.extend_from_slice(msg);
    let e = reduce32(&tagged_hash(b"BIP0340/challenge", &data));
    let rr = g_mul(&s) + p * (-e);
    !is_identity(&rr) && !y_odd(&rr) && x_bytes(&rr) == r
}

/// `bip340.sign` with a secret already in a Scalar.
pub fn bip340_sign(msg: &[u8; 32], d0: &Scalar, aux: &[u8; 32]) -> R<[u8; 64]> {
    if bool::from(d0.is_zero()) {
        return Err(PyErr::value("invalid secret key"));
    }
    let pt = g_mul(d0);
    let pa = pt.to_affine();
    let d = Scalar::conditional_select(d0, &-*d0, pa.y_is_odd());
    let px: [u8; 32] = pa.x().into();
    let ah = tagged_hash(b"BIP0340/aux", aux);
    let db = scalar_bytes(&d);
    let mut t = [0u8; 32];
    for k in 0..32 {
        t[k] = db[k] ^ ah[k];
    }
    let mut nd = Vec::with_capacity(96);
    nd.extend_from_slice(&t);
    nd.extend_from_slice(&px);
    nd.extend_from_slice(msg);
    let k0 = reduce32(&tagged_hash(b"BIP0340/nonce", &nd));
    if bool::from(k0.is_zero()) {
        return Err(PyErr::value("nonce is zero"));
    }
    let r = g_mul(&k0).to_affine();
    let k = Scalar::conditional_select(&k0, &-k0, r.y_is_odd());
    let rx: [u8; 32] = r.x().into();
    let mut cd = Vec::with_capacity(96);
    cd.extend_from_slice(&rx);
    cd.extend_from_slice(&px);
    cd.extend_from_slice(msg);
    let e = reduce32(&tagged_hash(b"BIP0340/challenge", &cd));
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx);
    sig[32..].copy_from_slice(&scalar_bytes(&(k + e * d)));
    if !bip340_verify(msg, &px, &sig) {
        return Err(PyErr::new("RuntimeError", "signature self-check failed"));
    }
    Ok(sig)
}

/// `frost.lagrange(i, signers)` over the signer list exactly as given (duplicates included).
pub fn lagrange(i: i128, signers: &[i128]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in signers {
        if j != i {
            num *= scalar_from_i128(j);
            den *= scalar_from_i128(j - i);
        }
    }
    // pow(den, N - 2, N): den == 0 gives 0, like Python.
    num * Option::<Scalar>::from(den.invert()).unwrap_or(Scalar::ZERO)
}

/// `frost.challenge`.
pub fn challenge(r_x: &[u8], group_x: &[u8], msg: &[u8]) -> Scalar {
    let mut d = Vec::with_capacity(r_x.len() + group_x.len() + msg.len());
    d.extend_from_slice(r_x);
    d.extend_from_slice(group_x);
    d.extend_from_slice(msg);
    reduce32(&tagged_hash(b"BIP0340/challenge", &d))
}

/// `pow(j, k, N)` as a Scalar.
pub fn pow_small(j: i128, k: usize) -> Scalar {
    let b = scalar_from_i128(j);
    let mut acc = Scalar::ONE;
    for _ in 0..k {
        acc *= b;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip340_vector_0() {
        // BIP340 test vector 0.
        let sk = Scalar::from(3u64);
        let sig = bip340_sign(&[0u8; 32], &sk, &[0u8; 32]).unwrap();
        assert_eq!(
            crate::json::hex(&sig),
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        );
        assert!(bip340_verify(&[0u8; 32], &x_bytes(&g_mul(&sk)), &sig));
    }

    #[test]
    fn negative_hex_xor_matches_python() {
        // Python: (int("-5", 16) ^ 3) % N == N - 8
        let pad = {
            let mut p = [0u8; 32];
            p[31] = 3;
            p
        };
        assert_eq!(xor_pad_from_py_hex("-5", &pad).unwrap(), -Scalar::from(8u64));
        assert_eq!(xor_pad_from_py_hex("5", &pad).unwrap(), Scalar::from(6u64));
        assert_eq!(scalar_from_py_hex("-0x1").unwrap(), -Scalar::ONE);
    }
}
