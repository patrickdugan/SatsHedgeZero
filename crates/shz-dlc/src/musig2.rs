//! BIP-327 MuSig2 (key aggregation, tweaks, two-round nonces, partial signatures and their
//! verification, aggregation) and MuSig2 adaptor signatures that complete with a DLC oracle's
//! attestation scalar.
//!
//! Follows the BIP-327 reference (`bip-0327/reference.py`) step for step and is checked against its
//! vector files (`tests/musig2_bip327.rs`).
//!
//! **Adaptor extension.** With adaptor point `T = t·G` the session nonce is `R' = R + T` where
//! `R = R_1 + b·R_2` is BIP-327's aggregate nonce. The challenge is `e = H(x(R') ‖ x(Q) ‖ m)` and
//! signers negate their nonces when `R'` has odd `y`. The aggregate pre-signature `(R', s)` satisfies
//! `s·G = ±R + e·Q`, so `s' = s + t` (`R'` even) or `s' = s − t` (`R'` odd) is a BIP-340 signature
//! `(x(R'), s')` for `Q`, and anyone holding the pre-signature and the final signature recovers `t`.
//!
//! **Nonces.** A [`SecNonce`] signs once: [`sign`] zeroes it and refuses an all-zero nonce. A
//! [`NonceStore`] keeps one secret nonce per CET id on disk and deletes it (and persists the
//! deletion) before handing it out, so a crash after signing cannot replay it.
use k256::{
    elliptic_curve::{
        bigint::U256,
        group::Group,
        ops::Reduce,
        point::AffineCoordinates,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use std::{collections::BTreeMap, path::PathBuf};

use crate::tagged_hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MusigError {
    /// A participant's (or the aggregator's, `signer: None`) contribution is invalid.
    InvalidContribution { signer: Option<usize>, contrib: &'static str },
    /// An argument is out of range or inconsistent.
    Value(String),
}

impl std::fmt::Display for MusigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MusigError::InvalidContribution { signer, contrib } => write!(f, "invalid {contrib} from signer {signer:?}"),
            MusigError::Value(m) => f.write_str(m),
        }
    }
}
impl std::error::Error for MusigError {}

type R<T> = Result<T, MusigError>;

fn value<T>(m: &str) -> R<T> {
    Err(MusigError::Value(m.into()))
}

fn int_mod_n(b: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(b))
}

/// A scalar from 32 big-endian bytes, `None` when it is `>= n`.
fn scalar_lt_n(b: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*b).into()))
}

fn has_even_y(p: &ProjectivePoint) -> bool {
    !bool::from(p.to_affine().y_is_odd())
}

pub fn xbytes(p: &ProjectivePoint) -> [u8; 32] {
    p.to_affine().x().into()
}

pub fn cbytes(p: &ProjectivePoint) -> [u8; 33] {
    p.to_affine().to_encoded_point(true).as_bytes().try_into().unwrap()
}

fn cbytes_ext(p: &ProjectivePoint) -> [u8; 33] {
    if bool::from(p.is_identity()) {
        [0; 33]
    } else {
        cbytes(p)
    }
}

fn cpoint(b: &[u8]) -> Option<ProjectivePoint> {
    if b.len() != 33 || !(b[0] == 2 || b[0] == 3) {
        return None;
    }
    let ep = EncodedPoint::from_bytes(b).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)).map(ProjectivePoint::from)
}

fn cpoint_ext(b: &[u8]) -> Option<ProjectivePoint> {
    if b.iter().all(|&x| x == 0) && b.len() == 33 {
        Some(ProjectivePoint::IDENTITY)
    } else {
        cpoint(b)
    }
}

fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

/// The 33-byte compressed public key of a secret key (`individual_pk`).
pub fn individual_pk(sk: &[u8; 32]) -> R<[u8; 33]> {
    let d = scalar_lt_n(sk).filter(|d| !bool::from(d.is_zero())).ok_or_else(|| MusigError::Value("The secret key must be an integer in the range 1..n-1.".into()))?;
    Ok(cbytes(&(ProjectivePoint::GENERATOR * d)))
}

pub fn key_sort(pubkeys: &[[u8; 33]]) -> Vec<[u8; 33]> {
    let mut v = pubkeys.to_vec();
    v.sort();
    v
}

/// `KeyAggContext`: aggregate point, sign accumulator `g` (as a scalar ±1 product), tweak accumulator.
#[derive(Debug, Clone)]
pub struct KeyAggContext {
    pub q: ProjectivePoint,
    pub gacc: Scalar,
    pub tacc: Scalar,
}

impl KeyAggContext {
    pub fn xonly(&self) -> [u8; 32] {
        xbytes(&self.q)
    }
}

fn hash_keys(pubkeys: &[[u8; 33]]) -> [u8; 32] {
    tagged_hash(b"KeyAgg list", &pubkeys.concat())
}

fn second_key(pubkeys: &[[u8; 33]]) -> [u8; 33] {
    pubkeys.iter().skip(1).find(|k| **k != pubkeys[0]).copied().unwrap_or([0; 33])
}

fn key_agg_coeff_internal(pubkeys: &[[u8; 33]], pk: &[u8; 33], pk2: &[u8; 33]) -> Scalar {
    if pk == pk2 {
        return Scalar::ONE;
    }
    let l = hash_keys(pubkeys);
    int_mod_n(&tagged_hash(b"KeyAgg coefficient", &[&l[..], &pk[..]].concat()))
}

pub fn key_agg_coeff(pubkeys: &[[u8; 33]], pk: &[u8; 33]) -> Scalar {
    key_agg_coeff_internal(pubkeys, pk, &second_key(pubkeys))
}

pub fn key_agg(pubkeys: &[[u8; 33]]) -> R<KeyAggContext> {
    let pk2 = second_key(pubkeys);
    let mut q = ProjectivePoint::IDENTITY;
    for (i, pk) in pubkeys.iter().enumerate() {
        let p = cpoint(pk).ok_or(MusigError::InvalidContribution { signer: Some(i), contrib: "pubkey" })?;
        q += p * key_agg_coeff_internal(pubkeys, pk, &pk2);
    }
    if bool::from(q.is_identity()) {
        return value("The aggregate key is infinity.");
    }
    Ok(KeyAggContext { q, gacc: Scalar::ONE, tacc: Scalar::ZERO })
}

pub fn apply_tweak(ctx: &KeyAggContext, tweak: &[u8; 32], is_xonly: bool) -> R<KeyAggContext> {
    let g = if is_xonly && !has_even_y(&ctx.q) { -Scalar::ONE } else { Scalar::ONE };
    let t = scalar_lt_n(tweak).ok_or_else(|| MusigError::Value("The tweak must be less than n.".into()))?;
    let q = ctx.q * g + ProjectivePoint::GENERATOR * t;
    if bool::from(q.is_identity()) {
        return value("The result of tweaking cannot be infinity.");
    }
    Ok(KeyAggContext { q, gacc: g * ctx.gacc, tacc: t + g * ctx.tacc })
}

pub fn key_agg_and_tweak(pubkeys: &[[u8; 33]], tweaks: &[[u8; 32]], is_xonly: &[bool]) -> R<KeyAggContext> {
    if tweaks.len() != is_xonly.len() {
        return value("The `tweaks` and `is_xonly` arrays must have the same length.");
    }
    let mut c = key_agg(pubkeys)?;
    for (t, x) in tweaks.iter().zip(is_xonly) {
        c = apply_tweak(&c, t, *x)?;
    }
    Ok(c)
}

/// Secret nonce `k_1 ‖ k_2 ‖ pk` (97 bytes). Signing zeroes the scalars.
#[derive(Clone)]
pub struct SecNonce(pub [u8; 97]);

impl std::fmt::Debug for SecNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecNonce(..)")
    }
}

fn nonce_hash(rand: &[u8; 32], pk: &[u8], aggpk: &[u8], i: u8, msg_prefixed: &[u8], extra_in: &[u8]) -> Scalar {
    let mut b = rand.to_vec();
    b.push(pk.len() as u8);
    b.extend(pk);
    b.push(aggpk.len() as u8);
    b.extend(aggpk);
    b.extend(msg_prefixed);
    b.extend((extra_in.len() as u32).to_be_bytes());
    b.extend(extra_in);
    b.push(i);
    int_mod_n(&tagged_hash(b"MuSig/nonce", &b))
}

/// `nonce_gen_internal`: deterministic in `rand_`; callers pass 32 fresh random bytes.
pub fn nonce_gen_internal(rand_: &[u8; 32], sk: Option<&[u8; 32]>, pk: &[u8; 33], aggpk: Option<&[u8; 32]>, msg: Option<&[u8]>, extra_in: Option<&[u8]>) -> R<(SecNonce, [u8; 66])> {
    let rand: [u8; 32] = match sk {
        Some(sk) => {
            let h = tagged_hash(b"MuSig/aux", rand_);
            core::array::from_fn(|i| sk[i] ^ h[i])
        }
        None => *rand_,
    };
    let aggpk: &[u8] = aggpk.map(|a| &a[..]).unwrap_or(&[]);
    let msg_prefixed = match msg {
        None => vec![0u8],
        Some(m) => [vec![1u8], (m.len() as u64).to_be_bytes().to_vec(), m.to_vec()].concat(),
    };
    let extra = extra_in.unwrap_or(&[]);
    let k1 = nonce_hash(&rand, pk, aggpk, 0, &msg_prefixed, extra);
    let k2 = nonce_hash(&rand, pk, aggpk, 1, &msg_prefixed, extra);
    if bool::from(k1.is_zero()) || bool::from(k2.is_zero()) {
        return value("nonce is zero");
    }
    let mut sec = [0u8; 97];
    sec[..32].copy_from_slice(&scalar_bytes(&k1));
    sec[32..64].copy_from_slice(&scalar_bytes(&k2));
    sec[64..].copy_from_slice(pk);
    let mut pubn = [0u8; 66];
    pubn[..33].copy_from_slice(&cbytes(&(ProjectivePoint::GENERATOR * k1)));
    pubn[33..].copy_from_slice(&cbytes(&(ProjectivePoint::GENERATOR * k2)));
    Ok((SecNonce(sec), pubn))
}

/// `nonce_gen` with 32 bytes from the OS RNG.
pub fn nonce_gen(sk: Option<&[u8; 32]>, pk: &[u8; 33], aggpk: Option<&[u8; 32]>, msg: Option<&[u8]>, extra_in: Option<&[u8]>) -> R<(SecNonce, [u8; 66])> {
    use rand_core::{OsRng, RngCore};
    let mut r = [0u8; 32];
    OsRng.fill_bytes(&mut r);
    nonce_gen_internal(&r, sk, pk, aggpk, msg, extra_in)
}

pub fn nonce_agg(pubnonces: &[[u8; 66]]) -> R<[u8; 66]> {
    let mut out = [0u8; 66];
    for j in 0..2 {
        let mut rj = ProjectivePoint::IDENTITY;
        for (i, pn) in pubnonces.iter().enumerate() {
            rj += cpoint(&pn[j * 33..(j + 1) * 33]).ok_or(MusigError::InvalidContribution { signer: Some(i), contrib: "pubnonce" })?;
        }
        out[j * 33..(j + 1) * 33].copy_from_slice(&cbytes_ext(&rj));
    }
    Ok(out)
}

/// A signing session; `adaptor` is the DLC adaptor point `T` (None for plain BIP-327).
#[derive(Debug, Clone)]
pub struct Session {
    pub aggnonce: [u8; 66],
    pub pubkeys: Vec<[u8; 33]>,
    pub tweaks: Vec<[u8; 32]>,
    pub is_xonly: Vec<bool>,
    pub msg: Vec<u8>,
    pub adaptor: Option<ProjectivePoint>,
}

struct Values {
    q: ProjectivePoint,
    gacc: Scalar,
    tacc: Scalar,
    b: Scalar,
    /// The nonce the challenge commits to: `R` (plain) or `R + T` (adaptor).
    r: ProjectivePoint,
    e: Scalar,
}

fn session_values(s: &Session) -> R<Values> {
    let c = key_agg_and_tweak(&s.pubkeys, &s.tweaks, &s.is_xonly)?;
    let b = int_mod_n(&tagged_hash(b"MuSig/noncecoef", &[&s.aggnonce[..], &xbytes(&c.q)[..], &s.msg[..]].concat()));
    let r1 = cpoint_ext(&s.aggnonce[..33]).ok_or(MusigError::InvalidContribution { signer: None, contrib: "aggnonce" })?;
    let r2 = cpoint_ext(&s.aggnonce[33..]).ok_or(MusigError::InvalidContribution { signer: None, contrib: "aggnonce" })?;
    let r_ = r1 + r2 * b;
    let mut r = if bool::from(r_.is_identity()) { ProjectivePoint::GENERATOR } else { r_ };
    if let Some(t) = s.adaptor {
        r += t;
        if bool::from(r.is_identity()) {
            return value("R + T is infinity");
        }
    }
    let e = int_mod_n(&tagged_hash(b"BIP0340/challenge", &[&xbytes(&r)[..], &xbytes(&c.q)[..], &s.msg[..]].concat()));
    Ok(Values { q: c.q, gacc: c.gacc, tacc: c.tacc, b, r, e })
}

fn session_coeff(s: &Session, p: &ProjectivePoint) -> R<Scalar> {
    let pk = cbytes(p);
    if !s.pubkeys.contains(&pk) {
        return value("The signer's pubkey must be included in the list of pubkeys.");
    }
    Ok(key_agg_coeff(&s.pubkeys, &pk))
}

/// Partial signature (`sign`); with `s.adaptor` set, a partial adaptor signature. Zeroes `secnonce`.
pub fn sign(secnonce: &mut SecNonce, sk: &[u8; 32], s: &Session) -> R<[u8; 32]> {
    let v = session_values(s)?;
    let k1b: [u8; 32] = secnonce.0[..32].try_into().unwrap();
    let k2b: [u8; 32] = secnonce.0[32..64].try_into().unwrap();
    secnonce.0[..64].fill(0);
    let k1_ = scalar_lt_n(&k1b).filter(|k| !bool::from(k.is_zero())).ok_or_else(|| MusigError::Value("first secnonce value is out of range.".into()))?;
    let k2_ = scalar_lt_n(&k2b).filter(|k| !bool::from(k.is_zero())).ok_or_else(|| MusigError::Value("second secnonce value is out of range.".into()))?;
    let (k1, k2) = if has_even_y(&v.r) { (k1_, k2_) } else { (-k1_, -k2_) };
    let d_ = scalar_lt_n(sk).filter(|d| !bool::from(d.is_zero())).ok_or_else(|| MusigError::Value("secret key value is out of range.".into()))?;
    let p = ProjectivePoint::GENERATOR * d_;
    if cbytes(&p)[..] != secnonce.0[64..] {
        return value("Public key does not match nonce_gen argument");
    }
    let a = session_coeff(s, &p)?;
    let g = if has_even_y(&v.q) { Scalar::ONE } else { -Scalar::ONE };
    let d = g * v.gacc * d_;
    let sig = k1 + v.b * k2 + v.e * a * d;
    let psig = scalar_bytes(&sig);
    let mut pubn = [0u8; 66];
    pubn[..33].copy_from_slice(&cbytes(&(ProjectivePoint::GENERATOR * k1_)));
    pubn[33..].copy_from_slice(&cbytes(&(ProjectivePoint::GENERATOR * k2_)));
    debug_assert!(partial_sig_verify_internal(&psig, &pubn, &cbytes(&p), s).unwrap_or(false));
    Ok(psig)
}

/// `partial_sig_verify_internal`; also verifies partial adaptor signatures (`s.adaptor`).
pub fn partial_sig_verify_internal(psig: &[u8; 32], pubnonce: &[u8; 66], pk: &[u8; 33], s: &Session) -> R<bool> {
    let v = session_values(s)?;
    let Some(sc) = scalar_lt_n(psig) else { return Ok(false) };
    let r1 = cpoint(&pubnonce[..33]).ok_or(MusigError::InvalidContribution { signer: None, contrib: "pubnonce" })?;
    let r2 = cpoint(&pubnonce[33..]).ok_or(MusigError::InvalidContribution { signer: None, contrib: "pubnonce" })?;
    let re_ = r1 + r2 * v.b;
    let re = if has_even_y(&v.r) { re_ } else { -re_ };
    let p = cpoint(pk).ok_or(MusigError::InvalidContribution { signer: None, contrib: "pubkey" })?;
    let a = session_coeff(s, &p)?;
    let g = if has_even_y(&v.q) { Scalar::ONE } else { -Scalar::ONE };
    Ok(ProjectivePoint::GENERATOR * sc == re + p * (v.e * a * g * v.gacc))
}

/// `partial_sig_verify`: aggregates the nonces itself; signer index `i`.
pub fn partial_sig_verify(psig: &[u8; 32], pubnonces: &[[u8; 66]], pubkeys: &[[u8; 33]], tweaks: &[[u8; 32]], is_xonly: &[bool], msg: &[u8], i: usize) -> R<bool> {
    if pubnonces.len() != pubkeys.len() {
        return value("The `pubnonces` and `pubkeys` arrays must have the same length.");
    }
    if tweaks.len() != is_xonly.len() {
        return value("The `tweaks` and `is_xonly` arrays must have the same length.");
    }
    let aggnonce = nonce_agg(pubnonces)?;
    let s = Session { aggnonce, pubkeys: pubkeys.to_vec(), tweaks: tweaks.to_vec(), is_xonly: is_xonly.to_vec(), msg: msg.to_vec(), adaptor: None };
    partial_sig_verify_internal(psig, &pubnonces[i], &pubkeys[i], &s).map_err(|e| match e {
        MusigError::InvalidContribution { signer: None, contrib } => MusigError::InvalidContribution { signer: Some(i), contrib },
        e => e,
    })
}

/// `partial_sig_agg`: the 64-byte BIP-340 signature (plain session), or the adaptor
/// pre-signature `x(R + T) ‖ s` (adaptor session; complete it with [`adaptor_complete`]).
pub fn partial_sig_agg(psigs: &[[u8; 32]], s: &Session) -> R<[u8; 64]> {
    let v = session_values(s)?;
    let mut acc = Scalar::ZERO;
    for (i, p) in psigs.iter().enumerate() {
        acc += scalar_lt_n(p).ok_or(MusigError::InvalidContribution { signer: Some(i), contrib: "psig" })?;
    }
    let g = if has_even_y(&v.q) { Scalar::ONE } else { -Scalar::ONE };
    acc += v.e * g * v.tacc;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&xbytes(&v.r));
    out[32..].copy_from_slice(&scalar_bytes(&acc));
    Ok(out)
}

/// Whether the adaptor session's `R + T` has odd `y` (completion subtracts `t` then).
pub fn adaptor_negated(s: &Session) -> R<bool> {
    Ok(!has_even_y(&session_values(s)?.r))
}

/// Complete an aggregate adaptor pre-signature with the adaptor secret `t` (the oracle's
/// attestation scalar for the outcome).
pub fn adaptor_complete(presig: &[u8; 64], t: &[u8; 32], negated: bool) -> R<[u8; 64]> {
    let s = scalar_lt_n(presig[32..].try_into().unwrap()).ok_or_else(|| MusigError::Value("pre-signature scalar out of range".into()))?;
    let t = scalar_lt_n(t).ok_or_else(|| MusigError::Value("adaptor secret out of range".into()))?;
    let f = if negated { s - t } else { s + t };
    let mut out = *presig;
    out[32..].copy_from_slice(&scalar_bytes(&f));
    Ok(out)
}

/// Recover `t` from a pre-signature and the completed signature.
pub fn adaptor_extract(presig: &[u8; 64], sig: &[u8; 64], negated: bool) -> R<[u8; 32]> {
    let s = scalar_lt_n(presig[32..].try_into().unwrap()).ok_or_else(|| MusigError::Value("pre-signature scalar out of range".into()))?;
    let f = scalar_lt_n(sig[32..].try_into().unwrap()).ok_or_else(|| MusigError::Value("signature scalar out of range".into()))?;
    Ok(scalar_bytes(&if negated { s - f } else { f - s }))
}

/// Secret nonces kept on disk, one per CET id, deleted (and the deletion persisted) before use.
pub struct NonceStore {
    path: PathBuf,
    map: BTreeMap<String, String>,
}

impl NonceStore {
    pub fn open(path: impl Into<PathBuf>) -> R<Self> {
        let path = path.into();
        let map = match std::fs::read_to_string(&path) {
            Ok(s) => serde_json_lite::parse(&s).map_err(MusigError::Value)?,
            Err(_) => BTreeMap::new(),
        };
        Ok(NonceStore { path, map })
    }
    fn save(&self) -> R<()> {
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json_lite::dump(&self.map)).map_err(|e| MusigError::Value(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| MusigError::Value(e.to_string()))
    }
    /// Store a fresh secret nonce for `id`. Refuses an id that already has one.
    pub fn put(&mut self, id: &str, sec: &SecNonce) -> R<()> {
        if self.map.contains_key(id) {
            return value(&format!("a nonce for {id} already exists"));
        }
        self.map.insert(id.into(), hex::encode(sec.0));
        self.save()
    }
    /// Remove and return the secret nonce for `id`. A second call for the same id fails.
    pub fn take(&mut self, id: &str) -> R<SecNonce> {
        let h = self.map.remove(id).ok_or_else(|| MusigError::Value(format!("no unused nonce for {id} (burned or never generated)")))?;
        self.save()?;
        let b = hex::decode(h).map_err(|e| MusigError::Value(e.to_string()))?;
        Ok(SecNonce(b.try_into().map_err(|_| MusigError::Value("stored nonce has the wrong length".into()))?))
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// A flat `{"id": "hex"}` JSON object, without a serde_json dependency in the library.
mod serde_json_lite {
    use std::collections::BTreeMap;
    pub fn dump(m: &BTreeMap<String, String>) -> String {
        let items: Vec<String> = m.iter().map(|(k, v)| format!("\"{}\":\"{}\"", k.replace('\\', "\\\\").replace('"', "\\\""), v)).collect();
        format!("{{{}}}", items.join(","))
    }
    pub fn parse(s: &str) -> Result<BTreeMap<String, String>, String> {
        let s = s.trim();
        let inner = s.strip_prefix('{').and_then(|x| x.strip_suffix('}')).ok_or("nonce store is not a JSON object")?;
        let mut m = BTreeMap::new();
        let mut rest = inner.trim();
        while !rest.is_empty() {
            let (k, r) = string(rest)?;
            let r = r.trim_start().strip_prefix(':').ok_or("expected ':'")?.trim_start();
            let (v, r) = string(r)?;
            m.insert(k, v);
            rest = r.trim_start();
            rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
        }
        Ok(m)
    }
    fn string(s: &str) -> Result<(String, &str), String> {
        let s = s.strip_prefix('"').ok_or("expected a string")?;
        let mut out = String::new();
        let mut it = s.char_indices();
        while let Some((i, c)) = it.next() {
            match c {
                '\\' => {
                    let (_, n) = it.next().ok_or("bad escape")?;
                    out.push(n);
                }
                '"' => return Ok((out, &s[i + 1..])),
                c => out.push(c),
            }
        }
        Err("unterminated string".into())
    }
}
