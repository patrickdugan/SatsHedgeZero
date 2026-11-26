//! FROST signing (`frost.py`): durable nonce state and partial signatures.

use std::path::{Path, PathBuf};

use k256::Scalar;

use crate::ec::{self, Point};
use crate::json::{self, J, Num, PyErr, R, Style, fromhex_j, hex, py_int_str};
use crate::store::atomic_write;

/// Source of fresh nonces and auxiliary randomness. Production uses the OS RNG; the vector
/// tests replay the exact sequence the Python reference drew.
pub trait Rng: Send {
    fn scalar(&mut self) -> Scalar;
    fn bytes32(&mut self) -> [u8; 32];
}

pub struct OsRng;

impl Rng for OsRng {
    fn scalar(&mut self) -> Scalar {
        ec::rand_scalar()
    }
    fn bytes32(&mut self) -> [u8; 32] {
        ec::rand32()
    }
}

/// The member's secret share and public group description (`share.json`).
pub struct Share {
    pub index: i128,
    pub secret: Scalar,
    pub group: J,
    pub group_pubkey: String,
    pub group_x: Vec<u8>,
    pub threshold: i128,
    pub signers: i128,
}

impl Share {
    pub fn from_json(j: &J) -> R<Share> {
        let index = j.at("index")?.strict_int().ok_or_else(|| PyErr::value("share index must be an integer"))?;
        let secret = ec::scalar_from_py_hex(j.at("secret_share")?.str_or("secret_share")?)?;
        let group = j.at("group")?.clone();
        let group_pubkey = group.at("group_pubkey")?.str_or("group_pubkey")?.to_string();
        let group_x = json::py_fromhex(&group_pubkey)?;
        let threshold = json::py_int(group.at("threshold")?)?;
        let signers = json::py_int(group.at("signers")?)?;
        Ok(Share { index, secret, group, group_pubkey, group_x, threshold, signers })
    }
    /// Y_j from `verification_shares[str(j)]`.
    pub fn verification_share(&self, j: i128) -> R<Point> {
        let y = self.group.at("verification_shares")?.at(&j.to_string())?;
        ec::deser(&fromhex_j(y)?)
    }
}

/// `frost.SignerState` over `nonces.json`.
pub struct SignerState {
    pub path: PathBuf,
    pub s: J,
}

fn key_int(k: &str) -> R<i128> {
    py_int_str(k)
}

impl SignerState {
    pub fn open(path: &Path) -> R<SignerState> {
        let s = if path.exists() {
            let text = std::fs::read(path).map_err(|e| PyErr::new("OSError", e.to_string()))?;
            json::loads_bytes(&text)?
        } else {
            json::loads(r#"{"last_seq": 0, "last_msg": null, "nonces": {}}"#).unwrap()
        };
        Ok(SignerState { path: path.to_path_buf(), s })
    }

    fn save(&self) -> R<()> {
        atomic_write(&self.path, ".state", json::dumps(&self.s, Style::Default).as_bytes())
    }

    pub fn last_seq(&self) -> R<Num> {
        Num::need(self.s.at("last_seq")?)
    }

    pub fn last_slot(&self) -> R<Num> {
        match self.s.get("last_slot")? {
            Some(v) => Num::need(v),
            None => Ok(Num::I(0)),
        }
    }

    pub fn commit(&mut self, seq: i128, rng: &mut dyn Rng) -> R<(Scalar, Scalar)> {
        if Num::I(seq).le(self.last_seq()?) {
            return Err(PyErr::value("sequence already signed or older"));
        }
        let key = seq.to_string();
        if !self.s.at("nonces")?.contains_key(&key) {
            let last = self.last_seq()?;
            let mut keep: Vec<(String, J)> = Vec::new();
            for (k, v) in self.s.at("nonces")?.items()? {
                let ki = key_int(k)?;
                if last.lt(Num::I(ki)) && ki >= seq - 64 {
                    keep.push((k.clone(), v.clone()));
                }
            }
            let excess = keep.len().saturating_sub(63);
            if excess > 0 {
                let mut order: Vec<(i128, usize)> = Vec::new();
                for (pos, (k, _)) in keep.iter().enumerate() {
                    order.push((key_int(k)?, pos));
                }
                order.sort_by_key(|&(ki, pos)| (ki, pos));
                let drop: Vec<usize> = order[..excess].iter().map(|&(_, p)| p).collect();
                keep = keep.into_iter().enumerate().filter(|(p, _)| !drop.contains(p)).map(|(_, kv)| kv).collect();
            }
            let d = rng.scalar();
            let e = rng.scalar();
            keep.push((key.clone(), J::Arr(vec![J::s(ec::scalar_hex(&d)), J::s(ec::scalar_hex(&e))])));
            self.s.set("nonces", J::Obj(keep));
            self.save()?;
        }
        let pair = self.s.at("nonces")?.at(&key)?;
        Ok((nonce_scalar(pair.idx(0)?)?, nonce_scalar(pair.idx(1)?)?))
    }

    pub fn take(&mut self, seq: i128, msg: &[u8], slot_us: i128) -> R<(Scalar, Scalar)> {
        if Num::I(seq).le(self.last_seq()?) {
            return Err(PyErr::value("sequence already signed or older"));
        }
        let pair = self.s.at_mut("nonces")?.pop(&seq.to_string()).ok_or_else(|| PyErr::value("no unused nonce for this sequence"))?;
        self.s.set("last_seq", J::Int(seq));
        self.s.set("last_msg", J::s(hex(msg)));
        let last_slot = self.last_slot()?;
        let new_slot = if Num::I(slot_us).lt(last_slot) { self.s.at("last_slot")?.clone() } else { J::Int(slot_us) };
        self.s.set("last_slot", new_slot);
        self.save()?;
        Ok((nonce_scalar(pair.idx(0)?)?, nonce_scalar(pair.idx(1)?)?))
    }
}

fn nonce_scalar(j: &J) -> R<Scalar> {
    ec::scalar_from_py_hex(j.str_or("nonce")?)
}

/// A commitment entry as the coordinator sent it.
struct Commit<'a> {
    index: &'a J,
    d: &'a J,
    e: &'a J,
}

fn commit_list(commits: &J) -> R<Vec<Commit<'_>>> {
    let J::Arr(v) = commits else {
        return Err(PyErr::type_(format!("'{}' commitments are not a list", commits.type_name())));
    };
    v.iter().map(|c| Ok(Commit { index: c.at("index")?, d: c.at("D")?, e: c.at("E")? })).collect()
}

/// `int.to_bytes(4, "big")` for an index (bool counts as int; floats have no `to_bytes`).
fn index_bytes(j: &J) -> R<[u8; 4]> {
    let v = match j {
        J::Int(i) => *i,
        J::Bool(b) => *b as i128,
        other => return Err(PyErr::new("AttributeError", format!("'{}' object has no attribute 'to_bytes'", other.type_name()))),
    };
    if !(0..1 << 32).contains(&v) {
        return Err(PyErr::new("OverflowError", "int too big to convert"));
    }
    Ok((v as u32).to_be_bytes())
}

/// `frost.validate_set`: returns the sorted signer indices.
fn validate_set(cs: &[Commit], t: i128, n: i128) -> R<Vec<Num>> {
    let idx: Vec<Num> = cs.iter().map(|c| Num::need(c.index)).collect::<R<_>>()?;
    let mut distinct: Vec<Num> = Vec::new();
    for &i in &idx {
        if !distinct.iter().any(|&d| d.eq(i)) {
            distinct.push(i);
        }
    }
    if (idx.len() as i128) < t || distinct.len() != idx.len() || idx.iter().any(|&i| !(Num::I(1).le(i) && i.le(Num::I(n)))) {
        return Err(PyErr::value("invalid signing set"));
    }
    let mut s = idx;
    s.sort_by(|a, b| a.cmp(*b).unwrap_or(std::cmp::Ordering::Equal));
    Ok(s)
}

fn encode_commitments(cs: &[Commit]) -> R<Vec<u8>> {
    let mut order: Vec<&Commit> = cs.iter().collect();
    order.sort_by(|a, b| {
        let (x, y) = (Num::of(a.index), Num::of(b.index));
        match (x, y) {
            (Some(x), Some(y)) => x.cmp(y).unwrap_or(std::cmp::Ordering::Equal),
            _ => std::cmp::Ordering::Equal,
        }
    });
    let mut out = Vec::new();
    for c in order {
        out.extend_from_slice(&index_bytes(c.index)?);
        out.extend_from_slice(&fromhex_j(c.d)?);
        out.extend_from_slice(&fromhex_j(c.e)?);
    }
    Ok(out)
}

fn binding_factor(group_x: &[u8], msg: &[u8], enc: &[u8], i: &[u8; 4]) -> Scalar {
    let mut d = Vec::with_capacity(group_x.len() + msg.len() + enc.len() + 4);
    d.extend_from_slice(group_x);
    d.extend_from_slice(msg);
    d.extend_from_slice(enc);
    d.extend_from_slice(i);
    ec::reduce32(&ec::tagged_hash(b"SHZ/FROST/rho", &d))
}

/// `frost.partial_sign`.
pub fn partial_sign(share: &Share, d: &Scalar, e: &Scalar, msg: &[u8], commits: &J) -> R<Scalar> {
    let cs = commit_list(commits)?;
    let signers = validate_set(&cs, share.threshold, share.signers)?;
    let i = share.index;
    let mine = cs
        .iter()
        .find(|c| Num::of(c.index).is_some_and(|x| x.eq(Num::I(i))))
        .ok_or_else(|| PyErr::new("StopIteration", ""))?;
    let my_d = hex(&ec::ser(&ec::g_mul(d)));
    let my_e = hex(&ec::ser(&ec::g_mul(e)));
    if !json::is_str(mine.d, &my_d) || !json::is_str(mine.e, &my_e) {
        return Err(PyErr::value("commitment list does not contain my commitments"));
    }
    let gx = &share.group_x;
    let mut r = Point::IDENTITY;
    let mut enc: Option<Vec<u8>> = None;
    for c in &cs {
        let enc_b = match &enc {
            Some(b) => b.clone(),
            None => {
                let b = encode_commitments(&cs)?;
                enc = Some(b.clone());
                b
            }
        };
        let rho = binding_factor(gx, msg, &enc_b, &index_bytes(c.index)?);
        r += ec::deser(&fromhex_j(c.d)?)? + ec::deser(&fromhex_j(c.e)?)? * rho;
    }
    if ec::is_identity(&r) {
        return Err(PyErr::value("degenerate group commitment"));
    }
    let enc = enc.unwrap_or_default();
    let rho = binding_factor(gx, msg, &enc, &index_bytes(&J::Int(i))?);
    let mut k = d + &(rho * e);
    if ec::y_odd(&r) {
        k = -k;
    }
    let c = ec::challenge(&ec::x_bytes(&r), gx, msg);
    let ints: Vec<i128> = signers
        .iter()
        .map(|n| match n {
            Num::I(v) => Ok(*v),
            Num::F(_) => Err(PyErr::new("AttributeError", "'float' object has no attribute 'to_bytes'")),
        })
        .collect::<R<_>>()?;
    Ok(k + ec::lagrange(i, &ints) * share.secret * c)
}
