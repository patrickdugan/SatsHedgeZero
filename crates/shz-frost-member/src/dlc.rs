//! Threshold DLC oracle member (`dlc_oracle.DlcMember`) over `dlc.json`.

use std::path::{Path, PathBuf};

use k256::Scalar;

use crate::ec::{self, Point};
use crate::frost::{Rng, Share};
use crate::json::{self, J, Num, PyErr, R, Style, fromhex_j, hex, py_eq, py_int, py_int_str};
use crate::store::atomic_write;

pub const DIGIT_TAG: &[u8] = b"SatsHedgeZero/DLC/DigitOutcome/v0";
pub const ANN_TAG: &[u8] = b"SHZ/DLC/ANNOUNCEMENT/V1";
pub const UNATTESTABLE_TAG: &[u8] = b"SHZ/DLC/UNATTESTABLE/V1";
pub const LOCK_TAG: &[u8] = b"SHZ/DLC/DECISION-LOCK/V1";
pub const PAD_TAG: &[u8] = b"SHZ/DLC/SHARE-PAD/V1";
pub const UNATTESTABLE_GRACE_US: i128 = 60_000_000;
pub const OUTCOME_WINDOW_US: i128 = 30_000_000;
pub const OUTCOME_RULE: &str = "floor(median_e8 / 1e8) of the first VALID FROST relay packet with slot_us >= maturity";
pub const UNATTESTABLE_RULE: &str = "threshold BIP340 signature over tagged_hash('SHZ/DLC/UNATTESTABLE/V1', event_id) with unattestable_nonce_x when no VALID packet exists in the outcome window; members never sign both this and digits";
pub const DIGIT_MESSAGE_RULE: &str = "shz_dlc::oracle_digit_message(event_id, digit_idx, bit), MSB first (shz_margin::decompose_price_bits)";
pub const UNATTESTABLE: &str = "unattestable";

pub fn decision_quorum(t: i128, n: i128) -> i128 {
    (n + t + 1).div_euclid(2)
}

pub fn price_decision(price: i128) -> R<String> {
    if price < 0 {
        return Err(PyErr::value("price must be a non-negative integer"));
    }
    Ok(format!("price:{price}"))
}

fn le4(n: usize) -> [u8; 4] {
    (n as u32).to_le_bytes()
}

pub fn lock_message(event_id: &str, decision: &str) -> [u8; 32] {
    let e = event_id.as_bytes();
    let mut d = Vec::new();
    d.extend_from_slice(&le4(e.len()));
    d.extend_from_slice(e);
    d.extend_from_slice(decision.as_bytes());
    ec::tagged_hash(LOCK_TAG, &d)
}

fn byte(v: i128) -> R<u8> {
    u8::try_from(v).map_err(|_| PyErr::value("bytes must be in range(0, 256)"))
}

pub fn digit_message(event_id: &str, idx: i128, bit: i128) -> R<[u8; 32]> {
    let e = event_id.as_bytes();
    let mut d = Vec::new();
    d.extend_from_slice(&le4(e.len()));
    d.extend_from_slice(e);
    d.push(byte(idx)?);
    d.push(byte(bit)?);
    Ok(ec::tagged_hash(DIGIT_TAG, &d))
}

pub fn unattestable_message(event_id: &str) -> [u8; 32] {
    ec::tagged_hash(UNATTESTABLE_TAG, event_id.as_bytes())
}

pub fn decompose(price: i128, n: i128) -> Vec<i128> {
    let p = if n >= 127 { price } else { price.min((1i128 << n.max(0)) - 1) };
    (0..n.max(0)).rev().map(|s| if s >= 127 { 0 } else { (p >> s) & 1 }).collect()
}

pub fn announcement_message(core: &J) -> [u8; 32] {
    ec::tagged_hash(ANN_TAG, json::dumps(core, Style::Canonical).as_bytes())
}

/// `dlc_oracle.canonical_core`.
pub fn canonical_core(group: &J, event_id: &J, maturity_unix: &J, num_bits: &J, r_list: &J) -> R<J> {
    let nb = py_int(num_bits)?;
    let J::Arr(r) = r_list else { return Err(PyErr::type_("nonce list is not a list")) };
    if r.len() as i128 != nb + 2 || nb < 0 {
        return Err(PyErr::value("nonce list does not match num_bits"));
    }
    let nb = nb as usize;
    let mut c = J::obj();
    c.set("event_id", event_id.clone());
    c.set("maturity_unix", maturity_unix.clone());
    c.set("num_bits", num_bits.clone());
    c.set("oracle_pubkey_x", group.at("group_pubkey")?.clone());
    c.set("digit_nonces_x", J::Arr(r[..nb].to_vec()));
    c.set("announcement_nonce_x", r[nb].clone());
    c.set("unattestable_nonce_x", r[nb + 1].clone());
    c.set("unattestable_rule", J::s(UNATTESTABLE_RULE));
    c.set("outcome", J::s(OUTCOME_RULE));
    c.set("digit_message", J::s(DIGIT_MESSAGE_RULE));
    c.set("threshold", J::s(format!("{}-of-{}", py_str(group.at("threshold")?), py_str(group.at("signers")?))));
    Ok(c)
}

/// `str(x)` for a JSON scalar.
fn py_str(j: &J) -> String {
    match j {
        J::Str(s) => s.clone(),
        J::Int(i) => i.to_string(),
        J::Bool(b) => if *b { "True".into() } else { "False".into() },
        J::Null => "None".into(),
        J::Float(f) => match json::py_float_repr(*f).as_str() {
            "NaN" => "nan".into(),
            "Infinity" => "inf".into(),
            "-Infinity" => "-inf".into(),
            s => s.into(),
        },
        other => json::dumps(other, Style::Default),
    }
}

fn event_str(event_id: &J) -> R<&str> {
    event_id.as_str().ok_or_else(|| {
        PyErr::new("AttributeError", format!("'{}' object has no attribute 'encode'", event_id.type_name()))
    })
}

/// `_pad`: ECDH pad between this member and `peer` for one share.
fn pad(share: &Share, peer: i128, event_id: &J, dealer: i128, recipient: i128, d: usize) -> R<[u8; 32]> {
    let y_peer = share.verification_share(peer)?;
    let shared = y_peer * share.secret;
    let mut data = Vec::new();
    data.extend_from_slice(&ec::x_bytes(&shared));
    data.extend_from_slice(event_str(event_id)?.as_bytes());
    data.push(byte(dealer)?);
    data.push(byte(recipient)?);
    let d16 = u16::try_from(d).map_err(|_| PyErr::new("OverflowError", "int too big to convert"))?;
    data.extend_from_slice(&d16.to_be_bytes());
    Ok(ec::tagged_hash(PAD_TAG, &data))
}

fn eval_poly(p: &[Scalar], j: i128) -> Scalar {
    p.iter().enumerate().fold(Scalar::ZERO, |acc, (k, a)| acc + a * &ec::pow_small(j, k))
}

fn eval_commitments(commits: &J, j: i128) -> R<Point> {
    let mut acc = Point::IDENTITY;
    for (k, c) in commits.iter_py()?.iter().enumerate() {
        acc += ec::deser(&fromhex_j(c)?)? * ec::pow_small(j, k);
    }
    Ok(acc)
}

fn group_nonce(deals: &J, d: usize) -> R<Point> {
    let mut acc = Point::IDENTITY;
    for (_, dl) in deals.items()? {
        acc += ec::deser(&fromhex_j(dl.at("commitments")?.idx(d)?.idx(0)?)?)?;
    }
    Ok(acc)
}

fn py_index(list: &J, d: i128) -> R<&J> {
    let n = list.len()? as i128;
    let k = if d < 0 { n + d } else { d };
    if k < 0 || k >= n {
        return Err(PyErr::new("IndexError", "list index out of range"));
    }
    list.idx(k as usize)
}

pub struct DlcMember {
    pub path: PathBuf,
    pub s: J,
}

impl DlcMember {
    pub fn open(path: &Path) -> R<DlcMember> {
        let s = if path.exists() {
            let raw = std::fs::read(path).map_err(|e| PyErr::new("OSError", e.to_string()))?;
            json::loads_bytes(&raw)?
        } else {
            json::loads(r#"{"events": {}}"#).unwrap()
        };
        Ok(DlcMember { path: path.to_path_buf(), s })
    }

    fn save(&self) -> R<()> {
        atomic_write(&self.path, ".dlc", json::dumps(&self.s, Style::Default).as_bytes())
    }

    fn lookup(&self, event_id: &J) -> R<Option<&J>> {
        match event_id.as_str() {
            Some(k) => self.s.at("events")?.get(k),
            None => Ok(None),
        }
    }

    /// `_ev`.
    pub fn ev(&self, event_id: &J) -> R<&J> {
        self.lookup(event_id)?.ok_or_else(|| PyErr::value("unknown event"))
    }

    fn ev_mut(&mut self, event_id: &J) -> R<&mut J> {
        let k = event_id.as_str().ok_or_else(|| PyErr::value("unknown event"))?.to_string();
        self.s.at_mut("events")?.at_mut(&k).map_err(|_| PyErr::value("unknown event"))
    }

    pub fn deal(&mut self, share: &Share, rng: &mut dyn Rng, event_id: &J, maturity_unix: i128, num_bits: i128, members: &[i128]) -> R<J> {
        if let Some(ev) = self.lookup(event_id)? {
            if !py_eq(ev.at("maturity_unix")?, &J::Int(maturity_unix)) || !py_eq(ev.at("num_bits")?, &J::Int(num_bits)) {
                return Err(PyErr::value("event redefined"));
            }
            return match ev.get("deal")? {
                Some(d) => Ok(d.clone()),
                None => Err(PyErr::value("event already set up")),
            };
        }
        let n_nonces = num_bits + 2;
        let count = n_nonces.max(0) as usize;
        let t = share.threshold.max(0) as usize;
        let polys: Vec<Vec<Scalar>> = (0..count).map(|_| (0..t).map(|_| rng.scalar()).collect()).collect();
        let commitments = J::Arr(polys.iter().map(|p| J::Arr(p.iter().map(|a| J::s(hex(&ec::ser(&ec::g_mul(a))))).collect())).collect());
        let mut enc = J::obj();
        for &j in members {
            if j == share.index {
                continue;
            }
            let mut row = Vec::with_capacity(count);
            for (d, p) in polys.iter().enumerate() {
                let v = ec::scalar_bytes(&eval_poly(p, j));
                let pd = pad(share, j, event_id, share.index, j, d)?;
                let mut x = [0u8; 32];
                for k in 0..32 {
                    x[k] = v[k] ^ pd[k];
                }
                row.push(J::s(hex(&x)));
            }
            enc.set(&j.to_string(), J::Arr(row));
        }
        let own = J::Arr(polys.iter().map(|p| J::s(ec::scalar_hex(&eval_poly(p, share.index)))).collect());
        let mut deal = J::obj();
        deal.set("dealer", J::Int(share.index));
        deal.set("commitments", commitments);
        deal.set("enc", enc);
        let mut ev = J::obj();
        ev.set("maturity_unix", J::Int(maturity_unix));
        ev.set("num_bits", J::Int(num_bits));
        ev.set("n_nonces", J::Int(n_nonces));
        ev.set("deal", deal.clone());
        ev.set("own", own);
        let key = event_str(event_id)?.to_string();
        self.s.at_mut("events")?.set(&key, ev);
        self.save()?;
        Ok(deal)
    }

    pub fn receive(&mut self, share: &Share, event_id: &J, deals: &J) -> R<J> {
        let i = share.index;
        let t = share.threshold;
        let ev = self.ev(event_id)?;
        if ev.contains_key("nonce_shares") {
            return Ok(ev.at("R")?.clone());
        }
        let J::Obj(_) = deals else { return Err(PyErr::type_("deals must be a dict")) };
        if !deals.contains_key(&i.to_string()) || (deals.len()? as i128) < t {
            return Err(PyErr::value("qualified dealer set must include me and have at least t members"));
        }
        let n_nonces = match ev.get("n_nonces")? {
            Some(n) => py_int(n)?,
            None => py_int(ev.at("num_bits")?)? + 1,
        };
        if !py_eq(deals.at(&i.to_string())?.at("commitments")?, ev.at("deal")?.at("commitments")?) {
            return Err(PyErr::value("my own commitments were altered"));
        }
        let count = n_nonces.max(0) as usize;
        let mut shares = vec![Scalar::ZERO; count];
        for (dealer, dl) in deals.items()? {
            let di = py_int_str(dealer)?;
            let commits = dl.at("commitments")?;
            let mut malformed = commits.len()? as i128 != n_nonces;
            if !malformed {
                for c in commits.iter_py()? {
                    if c.len()? as i128 != t {
                        malformed = true;
                        break;
                    }
                }
            }
            if malformed {
                return Err(PyErr::value(format!("malformed deal from {di}")));
            }
            for (d, acc) in shares.iter_mut().enumerate() {
                let sh = if di == i {
                    ec::scalar_from_py_hex(ev.at("own")?.idx(d)?.str_or("int() argument")?)?
                } else {
                    let enc = dl.at("enc")?.at(&i.to_string())?.idx(d)?;
                    let text = enc.as_str().ok_or_else(|| PyErr::type_("int() can't convert non-string with explicit base"))?;
                    let pd = pad(share, di, event_id, di, i, d)?;
                    ec::xor_pad_from_py_hex(text, &pd)?
                };
                if ec::g_mul(&sh) != eval_commitments(commits.idx(d)?, i)? {
                    return Err(PyErr::value(format!("share from dealer {di} fails its commitments (nonce {d})")));
                }
                *acc += sh;
            }
        }
        let mut r_x = Vec::with_capacity(count);
        let mut negate = Vec::with_capacity(count);
        for (d, sh) in shares.iter_mut().enumerate() {
            let r = group_nonce(deals, d)?;
            if ec::is_identity(&r) {
                return Err(PyErr::type_("'NoneType' object is not subscriptable"));
            }
            let odd = ec::y_odd(&r);
            negate.push(J::Bool(odd));
            if odd {
                *sh = -*sh;
            }
            r_x.push(J::s(hex(&ec::x_bytes(&r))));
        }
        let mut qualified: Vec<i128> = deals.items()?.iter().map(|(k, _)| py_int_str(k)).collect::<R<_>>()?;
        qualified.sort();
        let r_list = J::Arr(r_x);
        let ev = self.ev_mut(event_id)?;
        ev.set("nonce_shares", J::Arr(shares.iter().map(|s| J::s(ec::scalar_hex(s))).collect()));
        ev.set("R", r_list.clone());
        ev.set("negate", J::Arr(negate));
        ev.set("qualified", J::Arr(qualified.into_iter().map(J::Int).collect()));
        ev.set("signed", J::obj());
        ev.pop("deal");
        ev.pop("own");
        self.save()?;
        Ok(r_list)
    }

    /// `_partial`: locks nonce `d` to `msg` in memory (callers persist) and returns z_j.
    pub fn partial(&mut self, share: &Share, event_id: &J, d: i128, msg: &[u8], signers: &[i128]) -> R<Scalar> {
        let i = share.index;
        let ev = self.ev_mut(event_id)?;
        let qualified: Vec<J> = ev.at("qualified")?.iter_py()?;
        let in_q = |s: i128| qualified.iter().any(|q| py_eq(q, &J::Int(s)));
        if !signers.contains(&i) || (signers.len() as i128) < share.threshold || !signers.iter().all(|&s| in_q(s)) {
            return Err(PyErr::value("invalid signing set"));
        }
        let key = d.to_string();
        let mh = hex(msg);
        if let Some(prev) = ev.at("signed")?.get(&key)? {
            if !json::is_str(prev, &mh) && !matches!(prev, J::Null) {
                return Err(PyErr::value(format!("nonce {d} already signed a different message")));
            }
        }
        ev.at_mut("signed")?.set(&key, J::s(mh));
        let r_x = fromhex_j(py_index(ev.at("R")?, d)?)?;
        let c = ec::challenge(&r_x, &share.group_x, msg);
        let k = ec::scalar_from_py_hex(py_index(ev.at("nonce_shares")?, d)?.str_or("int() argument")?)?;
        Ok(ec::lagrange(i, signers) * (k + c * share.secret))
    }

    pub fn sign_announcement(&mut self, share: &Share, event_id: &J, core: &J, signers: &[i128]) -> R<String> {
        let ev = self.ev(event_id)?;
        let nb_j = ev.at("num_bits")?.clone();
        let canon = canonical_core(&share.group, event_id, ev.at("maturity_unix")?, &nb_j, ev.at("R")?)?;
        let msg = announcement_message(&canon);
        if !matches!(core, J::Obj(_)) || announcement_message(core) != msg {
            return Err(PyErr::value("announcement is not the canonical core of my nonce setup"));
        }
        let z = self.partial(share, event_id, py_int(&nb_j)?, &msg, signers)?;
        self.save()?;
        Ok(ec::scalar_hex(&z))
    }

    fn signed_keys(ev: &J) -> R<Vec<(i128, J)>> {
        ev.at("signed")?.items()?.iter().map(|(k, v)| Ok((py_int_str(k)?, v.clone()))).collect()
    }

    fn maturity_us(ev: &J) -> R<i128> {
        Ok(py_int(ev.at("maturity_unix")?)? * 1_000_000)
    }

    pub fn lock_decision(&mut self, share: &Share, rng: &mut dyn Rng, event_id: &J, decision: &str, now_us: Option<i128>) -> R<String> {
        let ev = self.ev(event_id)?;
        if !ev.contains_key("nonce_shares") {
            return Err(PyErr::value("event nonce setup is not complete"));
        }
        let nb = py_int(ev.at("num_bits")?)?;
        if let Some(prev) = ev.get("decision")? {
            if !matches!(prev, J::Null) && !json::is_str(prev, decision) {
                return Err(PyErr::value(format!("event is already locked to {}", py_str(prev))));
            }
        }
        let signed = Self::signed_keys(ev)?;
        if decision == UNATTESTABLE {
            if ev.at("R")?.len()? as i128 <= nb + 1 {
                return Err(PyErr::value("event was announced without an unattestable nonce"));
            }
            match now_us {
                Some(now) if now >= Self::maturity_us(ev)? + OUTCOME_WINDOW_US + UNATTESTABLE_GRACE_US => {}
                _ => return Err(PyErr::value("outcome window plus grace has not passed")),
            }
            if signed.iter().any(|(d, _)| *d < nb) {
                return Err(PyErr::value("already attested"));
            }
        } else {
            let price = match decision.strip_prefix("price:") {
                None => return Err(PyErr::value("unknown decision")),
                Some(rest) => py_int_str(rest)?,
            };
            if price_decision(price)? != decision {
                return Err(PyErr::value("unknown decision"));
            }
            let unatt = ev.get("unattestable")?.is_some_and(|v| v.truthy());
            if unatt || ev.at("signed")?.contains_key(&(nb + 1).to_string()) {
                return Err(PyErr::value("event declared unattestable"));
            }
            let bits = J::Arr(decompose(price, nb).into_iter().map(J::Int).collect());
            for (d, m) in &signed {
                if *d < nb {
                    let bit = py_int(py_index(&bits, *d)?)?;
                    if !json::is_str(m, &hex(&digit_message(event_str(event_id)?, *d, bit)?)) {
                        return Err(PyErr::value("a digit nonce already signed a different outcome"));
                    }
                }
            }
        }
        self.ev_mut(event_id)?.set("decision", J::s(decision));
        self.save()?;
        let sig = ec::bip340_sign(&lock_message(event_str(event_id)?, decision), &share.secret, &rng.bytes32())?;
        Ok(hex(&sig))
    }

    fn require_quorum(&self, share: &Share, event_id: &J, decision: &str, locks: &J) -> R<()> {
        let ev = self.ev(event_id)?;
        if !ev.get("decision")?.is_some_and(|d| json::is_str(d, decision)) {
            return Err(PyErr::value("this member has not locked that decision"));
        }
        let q = decision_quorum(share.threshold, share.signers);
        let got = verified_lockers(share, event_str(event_id)?, decision, locks)?;
        if (got.len() as i128) < q {
            return Err(PyErr::value(format!("decision is locked by {} members, quorum is {q}", got.len())));
        }
        Ok(())
    }

    pub fn sign_unattestable(&mut self, share: &Share, event_id: &J, now_us: i128, signers: &[i128], locks: &J) -> R<String> {
        let ev = self.ev(event_id)?;
        let nb = py_int(ev.at("num_bits")?)?;
        if ev.at("R")?.len()? as i128 <= nb + 1 {
            return Err(PyErr::value("event was announced without an unattestable nonce"));
        }
        if now_us < Self::maturity_us(ev)? + OUTCOME_WINDOW_US + UNATTESTABLE_GRACE_US {
            return Err(PyErr::value("outcome window plus grace has not passed"));
        }
        if Self::signed_keys(ev)?.iter().any(|(d, _)| *d < nb) {
            return Err(PyErr::value("already attested"));
        }
        self.require_quorum(share, event_id, UNATTESTABLE, locks)?;
        let z = self.partial(share, event_id, nb + 1, &unattestable_message(event_str(event_id)?), signers)?;
        self.save()?;
        Ok(ec::scalar_hex(&z))
    }

    pub fn sign_outcome(&mut self, share: &Share, event_id: &J, price: i128, signers: &[i128], locks: &J) -> R<Vec<String>> {
        let ev = self.ev(event_id)?;
        let nb = py_int(ev.at("num_bits")?)?;
        let unatt = ev.get("unattestable")?.is_some_and(|v| v.truthy());
        if unatt || ev.at("signed")?.contains_key(&(nb + 1).to_string()) {
            return Err(PyErr::value("event declared unattestable"));
        }
        self.require_quorum(share, event_id, &price_decision(price)?, locks)?;
        let bits = decompose(price, nb);
        let mut zs = Vec::new();
        for d in 0..nb.max(0) {
            let msg = digit_message(event_str(event_id)?, d, bits[d as usize])?;
            zs.push(ec::scalar_hex(&self.partial(share, event_id, d, &msg, signers)?));
        }
        self.save()?;
        Ok(zs)
    }
}

/// `verified_lockers`: members whose lock signature covers this decision.
pub fn verified_lockers(share: &Share, event_id: &str, decision: &str, locks: &J) -> R<Vec<i128>> {
    let msg = lock_message(event_id, decision);
    let mut ok: Vec<i128> = Vec::new();
    if !locks.truthy() {
        return Ok(ok);
    }
    let vs = share.group.at("verification_shares")?;
    for (j, sig) in locks.items()? {
        let ji = py_int_str(j)?;
        let Some(y) = vs.get(&ji.to_string())? else { continue };
        let (Ok(yb), Ok(sb)) = (fromhex_j(y), fromhex_j(sig)) else { continue };
        if yb.is_empty() {
            continue;
        }
        if ec::bip340_verify(&msg, &yb[1..], &sb) && !ok.contains(&ji) {
            ok.push(ji);
        }
    }
    Ok(ok)
}

/// `Num` helper for event maturity windows in the member.
pub fn in_window(maturity_us: i128, s: Num) -> bool {
    Num::I(maturity_us).le(s) && s.lt(Num::I(maturity_us + OUTCOME_WINDOW_US))
}
