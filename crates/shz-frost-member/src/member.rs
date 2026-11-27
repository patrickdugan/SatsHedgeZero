//! One FROST confederation member (`frost_signer.Member` plus its HTTP handler logic).

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::auth::Verifier;
use crate::dlc::{self, DlcMember};
use crate::ec;
use crate::frost::{self, Rng, Share, SignerState};
use crate::json::{self, J, Num, PyErr, R, fromhex_j, hex, is_str, py_eq, py_int};
use crate::view::View;

pub const SCHEMA: &str = "shz-public-relay/v1";
pub const SIGNING_TAG: &[u8] = b"SHZ/PUBLIC-RELAY-PACKET/V1";
pub const MAX_SLOT_SKEW_US: i128 = 60_000_000;
pub const MAX_SEQ: i128 = 1 << 53;
pub const MAX_SEQ_JUMP: i128 = 1 << 20;
pub const MAX_DEVIATION_BPS: i128 = 50;
pub const VIEW_REFRESH_S: f64 = 15.0;
pub const VIEW_MAX_AGE_S: f64 = 35.0;
pub const MAX_BODY: i128 = 1_000_000;

pub fn packet_message(body: &J) -> [u8; 32] {
    ec::tagged_hash(SIGNING_TAG, json::dumps(body, json::Style::Canonical).as_bytes())
}

/// `public_relay.verify_packet`.
pub fn verify_packet(pkt: &J, pk_hex: &str) -> R<bool> {
    let msg = packet_message(pkt.at("body")?);
    if !is_str(pkt.at("digest")?, &hex(&msg)) {
        return Ok(false);
    }
    let pk = json::py_fromhex(pk_hex)?;
    let sig = fromhex_j(pkt.at("signature")?)?;
    Ok(ec::bip340_verify(&msg, &pk, &sig))
}

pub type Clock = Box<dyn Fn() -> i128 + Send + Sync>;

pub struct Member {
    pub share: Share,
    pub view: View,
    pub max_deviation_bps: i128,
    pub view_max_age_us: i128,
    pub state: Mutex<SignerState>,
    pub dlc: Mutex<DlcMember>,
    /// Slots of group-signed VALID packets seen, in insertion order (Python dict keys).
    seen_valid: Mutex<Vec<Num>>,
    pub rng: Arc<Mutex<Box<dyn Rng>>>,
    pub clock: Clock,
    pub signed: AtomicU64,
    pub refused: AtomicU64,
    pub auth_refused: AtomicU64,
    pub content_refusals: AtomicU64,
    pub verifier: Option<Verifier>,
    #[cfg(feature = "test-hooks")]
    pub hooks: crate::hooks::Hooks,
}

fn int_list(j: &J) -> R<Vec<i128>> {
    j.iter_py()?.iter().map(py_int).collect()
}

impl Member {
    #[allow(clippy::too_many_arguments)]
    pub fn new(share: Share, state_dir: &Path, dlc_path: Option<&Path>, view: View, max_deviation_bps: i128, view_max_age_s: f64, rng: Arc<Mutex<Box<dyn Rng>>>, clock: Clock) -> R<Member> {
        std::fs::create_dir_all(state_dir).map_err(|e| PyErr::new("OSError", e.to_string()))?;
        let state = SignerState::open(&state_dir.join("nonces.json"))?;
        let dlc_file = dlc_path.map(Path::to_path_buf).unwrap_or_else(|| state_dir.join("dlc.json"));
        let dlc = DlcMember::open(&dlc_file)?;
        Ok(Member {
            share,
            view,
            max_deviation_bps,
            view_max_age_us: (view_max_age_s * 1_000_000.0) as i128,
            state: Mutex::new(state),
            dlc: Mutex::new(dlc),
            seen_valid: Mutex::new(Vec::new()),
            rng,
            clock,
            signed: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            auth_refused: AtomicU64::new(0),
            content_refusals: AtomicU64::new(0),
            verifier: None,
            #[cfg(feature = "test-hooks")]
            hooks: Default::default(),
        })
    }

    pub fn index(&self) -> i128 {
        self.share.index
    }

    fn now(&self) -> i128 {
        (self.clock)()
    }

    /// `_observe`: remember a group-signed VALID packet's slot.
    pub fn observe(&self, pkt: &J) -> R<()> {
        let body = pkt.at("body")?;
        if body.get("status")?.is_some_and(|s| is_str(s, "VALID")) {
            let slot_j = body.at("slot_us")?;
            let slot = Num::of(slot_j).ok_or_else(|| PyErr::type_(format!("unhashable type: '{}'", slot_j.type_name())))?;
            let mut seen = self.seen_valid.lock().unwrap();
            if !seen.iter().any(|s| s.eq(slot)) {
                seen.push(slot);
            }
            if seen.len() > 2_000 {
                // dict.pop(min(dict)): Python's min keeps the first item no later item is below.
                let mut m = 0;
                for k in 1..seen.len() {
                    if seen[k].lt(seen[m]) {
                        m = k;
                    }
                }
                seen.remove(m);
            }
        }
        Ok(())
    }

    fn any_seen(&self, f: impl Fn(Num) -> bool) -> bool {
        self.seen_valid.lock().unwrap().iter().any(|&s| f(s))
    }

    fn maturity_us(&self, event_id: &J) -> R<i128> {
        let dlc = self.dlc.lock().unwrap();
        Ok(py_int(dlc.ev(event_id)?.at("maturity_unix")?)? * 1_000_000)
    }

    fn window_clear(&self, event_id: &J) -> R<()> {
        let m = self.maturity_us(event_id)?;
        if self.any_seen(|s| dlc::in_window(m, s)) {
            return Err(PyErr::value("a VALID packet in the outcome window exists"));
        }
        Ok(())
    }

    pub fn dlc_lock_unattestable(&self, req: &J) -> R<J> {
        let event_id = req.at("event_id")?;
        self.window_clear(event_id)?;
        let now = self.now();
        let lock = {
            let mut rng = self.rng.lock().unwrap();
            self.dlc.lock().unwrap().lock_decision(&self.share, rng.as_mut(), event_id, dlc::UNATTESTABLE, Some(now))?
        };
        Ok(obj(vec![("index", J::Int(self.index())), ("lock", J::s(lock))]))
    }

    pub fn dlc_unattestable(&self, req: &J) -> R<J> {
        let event_id = req.at("event_id")?;
        let signers = int_list(req.at("signers")?)?;
        self.window_clear(event_id)?;
        let now = self.now();
        let locks = req.get_or_null("locks")?;
        let z = self.dlc.lock().unwrap().sign_unattestable(&self.share, event_id, now, &signers, &locks)?;
        Ok(obj(vec![("index", J::Int(self.index())), ("z", J::s(z))]))
    }

    fn outcome_price(&self, event_id: &J, pkt: &J) -> R<i128> {
        if !verify_packet(pkt, &self.share.group_pubkey)? {
            return Err(PyErr::value("outcome packet is not group-signed"));
        }
        let b = pkt.at("body")?;
        let maturity = self.maturity_us(event_id)?;
        let slot = b.get_or_null("slot_us")?;
        let median = b.get_or_null("median_e8")?;
        let status_valid = b.get("status")?.is_some_and(|s| is_str(s, "VALID"));
        let slot_i = slot.strict_int();
        if !status_valid || slot_i.is_none() || !dlc::in_window(maturity, Num::I(slot_i.unwrap())) {
            return Err(PyErr::value("outcome packet is not a VALID packet in the maturity window"));
        }
        let slot_i = slot_i.unwrap();
        let med = match median.strict_int() {
            Some(m) if m > 0 => m,
            _ => return Err(PyErr::value("outcome packet has no positive integer median")),
        };
        if self.any_seen(|s| Num::I(maturity).le(s) && s.lt(Num::I(slot_i))) {
            return Err(PyErr::value("an earlier VALID packet at or after maturity exists"));
        }
        self.observe(pkt)?;
        Ok(med.div_euclid(100_000_000))
    }

    pub fn dlc_lock_outcome(&self, req: &J) -> R<J> {
        let event_id = req.at("event_id")?;
        let price = self.outcome_price(event_id, req.at("packet")?)?;
        let lock = {
            let mut rng = self.rng.lock().unwrap();
            self.dlc.lock().unwrap().lock_decision(&self.share, rng.as_mut(), event_id, &dlc::price_decision(price)?, None)?
        };
        Ok(obj(vec![("index", J::Int(self.index())), ("price_usd", J::Int(price)), ("lock", J::s(lock))]))
    }

    pub fn dlc_attest(&self, req: &J) -> R<J> {
        let event_id = req.at("event_id")?;
        let signers = int_list(req.at("signers")?)?;
        let price = self.outcome_price(event_id, req.at("packet")?)?;
        let locks = req.get_or_null("locks")?;
        let zs = self.dlc.lock().unwrap().sign_outcome(&self.share, event_id, price, &signers, &locks)?;
        Ok(obj(vec![("index", J::Int(self.index())), ("price_usd", J::Int(price)), ("z", J::Arr(zs.into_iter().map(J::Str).collect()))]))
    }

    /// `_check_content`.
    pub fn check_content(&self, body: &J) -> R<()> {
        let status = body.get_or_null("status")?;
        if !is_str(&body.get_or_null("market")?, "BTC/USD") || !(is_str(&status, "VALID") || is_str(&status, "HOLD")) {
            return Err(PyErr::value("unknown market or status"));
        }
        if !is_str(&status, "VALID") {
            return Ok(());
        }
        let median = match body.get_or_null("median_e8")?.strict_int() {
            Some(m) if m > 0 => m,
            _ => return Err(PyErr::value("VALID body has no positive integer median")),
        };
        if let View::NoCheck = self.view {
            return Ok(());
        }
        let now = self.now();
        let res = (|| {
            let reading = self.view.get(now);
            let (at, r) = match reading {
                Some(rd) if rd.median_e8.is_some() => (rd.at_us, rd.median_e8.unwrap()),
                _ => return Err(PyErr::value("no usable independent price reading")),
            };
            if now - at > self.view_max_age_us {
                return Err(PyErr::value("independent price reading is stale"));
            }
            let dev = ((median - r).abs() * 10_000).div_euclid(r);
            if dev > self.max_deviation_bps {
                return Err(PyErr::value(format!("median is {dev} bps from this member's own reading (limit {})", self.max_deviation_bps)));
            }
            Ok(())
        })();
        if res.is_err() {
            self.content_refusals.fetch_add(1, Ordering::SeqCst);
        }
        res
    }

    pub fn view_status(&self) -> J {
        if let View::NoCheck = self.view {
            return obj(vec![("check", J::s("disabled"))]);
        }
        let now = self.now();
        match self.view.get(now) {
            None => obj(vec![("check", J::s("enabled")), ("reading", J::Null)]),
            Some(r) => {
                let age = (now - r.at_us) as f64 / 1e6;
                let age = format!("{age:.3}").parse::<f64>().unwrap_or(age);
                obj(vec![
                    ("check", J::s("enabled")),
                    ("status", J::s(r.status)),
                    ("fast_sources_used", J::Int(r.fast_sources_used as i128)),
                    ("median_e8", r.median_e8.map(J::Int).unwrap_or(J::Null)),
                    ("age_s", J::Float(age)),
                    ("max_deviation_bps", J::Int(self.max_deviation_bps)),
                    ("content_refusals", J::Int(self.content_refusals.load(Ordering::SeqCst) as i128)),
                ])
            }
        }
    }

    pub fn commit(&self, seq: i128) -> R<J> {
        if !(0 < seq && seq < MAX_SEQ) {
            return Err(PyErr::value("sequence out of range"));
        }
        let (d, e) = {
            let mut st = self.state.lock().unwrap();
            let mut rng = self.rng.lock().unwrap();
            st.commit(seq, rng.as_mut())?
        };
        Ok(obj(vec![
            ("index", J::Int(self.index())),
            ("D", J::s(hex(&ec::ser(&ec::g_mul(&d))))),
            ("E", J::s(hex(&ec::ser(&ec::g_mul(&e))))),
        ]))
    }

    pub fn sign(&self, req: &J) -> R<J> {
        #[cfg(feature = "test-hooks")]
        if let Some(r) = self.hooks.sign_override(self.index(), req) {
            return r;
        }
        let body = req.at("body")?;
        let seq = py_int(req.at("seq")?)?;
        let commits = req.at("commitments")?;
        if !is_str(&body.get_or_null("schema")?, SCHEMA) || !py_eq(&body.get_or_null("seq")?, &J::Int(seq)) {
            return Err(PyErr::value("body does not match the requested sequence"));
        }
        let now = self.now();
        let slot = match body.get_or_null("slot_us")?.strict_int() {
            Some(s) if (now - s).abs() <= MAX_SLOT_SKEW_US => s,
            _ => return Err(PyErr::value("slot time not recent")),
        };
        let parent = req.get_or_null("parent")?;
        let parent_seq = if let J::Null = parent {
            let last = self.state.lock().unwrap().last_seq()?;
            if !is_str(&body.get_or_null("previous")?, &"00".repeat(32)) || !last.eq(Num::I(0)) {
                return Err(PyErr::value("missing parent packet"));
            }
            Num::I(0)
        } else {
            if !verify_packet(&parent, &self.share.group_pubkey)? {
                return Err(PyErr::value("parent packet is not group-signed"));
            }
            let pb = parent.at("body")?;
            let parent_seq = Num::need(pb.at("seq")?)?;
            if !parent_seq.lt(Num::I(seq)) && cmp_defined(parent_seq, Num::I(seq)) || !py_eq(&body.get_or_null("previous")?, parent.at("digest")?) {
                return Err(PyErr::value("body does not extend the parent packet"));
            }
            let ps = Num::need(pb.at("slot_us")?)?;
            if cmp_defined(ps, Num::I(slot)) && !ps.lt(Num::I(slot)) {
                return Err(PyErr::value("slot does not advance past the parent packet"));
            }
            self.observe(&parent)?;
            parent_seq
        };
        let jump = Num::I(seq).sub(parent_seq);
        if seq >= MAX_SEQ || Num::I(MAX_SEQ_JUMP).lt(jump) {
            return Err(PyErr::value("sequence jumps too far past the parent packet"));
        }
        self.check_content(body)?;
        let msg = packet_message(body);
        let mut st = self.state.lock().unwrap();
        if Num::I(slot).le(st.last_slot()?) {
            return Err(PyErr::value("slot already signed or older"));
        }
        let (d, e) = st.take(seq, &msg, slot)?;
        let z = frost::partial_sign(&self.share, &d, &e, &msg, commits)?;
        #[cfg(feature = "test-hooks")]
        let z = self.hooks.partial_override(self.index(), &d, &e, &msg, commits, z)?;
        self.signed.fetch_add(1, Ordering::SeqCst);
        Ok(obj(vec![("index", J::Int(self.index())), ("z", J::s(ec::scalar_hex(&z)))]))
    }

    pub fn healthz(&self) -> R<J> {
        let last_seq = self.state.lock().unwrap().s.at("last_seq")?.clone();
        Ok(obj(vec![
            ("index", J::Int(self.index())),
            ("last_seq", last_seq),
            ("signed", J::Int(self.signed.load(Ordering::SeqCst) as i128)),
            ("refused", J::Int(self.refused.load(Ordering::SeqCst) as i128)),
            ("group_pubkey", J::s(self.share.group_pubkey.clone())),
            ("price_view", self.view_status()),
            ("coord_auth", J::Bool(self.verifier.is_some())),
            ("auth_refused", J::Int(self.auth_refused.load(Ordering::SeqCst) as i128)),
        ]))
    }

    /// `do_POST` after the body was read: auth, JSON, dispatch. Returns (status, response).
    pub fn post(&self, path: &str, raw: &[u8], auth_header: Option<&str>, content_length_err: Option<PyErr>) -> (u16, J) {
        let auth = match content_length_err {
            Some(e) => Err(e.msg),
            None => match &self.verifier {
                Some(v) => v.check(path, raw, auth_header, self.now()),
                None => Ok(()),
            },
        };
        if let Err(e) = auth {
            self.auth_refused.fetch_add(1, Ordering::SeqCst);
            return (401, obj(vec![("error", J::s(format!("unauthorized: {e}")))]));
        }
        match json::loads_bytes(raw).and_then(|req| self.route(path, &req)) {
            Ok(Some(r)) => (200, r),
            Ok(None) => (404, obj(vec![("error", J::s("not found"))])),
            Err(e) => {
                self.refused.fetch_add(1, Ordering::SeqCst);
                (409, obj(vec![("error", J::s(e.to_string()))]))
            }
        }
    }

    fn route(&self, path: &str, req: &J) -> R<Option<J>> {
        let i = J::Int(self.index());
        Ok(Some(match path {
            "/commit" => self.commit(py_int(req.at("seq")?)?)?,
            "/sign" => self.sign(req)?,
            "/dlc/deal" => {
                let event_id = req.at("event_id")?;
                let maturity = py_int(req.at("maturity_unix")?)?;
                let nb = py_int(req.at("num_bits")?)?;
                let members = int_list(req.at("members")?)?;
                let mut rng = self.rng.lock().unwrap();
                self.dlc.lock().unwrap().deal(&self.share, rng.as_mut(), event_id, maturity, nb, &members)?
            }
            "/dlc/receive" => {
                let r = self.dlc.lock().unwrap().receive(&self.share, req.at("event_id")?, req.at("deals")?)?;
                obj(vec![("index", i), ("R", r)])
            }
            "/dlc/sign-announcement" => {
                let (event_id, core) = (req.at("event_id")?, req.at("core")?);
                let signers = int_list(req.at("signers")?)?;
                let z = self.dlc.lock().unwrap().sign_announcement(&self.share, event_id, core, &signers)?;
                obj(vec![("index", i), ("z", J::s(z))])
            }
            "/dlc/lock-outcome" => self.dlc_lock_outcome(req)?,
            "/dlc/lock-unattestable" => self.dlc_lock_unattestable(req)?,
            "/dlc/sign-outcome" => self.dlc_attest(req)?,
            "/dlc/sign-unattestable" => self.dlc_unattestable(req)?,
            #[cfg(feature = "test-hooks")]
            p if p.starts_with("/test/") => return crate::hooks::route(self, p, req),
            _ => return Ok(None),
        }))
    }
}

/// True when Python's comparison is defined (neither side NaN): `a >= b` is then `!(a < b)`.
fn cmp_defined(a: Num, b: Num) -> bool {
    a.cmp(b).is_some()
}

pub fn obj(items: Vec<(&str, J)>) -> J {
    let mut o = J::obj();
    for (k, v) in items {
        o.set(k, v);
    }
    o
}
