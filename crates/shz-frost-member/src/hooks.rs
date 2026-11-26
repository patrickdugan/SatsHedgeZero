//! Test hooks (cargo feature `test-hooks`, never in a deployed build): the Python suites drive
//! member internals that have no HTTP endpoint (`Member._check_content`, `DlcMember.sign_outcome`,
//! the `StaticView`, monkeypatched `partial_sign` / `Member.sign`) through `/test/*` routes and
//! callbacks to the harness.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use k256::Scalar;

use crate::ec;
use crate::json::{self, J, PyErr, R, py_int};
use crate::member::{Member, obj};
use crate::view::View;

#[derive(Default)]
pub struct Hooks {
    pub url: Mutex<Option<String>>,
    pub sign: AtomicBool,
    pub partial: AtomicBool,
}

fn call(url: &str, what: &str, body: &J) -> R<J> {
    let (code, raw) = crate::net::post(&format!("{url}/{what}"), json::dumps(body, json::Style::Default).as_bytes(), Duration::from_secs(30))
        .map_err(|e| PyErr::new("RuntimeError", format!("test hook callback failed: {e}")))?;
    if code != 200 {
        return Err(PyErr::new("RuntimeError", format!("test hook callback returned {code}")));
    }
    json::loads_bytes(&raw)
}

fn err_from(text: &str) -> PyErr {
    let (kind, msg) = text.split_once(": ").unwrap_or(("ValueError", text));
    let kind: &'static str = match kind {
        "KeyError" => "KeyError",
        "TypeError" => "TypeError",
        "RuntimeError" => "RuntimeError",
        _ => "ValueError",
    };
    PyErr::new(kind, msg)
}

impl Hooks {
    fn url(&self) -> Option<String> {
        self.url.lock().unwrap().clone()
    }

    pub fn sign_override(&self, index: i128, req: &J) -> Option<R<J>> {
        if !self.sign.load(Ordering::SeqCst) {
            return None;
        }
        let url = self.url()?;
        Some(call(&url, "sign", &obj(vec![("index", J::Int(index)), ("req", req.clone())])).and_then(|r| match r.get("error") {
            Ok(Some(J::Str(e))) => Err(err_from(e)),
            _ => Ok(r.at("result")?.clone()),
        }))
    }

    pub fn partial_override(&self, index: i128, d: &Scalar, e: &Scalar, msg: &[u8], commits: &J, z: Scalar) -> R<Scalar> {
        if !self.partial.load(Ordering::SeqCst) {
            return Ok(z);
        }
        let Some(url) = self.url() else { return Ok(z) };
        let r = call(
            &url,
            "partial",
            &obj(vec![
                ("index", J::Int(index)),
                ("d", J::s(ec::scalar_hex(d))),
                ("e", J::s(ec::scalar_hex(e))),
                ("msg", J::s(json::hex(msg))),
                ("commits", commits.clone()),
                ("z", J::s(ec::scalar_hex(&z))),
            ]),
        )?;
        ec::scalar_from_py_hex(r.at("z")?.str_or("z")?)
    }
}

fn ok(result: J) -> R<Option<J>> {
    Ok(Some(obj(vec![("result", result)])))
}

fn ints(j: &J) -> R<Vec<i128>> {
    j.iter_py()?.iter().map(py_int).collect()
}

pub fn route(m: &Member, path: &str, req: &J) -> R<Option<J>> {
    let share = &m.share;
    match path {
        "/test/view" => {
            let View::Static(v) = &m.view else { return Err(PyErr::value("member has no static view")) };
            let mut v = v.lock().unwrap();
            v.median_e8 = req.get_or_null("median_e8")?.strict_int();
            v.at_us = req.get_or_null("at_us")?.strict_int();
            ok(J::Null)
        }
        "/test/observe" => {
            m.observe(req.at("packet")?)?;
            ok(J::Null)
        }
        "/test/check-content" => {
            m.check_content(req.at("body")?)?;
            ok(J::Null)
        }
        "/test/stats" => ok(obj(vec![
            ("content_refusals", J::Int(m.content_refusals.load(Ordering::SeqCst) as i128)),
            ("signed", J::Int(m.signed.load(Ordering::SeqCst) as i128)),
        ])),
        "/test/state" => ok(m.state.lock().unwrap().s.clone()),
        "/test/hooks" => {
            if let Some(b) = req.get("sign")? {
                m.hooks.sign.store(b.truthy(), Ordering::SeqCst);
            }
            if let Some(b) = req.get("partial")? {
                m.hooks.partial.store(b.truthy(), Ordering::SeqCst);
            }
            if let Some(J::Str(u)) = req.get("url")? {
                *m.hooks.url.lock().unwrap() = Some(u.clone());
            }
            ok(J::Null)
        }
        "/test/dlc/state" => ok(m.dlc.lock().unwrap().s.clone()),
        "/test/dlc/deal" => {
            let mut rng = m.rng.lock().unwrap();
            let r = m.dlc.lock().unwrap().deal(share, rng.as_mut(), req.at("event_id")?, py_int(req.at("maturity_unix")?)?, py_int(req.at("num_bits")?)?, &ints(req.at("members")?)?)?;
            ok(r)
        }
        "/test/dlc/receive" => ok(m.dlc.lock().unwrap().receive(share, req.at("event_id")?, req.at("deals")?)?),
        "/test/dlc/sign-announcement" => {
            ok(J::s(m.dlc.lock().unwrap().sign_announcement(share, req.at("event_id")?, req.at("core")?, &ints(req.at("signers")?)?)?))
        }
        "/test/dlc/lock-decision" => {
            let now = match req.get_or_null("now_us")? {
                J::Null => None,
                n => Some(py_int(&n)?),
            };
            let decision = req.at("decision")?.str_or("decision")?.to_string();
            let mut rng = m.rng.lock().unwrap();
            ok(J::s(m.dlc.lock().unwrap().lock_decision(share, rng.as_mut(), req.at("event_id")?, &decision, now)?))
        }
        "/test/dlc/sign-outcome" => {
            let zs = m.dlc.lock().unwrap().sign_outcome(share, req.at("event_id")?, py_int(req.at("price_usd")?)?, &ints(req.at("signers")?)?, &req.get_or_null("locks")?)?;
            ok(J::Arr(zs.into_iter().map(J::Str).collect()))
        }
        "/test/dlc/sign-unattestable" => {
            let z = m.dlc.lock().unwrap().sign_unattestable(share, req.at("event_id")?, py_int(req.at("now_us")?)?, &ints(req.at("signers")?)?, &req.get_or_null("locks")?)?;
            ok(J::s(z))
        }
        "/test/dlc/partial" => {
            let msg = json::fromhex_j(req.at("msg")?)?;
            let z = m.dlc.lock().unwrap().partial(share, req.at("event_id")?, py_int(req.at("d")?)?, &msg, &ints(req.at("signers")?)?)?;
            ok(J::s(ec::scalar_hex(&z)))
        }
        _ => Ok(None),
    }
}
