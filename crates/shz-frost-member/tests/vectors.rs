//! Byte-identical replay of `tests/vectors.json` (generated from the Python member by
//! `tests/gen_vectors.py`): same requests, same nonce stream, same clock, so every response body
//! and every state file must match the Python member's bytes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use k256::Scalar;
use sha2::{Digest, Sha256};
use shz_frost_member::auth::{self, Verifier};
use shz_frost_member::ec;
use shz_frost_member::frost::{Rng, Share};
use shz_frost_member::json::{self, J, Style};
use shz_frost_member::member::Member;
use shz_frost_member::view::{StaticView, View};

const N_MINUS_1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf,
    0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
];

/// `gen_vectors.Stream`: scalar_k = int(sha256(tag | k)) % (N - 1) + 1, aux_k = sha256(tag | k).
struct Stream {
    k: u32,
    a: u32,
}

/// x mod (N - 1) for a 256-bit x: x < 2^256 < 2 (N - 1), so one conditional subtraction.
fn mod_n_minus_1(x: [u8; 32]) -> [u8; 32] {
    if x < N_MINUS_1 {
        return x;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for k in (0..32).rev() {
        let mut v = x[k] as i16 - N_MINUS_1[k] as i16 - borrow;
        borrow = 0;
        if v < 0 {
            v += 256;
            borrow = 1;
        }
        out[k] = v as u8;
    }
    out
}

impl Rng for Stream {
    fn scalar(&mut self) -> Scalar {
        self.k += 1;
        let mut h = Sha256::new();
        h.update(b"shz-frost-member/vector/scalar/");
        h.update(self.k.to_be_bytes());
        let r = mod_n_minus_1(h.finalize().into());
        ec::reduce32(&r) + Scalar::ONE
    }
    fn bytes32(&mut self) -> [u8; 32] {
        self.a += 1;
        let mut h = Sha256::new();
        h.update(b"shz-frost-member/vector/aux/");
        h.update(self.a.to_be_bytes());
        h.finalize().into()
    }
}

fn vectors() -> J {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("vectors.json");
    json::loads_bytes(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn rust_member_matches_python_member_byte_for_byte() {
    let v = vectors();
    let clock = v.at("clock_us").unwrap().strict_int().unwrap();
    let median = v.at("static_median_e8").unwrap().strict_int();
    let start = v.at("rng_start").unwrap().strict_int().unwrap() as u32;
    let rng: Arc<Mutex<Box<dyn Rng>>> = Arc::new(Mutex::new(Box::new(Stream { k: start, a: 0 })));
    let root = std::env::temp_dir().join(format!("shz-frost-member-vectors-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut members = Vec::new();
    for s in v.at("shares").unwrap().iter_py().unwrap() {
        let share = Share::from_json(&s).unwrap();
        let dir = root.join(format!("m{}", share.index));
        let view = View::Static(Mutex::new(StaticView { median_e8: median, at_us: None }));
        members.push(Member::new(share, &dir, None, view, 50, 35.0, rng.clone(), Box::new(move || clock)).unwrap());
    }
    let steps = v.at("steps").unwrap().iter_py().unwrap();
    for (n, st) in steps.iter().enumerate() {
        let i = st.at("member").unwrap().strict_int().unwrap() as usize;
        let m = &members[i - 1];
        let path = st.at("path").unwrap().as_str().unwrap();
        let (code, body) = if st.at("method").unwrap().as_str() == Some("GET") {
            if path == "/healthz" { (200, m.healthz().unwrap()) } else { (404, json::loads(r#"{"error": "not found"}"#).unwrap()) }
        } else {
            let raw = st.at("request").unwrap().as_str().unwrap().as_bytes();
            m.post(path, raw, None, None)
        };
        let got = json::dumps(&body, Style::Default);
        let want = st.at("response").unwrap().as_str().unwrap();
        assert_eq!(code as i128, st.at("status").unwrap().strict_int().unwrap(), "step {n} member {i} {path}: {got}");
        assert_eq!(got, want, "step {n} member {i} {path}");
    }
    let files = v.at("files").unwrap();
    for (i, f) in files.items().unwrap() {
        let dir = root.join(format!("m{i}"));
        for (name, key) in [("nonces.json", "nonces"), ("dlc.json", "dlc")] {
            let got = std::fs::read_to_string(dir.join(name)).unwrap();
            assert_eq!(got, f.at(key).unwrap().as_str().unwrap(), "member {i} {name}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rust_member_restarts_on_python_state_files() {
    // A member switched from Python keeps its share, nonce high-water mark and DLC state: the
    // Rust member loads the Python member's final files and serves the same health and refusals.
    let v = vectors();
    let clock = v.at("clock_us").unwrap().strict_int().unwrap();
    let root = std::env::temp_dir().join(format!("shz-frost-member-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let share = Share::from_json(&v.at("shares").unwrap().idx(2).unwrap().clone()).unwrap();
    let f = v.at("files").unwrap().at("3").unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("nonces.json"), f.at("nonces").unwrap().as_str().unwrap()).unwrap();
    std::fs::write(root.join("dlc.json"), f.at("dlc").unwrap().as_str().unwrap()).unwrap();
    let rng: Arc<Mutex<Box<dyn Rng>>> = Arc::new(Mutex::new(Box::new(Stream { k: 10_000, a: 10_000 })));
    let m = Member::new(share, &root, None, View::NoCheck, 50, 35.0, rng, Box::new(move || clock)).unwrap();
    assert_eq!(json::dumps(m.healthz().unwrap().at("last_seq").unwrap(), Style::Default), "2");
    let (code, r) = m.post("/commit", br#"{"seq": 2}"#, None, None);
    assert_eq!((code, json::dumps(&r, Style::Default).as_str()), (409, r#"{"error": "ValueError: sequence already signed or older"}"#));
    // The attested event stays locked: a different price is refused after the restart.
    let (code, r) = m.post("/dlc/receive", br#"{"event_id": "SHZ-BTCUSD-VEC1", "deals": {}}"#, None, None);
    assert_eq!(code, 200, "{}", json::dumps(&r, Style::Default));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn coordinator_auth_matches_python() {
    let v = vectors();
    let a = v.at("auth").unwrap();
    let group = v.at("group").unwrap();
    let gx = json::py_fromhex(group.at("group_pubkey").unwrap().as_str().unwrap()).unwrap();
    let master: [u8; 32] = json::py_fromhex(a.at("master").unwrap().as_str().unwrap()).unwrap().try_into().unwrap();
    let key = auth::member_key(&master, &gx, 1);
    assert_eq!(json::hex(&key), a.at("key").unwrap().as_str().unwrap());
    let now = a.at("now_us").unwrap().strict_int().unwrap();
    let body = a.at("body").unwrap().as_str().unwrap().as_bytes();
    let header = a.at("header").unwrap().as_str().unwrap();
    let ver = Verifier::new(key, gx.clone(), 1);
    assert_eq!(ver.check("/commit", body, Some(header), now), Ok(()));
    assert_eq!(ver.check("/commit", body, Some(header), now).unwrap_err(), "replayed coordinator request");
    let fresh = Verifier::new(key, gx.clone(), 1);
    assert_eq!(fresh.check("/sign", body, Some(header), now).unwrap_err(), "bad coordinator MAC");
    assert_eq!(fresh.check("/commit", b"{}", Some(header), now).unwrap_err(), "bad coordinator MAC");
    assert_eq!(fresh.check("/commit", body, Some(header), now + 31_000_000).unwrap_err(), "coordinator timestamp outside the window");
    let other = Verifier::new(auth::member_key(&master, &gx, 2), gx, 2);
    assert_eq!(other.check("/commit", body, Some(header), now).unwrap_err(), "bad coordinator MAC");
    for bad in ["v1", "v2 1 00 00", "v1 x y z"] {
        assert_eq!(fresh.check("/commit", body, Some(bad), now).unwrap_err(), "malformed coordinator authentication");
    }
    assert_eq!(fresh.check("/commit", body, None, now).unwrap_err(), "missing coordinator authentication");
}
