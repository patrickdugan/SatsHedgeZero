//! Coordinator request authentication, member side (`coord_auth.Verifier`).

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::json::{py_fromhex, py_int_str};

pub const HEADER: &str = "X-SHZ-Auth";
pub const WINDOW_S: i128 = 30;
const KEY_TAG: &[u8] = b"SHZ/RELAY/COORD-AUTH-KEY/V1";
const REQ_TAG: &[u8] = b"SHZ/RELAY/COORD-REQ/V1";

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// `coord_auth.member_key` (used by tests and vectors; members only hold the result).
pub fn member_key(master: &[u8; 32], group_pubkey: &[u8], index: u32) -> [u8; 32] {
    let mut m = KEY_TAG.to_vec();
    m.extend_from_slice(group_pubkey);
    m.extend_from_slice(&index.to_be_bytes());
    hmac(master, &m)
}

pub fn mac(key: &[u8], group_pubkey: &[u8], index: u32, path: &str, ts_us: u64, nonce: &[u8], body: &[u8]) -> [u8; 32] {
    let p = path.as_bytes();
    let mut m = REQ_TAG.to_vec();
    m.extend_from_slice(group_pubkey);
    m.extend_from_slice(&index.to_be_bytes());
    m.extend_from_slice(&(p.len() as u16).to_be_bytes());
    m.extend_from_slice(p);
    m.extend_from_slice(&ts_us.to_be_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(&Sha256::digest(body));
    hmac(key, &m)
}

pub struct Verifier {
    key: [u8; 32],
    group_pubkey: Vec<u8>,
    index: u32,
    window_us: i128,
    seen: Mutex<HashMap<Vec<u8>, i128>>,
}

impl Verifier {
    pub fn new(key: [u8; 32], group_pubkey: Vec<u8>, index: u32) -> Verifier {
        Verifier { key, group_pubkey, index, window_us: WINDOW_S * 1_000_000, seen: Mutex::new(HashMap::new()) }
    }

    /// `Verifier.check`; Err carries the AuthError text.
    pub fn check(&self, path: &str, body: &[u8], value: Option<&str>, now_us: i128) -> Result<(), String> {
        let value = match value {
            Some(v) if !v.is_empty() => v,
            _ => return Err("missing coordinator authentication".into()),
        };
        let malformed = || "malformed coordinator authentication".to_string();
        let parts: Vec<&str> = value.split(' ').collect();
        if parts.len() != 4 || parts[0] != "v1" {
            return Err(malformed());
        }
        let ts = py_int_str(parts[1]).map_err(|_| malformed())?;
        let nonce = py_fromhex(parts[2]).map_err(|_| malformed())?;
        let got = py_fromhex(parts[3]).map_err(|_| malformed())?;
        if nonce.len() != 16 || got.len() != 32 || !(0..1i128 << 63).contains(&ts) {
            return Err(malformed());
        }
        if (now_us - ts).abs() > self.window_us {
            return Err("coordinator timestamp outside the window".into());
        }
        let want = mac(&self.key, &self.group_pubkey, self.index, path, ts as u64, &nonce, body);
        let mut diff = 0u8;
        for k in 0..32 {
            diff |= want[k] ^ got[k];
        }
        if diff != 0 {
            return Err("bad coordinator MAC".into());
        }
        let mut seen = self.seen.lock().unwrap();
        if seen.contains_key(&nonce) {
            return Err("replayed coordinator request".into());
        }
        let w = self.window_us;
        seen.retain(|_, t| (now_us - *t).abs() <= w);
        seen.insert(nonce, ts);
        Ok(())
    }
}

/// `coord_auth.read_key`.
pub fn read_key(path: &str) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let k = py_fromhex(text.trim()).map_err(|e| e.to_string())?;
    k.try_into().map_err(|_| format!("{path}: expected 32 bytes of hex"))
}
