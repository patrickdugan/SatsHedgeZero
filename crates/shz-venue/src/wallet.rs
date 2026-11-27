//! Wallet connect: Nostr (NIP-07) and LNURL-auth (LUD-04) logins that authorize a
//! browser *trading key*.
//!
//! The router verifies raw BIP340 signatures by the account owner over venue-chosen
//! 32-byte messages (allocation digest, intent id, batch approvals, channel acks).
//! Neither NIP-07 (it only signs Nostr events) nor LNURL-auth (it only signs k1) can
//! produce those, so a wallet never signs approvals directly. Instead the wallet
//! authorizes a trading key once, with an expiry, and the trading key keeps signing
//! as before. A link needs both sides to consent: the wallet proves control of its
//! key (Nostr event envelope or LNURL ECDSA signature) and the trading key signs the
//! same link hash with BIP340, so nobody can attach someone else's key to a wallet.

use std::collections::BTreeMap;

use k256::ecdsa::{Signature as EcdsaSig, VerifyingKey, signature::hazmat::PrehashVerifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use shz_dlc::{bip340_verify, tagged_hash};

use crate::core::{Key, Venue, h, now_us, parse_key, parse_sig};

/// Nostr event kind carrying a venue request (ephemeral range, unassigned).
pub const NOSTR_KIND: u64 = 27810;
pub const NOSTR_SKEW_S: u64 = 300;
pub const CHALLENGE_TTL_US: u64 = 300_000_000;
pub const LNURL_K1_TTL_US: u64 = 300_000_000;
pub const LINK_TTL_US: u64 = 86_400_000_000;

// ------------------------------------------------------- nostr envelope ----

/// What the venue expects an envelope to commit to.
pub struct Expect<'a> {
    pub venue: &'a str,
    pub req: &'a str,
    pub hash: Key,
    pub pubkey: Option<Key>,
}

fn tag_value<'a>(tags: &'a [Value], name: &str) -> Result<Option<&'a str>, String> {
    let mut found = None;
    for t in tags {
        let a = t.as_array().ok_or("tags must be arrays")?;
        if a.first().and_then(Value::as_str) == Some(name) {
            if found.is_some() {
                return Err(format!("duplicate {name} tag"));
            }
            found = Some(a.get(1).and_then(Value::as_str).ok_or_else(|| format!("{name} tag needs a value"))?);
        }
    }
    Ok(found)
}

fn clean(s: &str) -> bool {
    // NIP-01 escapes only a few control characters; refuse the rest so every
    // serializer produces the same bytes.
    s.chars().all(|c| c >= ' ' || matches!(c, '\n' | '\r' | '\t'))
}

/// NIP-01 event id: sha256 of `[0,pubkey,created_at,kind,tags,content]`.
pub fn nostr_event_id(pubkey: &str, created_at: u64, kind: u64, tags: &Value, content: &str) -> Key {
    let ser = serde_json::to_string(&json!([0, pubkey, created_at, kind, tags, content])).expect("json");
    Sha256::digest(ser.as_bytes()).into()
}

/// Verify a signed Nostr event that commits to one venue request: kind, event id,
/// BIP340 signature, freshness, and the `shz-venue`, `shz-req` and `shz-hash` tags.
/// Returns the signer's x-only key.
pub fn verify_nostr_envelope(ev: &Value, ex: &Expect, now_s: u64) -> Result<Key, String> {
    if ev["kind"].as_u64() != Some(NOSTR_KIND) {
        return Err("wrong event kind".into());
    }
    let pk_hex = ev["pubkey"].as_str().ok_or("missing pubkey")?;
    let pubkey = parse_key(pk_hex).map_err(|_| "bad pubkey")?;
    if ex.pubkey.is_some_and(|want| want != pubkey) {
        return Err("event signed by a different key".into());
    }
    let created = ev["created_at"].as_u64().ok_or("missing created_at")?;
    if created.abs_diff(now_s) > NOSTR_SKEW_S {
        return Err("event timestamp outside the allowed window".into());
    }
    let content = ev["content"].as_str().ok_or("missing content")?;
    let tags = ev["tags"].as_array().ok_or("missing tags")?;
    let tags_clean = tags.iter().all(|t| t.as_array().is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(clean))));
    if !clean(content) || !tags_clean {
        return Err("control characters in event".into());
    }
    let id = nostr_event_id(pk_hex, created, NOSTR_KIND, &ev["tags"], content);
    if parse_key(ev["id"].as_str().unwrap_or("")).ok() != Some(id) {
        return Err("event id does not match its content".into());
    }
    let sig = parse_sig(ev["sig"].as_str().unwrap_or(""))?;
    bip340_verify(&pubkey, &id, &sig).map_err(|_| "event signature does not verify")?;
    if tag_value(tags, "shz-venue")? != Some(ex.venue) {
        return Err("event is for another venue".into());
    }
    if tag_value(tags, "shz-req")? != Some(ex.req) {
        return Err("event is for another request".into());
    }
    if tag_value(tags, "shz-hash")?.and_then(|s| parse_key(s).ok()) != Some(ex.hash) {
        return Err("event does not commit to the expected hash".into());
    }
    Ok(pubkey)
}

// ------------------------------------------------------------ link hash ----

/// The message both the wallet (inside its proof) and the trading key sign.
pub fn link_hash(network: &Key, kind: &str, wallet: &[u8], trade_key: &Key, nonce: &Key, expires_us: u64) -> Key {
    let mut m = Vec::new();
    m.extend_from_slice(network);
    m.push(kind.len() as u8);
    m.extend_from_slice(kind.as_bytes());
    m.push(wallet.len() as u8);
    m.extend_from_slice(wallet);
    m.extend_from_slice(trade_key);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&expires_us.to_le_bytes());
    tagged_hash(b"SHZ/VENUE/WALLET-LINK/V1", &m)
}

// ---------------------------------------------------------------- bech32 ----

pub(crate) const B32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub(crate) fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ *v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}
pub(crate) fn hrp_expand(hrp: &str) -> Vec<u8> {
    hrp.bytes().map(|b| b >> 5).chain([0]).chain(hrp.bytes().map(|b| b & 31)).collect()
}
/// Plain bech32 (not bech32m), no length limit, as LUD-01 requires.
pub fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let mut five = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in data {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            five.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        five.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut vals = hrp_expand(hrp);
    vals.extend(&five);
    vals.extend([0u8; 6]);
    let pm = polymod(&vals) ^ 1;
    for i in 0..6 {
        five.push(((pm >> (5 * (5 - i))) & 31) as u8);
    }
    format!("{hrp}1{}", five.iter().map(|v| B32[*v as usize] as char).collect::<String>())
}
#[cfg(test)]
pub fn bech32_decode(s: &str) -> Option<(String, Vec<u8>)> {
    let s = s.to_ascii_lowercase();
    let (hrp, rest) = s.rsplit_once('1')?;
    let five: Vec<u8> = rest.bytes().map(|c| B32.iter().position(|x| *x == c).map(|p| p as u8)).collect::<Option<_>>()?;
    if five.len() < 6 {
        return None;
    }
    let mut vals = hrp_expand(hrp);
    vals.extend(&five);
    if polymod(&vals) != 1 {
        return None;
    }
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for v in &five[..five.len() - 6] {
        acc = (acc << 5) | *v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some((hrp.to_string(), out))
}

// ----------------------------------------------------------------- state ----
//
// Starting a login creates no server state: the Nostr challenge and the LNURL k1 are MACs
// under a per-process secret over everything the later step needs. State is created only
// after a wallet signature verifies, in tables of at most MAX_ENTRIES that drop their oldest
// entry when full, so unauthenticated requests cannot fill them and lock out other users.

#[derive(Clone, Debug, PartialEq)]
pub struct WalletLink {
    pub kind: String,
    pub wallet: String,
    pub issued_us: u64,
    pub expires_us: u64,
}
impl WalletLink {
    pub fn json(&self) -> Value {
        json!({"kind": self.kind, "wallet": self.wallet, "issued_us": self.issued_us, "expires_us": self.expires_us})
    }
}

pub const MAX_ENTRIES: usize = 4096;

/// Map keyed by a 32-byte id; when full it drops expired entries, then the oldest.
struct Bounded<V> {
    m: BTreeMap<Key, (u64, V)>,
}
impl<V> Default for Bounded<V> {
    fn default() -> Self {
        Self { m: BTreeMap::new() }
    }
}
impl<V> Bounded<V> {
    fn get(&self, k: &Key) -> Option<&V> {
        self.m.get(k).map(|(_, v)| v)
    }
    fn get_mut(&mut self, k: &Key) -> Option<&mut V> {
        self.m.get_mut(k).map(|(_, v)| v)
    }
    fn insert(&mut self, k: Key, now: u64, v: V, expired: impl Fn(&V) -> bool) {
        if !self.m.contains_key(&k) && self.m.len() >= MAX_ENTRIES {
            self.m.retain(|_, (_, v)| !expired(v));
            if self.m.len() >= MAX_ENTRIES
                && let Some(oldest) = self.m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| *k)
            {
                self.m.remove(&oldest);
            }
        }
        self.m.insert(k, (now, v));
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.m.len()
    }
}

enum LnurlState {
    Authed { wallet: [u8; 33], link_expires_us: u64 },
    Done,
}
struct LnurlSession {
    trade_key: Key,
    expires_us: u64,
    state: LnurlState,
}

pub struct Wallets {
    secret: Key,
    links: BTreeMap<Key, WalletLink>,
    /// Nostr challenge MACs already used, kept until the challenge expires.
    used: Bounded<u64>,
    /// LNURL k1s a wallet has signed.
    lnurl: Bounded<LnurlSession>,
}

impl Default for Wallets {
    fn default() -> Self {
        Self { secret: random32().expect("OS RNG"), links: BTreeMap::new(), used: Bounded::default(), lnurl: Bounded::default() }
    }
}

fn random32() -> Result<Key, String> {
    let mut k = [0u8; 32];
    crate::core::getrandom(&mut k)?;
    Ok(k)
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Challenge token: trade_key | link_expires_us | expires_us (both u64 BE) | mac.
const TOKEN_LEN: usize = 32 + 8 + 8 + 32;

impl Wallets {
    /// Keyed hash over fixed-length fields, secret first, so length extension yields no valid input.
    fn mac(&self, tag: &[u8], parts: &[&[u8]]) -> Key {
        let mut m = self.secret.to_vec();
        for p in parts {
            m.extend_from_slice(p);
        }
        tagged_hash(tag, &m)
    }
    fn nostr_mac(&self, network: &Key, wallet: &Key, trade_key: &Key, link_exp: u64, exp: u64) -> Key {
        self.mac(b"SHZ/VENUE/NOSTR-CHALLENGE/V1", &[network, wallet, trade_key, &link_exp.to_be_bytes(), &exp.to_be_bytes()])
    }
    fn lnurl_k1(&self, network: &Key, trade_key: &Key, exp: u64) -> Key {
        self.mac(b"SHZ/VENUE/LNURL-K1/V1", &[network, trade_key, &exp.to_be_bytes()])
    }

    pub fn link(&self, trade_key: &Key) -> Option<&WalletLink> {
        self.links.get(trade_key)
    }
    pub fn restore(&mut self, trade_key: Key, link: WalletLink) {
        self.links.insert(trade_key, link);
    }

    /// A trading key linked to a wallet stops signing once the authorization expires.
    pub fn check(&self, owner: &Key, now: u64) -> Result<(), String> {
        match self.links.get(owner) {
            Some(l) if l.expires_us <= now => Err("wallet authorization expired; reconnect the wallet".into()),
            _ => Ok(()),
        }
    }

    /// A key stays bound to the first wallet that authorizes it; the same wallet may renew.
    fn install(&mut self, trade_key: Key, link: WalletLink) -> Result<WalletLink, String> {
        if let Some(old) = self.links.get(&trade_key)
            && (old.wallet != link.wallet || old.kind != link.kind)
        {
            return Err("trading key is bound to another wallet".into());
        }
        self.links.insert(trade_key, link.clone());
        Ok(link)
    }

    // ---- nostr ----
    pub fn nostr_challenge(&mut self, network: &Key, wallet: Key, trade_key: Key, now: u64) -> Result<Value, String> {
        shz_dlc::lift_x_even(&wallet).map_err(|_| "wallet is not a valid x-only key")?;
        shz_dlc::lift_x_even(&trade_key).map_err(|_| "trade_key is not a valid x-only key")?;
        let (exp, link_expires_us) = (now + CHALLENGE_TTL_US, now + LINK_TTL_US);
        let mac = self.nostr_mac(network, &wallet, &trade_key, link_expires_us, exp);
        let mut token = Vec::with_capacity(TOKEN_LEN);
        token.extend_from_slice(&trade_key);
        token.extend_from_slice(&link_expires_us.to_be_bytes());
        token.extend_from_slice(&exp.to_be_bytes());
        token.extend_from_slice(&mac);
        let hash = link_hash(network, "nostr", &wallet, &trade_key, &mac, link_expires_us);
        Ok(json!({"challenge": hex::encode(token), "hash": h(&hash), "kind": NOSTR_KIND, "venue": h(network), "req": "wallet-link",
                  "expires_us": exp, "link_expires_us": link_expires_us}))
    }

    /// `body`: `{event, session_signature}`. The event is a kind-27810 Nostr event with
    /// tags `shz-venue`, `shz-req=wallet-link`, `shz-hash`, `shz-challenge`.
    pub fn nostr_link(&mut self, network: &Key, body: &Value, now: u64) -> Result<(Key, WalletLink), String> {
        let ev = &body["event"];
        let tags = ev["tags"].as_array().ok_or("missing tags")?;
        let token = hex::decode(tag_value(tags, "shz-challenge")?.ok_or("missing shz-challenge tag")?).map_err(|_| "bad challenge")?;
        if token.len() != TOKEN_LEN {
            return Err("bad challenge".into());
        }
        let trade_key: Key = token[..32].try_into().expect("32");
        let link_expires_us = u64::from_be_bytes(token[32..40].try_into().expect("8"));
        let exp = u64::from_be_bytes(token[40..48].try_into().expect("8"));
        let mac: Key = token[48..].try_into().expect("32");
        let wallet = parse_key(ev["pubkey"].as_str().unwrap_or("")).map_err(|_| "bad pubkey")?;
        if !eq_ct(&mac, &self.nostr_mac(network, &wallet, &trade_key, link_expires_us, exp)) {
            return Err("challenge was not issued to this wallet and trading key".into());
        }
        if exp <= now {
            return Err("challenge expired".into());
        }
        if self.used.get(&mac).is_some() {
            return Err("challenge already used".into());
        }
        let hash = link_hash(network, "nostr", &wallet, &trade_key, &mac, link_expires_us);
        let venue = h(network);
        verify_nostr_envelope(ev, &Expect { venue: &venue, req: "wallet-link", hash, pubkey: Some(wallet) }, now / 1_000_000)?;
        let ssig = parse_sig(body["session_signature"].as_str().unwrap_or("")).map_err(|_| "session_signature required")?;
        bip340_verify(&trade_key, &hash, &ssig).map_err(|_| "trading key signature does not verify")?;
        let link = self.install(trade_key, WalletLink { kind: "nostr".into(), wallet: h(&wallet), issued_us: now, expires_us: link_expires_us })?;
        self.used.insert(mac, now, exp, |e| *e <= now);
        Ok((trade_key, link))
    }

    // ---- lnurl-auth ----
    /// A k1 bound to the browser's trading key and an expiry; nothing is stored.
    pub fn lnurl_start(&mut self, network: &Key, trade_key: Key, now: u64) -> Result<(Key, u64), String> {
        shz_dlc::lift_x_even(&trade_key).map_err(|_| "trade_key is not a valid x-only key")?;
        let exp = now + LNURL_K1_TTL_US;
        Ok((self.lnurl_k1(network, &trade_key, exp), exp))
    }

    /// LUD-04 callback: `sig` is the DER ECDSA signature of k1 under the compressed `key`.
    /// `t` and `e` (trading key and expiry) come back in the callback URL; k1 authenticates them.
    #[allow(clippy::too_many_arguments)]
    pub fn lnurl_callback(&mut self, network: &Key, k1_hex: &str, sig_hex: &str, key_hex: &str, t_hex: &str, e: &str, now: u64) -> Result<(), String> {
        let k1 = parse_key(k1_hex).map_err(|_| "bad k1")?;
        let trade_key = parse_key(t_hex).map_err(|_| "unknown k1")?;
        let exp: u64 = e.parse().map_err(|_| "unknown k1")?;
        if !eq_ct(&k1, &self.lnurl_k1(network, &trade_key, exp)) {
            return Err("unknown k1".into());
        }
        if exp <= now {
            return Err("k1 expired".into());
        }
        if self.lnurl.get(&k1).is_some() {
            return Err("k1 already used".into());
        }
        let key: [u8; 33] = hex::decode(key_hex).map_err(|_| "bad key")?.try_into().map_err(|_| "key must be a 33-byte compressed point")?;
        let der = hex::decode(sig_hex).map_err(|_| "bad sig")?;
        verify_lnurl_sig(&k1, &der, &key)?;
        let s = LnurlSession { trade_key, expires_us: exp, state: LnurlState::Authed { wallet: key, link_expires_us: now + LINK_TTL_US } };
        self.lnurl.insert(k1, now, s, |s| s.expires_us + LNURL_K1_TTL_US <= now);
        Ok(())
    }

    /// `pending` until a wallet signs k1 (the browser tracks the k1 expiry it was given).
    pub fn lnurl_status(&self, network: &Key, k1_hex: &str, now: u64) -> Result<Value, String> {
        let k1 = parse_key(k1_hex).map_err(|_| "bad k1")?;
        let Some(s) = self.lnurl.get(&k1) else { return Ok(json!({"status": "pending"})) };
        if s.expires_us <= now && !matches!(s.state, LnurlState::Done) {
            return Ok(json!({"status": "expired"}));
        }
        Ok(match &s.state {
            LnurlState::Authed { wallet, link_expires_us } => json!({
                "status": "authed", "wallet": h(wallet), "link_expires_us": link_expires_us,
                "hash": h(&link_hash(network, "lnurl", wallet, &s.trade_key, &k1, *link_expires_us))}),
            LnurlState::Done => json!({"status": "linked"}),
        })
    }

    /// The browser's trading key signs the link hash, completing the binding.
    pub fn lnurl_confirm(&mut self, network: &Key, k1_hex: &str, sig_hex: &str, now: u64) -> Result<(Key, WalletLink), String> {
        let k1 = parse_key(k1_hex).map_err(|_| "bad k1")?;
        let s = self.lnurl.get(&k1).ok_or("wallet has not authenticated this k1")?;
        let LnurlState::Authed { wallet, link_expires_us } = s.state else { return Err("k1 already used".into()) };
        if link_expires_us <= now {
            return Err("authorization expired".into());
        }
        let (trade_key, hash) = (s.trade_key, link_hash(network, "lnurl", &wallet, &s.trade_key, &k1, link_expires_us));
        let sig = parse_sig(sig_hex).map_err(|_| "session_signature required")?;
        bip340_verify(&trade_key, &hash, &sig).map_err(|_| "trading key signature does not verify")?;
        let link = self.install(trade_key, WalletLink { kind: "lnurl".into(), wallet: h(&wallet), issued_us: now, expires_us: link_expires_us })?;
        self.lnurl.get_mut(&k1).expect("present").state = LnurlState::Done;
        Ok((trade_key, link))
    }
}

pub fn verify_lnurl_sig(k1: &Key, der: &[u8], key: &[u8; 33]) -> Result<(), String> {
    let vk = VerifyingKey::from_sec1_bytes(key).map_err(|_| "key is not a valid secp256k1 point")?;
    let sig = EcdsaSig::from_der(der).map_err(|_| "signature is not valid DER")?;
    // Wallets differ on low-S; the k1 is single-use, so malleability is harmless.
    let sig = sig.normalize_s().unwrap_or(sig);
    vk.verify_prehash(k1, &sig).map_err(|_| "signature does not verify".to_string())
}

// ----------------------------------------------------------------- venue ----

fn session_url(origin: &str, k1: &Key, trade_key: &Key, exp: u64) -> Result<String, String> {
    let o = origin.trim_end_matches('/');
    let local = o.starts_with("http://localhost") || o.starts_with("http://127.0.0.1");
    if !(o.starts_with("https://") || local) || o.len() > 200 || o.bytes().any(|b| b <= b' ' || b == b'?' || b == b'#') {
        return Err("origin must be an https URL".into());
    }
    Ok(format!("{o}/api/wallet/lnurl/callback?tag=login&action=login&k1={}&t={}&e={exp}", h(k1), h(trade_key)))
}

impl Venue {
    pub fn wallet_check(&self, owner: &Key) -> Result<(), String> {
        self.wallets.check(owner, now_us())
    }
    fn persist_link(&mut self, trade_key: &Key, l: &WalletLink) {
        self.persist(json!({"kind": "wallet_link", "trade_key": h(trade_key), "link": l.json()}));
    }
    pub fn restore_link(&mut self, e: &Value) {
        let (Some(Ok(k)), l) = (e["trade_key"].as_str().map(parse_key), &e["link"]) else { return };
        if let (Some(kind), Some(wallet), Some(i), Some(x)) = (l["kind"].as_str(), l["wallet"].as_str(), l["issued_us"].as_u64(), l["expires_us"].as_u64()) {
            self.wallets.restore(k, WalletLink { kind: kind.into(), wallet: wallet.into(), issued_us: i, expires_us: x });
        }
    }
    pub fn wallet_link_view(&self, owner: &Key) -> Value {
        self.wallets.link(owner).map(WalletLink::json).unwrap_or(Value::Null)
    }
    pub fn wallet_nostr_challenge(&mut self, wallet: Key, trade_key: Key) -> Result<Value, String> {
        let n = self.scope.network;
        self.wallets.nostr_challenge(&n, wallet, trade_key, now_us())
    }
    pub fn wallet_nostr_link(&mut self, body: &Value) -> Result<Value, String> {
        let n = self.scope.network;
        let (k, l) = self.wallets.nostr_link(&n, body, now_us())?;
        self.persist_link(&k, &l);
        Ok(json!({"trade_key": h(&k), "link": l.json()}))
    }
    pub fn wallet_lnurl_start(&mut self, trade_key: Key, origin: &str) -> Result<Value, String> {
        let n = self.scope.network;
        let (k1, exp) = self.wallets.lnurl_start(&n, trade_key, now_us())?;
        let url = session_url(origin, &k1, &trade_key, exp)?;
        Ok(json!({"k1": h(&k1), "callback": url, "lnurl": bech32_encode("lnurl", url.as_bytes()).to_ascii_uppercase(), "expires_us": exp}))
    }
    /// LUD-04 reply body.
    pub fn wallet_lnurl_callback(&mut self, k1: &str, sig: &str, key: &str, t: &str, e: &str) -> Value {
        let n = self.scope.network;
        match self.wallets.lnurl_callback(&n, k1, sig, key, t, e, now_us()) {
            Ok(()) => json!({"status": "OK"}),
            Err(e) => json!({"status": "ERROR", "reason": e}),
        }
    }
    pub fn wallet_lnurl_status(&self, k1: &str) -> Result<Value, String> {
        self.wallets.lnurl_status(&self.scope.network, k1, now_us())
    }
    pub fn wallet_lnurl_confirm(&mut self, k1: &str, sig: &str) -> Result<Value, String> {
        let n = self.scope.network;
        let (k, l) = self.wallets.lnurl_confirm(&n, k1, sig, now_us())?;
        self.persist_link(&k, &l);
        Ok(json!({"trade_key": h(&k), "link": l.json()}))
    }
}

// ----------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
    use shz_dlc::{bip340_sign, pubkey_x_from_secret};

    const NET: Key = [7u8; 32];

    fn xonly(sk: &Key) -> Key {
        pubkey_x_from_secret(sk).expect("pk")
    }

    fn event(sk: &Key, created: u64, venue: &str, req: &str, hash: &Key, extra: Vec<Vec<String>>) -> Value {
        let pk = h(&xonly(sk));
        let mut tags: Vec<Vec<String>> = vec![
            vec!["shz-venue".into(), venue.into()],
            vec!["shz-req".into(), req.into()],
            vec!["shz-hash".into(), h(hash)],
        ];
        tags.extend(extra);
        let tags = json!(tags);
        let content = "SatsHedgeZero testnet: authorize trading key";
        let id = nostr_event_id(&pk, created, NOSTR_KIND, &tags, content);
        let sig = bip340_sign(sk, &id).unwrap();
        json!({"id": h(&id), "pubkey": pk, "created_at": created, "kind": NOSTR_KIND, "tags": tags, "content": content, "sig": h(&sig.to_bytes())})
    }

    fn chal_event(wsk: &Key, c: &Value, now: u64) -> (Value, Key) {
        let hash = parse_key(c["hash"].as_str().unwrap()).unwrap();
        let ev = event(wsk, now / 1_000_000, &h(&NET), "wallet-link", &hash, vec![vec!["shz-challenge".into(), c["challenge"].as_str().unwrap().into()]]);
        (ev, hash)
    }

    #[test]
    fn shared_vector_from_js_stub_verifies() {
        // ui/venue/test/wallet.test.mjs signs this with a stub window.nostr and asserts the same bytes.
        let v: Value = serde_json::from_str(include_str!("../../../ui/venue/test/nostr_vector.json")).unwrap();
        let ev = &v["event"];
        let hash = parse_key(v["hash"].as_str().unwrap()).unwrap();
        let ex = Expect { venue: v["venue"].as_str().unwrap(), req: v["req"].as_str().unwrap(), hash, pubkey: Some(parse_key(v["pubkey"].as_str().unwrap()).unwrap()) };
        let now = ev["created_at"].as_u64().unwrap();
        assert!(verify_nostr_envelope(ev, &ex, now).is_ok());
        assert!(verify_nostr_envelope(ev, &Expect { hash: [1; 32], ..ex }, now).is_err());
    }

    #[test]
    fn shared_vector_link_hash_matches_js() {
        let v: Value = serde_json::from_str(include_str!("../../../ui/venue/test/nostr_vector.json")).unwrap();
        let l = &v["link"];
        let hash = link_hash(
            &parse_key(l["network"].as_str().unwrap()).unwrap(), "nostr", &parse_key(v["pubkey"].as_str().unwrap()).unwrap(),
            &parse_key(l["trade_key"].as_str().unwrap()).unwrap(), &parse_key(l["challenge"].as_str().unwrap()).unwrap(), l["expires_us"].as_u64().unwrap());
        assert_eq!(h(&hash), v["hash"].as_str().unwrap());
    }

    #[test]
    fn envelope_valid_and_rejections() {
        let sk = [3u8; 32];
        let hash = [9u8; 32];
        let venue = h(&NET);
        let ev = event(&sk, 1_000_000, &venue, "wallet-link", &hash, vec![]);
        let ex = Expect { venue: &venue, req: "wallet-link", hash, pubkey: Some(xonly(&sk)) };
        assert_eq!(verify_nostr_envelope(&ev, &ex, 1_000_000).unwrap(), xonly(&sk));
        // wrong hash
        assert!(verify_nostr_envelope(&ev, &Expect { hash: [8; 32], ..ex }, 1_000_000).unwrap_err().contains("hash"));
        // wrong pubkey
        assert!(verify_nostr_envelope(&ev, &Expect { pubkey: Some(xonly(&[4u8; 32])), ..ex }, 1_000_000).unwrap_err().contains("different key"));
        // replayed for another request or another venue
        assert!(verify_nostr_envelope(&ev, &Expect { req: "order", ..ex }, 1_000_000).unwrap_err().contains("request"));
        assert!(verify_nostr_envelope(&ev, &Expect { venue: "other", ..ex }, 1_000_000).unwrap_err().contains("venue"));
        // stale
        assert!(verify_nostr_envelope(&ev, &ex, 1_000_000 + NOSTR_SKEW_S + 1).unwrap_err().contains("timestamp"));
        // tampered content: id no longer matches
        let mut t = ev.clone();
        t["content"] = json!("something else");
        assert!(verify_nostr_envelope(&t, &ex, 1_000_000).unwrap_err().contains("id"));
        // right id, signature from another key
        let mut f = ev.clone();
        f["sig"] = event(&[4u8; 32], 1_000_000, &venue, "wallet-link", &hash, vec![])["sig"].clone();
        assert!(verify_nostr_envelope(&f, &ex, 1_000_000).unwrap_err().contains("signature"));
        // wrong kind
        let mut k = ev.clone();
        k["kind"] = json!(1);
        assert!(verify_nostr_envelope(&k, &ex, 1_000_000).is_err());
        // duplicate hash tag
        let dup = event(&sk, 1_000_000, &venue, "wallet-link", &hash, vec![vec!["shz-hash".into(), h(&[8; 32])]]);
        assert!(verify_nostr_envelope(&dup, &ex, 1_000_000).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn nostr_link_flow_binds_both_keys() {
        let (wsk, tsk) = ([3u8; 32], [5u8; 32]);
        let (wallet, trade) = (xonly(&wsk), xonly(&tsk));
        let mut w = Wallets::default();
        let now = 2_000_000_000_000_000u64;
        let c = w.nostr_challenge(&NET, wallet, trade, now).unwrap();
        let (ev, hash) = chal_event(&wsk, &c, now);
        let ssig = h(&bip340_sign(&tsk, &hash).unwrap().to_bytes());
        // the trading key must consent
        let bad = json!({"event": ev, "session_signature": h(&bip340_sign(&[6u8; 32], &hash).unwrap().to_bytes())});
        assert!(w.nostr_link(&NET, &bad, now).unwrap_err().contains("trading key"));
        // an event from another wallet key is refused: the challenge MAC names the wallet
        let (other, _) = chal_event(&[4u8; 32], &c, now);
        assert!(w.nostr_link(&NET, &json!({"event": other, "session_signature": ssig}), now).unwrap_err().contains("not issued"));
        // a challenge whose expiries were edited no longer verifies
        let mut tok = hex::decode(c["challenge"].as_str().unwrap()).unwrap();
        tok[39] ^= 1;
        let (edited, _) = chal_event(&wsk, &json!({"hash": c["hash"], "challenge": hex::encode(&tok)}), now);
        assert!(w.nostr_link(&NET, &json!({"event": edited, "session_signature": ssig}), now).unwrap_err().contains("not issued"));
        let (k, l) = w.nostr_link(&NET, &json!({"event": ev, "session_signature": ssig}), now).unwrap();
        assert_eq!(k, trade);
        assert_eq!(l.wallet, h(&wallet));
        assert_eq!(l.expires_us, now + LINK_TTL_US);
        // the challenge is single use
        assert!(w.nostr_link(&NET, &json!({"event": ev, "session_signature": ssig}), now).unwrap_err().contains("challenge"));
        // expiry gate
        assert!(w.check(&trade, now + LINK_TTL_US - 1).is_ok());
        assert!(w.check(&trade, now + LINK_TTL_US).is_err());
        assert!(w.check(&[1; 32], u64::MAX).is_ok());
    }

    #[test]
    fn expired_challenge_and_rebinding_refused() {
        let (wsk, tsk) = ([3u8; 32], [5u8; 32]);
        let mut w = Wallets::default();
        let now = 2_000_000_000_000_000u64;
        let c = w.nostr_challenge(&NET, xonly(&wsk), xonly(&tsk), now).unwrap();
        let (ev, hash) = chal_event(&wsk, &c, now);
        let body = json!({"event": ev, "session_signature": h(&bip340_sign(&tsk, &hash).unwrap().to_bytes())});
        assert!(w.nostr_link(&NET, &body, now + CHALLENGE_TTL_US + 1).unwrap_err().contains("challenge"));
        // a different wallet cannot take over an already linked trading key
        let c = w.nostr_challenge(&NET, xonly(&wsk), xonly(&tsk), now).unwrap();
        let (ev, hash) = chal_event(&wsk, &c, now);
        w.nostr_link(&NET, &json!({"event": ev, "session_signature": h(&bip340_sign(&tsk, &hash).unwrap().to_bytes())}), now).unwrap();
        let w2 = [4u8; 32];
        let c2 = w.nostr_challenge(&NET, xonly(&w2), xonly(&tsk), now).unwrap();
        let (ev2, hash2) = chal_event(&w2, &c2, now);
        let r = w.nostr_link(&NET, &json!({"event": ev2, "session_signature": h(&bip340_sign(&tsk, &hash2).unwrap().to_bytes())}), now);
        assert!(r.unwrap_err().contains("another wallet"));
    }

    fn lnurl_sign(sk: &[u8; 32], k1: &Key) -> (String, String) {
        let key = SigningKey::from_bytes(sk.into()).unwrap();
        let sig: EcdsaSig = key.sign_prehash(k1).unwrap();
        let pk = key.verifying_key().to_encoded_point(true);
        (h(sig.to_der().as_bytes()), h(pk.as_bytes()))
    }

    #[test]
    fn lnurl_auth_flow() {
        let (lsk, tsk) = ([0x42u8; 32], [5u8; 32]);
        let trade = xonly(&tsk);
        let mut w = Wallets::default();
        let now = 2_000_000_000_000_000u64;
        let (k1, exp) = w.lnurl_start(&NET, trade, now).unwrap();
        assert_eq!(exp, now + LNURL_K1_TTL_US);
        assert_eq!(w.lnurl_status(&NET, &h(&k1), now).unwrap()["status"], "pending");
        let (t, e) = (h(&trade), exp.to_string());
        let cb = |w: &mut Wallets, k1: &str, sig: &str, key: &str, now: u64| w.lnurl_callback(&NET, k1, sig, key, &t, &e, now);
        let (sig, key) = lnurl_sign(&lsk, &k1);
        // a signature over a different k1, or from a different key, fails
        let (bad_sig, _) = lnurl_sign(&lsk, &[1; 32]);
        assert!(cb(&mut w, &h(&k1), &bad_sig, &key, now).unwrap_err().contains("verify"));
        let (_, other_key) = lnurl_sign(&[0x43u8; 32], &k1);
        assert!(cb(&mut w, &h(&k1), &sig, &other_key, now).unwrap_err().contains("verify"));
        assert!(cb(&mut w, &h(&k1), "zz", &key, now).is_err());
        assert!(cb(&mut w, &h(&k1), &sig, "02aa", now).is_err());
        // expired and unknown k1; a k1 replayed with another trading key or expiry is unknown
        assert!(cb(&mut w, &h(&k1), &sig, &key, exp).unwrap_err().contains("expired"));
        assert!(cb(&mut w, &h(&[9; 32]), &sig, &key, now).unwrap_err().contains("unknown"));
        assert!(w.lnurl_callback(&NET, &h(&k1), &sig, &key, &h(&xonly(&[6u8; 32])), &e, now).unwrap_err().contains("unknown"));
        assert!(w.lnurl_callback(&NET, &h(&k1), &sig, &key, &t, &(exp + 1).to_string(), now).unwrap_err().contains("unknown"));
        // confirm before the wallet authenticated
        let early = h(&bip340_sign(&tsk, &[0; 32]).unwrap().to_bytes());
        assert!(w.lnurl_confirm(&NET, &h(&k1), &early, now).unwrap_err().contains("not authenticated"));
        cb(&mut w, &h(&k1), &sig, &key, now).unwrap();
        // single use
        assert!(cb(&mut w, &h(&k1), &sig, &key, now).unwrap_err().contains("already used"));
        let st = w.lnurl_status(&NET, &h(&k1), now).unwrap();
        assert_eq!(st["status"], "authed");
        assert_eq!(st["wallet"], key);
        let hash = parse_key(st["hash"].as_str().unwrap()).unwrap();
        // only the trading key bound at start can confirm
        let wrong = h(&bip340_sign(&[6u8; 32], &hash).unwrap().to_bytes());
        assert!(w.lnurl_confirm(&NET, &h(&k1), &wrong, now).unwrap_err().contains("trading key"));
        let good = h(&bip340_sign(&tsk, &hash).unwrap().to_bytes());
        let (k, l) = w.lnurl_confirm(&NET, &h(&k1), &good, now).unwrap();
        assert_eq!((k, l.kind.as_str(), l.wallet.as_str()), (trade, "lnurl", key.as_str()));
        assert_eq!(l.expires_us, now + LINK_TTL_US);
        assert!(w.check(&trade, now + LINK_TTL_US).is_err());
        assert_eq!(w.lnurl_status(&NET, &h(&k1), now).unwrap()["status"], "linked");
    }

    #[test]
    fn starting_logins_stores_nothing_and_full_tables_evict_the_oldest() {
        let mut w = Wallets::default();
        let now = 2_000_000_000_000_000u64;
        let trade = xonly(&[5u8; 32]);
        for i in 0..10_000u64 {
            w.lnurl_start(&NET, trade, now + i).unwrap();
            w.nostr_challenge(&NET, xonly(&[3u8; 32]), trade, now + i).unwrap();
        }
        assert_eq!((w.lnurl.len(), w.used.len()), (0, 0), "unauthenticated starts create no state");
        let mut b: Bounded<u64> = Bounded::default();
        for i in 0..(MAX_ENTRIES as u64 + 10) {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_be_bytes());
            b.insert(k, i, u64::MAX, |_| false);
        }
        assert_eq!(b.len(), MAX_ENTRIES);
        assert!(b.get(&[0u8; 32]).is_none(), "oldest entry evicted");
        let mut newest = [0u8; 32];
        newest[..8].copy_from_slice(&(MAX_ENTRIES as u64 + 9).to_be_bytes());
        assert!(b.get(&newest).is_some());
    }

    #[test]
    fn lnurl_accepts_high_s_signatures() {
        let k1 = [3u8; 32];
        let (sig, key) = lnurl_sign(&[0x42u8; 32], &k1);
        let parsed = EcdsaSig::from_der(&hex::decode(&sig).unwrap()).unwrap();
        let high = EcdsaSig::from_scalars(parsed.r(), -*parsed.s()).unwrap();
        let key: [u8; 33] = hex::decode(key).unwrap().try_into().unwrap();
        assert!(verify_lnurl_sig(&k1, high.to_der().as_bytes(), &key).is_ok());
    }

    #[test]
    fn bech32_roundtrip_and_checksum() {
        let url = "https://shz.example/api/wallet/lnurl/callback?tag=login&k1=00";
        let enc = bech32_encode("lnurl", url.as_bytes());
        assert!(enc.starts_with("lnurl1"));
        let (hrp, data) = bech32_decode(&enc.to_ascii_uppercase()).unwrap();
        assert_eq!((hrp.as_str(), data.as_slice()), ("lnurl", url.as_bytes()));
        let mut bad = enc.into_bytes();
        let n = bad.len() - 1;
        bad[n] = if bad[n] == b'q' { b'p' } else { b'q' };
        assert!(bech32_decode(std::str::from_utf8(&bad).unwrap()).is_none());
        // BIP173: "a12uel5l" is a valid empty-data bech32 string.
        assert_eq!(bech32_decode("a12uel5l"), Some(("a".into(), vec![])));
        assert_eq!(bech32_encode("a", &[]), "a12uel5l");
    }

    #[test]
    fn origin_must_be_https() {
        assert!(session_url("https://shz.example", &[1; 32], &[2; 32], 5).unwrap().starts_with("https://shz.example/api/wallet/lnurl/callback?tag=login"));
        assert!(session_url("http://evil.example", &[1; 32], &[2; 32], 5).is_err());
        assert!(session_url("https://a.example/?x=1", &[1; 32], &[2; 32], 5).is_err());
    }
}
