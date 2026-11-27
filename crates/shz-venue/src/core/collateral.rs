//! On-chain collateral accounts (`--collateral-chain regtest|testnet4`, docs/SHZ_MVP_COLLATERAL.md).
//!
//! A trader deposits to `account(T, B, h)` (docs/SHZ_DLC_BATCHER.md section 2): settle leaf
//! `<T> CHECKSIGVERIFY <B> CHECKSIG`, refund leaf `<h> CLTV DROP <T> CHECKSIG`, NUMS internal key.
//! `T` is the venue owner key, `B` the batcher key of `--batcher-key`. The watcher credits a deposit
//! after `--min-conf` confirmations; the owner signs a `collateral` registration and the deposit
//! outpoint becomes the account's venue channel. At each epoch the settler posts one settlement
//! package; every account in it is spent through its settle leaf into a rollover output
//! `account(T, B, h_next)` worth `collateral + net - withdrawal`, plus a payout of any owner-signed
//! withdrawal. Owners sign their own input in the browser; agents cannot (settlement signatures are
//! verified against the owner key only and are not in the agent API's pending set).

use std::{collections::BTreeMap, time::Duration};

use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use shz_dlc::{BtcOutPoint, bip340_verify, tagged_hash};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Key, Venue, h, now_us, parse_key, parse_sig};

/// BIP-341's provably unspendable internal key `H`.
pub const NUMS: Key = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];
pub const DUST: u64 = 330;
pub const TAG_PACKAGE: &[u8] = b"LIGHTNINGER/SETTLE-PACKAGE/V1";
pub const TAG_WITHDRAW: &[u8] = b"LIGHTNINGER/WITHDRAW/V1";
pub const TAG_BROADCAST: &[u8] = b"LIGHTNINGER/SETTLE-BROADCAST/V1";

// ------------------------------------------------------------- config ----

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Net {
    Regtest,
    Testnet4,
}
impl Net {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "regtest" => Ok(Net::Regtest),
            "testnet4" => Ok(Net::Testnet4),
            _ => Err("--collateral-chain must be regtest or testnet4".into()),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Net::Regtest => "regtest",
            Net::Testnet4 => "testnet4",
        }
    }
    pub fn hrp(self) -> &'static str {
        match self {
            Net::Regtest => "bcrt",
            Net::Testnet4 => "tb",
        }
    }
    pub fn explorer_tx(self, txid: &str) -> Option<String> {
        match self {
            Net::Regtest => None,
            Net::Testnet4 => Some(format!("https://mempool.space/testnet4/tx/{txid}")),
        }
    }
}

#[derive(Clone)]
pub struct ChainCfg {
    pub net: Net,
    pub rpc_url: String,
    /// `user:password` for HTTP basic auth (read from `--bitcoind-auth-file`, never logged).
    pub rpc_auth: String,
    pub batcher: Key,
    /// Refund delay of a fresh account output, in blocks from the tip.
    pub refund_blocks: u32,
    pub min_conf: u32,
    /// A deposit (or rollover) must leave at least this many blocks before its refund height.
    pub min_lock: u32,
    pub poll_ms: u64,
}

// ------------------------------------------------------------- script ----

pub fn push32(x: &Key) -> Vec<u8> {
    [vec![0x20], x.to_vec()].concat()
}
/// Minimal CScriptNum push of a non-negative number.
pub fn num(n: u32) -> Vec<u8> {
    if n == 0 {
        return vec![0x00];
    }
    if n <= 16 {
        return vec![0x50 + n as u8];
    }
    let mut b = n.to_le_bytes().to_vec();
    while b.len() > 1 && b[b.len() - 1] == 0 && b[b.len() - 2] & 0x80 == 0 {
        b.pop();
    }
    if b[b.len() - 1] & 0x80 != 0 {
        b.push(0);
    }
    [vec![b.len() as u8], b].concat()
}
pub fn compact(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [vec![0xfd], (n as u16).to_le_bytes().to_vec()].concat(),
        _ => [vec![0xfe], (n as u32).to_le_bytes().to_vec()].concat(),
    }
}
pub fn tapleaf(script: &[u8]) -> Key {
    let mut m = vec![0xc0];
    m.extend(compact(script.len()));
    m.extend(script);
    tagged_hash(b"TapLeaf", &m)
}
fn branch(a: &Key, b: &Key) -> Key {
    let (x, y) = if a < b { (a, b) } else { (b, a) };
    tagged_hash(b"TapBranch", &[&x[..], &y[..]].concat())
}
/// Output key and parity of `p` tweaked by `root`.
fn tweak(p: &Key, root: &Key) -> Result<(Key, u8), String> {
    let pp = shz_dlc::lift_x_even(p).map_err(|_| "bad internal key")?;
    let t = tagged_hash(b"TapTweak", &[&p[..], &root[..]].concat());
    let ts: Scalar = Option::from(Scalar::from_repr(t.into())).ok_or("tweak out of range")?;
    let q = (ProjectivePoint::from(pp) + ProjectivePoint::GENERATOR * ts).to_affine();
    let e = q.to_encoded_point(true);
    Ok((e.as_bytes()[1..33].try_into().unwrap(), e.as_bytes()[0] & 1))
}

/// The collateral account output `account(T, B, h)`; leaf order as `lightninger_dlc_batcher::account_output`.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountScript {
    pub settle: Vec<u8>,
    pub refund: Vec<u8>,
    pub output_key: Key,
    parity: u8,
}
impl AccountScript {
    pub fn new(t: &Key, b: &Key, refund_height: u32) -> Result<Self, String> {
        let settle = [push32(t), vec![0xad], push32(b), vec![0xac]].concat();
        let refund = [num(refund_height), vec![0xb1, 0x75], push32(t), vec![0xac]].concat();
        let root = branch(&tapleaf(&settle), &tapleaf(&refund));
        let (output_key, parity) = tweak(&NUMS, &root)?;
        Ok(Self { settle, refund, output_key, parity })
    }
    pub fn spk(&self) -> Vec<u8> {
        [vec![0x51, 0x20], self.output_key.to_vec()].concat()
    }
    /// Control block of leaf 0 (settle) or 1 (refund).
    pub fn control(&self, leaf: usize) -> Vec<u8> {
        let other = if leaf == 0 { tapleaf(&self.refund) } else { tapleaf(&self.settle) };
        [vec![0xc0 | self.parity], NUMS.to_vec(), other.to_vec()].concat()
    }
    pub fn json(&self, net: Net) -> Value {
        json!({"spk": h(&self.spk()), "address": address(net, &self.spk()).unwrap_or_default(), "output_key": h(&self.output_key),
               "settle_script": h(&self.settle), "settle_control": h(&self.control(0)), "settle_leaf": h(&tapleaf(&self.settle)),
               "refund_script": h(&self.refund), "refund_control": h(&self.control(1)), "refund_leaf": h(&tapleaf(&self.refund))})
    }
}

// ------------------------------------------------------------ address ----

fn to_five(data: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, vec![]);
    for b in data {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}
/// Segwit address of a witness v0/v1+ scriptPubKey (bech32 for v0, bech32m otherwise).
pub fn address(net: Net, spk: &[u8]) -> Result<String, String> {
    if spk.len() < 4 || spk[1] as usize != spk.len() - 2 {
        return Err("not a witness program".into());
    }
    let ver = match spk[0] {
        0 => 0u8,
        0x51..=0x60 => spk[0] - 0x50,
        _ => return Err("not a witness program".into()),
    };
    let hrp = net.hrp();
    let mut data = vec![ver];
    data.extend(to_five(&spk[2..]));
    let mut vals = crate::wallet::hrp_expand(hrp);
    vals.extend(&data);
    vals.extend([0u8; 6]);
    let pm = crate::wallet::polymod(&vals) ^ if ver == 0 { 1 } else { 0x2bc830a3 };
    for i in 0..6 {
        data.push(((pm >> (5 * (5 - i))) & 31) as u8);
    }
    Ok(format!("{hrp}1{}", data.iter().map(|v| crate::wallet::B32[*v as usize] as char).collect::<String>()))
}
/// scriptPubKey of a segwit address on `net` (BIP-173 / BIP-350 rules).
pub fn decode_address(net: Net, s: &str) -> Result<Vec<u8>, String> {
    if s != s.to_ascii_lowercase() && s != s.to_ascii_uppercase() {
        return Err("mixed-case address".into());
    }
    let s = s.to_ascii_lowercase();
    let (hrp, rest) = s.rsplit_once('1').ok_or("not a bech32 address")?;
    if hrp != net.hrp() {
        return Err(format!("address is not for {} (expected prefix {}1)", net.name(), net.hrp()));
    }
    let five: Vec<u8> = rest.bytes().map(|c| crate::wallet::B32.iter().position(|x| *x == c).map(|p| p as u8)).collect::<Option<_>>().ok_or("bad bech32 character")?;
    if five.len() < 7 {
        return Err("address too short".into());
    }
    let mut vals = crate::wallet::hrp_expand(hrp);
    vals.extend(&five);
    let pm = crate::wallet::polymod(&vals);
    let ver = five[0];
    let want = if ver == 0 { 1 } else { 0x2bc830a3 };
    if pm != want {
        return Err("address checksum does not verify".into());
    }
    let (mut acc, mut bits, mut prog) = (0u32, 0u32, vec![]);
    for v in &five[1..five.len() - 6] {
        acc = (acc << 5) | *v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            prog.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return Err("address has non-zero padding".into());
    }
    if ver > 16 || prog.len() < 2 || prog.len() > 40 || (ver == 0 && prog.len() != 20 && prog.len() != 32) {
        return Err("invalid witness program".into());
    }
    Ok([vec![if ver == 0 { 0 } else { 0x50 + ver }, prog.len() as u8], prog].concat())
}

// ----------------------------------------------------------------- tx ----

#[derive(Clone, Debug, PartialEq)]
pub struct TxIn {
    /// Internal byte order (as serialized).
    pub txid: Key,
    pub vout: u32,
    pub sequence: u32,
}
#[derive(Clone, Debug, PartialEq)]
pub struct TxOut {
    pub value: u64,
    pub spk: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

struct Rd<'a>(&'a [u8], usize);
impl Rd<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let s = self.0.get(self.1..self.1 + n).ok_or("transaction truncated")?;
        self.1 += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn compact(&mut self) -> Result<usize, String> {
        let b = self.take(1)?[0];
        Ok(match b {
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize,
            0xfe => u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize,
            0xff => return Err("oversized compact size".into()),
            n => n as usize,
        })
    }
}

impl Tx {
    /// An unsigned transaction: legacy serialization (no witness), empty scriptSigs.
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        let mut r = Rd(b, 0);
        let version = r.u32()?;
        let n = r.compact()?;
        if n == 0 {
            return Err("unsigned transaction must not use the witness serialization".into());
        }
        let mut inputs = vec![];
        for _ in 0..n {
            let txid: Key = r.take(32)?.try_into().unwrap();
            let vout = r.u32()?;
            if r.compact()? != 0 {
                return Err("scriptSig must be empty".into());
            }
            inputs.push(TxIn { txid, vout, sequence: r.u32()? });
        }
        let m = r.compact()?;
        let mut outputs = vec![];
        for _ in 0..m {
            let value = r.u64()?;
            let l = r.compact()?;
            outputs.push(TxOut { value, spk: r.take(l)?.to_vec() });
        }
        let locktime = r.u32()?;
        if r.1 != b.len() {
            return Err("trailing bytes after transaction".into());
        }
        Ok(Self { version, inputs, outputs, locktime })
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = self.version.to_le_bytes().to_vec();
        v.extend(compact(self.inputs.len()));
        for i in &self.inputs {
            v.extend(i.txid);
            v.extend(i.vout.to_le_bytes());
            v.push(0);
            v.extend(i.sequence.to_le_bytes());
        }
        v.extend(compact(self.outputs.len()));
        for o in &self.outputs {
            v.extend(ser_out(o));
        }
        v.extend(self.locktime.to_le_bytes());
        v
    }
    /// Display-order txid (witness data does not change it).
    pub fn txid(&self) -> Key {
        let mut t: Key = Sha256::digest(Sha256::digest(self.serialize())).into();
        t.reverse();
        t
    }
}
fn ser_out(o: &TxOut) -> Vec<u8> {
    let mut v = o.value.to_le_bytes().to_vec();
    v.extend(compact(o.spk.len()));
    v.extend(&o.spk);
    v
}
fn sha(b: &[u8]) -> Key {
    Sha256::digest(b).into()
}
pub fn rev(k: &Key) -> Key {
    let mut x = *k;
    x.reverse();
    x
}

/// BIP-341 signature message of script-path input `i` (ext_flag 1, no annex, key version 0,
/// no OP_CODESEPARATOR) through leaf `leaf`, for hash types 0x00, 0x01, 0x02, 0x03 and their ACP forms.
pub fn tap_sighash(tx: &Tx, prevouts: &[(u64, Vec<u8>)], i: usize, hash_type: u8, leaf: &Key) -> Result<Key, String> {
    if !matches!(hash_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83) {
        return Err("unsupported hash type".into());
    }
    if prevouts.len() != tx.inputs.len() || i >= tx.inputs.len() {
        return Err("prevouts do not match the inputs".into());
    }
    let acp = hash_type & 0x80 != 0;
    let out_type = if hash_type == 0 { 1 } else { hash_type & 3 };
    let mut m = vec![0u8, hash_type];
    m.extend(tx.version.to_le_bytes());
    m.extend(tx.locktime.to_le_bytes());
    if !acp {
        m.extend(sha(&tx.inputs.iter().flat_map(|x| [x.txid.to_vec(), x.vout.to_le_bytes().to_vec()].concat()).collect::<Vec<u8>>()));
        m.extend(sha(&prevouts.iter().flat_map(|p| p.0.to_le_bytes()).collect::<Vec<u8>>()));
        m.extend(sha(&prevouts.iter().flat_map(|p| [compact(p.1.len()), p.1.clone()].concat()).collect::<Vec<u8>>()));
        m.extend(sha(&tx.inputs.iter().flat_map(|x| x.sequence.to_le_bytes()).collect::<Vec<u8>>()));
    }
    if out_type == 1 {
        m.extend(sha(&tx.outputs.iter().flat_map(ser_out).collect::<Vec<u8>>()));
    }
    m.push(2); // ext_flag 1, no annex
    if acp {
        let x = &tx.inputs[i];
        m.extend(x.txid);
        m.extend(x.vout.to_le_bytes());
        m.extend(prevouts[i].0.to_le_bytes());
        m.extend(compact(prevouts[i].1.len()));
        m.extend(&prevouts[i].1);
        m.extend(x.sequence.to_le_bytes());
    } else {
        m.extend((i as u32).to_le_bytes());
    }
    if out_type == 3 {
        let o = tx.outputs.get(i).ok_or("SIGHASH_SINGLE without a matching output")?;
        m.extend(sha(&ser_out(o)));
    }
    m.extend(leaf);
    m.push(0);
    m.extend(u32::MAX.to_le_bytes());
    Ok(tagged_hash(b"TapSighash", &m))
}

pub fn package_id(raw: &[u8], through: u64) -> Key {
    tagged_hash(TAG_PACKAGE, &[raw, &through.to_le_bytes()].concat())
}
pub fn withdraw_digest(owner: &Key, sats: u64, spk: &[u8], nonce_us: u64) -> Key {
    let mut m = owner.to_vec();
    m.extend(sats.to_le_bytes());
    m.push(spk.len() as u8);
    m.extend(spk);
    m.extend(nonce_us.to_le_bytes());
    tagged_hash(TAG_WITHDRAW, &m)
}

// ---------------------------------------------------------------- rpc ----

fn b64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// One bitcoind JSON-RPC call over plain HTTP (loopback node). Errors carry bitcoind's message.
pub async fn rpc(cfg: &ChainCfg, method: &str, params: Value) -> Result<Value, String> {
    let url = cfg.rpc_url.strip_prefix("http://").ok_or("--bitcoind-rpc must be http://host:port[/wallet/name]")?;
    let (hostport, path) = url.split_once('/').map(|(a, b)| (a, format!("/{b}"))).unwrap_or((url, "/".into()));
    let body = json!({"jsonrpc": "1.0", "id": "shz-venue", "method": method, "params": params}).to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        b64(cfg.rpc_auth.as_bytes()),
        body.len()
    );
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(hostport).await.map_err(|e| format!("bitcoind connect: {e}"))?;
        s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut buf = vec![];
        s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
        Ok::<_, String>(buf)
    };
    let buf = tokio::time::timeout(Duration::from_secs(300), fut).await.map_err(|_| "bitcoind timeout".to_string())??;
    let p = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("bitcoind: bad HTTP response")?;
    let head = String::from_utf8_lossy(&buf[..p]).to_string();
    if head.starts_with("HTTP/1.1 401") {
        return Err("bitcoind: unauthorized (check --bitcoind-auth-file)".into());
    }
    let mut body = buf[p + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut out = vec![];
        let mut i = 0;
        while let Some(e) = body[i..].windows(2).position(|w| w == b"\r\n") {
            let n = usize::from_str_radix(String::from_utf8_lossy(&body[i..i + e]).trim(), 16).unwrap_or(0);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&body[i + e + 2..(i + e + 2 + n).min(body.len())]);
            i += e + 2 + n + 2;
        }
        body = out;
    }
    let v: Value = serde_json::from_slice(&body).map_err(|_| format!("bitcoind: {}", head.lines().next().unwrap_or("")))?;
    if !v["error"].is_null() {
        return Err(format!("bitcoind {method}: {}", v["error"]["message"].as_str().unwrap_or("error")));
    }
    Ok(v["result"].clone())
}

// -------------------------------------------------------------- state ----

#[derive(Clone, Debug)]
pub struct AddrRec {
    pub refund_height: u32,
    pub issued_height: u32,
}
#[derive(Clone, Debug)]
pub struct Seen {
    /// Display order.
    pub txid: Key,
    pub vout: u32,
    pub value: u64,
    pub height: u32,
}
#[derive(Clone, Debug)]
pub struct Acct {
    pub channel: BtcOutPoint,
    /// Current collateral output (display-order txid).
    pub txid: Key,
    pub vout: u32,
    pub value: u64,
    pub refund_height: u32,
    pub deposit_height: u32,
    /// Last venue batch whose net is in `value`.
    pub settled_through: u64,
    pub closed: Option<String>,
    pub last_nonce: u64,
}
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub id: String,
    pub owner: Key,
    pub sats: u64,
    pub spk: Vec<u8>,
    pub address: String,
    pub status: String,
    pub package: Option<Key>,
    pub txid: Option<Key>,
    pub requested_us: u64,
}
#[derive(Clone, Debug)]
pub struct PkgAcct {
    pub owner: Key,
    pub input: usize,
    pub hash_type: u8,
    pub outputs: Vec<usize>,
    pub sighash: Key,
    pub from: u64,
    pub net: i64,
    pub value_in: u64,
    pub refund_in: u32,
    pub rollover: Option<(usize, u64)>,
    pub withdraw: Option<(usize, u64, String)>,
    pub batches: Vec<u64>,
}
#[derive(Clone, Debug)]
pub struct Package {
    pub id: Key,
    pub event_id: String,
    pub through: u64,
    pub tx: Tx,
    pub prevouts: Vec<(u64, Vec<u8>)>,
    pub refund_height: u32,
    pub accounts: Vec<PkgAcct>,
    pub sigs: BTreeMap<Key, Vec<u8>>,
    pub created_us: u64,
    pub broadcast: bool,
}
impl Package {
    pub fn complete(&self) -> bool {
        self.accounts.iter().all(|a| self.sigs.contains_key(&a.owner))
    }
}

pub struct CollState {
    pub cfg: ChainCfg,
    pub tip: u32,
    pub addrs: BTreeMap<Key, AddrRec>,
    pub seen: BTreeMap<Key, Seen>,
    pub accts: BTreeMap<Key, Acct>,
    pub withdrawals: BTreeMap<String, Withdrawal>,
    pub package: Option<Package>,
    pub history: Vec<Value>,
    pub rpc_error: Option<String>,
    pub scanned_tip: u32,
}

/// Outputs the venue requires for one account at `through` with rollover refund height `h_next`.
#[derive(Clone, Debug, PartialEq)]
pub struct Required {
    pub from: u64,
    pub net: i64,
    pub value_after: i64,
    pub rollover: Option<(u64, Vec<u8>)>,
    pub withdraw: Option<(u64, Vec<u8>, String)>,
    pub deferred: Option<String>,
    pub batches: Vec<u64>,
}

impl CollState {
    pub fn new(cfg: ChainCfg) -> Self {
        Self { cfg, tip: 0, addrs: BTreeMap::new(), seen: BTreeMap::new(), accts: BTreeMap::new(), withdrawals: BTreeMap::new(), package: None, history: vec![], rpc_error: None, scanned_tip: 0 }
    }
    pub fn script(&self, owner: &Key, refund_height: u32) -> Result<AccountScript, String> {
        AccountScript::new(owner, &self.cfg.batcher, refund_height)
    }
    fn pending_withdrawal(&self, owner: &Key) -> Option<&Withdrawal> {
        self.withdrawals.values().find(|w| w.owner == *owner && (w.status == "pending" || w.status == "included"))
    }

    /// Fold one journaled `coll_*` record in (startup replay and live writes share this).
    pub fn apply(&mut self, e: &Value) -> Result<(), String> {
        let owner = || parse_key(e["owner"].as_str().unwrap_or(""));
        match e["kind"].as_str().unwrap_or("") {
            "coll_addr" => {
                self.addrs.insert(owner()?, AddrRec { refund_height: e["refund_height"].as_u64().unwrap_or(0) as u32, issued_height: e["issued_height"].as_u64().unwrap_or(0) as u32 });
            }
            "coll_deposit" => {
                let o = owner()?;
                let txid = parse_key(e["txid"].as_str().unwrap_or(""))?;
                let vout = e["vout"].as_u64().unwrap_or(0) as u32;
                self.accts.insert(o, Acct {
                    channel: BtcOutPoint { txid, vout },
                    txid,
                    vout,
                    value: e["value"].as_u64().unwrap_or(0),
                    refund_height: e["refund_height"].as_u64().unwrap_or(0) as u32,
                    deposit_height: e["height"].as_u64().unwrap_or(0) as u32,
                    settled_through: e["settled_through"].as_u64().unwrap_or(0),
                    closed: None,
                    last_nonce: 0,
                });
            }
            "coll_withdraw" => {
                let o = owner()?;
                let id = e["id"].as_str().unwrap_or("").to_string();
                if let Some(a) = self.accts.get_mut(&o) {
                    a.last_nonce = a.last_nonce.max(e["nonce_us"].as_u64().unwrap_or(0));
                }
                self.withdrawals.insert(id.clone(), Withdrawal {
                    id,
                    owner: o,
                    sats: e["sats"].as_u64().unwrap_or(0),
                    spk: hex::decode(e["spk"].as_str().unwrap_or("")).map_err(|_| "bad spk")?,
                    address: e["address"].as_str().unwrap_or("").into(),
                    status: "pending".into(),
                    package: None,
                    txid: None,
                    requested_us: e["requested_us"].as_u64().unwrap_or(0),
                });
            }
            "coll_settled" => {
                let txid = parse_key(e["txid"].as_str().unwrap_or(""))?;
                let through = e["through"].as_u64().unwrap_or(0);
                for a in e["accounts"].as_array().cloned().unwrap_or_default() {
                    let o = parse_key(a["owner"].as_str().unwrap_or(""))?;
                    if let Some(w) = a["withdraw_id"].as_str().and_then(|id| self.withdrawals.get_mut(id)) {
                        w.status = "paid".into();
                        w.txid = Some(txid);
                    }
                    let Some(acct) = self.accts.get_mut(&o) else { continue };
                    acct.settled_through = through;
                    match a["rollover"].as_object() {
                        Some(r) => {
                            acct.txid = txid;
                            acct.vout = r["vout"].as_u64().unwrap_or(0) as u32;
                            acct.value = r["value"].as_u64().unwrap_or(0);
                            acct.refund_height = r["refund_height"].as_u64().unwrap_or(0) as u32;
                        }
                        None => {
                            acct.value = 0;
                            acct.closed = Some(format!("withdrawn in full by settlement {}", h(&txid)));
                        }
                    }
                }
                self.history.push(e.clone());
            }
            "coll_closed" => {
                if let Some(a) = self.accts.get_mut(&owner()?) {
                    a.closed = Some(e["reason"].as_str().unwrap_or("closed").into());
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// ---------------------------------------------------------- venue api ----

impl Venue {
    fn coll(&self) -> Result<&CollState, String> {
        self.coll.as_ref().ok_or_else(|| "collateral accounts are off on this venue (no --collateral-chain)".to_string())
    }
    fn coll_mut(&mut self) -> Result<&mut CollState, String> {
        self.coll.as_mut().ok_or_else(|| "collateral accounts are off on this venue (no --collateral-chain)".to_string())
    }
    fn coll_record(&mut self, e: Value) -> Result<(), String> {
        self.coll_mut()?.apply(&e)?;
        self.persist(e);
        self.emit(json!({"type": "account"}));
        self.emit(json!({"type": "collateral"}));
        Ok(())
    }

    /// Switch collateral accounts on: fold the journaled `coll_*` records in.
    pub fn collateral_enable(&mut self, cfg: ChainCfg) -> Result<String, String> {
        let mut st = CollState::new(cfg);
        for e in std::mem::take(&mut self.coll_log) {
            st.apply(&e)?;
        }
        let s = format!("{} batcher={} refund_blocks={} min_conf={} accounts={}", st.cfg.net.name(), h(&st.cfg.batcher), st.cfg.refund_blocks, st.cfg.min_conf, st.accts.len());
        self.coll = Some(st);
        Ok(s)
    }

    /// Intents from a collateral account that has closed (withdrawn in full, refunded) are refused.
    pub fn collateral_gate(&self, owner: &Key) -> Result<(), String> {
        match self.coll.as_ref().and_then(|c| c.accts.get(owner)).and_then(|a| a.closed.clone()) {
            Some(why) => Err(format!("collateral account closed: {why}")),
            None => Ok(()),
        }
    }

    /// The deposit address of `owner`: issued once (journaled) and re-issued with a later refund
    /// height when the old one is too close to its refund height and still unfunded.
    pub fn collateral_address(&mut self, owner: Key) -> Result<Value, String> {
        shz_dlc::lift_x_even(&owner).map_err(|_| "owner is not a valid x-only key")?;
        let c = self.coll()?;
        if c.tip == 0 {
            return Err(format!("chain not synced yet{}", c.rpc_error.as_ref().map(|e| format!(": {e}")).unwrap_or_default()));
        }
        let stale = match c.addrs.get(&owner) {
            None => true,
            Some(a) => !c.accts.contains_key(&owner) && !c.seen.contains_key(&owner) && a.refund_height < c.tip + c.cfg.min_lock,
        };
        if stale && c.accts.contains_key(&owner) {
            return self.collateral_view(&owner);
        }
        if stale {
            let (tip, rb) = (c.tip, c.cfg.refund_blocks);
            self.coll_record(json!({"kind": "coll_addr", "owner": h(&owner), "refund_height": tip + rb, "issued_height": tip}))?;
        }
        self.collateral_view(&owner)
    }

    /// Everything the UI shows about one owner's on-chain collateral.
    pub fn collateral_view(&self, owner: &Key) -> Result<Value, String> {
        let c = self.coll()?;
        let net = c.cfg.net;
        let addr = c.addrs.get(owner).map(|a| {
            let s = c.script(owner, a.refund_height);
            json!({"refund_height": a.refund_height, "issued_height": a.issued_height, "script": s.as_ref().ok().map(|s| s.json(net)),
                   "address": s.ok().and_then(|s| address(net, &s.spk()).ok()), "credit_by_height": a.refund_height.saturating_sub(c.cfg.min_lock)})
        });
        let seen = c.seen.get(owner).map(|d| {
            let conf = if d.height == 0 { 0 } else { c.tip.saturating_sub(d.height) + 1 };
            json!({"txid": h(&d.txid), "vout": d.vout, "value": d.value, "height": d.height, "confirmations": conf, "required": c.cfg.min_conf,
                   "ready": conf >= c.cfg.min_conf, "explorer_url": net.explorer_tx(&h(&d.txid))})
        });
        let acct = c.accts.get(owner).map(|a| {
            let s = c.script(owner, a.refund_height).ok();
            json!({"channel": {"txid": h(&a.channel.txid), "vout": a.channel.vout}, "outpoint": {"txid": h(&a.txid), "vout": a.vout},
                   "value": a.value, "deposit_height": a.deposit_height, "refund_height": a.refund_height, "blocks_to_refund": a.refund_height as i64 - c.tip as i64,
                   "settled_through": a.settled_through, "closed": a.closed, "script": s.map(|s| s.json(net)),
                   "explorer_url": net.explorer_tx(&h(&a.txid))})
        });
        let withdrawals: Vec<Value> = c.withdrawals.values().filter(|w| w.owner == *owner).map(withdrawal_json).collect();
        let pkg = c.package.as_ref().and_then(|p| p.accounts.iter().find(|a| a.owner == *owner).map(|a| json!({"package_id": h(&p.id), "signed": p.sigs.contains_key(owner), "input": a.input, "through": p.through})));
        Ok(json!({"network": net.name(), "tip_height": c.tip, "batcher_key": h(&c.cfg.batcher), "min_conf": c.cfg.min_conf,
                  "deposit": addr, "seen": seen, "account": acct, "withdrawals": withdrawals, "settlement": pkg}))
    }

    /// Draft of a `collateral` registration from the watcher's confirmed deposit (never client input).
    pub(crate) fn collateral_draft_source(&self, owner: &Key) -> Result<(BtcOutPoint, u64, String), String> {
        let c = self.coll()?;
        let a = c.addrs.get(owner).ok_or("no deposit address issued for this key")?;
        let d = c.seen.get(owner).ok_or("no deposit seen yet")?;
        let conf = if d.height == 0 { 0 } else { c.tip.saturating_sub(d.height) + 1 };
        if conf < c.cfg.min_conf {
            return Err(format!("deposit has {conf} of {} confirmations", c.cfg.min_conf));
        }
        if a.refund_height < d.height + c.cfg.min_lock {
            return Err(format!("deposit at height {} is too close to the address's refund height {}; request a new address and refund this output at its refund height", d.height, a.refund_height));
        }
        Ok((BtcOutPoint { txid: d.txid, vout: d.vout }, d.value, format!("{} collateral", c.cfg.net.name())))
    }

    /// Called by `register` for a `collateral` account: journal the credited deposit.
    pub(crate) fn collateral_registered(&mut self, owner: &Key) -> Result<(), String> {
        let c = self.coll()?;
        let a = c.addrs.get(owner).ok_or("no deposit address")?.clone();
        let d = c.seen.get(owner).ok_or("no deposit")?.clone();
        let through = self.router.next_resolution().map_err(|e| e.to_string())?.saturating_sub(1);
        self.coll_record(json!({"kind": "coll_deposit", "owner": h(owner), "txid": h(&d.txid), "vout": d.vout, "value": d.value,
                                "height": d.height, "refund_height": a.refund_height, "settled_through": through, "credited_us": now_us()}))
    }

    /// Owner-signed withdrawal of free collateral to `address`; debited from the router now,
    /// paid by the next settlement that includes the account.
    pub fn collateral_withdraw(&mut self, j: &Value) -> Result<Value, String> {
        let owner = parse_key(j["owner"].as_str().ok_or("owner required")?)?;
        let sats = j["sats"].as_u64().ok_or("sats required")?;
        let address_s = j["address"].as_str().ok_or("address required")?.trim().to_string();
        let nonce = j["nonce_us"].as_u64().ok_or("nonce_us required")?;
        let sig = parse_sig(j["signature"].as_str().ok_or("signature required")?)?;
        let c = self.coll()?;
        let spk = decode_address(c.cfg.net, &address_s)?;
        let a = c.accts.get(&owner).ok_or("no collateral account for this key")?.clone();
        if let Some(why) = &a.closed {
            return Err(format!("account closed: {why}"));
        }
        if nonce <= a.last_nonce {
            return Err("nonce_us must increase".into());
        }
        if sats < DUST {
            return Err(format!("withdrawals start at {DUST} sats"));
        }
        if c.pending_withdrawal(&owner).is_some() {
            return Err("a withdrawal is already pending for this account".into());
        }
        bip340_verify(&owner, &withdraw_digest(&owner, sats, &spk, nonce), &sig).map_err(|_| "withdrawal signature does not verify")?;
        let free = self.balance(&owner).map(|b| b.free).unwrap_or(0);
        if sats > free {
            return Err(format!("only {free} sats are free (open orders and positions hold the rest)"));
        }
        self.router.collateral_transfer(a.channel.clone(), sats, false).map_err(|e| format!("withdraw: {e}"))?;
        let id = h(&withdraw_digest(&owner, sats, &spk, nonce))[..16].to_string();
        self.coll_record(json!({"kind": "coll_withdraw", "id": id, "owner": h(&owner), "sats": sats, "spk": h(&spk), "address": address_s,
                                "nonce_us": nonce, "requested_us": now_us(), "signature": hex::encode(sig.to_bytes())}))?;
        Ok(withdrawal_json(&self.coll()?.withdrawals[&id]))
    }

    /// Highest batch every earlier batch of which has resolved.
    fn resolved_through(&self) -> u64 {
        self.router.next_resolution().unwrap_or(1).saturating_sub(1)
    }

    /// Outputs the venue requires for `owner` at `through`, rollover refund height `h_next`.
    pub fn collateral_required(&self, owner: &Key, through: u64, h_next: u32) -> Result<Required, String> {
        let c = self.coll()?;
        let a = c.accts.get(owner).ok_or("no collateral account")?;
        let mut net = 0i64;
        let mut batches = vec![];
        for seq in a.settled_through + 1..=through {
            if let Ok(Some(cl)) = self.router.clearing(seq) {
                let mut hit = false;
                for r in cl.rows.iter().filter(|r| r.channel == a.channel) {
                    net += r.net;
                    hit = true;
                }
                if hit {
                    batches.push(seq);
                }
            }
        }
        let value_after = a.value as i64 + net;
        if value_after < 0 {
            return Err(format!("account value after net is negative ({value_after})"));
        }
        let mut w = c.pending_withdrawal(owner).map(|w| (w.sats, w.spk.clone(), w.id.clone()));
        let mut deferred = None;
        if let Some((ws, _, _)) = &w
            && *ws as i64 > value_after
        {
            deferred = Some(format!("withdrawal of {ws} exceeds the account's settled value {value_after}"));
            w = None;
        }
        let mut rem = value_after - w.as_ref().map(|x| x.0 as i64).unwrap_or(0);
        if let Some(x) = w.as_mut()
            && rem > 0
            && (rem as u64) < DUST
        {
            x.0 = value_after as u64;
            rem = 0;
        }
        if w.is_none() && (rem as u64) < DUST {
            return Err(format!("account value {rem} is below dust"));
        }
        let rollover = (rem > 0).then(|| -> Result<_, String> { Ok((rem as u64, c.script(owner, h_next)?.spk())) }).transpose()?;
        Ok(Required { from: a.settled_through, net, value_after, rollover, withdraw: w, deferred, batches })
    }

    /// `GET /api/settlement/epoch`: what the settler should settle now.
    pub fn settlement_epoch(&self) -> Result<Value, String> {
        let c = self.coll()?;
        let through = self.resolved_through();
        let h_next = c.tip + c.cfg.refund_blocks;
        let mut accounts = vec![];
        for (o, a) in &c.accts {
            if a.closed.is_some() {
                continue;
            }
            let s = c.script(o, a.refund_height)?;
            let base = json!({"owner": h(o), "channel": {"txid": h(&a.channel.txid), "vout": a.channel.vout},
                "collateral": {"txid": h(&a.txid), "vout": a.vout, "value": a.value, "refund_height": a.refund_height, "spk": h(&s.spk()),
                               "settle_script": h(&s.settle), "settle_control": h(&s.control(0))}});
            let mut x = base;
            match self.collateral_required(o, through, h_next) {
                Ok(r) => {
                    let mut outs = vec![];
                    if let Some((v, spk)) = &r.rollover {
                        outs.push(json!({"role": "rollover", "value": v, "spk": h(spk), "refund_height": h_next}));
                    }
                    if let Some((v, spk, id)) = &r.withdraw {
                        outs.push(json!({"role": "withdraw", "value": v, "spk": h(spk), "withdraw_id": id}));
                    }
                    x["from_batch"] = json!(r.from);
                    x["net_sats"] = json!(r.net);
                    x["batches"] = json!(r.batches);
                    x["withdraw"] = json!(r.withdraw.as_ref().map(|(v, spk, id)| json!({"id": id, "sats": v, "spk": h(spk)})));
                    x["withdraw_deferred"] = json!(r.deferred);
                    x["outputs"] = json!(outs);
                    x["touched"] = json!(r.net != 0 || r.withdraw.is_some());
                }
                Err(e) => {
                    x["error"] = json!(e);
                    x["touched"] = json!(false);
                }
            }
            accounts.push(x);
        }
        Ok(json!({"network": c.cfg.net.name(), "batcher_key": h(&c.cfg.batcher), "through_batch": through, "tip_height": c.tip,
                  "refund_height": h_next, "refund_window": [c.tip + c.cfg.min_lock, c.tip + c.cfg.refund_blocks + 12],
                  "open_package": c.package.as_ref().map(|p| h(&p.id)), "accounts": accounts}))
    }

    /// `POST /api/settlement/package`: check the settler's unsigned settlement against the venue's
    /// own epoch view and compute every account's sighash.
    pub fn settlement_package(&mut self, j: &Value) -> Result<Value, String> {
        let raw = hex::decode(j["tx"].as_str().ok_or("tx required")?).map_err(|_| "tx: bad hex")?;
        let tx = Tx::parse(&raw)?;
        let through = j["through_batch"].as_u64().ok_or("through_batch required")?;
        let id = package_id(&raw, through);
        let c = self.coll()?;
        let sig = parse_sig(j["batcher_signature"].as_str().ok_or("batcher_signature required")?)?;
        bip340_verify(&c.cfg.batcher, &id, &sig).map_err(|_| "batcher_signature does not verify under --batcher-key")?;
        if let Some(p) = &c.package
            && p.broadcast
        {
            return Err(format!("package {} is broadcast; wait for it to confirm", h(&p.id)));
        }
        if through > self.resolved_through() {
            return Err(format!("through_batch {through} has not resolved (resolved through {})", self.resolved_through()));
        }
        let refund_height = j["refund_height"].as_u64().ok_or("refund_height required")? as u32;
        let (lo, hi) = (c.tip + c.cfg.min_lock, c.tip + c.cfg.refund_blocks + 12);
        if refund_height < lo || refund_height > hi {
            return Err(format!("refund_height {refund_height} outside [{lo}, {hi}]"));
        }
        let prevouts: Vec<(u64, Vec<u8>)> = j["prevouts"]
            .as_array()
            .ok_or("prevouts required")?
            .iter()
            .map(|p| Ok((p["value"].as_u64().ok_or("prevout value")?, hex::decode(p["spk"].as_str().ok_or("prevout spk")?).map_err(|_| "prevout spk hex")?)))
            .collect::<Result<_, String>>()?;
        if prevouts.len() != tx.inputs.len() {
            return Err("one prevout per input".into());
        }
        let mut accounts = vec![];
        let mut used_in = std::collections::BTreeSet::new();
        let mut used_out = std::collections::BTreeSet::new();
        for x in j["accounts"].as_array().ok_or("accounts required")? {
            let owner = parse_key(x["owner"].as_str().ok_or("account owner")?)?;
            let input = x["input"].as_u64().ok_or("account input")? as usize;
            let hash_type = x["hash_type"].as_u64().ok_or("account hash_type")? as u8;
            let outputs: Vec<usize> = x["outputs"].as_array().ok_or("account outputs")?.iter().map(|o| o.as_u64().map(|v| v as usize).ok_or("output index")).collect::<Result<_, _>>()?;
            let a = c.accts.get(&owner).ok_or_else(|| format!("{}: no collateral account", h(&owner)))?;
            if let Some(why) = &a.closed {
                return Err(format!("{}: closed ({why})", h(&owner)));
            }
            if through < a.settled_through {
                return Err(format!("{}: already settled through {}", h(&owner), a.settled_through));
            }
            if !used_in.insert(input) || input >= tx.inputs.len() {
                return Err(format!("{}: input {input} is out of range or used twice", h(&owner)));
            }
            let ti = &tx.inputs[input];
            if rev(&ti.txid) != a.txid || ti.vout != a.vout {
                return Err(format!("{}: input {input} does not spend the account's collateral {}:{}", h(&owner), h(&a.txid), a.vout));
            }
            let s = c.script(&owner, a.refund_height)?;
            if prevouts[input] != (a.value, s.spk()) {
                return Err(format!("{}: prevout {input} is not the account's value and script", h(&owner)));
            }
            for o in &outputs {
                if *o >= tx.outputs.len() || !used_out.insert(*o) {
                    return Err(format!("{}: output {o} is out of range or used twice", h(&owner)));
                }
            }
            match hash_type {
                0x83 if outputs != vec![input] => return Err(format!("{}: SIGHASH_SINGLE|ANYONECANPAY needs exactly one output at index {input}", h(&owner))),
                0x00 | 0x01 | 0x81 | 0x83 => {}
                _ => return Err(format!("{}: hash type {hash_type:#x} not allowed (0x00, 0x01, 0x81, 0x83)", h(&owner))),
            }
            let r = self.collateral_required(&owner, through, refund_height)?;
            let mut want: Vec<(u64, Vec<u8>)> = r.rollover.iter().cloned().chain(r.withdraw.iter().map(|w| (w.0, w.1.clone()))).collect();
            let mut got: Vec<(u64, Vec<u8>)> = outputs.iter().map(|o| (tx.outputs[*o].value, tx.outputs[*o].spk.clone())).collect();
            want.sort();
            got.sort();
            if want != got {
                return Err(format!("{}: outputs differ from the venue's (want {})", h(&owner),
                    want.iter().map(|(v, s)| format!("{v} to {}", h(s))).collect::<Vec<_>>().join(", ")));
            }
            let find = |v: u64, spk: &[u8]| outputs.iter().copied().find(|o| tx.outputs[*o].value == v && tx.outputs[*o].spk == spk);
            let rollover = r.rollover.as_ref().map(|(v, spk)| (find(*v, spk).unwrap(), *v));
            let withdraw = r.withdraw.as_ref().map(|(v, spk, id)| (outputs.iter().copied().find(|o| tx.outputs[*o].value == *v && tx.outputs[*o].spk == *spk && Some(*o) != rollover.map(|r| r.0)).unwrap(), *v, id.clone()));
            let sighash = tap_sighash(&tx, &prevouts, input, hash_type, &tapleaf(&s.settle))?;
            accounts.push(PkgAcct { owner, input, hash_type, outputs, sighash, from: r.from, net: r.net, value_in: a.value, refund_in: a.refund_height, rollover, withdraw, batches: r.batches });
        }
        if accounts.is_empty() {
            return Err("a package settles at least one account".into());
        }
        let pkg = Package { id, event_id: j["event_id"].as_str().unwrap_or("").into(), through, tx, prevouts, refund_height, accounts, sigs: BTreeMap::new(), created_us: now_us(), broadcast: false };
        let st = self.coll_mut()?;
        for w in st.withdrawals.values_mut().filter(|w| w.status == "included") {
            w.status = "pending".into();
            w.package = None;
        }
        for a in &pkg.accounts {
            if let Some((_, _, wid)) = &a.withdraw
                && let Some(w) = st.withdrawals.get_mut(wid)
            {
                w.status = "included".into();
                w.package = Some(id);
            }
        }
        let sighashes: BTreeMap<String, String> = pkg.accounts.iter().map(|a| (h(&a.owner), h(&a.sighash))).collect();
        let txid = pkg.tx.txid();
        st.package = Some(pkg);
        self.emit(json!({"type": "account"}));
        self.emit(json!({"type": "settlement", "package_id": h(&id), "phase": "signing"}));
        Ok(json!({"package_id": h(&id), "txid": h(&txid), "sighashes": sighashes}))
    }

    pub fn settlement_package_view(&self, id: &Key) -> Result<Value, String> {
        let c = self.coll()?;
        let p = c.package.as_ref().filter(|p| p.id == *id).ok_or("no such open package")?;
        Ok(package_json(c, p))
    }
    pub fn settlement_open(&self) -> Result<Value, String> {
        let c = self.coll()?;
        Ok(c.package.as_ref().map(|p| package_json(c, p)).unwrap_or(Value::Null))
    }

    /// `POST /api/settlement/sign`: the owner's signature of its own input.
    pub fn settlement_sign(&mut self, j: &Value) -> Result<Value, String> {
        let id = parse_key(j["package_id"].as_str().ok_or("package_id required")?)?;
        let owner = parse_key(j["owner"].as_str().ok_or("owner required")?)?;
        let sig = hex::decode(j["signature"].as_str().ok_or("signature required")?).map_err(|_| "signature: bad hex")?;
        let st = self.coll_mut()?;
        let p = st.package.as_mut().filter(|p| p.id == id).ok_or("no such open package")?;
        let a = p.accounts.iter().find(|a| a.owner == owner).ok_or("this key has no input in the package")?;
        let want = if a.hash_type == 0 { 64 } else { 65 };
        if sig.len() != want || (want == 65 && sig[64] != a.hash_type) {
            return Err(format!("signature must be {want} bytes{}", if want == 65 { format!(" ending in hash type {:#04x}", a.hash_type) } else { String::new() }));
        }
        let s = parse_sig(&hex::encode(&sig[..64]))?;
        bip340_verify(&owner, &a.sighash, &s).map_err(|_| "signature does not verify against the input's sighash")?;
        p.sigs.insert(owner, sig);
        let done = p.complete();
        self.emit(json!({"type": "account"}));
        self.emit(json!({"type": "settlement", "package_id": h(&id), "phase": if done { "signed" } else { "signing" }}));
        Ok(json!({"accepted": true, "complete": done}))
    }

    /// `POST /api/settlement/broadcast`: the settler broadcast the package; the watcher confirms it.
    pub fn settlement_broadcast(&mut self, j: &Value) -> Result<Value, String> {
        let id = parse_key(j["package_id"].as_str().ok_or("package_id required")?)?;
        let txid = parse_key(j["txid"].as_str().ok_or("txid required")?)?;
        let st = self.coll_mut()?;
        let batcher = st.cfg.batcher;
        let p = st.package.as_mut().filter(|p| p.id == id).ok_or("no such open package")?;
        if p.tx.txid() != txid {
            return Err("txid is not the package transaction's".into());
        }
        if let Some(s) = j["batcher_signature"].as_str() {
            let s = parse_sig(s)?;
            bip340_verify(&batcher, &tagged_hash(TAG_BROADCAST, &[id.as_slice(), &txid].concat()), &s).map_err(|_| "batcher_signature does not verify")?;
        }
        if !p.complete() {
            return Err("package is not fully signed".into());
        }
        p.broadcast = true;
        self.emit(json!({"type": "settlement", "package_id": h(&id), "phase": "broadcast"}));
        Ok(json!({"accepted": true}))
    }

    pub fn collateral_summary(&self) -> Value {
        let Some(c) = self.coll.as_ref() else { return Value::Null };
        json!({"network": c.cfg.net.name(), "tip_height": c.tip, "batcher_key": h(&c.cfg.batcher), "accounts": c.accts.len(),
               "open_package": c.package.as_ref().map(|p| h(&p.id)), "settlements": c.history.len(), "rpc_error": c.rpc_error,
               "min_conf": c.cfg.min_conf, "refund_blocks": c.cfg.refund_blocks})
    }
    pub fn settlement_history(&self, limit: usize) -> Result<Value, String> {
        Ok(json!(self.coll()?.history.iter().rev().take(limit).cloned().collect::<Vec<_>>()))
    }
}

fn withdrawal_json(w: &Withdrawal) -> Value {
    json!({"id": w.id, "owner": h(&w.owner), "sats": w.sats, "address": w.address, "spk": h(&w.spk), "status": w.status,
           "package_id": w.package.map(|p| h(&p)), "txid": w.txid.map(|t| h(&t)), "requested_us": w.requested_us})
}

fn package_json(c: &CollState, p: &Package) -> Value {
    let net = c.cfg.net;
    json!({
        "package_id": h(&p.id), "event_id": p.event_id, "through_batch": p.through, "network": net.name(),
        "tx": h(&p.tx.serialize()), "txid": h(&p.tx.txid()), "refund_height": p.refund_height, "batcher_key": h(&c.cfg.batcher),
        "prevouts": p.prevouts.iter().map(|(v, s)| json!({"value": v, "spk": h(s)})).collect::<Vec<_>>(),
        "outputs": p.tx.outputs.iter().map(|o| json!({"value": o.value, "spk": h(&o.spk), "address": address(net, &o.spk).ok()})).collect::<Vec<_>>(),
        "accounts": p.accounts.iter().map(|a| {
            let s = c.script(&a.owner, a.refund_in).ok();
            json!({"owner": h(&a.owner), "input": a.input, "hash_type": a.hash_type, "outputs": a.outputs, "sighash": h(&a.sighash),
                   "from_batch": a.from, "net_sats": a.net, "value_in": a.value_in, "refund_height_in": a.refund_in, "batches": a.batches,
                   "rollover": a.rollover.map(|(i, v)| json!({"index": i, "value": v, "refund_height": p.refund_height})),
                   "withdraw": a.withdraw.as_ref().map(|(i, v, id)| json!({"index": i, "value": v, "withdraw_id": id, "address": address(net, &p.tx.outputs[*i].spk).ok()})),
                   "settle_script": s.as_ref().map(|s| h(&s.settle)), "settle_control": s.as_ref().map(|s| h(&s.control(0))),
                   "signature": p.sigs.get(&a.owner).map(hex::encode)})
        }).collect::<Vec<_>>(),
        "signatures": p.sigs.iter().map(|(o, s)| (h(o), json!(hex::encode(s)))).collect::<serde_json::Map<_, _>>(),
        "complete": p.complete(), "broadcast": p.broadcast, "created_us": p.created_us,
    })
}

// ------------------------------------------------------------ watcher ----

/// Poll bitcoind: tip, deposits to issued addresses (`scantxoutset`), confirmation of the open
/// package, and collateral outputs spent outside a settlement (the refund path).
pub async fn run(venue: std::sync::Arc<tokio::sync::Mutex<Venue>>) {
    let mut ticks = 0u64;
    loop {
        let cfg = match venue.lock().await.coll.as_ref() {
            Some(c) => c.cfg.clone(),
            None => return,
        };
        tokio::time::sleep(Duration::from_millis(if ticks == 0 { 0 } else { cfg.poll_ms })).await;
        ticks += 1;
        if let Err(e) = watch_once(&venue, &cfg).await {
            let mut v = venue.lock().await;
            if let Some(c) = v.coll.as_mut() {
                if c.rpc_error.as_deref() != Some(e.as_str()) {
                    eprintln!("collateral watcher: {e}");
                }
                c.rpc_error = Some(e);
            }
        }
    }
}

pub async fn watch_once(venue: &std::sync::Arc<tokio::sync::Mutex<Venue>>, cfg: &ChainCfg) -> Result<(), String> {
    let tip = rpc(cfg, "getblockcount", json!([])).await?.as_u64().ok_or("getblockcount")? as u32;
    // Work list under the lock; RPC without it.
    let (scan, pkg, spent_check, rescan) = {
        let mut v = venue.lock().await;
        let c = v.coll.as_mut().ok_or("off")?;
        let moved = c.tip != tip;
        c.tip = tip;
        c.rpc_error = None;
        let scan: Vec<(Key, Vec<u8>)> = c
            .addrs
            .iter()
            .filter(|(o, _)| !c.accts.contains_key(*o))
            .filter_map(|(o, a)| c.script(o, a.refund_height).ok().map(|s| (*o, s.spk())))
            .collect();
        let pkg = c.package.as_ref().filter(|p| p.complete()).map(|p| (p.id, p.tx.txid(), p.tx.outputs.iter().enumerate().filter(|(_, o)| o.spk.first() != Some(&0x6a)).map(|(i, _)| i).collect::<Vec<_>>()));
        let in_pkg: Vec<Key> = c.package.as_ref().filter(|p| p.complete()).map(|p| p.accounts.iter().map(|a| a.owner).collect()).unwrap_or_default();
        let spent_check: Vec<(Key, Key, u32)> = c.accts.iter().filter(|(o, a)| a.closed.is_none() && !in_pkg.contains(o)).map(|(o, a)| (*o, a.txid, a.vout)).collect();
        let rescan = moved || c.scanned_tip == 0 || c.seen.len() < scan.len();
        if moved {
            v.emit(json!({"type": "account"}));
        }
        (scan, pkg, spent_check, rescan)
    };
    // Deposits.
    let mut seen: BTreeMap<Key, Seen> = BTreeMap::new();
    if rescan && !scan.is_empty() {
        let desc: Vec<String> = scan.iter().map(|(_, s)| format!("raw({})", h(s))).collect();
        let r = rpc(cfg, "scantxoutset", json!(["start", desc])).await?;
        for u in r["unspents"].as_array().cloned().unwrap_or_default() {
            let spk = hex::decode(u["scriptPubKey"].as_str().unwrap_or("")).unwrap_or_default();
            let Some((o, _)) = scan.iter().find(|(_, s)| *s == spk) else { continue };
            let value = (u["amount"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
            let d = Seen { txid: parse_key(u["txid"].as_str().unwrap_or(""))?, vout: u["vout"].as_u64().unwrap_or(0) as u32, value, height: u["height"].as_u64().unwrap_or(0) as u32 };
            // The largest (then earliest) output to the address is the deposit; others refund at h.
            let better = seen.get(o).is_none_or(|x| (d.value, std::cmp::Reverse(d.height)) > (x.value, std::cmp::Reverse(x.height)));
            if better {
                seen.insert(*o, d);
            }
        }
    }
    // Package confirmation.
    let mut confirmed: Option<(Key, u32)> = None;
    if let Some((id, txid, outs)) = &pkg {
        for o in outs {
            let r = rpc(cfg, "gettxout", json!([h(txid), o, false])).await?;
            if let Some(n) = r["confirmations"].as_u64()
                && n as u32 >= cfg.min_conf
            {
                confirmed = Some((*id, tip + 1 - n as u32));
                break;
            }
        }
    }
    // Collateral outputs spent outside a settlement.
    let mut spent = vec![];
    for (o, txid, vout) in &spent_check {
        let r = rpc(cfg, "gettxout", json!([h(txid), vout, true])).await?;
        if r.is_null() {
            spent.push(*o);
        }
    }
    let mut v = venue.lock().await;
    {
        let c = v.coll.as_mut().ok_or("off")?;
        if rescan && !scan.is_empty() {
            c.scanned_tip = tip;
            for (o, _) in &scan {
                match seen.remove(o) {
                    Some(d) => {
                        c.seen.insert(*o, d);
                    }
                    None => {
                        c.seen.remove(o);
                    }
                }
            }
        }
    }
    if let Some((id, height)) = confirmed {
        v.settlement_confirmed(id, height)?;
    }
    for o in spent {
        let still = v.coll.as_ref().and_then(|c| c.accts.get(&o)).is_some_and(|a| a.closed.is_none());
        if still {
            v.coll_record(json!({"kind": "coll_closed", "owner": h(&o), "reason": "collateral output spent outside a settlement (refund path)"}))?;
        }
    }
    v.emit(json!({"type": "collateral"}));
    Ok(())
}

impl Venue {
    /// The open package confirmed: journal `coll_settled` (rollovers, paid withdrawals).
    pub fn settlement_confirmed(&mut self, id: Key, height: u32) -> Result<(), String> {
        let c = self.coll()?;
        let p = c.package.as_ref().filter(|p| p.id == id).ok_or("package gone")?.clone();
        let txid = p.tx.txid();
        let accounts: Vec<Value> = p
            .accounts
            .iter()
            .map(|a| json!({"owner": h(&a.owner), "input": a.input, "from": a.from, "net": a.net, "value_in": a.value_in,
                            "rollover": a.rollover.map(|(i, v)| json!({"vout": i, "value": v, "refund_height": p.refund_height})),
                            "withdraw_id": a.withdraw.as_ref().map(|w| w.2.clone()), "withdraw_sats": a.withdraw.as_ref().map(|w| w.1),
                            "batches": a.batches}))
            .collect();
        self.coll_mut()?.package = None;
        self.coll_record(json!({"kind": "coll_settled", "package_id": h(&id), "txid": h(&txid), "height": height, "through": p.through,
                                "event_id": p.event_id, "refund_height": p.refund_height, "accounts": accounts, "settled_us": now_us()}))?;
        self.emit(json!({"type": "settlement", "package_id": h(&id), "phase": "confirmed", "txid": h(&txid)}));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_num_and_address_roundtrip() {
        assert_eq!(num(140), vec![0x02, 0x8c, 0x00]);
        assert_eq!(num(100), vec![0x01, 0x64]);
        assert_eq!(num(500_000), vec![0x03, 0x20, 0xa1, 0x07]);
        let s = AccountScript::new(&shz_dlc::pubkey_x_from_secret(&[3; 32]).unwrap(), &shz_dlc::pubkey_x_from_secret(&[4; 32]).unwrap(), 140).unwrap();
        for net in [Net::Regtest, Net::Testnet4] {
            let a = address(net, &s.spk()).unwrap();
            assert_eq!(decode_address(net, &a).unwrap(), s.spk());
            assert!(decode_address(if net == Net::Regtest { Net::Testnet4 } else { Net::Regtest }, &a).is_err());
        }
        // BIP-350 vectors (testnet v1, v0 p2wsh).
        let v1 = decode_address(Net::Testnet4, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c").unwrap();
        assert_eq!(h(&v1), "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433");
        let v0 = decode_address(Net::Testnet4, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7").unwrap();
        assert_eq!(h(&v0), "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
        assert_eq!(address(Net::Testnet4, &v1).unwrap(), "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c");
        assert!(decode_address(Net::Testnet4, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0d").is_err());
    }

    #[test]
    fn tx_roundtrip_and_sighash_types() {
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn { txid: [1; 32], vout: 0, sequence: 0xffff_fffd }, TxIn { txid: [2; 32], vout: 3, sequence: 0xffff_fffd }],
            outputs: vec![TxOut { value: 1000, spk: vec![0x51, 0x20].into_iter().chain([7u8; 32]).collect() }, TxOut { value: 0, spk: vec![0x6a, 0x01, 0x00] }],
            locktime: 0,
        };
        let raw = tx.serialize();
        assert_eq!(Tx::parse(&raw).unwrap(), tx);
        let pv = vec![(5000, vec![0x51, 0x20].into_iter().chain([8u8; 32]).collect::<Vec<u8>>()), (6000, vec![0x51, 0x20].into_iter().chain([9u8; 32]).collect())];
        let leaf = [5; 32];
        let a = tap_sighash(&tx, &pv, 0, 0x83, &leaf).unwrap();
        // ACP|SINGLE ignores the other input and every other output.
        let mut t2 = tx.clone();
        t2.inputs[1].vout = 9;
        t2.outputs[1].value = 7;
        let mut pv2 = pv.clone();
        pv2[1].0 = 1;
        assert_eq!(tap_sighash(&t2, &pv2, 0, 0x83, &leaf).unwrap(), a);
        // ALL|ACP covers every output but not the other input.
        let b = tap_sighash(&tx, &pv, 0, 0x81, &leaf).unwrap();
        let mut t3 = tx.clone();
        t3.inputs[1].vout = 9;
        assert_eq!(tap_sighash(&t3, &pv2, 0, 0x81, &leaf).unwrap(), b);
        assert_ne!(tap_sighash(&t2, &pv, 0, 0x81, &leaf).unwrap(), b);
        // DEFAULT covers the other input's amount too.
        let d = tap_sighash(&tx, &pv, 0, 0x00, &leaf).unwrap();
        assert_ne!(tap_sighash(&tx, &pv2, 0, 0x00, &leaf).unwrap(), d);
        assert!(Tx::parse(&[raw.clone(), vec![0]].concat()).is_err());
    }

    /// sdk/vectors/collateral_vectors.json: account scripts, a settlement-shaped transaction and its
    /// sighashes per hash type, a withdrawal digest and a package id; ui/venue/test/settle.test.mjs
    /// recomputes every value in JS.
    #[test]
    fn shared_collateral_vectors() {
        let t = shz_dlc::pubkey_x_from_secret(&[0x31; 32]).unwrap();
        let b = shz_dlc::pubkey_x_from_secret(&[0x32; 32]).unwrap();
        let (h_in, h_next) = (140u32, 600u32);
        let s_in = AccountScript::new(&t, &b, h_in).unwrap();
        let s_out = AccountScript::new(&t, &b, h_next).unwrap();
        let other = AccountScript::new(&b, &t, 150).unwrap();
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn { txid: [0xa1; 32], vout: 1, sequence: 0xffff_fffd }, TxIn { txid: [0xa2; 32], vout: 0, sequence: 0xffff_fffd }, TxIn { txid: [0xa3; 32], vout: 2, sequence: 0xffff_fffd }],
            outputs: vec![
                TxOut { value: 19_972, spk: s_out.spk() },
                TxOut { value: 20_028, spk: other.spk() },
                TxOut { value: 0, spk: [vec![0x6a, 0x24], b"SHZB".to_vec(), vec![0x77; 32]].concat() },
                TxOut { value: 97_000, spk: [vec![0x51, 0x20], vec![0x55; 32]].concat() },
                TxOut { value: 500, spk: decode_address(Net::Regtest, &address(Net::Regtest, &[vec![0x00, 0x14], vec![0x66; 20]].concat()).unwrap()).unwrap() },
            ],
            locktime: 0,
        };
        let pv: Vec<(u64, Vec<u8>)> = vec![(20_000, s_in.spk()), (20_000, other.spk()), (100_000, [vec![0x51, 0x20], vec![0x54; 32]].concat())];
        let leaf = tapleaf(&s_in.settle);
        let sig = |ht: u8| h(&tap_sighash(&tx, &pv, 0, ht, &leaf).unwrap());
        let raw = tx.serialize();
        let spk_w = tx.outputs[4].spk.clone();
        let v = json!({
            "description": "Shared collateral vectors (crates/shz-venue/src/core/collateral.rs shared_collateral_vectors).",
            "trader": h(&t), "batcher": h(&b), "refund_height_in": h_in, "refund_height_next": h_next,
            "account_in": {"spk": h(&s_in.spk()), "address_regtest": address(Net::Regtest, &s_in.spk()).unwrap(), "address_testnet4": address(Net::Testnet4, &s_in.spk()).unwrap(),
                           "settle_script": h(&s_in.settle), "refund_script": h(&s_in.refund), "settle_control": h(&s_in.control(0)), "refund_control": h(&s_in.control(1)), "settle_leaf": h(&leaf)},
            "account_next_spk": h(&s_out.spk()),
            "tx": h(&raw), "txid": h(&tx.txid()),
            "prevouts": pv.iter().map(|(v, s)| json!({"value": v, "spk": h(s)})).collect::<Vec<_>>(),
            "sighash_input0": {"0": sig(0x00), "1": sig(0x01), "129": sig(0x81), "131": sig(0x83)},
            "withdraw": {"address_regtest": address(Net::Regtest, &spk_w).unwrap(), "spk": h(&spk_w), "sats": 500, "nonce_us": 1_764_300_000_000_000u64,
                         "digest": h(&withdraw_digest(&t, 500, &spk_w, 1_764_300_000_000_000))},
            "package_id_through_19": h(&package_id(&raw, 19)),
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/vectors/collateral_vectors.json");
        if std::env::var("SHZ_WRITE_VECTORS").is_ok() {
            std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "
").unwrap();
        }
        let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("sdk/vectors/collateral_vectors.json (SHZ_WRITE_VECTORS=1 writes it)")).unwrap();
        assert_eq!(on_disk, v, "sdk/vectors/collateral_vectors.json is stale");
    }

    fn cfg(b: Key) -> ChainCfg {
        ChainCfg { net: Net::Regtest, rpc_url: "http://127.0.0.1:9".into(), rpc_auth: "u:p".into(), batcher: b, refund_blocks: 100, min_conf: 2, min_lock: 50, poll_ms: 1000 }
    }

    /// Deposit -> registration -> owner-signed withdrawal -> settler package checked against the
    /// venue's own view -> owner signature (agent key refused) -> confirmation -> rollover; the
    /// journal restores the same state after a restart.
    #[test]
    fn deposit_withdraw_settle_and_restore() {
        use shz_dlc::{bip340_sign, pubkey_x_from_secret};
        let dir = std::env::temp_dir().join(format!("shz-venue-coll-{}", now_us()));
        let (tsk, bsk, agent_sk) = ([0x41u8; 32], [0x42u8; 32], [0x43u8; 32]);
        let (t, b) = (pubkey_x_from_secret(&tsk).unwrap(), pubkey_x_from_secret(&bsk).unwrap());
        let sigx = |k: &Key, m: &Key| hex::encode(bip340_sign(k, m).unwrap().to_bytes());
        let deposit_txid = [0xd1u8; 32];
        {
            let mut v = Venue::open(&dir, [7; 32], "http://127.0.0.1:9".into()).unwrap();
            v.collateral_enable(cfg(b)).unwrap();
            assert!(v.collateral_address(t).is_err(), "no tip yet");
            v.coll.as_mut().unwrap().tip = 200;
            let a = v.collateral_address(t).unwrap();
            assert_eq!(a["deposit"]["refund_height"], 300);
            assert!(v.register_draft(t, "demo", None, None).is_err(), "demo is refused under --collateral-chain");
            v.coll.as_mut().unwrap().seen.insert(t, Seen { txid: deposit_txid, vout: 1, value: 50_000, height: 201 });
            assert!(v.register_draft(t, "collateral", None, None).unwrap_err().contains("1 of 2"));
            v.coll.as_mut().unwrap().tip = 202;
            let d = v.register_draft(t, "collateral", None, None).unwrap();
            assert_eq!(d["cap_sats"], 50_000);
            let digest = parse_key(d["allocation_digest"].as_str().unwrap()).unwrap();
            v.register(d["draft_id"].as_str().unwrap(), parse_sig(&sigx(&tsk, &digest)).unwrap()).unwrap();
            assert_eq!(v.balance(&t).unwrap().free, 50_000);
            // Withdrawal: signed, bounded by free collateral, debited from the router now.
            let addr = address(Net::Regtest, &[vec![0x00, 0x14], vec![0x66; 20]].concat()).unwrap();
            let spk = decode_address(Net::Regtest, &addr).unwrap();
            let body = |sats: u64, nonce: u64, k: &Key| json!({"owner": h(&t), "sats": sats, "address": addr, "nonce_us": nonce, "signature": sigx(k, &withdraw_digest(&t, sats, &spk, nonce))});
            assert!(v.collateral_withdraw(&body(60_000, 1, &tsk)).unwrap_err().contains("free"));
            assert!(v.collateral_withdraw(&body(10_000, 2, &agent_sk)).unwrap_err().contains("signature"));
            v.collateral_withdraw(&body(10_000, 3, &tsk)).unwrap();
            assert!(v.collateral_withdraw(&body(1_000, 4, &tsk)).unwrap_err().contains("pending"));
            assert_eq!(v.balance(&t).unwrap().free, 40_000);
            let ep = v.settlement_epoch().unwrap();
            let acct = &ep["accounts"][0];
            assert_eq!(acct["touched"], true);
            assert_eq!(acct["outputs"].as_array().unwrap().len(), 2);
            // The settler's transaction: account input + operator input; rollover, payout, OP_RETURN, change.
            let h_next = 302u32;
            let roll = AccountScript::new(&t, &b, h_next).unwrap();
            let s_in = AccountScript::new(&t, &b, 300).unwrap();
            let op_spk = [vec![0x51, 0x20], vec![0x55; 32]].concat();
            let tx = Tx {
                version: 2,
                inputs: vec![TxIn { txid: rev(&deposit_txid), vout: 1, sequence: 0xffff_fffd }, TxIn { txid: [0xe1; 32], vout: 0, sequence: 0xffff_fffd }],
                outputs: vec![TxOut { value: 40_000, spk: roll.spk() }, TxOut { value: 10_000, spk: spk.clone() }, TxOut { value: 0, spk: vec![0x6a, 0x01, 0x01] }, TxOut { value: 9_000, spk: op_spk.clone() }],
                locktime: 0,
            };
            let raw = tx.serialize();
            let pkg = |ht: u8, outs: Vec<usize>, signer: &Key, txv: &Tx| {
                let raw = txv.serialize();
                json!({"event_id": "SHZ-BTCUSD-T", "through_batch": 0, "tx": h(&raw), "refund_height": h_next,
                       "prevouts": [{"value": 50_000, "spk": h(&s_in.spk())}, {"value": 10_000, "spk": h(&op_spk)}],
                       "accounts": [{"owner": h(&t), "input": 0, "hash_type": ht, "outputs": outs}],
                       "batcher_signature": sigx(signer, &package_id(&raw, 0))})
            };
            assert!(v.settlement_package(&pkg(0x81, vec![0, 1], &agent_sk, &tx)).unwrap_err().contains("batcher_signature"));
            assert!(v.settlement_package(&pkg(0x83, vec![0, 1], &bsk, &tx)).unwrap_err().contains("SINGLE"), "two outputs need ALL coverage");
            let mut short = tx.clone();
            short.outputs[1].value = 9_999;
            assert!(v.settlement_package(&pkg(0x81, vec![0, 1], &bsk, &short)).unwrap_err().contains("outputs differ"));
            let mut thief = tx.clone();
            thief.outputs[1].spk = op_spk.clone();
            assert!(v.settlement_package(&pkg(0x81, vec![0, 1], &bsk, &thief)).unwrap_err().contains("outputs differ"));
            let r = v.settlement_package(&pkg(0x81, vec![0, 1], &bsk, &tx)).unwrap();
            let id = parse_key(r["package_id"].as_str().unwrap()).unwrap();
            assert_eq!(id, package_id(&raw, 0));
            let sighash = tap_sighash(&tx, &[(50_000, s_in.spk()), (10_000, op_spk.clone())], 0, 0x81, &tapleaf(&s_in.settle)).unwrap();
            assert_eq!(r["sighashes"][h(&t)], h(&sighash));
            assert_eq!(v.coll.as_ref().unwrap().withdrawals.values().next().unwrap().status, "included");
            // Only the owner key signs the input; an agent's key does not verify.
            let sig_with = |k: &Key| format!("{}81", sigx(k, &sighash));
            assert!(v.settlement_sign(&json!({"package_id": h(&id), "owner": h(&t), "signature": sig_with(&agent_sk)})).is_err());
            assert!(v.settlement_sign(&json!({"package_id": h(&id), "owner": h(&t), "signature": sigx(&tsk, &sighash)})).unwrap_err().contains("65 bytes"));
            assert!(v.settlement_broadcast(&json!({"package_id": h(&id), "txid": h(&tx.txid())})).unwrap_err().contains("not fully signed"));
            assert_eq!(v.settlement_sign(&json!({"package_id": h(&id), "owner": h(&t), "signature": sig_with(&tsk)})).unwrap()["complete"], true);
            assert!(v.settlement_broadcast(&json!({"package_id": h(&id), "txid": h(&[9; 32])})).is_err());
            v.settlement_broadcast(&json!({"package_id": h(&id), "txid": h(&tx.txid())})).unwrap();
            v.settlement_confirmed(id, 205).unwrap();
            let c = v.collateral_view(&t).unwrap();
            assert_eq!(c["account"]["outpoint"]["txid"], h(&tx.txid()));
            assert_eq!(c["account"]["value"], 40_000);
            assert_eq!(c["account"]["refund_height"], h_next);
            assert_eq!(c["withdrawals"][0]["status"], "paid");
        }
        // Restart: the journal rebuilds the same account, and the router keeps the debit.
        let mut v = Venue::open(&dir, [7; 32], "http://127.0.0.1:9".into()).unwrap();
        v.collateral_enable(cfg(b)).unwrap();
        let c = v.collateral_view(&t).unwrap();
        assert_eq!(c["account"]["value"], 40_000);
        assert_eq!(c["account"]["refund_height"], 302);
        assert_eq!(c["account"]["channel"]["txid"], h(&deposit_txid));
        assert_eq!(c["withdrawals"][0]["status"], "paid");
        assert_eq!(v.balance(&t).unwrap().free, 40_000);
        assert_eq!(v.account_view(&t)["label"], "regtest collateral");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
