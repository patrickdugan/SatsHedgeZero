//! On-chain collateral accounts (`--collateral-chain regtest|testnet4`, docs/SHZ_MVP_COLLATERAL.md).
//!
//! A trader deposits to `account(T, B, h)` (docs/SHZ_DLC_BATCHER.md section 2): settle leaf
//! `<T> CHECKSIGVERIFY <B> CHECKSIG`, refund leaf `<h> CLTV DROP <T> CHECKSIG`, NUMS internal key.
//! `T` is the venue owner key, `B` the batcher key of `--batcher-key`. The watcher credits a deposit
//! after `--min-conf` confirmations; the owner signs a `collateral` registration and the deposit
//! outpoint becomes the account's venue channel. At each oracle maturity the settlement daemon
//! (`shz-batcher`) posts one package per segment of committed batches (settlement co-sign contract
//! v1): every account entry spends its collateral through the settle leaf into `account(T, B, h')`
//! (roll) or, after an owner-signed withdrawal, to the owner's address, worth `collateral + net`.
//! The venue checks each entry against its own records and recomputes the SIGHASH_SINGLE|ANYONECANPAY
//! sighash; owners sign their own input in the browser; agents cannot (settlement signatures are
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
/// Daemon POST authentication and owner withdrawal tags (settlement co-sign contract v1).
pub const TAG_POST: &[u8] = b"SHZ/BATCHER/POST/V1";
pub const TAG_WITHDRAW: &[u8] = b"SHZ/WITHDRAW/V1";
pub const SIGHASH_SINGLE_ACP: u8 = 0x83;

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
    /// Re-read before every call when set, so a bitcoind `.cookie` that changes on restart keeps working.
    pub rpc_auth_file: Option<String>,
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

#[cfg_attr(not(test), allow(dead_code))]
struct Rd<'a>(&'a [u8], usize);
#[cfg_attr(not(test), allow(dead_code))]
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
    #[cfg_attr(not(test), allow(dead_code))]
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
    #[cfg_attr(not(test), allow(dead_code))]
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


/// BIP340 tagged message the daemon signs for each POST body (`X-SHZ-Batcher` header).
pub fn post_digest(body: &[u8]) -> Key {
    tagged_hash(TAG_POST, body)
}
/// Owner's withdrawal request: `owner || u32le(len spk) || spk || u64le(time_us)`.
pub fn withdraw_msg(owner: &Key, spk: &[u8], time_us: u64) -> Key {
    let mut m = owner.to_vec();
    m.extend((spk.len() as u32).to_le_bytes());
    m.extend(spk);
    m.extend(time_us.to_le_bytes());
    tagged_hash(TAG_WITHDRAW, &m)
}
/// SIGHASH_SINGLE|ANYONECANPAY commits to the account's own input and the output at its index only,
/// so a one-input one-output transaction carrying them gives the settlement's sighash.
#[allow(clippy::too_many_arguments)]
pub fn entry_sighash(version: u32, locktime: u32, txid_display: &Key, vout: u32, amount: u64, spk: &[u8], sequence: u32, out_value: u64, out_spk: &[u8], leaf: &Key) -> Result<Key, String> {
    let tx = Tx { version, inputs: vec![TxIn { txid: rev(txid_display), vout, sequence }], outputs: vec![TxOut { value: out_value, spk: out_spk.to_vec() }], locktime };
    tap_sighash(&tx, &[(amount, spk.to_vec())], 0, SIGHASH_SINGLE_ACP, leaf)
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
pub struct Withdrawal {
    pub spk: Vec<u8>,
    pub address: String,
    pub time_us: u64,
    pub sig: String,
    pub status: String,
    pub txid: Option<Key>,
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
    pub withdrawal: Option<Withdrawal>,
}
/// One account's entry of a daemon package, as posted (`raw`) plus what the venue derived.
#[derive(Clone, Debug)]
pub struct Entry {
    pub owner: Key,
    pub raw: Value,
    pub out_value: u64,
    pub out_spk: Vec<u8>,
    pub kind: String,
    pub refund_height: Option<u32>,
    pub sighash: Key,
    /// Batch the input's value is settled through (the account's, or the earlier package's).
    pub base_through: u64,
}
#[derive(Clone, Debug)]
pub struct Package {
    pub epoch: String,
    pub segment: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub deadline_us: u64,
    pub tx: Value,
    pub entries: Vec<Entry>,
    pub sigs: BTreeMap<Key, (String, u64)>,
    pub created_us: u64,
}
/// A payout the daemon reported broadcast (or staged); applied when the chain shows it.
#[derive(Clone, Debug)]
pub struct PendingPayout {
    pub owner: Key,
    pub epoch: String,
    pub segment: u64,
    pub txid: Key,
    pub vout: Option<u32>,
    pub value: u64,
    pub spk: Vec<u8>,
    pub kind: String,
    pub refund_height: Option<u32>,
    pub last_seq: u64,
}

pub struct CollState {
    pub cfg: ChainCfg,
    pub tip: u32,
    pub addrs: BTreeMap<Key, AddrRec>,
    pub seen: BTreeMap<Key, Seen>,
    pub accts: BTreeMap<Key, Acct>,
    pub packages: BTreeMap<(String, u64), Package>,
    pub pending: Vec<PendingPayout>,
    pub results: Vec<Value>,
    pub rpc_error: Option<String>,
    pub scanned_tip: u32,
}

fn hexv(v: &Value) -> Result<Vec<u8>, String> {
    hex::decode(v.as_str().ok_or("missing hex field")?).map_err(|_| "bad hex".to_string())
}
fn u(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("missing {what}"))
}

impl CollState {
    pub fn new(cfg: ChainCfg) -> Self {
        Self { cfg, tip: 0, addrs: BTreeMap::new(), seen: BTreeMap::new(), accts: BTreeMap::new(), packages: BTreeMap::new(), pending: vec![], results: vec![], rpc_error: None, scanned_tip: 0 }
    }
    pub fn script(&self, owner: &Key, refund_height: u32) -> Result<AccountScript, String> {
        AccountScript::new(owner, &self.cfg.batcher, refund_height)
    }
    fn parse_package(j: &Value, derived: &Value) -> Result<Package, String> {
        let mut entries = vec![];
        for (e, d) in j["accounts"].as_array().ok_or("accounts")?.iter().zip(derived.as_array().ok_or("derived")?) {
            let o = &e["output"];
            entries.push(Entry {
                owner: parse_key(e["owner"].as_str().ok_or("owner")?)?,
                raw: e.clone(),
                out_value: u(&o["value"], "output.value")?,
                out_spk: hexv(&o["spk"])?,
                kind: o["kind"].as_str().unwrap_or("").into(),
                refund_height: o["refund_height"].as_u64().map(|x| x as u32),
                sighash: parse_key(d["sighash"].as_str().ok_or("sighash")?)?,
                base_through: u(&d["base_through"], "base_through")?,
            });
        }
        Ok(Package {
            epoch: j["epoch"].as_str().ok_or("epoch")?.into(),
            segment: u(&j["segment"], "segment")?,
            first_seq: j["first_seq"].as_u64().unwrap_or(0),
            last_seq: u(&j["last_seq"], "last_seq")?,
            deadline_us: j["deadline_us"].as_u64().unwrap_or(u64::MAX),
            tx: j["tx"].clone(),
            entries,
            sigs: BTreeMap::new(),
            created_us: j["created_us"].as_u64().unwrap_or(0),
        })
    }
    /// Accounts in an open package or with a payout awaiting confirmation.
    fn in_flight(&self, owner: &Key) -> bool {
        self.pending.iter().any(|p| p.owner == *owner) || self.packages.values().any(|p| p.entries.iter().any(|e| e.owner == *owner) && p.sigs.contains_key(owner))
    }

    /// Fold one journaled `coll_*` record in (startup replay and live writes share this).
    pub fn apply(&mut self, e: &Value) -> Result<(), String> {
        let owner = || parse_key(e["owner"].as_str().unwrap_or(""));
        match e["kind"].as_str().unwrap_or("") {
            "coll_addr" => {
                self.addrs.insert(owner()?, AddrRec { refund_height: e["refund_height"].as_u64().unwrap_or(0) as u32, issued_height: e["issued_height"].as_u64().unwrap_or(0) as u32 });
            }
            "coll_deposit" => {
                let txid = parse_key(e["txid"].as_str().unwrap_or(""))?;
                let vout = e["vout"].as_u64().unwrap_or(0) as u32;
                self.accts.insert(owner()?, Acct {
                    channel: BtcOutPoint { txid, vout },
                    txid,
                    vout,
                    value: e["value"].as_u64().unwrap_or(0),
                    refund_height: e["refund_height"].as_u64().unwrap_or(0) as u32,
                    deposit_height: e["height"].as_u64().unwrap_or(0) as u32,
                    settled_through: e["settled_through"].as_u64().unwrap_or(0),
                    closed: None,
                    withdrawal: None,
                });
            }
            "coll_withdraw" => {
                if let Some(a) = self.accts.get_mut(&owner()?) {
                    a.withdrawal = Some(Withdrawal {
                        spk: hexv(&e["spk"])?,
                        address: e["address"].as_str().unwrap_or("").into(),
                        time_us: e["time_us"].as_u64().unwrap_or(0),
                        sig: e["sig"].as_str().unwrap_or("").into(),
                        status: "pending".into(),
                        txid: None,
                    });
                }
            }
            "coll_package" => {
                let p = Self::parse_package(&e["package"], &e["derived"])?;
                self.packages.insert((p.epoch.clone(), p.segment), p);
            }
            "coll_sig" => {
                let k = (e["epoch"].as_str().unwrap_or("").to_string(), e["segment"].as_u64().unwrap_or(0));
                if let Some(p) = self.packages.get_mut(&k) {
                    p.sigs.insert(owner()?, (e["sig"].as_str().unwrap_or("").into(), e["received_us"].as_u64().unwrap_or(0)));
                }
            }
            "coll_result" => {
                let r = &e["result"];
                let k = (r["epoch"].as_str().unwrap_or("").to_string(), r["segment"].as_u64().unwrap_or(0));
                self.packages.remove(&k);
                if matches!(r["status"].as_str(), Some("broadcast") | Some("staged")) {
                    let txid = parse_key(r["txid"].as_str().unwrap_or(""))?;
                    for p in e["payouts"].as_array().cloned().unwrap_or_default() {
                        self.pending.push(PendingPayout {
                            owner: parse_key(p["owner"].as_str().unwrap_or(""))?,
                            epoch: k.0.clone(),
                            segment: k.1,
                            txid,
                            vout: p["vout"].as_u64().map(|v| v as u32),
                            value: p["value"].as_u64().unwrap_or(0),
                            spk: hexv(&p["spk"])?,
                            kind: p["kind"].as_str().unwrap_or("").into(),
                            refund_height: p["refund_height"].as_u64().map(|v| v as u32),
                            last_seq: p["last_seq"].as_u64().unwrap_or(0),
                        });
                    }
                }
                self.results.push(r.clone());
            }
            "coll_result_update" => {
                let (ep, seg) = (e["epoch"].as_str().unwrap_or(""), e["segment"].as_u64().unwrap_or(0));
                if let (Some(x), Some(f)) = (self.results.iter_mut().find(|x| x["epoch"] == ep && x["segment"] == seg), e["fields"].as_object())
                    && let Some(o) = x.as_object_mut()
                {
                    for (key, v) in f {
                        o.insert(key.clone(), v.clone());
                    }
                }
            }
            "coll_settled" => {
                let o = owner()?;
                let txid = parse_key(e["txid"].as_str().unwrap_or(""))?;
                let vout = e["vout"].as_u64().unwrap_or(0) as u32;
                self.pending.retain(|p| !(p.owner == o && p.txid == txid));
                let Some(a) = self.accts.get_mut(&o) else { return Ok(()) };
                a.settled_through = e["last_seq"].as_u64().unwrap_or(a.settled_through);
                if e["payout_kind"] == "withdraw" {
                    a.value = 0;
                    a.closed = Some(format!("withdrawn in full by {}", h(&txid)));
                    if let Some(w) = a.withdrawal.as_mut() {
                        w.status = "paid".into();
                        w.txid = Some(txid);
                    }
                } else {
                    a.txid = txid;
                    a.vout = vout;
                    a.value = e["value"].as_u64().unwrap_or(0);
                    a.refund_height = e["refund_height"].as_u64().unwrap_or(0) as u32;
                }
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
    /// Daemon POSTs carry `X-SHZ-Batcher`: BIP340 by `--batcher-key` over `post_digest(body)`.
    pub fn batcher_auth(&self, body: &[u8], sig_hex: Option<&str>) -> Result<(), String> {
        let c = self.coll()?;
        let sig = parse_sig(sig_hex.ok_or("X-SHZ-Batcher header required")?)?;
        bip340_verify(&c.cfg.batcher, &post_digest(body), &sig).map_err(|_| "X-SHZ-Batcher does not verify under --batcher-key".to_string())
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

    /// Intents from a collateral account that has closed or asked to withdraw are refused
    /// (cancels still pass).
    pub fn collateral_gate(&self, owner: &Key) -> Result<(), String> {
        let Some(a) = self.coll.as_ref().and_then(|c| c.accts.get(owner)) else { return Ok(()) };
        if let Some(why) = &a.closed {
            return Err(format!("collateral account closed: {why}"));
        }
        if a.withdrawal.as_ref().is_some_and(|w| w.status == "pending") {
            return Err("a withdrawal is pending: the account pays out in full at the next settlement".into());
        }
        Ok(())
    }

    /// The deposit address of `owner`: issued once (journaled) and re-issued with a later refund
    /// height when the old one is too close to its refund height and still unfunded.
    pub fn collateral_address(&mut self, owner: Key) -> Result<Value, String> {
        shz_dlc::lift_x_even(&owner).map_err(|_| "owner is not a valid x-only key")?;
        let c = self.coll()?;
        if c.tip == 0 {
            return Err(format!("chain not synced yet{}", c.rpc_error.as_ref().map(|e| format!(": {e}")).unwrap_or_default()));
        }
        if c.accts.contains_key(&owner) {
            return self.collateral_view(&owner);
        }
        let stale = match c.addrs.get(&owner) {
            None => true,
            Some(a) => !c.seen.contains_key(&owner) && a.refund_height < c.tip + c.cfg.min_lock,
        };
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
                   "withdrawal": a.withdrawal.as_ref().map(|w| withdrawal_json(net, w)),
                   "explorer_url": net.explorer_tx(&h(&a.txid))})
        });
        let pkgs: Vec<Value> = c.packages.values().filter_map(|p| p.entries.iter().find(|e| e.owner == *owner).map(|_| json!({"epoch": p.epoch, "segment": p.segment, "signed": p.sigs.contains_key(owner), "deadline_us": p.deadline_us}))).collect();
        let pending: Vec<Value> = c.pending.iter().filter(|p| p.owner == *owner).map(|p| json!({"epoch": p.epoch, "segment": p.segment, "txid": h(&p.txid), "kind": p.kind, "value": p.value})).collect();
        Ok(json!({"network": net.name(), "tip_height": c.tip, "batcher_key": h(&c.cfg.batcher), "min_conf": c.cfg.min_conf,
                  "deposit": addr, "seen": seen, "account": acct, "packages": pkgs, "confirming": pending}))
    }

    /// Source of a collateral registration: the watcher's confirmed deposit, or an explicit
    /// outpoint (`kind: "utxo"` with `refund_height`) the HTTP layer checked with `gettxout`.
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
    /// `kind: "utxo"` + `refund_height` under `--collateral-chain`: record the checked outpoint as
    /// this owner's address and deposit so the registration takes the collateral path.
    pub(crate) fn collateral_explicit(&mut self, owner: Key, refund_height: u32, d: Seen) -> Result<(), String> {
        let c = self.coll()?;
        if c.accts.contains_key(&owner) {
            return Err("owner already has an account".into());
        }
        let tip = c.tip;
        if c.addrs.get(&owner).map(|a| a.refund_height) != Some(refund_height) {
            self.coll_record(json!({"kind": "coll_addr", "owner": h(&owner), "refund_height": refund_height, "issued_height": tip}))?;
        }
        self.coll_mut()?.seen.insert(owner, d);
        Ok(())
    }

    /// Called by `register` for a collateral account: journal the credited deposit.
    pub(crate) fn collateral_registered(&mut self, owner: &Key) -> Result<(), String> {
        let c = self.coll()?;
        let a = c.addrs.get(owner).ok_or("no deposit address")?.clone();
        let d = c.seen.get(owner).ok_or("no deposit")?.clone();
        let through = self.resolved_through();
        self.coll_record(json!({"kind": "coll_deposit", "owner": h(owner), "txid": h(&d.txid), "vout": d.vout, "value": d.value,
                                "height": d.height, "refund_height": a.refund_height, "settled_through": through, "credited_us": now_us()}))
    }

    /// `POST /api/settlement/withdraw`: owner-signed request to pay the whole account to `spk` at
    /// the next settlement. The account must be flat with no resting orders; its free balance is
    /// debited from the router at once and new orders are refused.
    pub fn collateral_withdraw(&mut self, j: &Value) -> Result<Value, String> {
        let owner = parse_key(j["owner"].as_str().ok_or("owner required")?)?;
        let time_us = j["time_us"].as_u64().ok_or("time_us required")?;
        let sig = parse_sig(j["sig"].as_str().ok_or("sig required")?)?;
        let c = self.coll()?;
        let net = c.cfg.net;
        let spk = match (j["spk"].as_str(), j["address"].as_str()) {
            (Some(s), _) => hex::decode(s).map_err(|_| "spk: bad hex")?,
            (None, Some(a)) => decode_address(net, a.trim())?,
            _ => return Err("spk or address required".into()),
        };
        let address = address(net, &spk).map_err(|_| "spk is not a segwit output script")?;
        let a = c.accts.get(&owner).ok_or("no collateral account for this key")?.clone();
        if let Some(why) = &a.closed {
            return Err(format!("account closed: {why}"));
        }
        if a.withdrawal.is_some() {
            return Err("a withdrawal is already pending for this account".into());
        }
        bip340_verify(&owner, &withdraw_msg(&owner, &spk, time_us), &sig).map_err(|_| "withdrawal signature does not verify")?;
        let pos = self.position(&owner);
        if pos["net_usd"].as_i64().unwrap_or(0) != 0 || pos["margin_sats"].as_u64().unwrap_or(0) != 0 || pos["unsettled_usd"].as_i64().unwrap_or(0) != 0 {
            return Err("close every position before withdrawing (the whole account pays out)".into());
        }
        if self.intents.values().any(|r| r.intent.owner == owner && (r.status == "resting" || r.status == "queued")) {
            return Err("cancel resting orders before withdrawing".into());
        }
        let free = self.balance(&owner).map(|b| b.free).unwrap_or(0);
        if free > 0 {
            self.router.collateral_transfer(a.channel.clone(), free, false).map_err(|e| format!("withdraw: {e}"))?;
        }
        self.coll_record(json!({"kind": "coll_withdraw", "owner": h(&owner), "spk": h(&spk), "address": address, "time_us": time_us,
                                "sig": hex::encode(sig.to_bytes()), "router_debit": free, "requested_us": now_us()}))?;
        Ok(json!({"accepted": true, "address": address, "router_debit_sats": free}))
    }
    /// `GET /api/settlement/withdrawals`: pending requests for the daemon (it re-verifies them).
    pub fn collateral_withdrawals(&self) -> Result<Value, String> {
        let c = self.coll()?;
        Ok(json!(c.accts.iter().filter_map(|(o, a)| a.withdrawal.as_ref().filter(|w| w.status == "pending" && a.closed.is_none())
            .map(|w| json!({"owner": h(o), "spk": h(&w.spk), "time_us": w.time_us, "sig": w.sig, "address": w.address}))).collect::<Vec<_>>()))
    }

    /// Highest batch every earlier batch of which has resolved.
    fn resolved_through(&self) -> u64 {
        self.router.next_resolution().unwrap_or(1).saturating_sub(1)
    }
    /// Sum of the account's clearing-row nets over batches `(from, to]`, and the batches it had rows in.
    pub fn collateral_net(&self, channel: &BtcOutPoint, from: u64, to: u64) -> (i64, Vec<u64>) {
        let (mut net, mut seqs) = (0i64, vec![]);
        for seq in from + 1..=to {
            if let Ok(Some(cl)) = self.router.clearing(seq) {
                let mut hit = false;
                for r in cl.rows.iter().filter(|r| r.channel == *channel) {
                    net += r.net;
                    hit = true;
                }
                if hit {
                    seqs.push(seq);
                }
            }
        }
        (net, seqs)
    }

    /// `GET /api/settlement/epoch`: each account's settled value and its net since then.
    pub fn settlement_epoch(&self) -> Result<Value, String> {
        let c = self.coll()?;
        let through = self.resolved_through();
        let accounts: Vec<Value> = c.accts.iter().map(|(o, a)| {
            let (net, seqs) = self.collateral_net(&a.channel, a.settled_through, through);
            json!({"owner": h(o), "channel": {"txid": h(&a.channel.txid), "vout": a.channel.vout}, "outpoint": {"txid": h(&a.txid), "vout": a.vout},
                   "collateral": a.value, "refund_height": a.refund_height, "settled_through": a.settled_through, "net": net, "batches": seqs,
                   "payout": a.value as i64 + net, "closed": a.closed, "withdraw": a.withdrawal.as_ref().filter(|w| w.status == "pending").map(|w| h(&w.spk))})
        }).collect();
        Ok(json!({"network": c.cfg.net.name(), "batcher_key": h(&c.cfg.batcher), "through_batch": through, "tip_height": c.tip, "accounts": accounts}))
    }

    /// `POST /api/settlement/package` (daemon, authenticated): check every account entry against the
    /// venue's own records (input = the account's collateral or an earlier package's roll, payout =
    /// collateral + clearing net since the last applied settlement, roll to the owner's account script
    /// or withdrawal to the owner's signed address) and the 0x83 sighash, then open the package.
    pub fn settlement_package(&mut self, body: &[u8], auth: Option<&str>) -> Result<Value, String> {
        self.batcher_auth(body, auth)?;
        let j: Value = serde_json::from_slice(body).map_err(|_| "body is not JSON")?;
        let c = self.coll()?;
        if let Some(n) = j["network"].as_str()
            && n != c.cfg.net.name()
        {
            return Err(format!("package is for {n}; this venue runs {}", c.cfg.net.name()));
        }
        let epoch = j["epoch"].as_str().ok_or("epoch required")?.to_string();
        let segment = u(&j["segment"], "segment")?;
        let last_seq = u(&j["last_seq"], "last_seq")?;
        if last_seq > self.resolved_through() {
            return Err(format!("last_seq {last_seq} has not resolved (resolved through {})", self.resolved_through()));
        }
        let (version, locktime) = (j["tx"]["version"].as_u64().unwrap_or(2) as u32, j["tx"]["locktime"].as_u64().unwrap_or(0) as u32);
        let mut derived = vec![];
        let mut owners = std::collections::BTreeSet::new();
        for e in j["accounts"].as_array().ok_or("accounts required")? {
            let owner = parse_key(e["owner"].as_str().ok_or("account owner")?)?;
            let who = &h(&owner)[..8];
            if !owners.insert(owner) {
                return Err(format!("{who}: listed twice"));
            }
            let a = c.accts.get(&owner).ok_or_else(|| format!("{who}: no collateral account"))?;
            if let Some(why) = &a.closed {
                return Err(format!("{who}: closed ({why})"));
            }
            let i = &e["input"];
            let (itxid, ivout, amount, ispk) = (parse_key(i["txid"].as_str().ok_or("input.txid")?)?, u(&i["vout"], "input.vout")? as u32, u(&i["amount"], "input.amount")?, hexv(&i["spk"])?);
            // Base: the account's collateral, or the roll output of an earlier open package.
            let base = if (itxid, ivout) == (a.txid, a.vout) {
                Some((a.value, a.refund_height, a.settled_through))
            } else {
                c.packages.iter().filter(|(k, _)| **k != (epoch.clone(), segment)).find_map(|(_, p)| {
                    p.entries.iter().find(|x| x.owner == owner && x.kind == "roll" && x.out_value == amount && x.out_spk == ispk).map(|x| (x.out_value, x.refund_height.unwrap_or(0), p.last_seq))
                })
            };
            let (value, refund_in, from) = base.ok_or_else(|| format!("{who}: input {}:{ivout} is neither the account's collateral {}:{} nor an open package's roll", h(&itxid), h(&a.txid), a.vout))?;
            let s_in = c.script(&owner, refund_in)?;
            if amount != value || ispk != s_in.spk() {
                return Err(format!("{who}: input must be {value} sats to account(T, B, {refund_in})"));
            }
            if hexv(&i["leaf"])? != s_in.settle {
                return Err(format!("{who}: leaf is not the account's settle leaf"));
            }
            let leaf_hash = tapleaf(&s_in.settle);
            if i["leaf_hash"].as_str().is_some_and(|x| x != h(&leaf_hash)) {
                return Err(format!("{who}: leaf_hash is not the settle leaf's"));
            }
            if last_seq < from {
                return Err(format!("{who}: already settled through batch {from}"));
            }
            let (net, _) = self.collateral_net(&a.channel, from, last_seq);
            let o = &e["output"];
            let (ovalue, ospk) = (u(&o["value"], "output.value")?, hexv(&o["spk"])?);
            let want = value as i64 + net;
            if ovalue as i64 != want {
                return Err(format!("{who}: output pays {ovalue}; the venue's collateral {value} + net {net} over batches ({from}, {last_seq}] is {want}"));
            }
            let theirs = e["collateral"].as_i64().unwrap_or(0) + e["carry_in"].as_i64().unwrap_or(0) + e["net"].as_i64().unwrap_or(0);
            if theirs != want {
                return Err(format!("{who}: collateral + carry_in + net = {theirs}, output {ovalue}"));
            }
            if ovalue < DUST {
                return Err(format!("{who}: payout {ovalue} is below dust"));
            }
            match o["kind"].as_str() {
                Some("roll") => {
                    let rh = u(&o["refund_height"], "output.refund_height")? as u32;
                    let hi = c.tip + 2 * c.cfg.refund_blocks + 144;
                    if rh <= c.tip + 6 || rh > hi {
                        return Err(format!("{who}: roll refund height {rh} outside ({}, {hi}]", c.tip + 6));
                    }
                    if ospk != c.script(&owner, rh)?.spk() {
                        return Err(format!("{who}: roll output is not account(T, B, {rh})"));
                    }
                }
                Some("withdraw") => {
                    let w = a.withdrawal.as_ref().filter(|w| w.status == "pending").ok_or_else(|| format!("{who}: withdraw output without a pending withdrawal"))?;
                    if ospk != w.spk {
                        return Err(format!("{who}: withdraw output does not pay the owner's signed address"));
                    }
                }
                _ => return Err(format!("{who}: output.kind must be roll or withdraw")),
            }
            if e["sighash_type"].as_u64() != Some(SIGHASH_SINGLE_ACP as u64) {
                return Err(format!("{who}: sighash_type must be 131 (SINGLE|ANYONECANPAY)"));
            }
            let seq = i["sequence"].as_u64().unwrap_or(0xffff_fffd) as u32;
            let sh = entry_sighash(version, locktime, &itxid, ivout, amount, &ispk, seq, ovalue, &ospk, &leaf_hash)?;
            if e["sighash"].as_str() != Some(h(&sh).as_str()) {
                return Err(format!("{who}: sighash differs from the venue's {}", h(&sh)));
            }
            derived.push(json!({"owner": h(&owner), "sighash": h(&sh), "base_through": from}));
        }
        if derived.is_empty() {
            return Err("a package settles at least one account".into());
        }
        let mut pkg = j.clone();
        pkg["created_us"] = json!(now_us());
        self.coll_record(json!({"kind": "coll_package", "package": pkg, "derived": derived}))?;
        self.emit(json!({"type": "settlement", "epoch": epoch, "segment": segment, "phase": "signing"}));
        Ok(json!({"accepted": true, "epoch": epoch, "segment": segment, "accounts": derived.len()}))
    }

    /// `GET /api/settlement/package?owner=T`: the earliest open package with an entry for `owner`.
    pub fn settlement_package_for(&self, owner: &Key) -> Result<Value, String> {
        let c = self.coll()?;
        let mut ps: Vec<&Package> = c.packages.values().filter(|p| p.entries.iter().any(|e| e.owner == *owner)).collect();
        ps.sort_by_key(|p| (p.sigs.contains_key(owner), p.created_us));
        let p = ps.first().ok_or("no open package for this key")?;
        let e = p.entries.iter().find(|e| e.owner == *owner).unwrap();
        let mut acc = e.raw.clone();
        acc["signed"] = json!(p.sigs.contains_key(owner));
        let (net, seqs) = self.collateral_net(&c.accts[owner].channel, e.base_through, p.last_seq);
        Ok(json!({"epoch": p.epoch, "segment": p.segment, "first_seq": p.first_seq, "last_seq": p.last_seq, "deadline_us": p.deadline_us, "tx": p.tx,
                  "network": c.cfg.net.name(), "batcher_key": h(&c.cfg.batcher), "account": acc,
                  "venue": {"base_through": e.base_through, "net": net, "batches": seqs, "sighash": h(&e.sighash)}}))
    }

    /// `POST /api/settlement/signature`: the owner's 0x83 signature of its own input.
    pub fn settlement_signature(&mut self, j: &Value) -> Result<Value, String> {
        let epoch = j["epoch"].as_str().ok_or("epoch required")?.to_string();
        let segment = u(&j["segment"], "segment")?;
        let owner = parse_key(j["owner"].as_str().ok_or("owner required")?)?;
        let sig = hex::decode(j["sig"].as_str().ok_or("sig required")?).map_err(|_| "sig: bad hex")?;
        let c = self.coll()?;
        let p = c.packages.get(&(epoch.clone(), segment)).ok_or("no such open package")?;
        let e = p.entries.iter().find(|e| e.owner == owner).ok_or("this key has no input in the package")?;
        if now_us() > p.deadline_us {
            return Err("the package's signing deadline has passed".into());
        }
        if sig.len() != 65 || sig[64] != SIGHASH_SINGLE_ACP {
            return Err("sig must be 65 bytes ending in 83".into());
        }
        bip340_verify(&owner, &e.sighash, &parse_sig(&hex::encode(&sig[..64]))?).map_err(|_| "BAD: signature does not verify against the input's sighash")?;
        let done = p.entries.iter().all(|x| x.owner == owner || p.sigs.contains_key(&x.owner));
        self.coll_record(json!({"kind": "coll_sig", "epoch": epoch, "segment": segment, "owner": h(&owner), "sig": hex::encode(&sig), "received_us": now_us()}))?;
        self.emit(json!({"type": "settlement", "epoch": epoch, "segment": segment, "phase": if done { "signed" } else { "signing" }}));
        Ok(json!({"accepted": true, "complete": done}))
    }
    /// `GET /api/settlement/signatures?epoch=&segment=` (daemon).
    pub fn settlement_signatures(&self, epoch: &str, segment: u64) -> Result<Value, String> {
        let c = self.coll()?;
        let p = c.packages.get(&(epoch.to_string(), segment)).ok_or("no such open package")?;
        Ok(json!({"signatures": p.sigs.iter().map(|(o, (s, t))| json!({"owner": h(o), "sig": s, "received_us": t})).collect::<Vec<_>>()}))
    }

    /// `POST /api/settlement/result` (daemon, authenticated): closes the package; payouts of a
    /// broadcast or staged settlement are applied once the chain shows them at `--min-conf`.
    pub fn settlement_result(&mut self, body: &[u8], auth: Option<&str>) -> Result<Value, String> {
        self.batcher_auth(body, auth)?;
        let r: Value = serde_json::from_slice(body).map_err(|_| "body is not JSON")?;
        let c = self.coll()?;
        let k = (r["epoch"].as_str().ok_or("epoch required")?.to_string(), u(&r["segment"], "segment")?);
        let status = r["status"].as_str().ok_or("status required")?.to_string();
        // A second result for the same segment (the prover's statement after the broadcast) updates
        // the first one's fields; payouts are taken from the first only.
        if c.results.iter().any(|x| x["epoch"] == r["epoch"] && x["segment"] == r["segment"]) {
            let mut rec = r.clone();
            rec.as_object_mut().ok_or("result must be an object")?.retain(|key, v| !v.is_null() && !matches!(key.as_str(), "payouts" | "rolled" | "broadcast_command"));
            rec["updated_us"] = json!(now_us());
            self.coll_record(json!({"kind": "coll_result_update", "epoch": k.0, "segment": k.1, "fields": rec}))?;
            self.emit(json!({"type": "settlement", "epoch": k.0, "segment": k.1, "phase": "updated"}));
            return Ok(json!({"accepted": true, "updated": true}));
        }
        let p = c.packages.get(&k);
        let mut payouts = vec![];
        if matches!(status.as_str(), "broadcast" | "staged") {
            parse_key(r["txid"].as_str().ok_or("txid required")?)?;
            let p = p.ok_or("no such open package")?;
            let rolled: Vec<String> = r["rolled"].as_array().cloned().unwrap_or_default().iter().filter_map(|x| x.as_str().map(String::from)).collect();
            for x in r["payouts"].as_array().cloned().unwrap_or_default() {
                let o = parse_key(x["owner"].as_str().ok_or("payout owner")?)?;
                if rolled.contains(&h(&o)) {
                    continue;
                }
                let e = p.entries.iter().find(|e| e.owner == o).ok_or_else(|| format!("payout to {} is not in the package", &h(&o)[..8]))?;
                if !p.sigs.contains_key(&o) {
                    return Err(format!("payout to {} without its signature", &h(&o)[..8]));
                }
                payouts.push(json!({"owner": h(&o), "vout": x["vout"], "value": e.out_value, "spk": h(&e.out_spk), "kind": e.kind, "refund_height": e.refund_height, "last_seq": p.last_seq}));
            }
        }
        let mut rec = r.clone();
        rec["received_us"] = json!(now_us());
        // A staged result's broadcast command may carry bitcoin-cli credentials: never journal them.
        if let Some(cmd) = rec["broadcast_command"].as_str() {
            let clean: Vec<&str> = cmd.split_whitespace().filter(|w| !w.starts_with("-rpcpassword") && !w.starts_with("-rpcuser") && !w.starts_with("-rpccookiefile")).collect();
            rec["broadcast_command"] = json!(clean.join(" "));
        }
        self.coll_record(json!({"kind": "coll_result", "result": rec, "payouts": payouts}))?;
        self.emit(json!({"type": "settlement", "epoch": k.0, "segment": k.1, "phase": status}));
        Ok(json!({"accepted": true, "awaiting_confirmation": payouts.len()}))
    }
    pub fn settlement_results(&self, limit: usize) -> Result<Value, String> {
        Ok(json!(self.coll()?.results.iter().rev().take(limit).cloned().collect::<Vec<_>>()))
    }
    pub fn settlement_open(&self) -> Result<Value, String> {
        let c = self.coll()?;
        Ok(json!(c.packages.values().map(|p| json!({"epoch": p.epoch, "segment": p.segment, "first_seq": p.first_seq, "last_seq": p.last_seq, "deadline_us": p.deadline_us,
            "accounts": p.entries.iter().map(|e| json!({"owner": h(&e.owner), "kind": e.kind, "value": e.out_value, "signed": p.sigs.contains_key(&e.owner)})).collect::<Vec<_>>()})).collect::<Vec<_>>()))
    }

    pub fn collateral_summary(&self) -> Value {
        let Some(c) = self.coll.as_ref() else { return Value::Null };
        json!({"network": c.cfg.net.name(), "tip_height": c.tip, "batcher_key": h(&c.cfg.batcher), "accounts": c.accts.len(),
               "open_packages": c.packages.len(), "confirming": c.pending.len(), "settlements": c.results.len(), "rpc_error": c.rpc_error,
               "min_conf": c.cfg.min_conf, "refund_blocks": c.cfg.refund_blocks})
    }
    /// Extra fields of a collateral account on `/api/explorer/accounts` (the daemon reads them).
    pub fn collateral_explorer(&self, owner: &Key) -> Option<Value> {
        let c = self.coll.as_ref()?;
        let a = c.accts.get(owner)?;
        let s = c.script(owner, a.refund_height).ok()?;
        Some(json!({"refund_height": a.refund_height, "spk": h(&s.spk()), "collateral_sats": a.value, "outpoint": {"txid": h(&a.txid), "vout": a.vout},
                    "funding": {"txid": h(&a.txid), "vout": a.vout}, "settled_through": a.settled_through, "closed": a.closed.is_some(), "closed_reason": a.closed}))
    }

    /// The chain shows a reported payout at `--min-conf`: journal it (roll or withdrawal).
    pub fn settlement_confirmed(&mut self, p: &PendingPayout, vout: u32, height: u32) -> Result<(), String> {
        self.coll_record(json!({"kind": "coll_settled", "owner": h(&p.owner), "txid": h(&p.txid), "vout": vout, "value": p.value, "refund_height": p.refund_height,
                                "payout_kind": p.kind, "last_seq": p.last_seq, "epoch": p.epoch, "segment": p.segment, "height": height, "settled_us": now_us()}))?;
        self.emit(json!({"type": "settlement", "epoch": p.epoch, "segment": p.segment, "phase": "confirmed", "txid": h(&p.txid)}));
        Ok(())
    }
}

fn withdrawal_json(net: Net, w: &Withdrawal) -> Value {
    json!({"address": address(net, &w.spk).unwrap_or_else(|_| w.address.clone()), "spk": h(&w.spk), "time_us": w.time_us, "status": w.status, "txid": w.txid.map(|t| h(&t))})
}

/// An explicit registration outpoint: unspent and confirmed on the venue's node, paying
/// `account(owner, B, refund_height)`.
pub async fn check_outpoint(cfg: &ChainCfg, owner: &Key, refund_height: u32, txid: &Key, vout: u32) -> Result<Seen, String> {
    let r = rpc(cfg, "gettxout", json!([h(txid), vout, false])).await?;
    if r.is_null() {
        return Err("outpoint is not a confirmed unspent output on the venue's node".into());
    }
    let want = AccountScript::new(owner, &cfg.batcher, refund_height)?.spk();
    if r["scriptPubKey"]["hex"].as_str() != Some(h(&want).as_str()) {
        return Err(format!("outpoint does not pay account(owner, B, {refund_height})"));
    }
    let conf = r["confirmations"].as_u64().unwrap_or(0) as u32;
    if conf < cfg.min_conf {
        return Err(format!("outpoint has {conf} of {} confirmations", cfg.min_conf));
    }
    let tip = rpc(cfg, "getblockcount", json!([])).await?.as_u64().unwrap_or(0) as u32;
    Ok(Seen { txid: *txid, vout, value: btc_sats(&r["value"]), height: tip + 1 - conf })
}

// ------------------------------------------------------------ watcher ----

/// Poll bitcoind: tip, deposits to issued addresses (`scantxoutset`), reported payouts reaching
/// `--min-conf`, and collateral outputs spent outside a settlement (the refund path).
pub async fn run(venue: std::sync::Arc<tokio::sync::Mutex<Venue>>) {
    let mut first = true;
    loop {
        let cfg = match venue.lock().await.coll.as_ref() {
            Some(c) => c.cfg.clone(),
            None => return,
        };
        if !first {
            tokio::time::sleep(Duration::from_millis(cfg.poll_ms)).await;
        }
        first = false;
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

fn btc_sats(v: &Value) -> u64 {
    (v.as_f64().unwrap_or(0.0) * 1e8).round() as u64
}

pub async fn watch_once(venue: &std::sync::Arc<tokio::sync::Mutex<Venue>>, cfg: &ChainCfg) -> Result<(), String> {
    let tip = rpc(cfg, "getblockcount", json!([])).await?.as_u64().ok_or("getblockcount")? as u32;
    let (scan, pending, spent_check, rescan, max_out) = {
        let mut v = venue.lock().await;
        let c = v.coll.as_mut().ok_or("off")?;
        let moved = c.tip != tip;
        c.tip = tip;
        c.rpc_error = None;
        let scan: Vec<(Key, Vec<u8>)> = c.addrs.iter().filter(|(o, _)| !c.accts.contains_key(*o)).filter_map(|(o, a)| c.script(o, a.refund_height).ok().map(|s| (*o, s.spk()))).collect();
        let spent_check: Vec<(Key, Key, u32)> = c.accts.iter().filter(|(o, a)| a.closed.is_none() && !c.in_flight(o)).map(|(o, a)| (*o, a.txid, a.vout)).collect();
        let rescan = moved || c.scanned_tip == 0;
        let max_out = 2 * c.accts.len() as u32 + 8;
        let pending = c.pending.clone();
        if moved {
            v.emit(json!({"type": "account"}));
        }
        (scan, pending, spent_check, rescan, max_out)
    };
    // Deposits to issued addresses.
    let mut seen: BTreeMap<Key, Seen> = BTreeMap::new();
    if rescan && !scan.is_empty() {
        let desc: Vec<String> = scan.iter().map(|(_, s)| format!("raw({})", h(s))).collect();
        let r = rpc(cfg, "scantxoutset", json!(["start", desc])).await?;
        for x in r["unspents"].as_array().cloned().unwrap_or_default() {
            let spk = hex::decode(x["scriptPubKey"].as_str().unwrap_or("")).unwrap_or_default();
            let Some((o, _)) = scan.iter().find(|(_, s)| *s == spk) else { continue };
            let d = Seen { txid: parse_key(x["txid"].as_str().unwrap_or(""))?, vout: x["vout"].as_u64().unwrap_or(0) as u32, value: btc_sats(&x["amount"]), height: x["height"].as_u64().unwrap_or(0) as u32 };
            // The largest (then earliest) output to the address is the deposit; any other output refunds at h.
            if seen.get(o).is_none_or(|y| (d.value, std::cmp::Reverse(d.height)) > (y.value, std::cmp::Reverse(y.height))) {
                seen.insert(*o, d);
            }
        }
    }
    // Reported payouts reaching min-conf.
    let mut confirmed = vec![];
    for p in &pending {
        let candidates: Vec<u32> = match p.vout {
            Some(v) => vec![v],
            None => (0..max_out).collect(),
        };
        for vout in candidates {
            let r = rpc(cfg, "gettxout", json!([h(&p.txid), vout, false])).await?;
            if r.is_null() {
                continue;
            }
            if btc_sats(&r["value"]) != p.value || r["scriptPubKey"]["hex"].as_str() != Some(h(&p.spk).as_str()) {
                continue;
            }
            if let Some(n) = r["confirmations"].as_u64()
                && n as u32 >= cfg.min_conf
            {
                confirmed.push((p.clone(), vout, tip + 1 - n as u32));
            }
            break;
        }
    }
    // Collateral outputs spent outside any settlement.
    let mut spent = vec![];
    for (o, txid, vout) in &spent_check {
        if rpc(cfg, "gettxout", json!([h(txid), vout, true])).await?.is_null() {
            spent.push(*o);
        }
    }
    let mut v = venue.lock().await;
    if rescan && !scan.is_empty() {
        let c = v.coll.as_mut().ok_or("off")?;
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
    for (p, vout, height) in confirmed {
        v.settlement_confirmed(&p, vout, height)?;
    }
    for o in spent {
        let still = v.coll.as_ref().is_some_and(|c| c.accts.get(&o).is_some_and(|a| a.closed.is_none()) && !c.in_flight(&o));
        if still {
            v.coll_record(json!({"kind": "coll_closed", "owner": h(&o), "reason": "collateral output spent outside a settlement (refund path)"}))?;
        }
    }
    v.emit(json!({"type": "collateral"}));
    Ok(())
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
        b64(cfg.rpc_auth_file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()).map(|s| s.trim().to_string()).unwrap_or_else(|| cfg.rpc_auth.clone()).as_bytes()),
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


#[cfg(test)]
mod tests {
    use super::*;
    use shz_dlc::{bip340_sign, pubkey_x_from_secret};

    #[test]
    fn script_num_and_address_roundtrip() {
        assert_eq!(num(140), vec![0x02, 0x8c, 0x00]);
        assert_eq!(num(100), vec![0x01, 0x64]);
        assert_eq!(num(500_000), vec![0x03, 0x20, 0xa1, 0x07]);
        let s = AccountScript::new(&pubkey_x_from_secret(&[3; 32]).unwrap(), &pubkey_x_from_secret(&[4; 32]).unwrap(), 140).unwrap();
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
        // ACP|SINGLE ignores the other input and every other output: the one-in one-out form agrees.
        let mut t2 = tx.clone();
        t2.inputs[1].vout = 9;
        t2.outputs[1].value = 7;
        let mut pv2 = pv.clone();
        pv2[1].0 = 1;
        assert_eq!(tap_sighash(&t2, &pv2, 0, 0x83, &leaf).unwrap(), a);
        assert_eq!(entry_sighash(2, 0, &rev(&[1; 32]), 0, 5000, &pv[0].1, 0xffff_fffd, 1000, &tx.outputs[0].spk, &leaf).unwrap(), a);
        let b = tap_sighash(&tx, &pv, 0, 0x81, &leaf).unwrap();
        assert_ne!(tap_sighash(&t2, &pv, 0, 0x81, &leaf).unwrap(), b);
        let d = tap_sighash(&tx, &pv, 0, 0x00, &leaf).unwrap();
        assert_ne!(tap_sighash(&tx, &pv2, 0, 0x00, &leaf).unwrap(), d);
        assert!(Tx::parse(&[raw.clone(), vec![0]].concat()).is_err());
    }

    /// sdk/vectors/collateral_vectors.json: account scripts, a settlement-shaped transaction and its
    /// sighashes per hash type, the 0x83 entry sighash, a withdrawal message and a POST digest;
    /// ui/venue/test/settle.test.mjs recomputes every value in JS.
    #[test]
    fn shared_collateral_vectors() {
        let t = pubkey_x_from_secret(&[0x31; 32]).unwrap();
        let b = pubkey_x_from_secret(&[0x32; 32]).unwrap();
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
                TxOut { value: 500, spk: [vec![0x00, 0x14], vec![0x66; 20]].concat() },
            ],
            locktime: 0,
        };
        let pv: Vec<(u64, Vec<u8>)> = vec![(20_000, s_in.spk()), (20_000, other.spk()), (100_000, [vec![0x51, 0x20], vec![0x54; 32]].concat())];
        let leaf = tapleaf(&s_in.settle);
        let sig = |ht: u8| h(&tap_sighash(&tx, &pv, 0, ht, &leaf).unwrap());
        let raw = tx.serialize();
        let spk_w = tx.outputs[4].spk.clone();
        let entry = entry_sighash(2, 0, &rev(&[0xa1; 32]), 1, 20_000, &s_in.spk(), 0xffff_fffd, 19_972, &s_out.spk(), &leaf).unwrap();
        assert_eq!(h(&entry), sig(0x83), "the entry sighash is the full transaction's for input 0 / output 0");
        let v = json!({
            "description": "Shared collateral vectors (crates/shz-venue/src/core/collateral.rs shared_collateral_vectors).",
            "trader": h(&t), "batcher": h(&b), "refund_height_in": h_in, "refund_height_next": h_next,
            "account_in": {"spk": h(&s_in.spk()), "address_regtest": address(Net::Regtest, &s_in.spk()).unwrap(), "address_testnet4": address(Net::Testnet4, &s_in.spk()).unwrap(),
                           "settle_script": h(&s_in.settle), "refund_script": h(&s_in.refund), "settle_control": h(&s_in.control(0)), "refund_control": h(&s_in.control(1)), "settle_leaf": h(&leaf)},
            "account_next_spk": h(&s_out.spk()),
            "tx": h(&raw), "txid": h(&tx.txid()),
            "prevouts": pv.iter().map(|(v, s)| json!({"value": v, "spk": h(s)})).collect::<Vec<_>>(),
            "sighash_input0": {"0": sig(0x00), "1": sig(0x01), "129": sig(0x81), "131": sig(0x83)},
            "entry": {"input": {"txid": h(&rev(&[0xa1; 32])), "vout": 1, "amount": 20_000, "spk": h(&s_in.spk()), "sequence": 0xffff_fffdu32, "leaf": h(&s_in.settle), "leaf_hash": h(&leaf)},
                      "output": {"value": 19_972, "spk": h(&s_out.spk()), "kind": "roll", "refund_height": h_next}, "sighash": h(&entry)},
            "withdraw": {"address_regtest": address(Net::Regtest, &spk_w).unwrap(), "spk": h(&spk_w), "time_us": 1_764_300_000_000_000u64,
                         "message": h(&withdraw_msg(&t, &spk_w, 1_764_300_000_000_000))},
            "post_digest_of_tx_hex": h(&post_digest(h(&raw).as_bytes())),
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/vectors/collateral_vectors.json");
        if std::env::var("SHZ_WRITE_VECTORS").is_ok() {
            std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
        }
        let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("sdk/vectors/collateral_vectors.json (SHZ_WRITE_VECTORS=1 writes it)")).unwrap();
        assert_eq!(on_disk, v, "sdk/vectors/collateral_vectors.json is stale");
    }

    fn cfg(b: Key) -> ChainCfg {
        ChainCfg { net: Net::Regtest, rpc_url: "http://127.0.0.1:9".into(), rpc_auth: "u:p".into(), rpc_auth_file: None, batcher: b, refund_blocks: 100, min_conf: 2, min_lock: 50, poll_ms: 1000 }
    }
    fn sigx(k: &Key, m: &Key) -> String {
        hex::encode(bip340_sign(k, m).unwrap().to_bytes())
    }
    /// A daemon package entry for `owner` spending `(txid, vout, amount)` of account(T, B, h_in).
    #[allow(clippy::too_many_arguments)]
    fn entry(owner: &Key, b: &Key, txid: &Key, vout: u32, amount: u64, h_in: u32, out_value: u64, out_spk: &[u8], kind: &str, h_out: Option<u32>, net: i64) -> Value {
        let s = AccountScript::new(owner, b, h_in).unwrap();
        let leaf = tapleaf(&s.settle);
        let sh = entry_sighash(2, 0, txid, vout, amount, &s.spk(), 0xffff_fffd, out_value, out_spk, &leaf).unwrap();
        json!({"owner": h(owner), "channel": {"txid": h(txid), "vout": vout},
               "input": {"txid": h(txid), "vout": vout, "amount": amount, "spk": h(&s.spk()), "sequence": 0xffff_fffdu32, "leaf": h(&s.settle), "leaf_hash": h(&leaf)},
               "output": {"value": out_value, "spk": h(out_spk), "kind": kind, "refund_height": h_out},
               "collateral": amount, "carry_in": 0, "net": net, "rows": [], "sighash_type": 131, "sighash": h(&sh)})
    }

    /// Deposit -> registration -> daemon package checked against the venue's records -> owner
    /// signature (agent key refused) -> result -> roll applied at confirmation -> withdrawal request
    /// (flat only) -> withdraw package -> account closed; the journal restores it after a restart.
    #[test]
    fn deposit_settle_withdraw_and_restore() {
        let dir = std::env::temp_dir().join(format!("shz-venue-coll-{}", now_us()));
        let (tsk, bsk, agent_sk) = ([0x41u8; 32], [0x42u8; 32], [0x43u8; 32]);
        let (t, b) = (pubkey_x_from_secret(&tsk).unwrap(), pubkey_x_from_secret(&bsk).unwrap());
        let deposit_txid = [0xd1u8; 32];
        let post = |v: &mut Venue, path: &str, body: &Value, k: &Key| {
            let raw = serde_json::to_vec(body).unwrap();
            let auth = sigx(k, &post_digest(&raw));
            if path == "package" { v.settlement_package(&raw, Some(&auth)) } else { v.settlement_result(&raw, Some(&auth)) }
        };
        let settle_txid = [0x5eu8; 32];
        let wd_txid = [0x6eu8; 32];
        {
            let mut v = Venue::open(&dir, [7; 32], "http://127.0.0.1:9".into()).unwrap();
            v.collateral_enable(cfg(b)).unwrap();
            assert!(v.collateral_address(t).is_err(), "no tip yet");
            v.coll.as_mut().unwrap().tip = 200;
            assert_eq!(v.collateral_address(t).unwrap()["deposit"]["refund_height"], 300);
            assert!(v.register_draft(t, "demo", None, None).is_err(), "demo is refused under --collateral-chain");
            v.coll.as_mut().unwrap().seen.insert(t, Seen { txid: deposit_txid, vout: 1, value: 50_000, height: 201 });
            assert!(v.register_draft(t, "collateral", None, None).unwrap_err().contains("1 of 2"));
            v.coll.as_mut().unwrap().tip = 202;
            let d = v.register_draft(t, "collateral", None, None).unwrap();
            assert_eq!(d["cap_sats"], 50_000);
            let digest = parse_key(d["allocation_digest"].as_str().unwrap()).unwrap();
            v.register(d["draft_id"].as_str().unwrap(), parse_sig(&sigx(&tsk, &digest)).unwrap()).unwrap();
            assert_eq!(v.balance(&t).unwrap().free, 50_000);
            assert_eq!(v.collateral_explorer(&t).unwrap()["refund_height"], 300);

            // Epoch package: roll the whole account (net 0) to account(T, B, 400).
            let roll = AccountScript::new(&t, &b, 400).unwrap();
            let pkg = |e: Value, seg: u64| json!({"version": 1, "network": "regtest", "epoch": "SHZ-BTCUSD-T1", "segment": seg, "first_seq": 1, "last_seq": 0,
                                                 "deadline_us": now_us() + 60_000_000, "tx": {"version": 2, "locktime": 0}, "accounts": [e]});
            let good = entry(&t, &b, &deposit_txid, 1, 50_000, 300, 50_000, &roll.spk(), "roll", Some(400), 0);
            assert!(post(&mut v, "package", &pkg(good.clone(), 0), &agent_sk).unwrap_err().contains("X-SHZ-Batcher"));
            let short = entry(&t, &b, &deposit_txid, 1, 50_000, 300, 49_999, &roll.spk(), "roll", Some(400), -1);
            assert!(post(&mut v, "package", &pkg(short, 0), &bsk).unwrap_err().contains("net 0"));
            let thief = entry(&t, &b, &deposit_txid, 1, 50_000, 300, 50_000, &[vec![0x51, 0x20], vec![0x55; 32]].concat(), "roll", Some(400), 0);
            assert!(post(&mut v, "package", &pkg(thief, 0), &bsk).unwrap_err().contains("not account"));
            let wrong_in = entry(&t, &b, &[0xd2; 32], 1, 50_000, 300, 50_000, &roll.spk(), "roll", Some(400), 0);
            assert!(post(&mut v, "package", &pkg(wrong_in, 0), &bsk).unwrap_err().contains("neither"));
            let unasked = entry(&t, &b, &deposit_txid, 1, 50_000, 300, 50_000, &[vec![0x00, 0x14], vec![0x66; 20]].concat(), "withdraw", None, 0);
            assert!(post(&mut v, "package", &pkg(unasked, 0), &bsk).unwrap_err().contains("without a pending withdrawal"));
            let mut bad_sh = good.clone();
            bad_sh["sighash"] = json!(h(&[0; 32]));
            assert!(post(&mut v, "package", &pkg(bad_sh, 0), &bsk).unwrap_err().contains("sighash"));
            post(&mut v, "package", &pkg(good.clone(), 0), &bsk).unwrap();
            let p = v.settlement_package_for(&t).unwrap();
            assert_eq!(p["account"]["signed"], false);
            let sh = parse_key(p["venue"]["sighash"].as_str().unwrap()).unwrap();
            let sig83 = |k: &Key| format!("{}83", sigx(k, &sh));
            assert!(v.settlement_signature(&json!({"epoch": "SHZ-BTCUSD-T1", "segment": 0, "owner": h(&t), "sig": sig83(&agent_sk)})).unwrap_err().contains("BAD"));
            assert!(v.settlement_signature(&json!({"epoch": "SHZ-BTCUSD-T1", "segment": 0, "owner": h(&t), "sig": sigx(&tsk, &sh)})).unwrap_err().contains("65 bytes"));
            assert_eq!(v.settlement_signature(&json!({"epoch": "SHZ-BTCUSD-T1", "segment": 0, "owner": h(&t), "sig": sig83(&tsk)})).unwrap()["complete"], true);
            assert_eq!(v.settlement_signatures("SHZ-BTCUSD-T1", 0).unwrap()["signatures"].as_array().unwrap().len(), 1);
            let res = json!({"epoch": "SHZ-BTCUSD-T1", "segment": 0, "status": "broadcast", "txid": h(&settle_txid), "payouts": [{"owner": h(&t), "value": 50_000, "kind": "roll", "vout": 0}], "rolled": []});
            assert!(post(&mut v, "result", &res, &agent_sk).is_err());
            post(&mut v, "result", &res, &bsk).unwrap();
            assert!(v.settlement_package_for(&t).is_err(), "package closed by the result");
            // The prover's second result for the segment updates the first; payouts are not taken twice.
            let mut proved = res.clone();
            proved["statement_sha256"] = json!(h(&[0x5a; 32]));
            assert_eq!(post(&mut v, "result", &proved, &bsk).unwrap()["updated"], true);
            assert_eq!(v.settlement_results(10).unwrap().as_array().unwrap().len(), 1);
            assert_eq!(v.settlement_results(10).unwrap()[0]["statement_sha256"], h(&[0x5a; 32]));
            assert_eq!(v.coll.as_ref().unwrap().pending.len(), 1);
            // The watcher saw the roll at min-conf.
            let pend = v.coll.as_ref().unwrap().pending[0].clone();
            v.settlement_confirmed(&pend, 0, 205).unwrap();
            let c = v.collateral_view(&t).unwrap();
            assert_eq!(c["account"]["outpoint"]["txid"], h(&settle_txid));
            assert_eq!(c["account"]["refund_height"], 400);
            assert_eq!(v.collateral_explorer(&t).unwrap()["spk"], h(&roll.spk()));

            // Withdrawal: owner-signed, whole account, router debited, new orders refused.
            let spk = [vec![0x00, 0x14], vec![0x66; 20]].concat();
            let wbody = |k: &Key, tu: u64| json!({"owner": h(&t), "spk": h(&spk), "time_us": tu, "sig": sigx(k, &withdraw_msg(&t, &spk, tu))});
            assert!(v.collateral_withdraw(&wbody(&agent_sk, 1)).unwrap_err().contains("signature"));
            v.collateral_withdraw(&wbody(&tsk, 2)).unwrap();
            assert!(v.collateral_withdraw(&wbody(&tsk, 3)).unwrap_err().contains("already pending"));
            assert_eq!(v.balance(&t).unwrap().free, 0);
            assert!(v.collateral_gate(&t).unwrap_err().contains("withdrawal is pending"));
            assert_eq!(v.collateral_withdrawals().unwrap().as_array().unwrap().len(), 1);
            let w = entry(&t, &b, &settle_txid, 0, 50_000, 400, 50_000, &spk, "withdraw", None, 0);
            let mut wp = pkg(w, 0);
            wp["epoch"] = json!("SHZ-BTCUSD-T2");
            post(&mut v, "package", &wp, &bsk).unwrap();
            let sh2 = parse_key(v.settlement_package_for(&t).unwrap()["venue"]["sighash"].as_str().unwrap()).unwrap();
            v.settlement_signature(&json!({"epoch": "SHZ-BTCUSD-T2", "segment": 0, "owner": h(&t), "sig": format!("{}83", sigx(&tsk, &sh2))})).unwrap();
            post(&mut v, "result", &json!({"epoch": "SHZ-BTCUSD-T2", "segment": 0, "status": "broadcast", "txid": h(&wd_txid), "payouts": [{"owner": h(&t), "value": 50_000, "kind": "withdraw"}], "rolled": []}), &bsk).unwrap();
            let pend = v.coll.as_ref().unwrap().pending[0].clone();
            assert_eq!(pend.vout, None, "no vout reported: the watcher scans the outputs");
            v.settlement_confirmed(&pend, 3, 210).unwrap();
            assert!(v.collateral_gate(&t).unwrap_err().contains("closed"));
            assert_eq!(v.collateral_withdrawals().unwrap().as_array().unwrap().len(), 0);
        }
        // Restart: the journal rebuilds the account, its rolls, the withdrawal and the closure.
        let mut v = Venue::open(&dir, [7; 32], "http://127.0.0.1:9".into()).unwrap();
        v.collateral_enable(cfg(b)).unwrap();
        let c = v.collateral_view(&t).unwrap();
        assert_eq!(c["account"]["channel"]["txid"], h(&deposit_txid));
        assert_eq!(c["account"]["withdrawal"]["status"], "paid");
        assert_eq!(c["account"]["withdrawal"]["txid"], h(&wd_txid));
        assert!(c["account"]["closed"].as_str().unwrap().contains("withdrawn"));
        assert_eq!(v.settlement_results(10).unwrap().as_array().unwrap().len(), 2);
        assert_eq!(v.balance(&t).unwrap().free, 0);
        assert_eq!(v.account_view(&t)["label"], "regtest collateral");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
