//! Lightninger DLC batcher: Taproot scripts of the collateral accounts and the BitVM3 claim graph,
//! transaction building and BIP-341/342 signing on top of `lightninger_bitvm3_clearing`'s `Tx` and
//! TapSighash reference, the conversion from venue explorer JSON to the batch relation, and a
//! Bitcoin Core node handle for regtest and testnet4.
#![forbid(unsafe_code)]

use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    schnorr::VerifyingKey,
    ProjectivePoint, Scalar,
};
use lightninger_bitvm3_clearing::{
    gadgets::tagged_hash,
    tapsighash_step::{tap_sighash_ext, BoundSlot, ScriptPath, SigSlot, Tx, TxIn, TxOut},
};
use lightninger_dlc_batch_relation as rel;
use serde_json::Value;
use shz_dlc::{bip340_sign, pubkey_x_from_secret};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

/// BIP-341's provably unspendable internal key `H` (lift_x of SHA256(G)).
pub const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CLTV: u8 = 0xb1;
pub const OP_CSV: u8 = 0xb2;
pub const OP_DROP: u8 = 0x75;
pub const OP_SHA256: u8 = 0xa8;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const SIGHASH_SINGLE_ACP: u8 = 0x83;

pub fn xonly(sk: &[u8; 32]) -> [u8; 32] {
    pubkey_x_from_secret(sk).expect("valid secret key")
}

pub fn push32(x: &[u8; 32]) -> Vec<u8> {
    [vec![0x20], x.to_vec()].concat()
}

/// Minimal CScriptNum push of a non-negative number (heights, CSV counts).
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

pub fn tapleaf(script: &[u8]) -> [u8; 32] {
    let mut m = vec![0xc0];
    m.extend(rel::compact(script.len()));
    m.extend(script);
    tagged_hash(b"TapLeaf", &m)
}

pub fn branch(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (x, y) = if a < b { (a, b) } else { (b, a) };
    tagged_hash(b"TapBranch", &[&x[..], &y[..]].concat())
}

pub fn tweak(p: &[u8; 32], root: &[u8; 32]) -> ([u8; 32], u8) {
    let vk = VerifyingKey::from_bytes(p).unwrap();
    let pp: ProjectivePoint = (*vk.as_affine()).into();
    let t = tagged_hash(b"TapTweak", &[&p[..], &root[..]].concat());
    let ts = Option::<Scalar>::from(Scalar::from_repr(t.into())).unwrap();
    let q = (pp + ProjectivePoint::GENERATOR * ts).to_affine();
    let e = q.to_encoded_point(true);
    (e.as_bytes()[1..33].try_into().unwrap(), e.as_bytes()[0] & 1)
}

/// A NUMS-keyed P2TR output with one or two leaves.
#[derive(Clone, Debug)]
pub struct TapOutput {
    pub leaves: Vec<Vec<u8>>,
    pub output_key: [u8; 32],
    parity: u8,
}

impl TapOutput {
    pub fn new(leaves: Vec<Vec<u8>>) -> Self {
        assert!(leaves.len() == 1 || leaves.len() == 2);
        let hs: Vec<[u8; 32]> = leaves.iter().map(|l| tapleaf(l)).collect();
        let root = if hs.len() == 1 { hs[0] } else { branch(&hs[0], &hs[1]) };
        let (q, parity) = tweak(&NUMS, &root);
        TapOutput { leaves, output_key: q, parity }
    }
    pub fn spk(&self) -> Vec<u8> {
        [vec![0x51, 0x20], self.output_key.to_vec()].concat()
    }
    pub fn leaf_hash(&self, i: usize) -> [u8; 32] {
        tapleaf(&self.leaves[i])
    }
    pub fn control(&self, i: usize) -> Vec<u8> {
        let mut c = vec![0xc0 | self.parity];
        c.extend(NUMS);
        if self.leaves.len() == 2 {
            c.extend(tapleaf(&self.leaves[1 - i]));
        }
        c
    }
}

/// Collateral account of trader `t` against batcher `b`: leaf 0 settle `<T> CHECKSIGVERIFY <B>
/// CHECKSIG` (the trader signs its own input and output with SIGHASH_SINGLE|ANYONECANPAY, the
/// batcher signs the whole transaction); leaf 1 refund `<h> CLTV DROP <T> CHECKSIG`.
pub fn account_output(t: &[u8; 32], b: &[u8; 32], refund_height: u32) -> TapOutput {
    let settle = [push32(t), vec![OP_CHECKSIGVERIFY], push32(b), vec![OP_CHECKSIG]].concat();
    let refund = [num(refund_height), vec![OP_CLTV, OP_DROP], push32(t), vec![OP_CHECKSIG]].concat();
    TapOutput::new(vec![settle, refund])
}

/// One-key script-path output (`<K> CHECKSIG`): payouts and operator liquidity.
pub fn key_output(k: &[u8; 32]) -> TapOutput {
    TapOutput::new(vec![[push32(k), vec![OP_CHECKSIG]].concat()])
}

pub fn serialize_signed(tx: &Tx) -> Vec<u8> {
    let s = tx.stripped();
    if tx.witness.iter().all(|w| w.is_empty()) {
        return s;
    }
    let mut v = s[..4].to_vec();
    v.extend([0, 1]);
    v.extend(&s[4..s.len() - 4]);
    for w in &tx.witness {
        v.extend(rel::compact(w.len()));
        for item in w {
            v.extend(rel::compact(item.len()));
            v.extend(item);
        }
    }
    v.extend(&s[s.len() - 4..]);
    v
}

/// Display-order hex txid to the internal byte order a `TxIn` holds.
pub fn txid_internal(display_hex: &str) -> [u8; 32] {
    let mut b: [u8; 32] = hex::decode(display_hex).unwrap().try_into().unwrap();
    b.reverse();
    b
}

pub fn txid_display(tx: &Tx) -> [u8; 32] {
    tx.txid()
}

pub fn input(txid_display_hex: &str, vout: u32, sequence: u32) -> TxIn {
    TxIn { txid: txid_internal(txid_display_hex), vout, script_sig: vec![], sequence }
}

pub fn out(value: u64, spk: Vec<u8>) -> TxOut {
    TxOut { value, spk }
}

/// Sign script-path input `i` of `tx` through leaf `leaf` of `o` for `signer` with `hash_type`.
/// Returns the 64/65-byte signature and its bound slot.
pub fn sign_leaf(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], i: usize, o: &TapOutput, leaf: usize, signer: &[u8; 32], hash_type: u8) -> (Vec<u8>, BoundSlot) {
    let e = ScriptPath { key: xonly(signer), tapleaf: o.leaf_hash(leaf), codesep: u32::MAX };
    let m = tap_sighash_ext(tx, amounts, spks, i, hash_type, None, Some(&e)).unwrap();
    let s = bip340_sign(signer, &m).unwrap();
    let mut sig = [s.r_x, s.s].concat();
    if hash_type != 0 {
        sig.push(hash_type);
    }
    (sig, BoundSlot { slot: SigSlot { input: i, hash_type, annex: None, sig_rx: s.r_x, sig_s: s.s }, script_path: Some(e) })
}

/// The venue's committed batches (explorer JSON of `ops/venue-bench/dlc_batch/fills.mjs`) as the
/// relation's `Batch`es, each checked to digest like `shz_dex`'s `BatchClearing::digest`.
pub fn venue_batches(v: &Value) -> Result<Vec<rel::Batch>, String> {
    use shz_dex::routing::clearing::BatchClearing;
    let mut out = Vec::new();
    for b in v["batches"].as_array().ok_or("batches")? {
        let b = b.get("batch").unwrap_or(b);
        if b["phase"] != "committed" {
            return Err(format!("batch {} is not committed", b["seq"]));
        }
        let c: BatchClearing = serde_json::from_value(b["clearing"].clone()).map_err(|e| format!("clearing: {e}"))?;
        let r = rel::Batch {
            seq: b["seq"].as_u64().ok_or("seq")?,
            rows: c
                .rows
                .iter()
                .map(|r| rel::Row {
                    channel_txid: r.channel.txid,
                    channel_vout: r.channel.vout,
                    pnl: r.pnl,
                    released: r.released,
                    collected: r.collected,
                    own_claim_used: r.own_claim_used,
                    shortfall: r.shortfall,
                    haircut: r.haircut,
                    claim_before: r.claim_before,
                    claim_after: r.claim_after,
                    paid: r.paid,
                    net: r.net,
                })
                .collect(),
            claim_haircuts: c.claim_haircuts.iter().map(|(o, h)| (o.txid, o.vout, *h)).collect(),
            shortfall: c.shortfall,
            fund_absorbed: c.fund_absorbed,
            haircut: c.haircut,
            layer: c.layer as u8,
            cash_before: c.cash_before,
            cash_after: c.cash_after,
            fund_after: c.fund_after,
            carry_after: c.carry_after,
            claims_after: c.claims_after,
        };
        if r.digest() != c.digest() {
            return Err(format!("batch {}: relation digest differs from BatchClearing::digest", r.seq));
        }
        out.push(r);
    }
    Ok(out)
}

/// A bitcoind handle: either a node this process spawned on a datadir, or an existing node reached
/// with `bitcoin-cli` arguments.
pub struct Node {
    child: Option<Child>,
    cli: PathBuf,
    args: Vec<String>,
}

impl Node {
    /// Spawn regtest on `datadir` (created if missing, kept on drop so later phases reuse the chain).
    pub fn regtest(bitcoind: &Path, datadir: &Path) -> Node {
        let cli = bitcoind.with_file_name(if cfg!(windows) { "bitcoin-cli.exe" } else { "bitcoin-cli" });
        let free = || TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (port, p2p) = (free(), free());
        std::fs::create_dir_all(datadir).unwrap();
        let child = Command::new(bitcoind)
            .args(["-regtest", "-server=1", "-txindex=1", "-fallbackfee=0.0001", "-rpcuser=lbc", "-rpcpassword=lbc", "-listen=0", "-dnsseed=0"])
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={port}"))
            .arg(format!("-port={p2p}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind");
        let args = vec!["-regtest".into(), "-rpcuser=lbc".into(), "-rpcpassword=lbc".into(), format!("-datadir={}", datadir.display()), format!("-rpcport={port}")];
        let n = Node { child: Some(child), cli, args };
        for _ in 0..400 {
            if n.try_cli(&["getblockchaininfo"]).is_ok() {
                return n;
            }
            thread::sleep(Duration::from_millis(150));
        }
        panic!("bitcoind RPC not ready");
    }
    pub fn existing(cli: PathBuf, args: Vec<String>) -> Node {
        Node { child: None, cli, args }
    }
    pub fn try_cli(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.cli).args(&self.args).args(args).output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
    pub fn cli(&self, args: &[&str]) -> String {
        self.try_cli(args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }
    pub fn json(&self, args: &[&str]) -> Value {
        let s = self.cli(args);
        serde_json::from_str(&s).unwrap_or(Value::String(s))
    }
    pub fn height(&self) -> u32 {
        self.cli(&["getblockcount"]).parse().unwrap()
    }
    /// `testmempoolaccept` of one or more raw transactions (parents first).
    pub fn accept(&self, txs: &[&[u8]]) -> Value {
        let a: Vec<String> = txs.iter().map(hex::encode).collect();
        self.json(&["testmempoolaccept", &serde_json::to_string(&a).unwrap()])
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = Command::new(&self.cli).args(&self.args).arg("stop").output();
            for _ in 0..100 {
                if let Ok(Some(_)) = c.try_wait() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = c.kill();
        }
    }
}

/// Address of a P2TR output key on the node's network.
pub fn address(node: &Node, output_key: &[u8; 32]) -> String {
    let d = node.json(&["getdescriptorinfo", &format!("rawtr({})", hex::encode(output_key))]);
    node.json(&["deriveaddresses", d["descriptor"].as_str().unwrap()])[0].as_str().unwrap().to_string()
}
