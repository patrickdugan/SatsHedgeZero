//! Lightninger DLC batcher: Taproot scripts of the collateral accounts and the BitVM3 claim graph,
//! transaction building and BIP-341/342 signing on top of `lightninger_bitvm3_clearing`'s `Tx` and
//! TapSighash reference, the conversion from venue explorer JSON to the batch relation, and a
//! Bitcoin Core node handle for regtest and testnet4.
#![forbid(unsafe_code)]

use k256::{
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, PrimeField},
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

/// BIP-341 tweak of x-only `p` with no script tree (`TapTweak(p)`).
pub fn tweak_keypath_only(p: &[u8; 32]) -> ([u8; 32], u8) {
    let vk = VerifyingKey::from_bytes(p).unwrap();
    let pp: ProjectivePoint = (*vk.as_affine()).into();
    let t = tagged_hash(b"TapTweak", p);
    let ts = Option::<Scalar>::from(Scalar::from_repr(t.into())).unwrap();
    let e = (pp + ProjectivePoint::GENERATOR * ts).to_affine().to_encoded_point(true);
    (e.as_bytes()[1..33].try_into().unwrap(), e.as_bytes()[0] & 1)
}

/// A P2TR output: internal key (NUMS unless given) and zero, one or two leaves.
#[derive(Clone, Debug)]
pub struct TapOutput {
    pub internal: [u8; 32],
    pub leaves: Vec<Vec<u8>>,
    pub output_key: [u8; 32],
    parity: u8,
}

impl TapOutput {
    pub fn new(leaves: Vec<Vec<u8>>) -> Self {
        Self::with_internal(NUMS, leaves)
    }
    pub fn with_internal(internal: [u8; 32], leaves: Vec<Vec<u8>>) -> Self {
        assert!(leaves.len() <= 2);
        let (q, parity) = match Self::root_of(&leaves) {
            Some(root) => tweak(&internal, &root),
            None => tweak_keypath_only(&internal),
        };
        TapOutput { internal, leaves, output_key: q, parity }
    }
    fn root_of(leaves: &[Vec<u8>]) -> Option<[u8; 32]> {
        let hs: Vec<[u8; 32]> = leaves.iter().map(|l| tapleaf(l)).collect();
        match hs.len() {
            0 => None,
            1 => Some(hs[0]),
            _ => Some(branch(&hs[0], &hs[1])),
        }
    }
    /// The script tree's merkle root (`None` for a key-path-only output).
    pub fn merkle_root(&self) -> Option<[u8; 32]> {
        Self::root_of(&self.leaves)
    }
    /// The BIP-341 tweak scalar bytes `TapTweak(internal ‖ root)`.
    pub fn tweak_bytes(&self) -> [u8; 32] {
        match self.merkle_root() {
            Some(r) => tagged_hash(b"TapTweak", &[&self.internal[..], &r[..]].concat()),
            None => tagged_hash(b"TapTweak", &self.internal),
        }
    }
    pub fn spk(&self) -> Vec<u8> {
        [vec![0x51, 0x20], self.output_key.to_vec()].concat()
    }
    pub fn leaf_hash(&self, i: usize) -> [u8; 32] {
        tapleaf(&self.leaves[i])
    }
    pub fn control(&self, i: usize) -> Vec<u8> {
        let mut c = vec![0xc0 | self.parity];
        c.extend(self.internal);
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

/// `SHZ-BTCUSD-YYYYMMDDTHHMMZ` of the 15-minute oracle maturity at or after `us` (Unix microseconds).
pub fn maturity_event(us: u64) -> String {
    let s = (us / 1_000_000).div_ceil(900) * 900;
    let (days, rem) = (s / 86_400, s % 86_400);
    // civil-from-days (Howard Hinnant)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("SHZ-BTCUSD-{y:04}{m:02}{d:02}T{:02}{:02}Z", rem / 3600, rem % 3600 / 60)
}

/// A signed settlement and its signature slots (input order, trader before batcher).
pub struct Built {
    pub tx: Tx,
    pub slots: Vec<BoundSlot>,
}

/// Amounts and keys of one run (regtest constants, or testnet4 keys from a file outside the repo).
pub struct SettleKeys {
    pub collateral: u64,
    pub liquidity: u64,
    pub batcher_sk: [u8; 32],
    pub operator_sk: [u8; 32],
}

/// Variant A settlement (script-leaf accounts): inputs `accts` (account output, display txid, vout)
/// then the operator's liquidity `liq`; outputs `payouts`, the marker, `change`. Traders sign their
/// input with SIGHASH_SINGLE|ANYONECANPAY, the batcher every account input with SIGHASH_DEFAULT, the
/// operator its input. `tamper` moves `d` sats from output `i` to the change after the traders signed
/// (the result must be refused).
#[allow(clippy::too_many_arguments)]
pub fn settlement(p: &SettleKeys, accts: &[(TapOutput, String, u32)], liq: &(TapOutput, String, u32), payouts: &[(u64, Vec<u8>)], marker: Vec<u8>, change: u64, change_spk: &[u8], traders: &[[u8; 32]], tamper: Option<(usize, i64)>) -> Built {
    settlement_a(p, accts, liq, payouts, marker, change, change_spk, traders, None, tamper)
}

/// [`settlement`] with each trader's SIGHASH_SINGLE|ANYONECANPAY signature made as an adaptor
/// signature under the oracle's outcome point and completed with the attestation scalar
/// (`oracle = Some`), as a DLC CET is.
#[allow(clippy::too_many_arguments)]
pub fn settlement_a(p: &SettleKeys, accts: &[(TapOutput, String, u32)], liq: &(TapOutput, String, u32), payouts: &[(u64, Vec<u8>)], marker: Vec<u8>, change: u64, change_spk: &[u8], traders: &[[u8; 32]], oracle: Option<&Oracle>, tamper: Option<(usize, i64)>) -> Built {
    let mut outs: Vec<_> = payouts.iter().map(|(v, s)| out(*v, s.clone())).collect();
    outs.push(out(0, marker));
    outs.push(out(change, change_spk.to_vec()));
    let mut ins: Vec<_> = accts.iter().map(|(_, t, v)| input(t, *v, 0xffff_fffd)).collect();
    ins.push(input(&liq.1, liq.2, 0xffff_fffd));
    let mut tx = Tx { version: 2, inputs: ins, outputs: outs, locktime: 0, witness: vec![] };
    let mut amounts = vec![p.collateral; accts.len()];
    amounts.push(p.liquidity);
    let mut spks: Vec<Vec<u8>> = accts.iter().map(|(o, _, _)| o.spk()).collect();
    spks.push(liq.0.spk());
    // traders sign SINGLE|ACP over the honest outputs
    let trader_sigs: Vec<(Vec<u8>, BoundSlot)> = (0..accts.len()).map(|i| sign_leaf_oracle(&tx, &amounts, &spks, i, &accts[i].0, 0, &traders[i], SIGHASH_SINGLE_ACP, oracle)).collect();
    if let Some((i, d)) = tamper {
        tx.outputs[i].value = (tx.outputs[i].value as i64 + d) as u64;
        let n = tx.outputs.len() - 1;
        tx.outputs[n].value = (tx.outputs[n].value as i64 - d) as u64;
    }
    let mut slots = Vec::new();
    let mut wit = Vec::new();
    for i in 0..accts.len() {
        let (sb, bs) = sign_leaf(&tx, &amounts, &spks, i, &accts[i].0, 0, &p.batcher_sk, 0);
        // `<T> CHECKSIGVERIFY <B> CHECKSIG` consumes the trader's signature first (top of stack)
        wit.push(vec![sb, trader_sigs[i].0.clone(), accts[i].0.leaves[0].clone(), accts[i].0.control(0)]);
        slots.push(trader_sigs[i].1.clone());
        slots.push(bs);
    }
    let (so, bo) = sign_leaf(&tx, &amounts, &spks, accts.len(), &liq.0, 0, &p.operator_sk, 0);
    wit.push(vec![so, liq.0.leaves[0].clone(), liq.0.control(0)]);
    slots.push(bo);
    tx.witness = wit;
    Built { tx, slots }
}

pub fn vsize(tx: &Tx) -> u64 {
    let full = serialize_signed(tx).len() as u64;
    let base = tx.stripped().len() as u64;
    (base * 3 + full).div_ceil(4)
}


// ---------------------------------------------------------------------------------------------
// DLC oracle adaptor and variant B (MuSig2 key path)
// ---------------------------------------------------------------------------------------------

/// The attested outcome of a DLC event: its adaptor (anticipation) point and attestation scalar.
#[derive(Clone, Debug)]
pub struct Oracle {
    pub point: ProjectivePoint,
    pub scalar: [u8; 32],
}

/// [`sign_leaf`], with the signature made as a BIP-340 adaptor signature under `oracle.point`,
/// verified as an adaptor, then completed with `oracle.scalar` (plain signature when `None`).
#[allow(clippy::too_many_arguments)]
pub fn sign_leaf_oracle(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], i: usize, o: &TapOutput, leaf: usize, signer: &[u8; 32], hash_type: u8, oracle: Option<&Oracle>) -> (Vec<u8>, BoundSlot) {
    let Some(or) = oracle else { return sign_leaf(tx, amounts, spks, i, o, leaf, signer, hash_type) };
    let e = ScriptPath { key: xonly(signer), tapleaf: o.leaf_hash(leaf), codesep: u32::MAX };
    let m = tap_sighash_ext(tx, amounts, spks, i, hash_type, None, Some(&e)).unwrap();
    let a = shz_dlc::adaptor_sign(signer, &m, &or.point).unwrap();
    shz_dlc::adaptor_verify(&e.key, &m, &or.point, &a).expect("adaptor verifies");
    let t = Option::<Scalar>::from(Scalar::from_repr(or.scalar.into())).expect("attestation scalar");
    let s = shz_dlc::adaptor_complete(&a, &t).unwrap();
    shz_dlc::bip340_verify(&e.key, &m, &s).expect("completed adaptor verifies");
    let mut sig = [s.r_x, s.s].concat();
    if hash_type != 0 {
        sig.push(hash_type);
    }
    (sig, BoundSlot { slot: SigSlot { input: i, hash_type, annex: None, sig_rx: s.r_x, sig_s: s.s }, script_path: Some(e) })
}

pub fn plain_pk(sk: &[u8; 32]) -> [u8; 33] {
    shz_dlc::musig2::individual_pk(sk).expect("valid secret key")
}

/// Variant B collateral account: internal key MuSig2(trader, batcher) (BIP-327 key aggregation of
/// the sorted plain keys), one leaf `<h> CLTV DROP <T> CHECKSIG`. Returns the output and the sorted
/// key list the MuSig2 sessions use.
pub fn account_output_b(trader: &[u8; 33], batcher: &[u8; 33], refund_height: u32) -> (TapOutput, Vec<[u8; 33]>) {
    let pks = shz_dlc::musig2::key_sort(&[*trader, *batcher]);
    let agg = shz_dlc::musig2::key_agg(&pks).unwrap().xonly();
    let tx: [u8; 32] = trader[1..].try_into().unwrap();
    let refund = [num(refund_height), vec![OP_CLTV, OP_DROP], push32(&tx), vec![OP_CHECKSIG]].concat();
    (TapOutput::with_internal(agg, vec![refund]), pks)
}

/// A key-path-only P2TR output of one key (`TapTweak(K)`, no script tree).
pub fn keypath_output(k: &[u8; 32]) -> TapOutput {
    TapOutput::with_internal(*k, vec![])
}

/// Single-key key-path signature of input `i`: the secret tweaked by the output's tweak.
pub fn sign_keypath(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], i: usize, o: &TapOutput, sk: &[u8; 32], hash_type: u8) -> (Vec<u8>, BoundSlot) {
    let m = tap_sighash_ext(tx, amounts, spks, i, hash_type, None, None).unwrap();
    let mut d = Option::<Scalar>::from(Scalar::from_repr((*sk).into())).unwrap();
    if bool::from((ProjectivePoint::GENERATOR * d).to_affine().y_is_odd()) {
        d = -d;
    }
    let t = Option::<Scalar>::from(Scalar::from_repr(o.tweak_bytes().into())).unwrap();
    let dt: [u8; 32] = (d + t).to_bytes().into();
    let s = bip340_sign(&dt, &m).unwrap();
    shz_dlc::bip340_verify(&o.output_key, &m, &s).expect("key-path signature verifies");
    let mut sig = [s.r_x, s.s].concat();
    if hash_type != 0 {
        sig.push(hash_type);
    }
    (sig, BoundSlot { slot: SigSlot { input: i, hash_type, annex: None, sig_rx: s.r_x, sig_s: s.s }, script_path: None })
}

/// Bytes and rounds one MuSig2 session exchanges between two signers: round 1 public nonces
/// (66 bytes each way), round 2 partial signatures (32 bytes each way).
pub const MUSIG2_ROUNDS: u32 = 2;
pub const MUSIG2_BYTES_2OF2: usize = 2 * 66 + 2 * 32;
/// A BIP-340 adaptor signature on the wire (`r_eff_x`, negation flag, `s_adapt`).
pub const ADAPTOR_SIG_BYTES: usize = 65;

/// MuSig2 (BIP-327) key-path signature of input `i` of `o` (internal key = aggregate of `pks`,
/// Taproot x-only tweak), by the signers `sks` (any order), with `hash_type`; as an adaptor
/// signature under `oracle.point` completed with `oracle.scalar` when given. Both partial
/// signatures are verified before aggregation and the result is verified against the output key.
#[allow(clippy::too_many_arguments)]
pub fn sign_musig_keypath(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], i: usize, o: &TapOutput, pks: &[[u8; 33]], sks: &[[u8; 32]], hash_type: u8, oracle: Option<&Oracle>) -> (Vec<u8>, BoundSlot) {
    use shz_dlc::musig2 as mu;
    let m = tap_sighash_ext(tx, amounts, spks, i, hash_type, None, None).unwrap();
    let tweak = o.tweak_bytes();
    let mut secs = Vec::new();
    let mut pubs = Vec::new();
    for sk in sks {
        let (s, p) = mu::nonce_gen(Some(sk), &plain_pk(sk), Some(&o.output_key), Some(&m), None).unwrap();
        secs.push(s);
        pubs.push(p);
    }
    let session = mu::Session { aggnonce: mu::nonce_agg(&pubs).unwrap(), pubkeys: pks.to_vec(), tweaks: vec![tweak], is_xonly: vec![true], msg: m.to_vec(), adaptor: oracle.map(|x| x.point) };
    let mut psigs = Vec::new();
    for (j, sk) in sks.iter().enumerate() {
        let ps = mu::sign(&mut secs[j], sk, &session).unwrap();
        assert!(mu::partial_sig_verify_internal(&ps, &pubs[j], &plain_pk(sk), &session).unwrap(), "partial signature {j}");
        psigs.push(ps);
    }
    let agg = mu::partial_sig_agg(&psigs, &session).unwrap();
    let fin = match oracle {
        Some(or) => mu::adaptor_complete(&agg, &or.scalar, mu::adaptor_negated(&session).unwrap()).unwrap(),
        None => agg,
    };
    let s = shz_dlc::Bip340Signature { r_x: fin[..32].try_into().unwrap(), s: fin[32..].try_into().unwrap() };
    shz_dlc::bip340_verify(&o.output_key, &m, &s).expect("MuSig2 key-path signature verifies");
    let mut sig = fin.to_vec();
    if hash_type != 0 {
        sig.push(hash_type);
    }
    (sig, BoundSlot { slot: SigSlot { input: i, hash_type, annex: None, sig_rx: s.r_x, sig_s: s.s }, script_path: None })
}

/// Variant B settlement: account inputs spent by MuSig2(trader, batcher) key-path signatures with
/// SIGHASH_SINGLE|ANYONECANPAY (adaptor under the oracle point when given), the operator's
/// key-path liquidity input with SIGHASH_DEFAULT. Same inputs, outputs and `tamper` as variant A.
#[allow(clippy::too_many_arguments)]
pub fn settlement_b(p: &SettleKeys, accts: &[(TapOutput, String, u32, Vec<[u8; 33]>)], liq: &(TapOutput, String, u32), payouts: &[(u64, Vec<u8>)], marker: Vec<u8>, change: u64, change_spk: &[u8], traders: &[[u8; 32]], oracle: Option<&Oracle>, tamper: Option<(usize, i64)>) -> Built {
    let mut outs: Vec<_> = payouts.iter().map(|(v, s)| out(*v, s.clone())).collect();
    outs.push(out(0, marker));
    outs.push(out(change, change_spk.to_vec()));
    let mut ins: Vec<_> = accts.iter().map(|(_, t, v, _)| input(t, *v, 0xffff_fffd)).collect();
    ins.push(input(&liq.1, liq.2, 0xffff_fffd));
    let mut tx = Tx { version: 2, inputs: ins, outputs: outs, locktime: 0, witness: vec![] };
    let mut amounts = vec![p.collateral; accts.len()];
    amounts.push(p.liquidity);
    let mut spks: Vec<Vec<u8>> = accts.iter().map(|(o, _, _, _)| o.spk()).collect();
    spks.push(liq.0.spk());
    let joint: Vec<(Vec<u8>, BoundSlot)> = (0..accts.len()).map(|i| sign_musig_keypath(&tx, &amounts, &spks, i, &accts[i].0, &accts[i].3, &[traders[i], p.batcher_sk], SIGHASH_SINGLE_ACP, oracle)).collect();
    if let Some((i, d)) = tamper {
        tx.outputs[i].value = (tx.outputs[i].value as i64 + d) as u64;
        let n = tx.outputs.len() - 1;
        tx.outputs[n].value = (tx.outputs[n].value as i64 - d) as u64;
    }
    let mut wit: Vec<Vec<Vec<u8>>> = joint.iter().map(|(s, _)| vec![s.clone()]).collect();
    let mut slots: Vec<BoundSlot> = joint.into_iter().map(|(_, b)| b).collect();
    let (so, bo) = sign_keypath(&tx, &amounts, &spks, accts.len(), &liq.0, &p.operator_sk, 0);
    wit.push(vec![so]);
    slots.push(bo);
    tx.witness = wit;
    Built { tx, slots }
}
