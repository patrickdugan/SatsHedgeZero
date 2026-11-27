//! The DLC batcher's settlement relation, shared by the native verifier (`dlc-batcher`) and the SP1
//! wrap guest. Plain Rust plus SHA-256, so it compiles for the zkVM unchanged.
//!
//! A batch epoch settles `N` collateral accounts in one transaction:
//!
//! - inputs `0..N` spend the accounts, in manifest order; input `N` is the operator's liquidity;
//! - outputs `0..N` pay each account's owner `collateral + sum(net)`, where `net` is the account's
//!   row in every venue V3 batch of the epoch (`ClearingRow::net`, the sats the channel adapter
//!   moves on the account's lane);
//! - output `N` is `OP_RETURN "SHZB" || manifest_hash`, so the settlement txid commits to the
//!   manifest; later outputs (operator change, pool return) are the operator's.
//!
//! The batches are authenticated by the clearing fold: their digests, chained from zero, must give
//! the chain the fold's `z_K` ends in (its last two elements, little-endian 128-bit halves).
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type H32 = [u8; 32];

pub fn sha256(b: &[u8]) -> H32 {
    Sha256::digest(b).into()
}

pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> H32 {
    let t = sha256(tag);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

/// `ClearingRow` of `shz_dex::routing::clearing`, field for field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub channel_txid: H32,
    pub channel_vout: u32,
    pub pnl: i64,
    pub released: u64,
    pub collected: u64,
    pub own_claim_used: u64,
    pub shortfall: u64,
    pub haircut: u64,
    pub claim_before: u64,
    pub claim_after: u64,
    pub paid: u64,
    pub net: i64,
}

/// `BatchClearing` of one committed batch, field for field, with its sequence number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub seq: u64,
    pub rows: Vec<Row>,
    pub claim_haircuts: Vec<(H32, u32, u64)>,
    pub shortfall: u64,
    pub fund_absorbed: u64,
    pub haircut: u64,
    pub layer: u8,
    pub cash_before: i64,
    pub cash_after: i64,
    pub fund_after: u64,
    pub carry_after: u64,
    pub claims_after: u64,
}

impl Batch {
    /// `BatchClearing::digest`: `tagged_hash("SHZ/HFT/CLEARING/V1", ..)` over the whole vector.
    pub fn digest(&self) -> H32 {
        let mut b = Vec::new();
        b.extend((self.rows.len() as u64).to_le_bytes());
        for r in &self.rows {
            b.extend(r.channel_txid);
            b.extend(r.channel_vout.to_le_bytes());
            b.extend(r.pnl.to_le_bytes());
            for n in [r.released, r.collected, r.own_claim_used, r.shortfall, r.haircut, r.claim_before, r.claim_after, r.paid] {
                b.extend(n.to_le_bytes());
            }
            b.extend(r.net.to_le_bytes());
        }
        b.extend((self.claim_haircuts.len() as u64).to_le_bytes());
        for (t, v, h) in &self.claim_haircuts {
            b.extend(t);
            b.extend(v.to_le_bytes());
            b.extend(h.to_le_bytes());
        }
        for n in [self.shortfall, self.fund_absorbed, self.haircut] {
            b.extend(n.to_le_bytes());
        }
        b.push(self.layer);
        b.extend(self.cash_before.to_le_bytes());
        b.extend(self.cash_after.to_le_bytes());
        for n in [self.fund_after, self.carry_after, self.claims_after] {
            b.extend(n.to_le_bytes());
        }
        tagged_hash(b"SHZ/HFT/CLEARING/V1", &b)
    }
}

pub const CHAIN_TAG: &[u8] = b"LIGHTNINGER/V3CLEAR/CHAIN/V1";

/// `chain' = SHA256(CHAIN_TAG || chain || seq_le64 || digest)` (`clearing_step::chain_next`).
pub fn chain_next(chain: &H32, seq: u64, digest: &H32) -> H32 {
    let mut b = CHAIN_TAG.to_vec();
    b.extend_from_slice(chain);
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(digest);
    sha256(&b)
}

/// The chain of consecutive batches from zero, as the clearing fold computes it.
pub fn chain_of(batches: &[Batch]) -> Result<H32, String> {
    let mut c = [0u8; 32];
    for (i, b) in batches.iter().enumerate() {
        if i > 0 && b.seq != batches[i - 1].seq + 1 {
            return Err(format!("batch {} does not follow batch {}", b.seq, batches[i - 1].seq));
        }
        c = chain_next(&c, b.seq, &b.digest());
    }
    Ok(c)
}

pub fn le_halves(d: &H32) -> (u128, u128) {
    (u128::from_le_bytes(d[0..16].try_into().unwrap()), u128::from_le_bytes(d[16..32].try_into().unwrap()))
}

/// One collateral account. `outpoint_txid` is in display order (as `bitcoin-cli` prints it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// The venue channel (allocation outpoint) whose clearing rows this account settles.
    pub channel_txid: H32,
    pub channel_vout: u32,
    /// The account owner's x-only key: venue owner key and the account's trader leaf key.
    pub owner: H32,
    pub outpoint_txid: H32,
    pub outpoint_vout: u32,
    pub collateral: u64,
    pub account_spk: Vec<u8>,
    pub payout_spk: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub network_code: u8,
    /// The oracle maturity that closes the epoch (event id), and its number.
    pub event_id: String,
    pub epoch_id: u64,
    /// The batcher's x-only key (second key of every account's settle leaf).
    pub batcher: H32,
    pub accounts: Vec<Account>,
    pub operator_txid: H32,
    pub operator_vout: u32,
    pub operator_amount: u64,
    pub operator_spk: Vec<u8>,
}

fn put_bytes(b: &mut Vec<u8>, x: &[u8]) {
    b.extend((x.len() as u32).to_le_bytes());
    b.extend(x);
}

impl Manifest {
    pub fn hash(&self) -> H32 {
        let mut b = Vec::new();
        b.push(self.network_code);
        put_bytes(&mut b, self.event_id.as_bytes());
        b.extend(self.epoch_id.to_le_bytes());
        b.extend(self.batcher);
        b.extend((self.accounts.len() as u32).to_le_bytes());
        for a in &self.accounts {
            b.extend(a.channel_txid);
            b.extend(a.channel_vout.to_le_bytes());
            b.extend(a.owner);
            b.extend(a.outpoint_txid);
            b.extend(a.outpoint_vout.to_le_bytes());
            b.extend(a.collateral.to_le_bytes());
            put_bytes(&mut b, &a.account_spk);
            put_bytes(&mut b, &a.payout_spk);
        }
        b.extend(self.operator_txid);
        b.extend(self.operator_vout.to_le_bytes());
        b.extend(self.operator_amount.to_le_bytes());
        put_bytes(&mut b, &self.operator_spk);
        tagged_hash(b"LIGHTNINGER/DLC-BATCH/MANIFEST/V1", &b)
    }

    /// Prevout amounts and scriptPubKeys of the settlement inputs, in input order.
    pub fn spent(&self) -> (Vec<u64>, Vec<Vec<u8>>) {
        let mut a: Vec<u64> = self.accounts.iter().map(|x| x.collateral).collect();
        let mut s: Vec<Vec<u8>> = self.accounts.iter().map(|x| x.account_spk.clone()).collect();
        a.push(self.operator_amount);
        s.push(self.operator_spk.clone());
        (a, s)
    }
}

pub fn compact(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [vec![0xfd], (n as u16).to_le_bytes().to_vec()].concat(),
        _ => [vec![0xfe], (n as u32).to_le_bytes().to_vec()].concat(),
    }
}

/// `SHA256(sha_amounts || sha_scriptpubkeys)` (`tapsighash_step::spent_commitment`).
pub fn spent_commitment(amounts: &[u64], spks: &[Vec<u8>]) -> H32 {
    let a: Vec<u8> = amounts.iter().flat_map(|x| x.to_le_bytes()).collect();
    let s: Vec<u8> = spks.iter().flat_map(|k| [compact(k.len()), k.clone()].concat()).collect();
    sha256(&[sha256(&a), sha256(&s)].concat())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTx {
    pub version: u32,
    /// (prevout txid in display order, vout, sequence)
    pub inputs: Vec<(H32, u32, u32)>,
    pub outputs: Vec<(u64, Vec<u8>)>,
    pub locktime: u32,
    /// Display-order txid of the non-witness serialization.
    pub txid: H32,
}

struct Rd<'a>(&'a [u8], usize);
impl Rd<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        if self.1 + n > self.0.len() {
            return Err("transaction truncated".into());
        }
        let s = &self.0[self.1..self.1 + n];
        self.1 += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn cs(&mut self) -> Result<usize, String> {
        Ok(match self.u8()? {
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize,
            0xfe => self.u32()? as usize,
            0xff => return Err("compact size too large".into()),
            n => n as usize,
        })
    }
}

/// Parse a (segwit or legacy) transaction and compute its txid.
pub fn parse_tx(raw: &[u8]) -> Result<ParsedTx, String> {
    let mut r = Rd(raw, 0);
    let version = r.u32()?;
    let segwit = raw.len() > 6 && raw[4] == 0 && raw[5] == 1;
    if segwit {
        r.take(2)?;
    }
    let body_start = r.1;
    let n_in = r.cs()?;
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let mut t: H32 = r.take(32)?.try_into().unwrap();
        t.reverse();
        let v = r.u32()?;
        let l = r.cs()?;
        r.take(l)?;
        inputs.push((t, v, r.u32()?));
    }
    let n_out = r.cs()?;
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let v = r.u64()?;
        let l = r.cs()?;
        outputs.push((v, r.take(l)?.to_vec()));
    }
    let body_end = r.1;
    if segwit {
        for _ in 0..n_in {
            for _ in 0..r.cs()? {
                let l = r.cs()?;
                r.take(l)?;
            }
        }
    }
    let locktime = r.u32()?;
    if r.1 != raw.len() {
        return Err("trailing bytes after the transaction".into());
    }
    let mut stripped = version.to_le_bytes().to_vec();
    stripped.extend(&raw[body_start..body_end]);
    stripped.extend(locktime.to_le_bytes());
    let mut txid = sha256(&sha256(&stripped));
    txid.reverse();
    Ok(ParsedTx { version, inputs, outputs, locktime, txid })
}

pub fn marker_script(manifest_hash: &H32) -> Vec<u8> {
    let mut s = vec![0x6a, 36];
    s.extend(b"SHZB");
    s.extend(manifest_hash);
    s
}

/// Net sats per manifest account over the epoch's batches. Every row must belong to a manifest
/// account: the settlement pays every account that moved.
pub fn net_per_account(m: &Manifest, batches: &[Batch]) -> Result<Vec<i64>, String> {
    let mut net = vec![0i64; m.accounts.len()];
    for b in batches {
        for r in &b.rows {
            let i = m
                .accounts
                .iter()
                .position(|a| a.channel_txid == r.channel_txid && a.channel_vout == r.channel_vout)
                .ok_or_else(|| format!("batch {} moves a channel that is not in the manifest", b.seq))?;
            net[i] = net[i].checked_add(r.net).ok_or("net overflow")?;
        }
    }
    Ok(net)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settled {
    pub txid: H32,
    pub payouts: Vec<u64>,
    pub net: Vec<i64>,
    /// Sats the operator paid in beyond the accounts' collateral: `sum(payouts) - sum(collateral)`.
    pub fronted: i64,
}

pub const DUST: u64 = 330;

/// The settlement relation (module doc), on the raw signed transaction.
pub fn check_settlement(raw: &[u8], m: &Manifest, batches: &[Batch]) -> Result<Settled, String> {
    let tx = parse_tx(raw)?;
    let n = m.accounts.len();
    if n == 0 {
        return Err("empty manifest".into());
    }
    if tx.inputs.len() != n + 1 {
        return Err(format!("settlement has {} inputs, the manifest needs {}", tx.inputs.len(), n + 1));
    }
    if tx.outputs.len() < n + 1 {
        return Err("settlement has fewer outputs than accounts plus the marker".into());
    }
    let net = net_per_account(m, batches)?;
    let mut payouts = Vec::with_capacity(n);
    for (i, a) in m.accounts.iter().enumerate() {
        if (tx.inputs[i].0, tx.inputs[i].1) != (a.outpoint_txid, a.outpoint_vout) {
            return Err(format!("input {i} does not spend account {i}"));
        }
        let p = a.collateral as i128 + net[i] as i128;
        if p < DUST as i128 {
            return Err(format!("account {i} payout {p} is below dust"));
        }
        let p = p as u64;
        if tx.outputs[i].0 != p {
            return Err(format!("output {i} pays {} sats, the clearing gives account {i} {p}", tx.outputs[i].0));
        }
        if tx.outputs[i].1 != a.payout_spk {
            return Err(format!("output {i} pays another script than account {i}'s payout key"));
        }
        payouts.push(p);
    }
    if (tx.inputs[n].0, tx.inputs[n].1) != (m.operator_txid, m.operator_vout) {
        return Err("input N is not the operator's liquidity".into());
    }
    if tx.outputs[n].1 != marker_script(&m.hash()) || tx.outputs[n].0 != 0 {
        return Err("output N is not OP_RETURN SHZB || manifest hash".into());
    }
    let fronted = payouts.iter().map(|&p| p as i64).sum::<i64>() - m.accounts.iter().map(|a| a.collateral as i64).sum::<i64>();
    Ok(Settled { txid: tx.txid, payouts, net, fronted })
}

pub const STATEMENT_MAGIC: &[u8; 33] = b"UTXOREF_L2_SETTLEMENT_GROTH16_V0\0";

/// `UtxoRefL2SettlementStatementV0` (304 bytes), as `shz_nova_bitvm::bitvm3` encodes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub network_code: u8,
    pub chain_genesis_hash: H32,
    pub contract_id: H32,
    pub commitment_hash: H32,
    pub assertion_txid: H32,
    pub settlement_txid: H32,
    pub program_hash: H32,
    pub verifying_key_hash: H32,
    pub policy_hash: H32,
    pub epoch_id: u64,
    pub assertion_vout: u32,
}

impl Statement {
    pub fn encode(&self) -> [u8; 304] {
        let mut o = [0u8; 304];
        o[0..33].copy_from_slice(STATEMENT_MAGIC);
        o[35] = self.network_code;
        o[36..68].copy_from_slice(&self.chain_genesis_hash);
        o[68..100].copy_from_slice(&self.contract_id);
        o[100..132].copy_from_slice(&self.commitment_hash);
        o[132..164].copy_from_slice(&self.assertion_txid);
        o[164..196].copy_from_slice(&self.settlement_txid);
        o[196..228].copy_from_slice(&self.program_hash);
        o[228..260].copy_from_slice(&self.verifying_key_hash);
        o[260..292].copy_from_slice(&self.policy_hash);
        o[292..300].copy_from_slice(&self.epoch_id.to_le_bytes());
        o[300..304].copy_from_slice(&self.assertion_vout.to_le_bytes());
        o
    }
}

/// `contract_id` of a batch epoch: the event that closes it and the manifest it settles.
pub fn contract_id(m: &Manifest) -> H32 {
    let mut b = b"LIGHTNINGER/DLC-BATCH/CONTRACT/V1".to_vec();
    put_bytes(&mut b, m.event_id.as_bytes());
    b.extend(m.hash());
    sha256(&b)
}

pub const JOINT_TAG: &[u8] = b"LIGHTNINGER/CET-SPENDS+CLEARING/V1";

/// One input's M17 fold, as the digests of its `z_0` and `z_n` (`cet::joint_commitment`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M17Io {
    pub input: u32,
    pub z0_sha256: H32,
    pub zn_sha256: H32,
}

/// `cet::joint_commitment` from the digests of each fold's IO (`hz` = SHA-256 of the 32-byte
/// little-endian field representations), then the outer `SHA256(JOINT_TAG || commitment)` that
/// `prove-cet` takes over its transactions (one transaction here).
pub fn joint_commitment(cz0: &H32, czk: &H32, tap_zk: &H32, secq_zk: &H32, m17: &[M17Io]) -> H32 {
    let mut b = JOINT_TAG.to_vec();
    for d in [cz0, czk, tap_zk, secq_zk] {
        b.extend(d);
    }
    for x in m17 {
        b.extend(x.input.to_le_bytes());
        b.extend(x.z0_sha256);
        b.extend(x.zn_sha256);
    }
    let inner = sha256(&b);
    let mut o = JOINT_TAG.to_vec();
    o.extend(inner);
    sha256(&o)
}

/// SHA-256 over field elements given as 32-byte little-endian representations.
pub fn hz(reprs: &[H32]) -> H32 {
    let mut b = Vec::with_capacity(32 * reprs.len());
    for r in reprs {
        b.extend(r);
    }
    sha256(&b)
}

/// `[u128_be(d[0..16]), u128_be(d[16..32])]`: the Groth16 / BitVM3 public inputs.
pub fn public_limbs(d: &H32) -> [u128; 2] {
    [u128::from_be_bytes(d[0..16].try_into().unwrap()), u128::from_be_bytes(d[16..32].try_into().unwrap())]
}

/// What the SP1 wrap guest reads after the clearing key and proof (bincode).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestIn {
    pub steps: u32,
    pub table: u32,
    /// The clearing fold's `z_0`, as 32-byte little-endian field representations.
    pub z0: Vec<H32>,
    /// The bind-mode TapSighash fold's `z_K` (10 elements).
    pub tap_zk: Vec<H32>,
    pub secq_zk_sha256: H32,
    pub m17: Vec<M17Io>,
    pub manifest: Manifest,
    pub batches: Vec<Batch>,
    pub settlement: Vec<u8>,
}

pub const PROGRAM: &str = "lightninger/dlc-batch/v1: lightninger/v3-clearing-batch-fold/v1 + lightninger/bip341-tapsighash-step/v1 bind + shz/mnr05-secq256k1-bip340-batch-auth/v1 + m17-nova-script@f80c364 + lightninger-dlc-batch-relation/v1";
pub const REGTEST_GENESIS: H32 = [
    0x0f, 0x91, 0x88, 0xf1, 0x3c, 0xb7, 0xb2, 0xc7, 0x1f, 0x2a, 0x33, 0x5e, 0x3a, 0x4f, 0xc3, 0x28, 0xbf, 0x5b, 0xeb, 0x43, 0x60, 0x12, 0xaf, 0xca, 0x59, 0x0b, 0x1a, 0x11, 0x46, 0x6e, 0x22, 0x06,
];
pub const TESTNET4_GENESIS: H32 = [
    0x00, 0x00, 0x00, 0x00, 0xda, 0x84, 0xf2, 0xba, 0xfb, 0xbc, 0x53, 0xde, 0xe2, 0x5a, 0x72, 0xae, 0x50, 0x7f, 0xf4, 0x91, 0x4b, 0x86, 0x7c, 0x56, 0x5b, 0xe3, 0x50, 0xb0, 0xda, 0x8b, 0xf0, 0x43,
];

/// A 32-byte digest as the two field elements `(lo, hi)` of its little-endian halves, each in the
/// 32-byte little-endian representation of a field element below 2^128.
pub fn limb_reprs(d: &H32) -> [H32; 2] {
    let mut lo = [0u8; 32];
    let mut hi = [0u8; 32];
    lo[..16].copy_from_slice(&d[..16]);
    hi[..16].copy_from_slice(&d[16..]);
    [lo, hi]
}

/// Everything the guest checks besides the Nova verifier itself, given that verifier's output
/// `zk` (clearing `z_K` reprs) and the clearing key's SHA-256. Returns the 304-byte statement.
pub fn guest_statement(g: &GuestIn, zk: &[H32], vk_sha256: &H32) -> Result<[u8; 304], String> {
    let a = g.table as usize;
    if g.z0.len() != 7 + 4 * a || zk.len() != g.z0.len() {
        return Err("clearing state has the wrong arity".into());
    }
    if g.batches.len() != g.steps as usize {
        return Err("one batch per folded step".into());
    }
    // z0: chain zero, sequence = first batch; zK: chain of the batches, sequence after the last
    let zero = limb_reprs(&[0u8; 32]);
    if g.z0[g.z0.len() - 2..] != zero {
        return Err("z_0 chain is not zero".into());
    }
    let seq = |r: &H32| u64::from_le_bytes(r[..8].try_into().unwrap());
    if seq(&g.z0[0]) != g.batches[0].seq || g.z0[0][8..] != [0u8; 24] {
        return Err("z_0 is not the state before the first batch".into());
    }
    if seq(&zk[0]) != g.batches.last().unwrap().seq + 1 || zk[0][8..] != [0u8; 24] {
        return Err("z_K is not the state after the last batch".into());
    }
    let chain = chain_of(&g.batches)?;
    if zk[zk.len() - 2..] != limb_reprs(&chain) {
        return Err("batch digests do not chain to the clearing fold's z_K".into());
    }
    let settled = check_settlement(&g.settlement, &g.manifest, &g.batches)?;
    if g.tap_zk.len() != 10 {
        return Err("TapSighash fold output is not in bind mode".into());
    }
    if g.tap_zk[3..5] != limb_reprs(&settled.txid) {
        return Err("TapSighash fold is over another transaction".into());
    }
    let (am, sp) = g.manifest.spent();
    if g.tap_zk[5..7] != limb_reprs(&spent_commitment(&am, &sp)) {
        return Err("TapSighash fold commits to other spent outputs".into());
    }
    let commitment = joint_commitment(&hz(&g.z0), &hz(zk), &hz(&g.tap_zk), &g.secq_zk_sha256, &g.m17);
    let st = Statement {
        network_code: g.manifest.network_code,
        chain_genesis_hash: match g.manifest.network_code {
            0 => REGTEST_GENESIS,
            1 => TESTNET4_GENESIS,
            _ => return Err("network must be regtest (0) or testnet4 (1)".into()),
        },
        contract_id: contract_id(&g.manifest),
        commitment_hash: commitment,
        assertion_txid: [0; 32],
        settlement_txid: settled.txid,
        program_hash: sha256(PROGRAM.as_bytes()),
        verifying_key_hash: *vk_sha256,
        policy_hash: g.manifest.hash(),
        epoch_id: g.manifest.epoch_id,
        assertion_vout: 0,
    };
    Ok(st.encode())
}
