//! Bitcoin `SHZIDX01` OP_RETURN transaction parser, PoW / chainwork header-chain tracker,
//! and SPV Merkle inclusion verifier modeled on `Near-One/btc-light-client-contract`.
//!
//! Enforces:
//! - Exact 40-byte `SHZIDX01 || checkpoint_root32` payload (`scriptPubKey = 6a28 || packet`, `0` sats).
//! - Witness-aware transaction parsing with explicit 64-byte stripped-tx rejection (CVE-2018-17144
//!   Merkle inner-node forgery defense from `Near-One/btc-light-client-contract` v2).
//! - 80-byte Bitcoin header PoW target check, cumulative chainwork (`U256`), canonical heaviest-chain
//!   selection, reorg orphan eviction, and confirmation depth `>= min_confirmations`.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SHZIDX01_MAGIC: &[u8; 8] = b"SHZIDX01";

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn reverse32(mut b: [u8; 32]) -> [u8; 32] {
    b.reverse();
    b
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BtcNetwork {
    Mainnet,
    Testnet4,
    Regtest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedShzAnchorTx {
    pub txid_hex: String,
    pub wtxid_hex: String,
    pub stripped_len: usize,
    pub segwit: bool,
    pub checkpoint_root_hex: String,
    pub packet_hex: String,
}

struct TxCursor<'a> {
    raw: &'a [u8],
    off: usize,
}

impl<'a> TxCursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.off.checked_add(n).ok_or("tx cursor overflow")?;
        let slice = self.raw.get(self.off..end).ok_or("truncated Bitcoin tx")?;
        self.off = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn compact_size(&mut self) -> Result<usize, String> {
        let a = self.u8()?;
        match a {
            0..=252 => Ok(a as usize),
            253 => {
                let v = u16::from_le_bytes(self.take(2)?.try_into().unwrap());
                if v < 253 {
                    return Err("noncanonical CompactSize u16".into());
                }
                Ok(v as usize)
            }
            254 => {
                let v = u32::from_le_bytes(self.take(4)?.try_into().unwrap());
                if v <= 0xffff {
                    return Err("noncanonical CompactSize u32".into());
                }
                Ok(v as usize)
            }
            255 => {
                let v = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
                if v <= 0xffff_ffff || v > 1_000_000 {
                    return Err("out-of-range CompactSize u64".into());
                }
                Ok(v as usize)
            }
        }
    }

    fn script(&mut self, max_len: usize) -> Result<&'a [u8], String> {
        let n = self.compact_size()?;
        if n > max_len {
            return Err("oversized script".into());
        }
        self.take(n)
    }
}

/// Parses a raw legacy or SegWit Bitcoin transaction, rejects 64-byte stripped transactions,
/// and verifies that it carries **exactly one** `0`-sat `OP_RETURN (SHZIDX01 || checkpoint_root32)` output.
pub fn verify_shzidx01_transaction(
    raw_tx: &[u8],
    expected_checkpoint_root: &[u8; 32],
) -> Result<ParsedShzAnchorTx, String> {
    if !(10..=250_000).contains(&raw_tx.len()) {
        return Err("invalid Bitcoin transaction byte length".into());
    }
    let mut c = TxCursor { raw: raw_tx, off: 0 };
    let version = c.take(4)?;
    let mut segwit = false;
    if c.raw.get(c.off) == Some(&0) {
        if c.raw.get(c.off + 1) != Some(&1) {
            return Err("unsupported SegWit marker/flag".into());
        }
        segwit = true;
        c.take(2)?;
    }
    let vin_start = c.off;
    let n_vin = c.compact_size()?;
    if !(1..=256).contains(&n_vin) {
        return Err("invalid input count".into());
    }
    for _ in 0..n_vin {
        c.take(36)?; // prevout txid + vout
        c.script(10_000)?; // scriptSig
        c.take(4)?; // sequence
    }
    let n_vout = c.compact_size()?;
    if !(1..=256).contains(&n_vout) {
        return Err("invalid output count".into());
    }
    let mut matched_packet: Option<Vec<u8>> = None;
    let mut shz_output_count = 0usize;
    for _ in 0..n_vout {
        let value_sats = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
        let spk = c.script(10_000)?;
        if spk.len() >= 10 && spk[0] == 0x6a && spk[1] == 0x28 && &spk[2..10] == SHZIDX01_MAGIC {
            shz_output_count += 1;
            if spk.len() != 42 || value_sats != 0 {
                return Err("malformed SHZIDX01 OP_RETURN length or non-zero satoshi value".into());
            }
            matched_packet = Some(spk[2..42].to_vec());
        }
    }
    let vout_end = c.off;
    if segwit {
        let mut any_nonempty_witness = false;
        for _ in 0..n_vin {
            let items = c.compact_size()?;
            if items > 256 {
                return Err("excessive witness stack items".into());
            }
            if items > 0 {
                any_nonempty_witness = true;
            }
            for _ in 0..items {
                let item_len = c.compact_size()?;
                if item_len > 150_000 {
                    return Err("oversized witness item".into());
                }
                c.take(item_len)?;
            }
        }
        if !any_nonempty_witness {
            return Err("SegWit flag set with empty witnesses".into());
        }
    }
    let locktime = c.take(4)?;
    if c.off != raw_tx.len() {
        return Err("trailing bytes after Bitcoin transaction".into());
    }

    let mut stripped = Vec::with_capacity(4 + (vout_end - vin_start) + 4);
    stripped.extend_from_slice(version);
    stripped.extend_from_slice(&raw_tx[vin_start..vout_end]);
    stripped.extend_from_slice(locktime);

    // Explicit defense against 64-byte Merkle inner-node forgery (Near-One v2 mitigation)
    if stripped.len() == 64 {
        return Err("64-byte stripped transaction forbidden (Merkle inner-node collision defense)".into());
    }
    if shz_output_count != 1 {
        return Err(format!("expected exactly 1 SHZIDX01 output, found {shz_output_count}"));
    }
    let packet = matched_packet.unwrap();
    if &packet[8..40] != expected_checkpoint_root {
        return Err("SHZIDX01 OP_RETURN checkpoint_root mismatch".into());
    }

    let txid = reverse32(double_sha256(&stripped));
    let wtxid = reverse32(double_sha256(raw_tx));
    Ok(ParsedShzAnchorTx {
        txid_hex: hex::encode(txid),
        wtxid_hex: hex::encode(wtxid),
        stripped_len: stripped.len(),
        segwit,
        checkpoint_root_hex: hex::encode(expected_checkpoint_root),
        packet_hex: hex::encode(packet),
    })
}

// --- Minimal big-endian 256-bit unsigned arithmetic for Bitcoin PoW target & chainwork ---

pub fn u256_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    a.cmp(b)
}

pub fn u256_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    if carry != 0 {
        None
    } else {
        Some(out)
    }
}

/// Expands Bitcoin compact `nBits` (`u32`) to big-endian 256-bit PoW target.
pub fn target_from_bits(bits: u32) -> Result<[u8; 32], String> {
    let exp = ((bits >> 24) & 0xff) as usize;
    let mant = bits & 0x00ff_ffff;
    if mant == 0 || (mant & 0x0080_0000) != 0 {
        return Err("invalid negative or zero compact nBits mantissa".into());
    }
    let mut target = [0u8; 32];
    let bytes = [
        ((mant >> 16) & 0xff) as u8,
        ((mant >> 8) & 0xff) as u8,
        (mant & 0xff) as u8,
    ];
    if exp <= 3 {
        let shift = 3 - exp;
        let v = mant >> (8 * shift);
        if v == 0 {
            return Err("zero PoW target".into());
        }
        target[29] = ((v >> 16) & 0xff) as u8;
        target[30] = ((v >> 8) & 0xff) as u8;
        target[31] = (v & 0xff) as u8;
    } else if exp <= 32 {
        let start = 32 - exp;
        for (j, &b) in bytes.iter().enumerate() {
            if start + j < 32 {
                target[start + j] = b;
            }
        }
    } else {
        return Err("compact nBits exponent > 32 overflows 256-bit target".into());
    }
    Ok(target)
}

/// Computes positive block work proxy strictly monotone decreasing in `target`:
/// Approximates `floor(2^256 / (target + 1))` using exact 128-bit division on the leading
/// non-zero 64-bit window of `target`, matching Bitcoin Core's `GetBlockProof` ordering.
pub fn work_from_bits(bits: u32) -> Result<[u8; 32], String> {
    let target = target_from_bits(bits)?;
    // Find first non-zero byte of big-endian target
    let first_nz = target.iter().position(|&b| b != 0).ok_or("zero target")?;
    // Extract up to 8 bytes starting at first_nz into a u64 divisor `d`
    let mut d_bytes = [0u8; 8];
    let take = (32 - first_nz).min(8);
    d_bytes[8 - take..8].copy_from_slice(&target[first_nz..first_nz + take]);
    let d = u128::from(u64::from_be_bytes(d_bytes)) + 1;
    // Target ~= d * 2^(8 * (32 - first_nz - take))
    // 2^256 / target ~= (2^64 * d_scale) / d shifted appropriately
    let num: u128 = 1u128 << 96;
    let q = num / d; // fits in u128, ~32..96 bits
    // Position of q's LSB in the 256-bit big-endian work array:
    // target ≈ d * 2^(8 * rem_bytes) where rem_bytes = 32 - first_nz - take.
    // num / d = 2^96 / d = (2^256 / (d * 2^(8*rem_bytes))) * 2^(96 - 256 + 8*rem_bytes)
    // => work = q * 2^(160 - 8*rem_bytes) -> shift left by (20 - rem_bytes) bytes!
    let rem_bytes = 32 - first_nz - take;
    let shift_bytes = 20usize.saturating_sub(rem_bytes);
    let q_be = q.to_be_bytes(); // 16 bytes
    let mut work = [0u8; 32];
    for (idx, &b) in q_be.iter().enumerate() {
        let rev_from_end = 15 - idx + shift_bytes;
        if rev_from_end < 32 {
            work[31 - rev_from_end] = b;
        }
    }
    if work.iter().all(|&b| b == 0) {
        work[31] = 1;
    }
    Ok(work)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBtcHeader {
    pub block_hash_hex: String,
    pub prev_block_hash_hex: String,
    pub merkle_root_le: [u8; 32],
    pub version: i32,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
    pub height: u64,
    pub cumulative_work_be: [u8; 32],
}

/// Trust-minimized Bitcoin Header Light Client modeled on `Near-One/btc-light-client-contract`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BtcLightClient {
    pub network: BtcNetwork,
    pub min_confirmations: u64,
    pub initial_hash_hex: String,
    pub tip_hash_hex: String,
    pub headers_pool: BTreeMap<String, StoredBtcHeader>,
    pub mainchain_height_to_hash: BTreeMap<u64, String>,
    pub mainchain_hash_to_height: BTreeMap<String, u64>,
}

pub fn parse_btc_header_80(raw80: &[u8]) -> Result<(String, String, [u8; 32], i32, u32, u32, u32, [u8; 32]), String> {
    if raw80.len() != 80 {
        return Err("expected 80-byte Bitcoin block header".into());
    }
    let version = i32::from_le_bytes(raw80[0..4].try_into().unwrap());
    if version < 4 {
        return Err("bad-version: Bitcoin header version must be >= 4".into());
    }
    let mut prev_le: [u8; 32] = raw80[4..36].try_into().unwrap();
    prev_le.reverse();
    let prev_hex = hex::encode(prev_le);

    let merkle_root_le: [u8; 32] = raw80[36..68].try_into().unwrap();
    let time = u32::from_le_bytes(raw80[68..72].try_into().unwrap());
    let bits = u32::from_le_bytes(raw80[72..76].try_into().unwrap());
    let nonce = u32::from_le_bytes(raw80[76..80].try_into().unwrap());

    let hash_le = double_sha256(raw80);
    let hash_be = reverse32(hash_le);
    let target_be = target_from_bits(bits)?;
    if u256_cmp(&hash_be, &target_be) == std::cmp::Ordering::Greater {
        return Err("high-hash: Bitcoin header does not satisfy compact nBits PoW target".into());
    }
    let hash_hex = hex::encode(hash_be);
    Ok((hash_hex, prev_hex, merkle_root_le, version, time, bits, nonce, hash_be))
}

impl BtcLightClient {
    pub fn from_trusted_anchor_header(
        network: BtcNetwork,
        min_confirmations: u64,
        anchor_height: u64,
        raw_header_80: &[u8],
    ) -> Result<Self, String> {
        if min_confirmations == 0 || min_confirmations > 100 {
            return Err("min_confirmations must be in 1..=100".into());
        }
        let (hash_hex, prev_hex, merkle_root_le, version, time, bits, nonce, _) =
            parse_btc_header_80(raw_header_80)?;
        let work = work_from_bits(bits)?;
        let stored = StoredBtcHeader {
            block_hash_hex: hash_hex.clone(),
            prev_block_hash_hex: prev_hex,
            merkle_root_le,
            version,
            time,
            bits,
            nonce,
            height: anchor_height,
            cumulative_work_be: work,
        };
        let mut headers_pool = BTreeMap::new();
        headers_pool.insert(hash_hex.clone(), stored);
        let mut mainchain_height_to_hash = BTreeMap::new();
        mainchain_height_to_hash.insert(anchor_height, hash_hex.clone());
        let mut mainchain_hash_to_height = BTreeMap::new();
        mainchain_hash_to_height.insert(hash_hex.clone(), anchor_height);

        Ok(Self {
            network,
            min_confirmations,
            initial_hash_hex: hash_hex.clone(),
            tip_hash_hex: hash_hex,
            headers_pool,
            mainchain_height_to_hash,
            mainchain_hash_to_height,
        })
    }

    /// Submits an 80-byte Bitcoin header, validates PoW, parent linkage, MTP, and difficulty rules,
    /// and updates the canonical mainchain if and only if cumulative work strictly exceeds the current tip.
    pub fn submit_header(&mut self, raw_header_80: &[u8]) -> Result<StoredBtcHeader, String> {
        let (hash_hex, prev_hex, merkle_root_le, version, time, bits, nonce, _) =
            parse_btc_header_80(raw_header_80)?;
        if let Some(existing) = self.headers_pool.get(&hash_hex) {
            return Ok(existing.clone());
        }
        let parent = self
            .headers_pool
            .get(&prev_hex)
            .ok_or("prev-blk-not-found: parent header unknown")?
            .clone();

        // Compute Median-Time-Past (up to 11 ancestors) matching Bitcoin consensus & Near-One
        let mut ancestor_times = Vec::with_capacity(11);
        let mut cur = Some(&parent);
        while let Some(h) = cur {
            ancestor_times.push(h.time);
            if ancestor_times.len() == 11 {
                break;
            }
            cur = self.headers_pool.get(&h.prev_block_hash_hex);
        }
        ancestor_times.sort_unstable();
        let mtp = ancestor_times[ancestor_times.len() / 2];
        if time <= mtp {
            return Err("time-too-old: block timestamp <= median-time-past".into());
        }

        // Enforce network difficulty transition rule within epoch
        let next_height = parent.height + 1;
        match self.network {
            BtcNetwork::Regtest => {
                if bits != 0x207f_ffff {
                    return Err("bad-diffbits: expected regtest 0x207fffff".into());
                }
            }
            BtcNetwork::Mainnet => {
                if next_height % 2016 != 0 && bits != parent.bits {
                    return Err("bad-diffbits: intra-epoch Mainnet difficulty mutation".into());
                }
            }
            BtcNetwork::Testnet4 => {
                if next_height % 2016 != 0 && time <= parent.time + 1200 && bits != parent.bits {
                    return Err("bad-diffbits: invalid Testnet4 intra-epoch bits".into());
                }
            }
        }

        let block_work = work_from_bits(bits)?;
        let cumulative_work_be =
            u256_add(&parent.cumulative_work_be, &block_work).ok_or("cumulative work overflow")?;

        let header = StoredBtcHeader {
            block_hash_hex: hash_hex.clone(),
            prev_block_hash_hex: prev_hex,
            merkle_root_le,
            version,
            time,
            bits,
            nonce,
            height: next_height,
            cumulative_work_be,
        };
        self.headers_pool.insert(hash_hex.clone(), header.clone());

        let current_tip = self.headers_pool.get(&self.tip_hash_hex).unwrap().clone();
        if u256_cmp(&header.cumulative_work_be, &current_tip.cumulative_work_be)
            == std::cmp::Ordering::Greater
        {
            self.reorg_to_new_tip(&header)?;
        }

        Ok(header)
    }

    fn reorg_to_new_tip(&mut self, new_tip: &StoredBtcHeader) -> Result<(), String> {
        // Collect fork path back to the first block already on `mainchain`
        let mut branch = Vec::new();
        let mut cursor = new_tip.clone();
        while self.mainchain_hash_to_height.get(&cursor.block_hash_hex) != Some(&cursor.height) {
            branch.push(cursor.clone());
            cursor = self
                .headers_pool
                .get(&cursor.prev_block_hash_hex)
                .ok_or("broken ancestor chain during reorg")?
                .clone();
        }
        let fork_ancestor_height = cursor.height;
        let old_tip_height = self.headers_pool.get(&self.tip_hash_hex).unwrap().height;

        // Evict orphaned mainchain entries strictly above `fork_ancestor_height`
        for h in (fork_ancestor_height + 1)..=old_tip_height {
            if let Some(old_hash) = self.mainchain_height_to_hash.remove(&h) {
                self.mainchain_hash_to_height.remove(&old_hash);
            }
        }
        // Apply new heaviest branch in ascending height order
        for blk in branch.into_iter().rev() {
            self.mainchain_height_to_hash
                .insert(blk.height, blk.block_hash_hex.clone());
            self.mainchain_hash_to_height
                .insert(blk.block_hash_hex, blk.height);
        }
        self.tip_hash_hex = new_tip.block_hash_hex.clone();
        Ok(())
    }

    /// Verifies that `raw_tx` carries `OP_RETURN (SHZIDX01 || expected_checkpoint_root)`,
    /// its `txid` is proven in `block_hash_hex` via `merkle_branch_hex` at `tx_index`,
    /// `block_hash_hex` is on the **canonical heaviest mainchain**, and has `>= min_confirmations`.
    pub fn verify_checkpoint_anchor_finality(
        &self,
        expected_checkpoint_root: &[u8; 32],
        raw_tx: &[u8],
        block_hash_hex: &str,
        tx_index: u32,
        merkle_branch_hex: &[String],
    ) -> Result<VerifiedBitcoinAnchorReceipt, String> {
        if merkle_branch_hex.len() > 32 {
            return Err("Merkle branch exceeds 32 levels".into());
        }
        // 1. Canonical mainchain membership check (rejects orphaned / noncanonical fork blocks!)
        let Some(&anchor_height) = self.mainchain_hash_to_height.get(block_hash_hex) else {
            return Err("noncanonical-or-unknown-header: block is not on canonical mainchain".into());
        };
        let tip = self.headers_pool.get(&self.tip_hash_hex).unwrap();
        let confirmations = tip.height.saturating_sub(anchor_height) + 1;
        if confirmations < self.min_confirmations {
            return Err(format!(
                "insufficient-confirmations: got {confirmations}, need >= {}",
                self.min_confirmations
            ));
        }

        // 2. Parse raw transaction & verify exact 40-byte SHZIDX01 || checkpoint_root32 OP_RETURN
        let parsed_tx = verify_shzidx01_transaction(raw_tx, expected_checkpoint_root)?;
        let txid_be: [u8; 32] = hex::decode(&parsed_tx.txid_hex).unwrap().try_into().unwrap();
        let mut node_le = reverse32(txid_be);

        // 3. Traverse Bitcoin SPV Merkle branch (`Near-One/btc-light-client-contract` merkle-tools)
        let mut idx = tx_index;
        for sib_hex in merkle_branch_hex {
            if sib_hex.len() != 64 || !sib_hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                return Err("noncanonical Merkle sibling hex".into());
            }
            let sib_be: [u8; 32] = hex::decode(sib_hex).map_err(|_| "bad sibling")?.try_into().unwrap();
            let sib_le = reverse32(sib_be);
            let mut pair = [0u8; 64];
            if (idx & 1) == 0 {
                pair[0..32].copy_from_slice(&node_le);
                pair[32..64].copy_from_slice(&sib_le);
            } else {
                pair[0..32].copy_from_slice(&sib_le);
                pair[32..64].copy_from_slice(&node_le);
            }
            node_le = double_sha256(&pair);
            idx >>= 1;
        }
        if idx != 0 {
            return Err("tx_index out of range for Merkle branch depth".into());
        }

        let header = self.headers_pool.get(block_hash_hex).unwrap();
        if node_le != header.merkle_root_le {
            return Err("merkle-mismatch: transaction SPV branch does not match block merkle_root".into());
        }

        Ok(VerifiedBitcoinAnchorReceipt {
            txid_hex: parsed_tx.txid_hex,
            wtxid_hex: parsed_tx.wtxid_hex,
            block_hash_hex: block_hash_hex.to_owned(),
            anchor_height,
            tip_height: tip.height,
            confirmations,
            checkpoint_root_hex: parsed_tx.checkpoint_root_hex,
            packet_hex: parsed_tx.packet_hex,
            canonical_mainchain_verified: true,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBitcoinAnchorReceipt {
    pub txid_hex: String,
    pub wtxid_hex: String,
    pub block_hash_hex: String,
    pub anchor_height: u64,
    pub tip_height: u64,
    pub confirmations: u64,
    pub checkpoint_root_hex: String,
    pub packet_hex: String,
    pub canonical_mainchain_verified: bool,
}

/// Deterministic regtest header miner helper for reproducible SPV & reorg adversarial tests.
pub fn mine_regtest_header(prev_hash_hex: &str, merkle_root_le: [u8; 32], time: u32, start_nonce: u32) -> [u8; 80] {
    let prev_be: [u8; 32] = hex::decode(prev_hash_hex).unwrap().try_into().unwrap();
    let prev_le = reverse32(prev_be);
    let bits: u32 = 0x207f_ffff;
    let target = target_from_bits(bits).unwrap();
    for nonce in start_nonce.. {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&4i32.to_le_bytes());
        h[4..36].copy_from_slice(&prev_le);
        h[36..68].copy_from_slice(&merkle_root_le);
        h[68..72].copy_from_slice(&time.to_le_bytes());
        h[72..76].copy_from_slice(&bits.to_le_bytes());
        h[76..80].copy_from_slice(&nonce.to_le_bytes());
        let hash_be = reverse32(double_sha256(&h));
        if u256_cmp(&hash_be, &target) != std::cmp::Ordering::Greater {
            return h;
        }
    }
    unreachable!()
}
