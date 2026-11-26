//! `SHZ-MNR-02`: Bob-Offline Multilateral Closeout with Bitcoin-Enforceable Settlement.
//!
//! Solves Issue #2 (`SHZ-MNR-02`) on today's Bitcoin consensus (`BIP-340/341/342`, zero soft forks):
//!
//! ### Core Construction (`Two-Tier CLTV + SIGHASH_SINGLE|ANYONECANPAY 0x83 Taproot Tree`)
//! A 2-party inverse DLC funding output `U_AB` uses the unspendable `UTXORef` NUMS internal key
//! and three Tapscript (`0xc0`) leaves:
//! - **Leaf 0 (`route_cet_leaf`, `nLockTime = maturity_height`)**:
//!   `<P_Alice> OP_CHECKSIGVERIFY <P_RouterGuard> OP_CHECKSIGVERIFY <P_Bob> OP_CHECKSIG`
//!   At origination (`t = 0`, before Carol exists!), Bob pre-signs an adaptor signature for each
//!   price outcome using `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY (0x83)` over a 1-in/1-out template
//!   where `Output 0 = (bob_payout(P_2), bob_spk)`. Under BIP-341, `0x83` commits *only* to
//!   `Input 0` (`U_AB`) and `Output 0` (`sha_single_output`), leaving `Outputs 1..M` (and any
//!   extra fee/offset inputs `1..K`) open for Alice + `P_RouterGuard` to bind with `SIGHASH_ALL (0x01)`
//!   at `t = 1` while Bob is **completely offline**!
//! - **Leaf 1 (`unilateral_cet_leaf`, `nLockTime = maturity_height + grace_blocks`)**:
//!   `<maturity + grace> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
//!   Pre-signed at `t = 0` by both Alice & Bob with `SIGHASH_DEFAULT (0x00)`. Preserves 100%
//!   trustless unilateral exit if `P_RouterGuard`/Carol/LP disappears, while being consensus
//!   `non-final` during `[maturity, maturity + grace - 1]` so Alice cannot double-spend/divert
//!   an already-authorized multilateral closeout!
//! - **Leaf 2 (`refund_leaf`, `nLockTime = maturity_height + refund_delay_blocks`)**:
//!   `<maturity + refund_delay> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
//!   Pre-signed at `t = 0` with plain BIP-340 `SIGHASH_DEFAULT (0x00)` signatures before funding,
//!   guaranteeing full margin recovery if the oracle withholds attestations.
//!
//! ### Pre-Maturity Impossibility & LP Advance Boundary
//! Before `maturity_height`, the oracle scalar `t(P_2)` does not exist and no non-custodial script
//! path on `U_AB` can release raw Bitcoin UTXO bytes while Bob is offline without a covenant/state
//! machine + counterparty novation. Immediate pre-maturity liquidity (`t = 1 < maturity`) therefore
//! uses `Candidate 4 (LP-Funded Close Advance)` secured by the priority `maturity_height` Leaf 0 claim.

use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{bigint::U256, group::Group, ops::Reduce},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dlc::{
    AdaptorSignature, Bip340Signature, adaptor_complete, adaptor_sign, adaptor_verify,
    bip340_sign, bip340_verify, lift_x_even, pubkey_x_from_secret, tagged_hash,
};
use shz_margin::SATS_PER_BTC;

use crate::{
    UtxoRefError,
    signing_target::{
        DEFAULT_CPFP_ANCHOR_SATS, LEAF_VERSION_TAPSCRIPT, point_coordinates, tap_branch_hash,
        tap_leaf_hash, utxoref_nums_internal_key,
    },
};

pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_SINGLE_ANYONECANPAY: u8 = 0x83;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn compact_size(value: usize) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(value as u32).to_le_bytes());
            out
        }
    }
}

fn push_script_num(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    if value <= 16 {
        return vec![0x50 + value as u8];
    }
    let mut bytes = Vec::new();
    let mut rem = value;
    while rem > 0 {
        bytes.push((rem & 0xff) as u8);
        rem >>= 8;
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(0);
    }
    let mut script = vec![bytes.len() as u8];
    script.extend(bytes);
    script
}

/// Exact `SHZ-MNR-01` toward-zero truncated inverse Long PnL in satoshis:
/// `(notional_usd * 1e8 * (exit_price_usd - entry_price_usd)) / (entry_price_usd * exit_price_usd)`
pub fn inverse_long_pnl_trunc_sats(
    notional_usd: u64,
    entry_price_usd: u64,
    exit_price_usd: u64,
) -> i128 {
    let n = (notional_usd as i128) * (SATS_PER_BTC as i128);
    let p0 = entry_price_usd as i128;
    let p2 = exit_price_usd as i128;
    (n * (p2 - p0)) / (p0 * p2)
}

/// Structured evaluation of all four `SHZ-MNR-02` candidate constructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mnr02CandidateAssessment {
    pub id: &'static str,
    pub works_with_bob_offline_at_maturity: bool,
    pub releases_u_ab_utxo_before_maturity_with_bob_offline: bool,
    pub discretionary_committee_custody: bool,
    pub preserves_unilateral_exit: bool,
    pub requires_covenant_soft_fork: bool,
    pub sighash_flags: Vec<u8>,
    pub summary: &'static str,
}

pub fn evaluate_mnr02_candidates() -> Vec<Mnr02CandidateAssessment> {
    vec![
        Mnr02CandidateAssessment {
            id: "1-fresh-mutual-signatures",
            works_with_bob_offline_at_maturity: false,
            releases_u_ab_utxo_before_maturity_with_bob_offline: false,
            discretionary_committee_custody: false,
            preserves_unilateral_exit: true,
            requires_covenant_soft_fork: false,
            sighash_flags: vec![SIGHASH_DEFAULT, SIGHASH_ALL],
            summary: "Baseline 1-tx cooperative settlement when Bob is online; blocked as soon as Bob's signer goes offline after funding.",
        },
        Mnr02CandidateAssessment {
            id: "2-origination-0x83-two-tier-cltv",
            works_with_bob_offline_at_maturity: true,
            releases_u_ab_utxo_before_maturity_with_bob_offline: false,
            discretionary_committee_custody: false,
            preserves_unilateral_exit: true,
            requires_covenant_soft_fork: false,
            sighash_flags: vec![SIGHASH_SINGLE_ANYONECANPAY, SIGHASH_ALL, SIGHASH_DEFAULT],
            summary: "Enforceable on today's Bitcoin Core at maturity with Bob offline: Bob's t=0 0x83 adaptor sig consensus-locks Output 0 (Bob's exact residual) while Alice + non-custodial RouterGuard sign 0x01 at t=1 to pay Carol + Alice on Leaf 0 (locktime=T), beating Alice's unilateral Leaf 1 (locktime=T+grace).",
        },
        Mnr02CandidateAssessment {
            id: "3-dlc-channel-conditional-clearing",
            works_with_bob_offline_at_maturity: false,
            releases_u_ab_utxo_before_maturity_with_bob_offline: false,
            discretionary_committee_custody: false,
            preserves_unilateral_exit: true,
            requires_covenant_soft_fork: false,
            sighash_flags: vec![SIGHASH_DEFAULT],
            summary: "Off-chain LN-DLC subchannel state updates require Bob's interactive revocation/commitment signature; when Bob is offline, settlement falls back to the L1 CET tree (where Candidate 2 enables routed L1 payout).",
        },
        Mnr02CandidateAssessment {
            id: "4-lp-funded-close-advance-over-0x83",
            works_with_bob_offline_at_maturity: true,
            releases_u_ab_utxo_before_maturity_with_bob_offline: false,
            discretionary_committee_custody: false,
            preserves_unilateral_exit: true,
            requires_covenant_soft_fork: false,
            sighash_flags: vec![SIGHASH_SINGLE_ANYONECANPAY, SIGHASH_ALL],
            summary: "Immediate t=1 liquid BTC exit for Alice before maturity while U_AB remains locked until T: LP advances Alice's locked-in payout from LP's own UTXO at t=1 in exchange for co-signing the priority Leaf 0 (locktime=T) claim on U_AB.",
        },
    ]
}

/// Multi-input SegWit/Taproot transaction input with spent prevout metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegwitTxIn {
    /// 32-byte little-endian internal txid + 4-byte little-endian vout.
    pub outpoint: [u8; 36],
    pub sequence: u32,
    pub prevout_value_sats: u64,
    pub prevout_script_pubkey: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
}

impl SegwitTxIn {
    pub fn from_display_txid(
        txid_display_hex: &str,
        vout: u32,
        sequence: u32,
        prevout_value_sats: u64,
        prevout_script_pubkey: Vec<u8>,
    ) -> Result<Self, UtxoRefError> {
        let mut txid_bytes: [u8; 32] = hex::decode(txid_display_hex)
            .map_err(|_| UtxoRefError::InvalidTransaction("invalid txid hex"))?
            .try_into()
            .map_err(|_| UtxoRefError::InvalidTransaction("txid must be 32 bytes"))?;
        txid_bytes.reverse(); // Bitcoin wire format uses little-endian internal txid
        let mut outpoint = [0u8; 36];
        outpoint[..32].copy_from_slice(&txid_bytes);
        outpoint[32..].copy_from_slice(&vout.to_le_bytes());
        Ok(Self {
            outpoint,
            sequence,
            prevout_value_sats,
            prevout_script_pubkey,
            witness: Vec::new(),
        })
    }
}

/// Multi-input, multi-output SegWit/Taproot transaction supporting `0x00`, `0x01`, and `0x83` `TapSighash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegwitTx {
    pub version: u32,
    pub inputs: Vec<SegwitTxIn>,
    pub outputs: Vec<(u64, Vec<u8>)>,
    pub locktime: u32,
}

impl SegwitTx {
    pub fn serialize_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend(compact_size(self.inputs.len()));
        for inp in &self.inputs {
            out.extend_from_slice(&inp.outpoint);
            out.push(0x00); // empty scriptSig
            out.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        out.extend(compact_size(self.outputs.len()));
        for (val, spk) in &self.outputs {
            out.extend_from_slice(&val.to_le_bytes());
            out.extend(compact_size(spk.len()));
            out.extend_from_slice(spk);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    pub fn serialize_segwit(&self) -> Vec<u8> {
        let has_witness = self.inputs.iter().any(|i| !i.witness.is_empty());
        if !has_witness {
            return self.serialize_unsigned();
        }
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x01]); // SegWit marker & flag
        out.extend(compact_size(self.inputs.len()));
        for inp in &self.inputs {
            out.extend_from_slice(&inp.outpoint);
            out.push(0x00);
            out.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        out.extend(compact_size(self.outputs.len()));
        for (val, spk) in &self.outputs {
            out.extend_from_slice(&val.to_le_bytes());
            out.extend(compact_size(spk.len()));
            out.extend_from_slice(spk);
        }
        for inp in &self.inputs {
            out.extend(compact_size(inp.witness.len()));
            for item in &inp.witness {
                out.extend(compact_size(item.len()));
                out.extend_from_slice(item);
            }
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    pub fn txid_hex(&self) -> String {
        let mut h = sha256(&sha256(&self.serialize_unsigned()));
        h.reverse();
        hex::encode(h)
    }

    pub fn wtxid_hex(&self) -> String {
        let mut h = sha256(&sha256(&self.serialize_segwit()));
        h.reverse();
        hex::encode(h)
    }

    pub fn vsize(&self) -> usize {
        let base = self.serialize_unsigned().len();
        let total = self.serialize_segwit().len();
        let weight = base * 3 + total;
        weight.div_ceil(4)
    }

    /// Exact BIP-341 `SigMsg` + `TapSighash` supporting `0x00` (`DEFAULT`), `0x01` (`ALL`),
    /// and `0x83` (`SINGLE | ANYONECANPAY`) for both key-path (`tapleaf_hash = None`) and
    /// script-path (`tapleaf_hash = Some(...)`).
    pub fn bip341_sighash(
        &self,
        input_index: usize,
        hash_type: u8,
        tapleaf_hash: Option<&[u8; 32]>,
    ) -> Result<[u8; 32], UtxoRefError> {
        if input_index >= self.inputs.len() {
            return Err(UtxoRefError::InvalidTransaction("input_index out of bounds"));
        }
        if !matches!(
            hash_type,
            SIGHASH_DEFAULT | SIGHASH_ALL | SIGHASH_SINGLE_ANYONECANPAY
        ) {
            return Err(UtxoRefError::InvalidTransaction("unsupported hash_type"));
        }

        let anyone_can_pay = (hash_type & 0x80) == 0x80;
        let base_type = if hash_type == 0x00 {
            0x01
        } else {
            hash_type & 0x03
        };

        let mut preimage = Vec::with_capacity(256);
        preimage.push(0x00); // epoch 0
        preimage.push(hash_type);
        preimage.extend_from_slice(&self.version.to_le_bytes());
        preimage.extend_from_slice(&self.locktime.to_le_bytes());

        if !anyone_can_pay {
            let mut prevouts = Vec::with_capacity(36 * self.inputs.len());
            let mut amounts = Vec::with_capacity(8 * self.inputs.len());
            let mut spks = Vec::with_capacity(35 * self.inputs.len());
            let mut seqs = Vec::with_capacity(4 * self.inputs.len());
            for inp in &self.inputs {
                prevouts.extend_from_slice(&inp.outpoint);
                amounts.extend_from_slice(&inp.prevout_value_sats.to_le_bytes());
                spks.extend(compact_size(inp.prevout_script_pubkey.len()));
                spks.extend_from_slice(&inp.prevout_script_pubkey);
                seqs.extend_from_slice(&inp.sequence.to_le_bytes());
            }
            preimage.extend_from_slice(&sha256(&prevouts));
            preimage.extend_from_slice(&sha256(&amounts));
            preimage.extend_from_slice(&sha256(&spks));
            preimage.extend_from_slice(&sha256(&seqs));
        }

        if base_type == 0x01 {
            let mut outs = Vec::new();
            for (val, spk) in &self.outputs {
                outs.extend_from_slice(&val.to_le_bytes());
                outs.extend(compact_size(spk.len()));
                outs.extend_from_slice(spk);
            }
            preimage.extend_from_slice(&sha256(&outs));
        }

        let spend_type = if tapleaf_hash.is_some() { 0x02u8 } else { 0x00u8 };
        preimage.push(spend_type);

        if anyone_can_pay {
            let inp = &self.inputs[input_index];
            preimage.extend_from_slice(&inp.outpoint);
            preimage.extend_from_slice(&inp.prevout_value_sats.to_le_bytes());
            preimage.extend(compact_size(inp.prevout_script_pubkey.len()));
            preimage.extend_from_slice(&inp.prevout_script_pubkey);
            preimage.extend_from_slice(&inp.sequence.to_le_bytes());
        } else {
            preimage.extend_from_slice(&(input_index as u32).to_le_bytes());
        }

        // BIP-341: `sha_single_output` precedes `ext_flag == 1` (`tapleaf_hash || 0x00 || 0xffffffff`)!
        if base_type == 0x03 {
            let (val, spk) = self.outputs.get(input_index).ok_or(
                UtxoRefError::InvalidTransaction("SIGHASH_SINGLE missing corresponding output"),
            )?;
            let mut single_out = Vec::with_capacity(9 + spk.len());
            single_out.extend_from_slice(&val.to_le_bytes());
            single_out.extend(compact_size(spk.len()));
            single_out.extend_from_slice(spk);
            preimage.extend_from_slice(&sha256(&single_out));
        }

        if let Some(leaf) = tapleaf_hash {
            preimage.extend_from_slice(leaf);
            preimage.push(0x00); // key_version = 0
            preimage.extend_from_slice(&[0xff; 4]); // codeseparator_pos = -1
        }

        Ok(tagged_hash(b"TapSighash", &preimage))
    }
}

/// Serializes a BIP-340 Schnorr signature with its BIP-341 witness sighash byte
/// (`64 bytes` when `hash_type == 0x00`, `65 bytes` when `hash_type != 0x00`).
pub fn encode_taproot_witness_sig(sig: &Bip340Signature, hash_type: u8) -> Vec<u8> {
    if hash_type == SIGHASH_DEFAULT {
        sig.to_bytes().to_vec()
    } else {
        let mut v = Vec::with_capacity(65);
        v.extend_from_slice(&sig.to_bytes());
        v.push(hash_type);
        v
    }
}

/// 3-leaf `SHZ-MNR-02` P2TR funding descriptor (`route_cet_leaf`, `unilateral_cet_leaf`, `refund_leaf`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mnr02TaprootTree {
    pub internal_xonly: [u8; 32],
    pub alice_pubkey_x: [u8; 32],
    pub bob_pubkey_x: [u8; 32],
    pub router_guard_pubkey_x: [u8; 32],
    pub sorted_ab: [[u8; 32]; 2],
    pub maturity_height: u32,
    pub unilateral_cltv_height: u32,
    pub refund_cltv_height: u32,
    pub route_cet_script: Vec<u8>,
    pub unilateral_cet_script: Vec<u8>,
    pub refund_script: Vec<u8>,
    pub route_leaf_hash: [u8; 32],
    pub unilateral_leaf_hash: [u8; 32],
    pub refund_leaf_hash: [u8; 32],
    pub route_control_block: Vec<u8>,
    pub unilateral_control_block: Vec<u8>,
    pub refund_control_block: Vec<u8>,
    pub script_pubkey: Vec<u8>,
}

impl Mnr02TaprootTree {
    pub fn build(
        alice_pubkey_x: [u8; 32],
        bob_pubkey_x: [u8; 32],
        router_guard_pubkey_x: [u8; 32],
        maturity_height: u32,
        grace_blocks: u32,
        refund_delay_blocks: u32,
    ) -> Result<Self, UtxoRefError> {
        if alice_pubkey_x == bob_pubkey_x
            || alice_pubkey_x == router_guard_pubkey_x
            || bob_pubkey_x == router_guard_pubkey_x
        {
            return Err(UtxoRefError::InvalidFunding("keys must be distinct"));
        }
        if grace_blocks == 0 || refund_delay_blocks <= grace_blocks {
            return Err(UtxoRefError::InvalidFunding(
                "require 0 < grace_blocks < refund_delay_blocks",
            ));
        }
        let internal_xonly = utxoref_nums_internal_key()?;

        // Leaf 0: `<P_Alice> OP_CHECKSIGVERIFY <P_Guard> OP_CHECKSIGVERIFY <P_Bob> OP_CHECKSIG`
        let mut route_cet_script = Vec::with_capacity(101);
        route_cet_script.push(0x20);
        route_cet_script.extend_from_slice(&alice_pubkey_x);
        route_cet_script.extend_from_slice(&[0xad, 0x20]);
        route_cet_script.extend_from_slice(&router_guard_pubkey_x);
        route_cet_script.extend_from_slice(&[0xad, 0x20]);
        route_cet_script.extend_from_slice(&bob_pubkey_x);
        route_cet_script.push(0xac);

        let sorted_ab = if alice_pubkey_x < bob_pubkey_x {
            [alice_pubkey_x, bob_pubkey_x]
        } else {
            [bob_pubkey_x, alice_pubkey_x]
        };
        // CLTV and nLockTime read values of 500,000,000 or more as unix times.
        const LOCKTIME_THRESHOLD: u32 = 500_000_000;
        let refund_cltv_height = maturity_height
            .checked_add(refund_delay_blocks)
            .filter(|h| *h < LOCKTIME_THRESHOLD)
            .ok_or(UtxoRefError::InvalidFunding("refund height must be a block height below 500,000,000"))?;
        let unilateral_cltv_height = maturity_height + grace_blocks; // below refund_cltv_height

        // Leaf 1: `<unilateral_cltv> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
        let mut unilateral_cet_script = push_script_num(unilateral_cltv_height as u64);
        unilateral_cet_script.extend_from_slice(&[0xb1, 0x75, 0x20]); // OP_CLTV OP_DROP <32B>
        unilateral_cet_script.extend_from_slice(&sorted_ab[0]);
        unilateral_cet_script.extend_from_slice(&[0xad, 0x20]);
        unilateral_cet_script.extend_from_slice(&sorted_ab[1]);
        unilateral_cet_script.push(0xac);

        // Leaf 2: `<refund_cltv> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
        let mut refund_script = push_script_num(refund_cltv_height as u64);
        refund_script.extend_from_slice(&[0xb1, 0x75, 0x20]);
        refund_script.extend_from_slice(&sorted_ab[0]);
        refund_script.extend_from_slice(&[0xad, 0x20]);
        refund_script.extend_from_slice(&sorted_ab[1]);
        refund_script.push(0xac);

        let route_leaf_hash = tap_leaf_hash(&route_cet_script);
        let unilateral_leaf_hash = tap_leaf_hash(&unilateral_cet_script);
        let refund_leaf_hash = tap_leaf_hash(&refund_script);

        let branch_12 = tap_branch_hash(&unilateral_leaf_hash, &refund_leaf_hash);
        let merkle_root = tap_branch_hash(&route_leaf_hash, &branch_12);

        let mut tweak_in = [0u8; 64];
        tweak_in[..32].copy_from_slice(&internal_xonly);
        tweak_in[32..].copy_from_slice(&merkle_root);
        let tweak = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tagged_hash(
            b"TapTweak",
            &tweak_in,
        )));

        let internal_pt = lift_x_even(&internal_xonly)
            .map_err(|_| UtxoRefError::InvalidCrypto("NUMS lift_x"))?;
        let (out_x, out_y) = point_coordinates(internal_pt + ProjectivePoint::GENERATOR * tweak)?;
        let parity_bit = out_y[31] & 1;
        let ctrl_header = LEAF_VERSION_TAPSCRIPT | parity_bit;

        let mut route_control_block = Vec::with_capacity(65);
        route_control_block.push(ctrl_header);
        route_control_block.extend_from_slice(&internal_xonly);
        route_control_block.extend_from_slice(&branch_12);

        let mut unilateral_control_block = Vec::with_capacity(97);
        unilateral_control_block.push(ctrl_header);
        unilateral_control_block.extend_from_slice(&internal_xonly);
        unilateral_control_block.extend_from_slice(&refund_leaf_hash);
        unilateral_control_block.extend_from_slice(&route_leaf_hash);

        let mut refund_control_block = Vec::with_capacity(97);
        refund_control_block.push(ctrl_header);
        refund_control_block.extend_from_slice(&internal_xonly);
        refund_control_block.extend_from_slice(&unilateral_leaf_hash);
        refund_control_block.extend_from_slice(&route_leaf_hash);

        let mut script_pubkey = Vec::with_capacity(34);
        script_pubkey.extend_from_slice(&[0x51, 0x20]);
        script_pubkey.extend_from_slice(&out_x);

        Ok(Self {
            internal_xonly,
            alice_pubkey_x,
            bob_pubkey_x,
            router_guard_pubkey_x,
            sorted_ab,
            maturity_height,
            unilateral_cltv_height,
            refund_cltv_height,
            route_cet_script,
            unilateral_cet_script,
            refund_script,
            route_leaf_hash,
            unilateral_leaf_hash,
            refund_leaf_hash,
            route_control_block,
            unilateral_control_block,
            refund_control_block,
            script_pubkey,
        })
    }
}

/// Origination-time (`t = 0`) pre-signed package created while Bob is online, BEFORE funding broadcast.
#[derive(Debug, Clone)]
pub struct OriginationPreSignedOutcome {
    pub price_usd: u64,
    pub bob_output_sats: u64,
    pub alice_unilateral_sats: u64,
    /// Bob's `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) adaptor sig on `route_cet_leaf`
    /// committing strictly to `Output 0 = (bob_output_sats, bob_spk)`!
    pub bob_route_0x83_adaptor_sig: AdaptorSignature,
    /// Standard `0x00` (`SIGHASH_DEFAULT`) unilateral fallback CET tx & adaptor sigs (`locktime = maturity + grace`).
    pub unilateral_tx: SegwitTx,
    pub alice_unilateral_adaptor_sig: AdaptorSignature,
    pub bob_unilateral_adaptor_sig: AdaptorSignature,
}

#[derive(Debug, Clone)]
pub struct OriginationPackage {
    pub tree: Mnr02TaprootTree,
    pub funding_txid_display: String,
    pub funding_vout: u32,
    pub funding_sats: u64,
    pub alice_margin_sats: u64,
    pub bob_margin_sats: u64,
    pub miner_fee_sats: u64,
    pub anchor_spk: Vec<u8>,
    pub alice_spk: Vec<u8>,
    pub bob_spk: Vec<u8>,
    pub outcomes: Vec<OriginationPreSignedOutcome>,
    /// Fully signed & verified `refund_leaf` transaction (`locktime = maturity + refund_delay`).
    pub signed_refund_tx: SegwitTx,
}

/// Step `t = 0` (Bob Online): Constructs AND verifies all `0x83` route adaptor pre-signatures,
/// `0x00` unilateral fallback adaptor pre-signatures, and the `0x00` refund transaction BEFORE
/// funding broadcast (`DLC_SECURITY_ARCHITECTURE_REVIEW.md` #9).
#[allow(clippy::too_many_arguments)]
pub fn build_origination_package(
    alice_sk: &[u8; 32],
    bob_sk: &[u8; 32],
    router_guard_pubkey_x: [u8; 32],
    funding_txid_display: &str,
    funding_vout: u32,
    alice_margin_sats: u64,
    bob_margin_sats: u64,
    notional_usd: u64,
    entry_price_usd: u64,
    miner_fee_sats: u64,
    maturity_height: u32,
    grace_blocks: u32,
    refund_delay_blocks: u32,
    alice_spk: Vec<u8>,
    bob_spk: Vec<u8>,
    anchor_spk: Vec<u8>,
    outcome_prices_and_points: &[(u64, ProjectivePoint)],
) -> Result<OriginationPackage, UtxoRefError> {
    let alice_pk = pubkey_x_from_secret(alice_sk).map_err(|_| UtxoRefError::InvalidCrypto("alice_sk"))?;
    let bob_pk = pubkey_x_from_secret(bob_sk).map_err(|_| UtxoRefError::InvalidCrypto("bob_sk"))?;

    let tree = Mnr02TaprootTree::build(
        alice_pk,
        bob_pk,
        router_guard_pubkey_x,
        maturity_height,
        grace_blocks,
        refund_delay_blocks,
    )?;

    let funding_sats = alice_margin_sats + bob_margin_sats;
    let distributable = funding_sats
        .checked_sub(miner_fee_sats + DEFAULT_CPFP_ANCHOR_SATS)
        .ok_or(UtxoRefError::AccountingViolation("collateral < fee + anchor"))?;

    let base_input = SegwitTxIn::from_display_txid(
        funding_txid_display,
        funding_vout,
        0xfffffffe, // enables nLockTime / OP_CLTV!
        funding_sats,
        tree.script_pubkey.clone(),
    )?;

    // 1. Build and sign 2-of-2 Refund Transaction FIRST (`locktime = refund_cltv_height`)
    let refund_alice = alice_margin_sats
        .checked_sub(miner_fee_sats / 2 + DEFAULT_CPFP_ANCHOR_SATS / 2)
        .ok_or(UtxoRefError::AccountingViolation("alice margin < her share of fee + anchor"))?;
    let refund_bob = distributable
        .checked_sub(refund_alice)
        .ok_or(UtxoRefError::AccountingViolation("bob margin < his share of fee + anchor"))?;
    if refund_alice < DEFAULT_CPFP_ANCHOR_SATS || refund_bob < DEFAULT_CPFP_ANCHOR_SATS {
        return Err(UtxoRefError::AccountingViolation("refund output below the 330-sat dust floor"));
    }
    let mut refund_tx = SegwitTx {
        version: 2,
        inputs: vec![base_input.clone()],
        outputs: vec![
            (refund_bob, bob_spk.clone()),
            (refund_alice, alice_spk.clone()),
            (DEFAULT_CPFP_ANCHOR_SATS, anchor_spk.clone()),
        ],
        locktime: tree.refund_cltv_height,
    };
    let refund_sighash =
        refund_tx.bip341_sighash(0, SIGHASH_DEFAULT, Some(&tree.refund_leaf_hash))?;
    let alice_ref_sig =
        bip340_sign(alice_sk, &refund_sighash).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
    let bob_ref_sig =
        bip340_sign(bob_sk, &refund_sighash).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
    bip340_verify(&alice_pk, &refund_sighash, &alice_ref_sig)
        .map_err(|_| UtxoRefError::InvalidCrypto("verify"))?;
    bip340_verify(&bob_pk, &refund_sighash, &bob_ref_sig)
        .map_err(|_| UtxoRefError::InvalidCrypto("verify"))?;

    let (sig_pk0, sig_pk1) = if tree.sorted_ab[0] == alice_pk {
        (alice_ref_sig, bob_ref_sig)
    } else {
        (bob_ref_sig, alice_ref_sig)
    };
    refund_tx.inputs[0].witness = vec![
        encode_taproot_witness_sig(&sig_pk1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&sig_pk0, SIGHASH_DEFAULT),
        tree.refund_script.clone(),
        tree.refund_control_block.clone(),
    ];

    // 2. For each price outcome, compute Bob's `0x83` template pre-sig AND both parties' `0x00` unilateral pre-sigs!
    let mut outcomes = Vec::with_capacity(outcome_prices_and_points.len());
    for &(price_usd, ref adaptor_pt) in outcome_prices_and_points {
        if bool::from(adaptor_pt.is_identity()) {
            return Err(UtxoRefError::InvalidCrypto("identity adaptor point"));
        }
        let pnl_long = inverse_long_pnl_trunc_sats(notional_usd, entry_price_usd, price_usd);
        // Keep >= 330-sat dust floor on both outputs so single-output `0x83` is always relay-standard!
        let min_dust = DEFAULT_CPFP_ANCHOR_SATS as i128;
        let max_side = (distributable - DEFAULT_CPFP_ANCHOR_SATS) as i128;
        let raw_alice = ((alice_margin_sats as i128) + pnl_long - (miner_fee_sats as i128)
            - (DEFAULT_CPFP_ANCHOR_SATS as i128))
            .clamp(min_dust, max_side) as u64;
        let bob_out = distributable - raw_alice;

        // `0x83` 1-in / 1-out template (Carol does NOT exist yet at t=0!)
        let template_0x83 = SegwitTx {
            version: 2,
            inputs: vec![base_input.clone()],
            outputs: vec![(bob_out, bob_spk.clone())],
            locktime: tree.maturity_height,
        };
        let sighash_0x83 = template_0x83.bip341_sighash(
            0,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&tree.route_leaf_hash),
        )?;
        let bob_route_0x83_adaptor_sig = adaptor_sign(bob_sk, &sighash_0x83, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob 0x83 adaptor_sign"))?;
        adaptor_verify(&bob_pk, &sighash_0x83, adaptor_pt, &bob_route_0x83_adaptor_sig)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob 0x83 adaptor_verify"))?;

        // Unilateral fallback CET (`locktime = unilateral_cltv_height`)
        let unilateral_tx = SegwitTx {
            version: 2,
            inputs: vec![base_input.clone()],
            outputs: vec![
                (bob_out, bob_spk.clone()),
                (raw_alice, alice_spk.clone()),
                (DEFAULT_CPFP_ANCHOR_SATS, anchor_spk.clone()),
            ],
            locktime: tree.unilateral_cltv_height,
        };
        let uni_sighash = unilateral_tx.bip341_sighash(
            0,
            SIGHASH_DEFAULT,
            Some(&tree.unilateral_leaf_hash),
        )?;
        let alice_uni_asig = adaptor_sign(alice_sk, &uni_sighash, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("alice uni adaptor_sign"))?;
        let bob_uni_asig = adaptor_sign(bob_sk, &uni_sighash, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob uni adaptor_sign"))?;
        adaptor_verify(&alice_pk, &uni_sighash, adaptor_pt, &alice_uni_asig)
            .map_err(|_| UtxoRefError::InvalidCrypto("alice uni verify"))?;
        adaptor_verify(&bob_pk, &uni_sighash, adaptor_pt, &bob_uni_asig)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob uni verify"))?;

        outcomes.push(OriginationPreSignedOutcome {
            price_usd,
            bob_output_sats: bob_out,
            alice_unilateral_sats: raw_alice,
            bob_route_0x83_adaptor_sig,
            unilateral_tx,
            alice_unilateral_adaptor_sig: alice_uni_asig,
            bob_unilateral_adaptor_sig: bob_uni_asig,
        });
    }

    Ok(OriginationPackage {
        tree,
        funding_txid_display: funding_txid_display.to_string(),
        funding_vout,
        funding_sats,
        alice_margin_sats,
        bob_margin_sats,
        miner_fee_sats,
        anchor_spk,
        alice_spk,
        bob_spk,
        outcomes,
        signed_refund_tx: refund_tx,
    })
}

/// Pre-signed multilateral routed closeout for one outcome price, authorized at `t = 1`
/// while **Bob is completely offline** (`bob_sk` is NOT passed anywhere in this function!).
#[derive(Debug, Clone)]
pub struct BobOfflineRoutedOutcome {
    pub price_usd: u64,
    pub bob_output_sats: u64,
    pub carol_routed_sats: u64,
    pub alice_closeout_sats: u64,
    pub unsigned_routed_tx: SegwitTx,
    pub alice_0x01_sig: Bip340Signature,
    pub guard_0x01_sig: Bip340Signature,
    pub bob_0x83_adaptor_sig: AdaptorSignature,
}

/// Step `t = 1` (**Bob Offline!**): Alice matches an offsetting Short with Carol at `close_price_usd`
/// (`$55,000` in MNR-01) and co-signs `route_cet_leaf` (`SIGHASH_ALL = 0x01`) with `router_guard_sk`
/// (which manages a one-shot anti-replay authorization token so Alice cannot sign conflicting routes!),
/// WITHOUT needing Bob online!
pub fn authorize_bob_offline_multilateral_closeout(
    orig: &OriginationPackage,
    alice_sk: &[u8; 32],
    router_guard_sk: &[u8; 32],
    notional_usd: u64,
    close_price_usd: u64,
    carol_spk: &[u8],
    outcome_prices_and_points: &[(u64, ProjectivePoint)],
) -> Result<Vec<BobOfflineRoutedOutcome>, UtxoRefError> {
    if pubkey_x_from_secret(alice_sk).map_err(|_| UtxoRefError::InvalidCrypto("alice_sk"))?
        != orig.tree.alice_pubkey_x
    {
        return Err(UtxoRefError::InvalidCrypto("alice_sk mismatch"));
    }
    if pubkey_x_from_secret(router_guard_sk).map_err(|_| UtxoRefError::InvalidCrypto("guard_sk"))?
        != orig.tree.router_guard_pubkey_x
    {
        return Err(UtxoRefError::InvalidCrypto("guard_sk mismatch"));
    }

    let base_input = SegwitTxIn::from_display_txid(
        &orig.funding_txid_display,
        orig.funding_vout,
        0xfffffffe,
        orig.funding_sats,
        orig.tree.script_pubkey.clone(),
    )?;

    let mut routed = Vec::with_capacity(orig.outcomes.len());
    for (pre, &(price_usd, ref adaptor_pt)) in
        orig.outcomes.iter().zip(outcome_prices_and_points.iter())
    {
        if pre.price_usd != price_usd {
            return Err(UtxoRefError::AccountingViolation("outcome grid mismatch"));
        }
        // In the offsetting leg (Alice Short vs Carol Long at `close_price_usd`):
        // When `price_usd > close_price_usd`, Alice owes Carol `pnl_offset > 0` out of Alice's U_AB slice!
        let pnl_offset_carol_long =
            inverse_long_pnl_trunc_sats(notional_usd, close_price_usd, price_usd);
        let carol_routed_sats = if pnl_offset_carol_long > 0 {
            (pnl_offset_carol_long as u64)
                .min(pre.alice_unilateral_sats.saturating_sub(DEFAULT_CPFP_ANCHOR_SATS))
        } else {
            0
        };
        let alice_closeout_sats = pre.alice_unilateral_sats - carol_routed_sats;

        let mut outputs = Vec::with_capacity(4);
        // Output 0 MUST be Bob's exact `(bob_output_sats, bob_spk)` committed in Bob's t=0 `0x83` sig!
        outputs.push((pre.bob_output_sats, orig.bob_spk.clone()));
        if carol_routed_sats >= DEFAULT_CPFP_ANCHOR_SATS {
            outputs.push((carol_routed_sats, carol_spk.to_vec()));
        }
        outputs.push((alice_closeout_sats, orig.alice_spk.clone()));
        outputs.push((DEFAULT_CPFP_ANCHOR_SATS, orig.anchor_spk.clone()));

        let tx = SegwitTx {
            version: 2,
            inputs: vec![base_input.clone()],
            outputs,
            locktime: orig.tree.maturity_height,
        };

        // Verify Bob's origination `0x83` adaptor sig STILL validates on this new multi-output tx!
        let check_0x83 = tx.bip341_sighash(
            0,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&orig.tree.route_leaf_hash),
        )?;
        adaptor_verify(
            &orig.tree.bob_pubkey_x,
            &check_0x83,
            adaptor_pt,
            &pre.bob_route_0x83_adaptor_sig,
        )
        .map_err(|_| {
            UtxoRefError::InvalidCrypto("Bob's t=0 0x83 adaptor sig failed on routed tx")
        })?;

        // Alice and RouterGuard sign `SIGHASH_ALL (0x01)` locking Carol's + Alice's + Anchor outputs!
        let sighash_0x01 =
            tx.bip341_sighash(0, SIGHASH_ALL, Some(&orig.tree.route_leaf_hash))?;
        let alice_0x01_sig = bip340_sign(alice_sk, &sighash_0x01)
            .map_err(|_| UtxoRefError::InvalidCrypto("alice 0x01 sign"))?;
        let guard_0x01_sig = bip340_sign(router_guard_sk, &sighash_0x01)
            .map_err(|_| UtxoRefError::InvalidCrypto("guard 0x01 sign"))?;

        routed.push(BobOfflineRoutedOutcome {
            price_usd,
            bob_output_sats: pre.bob_output_sats,
            carol_routed_sats,
            alice_closeout_sats,
            unsigned_routed_tx: tx,
            alice_0x01_sig,
            guard_0x01_sig,
            bob_0x83_adaptor_sig: pre.bob_route_0x83_adaptor_sig,
        });
    }

    Ok(routed)
}

/// Step `t = 2` (Maturity, **Bob Still Offline!**): Completes Bob's `0x83` adaptor signature
/// using the oracle scalar `oracle_scalar_t` and materializes the complete SegWit witness stack
/// `[bob_sig_65_0x83, guard_sig_65_0x01, alice_sig_65_0x01, route_cet_script, route_control_block]`.
pub fn finalize_bob_offline_routed_tx(
    tree: &Mnr02TaprootTree,
    routed_outcome: &BobOfflineRoutedOutcome,
    oracle_scalar_t: &Scalar,
) -> Result<SegwitTx, UtxoRefError> {
    let bob_completed = adaptor_complete(&routed_outcome.bob_0x83_adaptor_sig, oracle_scalar_t)
        .map_err(|_| UtxoRefError::InvalidCrypto("adaptor_complete failed"))?;

    let sighash_0x83 = routed_outcome.unsigned_routed_tx.bip341_sighash(
        0,
        SIGHASH_SINGLE_ANYONECANPAY,
        Some(&tree.route_leaf_hash),
    )?;
    bip340_verify(&tree.bob_pubkey_x, &sighash_0x83, &bob_completed)
        .map_err(|_| UtxoRefError::InvalidCrypto("completed Bob 0x83 Schnorr verify failed"))?;

    let mut signed = routed_outcome.unsigned_routed_tx.clone();
    signed.inputs[0].witness = vec![
        encode_taproot_witness_sig(&bob_completed, SIGHASH_SINGLE_ANYONECANPAY),
        encode_taproot_witness_sig(&routed_outcome.guard_0x01_sig, SIGHASH_ALL),
        encode_taproot_witness_sig(&routed_outcome.alice_0x01_sig, SIGHASH_ALL),
        tree.route_cet_script.clone(),
        tree.route_control_block.clone(),
    ];
    Ok(signed)
}

/// Materializes the grace-delayed `unilateral_cet_leaf` transaction (`locktime = maturity + grace`)
/// when no multilateral closeout occurred or if Carol/LP disappeared before countersigning.
pub fn finalize_unilateral_fallback_tx(
    tree: &Mnr02TaprootTree,
    pre: &OriginationPreSignedOutcome,
    oracle_scalar_t: &Scalar,
) -> Result<SegwitTx, UtxoRefError> {
    let alice_sig = adaptor_complete(&pre.alice_unilateral_adaptor_sig, oracle_scalar_t)
        .map_err(|_| UtxoRefError::InvalidCrypto("alice uni complete"))?;
    let bob_sig = adaptor_complete(&pre.bob_unilateral_adaptor_sig, oracle_scalar_t)
        .map_err(|_| UtxoRefError::InvalidCrypto("bob uni complete"))?;

    let uni_sighash = pre.unilateral_tx.bip341_sighash(
        0,
        SIGHASH_DEFAULT,
        Some(&tree.unilateral_leaf_hash),
    )?;
    bip340_verify(&tree.alice_pubkey_x, &uni_sighash, &alice_sig)
        .map_err(|_| UtxoRefError::InvalidCrypto("alice uni verify"))?;
    bip340_verify(&tree.bob_pubkey_x, &uni_sighash, &bob_sig)
        .map_err(|_| UtxoRefError::InvalidCrypto("bob uni verify"))?;

    let (sig_pk0, sig_pk1) = if tree.sorted_ab[0] == tree.alice_pubkey_x {
        (alice_sig, bob_sig)
    } else {
        (bob_sig, alice_sig)
    };

    let mut signed = pre.unilateral_tx.clone();
    signed.inputs[0].witness = vec![
        encode_taproot_witness_sig(&sig_pk1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&sig_pk0, SIGHASH_DEFAULT),
        tree.unilateral_cet_script.clone(),
        tree.unilateral_control_block.clone(),
    ];
    Ok(signed)
}
