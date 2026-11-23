//! Bitcoin-exact verification for the MNR-03 three-input Taproot clearing layout.

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, Signature};
use bitcoin::{Network, OutPoint, Script, TapLeafHash, TapSighashType, Transaction, TxOut, Txid, Wtxid};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod fixture;

#[cfg(feature = "mnr04-nova")]
pub mod nova;

pub const RELATION: &str = "shz/mnr04/bitcoin-exact-clearing/v1";
const MAX_TRANSACTION_BYTES: usize = 4096;
const ANCHOR_SATS: u64 = 330;

/// Authenticated policy for a specific clearing. The verifier obtains this independently
/// of the candidate transaction and proof, including exact outputs and original outpoints.
pub struct Policy {
    pub network: Network,
    pub prevouts: [(OutPoint, TxOut); 3],
    pub outputs: [TxOut; 5],
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub lock_time: u32,
    pub fee_sats: u64,
    pub epoch_context: [u8; 32],
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("invalid canonical bounded Bitcoin serialization")]
    Encoding,
    #[error("wrong MNR-04 input or output layout")]
    Layout,
    #[error("clearing transaction does not spend the approved ordered outpoints")]
    Outpoint,
    #[error("funding outpoint used more than once")]
    DoubleSpend,
    #[error("wrong locktime or sequence")]
    Timing,
    #[error("settlement differs from authorized payout scripts or amounts")]
    Payout,
    #[error("fee or anchor accounting failed")]
    Fee,
    #[error("invalid or unexpected Taproot script path at input {0}")]
    Script(usize),
    #[error("invalid or unexpected BIP340 signature at input {0}")]
    Signature(usize),
    #[error("Bitcoin TXID or WTXID differs from the approved clearing")]
    Identity,
}

#[derive(Debug, Serialize)]
pub struct Receipt {
    pub relation: &'static str,
    pub bitcoin_network: String,
    pub genesis_hash: String,
    pub txid: String,
    pub wtxid: String,
    pub transaction_commitment: String,
    pub ordered_funding_commitment: String,
    pub epoch_context: String,
    pub funded_sats: u64,
    pub payout_sats: [u64; 5],
    pub fee_sats: u64,
    pub sigmsg_hex: [[Option<String>; 3]; 3],
    pub native_signature_verified: bool,
    pub original_contract_policy_external: bool,
    pub nova_authorization_verified: bool,
    pub bitvm3_onchain_verified: bool,
    pub production_ready: bool,
}

pub fn parse_transaction(raw: &[u8]) -> Result<Transaction, Error> {
    if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
        return Err(Error::Encoding);
    }
    let tx = deserialize::<Transaction>(raw).map_err(|_| Error::Encoding)?;
    if serialize(&tx) != raw {
        return Err(Error::Encoding);
    }
    Ok(tx)
}

/// Parse only the exact x-only-key CHECKSIGVERIFY…CHECKSIG leaves used by this fixture.
/// This rejects annexes, OP_CODESEPARATOR and general scripts outside the relation.
fn threshold_keys(script: &Script, count: usize) -> Option<Vec<XOnlyPublicKey>> {
    if script.len() != 34 * count {
        return None;
    }
    script.as_bytes().chunks_exact(34).enumerate().map(|(position, chunk)| {
        let opcode = if position + 1 == count { 0xac } else { 0xad };
        if chunk[0] != 32 || chunk[33] != opcode {
            return None;
        }
        XOnlyPublicKey::from_slice(&chunk[1..33]).ok()
    }).collect()
}

pub fn verify(raw: &[u8], policy: &Policy) -> Result<Receipt, Error> {
    let tx = parse_transaction(raw)?;
    if tx.version != bitcoin::transaction::Version::TWO || tx.input.len() != 3 || tx.output.len() != 5 {
        return Err(Error::Layout);
    }
    if tx.lock_time.to_consensus_u32() != policy.lock_time
        || tx.input.iter().any(|i| i.sequence.to_consensus_u32() != 0xffff_fffe || !i.script_sig.is_empty())
    {
        return Err(Error::Timing);
    }
    for (index, input) in tx.input.iter().enumerate() {
        if tx.input[..index].iter().any(|i| i.previous_output == input.previous_output) {
            return Err(Error::DoubleSpend);
        }
        if input.previous_output != policy.prevouts[index].0 {
            return Err(Error::Outpoint);
        }
    }
    let prevouts = policy.prevouts.each_ref().map(|entry| entry.1.clone());
    let funded_sats = prevouts.iter().try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat())).ok_or(Error::Fee)?;
    let spent_sats = tx.output.iter().try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat())).ok_or(Error::Fee)?;
    if tx.output[4] != policy.outputs[4] || tx.output[4].value.to_sat() != ANCHOR_SATS {
        return Err(Error::Fee);
    }

    let mut cache = SighashCache::new(&tx);
    let secp = Secp256k1::verification_only();
    let mut sigmsg_hex: [[Option<String>; 3]; 3] = std::array::from_fn(|_| std::array::from_fn(|_| None));
    let mut paths = Vec::with_capacity(3);
    for (index, input) in tx.input.iter().enumerate() {
        let types: &[TapSighashType] = if index < 2 {
            &[TapSighashType::SinglePlusAnyoneCanPay, TapSighashType::All, TapSighashType::All]
        } else {
            &[TapSighashType::Default, TapSighashType::Default]
        };
        let witness: Vec<&[u8]> = input.witness.iter().collect();
        let n = types.len();
        if witness.len() != n + 2 { return Err(Error::Script(index)); }
        let script = Script::from_bytes(witness[n]);
        let keys = threshold_keys(script, n).ok_or(Error::Script(index))?;
        let control = ControlBlock::decode(witness[n + 1]).map_err(|_| Error::Script(index))?;
        let previous = &prevouts[index].script_pubkey;
        if !previous.is_p2tr() || control.leaf_version != LeafVersion::TapScript {
            return Err(Error::Script(index));
        }
        let output_key = XOnlyPublicKey::from_slice(&previous.as_bytes()[2..]).map_err(|_| Error::Script(index))?;
        if !control.verify_taproot_commitment(&secp, output_key, script) {
            return Err(Error::Script(index));
        }
        let leaf = TapLeafHash::from_script(script, LeafVersion::TapScript);
        paths.push((types, keys, leaf, witness));
    }
    // Verify both offline signatures before online SIGHASH_ALL can mask a Bob payout failure.
    let slots = [(0, 0), (1, 0), (0, 1), (0, 2), (1, 1), (1, 2), (2, 0), (2, 1)];
    for (index, slot) in slots {
        let (types, keys, leaf, witness) = &paths[index];
        let flag = types[slot];
        let pubkey = &keys[keys.len() - 1 - slot];
            let sig = Signature::from_slice(witness[slot]).map_err(|_| Error::Signature(index))?;
            if sig.sighash_type != flag || witness[slot].len() != if flag == TapSighashType::Default { 64 } else { 65 } {
                return Err(Error::Signature(index));
            }
            let message = cache.taproot_script_spend_signature_hash(index, &Prevouts::All(&prevouts), *leaf, flag)
                .map_err(|_| Error::Signature(index))?.to_byte_array();
            secp.verify_schnorr(&sig.signature, &Message::from_digest(message), pubkey)
                .map_err(|_| Error::Signature(index))?;
        sigmsg_hex[index][slot] = Some(hex::encode(message));
    }
    if tx.output != policy.outputs { return Err(Error::Payout); }
    if funded_sats.checked_sub(spent_sats) != Some(policy.fee_sats) {
        return Err(Error::Fee);
    }
    let txid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();
    if txid != policy.txid || wtxid != policy.wtxid { return Err(Error::Identity); }
    let genesis = bitcoin::blockdata::constants::genesis_block(policy.network).block_hash();
    let mut funding = Sha256::new();
    funding.update(b"shz/mnr04/funding/v1\0");
    for (outpoint, output) in &policy.prevouts {
        funding.update(serialize(outpoint));
        funding.update(serialize(output));
    }
    let funding: [u8; 32] = funding.finalize().into();
    let mut commitment = Sha256::new();
    commitment.update(RELATION);
    commitment.update([0]);
    commitment.update(genesis.to_byte_array());
    commitment.update(funding);
    commitment.update(policy.epoch_context);
    commitment.update(policy.fee_sats.to_be_bytes());
    commitment.update((raw.len() as u64).to_be_bytes());
    commitment.update(raw);
    Ok(Receipt {
        relation: RELATION, bitcoin_network: policy.network.to_string(), genesis_hash: genesis.to_string(),
        txid: txid.to_string(), wtxid: wtxid.to_string(), transaction_commitment: hex::encode(commitment.finalize()),
        ordered_funding_commitment: hex::encode(funding), epoch_context: hex::encode(policy.epoch_context),
        funded_sats, payout_sats: std::array::from_fn(|index| tx.output[index].value.to_sat()),
        fee_sats: policy.fee_sats, sigmsg_hex, native_signature_verified: true,
        original_contract_policy_external: true, nova_authorization_verified: false,
        bitvm3_onchain_verified: false, production_ready: false,
    })
}
