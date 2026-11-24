//! Exact 304-byte `UTXOREF_L2_SETTLEMENT_GROTH16_V0\0` BitVM3 L2 settlement statement codec
//! and big-endian 128-bit public-input limb splitter.
//!
//! Specification reference: `patrickdugan/UTXO-Ref` (`zk-groth16-bitvm/STATEMENT.md`, MIT).

use serde::{Deserialize, Serialize};

use crate::error::{NovaBitvmError, Result, VerificationHonestyFlags};
use crate::statement::{Hash, sha256};

/// Exact 33-byte ASCII domain tag including trailing NUL terminator.
pub const BITVM3_STATEMENT_MAGIC: &[u8; 33] = b"UTXOREF_L2_SETTLEMENT_GROTH16_V0\0";

/// Exact canonical byte length of `UtxoRefL2SettlementStatementV0`.
pub const BITVM3_STATEMENT_LEN: usize = 304;

/// Bitcoin Regtest genesis block hash (display order).
pub const BITCOIN_REGTEST_GENESIS_HASH_HEX: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Bitcoin Testnet4 (BIP-94) genesis block hash (display order).
pub const BITCOIN_TESTNET4_GENESIS_HASH_HEX: &str =
    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";

/// Pinned `lnm-nova` (`nova-snark 0.76.0`) Spartan + IPA verifier key SHA-256 for
/// `lnmarkets/sha256-transcript-accounting/v2` (`101,826,448` serialized VK bytes).
pub const LNM_NOVA_V2_VK_SHA256_HEX: &str =
    "4eafbd223936cc3c1e9b16e750f1946a57cd5413f86578f6f1d37d9abb53e38b";

/// Canonical Bitcoin network codes for byte offset `35` (`UTXO-Ref/zk-groth16-bitvm/STATEMENT.md`:
/// `regtest = 0; testnet4 = 1`; mainnet intentionally forbidden in v0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BitcoinNetworkCode {
    Regtest = 0,
    Testnet4 = 1,
}

impl BitcoinNetworkCode {
    pub fn from_u8(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Regtest),
            1 => Ok(Self::Testnet4),
            other => Err(NovaBitvmError::BitVm3(format!(
                "unsupported Bitcoin network_code {other} (expected 0=regtest or 1=testnet4 in v0)"
            ))),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Exact 304-byte `UTXORef` BitVM3 L2 Groth16 settlement statement (`v0`).
///
/// Canonical byte layout (`304 bytes` total):
/// - `0..33`:   `ASCII("UTXOREF_L2_SETTLEMENT_GROTH16_V0\0")` (`33B`)
/// - `33..35`:  `u16le(0)` reserved (`2B`)
/// - `35..36`:  `u8(network_code)` (`1B`)
/// - `36..68`:  `chain_genesis_hash` (`32B`)
/// - `68..100`: `contract_id` (`32B`)
/// - `100..132`: `commitment_hash` (`32B`)
/// - `132..164`: `assertion_txid` (`32B`)
/// - `164..196`: `settlement_txid` (`32B`)
/// - `196..228`: `program_hash` (`32B`)
/// - `228..260`: `verifying_key_hash` (`32B`)
/// - `260..292`: `policy_hash` (`32B`)
/// - `292..300`: `epoch_id` (`u64le`, `8B`)
/// - `300..304`: `assertion_vout` (`u32le`, `4B`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoRefL2SettlementStatementV0 {
    pub network_code: BitcoinNetworkCode,
    pub chain_genesis_hash: Hash,
    pub contract_id: Hash,
    pub commitment_hash: Hash,
    pub assertion_txid: Hash,
    pub settlement_txid: Hash,
    pub program_hash: Hash,
    pub verifying_key_hash: Hash,
    pub policy_hash: Hash,
    pub epoch_id: u64,
    pub assertion_vout: u32,
}

/// Splits `SHA256(encoded_304_bytes)` into the two Groth16/BitVM3 big-endian 128-bit public inputs:
/// `[u128::from_be_bytes(d[0..16]), u128::from_be_bytes(d[16..32])]`.
pub fn split_statement_digest_be_u128(digest: &Hash) -> [u128; 2] {
    let hi = u128::from_be_bytes(digest[0..16].try_into().expect("16-byte hi"));
    let lo = u128::from_be_bytes(digest[16..32].try_into().expect("16-byte lo"));
    [hi, lo]
}

impl UtxoRefL2SettlementStatementV0 {
    /// Encodes this statement into its exact 304-byte canonical binary representation.
    pub fn encode(&self) -> [u8; BITVM3_STATEMENT_LEN] {
        let mut out = [0u8; BITVM3_STATEMENT_LEN];
        out[0..33].copy_from_slice(BITVM3_STATEMENT_MAGIC);
        out[33..35].copy_from_slice(&0u16.to_le_bytes());
        out[35] = self.network_code.as_u8();
        out[36..68].copy_from_slice(&self.chain_genesis_hash);
        out[68..100].copy_from_slice(&self.contract_id);
        out[100..132].copy_from_slice(&self.commitment_hash);
        out[132..164].copy_from_slice(&self.assertion_txid);
        out[164..196].copy_from_slice(&self.settlement_txid);
        out[196..228].copy_from_slice(&self.program_hash);
        out[228..260].copy_from_slice(&self.verifying_key_hash);
        out[260..292].copy_from_slice(&self.policy_hash);
        out[292..300].copy_from_slice(&self.epoch_id.to_le_bytes());
        out[300..304].copy_from_slice(&self.assertion_vout.to_le_bytes());
        out
    }

    /// Strictly decodes a 304-byte `UTXOREF_L2_SETTLEMENT_GROTH16_V0\0` payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BITVM3_STATEMENT_LEN {
            return Err(NovaBitvmError::BitVm3(format!(
                "BitVM3 settlement statement must be exactly {BITVM3_STATEMENT_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if &bytes[0..33] != BITVM3_STATEMENT_MAGIC {
            return Err(NovaBitvmError::BitVm3(
                "invalid UTXOREF_L2_SETTLEMENT_GROTH16_V0 magic prefix".to_owned(),
            ));
        }
        let reserved = u16::from_le_bytes(bytes[33..35].try_into().expect("2-byte reserved"));
        if reserved != 0 {
            return Err(NovaBitvmError::BitVm3(format!(
                "reserved header u16 must be 0, got {reserved}"
            )));
        }
        let network_code = BitcoinNetworkCode::from_u8(bytes[35])?;
        Ok(Self {
            network_code,
            chain_genesis_hash: bytes[36..68].try_into().expect("32B"),
            contract_id: bytes[68..100].try_into().expect("32B"),
            commitment_hash: bytes[100..132].try_into().expect("32B"),
            assertion_txid: bytes[132..164].try_into().expect("32B"),
            settlement_txid: bytes[164..196].try_into().expect("32B"),
            program_hash: bytes[196..228].try_into().expect("32B"),
            verifying_key_hash: bytes[228..260].try_into().expect("32B"),
            policy_hash: bytes[260..292].try_into().expect("32B"),
            epoch_id: u64::from_le_bytes(bytes[292..300].try_into().expect("8B")),
            assertion_vout: u32::from_le_bytes(bytes[300..304].try_into().expect("4B")),
        })
    }

    /// Validates that none of the eight 32-byte hash commitments are all-zero and `epoch_id > 0`.
    pub fn validate_nonzero(&self) -> Result<()> {
        if self.epoch_id == 0 {
            return Err(NovaBitvmError::BitVm3("epoch_id must be positive".to_owned()));
        }
        for (value, label) in [
            (&self.chain_genesis_hash, "chain_genesis_hash"),
            (&self.contract_id, "contract_id"),
            (&self.commitment_hash, "commitment_hash"),
            (&self.assertion_txid, "assertion_txid"),
            (&self.settlement_txid, "settlement_txid"),
            (&self.program_hash, "program_hash"),
            (&self.verifying_key_hash, "verifying_key_hash"),
            (&self.policy_hash, "policy_hash"),
        ] {
            if *value == [0u8; 32] {
                return Err(NovaBitvmError::BitVm3(format!("{label} must be nonzero")));
            }
        }
        Ok(())
    }

    /// Computes `SHA256(encoded_304_bytes)`.
    pub fn statement_digest(&self) -> Hash {
        sha256(&self.encode())
    }

    /// Computes `[u128::from_be_bytes(d[0..16]), u128::from_be_bytes(d[16..32])]`.
    pub fn public_inputs_be(&self) -> [u128; 2] {
        split_statement_digest_be_u128(&self.statement_digest())
    }

    /// Builds a JSON-serializable summary carrying explicit native-only honesty flags.
    pub fn to_json_record(&self) -> BitVm3SettlementRecord {
        let encoded = self.encode();
        let digest = sha256(&encoded);
        let limbs = split_statement_digest_be_u128(&digest);
        BitVm3SettlementRecord {
            magic: "UTXOREF_L2_SETTLEMENT_GROTH16_V0\\0".to_owned(),
            encoded_len: BITVM3_STATEMENT_LEN,
            network_code: self.network_code,
            epoch_id: self.epoch_id,
            assertion_vout: self.assertion_vout,
            chain_genesis_hash_hex: hex::encode(self.chain_genesis_hash),
            contract_id_hex: hex::encode(self.contract_id),
            commitment_hash_hex: hex::encode(self.commitment_hash),
            assertion_txid_hex: hex::encode(self.assertion_txid),
            settlement_txid_hex: hex::encode(self.settlement_txid),
            program_hash_hex: hex::encode(self.program_hash),
            verifying_key_hash_hex: hex::encode(self.verifying_key_hash),
            policy_hash_hex: hex::encode(self.policy_hash),
            statement_304b_hex: hex::encode(encoded),
            statement_sha256_hex: hex::encode(digest),
            public_input_limbs_be_dec: [limbs[0].to_string(), limbs[1].to_string()],
            public_input_limbs_be_hex: [format!("{:032x}", limbs[0]), format!("{:032x}", limbs[1])],
            honesty: VerificationHonestyFlags::native_only(),
        }
    }
}

/// JSON-serializable view of a 304-byte BitVM3 settlement statement with explicit honesty flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitVm3SettlementRecord {
    pub magic: String,
    pub encoded_len: usize,
    pub network_code: BitcoinNetworkCode,
    pub epoch_id: u64,
    pub assertion_vout: u32,
    pub chain_genesis_hash_hex: String,
    pub contract_id_hex: String,
    pub commitment_hash_hex: String,
    pub assertion_txid_hex: String,
    pub settlement_txid_hex: String,
    pub program_hash_hex: String,
    pub verifying_key_hash_hex: String,
    pub policy_hash_hex: String,
    pub statement_304b_hex: String,
    pub statement_sha256_hex: String,
    pub public_input_limbs_be_dec: [String; 2],
    pub public_input_limbs_be_hex: [String; 2],
    pub honesty: VerificationHonestyFlags,
}
