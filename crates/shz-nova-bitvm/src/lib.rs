//! `shz-nova-bitvm` — Pure-MIT native batch settlement statement verifier, Nova v2 600-byte
//! signed-row transcript & 8-field expectation builder, Secq BIP-340 3-field claim binder,
//! and 304-byte `UTXOREF_L2_SETTLEMENT_GROTH16_V0\0` BitVM3 settlement statement codec.
//!
//! # License & Soundness Boundary
//! - Licensed under MIT (`#![forbid(unsafe_code)]`), using only workspace `k256` and `sha2`.
//! - Contains zero GPL-3.0 R1CS/M18 code: produces byte-exact inputs and `expected.json` pins
//!   ready for out-of-process `lnm-nova prepare` / `lnm-nova verify` and BitVM3 Groth16 verifiers.
//! - Every emitted record carries explicit [`VerificationHonestyFlags`] setting
//!   `native_statement_verified: true`, `nova_snark_verified: false`,
//!   `bitvm3_onchain_verified: false`, and `production_ready: false`.
#![forbid(unsafe_code)]

pub mod bitvm3;
pub mod bridge;
pub mod codec;
pub mod error;
pub mod fixture;
pub mod merkle;
pub mod nova;
pub mod secq_claim;
pub mod statement;
pub mod taproot;

pub use bitvm3::{
    BITCOIN_REGTEST_GENESIS_HASH_HEX, BITVM3_STATEMENT_LEN, BITVM3_STATEMENT_MAGIC,
    BitVm3SettlementRecord, BitcoinNetworkCode, UtxoRefL2SettlementStatementV0,
    split_statement_digest_be_u128,
};
pub use bridge::{
    BridgeSignerMaterial, JournalSummaryJson, Mnr02BitVm3BridgeSummary, NovaBitvmDemoReport,
    ShzDlcBridgeSpec, assemble_and_sign_bridged_batch, build_bitvm3_settlement_statement,
    build_unsigned_row_from_mnr02, build_unsigned_row_from_shz_dlc, build_verified_nova_bitvm_demo,
};
pub use codec::{decode_batch, decode_journal, encode_batch, encode_journal};
pub use error::{NovaBitvmError, Result, VerificationHonestyFlags};
pub use merkle::{
    SparseNullifierTree, accepted_contracts_root, empty_nullifier_root, outcome_leaf_hash,
    outcome_root_and_path,
};
pub use nova::{
    NOVA_CUMULATIVE_AMOUNT_BITS, NOVA_CUMULATIVE_AMOUNT_LIMIT, NOVA_MAX_STEPS,
    NOVA_RELATION_VERSION, NOVA_ROW_AMOUNT_BITS, NOVA_ROW_AMOUNT_LIMIT, NOVA_TRANSCRIPT_LEN,
    NOVA_TRANSCRIPT_PREFIX, NovaExpectedStatement, NovaFoldedState, check_cumulative_amount_56bit,
    check_row_amount_51bit, encode_signed_row_transcript, sha256_to_le_u128_halves,
    verify_signed_row_transcript,
};
pub use secq_claim::{
    RowSignatureSlot, SecqBip340Claim, build_and_verify_all_6_row_claims,
    expected_row_slot_material, secq_claim_digest_and_halves,
};
pub use statement::{
    BATCH_MAGIC, BatchContext, BatchWitness, DOMAIN, DlcSummary, Hash, JOURNAL_LEN, JOURNAL_MAGIC,
    Journal, JournalPins, MAX_MONEY, MAX_OUTCOMES, MAX_ROW_FEE_SATS, MAX_ROWS, MAX_WITNESS_BYTES,
    MIN_OUTPUT_SATS, OracleAttestation, Outcome, Row, SMT_DEPTH, Script, Sig,
    batch_consent_message, oracle_message, outpoint_nullifier, sha256, statement_domain,
    summary_digest, tagged_hash, unsigned_batch_transaction, verify_batch, verify_batch_bytes,
    verify_bip340, verify_expected_journal,
};
pub use taproot::derive_funding_script;
