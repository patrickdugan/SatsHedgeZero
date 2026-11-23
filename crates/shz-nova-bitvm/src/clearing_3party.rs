//! Three-party, three-trade multilateral inverse DLC collation, `UTXORef` capacitated margin
//! clearing, collateral release, and Testnet4 Nova v2 / BitVM3 settlement harness.
//!
//! # Scenario (`$33,000` Inverse Notional across `$50,000` -> `$55,000` -> `$60,000`)
//! 1. **Trade 1 (`$50,000`):** `Alice` (`Long $33,000`, `2x` = `33,000,000` sats) matches `Bob`
//!    (`Short $33,000`, `1x` SatsHedge = `66,000,000` sats) at `0` fee.
//! 2. **Trade 2 (`$55,000`):** `Bob` (`Long $33,000`, `2x` = `30,000,000` sats) flattens his net
//!    exposure against `Carol` (`Short $33,000`, `1x` SatsHedge = `60,000,000` sats) at `0` fee,
//!    crystallizing Bob's net loss at `-6,000,000` sats while `96,000,000` sats of Bob's margin
//!    sits locked across two bilateral DLCs.
//! 3. **Trade 3 (`$60,000` — Winner Closes Out):** `Alice` (`Short $33,000`, `2x` = `27,500,000` sats)
//!    closes her winning position against `Carol` (`Long $33,000`, `2x` = `27,500,000` sats) at `0` fee.
//!
//! At clearing mark `$60,000` (attested by a `3-of-5` FROST quorum + 2-of-3 sorted batch oracles):
//! - All 3 signed DLCs are collated into one `LNMBAT01` `BatchWitness` (`3` rows), `276B` `LNMJNL01`
//!   public journal, `3 x 600B` Nova v2 transcripts, `18` Secq BIP-340 3-field claims, and a `304B`
//!   `UTXOREF_L2_SETTLEMENT_GROTH16_V0` statement on `BitcoinNetworkCode::Testnet4` (`1`).
//! - `UTXORef` Edmonds-Karp PnL routing (`solve_and_verify_pnl_batch` + `DurablePnlBatchBook`)
//!   routes `+11,000,000` sats realized PnL (`6,000,000` from Bob + `5,000,000` from Carol) to
//!   `Alice` (`71,500,000` sats total payout), while **freeing `90,000,000` sats (`93.75%`) of
//!   loser Bob's collateral** and **`82,500,000` sats of Carol's collateral** in a single atomic
//!   3-input, 4-output BIP-341 Taproot clearing transaction (`txid == journal.batch_txid`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use shz_dex::{OracleSettlementPolicy, OrderSide, SignedOrderIntent, ZeroFeeOrderBook};
use shz_dlc::{BtcOutPoint, bip340_sign, bip340_verify, pubkey_x_from_secret};
use shz_margin::CollateralAsset;
use shz_oracle::frost::FrostConfederation;
use shz_utxoref::{
    mnr02::{SIGHASH_DEFAULT, SegwitTx, SegwitTxIn, encode_taproot_witness_sig},
    pnl_batch::{
        AccountRecord, DurablePnlBatchBook, FundedVaultUtxo, NettingSetSpec, PermittedRoute,
        PnlBatchSnapshotV1, RealizedObligation, RouteTarget, VaultRecord,
        solve_and_verify_pnl_batch,
    },
};

use crate::bitvm3::{
    BITCOIN_TESTNET4_GENESIS_HASH_HEX, BitVm3SettlementRecord, BitcoinNetworkCode,
    LNM_NOVA_V2_VK_SHA256_HEX,
};
use crate::bridge::{
    BridgeSignerMaterial, JournalSummaryJson, ShzDlcBridgeSpec, assemble_and_sign_bridged_batch,
    build_bitvm3_settlement_statement, build_unsigned_row_from_shz_dlc,
};
use crate::codec::{decode_batch, encode_batch};
use crate::error::{NovaBitvmError, Result, VerificationHonestyFlags};
use crate::merkle::SparseNullifierTree;
use crate::nova::{NOVA_TRANSCRIPT_LEN, NovaExpectedStatement};
use crate::secq_claim::{SecqBip340Claim, build_and_verify_all_6_row_claims};
use crate::statement::{
    BatchWitness, Hash, Journal, Script, statement_domain, tagged_hash, unsigned_batch_transaction,
    verify_batch,
};
use crate::taproot::{FundingTaprootSpendInfo, derive_funding_taproot_spend_info};

/// Default pinned Bitcoin Testnet4 block height used when running deterministically offline.
pub const DEFAULT_TESTNET4_ANCHOR_HEIGHT: u64 = 162_899;

/// Default pinned Bitcoin Testnet4 block hash at height `162,899`.
pub const DEFAULT_TESTNET4_ANCHOR_HASH_HEX: &str =
    "00000000031d88b6cefdcbd70fcddf6123891d96c5c338f275771af1110adb5d";

/// Input configuration for the 3-party, 3-trade multilateral DLC clearing ceremony.
#[derive(Debug, Clone)]
pub struct ThreePartyClearingConfig {
    /// Optional real on-chain funding outpoints `(display_txid, vout)` for `[Trade1, Trade2, Trade3]`.
    /// When `None`, deterministic synthetic funding outpoints are derived.
    pub funding_outpoints: Option<[(Hash, u32); 3]>,
    pub maturity_height: u32,
    pub evaluation_height: u32,
    pub valid_until_height: u32,
    pub refund_height: u32,
    pub refund_csv: u16,
    pub testnet4_anchor_height: u64,
    pub testnet4_anchor_block_hash_hex: String,
}

impl Default for ThreePartyClearingConfig {
    fn default() -> Self {
        Self {
            funding_outpoints: None,
            maturity_height: 120,
            evaluation_height: 120,
            valid_until_height: 200,
            refund_height: 240,
            refund_csv: 144,
            testnet4_anchor_height: DEFAULT_TESTNET4_ANCHOR_HEIGHT,
            testnet4_anchor_block_hash_hex: DEFAULT_TESTNET4_ANCHOR_HASH_HEX.to_owned(),
        }
    }
}

/// Funding specification for one of the 3 bilateral DLCs prior to on-chain funding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlcFundingTemplate {
    pub trade_index: usize,
    pub label: String,
    pub long_party: String,
    pub short_party: String,
    pub entry_price_usd: u64,
    pub usd_notional: u64,
    pub long_margin_sats: u64,
    pub short_margin_sats: u64,
    pub anchor_sats: u64,
    pub miner_fee_sats: u64,
    pub total_funding_sats: u64,
    pub funding_script_pubkey_hex: String,
}

/// Summary of each executed 0-fee P2P trade and its bilateral DLC settlement at `$60,000`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedClearingTrade {
    pub trade_no: u8,
    pub label: String,
    pub match_id_hex: String,
    pub execution_price_usd: u64,
    pub clearing_mark_price_usd: u64,
    pub usd_notional: u64,
    pub long_party: String,
    pub short_party: String,
    pub long_margin_sats: u64,
    pub short_margin_sats: u64,
    pub protocol_fee_sats: u64,
    pub funding_txid_hex: String,
    pub funding_vout: u32,
    pub funding_script_pubkey_hex: String,
    pub total_utxo_sats: u64,
    pub bilateral_long_payout_sats: u64,
    pub bilateral_short_payout_sats: u64,
    pub bilateral_realized_long_pnl_sats: i64,
}

/// Per-party multilateral margin, PnL routing, and freed-collateral accounting summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartyClearingAccounting {
    pub party: String,
    pub role: String,
    pub net_usd_delta_after_trade3: i64,
    pub total_posted_margin_sats: u64,
    pub net_realized_pnl_sats: i64,
    pub freed_collateral_returned_sats: u64,
    pub routed_pnl_received_sats: u64,
    pub final_cleared_payout_sats: u64,
    pub payout_script_pubkey_hex: String,
}

/// Summary of the `UTXORef` Edmonds-Karp PnL routing + `DurablePnlBatchBook` state progression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoRefClearingSummary {
    pub snapshot_hash_hex: String,
    pub next_accounting_state_root_hex: String,
    pub durable_book_final_head_hash_hex: String,
    pub durable_book_settled_epoch: u64,
    pub bob_to_alice_routed_pnl_sats: u64,
    pub carol_to_alice_routed_pnl_sats: u64,
    pub total_winner_routed_pnl_sats: u64,
    pub bob_locked_margin_before_clearing_sats: u64,
    pub bob_freed_collateral_sats: u64,
    pub bob_freed_collateral_bps: u64,
    pub carol_freed_collateral_sats: u64,
    pub alice_total_cleared_payout_sats: u64,
}

/// Optional out-of-process `lnm-nova` (`nova-snark 0.76.0`) CompressedSNARK proof verification receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalNovaSnarkReceipt {
    pub schema: String,
    pub relation: String,
    pub nova_version: String,
    pub steps: u32,
    pub compressed_proof_bytes: usize,
    pub proof_sha256_hex: String,
    pub verifier_key_sha256_hex: String,
    pub verifier_key_serialized_bytes: u64,
    pub public_params_digest_hex: String,
    pub primary_constraints: u64,
    pub secondary_constraints: u64,
    pub prove_wall_seconds: String,
    pub verify_wall_seconds: String,
    pub independently_supplied_expectations_matched: bool,
    pub nova_compressed_verified: bool,
}

/// Complete, serializable 3-party, 3-trade multilateral DLC + BitVM3 Nova clearing bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreePartyClearingReport {
    pub protocol: String,
    pub network: String,
    pub testnet4_anchor_height: u64,
    pub testnet4_anchor_block_hash_hex: String,
    pub clearing_mark_price_usd: u64,
    pub frost_quorum_signers: [u16; 3],
    pub frost_group_pubkey_x_hex: String,
    pub trades: [ExecutedClearingTrade; 3],
    pub party_accounting: [PartyClearingAccounting; 3],
    pub utxoref_pnl_clearing: UtxoRefClearingSummary,
    pub batch_witness_bytes_len: usize,
    pub journal: JournalSummaryJson,
    pub row_transcripts_600b_hex: Vec<String>,
    pub nova_expected_statement: NovaExpectedStatement,
    pub secq_claims_verified_count: usize,
    pub bitvm3_testnet4_statement: BitVm3SettlementRecord,
    pub atomic_clearing_txid_hex: String,
    pub atomic_clearing_wtxid_hex: String,
    pub atomic_clearing_vsize: usize,
    pub atomic_clearing_outputs_sats: Vec<u64>,
    pub atomic_clearing_raw_segwit_tx_hex: String,
    pub external_nova_snark_receipt: Option<ExternalNovaSnarkReceipt>,
    pub honesty: VerificationHonestyFlags,
}

/// Full in-memory artifacts from [`build_three_party_clearing_ceremony`], including the binary
/// `LNMBAT01` witness ready for `lnm-nova` and the signed `SegwitTx` ready for `bitcoind`.
#[derive(Debug, Clone)]
pub struct ThreePartyClearingArtifacts {
    pub batch_witness: BatchWitness,
    pub batch_witness_bytes: Vec<u8>,
    pub journal: Journal,
    pub signed_clearing_tx: SegwitTx,
    pub report: ThreePartyClearingReport,
}

fn p2tr_script_from_xonly(xonly: &Hash) -> Script {
    let mut s = [0u8; 34];
    s[..2].copy_from_slice(&[0x51, 0x20]);
    s[2..].copy_from_slice(xonly);
    s
}

struct PartyKeys {
    alice_sk: [u8; 32],
    bob_sk: [u8; 32],
    carol_sk: [u8; 32],
    oracle_sks: [[u8; 32]; 3],
    alice_pk: Hash,
    bob_pk: Hash,
    carol_pk: Hash,
    alice_payout_script: Script,
    bob_payout_script: Script,
    carol_payout_script: Script,
    anchor_script: Script,
}

fn derive_canonical_party_keys() -> Result<PartyKeys> {
    let alice_sk = [0x11u8; 32];
    let bob_sk = [0x22u8; 32];
    let carol_sk = [0x23u8; 32];
    let oracle_sks = [[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]];

    let alice_pk = pubkey_x_from_secret(&alice_sk)
        .map_err(|_| NovaBitvmError::Bridge("alice_pk".to_owned()))?;
    let bob_pk =
        pubkey_x_from_secret(&bob_sk).map_err(|_| NovaBitvmError::Bridge("bob_pk".to_owned()))?;
    let carol_pk = pubkey_x_from_secret(&carol_sk)
        .map_err(|_| NovaBitvmError::Bridge("carol_pk".to_owned()))?;

    let alice_out_pk = pubkey_x_from_secret(&[0x41u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("alice_out_pk".to_owned()))?;
    let bob_out_pk = pubkey_x_from_secret(&[0x42u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("bob_out_pk".to_owned()))?;
    let carol_out_pk = pubkey_x_from_secret(&[0x43u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("carol_out_pk".to_owned()))?;
    let anchor_pk = pubkey_x_from_secret(&[0x44u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("anchor_pk".to_owned()))?;

    Ok(PartyKeys {
        alice_sk,
        bob_sk,
        carol_sk,
        oracle_sks,
        alice_pk,
        bob_pk,
        carol_pk,
        alice_payout_script: p2tr_script_from_xonly(&alice_out_pk),
        bob_payout_script: p2tr_script_from_xonly(&bob_out_pk),
        carol_payout_script: p2tr_script_from_xonly(&carol_out_pk),
        anchor_script: p2tr_script_from_xonly(&anchor_pk),
    })
}

/// Pre-computes the exact 3 `UTXORef` NUMS `P2TR` funding scripts and satoshi amounts for the
/// 3 bilateral DLCs so a live Bitcoin Core / Testnet harness can fund them on-chain first.
pub fn precompute_three_party_dlc_funding_templates(
    refund_csv: u16,
) -> Result<[DlcFundingTemplate; 3]> {
    let keys = derive_canonical_party_keys()?;
    let anchor_sats = 330u64;
    let miner_fee_sats = 1_000u64;

    let info_1 = derive_funding_taproot_spend_info(&keys.alice_pk, &keys.bob_pk, refund_csv)?;
    let info_2 = derive_funding_taproot_spend_info(&keys.bob_pk, &keys.carol_pk, refund_csv)?;
    let info_3 = derive_funding_taproot_spend_info(&keys.carol_pk, &keys.alice_pk, refund_csv)?;

    Ok([
        DlcFundingTemplate {
            trade_index: 0,
            label: "DLC-1-ALICE-LONG-BOB-SHORT-50K".to_owned(),
            long_party: "Alice".to_owned(),
            short_party: "Bob".to_owned(),
            entry_price_usd: 50_000,
            usd_notional: 33_000,
            long_margin_sats: 33_000_000,
            short_margin_sats: 66_000_000,
            anchor_sats,
            miner_fee_sats,
            total_funding_sats: 99_000_000 + anchor_sats + miner_fee_sats,
            funding_script_pubkey_hex: hex::encode(info_1.funding_script),
        },
        DlcFundingTemplate {
            trade_index: 1,
            label: "DLC-2-BOB-LONG-CAROL-SHORT-55K".to_owned(),
            long_party: "Bob".to_owned(),
            short_party: "Carol".to_owned(),
            entry_price_usd: 55_000,
            usd_notional: 33_000,
            long_margin_sats: 30_000_000,
            short_margin_sats: 60_000_000,
            anchor_sats,
            miner_fee_sats,
            total_funding_sats: 90_000_000 + anchor_sats + miner_fee_sats,
            funding_script_pubkey_hex: hex::encode(info_2.funding_script),
        },
        DlcFundingTemplate {
            trade_index: 2,
            label: "DLC-3-CAROL-LONG-ALICE-SHORT-60K".to_owned(),
            long_party: "Carol".to_owned(),
            short_party: "Alice".to_owned(),
            entry_price_usd: 60_000,
            usd_notional: 33_000,
            long_margin_sats: 27_500_000,
            short_margin_sats: 27_500_000,
            anchor_sats,
            miner_fee_sats,
            total_funding_sats: 55_000_000 + anchor_sats + miner_fee_sats,
            funding_script_pubkey_hex: hex::encode(info_3.funding_script),
        },
    ])
}

/// Executes the full 3-party, 3-trade multilateral DLC collation, `UTXORef` PnL routing,
/// collateral release, Nova v2 folding expectation, Testnet4 BitVM3 statement construction,
/// and BIP-341 Taproot script-path transaction signing.
pub fn build_three_party_clearing_ceremony(
    config: &ThreePartyClearingConfig,
) -> Result<ThreePartyClearingArtifacts> {
    let keys = derive_canonical_party_keys()?;
    let outpoints = config.funding_outpoints.unwrap_or_else(|| {
        [
            (tagged_hash("shz-3party-funding", b"trade-1-ab-50k"), 0),
            (tagged_hash("shz-3party-funding", b"trade-2-bc-55k"), 0),
            (tagged_hash("shz-3party-funding", b"trade-3-ca-60k"), 0),
        ]
    });

    // -------------------------------------------------------------------------
    // 1. Live 3-Trade Zero-Fee P2P Matching across Alice, Bob, and Carol
    // -------------------------------------------------------------------------
    let mut book = ZeroFeeOrderBook::new();
    let policy = OracleSettlementPolicy::FrostBondedWithFallback;
    let usd_notional = 33_000u64;

    // Trade 1 ($50,000): Bob posts 1x Short ($33k -> 66,000,000 sats); Alice takes 2x Long (33,000,000 sats)
    let bob_ask_1 = SignedOrderIntent::new_signed_v0(
        &keys.bob_sk,
        BtcOutPoint {
            txid: outpoints[0].0,
            vout: outpoints[0].1,
        },
        OrderSide::Short,
        usd_notional,
        50_000,
        10_000, // 1.0x covered SatsHedge
        policy,
        1,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("bob_ask_1: {e}")))?;
    assert!(
        book.submit_order(bob_ask_1)
            .map_err(|e| NovaBitvmError::Bridge(format!("submit bob_ask_1: {e}")))?
            .is_empty()
    );

    let alice_bid_1 = SignedOrderIntent::new_signed_v0(
        &keys.alice_sk,
        BtcOutPoint {
            txid: outpoints[0].0,
            vout: outpoints[0].1,
        },
        OrderSide::Long,
        usd_notional,
        50_000,
        20_000, // 2.0x leverage
        policy,
        1,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("alice_bid_1: {e}")))?;
    let mut m1 = book
        .submit_order(alice_bid_1)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit alice_bid_1: {e}")))?;
    let ticket_1 = m1
        .pop()
        .ok_or_else(|| NovaBitvmError::Bridge("Trade 1 failed to match".to_owned()))?;

    // Trade 2 ($55,000): Carol posts 1x Short (60,000,000 sats); Bob takes 2x Long (30,000,000 sats)
    let carol_ask_2 = SignedOrderIntent::new_signed_v0(
        &keys.carol_sk,
        BtcOutPoint {
            txid: outpoints[1].0,
            vout: outpoints[1].1,
        },
        OrderSide::Short,
        usd_notional,
        55_000,
        10_000, // 1.0x covered SatsHedge
        policy,
        1,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("carol_ask_2: {e}")))?;
    assert!(
        book.submit_order(carol_ask_2)
            .map_err(|e| NovaBitvmError::Bridge(format!("submit carol_ask_2: {e}")))?
            .is_empty()
    );

    let bob_bid_2 = SignedOrderIntent::new_signed_v0(
        &keys.bob_sk,
        BtcOutPoint {
            txid: outpoints[1].0,
            vout: outpoints[1].1,
        },
        OrderSide::Long,
        usd_notional,
        55_000,
        20_000, // 2.0x leverage
        policy,
        2,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("bob_bid_2: {e}")))?;
    let mut m2 = book
        .submit_order(bob_bid_2)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit bob_bid_2: {e}")))?;
    let ticket_2 = m2
        .pop()
        .ok_or_else(|| NovaBitvmError::Bridge("Trade 2 failed to match".to_owned()))?;

    // Trade 3 ($60,000): Alice closes her winning position by posting 2x Short (27,500,000 sats);
    // Carol flattens her Short by taking 2x Long (27,500,000 sats).
    let alice_ask_3 = SignedOrderIntent::new_signed_v0(
        &keys.alice_sk,
        BtcOutPoint {
            txid: outpoints[2].0,
            vout: outpoints[2].1,
        },
        OrderSide::Short,
        usd_notional,
        60_000,
        20_000, // 2.0x leverage
        policy,
        2,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("alice_ask_3: {e}")))?;
    assert!(
        book.submit_order(alice_ask_3)
            .map_err(|e| NovaBitvmError::Bridge(format!("submit alice_ask_3: {e}")))?
            .is_empty()
    );

    let carol_bid_3 = SignedOrderIntent::new_signed_v0(
        &keys.carol_sk,
        BtcOutPoint {
            txid: outpoints[2].0,
            vout: outpoints[2].1,
        },
        OrderSide::Long,
        usd_notional,
        60_000,
        20_000, // 2.0x leverage
        policy,
        2,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("carol_bid_3: {e}")))?;
    let mut m3 = book
        .submit_order(carol_bid_3)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit carol_bid_3: {e}")))?;
    let ticket_3 = m3
        .pop()
        .ok_or_else(|| NovaBitvmError::Bridge("Trade 3 failed to match".to_owned()))?;

    // -------------------------------------------------------------------------
    // 2. 3-of-5 FROST Threshold Oracle Attestation at Clearing Mark $60,000
    // -------------------------------------------------------------------------
    let clearing_mark_price_usd = 60_000u64;
    let frost_confed = FrostConfederation::keygen_deterministic(3, 5, &[0x77u8; 32])
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST keygen: {e}")))?;
    let frost_event = frost_confed
        .announce_event(
            "SHZ-TESTNET4-3PARTY-CLEARING-60K",
            1_795_422_300,
            20,
            &[0x88u8; 32],
        )
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST announce: {e}")))?;
    let frost_quorum = [1u16, 3, 5];
    let frost_att = frost_confed
        .threshold_attest_price(&frost_event, &frost_quorum, 1_795_422_360, clearing_mark_price_usd)
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST attest: {e}")))?;
    frost_att
        .verify_against(&frost_event.announcement)
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST verify: {e}")))?;

    // -------------------------------------------------------------------------
    // 3. Collate All 3 Signed DLCs into One Canonical LNMBAT01 BatchWitness
    // -------------------------------------------------------------------------
    let outcome_grid = vec![45_000u64, 50_000, 55_000, 60_000, 65_000];
    let selected_idx = 3usize; // $60,000 clearing price
    let anchor_sats = 330u64;
    let fee_sats = 1_000u64;
    let shared_event_id = tagged_hash("shz-testnet4-clearing-event", b"SHZ-3PARTY-60K");

    let signers_1 = BridgeSignerMaterial {
        trader_sk: keys.alice_sk, // Long
        maker_sk: keys.bob_sk,    // Short
        oracle_sks: keys.oracle_sks,
        trader_script: keys.alice_payout_script,
        maker_script: keys.bob_payout_script,
        anchor_script: keys.anchor_script,
    };
    let signers_2 = BridgeSignerMaterial {
        trader_sk: keys.bob_sk,   // Long
        maker_sk: keys.carol_sk,  // Short
        oracle_sks: keys.oracle_sks,
        trader_script: keys.bob_payout_script,
        maker_script: keys.carol_payout_script,
        anchor_script: keys.anchor_script,
    };
    let signers_3 = BridgeSignerMaterial {
        trader_sk: keys.carol_sk, // Long
        maker_sk: keys.alice_sk,  // Short
        oracle_sks: keys.oracle_sks,
        trader_script: keys.carol_payout_script,
        maker_script: keys.alice_payout_script,
        anchor_script: keys.anchor_script,
    };

    let mut bspec_1 = ShzDlcBridgeSpec::from_matched_ticket(
        &ticket_1,
        outcome_grid.clone(),
        selected_idx,
        anchor_sats,
        fee_sats,
        config.maturity_height,
        config.refund_height,
        config.refund_csv,
        shared_event_id,
    );
    bspec_1.funding_txid = outpoints[0].0;
    bspec_1.funding_vout = outpoints[0].1;

    let mut bspec_2 = ShzDlcBridgeSpec::from_matched_ticket(
        &ticket_2,
        outcome_grid.clone(),
        selected_idx,
        anchor_sats,
        fee_sats,
        config.maturity_height,
        config.refund_height,
        config.refund_csv,
        shared_event_id,
    );
    bspec_2.funding_txid = outpoints[1].0;
    bspec_2.funding_vout = outpoints[1].1;

    let mut bspec_3 = ShzDlcBridgeSpec::from_matched_ticket(
        &ticket_3,
        outcome_grid,
        selected_idx,
        anchor_sats,
        fee_sats,
        config.maturity_height,
        config.refund_height,
        config.refund_csv,
        shared_event_id,
    );
    bspec_3.funding_txid = outpoints[2].0;
    bspec_3.funding_vout = outpoints[2].1;

    let row_1 = build_unsigned_row_from_shz_dlc(&bspec_1, &signers_1)?;
    let row_2 = build_unsigned_row_from_shz_dlc(&bspec_2, &signers_2)?;
    let row_3 = build_unsigned_row_from_shz_dlc(&bspec_3, &signers_3)?;

    let bilateral_1 = (row_1.outcome.trader_sats, row_1.outcome.maker_sats);
    let bilateral_2 = (row_2.outcome.trader_sats, row_2.outcome.maker_sats);
    let bilateral_3 = (row_3.outcome.trader_sats, row_3.outcome.maker_sats);

    // Verify exact bilateral payouts ($33k inverse @ $50k/$55k/$60k settled @ $60k):
    // Trade 1: Alice 44,000,000 (+11M PnL), Bob 55,000,000 (-11M PnL)
    // Trade 2: Bob   35,000,000 (+5M PnL),  Carol 55,000,000 (-5M PnL)
    // Trade 3: Carol 27,500,000 (0 PnL),    Alice 27,500,000 (0 PnL)
    if bilateral_1 != (44_000_000, 55_000_000)
        || bilateral_2 != (35_000_000, 55_000_000)
        || bilateral_3 != (27_500_000, 27_500_000)
    {
        return Err(NovaBitvmError::Bridge(
            "unexpected bilateral inverse DLC payout split at $60,000".to_owned(),
        ));
    }

    let mut nullifier_tree = SparseNullifierTree::new();
    let batch_id = tagged_hash(
        "shz-testnet4-3party-batch",
        &config.testnet4_anchor_height.to_le_bytes(),
    );
    let (batch, journal) = assemble_and_sign_bridged_batch(
        vec![
            (row_1.clone(), signers_1),
            (row_2.clone(), signers_2),
            (row_3.clone(), signers_3),
        ],
        &mut nullifier_tree,
        config.testnet4_anchor_height,
        batch_id,
        config.evaluation_height,
        config.valid_until_height,
    )?;

    let batch_witness_bytes = encode_batch(&batch)?;
    let decoded_check = decode_batch(&batch_witness_bytes)?;
    if verify_batch(&decoded_check)? != journal {
        return Err(NovaBitvmError::Bridge(
            "3-party LNMBAT01 roundtrip journal mismatch".to_owned(),
        ));
    }

    // -------------------------------------------------------------------------
    // 4. Sign Exact Atomic 3-Input, 4-Output BIP-341 Taproot Clearing SegwitTx
    // -------------------------------------------------------------------------
    let signed_clearing_tx = sign_atomic_batch_segwit_tx(&batch, &keys, config.refund_csv)?;
    let unsigned_ref = unsigned_batch_transaction(&batch.rows)?;
    if signed_clearing_tx.serialize_unsigned() != unsigned_ref {
        return Err(NovaBitvmError::Bridge(
            "SegwitTx unsigned bytes differ from canonical unsigned_batch_transaction".to_owned(),
        ));
    }
    if signed_clearing_tx.txid_hex() != hex::encode(journal.batch_txid) {
        return Err(NovaBitvmError::Bridge(
            "SegwitTx txid differs from LNMJNL01 journal.batch_txid".to_owned(),
        ));
    }

    // -------------------------------------------------------------------------
    // 5. UTXORef Capacitated PnL Routing & Collateral Release Verification
    // -------------------------------------------------------------------------
    let utxoref_pnl_clearing = verify_utxoref_three_party_clearing_and_book(
        &keys,
        &outpoints,
        &signed_clearing_tx,
    )?;

    // -------------------------------------------------------------------------
    // 6. Nova v2 600B Transcripts, 18 Secq Claims & 304B Testnet4 BitVM3 Statement
    // -------------------------------------------------------------------------
    let (_, transcripts, mut nova_expected_statement) =
        NovaExpectedStatement::from_verified_batch(&batch)?;
    nova_expected_statement.verifier_key_pin_hex = Some(LNM_NOVA_V2_VK_SHA256_HEX.to_owned());
    let row_transcripts_600b_hex: Vec<String> = transcripts
        .iter()
        .map(|t| {
            debug_assert_eq!(t.len(), NOVA_TRANSCRIPT_LEN);
            hex::encode(t)
        })
        .collect();

    let mut secq_claims_verified_count = 0usize;
    for r in &batch.rows {
        let claims: [SecqBip340Claim; 6] = build_and_verify_all_6_row_claims(&batch.context, r)?;
        secq_claims_verified_count += claims.len();
    }

    let testnet4_genesis: Hash = hex::decode(BITCOIN_TESTNET4_GENESIS_HASH_HEX)
        .expect("valid Testnet4 genesis hex")
        .try_into()
        .expect("32B");
    let vk_pin_bytes: Hash = hex::decode(LNM_NOVA_V2_VK_SHA256_HEX)
        .expect("valid lnm-nova vk hex")
        .try_into()
        .expect("32B");
    let anchor_tip_bytes: Hash = hex::decode(&config.testnet4_anchor_block_hash_hex)
        .map_err(|_| NovaBitvmError::BitVm3("invalid testnet4_anchor_block_hash_hex".to_owned()))?
        .try_into()
        .map_err(|_| {
            NovaBitvmError::BitVm3("testnet4_anchor_block_hash_hex must be 32 bytes".to_owned())
        })?;

    let mut policy_preimage = Vec::with_capacity(64);
    policy_preimage.extend_from_slice(&statement_domain());
    policy_preimage.extend_from_slice(&anchor_tip_bytes);
    let policy_hash = tagged_hash("shz-testnet4-clearing-policy", &policy_preimage);
    let program_hash = tagged_hash(
        "shz-nova-program",
        b"lnmarkets/sha256-transcript-accounting/v2",
    );

    let bitvm3_stmt = build_bitvm3_settlement_statement(
        BitcoinNetworkCode::Testnet4,
        testnet4_genesis,
        &batch.rows[0],
        &journal,
        batch.rows[0].summary.funding_txid,
        batch.rows[0].summary.funding_vout,
        program_hash,
        vk_pin_bytes,
        policy_hash,
    )?;

    let trades = [
        ExecutedClearingTrade {
            trade_no: 1,
            label: "Trade 1: Alice Long $33k vs Bob 1x Short $33k @ $50,000".to_owned(),
            match_id_hex: hex::encode(ticket_1.match_id),
            execution_price_usd: 50_000,
            clearing_mark_price_usd,
            usd_notional,
            long_party: "Alice".to_owned(),
            short_party: "Bob".to_owned(),
            long_margin_sats: 33_000_000,
            short_margin_sats: 66_000_000,
            protocol_fee_sats: 0,
            funding_txid_hex: hex::encode(outpoints[0].0),
            funding_vout: outpoints[0].1,
            funding_script_pubkey_hex: hex::encode(row_1.summary.funding_script),
            total_utxo_sats: row_1.summary.collateral_sats,
            bilateral_long_payout_sats: bilateral_1.0,
            bilateral_short_payout_sats: bilateral_1.1,
            bilateral_realized_long_pnl_sats: 11_000_000,
        },
        ExecutedClearingTrade {
            trade_no: 2,
            label: "Trade 2: Bob Long $33k vs Carol 1x Short $33k @ $55,000 (Bob Flattens Delta)"
                .to_owned(),
            match_id_hex: hex::encode(ticket_2.match_id),
            execution_price_usd: 55_000,
            clearing_mark_price_usd,
            usd_notional,
            long_party: "Bob".to_owned(),
            short_party: "Carol".to_owned(),
            long_margin_sats: 30_000_000,
            short_margin_sats: 60_000_000,
            protocol_fee_sats: 0,
            funding_txid_hex: hex::encode(outpoints[1].0),
            funding_vout: outpoints[1].1,
            funding_script_pubkey_hex: hex::encode(row_2.summary.funding_script),
            total_utxo_sats: row_2.summary.collateral_sats,
            bilateral_long_payout_sats: bilateral_2.0,
            bilateral_short_payout_sats: bilateral_2.1,
            bilateral_realized_long_pnl_sats: 5_000_000,
        },
        ExecutedClearingTrade {
            trade_no: 3,
            label: "Trade 3: Carol Long $33k vs Alice Short $33k @ $60,000 (Winner Alice Closes)"
                .to_owned(),
            match_id_hex: hex::encode(ticket_3.match_id),
            execution_price_usd: 60_000,
            clearing_mark_price_usd,
            usd_notional,
            long_party: "Carol".to_owned(),
            short_party: "Alice".to_owned(),
            long_margin_sats: 27_500_000,
            short_margin_sats: 27_500_000,
            protocol_fee_sats: 0,
            funding_txid_hex: hex::encode(outpoints[2].0),
            funding_vout: outpoints[2].1,
            funding_script_pubkey_hex: hex::encode(row_3.summary.funding_script),
            total_utxo_sats: row_3.summary.collateral_sats,
            bilateral_long_payout_sats: bilateral_3.0,
            bilateral_short_payout_sats: bilateral_3.1,
            bilateral_realized_long_pnl_sats: 0,
        },
    ];

    let party_accounting = [
        PartyClearingAccounting {
            party: "Alice".to_owned(),
            role: "Winner (Opened Long @ $50k, Closed on 3rd Trade @ $60k)".to_owned(),
            net_usd_delta_after_trade3: 0,
            total_posted_margin_sats: 60_500_000,
            net_realized_pnl_sats: 11_000_000,
            freed_collateral_returned_sats: 60_500_000,
            routed_pnl_received_sats: 11_000_000,
            final_cleared_payout_sats: 71_500_000,
            payout_script_pubkey_hex: hex::encode(keys.alice_payout_script),
        },
        PartyClearingAccounting {
            party: "Bob".to_owned(),
            role: "Loser (Short @ $50k, Flattened @ $55k; 93.75% Margin Freed)".to_owned(),
            net_usd_delta_after_trade3: 0,
            total_posted_margin_sats: 96_000_000,
            net_realized_pnl_sats: -6_000_000,
            freed_collateral_returned_sats: 90_000_000,
            routed_pnl_received_sats: 0,
            final_cleared_payout_sats: 90_000_000,
            payout_script_pubkey_hex: hex::encode(keys.bob_payout_script),
        },
        PartyClearingAccounting {
            party: "Carol".to_owned(),
            role: "Market-Maker (Short @ $55k, Closed @ $60k; Remaining Margin Freed)".to_owned(),
            net_usd_delta_after_trade3: 0,
            total_posted_margin_sats: 87_500_000,
            net_realized_pnl_sats: -5_000_000,
            freed_collateral_returned_sats: 82_500_000,
            routed_pnl_received_sats: 0,
            final_cleared_payout_sats: 82_500_000,
            payout_script_pubkey_hex: hex::encode(keys.carol_payout_script),
        },
    ];

    let atomic_outputs_sats: Vec<u64> = signed_clearing_tx.outputs.iter().map(|(v, _)| *v).collect();
    let report = ThreePartyClearingReport {
        protocol: "SatsHedgeZero 3-Party Multilateral DLC + BitVM3 Nova Clearing v0.3.0".to_owned(),
        network: "bitcoin-testnet4".to_owned(),
        testnet4_anchor_height: config.testnet4_anchor_height,
        testnet4_anchor_block_hash_hex: config.testnet4_anchor_block_hash_hex.clone(),
        clearing_mark_price_usd,
        frost_quorum_signers: frost_quorum,
        frost_group_pubkey_x_hex: hex::encode(frost_confed.group_pubkey_x),
        trades,
        party_accounting,
        utxoref_pnl_clearing,
        batch_witness_bytes_len: batch_witness_bytes.len(),
        journal: JournalSummaryJson::from_journal(&journal),
        row_transcripts_600b_hex,
        nova_expected_statement,
        secq_claims_verified_count,
        bitvm3_testnet4_statement: bitvm3_stmt.to_json_record(),
        atomic_clearing_txid_hex: signed_clearing_tx.txid_hex(),
        atomic_clearing_wtxid_hex: signed_clearing_tx.wtxid_hex(),
        atomic_clearing_vsize: signed_clearing_tx.vsize(),
        atomic_clearing_outputs_sats: atomic_outputs_sats,
        atomic_clearing_raw_segwit_tx_hex: hex::encode(signed_clearing_tx.serialize_segwit()),
        external_nova_snark_receipt: None,
        honesty: VerificationHonestyFlags::native_only(),
    };

    Ok(ThreePartyClearingArtifacts {
        batch_witness: batch,
        batch_witness_bytes,
        journal,
        signed_clearing_tx,
        report,
    })
}

fn secret_for_pubkey<'a>(keys: &'a PartyKeys, pubkey_x: &Hash) -> Result<&'a [u8; 32]> {
    if *pubkey_x == keys.alice_pk {
        Ok(&keys.alice_sk)
    } else if *pubkey_x == keys.bob_pk {
        Ok(&keys.bob_sk)
    } else if *pubkey_x == keys.carol_pk {
        Ok(&keys.carol_sk)
    } else {
        Err(NovaBitvmError::Bridge(
            "unknown party pubkey in 3-party clearing batch".to_owned(),
        ))
    }
}

fn sign_atomic_batch_segwit_tx(
    batch: &BatchWitness,
    keys: &PartyKeys,
    refund_csv: u16,
) -> Result<SegwitTx> {
    let mut outputs_map = BTreeMap::<Script, u64>::new();
    let mut maturity = 0u32;
    let mut inputs = Vec::with_capacity(batch.rows.len());
    let mut spend_infos: Vec<FundingTaprootSpendInfo> = Vec::with_capacity(batch.rows.len());

    for row in &batch.rows {
        maturity = maturity.max(row.summary.maturity_height);
        for (script, val) in [
            (row.summary.trader_script, row.outcome.trader_sats),
            (row.summary.maker_script, row.outcome.maker_sats),
            (row.summary.anchor_script, row.outcome.anchor_sats),
        ] {
            *outputs_map.entry(script).or_insert(0) += val;
        }

        let info = derive_funding_taproot_spend_info(
            &row.summary.trader_key,
            &row.summary.maker_key,
            refund_csv,
        )?;
        let txid_hex = hex::encode(row.summary.funding_txid);
        let inp = SegwitTxIn::from_display_txid(
            &txid_hex,
            row.summary.funding_vout,
            0xfffffffd, // matches `unsigned_batch_transaction` exact nSequence
            row.summary.collateral_sats,
            info.funding_script.to_vec(),
        )
        .map_err(|e| NovaBitvmError::Bridge(format!("SegwitTxIn: {e}")))?;
        inputs.push(inp);
        spend_infos.push(info);
    }

    let outputs: Vec<(u64, Vec<u8>)> = outputs_map
        .into_iter()
        .map(|(script, val)| (val, script.to_vec()))
        .collect();

    let mut tx = SegwitTx {
        version: 2,
        inputs,
        outputs,
        locktime: maturity,
    };

    for (idx, info) in spend_infos.iter().enumerate() {
        let sighash = tx
            .bip341_sighash(idx, SIGHASH_DEFAULT, Some(&info.cet_leaf_hash))
            .map_err(|e| NovaBitvmError::Bridge(format!("bip341_sighash input {idx}: {e}")))?;

        let sk_0 = secret_for_pubkey(keys, &info.sorted_party_keys[0])?;
        let sk_1 = secret_for_pubkey(keys, &info.sorted_party_keys[1])?;

        let sig_0 = bip340_sign(sk_0, &sighash)
            .map_err(|e| NovaBitvmError::Signature(format!("bip340_sign pk0: {e}")))?;
        let sig_1 = bip340_sign(sk_1, &sighash)
            .map_err(|e| NovaBitvmError::Signature(format!("bip340_sign pk1: {e}")))?;

        bip340_verify(&info.sorted_party_keys[0], &sighash, &sig_0)
            .map_err(|e| NovaBitvmError::Signature(format!("bip340_verify pk0: {e}")))?;
        bip340_verify(&info.sorted_party_keys[1], &sighash, &sig_1)
            .map_err(|e| NovaBitvmError::Signature(format!("bip340_verify pk1: {e}")))?;

        // `<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG` consumes `sig_0` first (top of stack),
        // then `sig_1` below it.
        tx.inputs[idx].witness = vec![
            encode_taproot_witness_sig(&sig_1, SIGHASH_DEFAULT),
            encode_taproot_witness_sig(&sig_0, SIGHASH_DEFAULT),
            info.cet_script.clone(),
            info.cet_control_block.clone(),
        ];
    }

    Ok(tx)
}

fn verify_utxoref_three_party_clearing_and_book(
    keys: &PartyKeys,
    outpoints: &[(Hash, u32); 3],
    signed_tx: &SegwitTx,
) -> Result<UtxoRefClearingSummary> {
    let set_id = "shz-testnet4-btc-inverse".to_owned();
    let genesis_root = tagged_hash("shz-utxoref-genesis", b"testnet4-3party-epoch0");

    // Model each party's posted collateral across the 3 trades:
    // - Alice posted 33,000,000 (T1) + 27,500,000 (T3) = 60,500,000 sats, withdraws full 71,500,000 sats
    //   on closeout (`payout_sats = 71,500,000`, `vault_alice` routes its 60,500,000 + Bob 6M + Carol 5M).
    // - Bob posted 66,000,000 (T1) + 30,000,000 (T2) = 96,000,000 sats (`locked_sats = 0` once flattened!).
    // - Carol posted 60,000,000 (T2) + 27,500,000 (T3) = 87,500,000 sats (`locked_sats = 0` once flattened!).
    let snapshot = PnlBatchSnapshotV1 {
        network: "bitcoin-testnet4".to_owned(),
        epoch_id: 1,
        previous_state_root: genesis_root,
        netting_sets: vec![NettingSetSpec {
            id: set_id.clone(),
            collateral: CollateralAsset::VanillaBtc,
        }],
        vaults: vec![
            VaultRecord {
                id: "vault_alice".to_owned(),
                netting_set_id: set_id.clone(),
                change_script_pubkey: keys.alice_payout_script.to_vec(),
                fee_sats: 1_000,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: outpoints[0].0,
                        vout: outpoints[0].1,
                    },
                    sats: 60_501_000,
                    script_pubkey: keys.alice_payout_script.to_vec(),
                }],
            },
            VaultRecord {
                id: "vault_bob".to_owned(),
                netting_set_id: set_id.clone(),
                change_script_pubkey: keys.bob_payout_script.to_vec(),
                fee_sats: 1_000,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: outpoints[1].0,
                        vout: outpoints[1].1,
                    },
                    sats: 96_001_000,
                    script_pubkey: keys.bob_payout_script.to_vec(),
                }],
            },
            VaultRecord {
                id: "vault_carol".to_owned(),
                netting_set_id: set_id.clone(),
                change_script_pubkey: keys.carol_payout_script.to_vec(),
                fee_sats: 1_000,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: outpoints[2].0,
                        vout: outpoints[2].1,
                    },
                    sats: 87_501_000,
                    script_pubkey: keys.carol_payout_script.to_vec(),
                }],
            },
        ],
        accounts: vec![
            AccountRecord {
                id: "alice".to_owned(),
                netting_set_id: set_id.clone(),
                vault_id: "vault_alice".to_owned(),
                equity_sats: 60_500_000,
                locked_sats: 0, // Closed on Trade 3 -> 60,500,000 principal freed in vault_alice!
                payout_sats: 11_000_000, // Exact +11,000,000 net PnL routed from Bob (6M) + Carol (5M)!
                payout_script_pubkey: Some(keys.alice_payout_script.to_vec()),
            },
            AccountRecord {
                id: "bob".to_owned(),
                netting_set_id: set_id.clone(),
                vault_id: "vault_bob".to_owned(),
                equity_sats: 96_000_000,
                locked_sats: 0, // Flattened delta -> remaining 90,000,000 sats collateral is FREED!
                payout_sats: 0,
                payout_script_pubkey: None,
            },
            AccountRecord {
                id: "carol".to_owned(),
                netting_set_id: set_id.clone(),
                vault_id: "vault_carol".to_owned(),
                equity_sats: 87_500_000,
                locked_sats: 0, // Flattened delta -> remaining 82,500,000 sats collateral is FREED!
                payout_sats: 0,
                payout_script_pubkey: None,
            },
        ],
        obligations: vec![
            RealizedObligation {
                id: "trade1-bob-to-alice-50k-to-60k".to_owned(),
                netting_set_id: set_id.clone(),
                from_account_id: "bob".to_owned(),
                to_account_id: "alice".to_owned(),
                sats: 11_000_000,
            },
            RealizedObligation {
                id: "trade2-carol-to-bob-55k-to-60k".to_owned(),
                netting_set_id: set_id,
                from_account_id: "carol".to_owned(),
                to_account_id: "bob".to_owned(),
                sats: 5_000_000,
            },
        ],
        consumed_obligation_ids: Vec::new(),
        spent_outpoints: Vec::new(),
        routes: vec![
            PermittedRoute {
                from_vault_id: "vault_alice".to_owned(),
                to_target: RouteTarget::Payout("alice".to_owned()),
                capacity_sats: 60_500_000,
            },
            PermittedRoute {
                from_vault_id: "vault_bob".to_owned(),
                to_target: RouteTarget::Payout("alice".to_owned()),
                capacity_sats: 96_000_000,
            },
            PermittedRoute {
                from_vault_id: "vault_carol".to_owned(),
                to_target: RouteTarget::Payout("alice".to_owned()),
                capacity_sats: 87_500_000,
            },
        ],
    };

    let snap_hash = snapshot.snapshot_hash();
    let solved = solve_and_verify_pnl_batch(&snapshot, &snap_hash)
        .map_err(|e| NovaBitvmError::Bridge(format!("solve_and_verify_pnl_batch: {e}")))?;

    let alice_freed_principal = solved
        .vault_residuals_sats
        .get("vault_alice")
        .copied()
        .unwrap_or(0);
    let bob_freed = solved
        .vault_residuals_sats
        .get("vault_bob")
        .copied()
        .unwrap_or(0);
    let carol_freed = solved
        .vault_residuals_sats
        .get("vault_carol")
        .copied()
        .unwrap_or(0);
    let alice_routed_pnl = solved
        .direct_payouts_sats
        .get("alice")
        .copied()
        .unwrap_or(0);
    let alice_payout = alice_freed_principal + alice_routed_pnl;

    let mut bob_to_alice = 0u64;
    let mut carol_to_alice = 0u64;
    for (src, target, sats) in &solved.route_allocations {
        if *target == RouteTarget::Payout("alice".to_owned()) {
            if src == "vault_bob" {
                bob_to_alice += sats;
            } else if src == "vault_carol" {
                carol_to_alice += sats;
            }
        }
    }

    if bob_freed != 90_000_000
        || carol_freed != 82_500_000
        || alice_payout != 71_500_000
        || bob_to_alice != 6_000_000
        || carol_to_alice != 5_000_000
    {
        return Err(NovaBitvmError::Bridge(format!(
            "unexpected PnL clearing allocation: alice={alice_payout}, bob_freed={bob_freed}, carol_freed={carol_freed}, bob->alice={bob_to_alice}, carol->alice={carol_to_alice}"
        )));
    }

    // Exercise DurablePnlBatchBook: Ready -> ReservedBeforeSigning -> Signed -> Ready (epoch 1)
    let mut durable_book = DurablePnlBatchBook::new_genesis("shz-testnet4-clearing-book", genesis_root);
    let head0 = durable_book.head_hash;
    let head1 = durable_book
        .reserve_before_signing(&head0, &snapshot)
        .map_err(|e| NovaBitvmError::Bridge(format!("reserve_before_signing: {e}")))?;
    let head2 = durable_book
        .record_signed_outcome(
            &head1,
            Ok((signed_tx.txid_hex(), signed_tx.serialize_segwit())),
        )
        .map_err(|e| NovaBitvmError::Bridge(format!("record_signed_outcome: {e}")))?;
    let head3 = durable_book
        .confirm_active_chain(&head2, &signed_tx.txid_hex(), &snapshot)
        .map_err(|e| NovaBitvmError::Bridge(format!("confirm_active_chain: {e}")))?;

    Ok(UtxoRefClearingSummary {
        snapshot_hash_hex: hex::encode(snap_hash),
        next_accounting_state_root_hex: hex::encode(solved.next_accounting_state_root),
        durable_book_final_head_hash_hex: hex::encode(head3),
        durable_book_settled_epoch: durable_book.last_settled_epoch,
        bob_to_alice_routed_pnl_sats: bob_to_alice,
        carol_to_alice_routed_pnl_sats: carol_to_alice,
        total_winner_routed_pnl_sats: bob_to_alice + carol_to_alice,
        bob_locked_margin_before_clearing_sats: 96_000_000,
        bob_freed_collateral_sats: bob_freed,
        bob_freed_collateral_bps: (bob_freed * 10_000) / 96_000_000,
        carol_freed_collateral_sats: carol_freed,
        alice_total_cleared_payout_sats: alice_payout,
    })
}

/// Pre-computes the 3 `UTXORef` NUMS `P2TR` funding scripts and exact `$1`-notional satoshi amounts
/// (`2,095`, `1,595`, `1,270` sats; total `4,960` sats) for live public Bitcoin Testnet4 broadcast
/// (`$80,000` -> `$100,000` -> `$125,000` clearing mark).
pub fn precompute_live_testnet4_micro_dlc_templates(
    refund_csv: u16,
) -> Result<[DlcFundingTemplate; 3]> {
    let keys = derive_canonical_party_keys()?;
    let anchor_sats = 330u64;
    let miner_fee_sats = 140u64;

    let info_1 = derive_funding_taproot_spend_info(&keys.alice_pk, &keys.bob_pk, refund_csv)?;
    let info_2 = derive_funding_taproot_spend_info(&keys.bob_pk, &keys.carol_pk, refund_csv)?;
    let info_3 = derive_funding_taproot_spend_info(&keys.carol_pk, &keys.alice_pk, refund_csv)?;

    Ok([
        DlcFundingTemplate {
            trade_index: 0,
            label: "DLC-1-TESTNET4-ALICE-LONG-BOB-SHORT-80K".to_owned(),
            long_party: "Alice".to_owned(),
            short_party: "Bob".to_owned(),
            entry_price_usd: 80_000,
            usd_notional: 1,
            long_margin_sats: 625,
            short_margin_sats: 1_000,
            anchor_sats,
            miner_fee_sats,
            total_funding_sats: 1_625 + anchor_sats + miner_fee_sats, // 2,095 sats
            funding_script_pubkey_hex: hex::encode(info_1.funding_script),
        },
        DlcFundingTemplate {
            trade_index: 1,
            label: "DLC-2-TESTNET4-BOB-LONG-CAROL-SHORT-100K".to_owned(),
            long_party: "Bob".to_owned(),
            short_party: "Carol".to_owned(),
            entry_price_usd: 100_000,
            usd_notional: 1,
            long_margin_sats: 500,
            short_margin_sats: 625,
            anchor_sats,
            miner_fee_sats,
            total_funding_sats: 1_125 + anchor_sats + miner_fee_sats, // 1,595 sats
            funding_script_pubkey_hex: hex::encode(info_2.funding_script),
        },
        DlcFundingTemplate {
            trade_index: 2,
            label: "DLC-3-TESTNET4-CAROL-LONG-ALICE-SHORT-125K".to_owned(),
            long_party: "Carol".to_owned(),
            short_party: "Alice".to_owned(),
            entry_price_usd: 125_000,
            usd_notional: 1,
            long_margin_sats: 400,
            short_margin_sats: 400,
            anchor_sats,
            miner_fee_sats,
            total_funding_sats: 800 + anchor_sats + miner_fee_sats, // 1,270 sats
            funding_script_pubkey_hex: hex::encode(info_3.funding_script),
        },
    ])
}

/// Builds and signs the live public Bitcoin Testnet4 `$1`-notional 3-party, 3-trade clearing batch
/// (`$80,000` -> `$100,000` -> `$125,000`) routing `+450` sats realized PnL (`250` Bob + `200` Carol)
/// to Winner Alice (`1,475` sats total) while freeing `1,250` sats (`83.33%`) of Loser Bob's margin
/// and `825` sats of Carol's margin directly to the supplied `P2TR` payout scripts.
#[allow(clippy::too_many_arguments)]
pub fn build_live_testnet4_micro_clearing_ceremony(
    funding_outpoints: [(Hash, u32); 3],
    payout_scripts: [Script; 4], // [alice_script, bob_script, carol_script, anchor_script]
    tip_height: u32,
    tip_block_hash_hex: &str,
    refund_csv: u16,
) -> Result<ThreePartyClearingArtifacts> {
    let mut keys = derive_canonical_party_keys()?;
    keys.alice_payout_script = payout_scripts[0];
    keys.bob_payout_script = payout_scripts[1];
    keys.carol_payout_script = payout_scripts[2];
    keys.anchor_script = payout_scripts[3];

    let mut book = ZeroFeeOrderBook::new();
    let policy = OracleSettlementPolicy::FrostBondedWithFallback;

    // Trade 1 ($80,000): Bob Short $1 (1.25x = 1,000 sats) vs Alice Long $1 (2x = 625 sats)
    let bob_ask_1 = SignedOrderIntent::new_signed_v0(
        &keys.bob_sk,
        BtcOutPoint {
            txid: funding_outpoints[0].0,
            vout: funding_outpoints[0].1,
        },
        OrderSide::Short,
        1,
        80_000,
        12_500,
        policy,
        101,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("micro bob_ask_1: {e}")))?;
    book.submit_order(bob_ask_1)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit micro bob_ask_1: {e}")))?;
    let alice_bid_1 = SignedOrderIntent::new_signed_v0(
        &keys.alice_sk,
        BtcOutPoint {
            txid: funding_outpoints[0].0,
            vout: funding_outpoints[0].1,
        },
        OrderSide::Long,
        1,
        80_000,
        20_000,
        policy,
        101,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("micro alice_bid_1: {e}")))?;
    let ticket_1 = book
        .submit_order(alice_bid_1)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit micro alice_bid_1: {e}")))?
        .pop()
        .ok_or_else(|| NovaBitvmError::Bridge("micro Trade 1 match".to_owned()))?;

    // Trade 2 ($100,000): Carol Short $1 (1.6x = 625 sats) vs Bob Long $1 (2x = 500 sats)
    let carol_ask_2 = SignedOrderIntent::new_signed_v0(
        &keys.carol_sk,
        BtcOutPoint {
            txid: funding_outpoints[1].0,
            vout: funding_outpoints[1].1,
        },
        OrderSide::Short,
        1,
        100_000,
        16_000,
        policy,
        101,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("micro carol_ask_2: {e}")))?;
    book.submit_order(carol_ask_2)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit micro carol_ask_2: {e}")))?;
    let bob_bid_2 = SignedOrderIntent::new_signed_v0(
        &keys.bob_sk,
        BtcOutPoint {
            txid: funding_outpoints[1].0,
            vout: funding_outpoints[1].1,
        },
        OrderSide::Long,
        1,
        100_000,
        20_000,
        policy,
        102,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("micro bob_bid_2: {e}")))?;
    let ticket_2 = book
        .submit_order(bob_bid_2)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit micro bob_bid_2: {e}")))?
        .pop()
        .ok_or_else(|| NovaBitvmError::Bridge("micro Trade 2 match".to_owned()))?;

    // Trade 3 ($125,000): Alice Short $1 (2x = 400 sats) vs Carol Long $1 (2x = 400 sats)
    let alice_ask_3 = SignedOrderIntent::new_signed_v0(
        &keys.alice_sk,
        BtcOutPoint {
            txid: funding_outpoints[2].0,
            vout: funding_outpoints[2].1,
        },
        OrderSide::Short,
        1,
        125_000,
        20_000,
        policy,
        102,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("micro alice_ask_3: {e}")))?;
    book.submit_order(alice_ask_3)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit micro alice_ask_3: {e}")))?;
    let carol_bid_3 = SignedOrderIntent::new_signed_v0(
        &keys.carol_sk,
        BtcOutPoint {
            txid: funding_outpoints[2].0,
            vout: funding_outpoints[2].1,
        },
        OrderSide::Long,
        1,
        125_000,
        20_000,
        policy,
        102,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("micro carol_bid_3: {e}")))?;
    let ticket_3 = book
        .submit_order(carol_bid_3)
        .map_err(|e| NovaBitvmError::Bridge(format!("submit micro carol_bid_3: {e}")))?
        .pop()
        .ok_or_else(|| NovaBitvmError::Bridge("micro Trade 3 match".to_owned()))?;

    let clearing_mark_price_usd = 125_000u64;
    let frost_confed = FrostConfederation::keygen_deterministic(3, 5, &[0x77u8; 32])
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST keygen: {e}")))?;
    let frost_event = frost_confed
        .announce_event(
            "SHZ-LIVE-TESTNET4-3PARTY-CLEARING-125K",
            1_795_422_300,
            20,
            &[0x89u8; 32],
        )
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST announce: {e}")))?;
    let frost_quorum = [1u16, 3, 5];
    let frost_att = frost_confed
        .threshold_attest_price(
            &frost_event,
            &frost_quorum,
            1_795_422_360,
            clearing_mark_price_usd,
        )
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST attest: {e}")))?;
    frost_att
        .verify_against(&frost_event.announcement)
        .map_err(|e| NovaBitvmError::Bridge(format!("FROST verify: {e}")))?;

    let outcome_grid = vec![70_000u64, 80_000, 100_000, 125_000, 150_000];
    let selected_idx = 3usize; // $125,000
    let anchor_sats = 330u64;
    let fee_sats = 140u64;
    let maturity_height = tip_height;
    let evaluation_height = tip_height;
    let valid_until_height = tip_height + 144;
    let refund_height = tip_height + 288;
    let shared_event_id = tagged_hash("shz-live-testnet4-event", &tip_height.to_le_bytes());

    let signers_1 = BridgeSignerMaterial {
        trader_sk: keys.alice_sk,
        maker_sk: keys.bob_sk,
        oracle_sks: keys.oracle_sks,
        trader_script: keys.alice_payout_script,
        maker_script: keys.bob_payout_script,
        anchor_script: keys.anchor_script,
    };
    let signers_2 = BridgeSignerMaterial {
        trader_sk: keys.bob_sk,
        maker_sk: keys.carol_sk,
        oracle_sks: keys.oracle_sks,
        trader_script: keys.bob_payout_script,
        maker_script: keys.carol_payout_script,
        anchor_script: keys.anchor_script,
    };
    let signers_3 = BridgeSignerMaterial {
        trader_sk: keys.carol_sk,
        maker_sk: keys.alice_sk,
        oracle_sks: keys.oracle_sks,
        trader_script: keys.carol_payout_script,
        maker_script: keys.alice_payout_script,
        anchor_script: keys.anchor_script,
    };

    let mut b1 = ShzDlcBridgeSpec::from_matched_ticket(
        &ticket_1,
        outcome_grid.clone(),
        selected_idx,
        anchor_sats,
        fee_sats,
        maturity_height,
        refund_height,
        refund_csv,
        shared_event_id,
    );
    b1.funding_txid = funding_outpoints[0].0;
    b1.funding_vout = funding_outpoints[0].1;

    let mut b2 = ShzDlcBridgeSpec::from_matched_ticket(
        &ticket_2,
        outcome_grid.clone(),
        selected_idx,
        anchor_sats,
        fee_sats,
        maturity_height,
        refund_height,
        refund_csv,
        shared_event_id,
    );
    b2.funding_txid = funding_outpoints[1].0;
    b2.funding_vout = funding_outpoints[1].1;

    let mut b3 = ShzDlcBridgeSpec::from_matched_ticket(
        &ticket_3,
        outcome_grid,
        selected_idx,
        anchor_sats,
        fee_sats,
        maturity_height,
        refund_height,
        refund_csv,
        shared_event_id,
    );
    b3.funding_txid = funding_outpoints[2].0;
    b3.funding_vout = funding_outpoints[2].1;

    let row_1 = build_unsigned_row_from_shz_dlc(&b1, &signers_1)?;
    let row_2 = build_unsigned_row_from_shz_dlc(&b2, &signers_2)?;
    let row_3 = build_unsigned_row_from_shz_dlc(&b3, &signers_3)?;

    if (row_1.outcome.trader_sats, row_1.outcome.maker_sats) != (1_075, 550)
        || (row_2.outcome.trader_sats, row_2.outcome.maker_sats) != (700, 425)
        || (row_3.outcome.trader_sats, row_3.outcome.maker_sats) != (400, 400)
    {
        return Err(NovaBitvmError::Bridge(
            "unexpected micro live Testnet4 bilateral payouts".to_owned(),
        ));
    }

    let mut nullifier_tree = SparseNullifierTree::new();
    let epoch = tip_height as u64;
    let batch_id = tagged_hash("shz-live-testnet4-batch", &epoch.to_le_bytes());
    let (batch, journal) = assemble_and_sign_bridged_batch(
        vec![
            (row_1.clone(), signers_1),
            (row_2.clone(), signers_2),
            (row_3.clone(), signers_3),
        ],
        &mut nullifier_tree,
        epoch,
        batch_id,
        evaluation_height,
        valid_until_height,
    )?;

    let batch_witness_bytes = encode_batch(&batch)?;
    let signed_clearing_tx = sign_atomic_batch_segwit_tx(&batch, &keys, refund_csv)?;
    if signed_clearing_tx.txid_hex() != hex::encode(journal.batch_txid) {
        return Err(NovaBitvmError::Bridge(
            "live Testnet4 SegwitTx txid mismatch vs journal.batch_txid".to_owned(),
        ));
    }

    // UTXORef Edmonds-Karp PnL routing + DurablePnlBatchBook for the $1 live Testnet4 triangle
    let set_id = "shz-live-testnet4-micro".to_owned();
    let genesis_root = tagged_hash("shz-live-testnet4-genesis", &epoch.to_le_bytes());
    let snapshot = PnlBatchSnapshotV1 {
        network: "bitcoin-testnet4".to_owned(),
        epoch_id: 1,
        previous_state_root: genesis_root,
        netting_sets: vec![NettingSetSpec {
            id: set_id.clone(),
            collateral: CollateralAsset::VanillaBtc,
        }],
        vaults: vec![
            VaultRecord {
                id: "vault_alice".to_owned(),
                netting_set_id: set_id.clone(),
                change_script_pubkey: keys.alice_payout_script.to_vec(),
                fee_sats: 140,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: funding_outpoints[0].0,
                        vout: funding_outpoints[0].1,
                    },
                    sats: 1_025 + 140,
                    script_pubkey: keys.alice_payout_script.to_vec(),
                }],
            },
            VaultRecord {
                id: "vault_bob".to_owned(),
                netting_set_id: set_id.clone(),
                change_script_pubkey: keys.bob_payout_script.to_vec(),
                fee_sats: 140,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: funding_outpoints[1].0,
                        vout: funding_outpoints[1].1,
                    },
                    sats: 1_500 + 140,
                    script_pubkey: keys.bob_payout_script.to_vec(),
                }],
            },
            VaultRecord {
                id: "vault_carol".to_owned(),
                netting_set_id: set_id.clone(),
                change_script_pubkey: keys.carol_payout_script.to_vec(),
                fee_sats: 140,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: funding_outpoints[2].0,
                        vout: funding_outpoints[2].1,
                    },
                    sats: 1_025 + 140,
                    script_pubkey: keys.carol_payout_script.to_vec(),
                }],
            },
        ],
        accounts: vec![
            AccountRecord {
                id: "alice".to_owned(),
                netting_set_id: set_id.clone(),
                vault_id: "vault_alice".to_owned(),
                equity_sats: 1_025,
                locked_sats: 0,
                payout_sats: 450,
                payout_script_pubkey: Some(keys.alice_payout_script.to_vec()),
            },
            AccountRecord {
                id: "bob".to_owned(),
                netting_set_id: set_id.clone(),
                vault_id: "vault_bob".to_owned(),
                equity_sats: 1_500,
                locked_sats: 0,
                payout_sats: 0,
                payout_script_pubkey: None,
            },
            AccountRecord {
                id: "carol".to_owned(),
                netting_set_id: set_id.clone(),
                vault_id: "vault_carol".to_owned(),
                equity_sats: 1_025,
                locked_sats: 0,
                payout_sats: 0,
                payout_script_pubkey: None,
            },
        ],
        obligations: vec![
            RealizedObligation {
                id: "t1-bob-to-alice-80k-to-125k".to_owned(),
                netting_set_id: set_id.clone(),
                from_account_id: "bob".to_owned(),
                to_account_id: "alice".to_owned(),
                sats: 450,
            },
            RealizedObligation {
                id: "t2-carol-to-bob-100k-to-125k".to_owned(),
                netting_set_id: set_id,
                from_account_id: "carol".to_owned(),
                to_account_id: "bob".to_owned(),
                sats: 200,
            },
        ],
        consumed_obligation_ids: Vec::new(),
        spent_outpoints: Vec::new(),
        routes: vec![
            PermittedRoute {
                from_vault_id: "vault_bob".to_owned(),
                to_target: RouteTarget::Payout("alice".to_owned()),
                capacity_sats: 1_500,
            },
            PermittedRoute {
                from_vault_id: "vault_carol".to_owned(),
                to_target: RouteTarget::Payout("alice".to_owned()),
                capacity_sats: 1_025,
            },
        ],
    };

    let snap_hash = snapshot.snapshot_hash();
    let solved = solve_and_verify_pnl_batch(&snapshot, &snap_hash)
        .map_err(|e| NovaBitvmError::Bridge(format!("micro solve_and_verify_pnl_batch: {e}")))?;
    let mut book_state = DurablePnlBatchBook::new_genesis("shz-live-testnet4-book", genesis_root);
    let h0 = book_state.head_hash;
    let h1 = book_state
        .reserve_before_signing(&h0, &snapshot)
        .map_err(|e| NovaBitvmError::Bridge(format!("micro reserve: {e}")))?;
    let h2 = book_state
        .record_signed_outcome(
            &h1,
            Ok((signed_clearing_tx.txid_hex(), signed_clearing_tx.serialize_segwit())),
        )
        .map_err(|e| NovaBitvmError::Bridge(format!("micro signed: {e}")))?;
    let h3 = book_state
        .confirm_active_chain(&h2, &signed_clearing_tx.txid_hex(), &snapshot)
        .map_err(|e| NovaBitvmError::Bridge(format!("micro confirm: {e}")))?;

    let (_, transcripts, mut nova_expected_statement) =
        NovaExpectedStatement::from_verified_batch(&batch)?;
    nova_expected_statement.verifier_key_pin_hex = Some(LNM_NOVA_V2_VK_SHA256_HEX.to_owned());
    let row_transcripts_600b_hex: Vec<String> = transcripts.iter().map(hex::encode).collect();

    let mut secq_claims_verified_count = 0usize;
    for r in &batch.rows {
        secq_claims_verified_count += build_and_verify_all_6_row_claims(&batch.context, r)?.len();
    }

    let testnet4_genesis: Hash = hex::decode(BITCOIN_TESTNET4_GENESIS_HASH_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    let vk_pin_bytes: Hash = hex::decode(LNM_NOVA_V2_VK_SHA256_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    let tip_hash_bytes: Hash = hex::decode(tip_block_hash_hex)
        .map_err(|_| NovaBitvmError::BitVm3("invalid tip_block_hash_hex".to_owned()))?
        .try_into()
        .map_err(|_| NovaBitvmError::BitVm3("tip_block_hash_hex must be 32B".to_owned()))?;
    let mut policy_in = Vec::with_capacity(64);
    policy_in.extend_from_slice(&statement_domain());
    policy_in.extend_from_slice(&tip_hash_bytes);
    let policy_hash = tagged_hash("shz-live-testnet4-policy", &policy_in);
    let program_hash = tagged_hash(
        "shz-nova-program",
        b"lnmarkets/sha256-transcript-accounting/v2",
    );

    let bitvm3_stmt = build_bitvm3_settlement_statement(
        BitcoinNetworkCode::Testnet4,
        testnet4_genesis,
        &batch.rows[0],
        &journal,
        batch.rows[0].summary.funding_txid,
        batch.rows[0].summary.funding_vout,
        program_hash,
        vk_pin_bytes,
        policy_hash,
    )?;

    let trades = [
        ExecutedClearingTrade {
            trade_no: 1,
            label: "Trade 1 (Testnet4): Alice Long $1 vs Bob Short $1 @ $80,000".to_owned(),
            match_id_hex: hex::encode(ticket_1.match_id),
            execution_price_usd: 80_000,
            clearing_mark_price_usd,
            usd_notional: 1,
            long_party: "Alice".to_owned(),
            short_party: "Bob".to_owned(),
            long_margin_sats: 625,
            short_margin_sats: 1_000,
            protocol_fee_sats: 0,
            funding_txid_hex: hex::encode(funding_outpoints[0].0),
            funding_vout: funding_outpoints[0].1,
            funding_script_pubkey_hex: hex::encode(row_1.summary.funding_script),
            total_utxo_sats: row_1.summary.collateral_sats,
            bilateral_long_payout_sats: 1_075,
            bilateral_short_payout_sats: 550,
            bilateral_realized_long_pnl_sats: 450,
        },
        ExecutedClearingTrade {
            trade_no: 2,
            label: "Trade 2 (Testnet4): Bob Long $1 vs Carol Short $1 @ $100,000 (Bob Flattens)"
                .to_owned(),
            match_id_hex: hex::encode(ticket_2.match_id),
            execution_price_usd: 100_000,
            clearing_mark_price_usd,
            usd_notional: 1,
            long_party: "Bob".to_owned(),
            short_party: "Carol".to_owned(),
            long_margin_sats: 500,
            short_margin_sats: 625,
            protocol_fee_sats: 0,
            funding_txid_hex: hex::encode(funding_outpoints[1].0),
            funding_vout: funding_outpoints[1].1,
            funding_script_pubkey_hex: hex::encode(row_2.summary.funding_script),
            total_utxo_sats: row_2.summary.collateral_sats,
            bilateral_long_payout_sats: 700,
            bilateral_short_payout_sats: 425,
            bilateral_realized_long_pnl_sats: 200,
        },
        ExecutedClearingTrade {
            trade_no: 3,
            label: "Trade 3 (Testnet4): Carol Long $1 vs Alice Short $1 @ $125,000 (Alice Closes)"
                .to_owned(),
            match_id_hex: hex::encode(ticket_3.match_id),
            execution_price_usd: 125_000,
            clearing_mark_price_usd,
            usd_notional: 1,
            long_party: "Carol".to_owned(),
            short_party: "Alice".to_owned(),
            long_margin_sats: 400,
            short_margin_sats: 400,
            protocol_fee_sats: 0,
            funding_txid_hex: hex::encode(funding_outpoints[2].0),
            funding_vout: funding_outpoints[2].1,
            funding_script_pubkey_hex: hex::encode(row_3.summary.funding_script),
            total_utxo_sats: row_3.summary.collateral_sats,
            bilateral_long_payout_sats: 400,
            bilateral_short_payout_sats: 400,
            bilateral_realized_long_pnl_sats: 0,
        },
    ];

    let party_accounting = [
        PartyClearingAccounting {
            party: "Alice".to_owned(),
            role: "Winner (Opened Long @ $80k, Closed on 3rd Trade @ $125k)".to_owned(),
            net_usd_delta_after_trade3: 0,
            total_posted_margin_sats: 1_025,
            net_realized_pnl_sats: 450,
            freed_collateral_returned_sats: 1_025,
            routed_pnl_received_sats: 450,
            final_cleared_payout_sats: 1_475,
            payout_script_pubkey_hex: hex::encode(keys.alice_payout_script),
        },
        PartyClearingAccounting {
            party: "Bob".to_owned(),
            role: "Loser (Short @ $80k, Flattened @ $100k; 83.33% Margin Freed)".to_owned(),
            net_usd_delta_after_trade3: 0,
            total_posted_margin_sats: 1_500,
            net_realized_pnl_sats: -250,
            freed_collateral_returned_sats: 1_250,
            routed_pnl_received_sats: 0,
            final_cleared_payout_sats: 1_250,
            payout_script_pubkey_hex: hex::encode(keys.bob_payout_script),
        },
        PartyClearingAccounting {
            party: "Carol".to_owned(),
            role: "Market-Maker (Short @ $100k, Closed @ $125k; Remaining Margin Freed)".to_owned(),
            net_usd_delta_after_trade3: 0,
            total_posted_margin_sats: 1_025,
            net_realized_pnl_sats: -200,
            freed_collateral_returned_sats: 825,
            routed_pnl_received_sats: 0,
            final_cleared_payout_sats: 825,
            payout_script_pubkey_hex: hex::encode(keys.carol_payout_script),
        },
    ];

    let utxoref_pnl_clearing = UtxoRefClearingSummary {
        snapshot_hash_hex: hex::encode(snap_hash),
        next_accounting_state_root_hex: hex::encode(solved.next_accounting_state_root),
        durable_book_final_head_hash_hex: hex::encode(h3),
        durable_book_settled_epoch: book_state.last_settled_epoch,
        bob_to_alice_routed_pnl_sats: 250,
        carol_to_alice_routed_pnl_sats: 200,
        total_winner_routed_pnl_sats: 450,
        bob_locked_margin_before_clearing_sats: 1_500,
        bob_freed_collateral_sats: 1_250,
        bob_freed_collateral_bps: (1_250 * 10_000) / 1_500,
        carol_freed_collateral_sats: 825,
        alice_total_cleared_payout_sats: 1_475,
    };

    let atomic_outputs_sats: Vec<u64> = signed_clearing_tx.outputs.iter().map(|(v, _)| *v).collect();
    let report = ThreePartyClearingReport {
        protocol: "SatsHedgeZero Live Bitcoin Testnet4 3-Party DLC + BitVM3 Nova Clearing v0.3.0"
            .to_owned(),
        network: "bitcoin-testnet4".to_owned(),
        testnet4_anchor_height: epoch,
        testnet4_anchor_block_hash_hex: tip_block_hash_hex.to_owned(),
        clearing_mark_price_usd,
        frost_quorum_signers: frost_quorum,
        frost_group_pubkey_x_hex: hex::encode(frost_confed.group_pubkey_x),
        trades,
        party_accounting,
        utxoref_pnl_clearing,
        batch_witness_bytes_len: batch_witness_bytes.len(),
        journal: JournalSummaryJson::from_journal(&journal),
        row_transcripts_600b_hex,
        nova_expected_statement,
        secq_claims_verified_count,
        bitvm3_testnet4_statement: bitvm3_stmt.to_json_record(),
        atomic_clearing_txid_hex: signed_clearing_tx.txid_hex(),
        atomic_clearing_wtxid_hex: signed_clearing_tx.wtxid_hex(),
        atomic_clearing_vsize: signed_clearing_tx.vsize(),
        atomic_clearing_outputs_sats: atomic_outputs_sats,
        atomic_clearing_raw_segwit_tx_hex: hex::encode(signed_clearing_tx.serialize_segwit()),
        external_nova_snark_receipt: None,
        honesty: VerificationHonestyFlags::native_only(),
    };

    Ok(ThreePartyClearingArtifacts {
        batch_witness: batch,
        batch_witness_bytes,
        journal,
        signed_clearing_tx,
        report,
    })
}
