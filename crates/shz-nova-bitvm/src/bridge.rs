//! Bridge helpers converting `SatsHedgeZero` inverse DLC (`MatchedDlcTicket` / `InverseContractSpec`)
//! and `SHZ-MNR-02` (`0x83 + two-tier CLTV` Bob-offline routed closeout) settlements into natively
//! verified `Row`, `BatchWitness`, `NovaExpectedStatement`, `SecqBip340Claim`, and 304-byte
//! `UtxoRefL2SettlementStatementV0` records.

use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{bigint::U256, ops::Reduce},
    schnorr::SigningKey,
};
use serde::{Deserialize, Serialize};
use shz_dex::MatchedDlcTicket;
use shz_dlc::pubkey_x_from_secret;
use shz_margin::InverseContractSpec;
use shz_utxoref::mnr02::{
    BobOfflineRoutedOutcome, OriginationPackage, authorize_bob_offline_multilateral_closeout,
    build_origination_package,
};

use crate::bitvm3::{
    BITCOIN_REGTEST_GENESIS_HASH_HEX, BitVm3SettlementRecord, BitcoinNetworkCode,
    UtxoRefL2SettlementStatementV0,
};
use crate::codec::{decode_batch, encode_batch, encode_journal};
use crate::error::{NovaBitvmError, Result, VerificationHonestyFlags};
use crate::merkle::{SparseNullifierTree, accepted_contracts_root, outcome_root_and_path};
use crate::nova::{NOVA_TRANSCRIPT_LEN, NovaExpectedStatement};
use crate::secq_claim::{RowSignatureSlot, SecqBip340Claim, build_and_verify_all_6_row_claims};
use crate::statement::{
    BatchContext, BatchWitness, DlcSummary, Hash, Journal, MAX_ROW_FEE_SATS, MIN_OUTPUT_SATS,
    OracleAttestation, Outcome, Row, Script, Sig, batch_consent_message, oracle_message,
    outpoint_nullifier, sha256, statement_domain, summary_digest, tagged_hash,
    unsigned_batch_transaction, verify_batch,
};
use crate::taproot::derive_funding_script;

fn sign_bip340_raw(secret: &[u8; 32], digest: &Hash) -> Result<Sig> {
    let sk = SigningKey::from_bytes(secret)
        .map_err(|_| NovaBitvmError::Bridge("invalid BIP-340 secret key".to_owned()))?;
    Ok(sk
        .sign_raw(digest, &[0u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("BIP-340 sign_raw failed".to_owned()))?
        .to_bytes())
}

fn p2tr_script_from_xonly(xonly: &Hash) -> Script {
    let mut s = [0u8; 34];
    s[..2].copy_from_slice(&[0x51, 0x20]);
    s[2..].copy_from_slice(xonly);
    s
}

/// Key material for building and signing a bridged `Row` in deterministic test/demo flows.
#[derive(Debug, Clone)]
pub struct BridgeSignerMaterial {
    pub trader_sk: [u8; 32],
    pub maker_sk: [u8; 32],
    pub oracle_sks: [[u8; 32]; 3],
    pub trader_script: Script,
    pub maker_script: Script,
    pub anchor_script: Script,
}

impl BridgeSignerMaterial {
    /// Derives sorted 3-oracle public keys alongside the mapping from sorted index to secret key.
    pub fn sorted_oracles(&self) -> Result<([Hash; 3], [[u8; 32]; 3])> {
        let mut pairs: Vec<(Hash, [u8; 32])> = Vec::with_capacity(3);
        for sk in self.oracle_sks {
            let pk = pubkey_x_from_secret(&sk)
                .map_err(|_| NovaBitvmError::Bridge("invalid oracle secret key".to_owned()))?;
            pairs.push((pk, sk));
        }
        pairs.sort_by_key(|(pk, _)| *pk);
        if pairs[0].0 == pairs[1].0 || pairs[1].0 == pairs[2].0 {
            return Err(NovaBitvmError::Bridge(
                "oracle keys must be strictly distinct".to_owned(),
            ));
        }
        Ok((
            [pairs[0].0, pairs[1].0, pairs[2].0],
            [pairs[0].1, pairs[1].1, pairs[2].1],
        ))
    }
}

/// Parameters for converting a `SatsHedgeZero` `InverseContractSpec` / `MatchedDlcTicket`
/// into an unsigned `Row` skeleton (signed once the batch context is finalized).
#[derive(Debug, Clone)]
pub struct ShzDlcBridgeSpec {
    pub contract_id: Hash,
    pub funding_txid: Hash,
    pub funding_vout: u32,
    pub spec: InverseContractSpec,
    pub outcome_prices_usd: Vec<u64>,
    pub selected_outcome_idx: usize,
    pub anchor_sats: u64,
    pub fee_sats: u64,
    pub maturity_height: u32,
    pub refund_height: u32,
    pub refund_csv: u16,
    pub oracle_event_id: Hash,
}

impl ShzDlcBridgeSpec {
    /// Creates a bridge specification directly from a matched `shz-dex` `MatchedDlcTicket`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_matched_ticket(
        ticket: &MatchedDlcTicket,
        outcome_prices_usd: Vec<u64>,
        selected_outcome_idx: usize,
        anchor_sats: u64,
        fee_sats: u64,
        maturity_height: u32,
        refund_height: u32,
        refund_csv: u16,
        oracle_event_id: Hash,
    ) -> Self {
        Self {
            contract_id: ticket.match_id,
            funding_txid: ticket.shared_funding_outpoint.txid,
            funding_vout: ticket.shared_funding_outpoint.vout,
            spec: ticket.contract_spec.clone(),
            outcome_prices_usd,
            selected_outcome_idx,
            anchor_sats,
            fee_sats,
            maturity_height,
            refund_height,
            refund_csv,
            oracle_event_id,
        }
    }
}

/// Converts a `SatsHedgeZero` inverse DLC spec into a `Row` with exact `UTXORef` NUMS P2TR
/// funding script and Merkle-committed payout outcomes matching `InverseContractSpec::settle_at_price`.
///
/// The row's `summary_signatures`, `oracle_attestations`, and `batch_signatures` are populated
/// by [`assemble_and_sign_bridged_batch`].
pub fn build_unsigned_row_from_shz_dlc(
    bridge: &ShzDlcBridgeSpec,
    signers: &BridgeSignerMaterial,
) -> Result<Row> {
    if bridge.anchor_sats < MIN_OUTPUT_SATS
        || bridge.fee_sats == 0
        || bridge.fee_sats > MAX_ROW_FEE_SATS
    {
        return Err(NovaBitvmError::Bridge(
            "invalid anchor_sats or fee_sats for batch row".to_owned(),
        ));
    }
    if bridge.outcome_prices_usd.is_empty()
        || bridge.selected_outcome_idx >= bridge.outcome_prices_usd.len()
    {
        return Err(NovaBitvmError::Bridge(
            "outcome_prices_usd must be non-empty and selected_outcome_idx in bounds".to_owned(),
        ));
    }
    let trader_key = pubkey_x_from_secret(&signers.trader_sk)
        .map_err(|_| NovaBitvmError::Bridge("invalid trader_sk".to_owned()))?;
    let maker_key = pubkey_x_from_secret(&signers.maker_sk)
        .map_err(|_| NovaBitvmError::Bridge("invalid maker_sk".to_owned()))?;
    let (oracle_keys, _) = signers.sorted_oracles()?;
    let funding_script = derive_funding_script(&trader_key, &maker_key, bridge.refund_csv)?;

    // Total on-chain collateral = contract economic collateral + CPFP anchor + row miner fee.
    let base_collateral = bridge.spec.total_collateral_sats();
    if base_collateral < 2 * MIN_OUTPUT_SATS {
        return Err(NovaBitvmError::Bridge(
            "contract total_collateral_sats below 2x P2TR dust".to_owned(),
        ));
    }
    let collateral_sats = base_collateral
        .checked_add(bridge.anchor_sats)
        .and_then(|v| v.checked_add(bridge.fee_sats))
        .ok_or_else(|| NovaBitvmError::Bridge("collateral overflow".to_owned()))?;

    let mut summary = DlcSummary {
        salt: tagged_hash("shz-dlc-salt", &bridge.contract_id),
        contract_id: bridge.contract_id,
        plan_digest: tagged_hash("shz-dlc-plan", &bridge.spec.usd_notional.to_le_bytes()),
        recovery_digest: tagged_hash("shz-dlc-recovery", &bridge.funding_txid),
        funding_txid: bridge.funding_txid,
        funding_vout: bridge.funding_vout,
        collateral_sats,
        funding_script,
        trader_key,
        maker_key,
        trader_script: signers.trader_script,
        maker_script: signers.maker_script,
        anchor_script: signers.anchor_script,
        oracle_keys,
        oracle_event_id: bridge.oracle_event_id,
        outcome_root: [0u8; 32],
        outcome_count: bridge.outcome_prices_usd.len() as u32,
        maturity_height: bridge.maturity_height,
        refund_height: bridge.refund_height,
        refund_csv: bridge.refund_csv,
    };

    let mut outcomes = Vec::with_capacity(bridge.outcome_prices_usd.len());
    for (idx, &price_usd) in bridge.outcome_prices_usd.iter().enumerate() {
        let split = bridge.spec.payout_at_price(price_usd);
        // Clamp both outputs >= MIN_OUTPUT_SATS while preserving exact `base_collateral` conservation.
        let trader_sats = split
            .long_sats
            .clamp(MIN_OUTPUT_SATS, base_collateral - MIN_OUTPUT_SATS);
        let maker_sats = base_collateral - trader_sats;

        let mut msg_preimage = Vec::with_capacity(48);
        msg_preimage.extend_from_slice(&bridge.contract_id);
        msg_preimage.extend_from_slice(&price_usd.to_le_bytes());
        msg_preimage.extend_from_slice(&(idx as u64).to_le_bytes());
        outcomes.push(Outcome {
            index: idx as u32,
            message: tagged_hash("shz-dlc-outcome-price", &msg_preimage),
            trader_sats,
            maker_sats,
            anchor_sats: bridge.anchor_sats,
            fee_sats: bridge.fee_sats,
        });
    }

    let (outcome_root, outcome_siblings) =
        outcome_root_and_path(&summary, &outcomes, bridge.selected_outcome_idx)?;
    summary.outcome_root = outcome_root;

    Ok(Row {
        summary,
        summary_signatures: [[0; 64]; 2],
        outcome: outcomes[bridge.selected_outcome_idx].clone(),
        outcome_siblings,
        oracle_attestations: [
            OracleAttestation {
                oracle_index: 0,
                signature: [0; 64],
            },
            OracleAttestation {
                oracle_index: 2,
                signature: [0; 64],
            },
        ],
        batch_signatures: [[0; 64]; 2],
        nullifier_siblings: Vec::new(),
    })
}

/// Converts an `SHZ-MNR-02` `OriginationPackage` + `BobOfflineRoutedOutcome` into an unsigned `Row`
/// preserving exact origination outcomes (`alice_unilateral_sats`, `bob_output_sats`, `anchor_sats`,
/// `miner_fee_sats`) and returning the `0x83` routed closeout `assertion_txid`.
pub fn build_unsigned_row_from_mnr02(
    orig: &OriginationPackage,
    routed: &BobOfflineRoutedOutcome,
    selected_outcome_idx: usize,
    signers: &BridgeSignerMaterial,
    refund_csv: u16,
    oracle_event_id: Hash,
) -> Result<(Row, Hash)> {
    if selected_outcome_idx >= orig.outcomes.len() {
        return Err(NovaBitvmError::Bridge(
            "selected_outcome_idx out of bounds for MNR-02 OriginationPackage".to_owned(),
        ));
    }
    let funding_txid: Hash = hex::decode(&orig.funding_txid_display)
        .map_err(|_| NovaBitvmError::Bridge("invalid MNR-02 funding_txid_display hex".to_owned()))?
        .try_into()
        .map_err(|_| NovaBitvmError::Bridge("funding_txid must be 32 bytes".to_owned()))?;
    let assertion_txid: Hash = hex::decode(routed.unsigned_routed_tx.txid_hex())
        .map_err(|_| NovaBitvmError::Bridge("invalid MNR-02 routed txid hex".to_owned()))?
        .try_into()
        .map_err(|_| NovaBitvmError::Bridge("assertion_txid must be 32 bytes".to_owned()))?;

    let trader_key = pubkey_x_from_secret(&signers.trader_sk)
        .map_err(|_| NovaBitvmError::Bridge("invalid trader_sk".to_owned()))?;
    let maker_key = pubkey_x_from_secret(&signers.maker_sk)
        .map_err(|_| NovaBitvmError::Bridge("invalid maker_sk".to_owned()))?;
    if trader_key != orig.tree.alice_pubkey_x || maker_key != orig.tree.bob_pubkey_x {
        return Err(NovaBitvmError::Bridge(
            "MNR-02 Alice/Bob pubkeys must match BridgeSignerMaterial trader/maker keys".to_owned(),
        ));
    }
    let (oracle_keys, _) = signers.sorted_oracles()?;
    let funding_script = derive_funding_script(&trader_key, &maker_key, refund_csv)?;

    let mut cid_in = Vec::with_capacity(68);
    cid_in.extend_from_slice(&funding_txid);
    cid_in.extend_from_slice(&orig.funding_vout.to_le_bytes());
    cid_in.extend_from_slice(&assertion_txid);
    let contract_id = tagged_hash("shz-mnr02-contract", &cid_in);

    let anchor_sats = orig
        .funding_sats
        .checked_sub(
            orig.outcomes[selected_outcome_idx].alice_unilateral_sats
                + orig.outcomes[selected_outcome_idx].bob_output_sats
                + orig.miner_fee_sats,
        )
        .ok_or_else(|| NovaBitvmError::Bridge("MNR-02 anchor_sats underflow".to_owned()))?;

    let mut summary = DlcSummary {
        salt: tagged_hash("shz-mnr02-salt", &contract_id),
        contract_id,
        plan_digest: tagged_hash("shz-mnr02-plan", &assertion_txid),
        recovery_digest: tagged_hash(
            "shz-mnr02-refund",
            &orig.signed_refund_tx.serialize_unsigned(),
        ),
        funding_txid,
        funding_vout: orig.funding_vout,
        collateral_sats: orig.funding_sats,
        funding_script,
        trader_key,
        maker_key,
        trader_script: signers.trader_script,
        maker_script: signers.maker_script,
        anchor_script: signers.anchor_script,
        oracle_keys,
        oracle_event_id,
        outcome_root: [0u8; 32],
        outcome_count: orig.outcomes.len() as u32,
        maturity_height: orig.tree.maturity_height,
        refund_height: orig.tree.refund_cltv_height,
        refund_csv,
    };

    let outcomes: Vec<Outcome> = orig
        .outcomes
        .iter()
        .enumerate()
        .map(|(idx, pre)| {
            let mut m = Vec::with_capacity(48);
            m.extend_from_slice(&contract_id);
            m.extend_from_slice(&pre.price_usd.to_le_bytes());
            m.extend_from_slice(&(idx as u64).to_le_bytes());
            Outcome {
                index: idx as u32,
                message: tagged_hash("shz-mnr02-outcome", &m),
                trader_sats: pre.alice_unilateral_sats,
                maker_sats: pre.bob_output_sats,
                anchor_sats,
                fee_sats: orig.miner_fee_sats,
            }
        })
        .collect();

    let (outcome_root, outcome_siblings) =
        outcome_root_and_path(&summary, &outcomes, selected_outcome_idx)?;
    summary.outcome_root = outcome_root;

    let row = Row {
        summary,
        summary_signatures: [[0; 64]; 2],
        outcome: outcomes[selected_outcome_idx].clone(),
        outcome_siblings,
        oracle_attestations: [
            OracleAttestation {
                oracle_index: 0,
                signature: [0; 64],
            },
            OracleAttestation {
                oracle_index: 2,
                signature: [0; 64],
            },
        ],
        batch_signatures: [[0; 64]; 2],
        nullifier_siblings: Vec::new(),
    };
    Ok((row, assertion_txid))
}

/// Assembles canonical outpoint ordering, 256-depth sparse nullifier transitions, `BatchContext`,
/// and BIP-340 summary/oracle/batch signatures for one or more bridged rows, returning a fully
/// verified `(BatchWitness, Journal)`.
pub fn assemble_and_sign_bridged_batch(
    mut rows_and_signers: Vec<(Row, BridgeSignerMaterial)>,
    nullifier_tree: &mut SparseNullifierTree,
    epoch: u64,
    batch_id: Hash,
    evaluation_height: u32,
    valid_until_height: u32,
) -> Result<(BatchWitness, Journal)> {
    if rows_and_signers.is_empty() {
        return Err(NovaBitvmError::Bridge(
            "at least one row is required to assemble a batch".to_owned(),
        ));
    }
    rows_and_signers.sort_by_key(|(r, _)| (r.summary.funding_txid, r.summary.funding_vout));

    let old_nullifier_root = nullifier_tree.root();
    let mut rows: Vec<Row> = Vec::with_capacity(rows_and_signers.len());
    let mut signers_sorted: Vec<BridgeSignerMaterial> = Vec::with_capacity(rows_and_signers.len());
    for (mut row, signer) in rows_and_signers {
        let nullifier = outpoint_nullifier(&row.summary);
        row.nullifier_siblings = nullifier_tree.proof(&nullifier);
        nullifier_tree.insert(&nullifier)?;
        rows.push(row);
        signers_sorted.push(signer);
    }

    let accepted_root = accepted_contracts_root(&rows)?;
    let tx_bytes = unsigned_batch_transaction(&rows)?;
    let context = BatchContext {
        epoch,
        batch_id,
        evaluation_height,
        valid_until_height,
        accepted_contracts_root: accepted_root,
        old_nullifier_root,
        new_nullifier_root: nullifier_tree.root(),
        batch_tx_digest: sha256(&tx_bytes),
        row_count: rows.len() as u32,
    };

    for (row, signer) in rows.iter_mut().zip(signers_sorted.iter()) {
        let s_hash = summary_digest(&row.summary);
        row.summary_signatures = [
            sign_bip340_raw(&signer.trader_sk, &s_hash)?,
            sign_bip340_raw(&signer.maker_sk, &s_hash)?,
        ];
        let c_hash = batch_consent_message(&context, &row.summary);
        row.batch_signatures = [
            sign_bip340_raw(&signer.trader_sk, &c_hash)?,
            sign_bip340_raw(&signer.maker_sk, &c_hash)?,
        ];
        let (_, sorted_oracle_sks) = signer.sorted_oracles()?;
        let o_hash = oracle_message(&row.summary, &row.outcome);
        for att in &mut row.oracle_attestations {
            att.signature = sign_bip340_raw(&sorted_oracle_sks[att.oracle_index as usize], &o_hash)?;
        }
    }

    let witness = BatchWitness { context, rows };
    let journal = verify_batch(&witness)?;
    Ok((witness, journal))
}

/// Constructs a verified 304-byte `UtxoRefL2SettlementStatementV0` tying a verified batch
/// `Journal` and `Row` (plus an assertion outpoint, e.g., an `SHZ-MNR-02` `0x83` txid or
/// batch funding outpoint) into the BitVM3 Groth16 statement layout.
#[allow(clippy::too_many_arguments)]
pub fn build_bitvm3_settlement_statement(
    network_code: BitcoinNetworkCode,
    chain_genesis_hash: Hash,
    row: &Row,
    journal: &Journal,
    assertion_txid: Hash,
    assertion_vout: u32,
    program_hash: Hash,
    verifying_key_hash: Hash,
    policy_hash: Hash,
) -> Result<UtxoRefL2SettlementStatementV0> {
    let journal_bytes = encode_journal(journal);
    let statement = UtxoRefL2SettlementStatementV0 {
        network_code,
        chain_genesis_hash,
        contract_id: row.summary.contract_id,
        commitment_hash: sha256(&journal_bytes),
        assertion_txid,
        settlement_txid: journal.batch_txid,
        program_hash,
        verifying_key_hash,
        policy_hash,
        epoch_id: journal.epoch,
        assertion_vout,
    };
    statement.validate_nonzero()?;
    Ok(statement)
}

/// JSON-serializable summary of a verified `LNMJNL01` journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalSummaryJson {
    pub domain_hex: String,
    pub epoch: u64,
    pub batch_id_hex: String,
    pub evaluation_height: u32,
    pub valid_until_height: u32,
    pub row_count: u32,
    pub accepted_contracts_root_hex: String,
    pub old_nullifier_root_hex: String,
    pub new_nullifier_root_hex: String,
    pub batch_tx_digest_hex: String,
    pub batch_txid_hex: String,
    pub total_collateral_sats: u64,
    pub total_payout_sats: u64,
    pub total_fee_sats: u64,
    pub journal_276b_hex: String,
    pub journal_sha256_hex: String,
}

impl JournalSummaryJson {
    pub fn from_journal(j: &Journal) -> Self {
        let bytes = encode_journal(j);
        let digest = sha256(&bytes);
        Self {
            domain_hex: hex::encode(j.domain),
            epoch: j.epoch,
            batch_id_hex: hex::encode(j.batch_id),
            evaluation_height: j.evaluation_height,
            valid_until_height: j.valid_until_height,
            row_count: j.row_count,
            accepted_contracts_root_hex: hex::encode(j.accepted_contracts_root),
            old_nullifier_root_hex: hex::encode(j.old_nullifier_root),
            new_nullifier_root_hex: hex::encode(j.new_nullifier_root),
            batch_tx_digest_hex: hex::encode(j.batch_tx_digest),
            batch_txid_hex: hex::encode(j.batch_txid),
            total_collateral_sats: j.total_collateral_sats,
            total_payout_sats: j.total_payout_sats,
            total_fee_sats: j.total_fee_sats,
            journal_276b_hex: hex::encode(bytes),
            journal_sha256_hex: hex::encode(digest),
        }
    }
}

/// Summary of the `SHZ-MNR-02` Bob-offline `0x83` closeout bridged into a BitVM3 statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mnr02BitVm3BridgeSummary {
    pub bob_offline_routed_txid_hex: String,
    pub bob_output_sats: u64,
    pub carol_routed_sats: u64,
    pub alice_closeout_sats: u64,
    pub batch_txid_hex: String,
    pub bitvm3_statement: BitVm3SettlementRecord,
    pub honesty: VerificationHonestyFlags,
}

/// Deterministic end-to-end 2-contract `shz nova-demo` verification bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NovaBitvmDemoReport {
    pub protocol: String,
    pub batch_witness_bytes_len: usize,
    pub row_count: u32,
    pub journal: JournalSummaryJson,
    pub row_transcripts_600b_hex: Vec<String>,
    pub nova_expected_statement: NovaExpectedStatement,
    pub secq_row0_claims: Vec<SecqBip340Claim>,
    pub bitvm3_settlement_statement: BitVm3SettlementRecord,
    pub mnr02_bridge: Mnr02BitVm3BridgeSummary,
    pub honesty: VerificationHonestyFlags,
}

/// Builds a deterministic, natively verified 2-contract SatsHedgeZero Nova/BitVM3 demo report
/// (plus an `SHZ-MNR-02` Bob-offline closeout bridge receipt) with explicit honesty flags.
pub fn build_verified_nova_bitvm_demo() -> Result<NovaBitvmDemoReport> {
    let trader_sk = [0x11u8; 32];
    let maker_sk = [0x22u8; 32];
    let oracle_sks = [[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]];

    let trader_payout_pk = pubkey_x_from_secret(&[0x41u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("trader payout pk".to_owned()))?;
    let maker_payout_pk = pubkey_x_from_secret(&[0x42u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("maker payout pk".to_owned()))?;
    let anchor_pk = pubkey_x_from_secret(&[0x43u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("anchor pk".to_owned()))?;

    let signers = BridgeSignerMaterial {
        trader_sk,
        maker_sk,
        oracle_sks,
        trader_script: p2tr_script_from_xonly(&trader_payout_pk),
        maker_script: p2tr_script_from_xonly(&maker_payout_pk),
        anchor_script: p2tr_script_from_xonly(&anchor_pk),
    };

    // Contract 0: $1,000 BTC-USD inverse 10x Long vs 1x SatsHedge Short @ $100,000 (settled @ $108,200)
    let spec_0 = InverseContractSpec::from_leverages_v0(1_000, 100_000, 100_000, 10_000)
        .map_err(|e| NovaBitvmError::Bridge(format!("spec_0: {e}")))?;
    let bridge_0 = ShzDlcBridgeSpec {
        contract_id: tagged_hash("shz-demo-contract", b"btc-perp-0"),
        funding_txid: tagged_hash("shz-demo-funding", b"utxo-0"),
        funding_vout: 0,
        spec: spec_0,
        outcome_prices_usd: vec![92_000, 100_000, 108_200, 115_000],
        selected_outcome_idx: 2,
        anchor_sats: 330,
        fee_sats: 1_000,
        maturity_height: 890_100,
        refund_height: 890_300,
        refund_csv: 144,
        oracle_event_id: tagged_hash("shz-demo-event", b"SHZ-BTCUSD-PERP-20261123-0"),
    };

    // Contract 1: $2,000 BTC-USD inverse 5x Long vs 1x SatsHedge Short @ $100,000 (settled @ $95,000)
    let spec_1 = InverseContractSpec::from_leverages_v0(2_000, 100_000, 50_000, 10_000)
        .map_err(|e| NovaBitvmError::Bridge(format!("spec_1: {e}")))?;
    let bridge_1 = ShzDlcBridgeSpec {
        contract_id: tagged_hash("shz-demo-contract", b"btc-perp-1"),
        funding_txid: tagged_hash("shz-demo-funding", b"utxo-1"),
        funding_vout: 1,
        spec: spec_1,
        outcome_prices_usd: vec![90_000, 95_000, 100_000, 110_000],
        selected_outcome_idx: 1,
        anchor_sats: 330,
        fee_sats: 1_000,
        maturity_height: 890_100,
        refund_height: 890_300,
        refund_csv: 144,
        oracle_event_id: tagged_hash("shz-demo-event", b"SHZ-BTCUSD-PERP-20261123-1"),
    };

    let row_0 = build_unsigned_row_from_shz_dlc(&bridge_0, &signers)?;
    let row_1 = build_unsigned_row_from_shz_dlc(&bridge_1, &signers)?;

    let mut smt = SparseNullifierTree::new();
    let (batch, journal) = assemble_and_sign_bridged_batch(
        vec![(row_0, signers.clone()), (row_1, signers.clone())],
        &mut smt,
        1,
        tagged_hash("shz-demo-batch", b"epoch-1"),
        890_110,
        890_200,
    )?;

    // Verify canonical LNMBAT01 roundtrip
    let encoded_batch = encode_batch(&batch)?;
    let decoded_batch = decode_batch(&encoded_batch)?;
    let verified_journal = verify_batch(&decoded_batch)?;
    if verified_journal != journal {
        return Err(NovaBitvmError::Bridge(
            "batch roundtrip journal mismatch".to_owned(),
        ));
    }

    // Build 600B Nova v2 transcripts & 8-field expected.json
    let (_, transcripts, nova_expected_statement) =
        NovaExpectedStatement::from_verified_batch(&batch)?;
    let row_transcripts_600b_hex: Vec<String> = transcripts
        .iter()
        .map(|t| {
            debug_assert_eq!(t.len(), NOVA_TRANSCRIPT_LEN);
            hex::encode(t)
        })
        .collect();

    // Build & verify all 6 Secq BIP-340 3-field claims for row 0
    let secq_row0_claims = build_and_verify_all_6_row_claims(&batch.context, &batch.rows[0])?.to_vec();
    // Explicitly double-check slot 0 binding
    secq_row0_claims[0].verify_against_row_slot(
        &batch.context,
        &batch.rows[0],
        RowSignatureSlot::SummaryTrader,
    )?;

    // Build 304B BitVM3 settlement statement V0 for the verified 2-contract batch
    let regtest_genesis: Hash = hex::decode(BITCOIN_REGTEST_GENESIS_HASH_HEX)
        .expect("valid genesis hex")
        .try_into()
        .expect("32B");
    let program_hash = tagged_hash("shz-nova-program", b"lnmarkets/sha256-transcript-accounting/v2");
    let verifying_key_hash = tagged_hash("shz-nova-vk-placeholder", b"unpinned-native-only-v0");
    let policy_hash = statement_domain();

    let bitvm3_stmt = build_bitvm3_settlement_statement(
        BitcoinNetworkCode::Regtest,
        regtest_genesis,
        &batch.rows[0],
        &journal,
        batch.rows[0].summary.funding_txid,
        batch.rows[0].summary.funding_vout,
        program_hash,
        verifying_key_hash,
        policy_hash,
    )?;
    // Roundtrip check exact 304B codec
    let encoded_304 = bitvm3_stmt.encode();
    let decoded_304 = UtxoRefL2SettlementStatementV0::decode(&encoded_304)?;
    if decoded_304 != bitvm3_stmt {
        return Err(NovaBitvmError::BitVm3(
            "304-byte BitVM3 statement roundtrip mismatch".to_owned(),
        ));
    }

    // Bridge an SHZ-MNR-02 Bob-offline 0x83 closeout into a verified Row + 304B BitVM3 statement
    let mnr02_bridge = build_demo_mnr02_bridge(
        &signers,
        regtest_genesis,
        program_hash,
        verifying_key_hash,
        policy_hash,
    )?;

    Ok(NovaBitvmDemoReport {
        protocol: "SatsHedgeZero Nova/BitVM3 Native Statement Harness v0.2.0".to_owned(),
        batch_witness_bytes_len: encoded_batch.len(),
        row_count: journal.row_count,
        journal: JournalSummaryJson::from_journal(&journal),
        row_transcripts_600b_hex,
        nova_expected_statement,
        secq_row0_claims,
        bitvm3_settlement_statement: bitvm3_stmt.to_json_record(),
        mnr02_bridge,
        honesty: VerificationHonestyFlags::native_only(),
    })
}

fn build_demo_mnr02_bridge(
    signers: &BridgeSignerMaterial,
    chain_genesis_hash: Hash,
    program_hash: Hash,
    verifying_key_hash: Hash,
    policy_hash: Hash,
) -> Result<Mnr02BitVm3BridgeSummary> {
    let guard_sk = [0x55u8; 32];
    let guard_pk = pubkey_x_from_secret(&guard_sk)
        .map_err(|_| NovaBitvmError::Bridge("guard_pk".to_owned()))?;
    let carol_pk = pubkey_x_from_secret(&[0x66u8; 32])
        .map_err(|_| NovaBitvmError::Bridge("carol_pk".to_owned()))?;
    let carol_spk = p2tr_script_from_xonly(&carol_pk).to_vec();

    let prices = [50_000u64, 55_000, 65_000];
    let outcome_points: Vec<(u64, ProjectivePoint)> = prices
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            let h = tagged_hash("shz-mnr02-demo-adaptor", &(i as u64).to_le_bytes());
            let s = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&h));
            (p, ProjectivePoint::GENERATOR * s)
        })
        .collect();

    let funding_txid_hex = hex::encode(tagged_hash("shz-mnr02-demo-funding", b"u_ab"));
    let orig = build_origination_package(
        &signers.trader_sk,
        &signers.maker_sk,
        guard_pk,
        &funding_txid_hex,
        0,
        2_000_000,
        2_000_000,
        1_000,
        50_000,
        1_000,
        890_100,
        6,
        144,
        signers.trader_script.to_vec(),
        signers.maker_script.to_vec(),
        signers.anchor_script.to_vec(),
        &outcome_points,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("MNR-02 build_origination_package: {e}")))?;

    let routed_all = authorize_bob_offline_multilateral_closeout(
        &orig,
        &signers.trader_sk,
        &guard_sk,
        1_000,
        55_000,
        &carol_spk,
        &outcome_points,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("MNR-02 bob-offline closeout: {e}")))?;

    // Outcome index 2 ($65,000): Carol receives routed profit while Bob is offline.
    let selected = 2usize;
    let routed = &routed_all[selected];
    let (row, assertion_txid) = build_unsigned_row_from_mnr02(
        &orig,
        routed,
        selected,
        signers,
        144,
        tagged_hash("shz-mnr02-event", b"SHZ-MNR02-20261123"),
    )?;

    let mut smt = SparseNullifierTree::new();
    let (batch, journal) = assemble_and_sign_bridged_batch(
        vec![(row, signers.clone())],
        &mut smt,
        2,
        tagged_hash("shz-mnr02-batch", b"epoch-2"),
        890_105,
        890_200,
    )?;

    let bitvm3_stmt = build_bitvm3_settlement_statement(
        BitcoinNetworkCode::Regtest,
        chain_genesis_hash,
        &batch.rows[0],
        &journal,
        assertion_txid,
        0,
        program_hash,
        verifying_key_hash,
        policy_hash,
    )?;

    Ok(Mnr02BitVm3BridgeSummary {
        bob_offline_routed_txid_hex: hex::encode(assertion_txid),
        bob_output_sats: routed.bob_output_sats,
        carol_routed_sats: routed.carol_routed_sats,
        alice_closeout_sats: routed.alice_closeout_sats,
        batch_txid_hex: hex::encode(journal.batch_txid),
        bitvm3_statement: bitvm3_stmt.to_json_record(),
        honesty: VerificationHonestyFlags::native_only(),
    })
}
