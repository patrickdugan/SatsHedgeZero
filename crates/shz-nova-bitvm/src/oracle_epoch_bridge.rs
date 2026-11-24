//! Oracle-Bound `SHZ-MNR-03` -> Nova v2 / BitVM3 Settlement Bridge (`oracle_epoch_bridge.rs`).
//!
//! Cryptographically binds:
//! 1. **Native Pyth Pro (`pyth-lazer`) Ed25519 Solana Envelope Verification**:
//!    Re-verifies raw signed bytes against a `PinnedPythSignerRegistry` + `PythProBtcUsdPolicy`
//!    (never trusting pre-parsed booleans) and enforces `whole_price_usd == settled_price_usd`.
//! 2. **`SHZ-MNR-03` 3-Party Multilateral Atomic Clearing with Bob 100% Offline (`0x83`)**:
//!    Consumes `Mnr03OriginationBundle` (containing zero secret keys; `bob_sk` dropped at `t = 0`),
//!    completes Bob's `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) adaptor pre-signatures on
//!    `U_AB` (`vin[0] -> vout[0]`) and `U_BC` (`vin[1] -> vout[1]`) using only `oracle_scalar_t`,
//!    and co-signs the 3-input, 5-output clearing transaction with `Alice + Carol + RouterGuard`.
//! 3. **3-Row `LNMBAT01` Nova Witness + `304B` `UtxoRefL2SettlementStatementV0` (`bob_sk` Absent!)**:
//!    Encodes all 3 channel clearing authorizations (`AB`: `Alice + Guard`, `BC`: `Carol + Guard`,
//!    `CA`: `Carol + Alice`) into a natively verified 3-row `BatchWitness` (`oracle_event_id ==
//!    pyth_receipt.receipt_hash`, `batch_id == session_hash`) and `304B` BitVM3 statement
//!    (`assertion_txid == mnr03_atomic_clearing_txid`), ready for out-of-process `lnm-nova` proving.

use k256::Scalar;
use serde::{Deserialize, Serialize};
use shz_dlc::pubkey_x_from_secret;
use shz_oracle::pyth_lazer::{
    PinnedPythSignerRegistry, PythProBtcUsdPolicy, VerifiedPythProBtcUsdReceipt,
    verify_pyth_pro_btc_usd_solana_envelope,
};
use shz_utxoref::mnr03::{
    Mnr03AssembledClearing, Mnr03ClearingReceipt, Mnr03OriginationBundle,
    assemble_mnr03_bob_offline_three_party_clearing,
};

use crate::{
    bitvm3::{
        BITCOIN_REGTEST_GENESIS_HASH_HEX, BITCOIN_TESTNET4_GENESIS_HASH_HEX,
        BitVm3SettlementRecord, BitcoinNetworkCode, LNM_NOVA_V2_VK_SHA256_HEX,
    },
    bridge::{
        BridgeSignerMaterial, JournalSummaryJson, assemble_and_sign_bridged_batch,
        build_bitvm3_settlement_statement,
    },
    clearing_3party::ExternalNovaSnarkReceipt,
    codec::{decode_batch, encode_batch},
    error::{NovaBitvmError, Result, VerificationHonestyFlags},
    merkle::{SparseNullifierTree, outcome_root_and_path},
    nova::{NOVA_TRANSCRIPT_LEN, NovaExpectedStatement},
    secq_claim::build_and_verify_all_6_row_claims,
    statement::{
        BatchWitness, DlcSummary, Hash, Journal, OracleAttestation, Outcome, Row, Script,
        tagged_hash, verify_batch,
    },
    taproot::derive_funding_script,
};

/// Verified summary of the native Pyth Pro oracle receipt bound into the clearing epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundPythProEpochSummary {
    pub feed_id: u32,
    pub channel_id: u8,
    pub publish_time_us: u64,
    pub feed_update_time_us: u64,
    pub price_e8: i64,
    pub whole_price_usd: u64,
    pub confidence_e8: u64,
    pub registry_epoch: u64,
    pub signer_pubkey_hex: String,
    pub signed_payload_sha256_hex: String,
    pub receipt_hash_hex: String,
    pub session_hash_hex: String,
    pub near_finality_verified: bool,
}

/// Complete, serializable report for an Oracle-Bound `SHZ-MNR-03` Bob-Offline 3-Party Clearing + Nova ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleBoundMnr03NovaReport {
    pub protocol: String,
    pub network: String,
    pub anchor_height: u64,
    pub anchor_block_hash_hex: String,
    pub bob_online_during_clearing_or_proving: bool,
    pub pyth_pro_epoch: BoundPythProEpochSummary,
    pub mnr03_clearing: Mnr03ClearingReceipt,
    pub mnr03_atomic_clearing_raw_segwit_tx_hex: String,
    pub batch_witness_bytes_len: usize,
    pub journal: JournalSummaryJson,
    pub row_transcripts_600b_hex: Vec<String>,
    pub nova_expected_statement: NovaExpectedStatement,
    pub secq_claims_verified_count: usize,
    pub bitvm3_statement: BitVm3SettlementRecord,
    pub external_nova_snark_receipt: Option<ExternalNovaSnarkReceipt>,
    pub honesty: VerificationHonestyFlags,
}

/// Full in-memory artifacts from [`build_oracle_bound_mnr03_nova_ceremony`].
#[derive(Debug, Clone)]
pub struct OracleBoundMnr03NovaArtifacts {
    pub pyth_receipt: VerifiedPythProBtcUsdReceipt,
    pub session_hash: Hash,
    pub mnr03_assembled: Mnr03AssembledClearing,
    pub batch_witness: BatchWitness,
    pub batch_witness_bytes: Vec<u8>,
    pub journal: Journal,
    pub report: OracleBoundMnr03NovaReport,
}

fn vec_spk_to_script34(spk: &[u8]) -> Result<Script> {
    spk.try_into()
        .map_err(|_| NovaBitvmError::Bridge("expected 34-byte P2TR scriptPubKey".to_owned()))
}

fn hex_to_hash32(h: &str) -> Result<Hash> {
    hex::decode(h)
        .map_err(|_| NovaBitvmError::Bridge("invalid 32-byte hex".to_owned()))?
        .try_into()
        .map_err(|_| NovaBitvmError::Bridge("expected 32-byte digest".to_owned()))
}

#[allow(clippy::too_many_arguments)]
fn build_online_authorized_clearing_row(
    channel_tag: &[u8],
    funding_txid: Hash,
    funding_vout: u32,
    collateral_sats: u64,
    trader_out_sats: u64,
    maker_out_sats: u64,
    anchor_sats: u64,
    fee_sats: u64,
    settled_price_usd: u64,
    maturity_height: u32,
    refund_height: u32,
    refund_csv: u16,
    oracle_event_id: Hash,
    assertion_txid: Hash,
    recovery_digest: Hash,
    signers: &BridgeSignerMaterial,
) -> Result<Row> {
    let trader_key = pubkey_x_from_secret(&signers.trader_sk)
        .map_err(|_| NovaBitvmError::Bridge("trader_sk".to_owned()))?;
    let maker_key = pubkey_x_from_secret(&signers.maker_sk)
        .map_err(|_| NovaBitvmError::Bridge("maker_sk".to_owned()))?;
    let (oracle_keys, _) = signers.sorted_oracles()?;
    let funding_script = derive_funding_script(&trader_key, &maker_key, refund_csv)?;

    let mut cid_in = Vec::with_capacity(96);
    cid_in.extend_from_slice(channel_tag);
    cid_in.extend_from_slice(&funding_txid);
    cid_in.extend_from_slice(&funding_vout.to_le_bytes());
    cid_in.extend_from_slice(&assertion_txid);
    let contract_id = tagged_hash("shz-mnr03-row-contract", &cid_in);

    let mut summary = DlcSummary {
        salt: tagged_hash("shz-mnr03-row-salt", &contract_id),
        contract_id,
        plan_digest: tagged_hash("shz-mnr03-assertion-plan", &assertion_txid),
        recovery_digest,
        funding_txid,
        funding_vout,
        collateral_sats,
        funding_script,
        trader_key,
        maker_key,
        trader_script: signers.trader_script,
        maker_script: signers.maker_script,
        anchor_script: signers.anchor_script,
        oracle_keys,
        oracle_event_id,
        outcome_root: [0u8; 32],
        outcome_count: 1,
        maturity_height,
        refund_height,
        refund_csv,
    };

    let mut msg_in = Vec::with_capacity(48);
    msg_in.extend_from_slice(&contract_id);
    msg_in.extend_from_slice(&settled_price_usd.to_le_bytes());
    msg_in.extend_from_slice(&oracle_event_id);
    let outcomes = vec![Outcome {
        index: 0,
        message: tagged_hash("shz-mnr03-pyth-outcome", &msg_in),
        trader_sats: trader_out_sats,
        maker_sats: maker_out_sats,
        anchor_sats,
        fee_sats,
    }];
    let (outcome_root, outcome_siblings) = outcome_root_and_path(&summary, &outcomes, 0)?;
    summary.outcome_root = outcome_root;

    Ok(Row {
        summary,
        summary_signatures: [[0; 64]; 2],
        outcome: outcomes[0].clone(),
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

/// Re-verifies a raw Pyth Pro Ed25519 Solana envelope, executes `SHZ-MNR-03` 3-party Bob-offline
/// atomic clearing (`bob_sk` 100% absent!), and builds a natively verified 3-row `LNMBAT01`
/// `BatchWitness` + `304B` `UtxoRefL2SettlementStatementV0` bound to `pyth_receipt.receipt_hash`,
/// `session_hash`, and `mnr03_atomic_clearing_txid`.
#[allow(clippy::too_many_arguments)]
pub fn build_oracle_bound_mnr03_nova_ceremony(
    orig: &Mnr03OriginationBundle,
    selected_outcome_idx: usize,
    oracle_scalar_t: &Scalar,
    pyth_solana_envelope_bytes: &[u8],
    pyth_registry: &PinnedPythSignerRegistry,
    pyth_policy: &PythProBtcUsdPolicy,
    pyth_now_us: u64,
    alice_sk: &[u8; 32],
    carol_sk: &[u8; 32],
    guard_sk: &[u8; 32],
    batch_oracle_sks: [[u8; 32]; 3],
    network_code: BitcoinNetworkCode,
    anchor_height: u64,
    anchor_block_hash_hex: &str,
    epoch_id: u64,
) -> Result<OracleBoundMnr03NovaArtifacts> {
    // 1. Re-verify the native Pyth Pro Ed25519 Solana envelope from raw bytes!
    let pyth_receipt = verify_pyth_pro_btc_usd_solana_envelope(
        pyth_solana_envelope_bytes,
        pyth_registry,
        pyth_policy,
        pyth_now_us,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("Pyth Pro verification failed: {e}")))?;

    let network_label = match network_code {
        BitcoinNetworkCode::Regtest => "bitcoin-regtest",
        BitcoinNetworkCode::Testnet4 => "bitcoin-testnet4",
    };

    // 2. Assemble the 3-input, 5-output `SHZ-MNR-03` atomic clearing tx WITHOUT `bob_sk`!
    let mnr03_assembled = assemble_mnr03_bob_offline_three_party_clearing(
        orig,
        selected_outcome_idx,
        oracle_scalar_t,
        alice_sk,
        carol_sk,
        guard_sk,
        network_label,
    )
    .map_err(|e| NovaBitvmError::Bridge(format!("MNR-03 clearing failed: {e}")))?;

    if pyth_receipt.whole_price_usd != mnr03_assembled.receipt.settled_price_usd {
        return Err(NovaBitvmError::Bridge(format!(
            "Pyth Pro whole_price_usd ({}) != MNR-03 settled_price_usd ({})",
            pyth_receipt.whole_price_usd, mnr03_assembled.receipt.settled_price_usd
        )));
    }

    let anchor_hash = hex_to_hash32(anchor_block_hash_hex)?;
    let assertion_txid = hex_to_hash32(&mnr03_assembled.receipt.atomic_clearing_txid_hex)?;

    // 3. Compute immutable `session_hash` binding Pyth Pro provenance + MNR-03 clearing txid + L1 anchor!
    let mut sess_in = Vec::with_capacity(144);
    sess_in.extend_from_slice(&epoch_id.to_le_bytes());
    sess_in.extend_from_slice(&pyth_receipt.receipt_hash);
    sess_in.extend_from_slice(&pyth_receipt.signed_payload_sha256);
    sess_in.extend_from_slice(&assertion_txid);
    sess_in.extend_from_slice(&anchor_hash);
    let session_hash = tagged_hash("SHZ/MNR03-ORACLE-CLEARING-EPOCH/V1", &sess_in);

    // 4. Construct the 3 online-authorized `LNMBAT01` Nova witness rows (`bob_sk` 100% absent!):
    //    - Row AB: signed by `(alice_sk, guard_sk)`
    //    - Row BC: signed by `(carol_sk, guard_sk)`
    //    - Row CA: signed by `(carol_sk, alice_sk)`
    let alice_script = vec_spk_to_script34(&orig.alice_spk)?;
    let bob_script = vec_spk_to_script34(&orig.bob_spk)?;
    let carol_script = vec_spk_to_script34(&orig.carol_spk)?;
    let anchor_script = vec_spk_to_script34(&orig.anchor_spk)?;

    let ab_signers = BridgeSignerMaterial {
        trader_sk: *alice_sk,
        maker_sk: *guard_sk,
        oracle_sks: batch_oracle_sks,
        trader_script: alice_script,
        maker_script: bob_script,
        anchor_script,
    };
    let bc_signers = BridgeSignerMaterial {
        trader_sk: *carol_sk,
        maker_sk: *guard_sk,
        oracle_sks: batch_oracle_sks,
        trader_script: carol_script,
        maker_script: bob_script,
        anchor_script,
    };
    let ca_signers = BridgeSignerMaterial {
        trader_sk: *carol_sk,
        maker_sk: *alice_sk,
        oracle_sks: batch_oracle_sks,
        trader_script: carol_script,
        maker_script: alice_script,
        anchor_script,
    };

    let ab_pre = &orig.ab_leg.outcomes[selected_outcome_idx];
    let bc_pre = &orig.bc_leg.outcomes[selected_outcome_idx];

    let ab_txid = hex_to_hash32(&orig.ab_leg.funding_txid_display)?;
    let bc_txid = hex_to_hash32(&orig.bc_leg.funding_txid_display)?;
    let ca_txid = hex_to_hash32(&orig.ca_funding_txid_display)?;

    let row_ab = build_online_authorized_clearing_row(
        b"MNR03-AB",
        ab_txid,
        orig.ab_leg.funding_vout,
        orig.ab_leg.funding_sats,
        ab_pre.counterparty_unilateral_sats,
        ab_pre.bob_pinned_sats,
        330,
        orig.params.unilateral_fee_sats,
        pyth_receipt.whole_price_usd,
        orig.params.maturity_height,
        orig.ab_leg.tree.refund_cltv_height,
        orig.params.ca_refund_csv,
        pyth_receipt.receipt_hash,
        assertion_txid,
        tagged_hash(
            "shz-mnr03-ab-refund",
            &orig.ab_leg.signed_refund_tx.serialize_unsigned(),
        ),
        &ab_signers,
    )?;

    let row_bc = build_online_authorized_clearing_row(
        b"MNR03-BC",
        bc_txid,
        orig.bc_leg.funding_vout,
        orig.bc_leg.funding_sats,
        bc_pre.counterparty_unilateral_sats,
        bc_pre.bob_pinned_sats,
        330,
        orig.params.unilateral_fee_sats,
        pyth_receipt.whole_price_usd,
        orig.params.maturity_height,
        orig.bc_leg.tree.refund_cltv_height,
        orig.params.ca_refund_csv,
        pyth_receipt.receipt_hash,
        assertion_txid,
        tagged_hash(
            "shz-mnr03-bc-refund",
            &orig.bc_leg.signed_refund_tx.serialize_unsigned(),
        ),
        &bc_signers,
    )?;

    let ca_fee = orig.params.unilateral_fee_sats;
    let ca_dist = orig
        .ca_funding_sats
        .checked_sub(330 + ca_fee)
        .ok_or_else(|| NovaBitvmError::Bridge("CA collateral < 330 + fee".to_owned()))?;
    let ca_carol = ca_dist / 2;
    let ca_alice = ca_dist - ca_carol;

    let row_ca = build_online_authorized_clearing_row(
        b"MNR03-CA",
        ca_txid,
        orig.ca_funding_vout,
        orig.ca_funding_sats,
        ca_carol,
        ca_alice,
        330,
        ca_fee,
        pyth_receipt.whole_price_usd,
        orig.params.maturity_height,
        orig.ab_leg.tree.refund_cltv_height,
        orig.params.ca_refund_csv,
        pyth_receipt.receipt_hash,
        assertion_txid,
        tagged_hash("shz-mnr03-ca-refund", &orig.ca_tree.refund_leaf_hash),
        &ca_signers,
    )?;

    let mut smt = SparseNullifierTree::new();
    let eval_height = orig.params.maturity_height;
    let valid_until = orig.ab_leg.tree.unilateral_cltv_height;
    let (batch_witness, journal) = assemble_and_sign_bridged_batch(
        vec![
            (row_ab, ab_signers),
            (row_bc, bc_signers),
            (row_ca, ca_signers),
        ],
        &mut smt,
        epoch_id,
        session_hash,
        eval_height,
        valid_until,
    )?;

    // Canonical binary LNMBAT01 roundtrip check
    let batch_witness_bytes = encode_batch(&batch_witness)?;
    let decoded = decode_batch(&batch_witness_bytes)?;
    let re_journal = verify_batch(&decoded)?;
    if re_journal != journal {
        return Err(NovaBitvmError::Bridge(
            "LNMBAT01 roundtrip journal mismatch".to_owned(),
        ));
    }

    // Nova v2 600B transcripts + 8-field expected pins + 18 Secq BIP-340 claims
    let (_, transcripts, nova_expected_statement) =
        NovaExpectedStatement::from_verified_batch(&batch_witness)?;
    let row_transcripts_600b_hex: Vec<String> = transcripts
        .iter()
        .map(|t| {
            debug_assert_eq!(t.len(), NOVA_TRANSCRIPT_LEN);
            hex::encode(t)
        })
        .collect();

    let mut secq_claims_verified_count = 0usize;
    for row in &batch_witness.rows {
        let claims = build_and_verify_all_6_row_claims(&batch_witness.context, row)?;
        secq_claims_verified_count += claims.len();
    }

    // 5. Build 304B `UtxoRefL2SettlementStatementV0` binding `assertion_txid == mnr03_clearing_txid`
    //    and `policy_hash` committing to `pyth_receipt.receipt_hash || session_hash || anchor_hash`!
    let genesis_hex = match network_code {
        BitcoinNetworkCode::Testnet4 => BITCOIN_TESTNET4_GENESIS_HASH_HEX,
        _ => BITCOIN_REGTEST_GENESIS_HASH_HEX,
    };
    let chain_genesis = hex_to_hash32(genesis_hex)?;
    let vk_hash = hex_to_hash32(LNM_NOVA_V2_VK_SHA256_HEX)?;
    let program_hash = tagged_hash("shz-mnr03-nova-program", b"lnmarkets-batch-nova-v2-mnr03");

    let mut policy_in = Vec::with_capacity(104);
    policy_in.extend_from_slice(&pyth_receipt.receipt_hash);
    policy_in.extend_from_slice(&session_hash);
    policy_in.extend_from_slice(&anchor_hash);
    policy_in.extend_from_slice(&anchor_height.to_le_bytes());
    let policy_hash = tagged_hash("shz-mnr03-pyth-policy", &policy_in);

    let bitvm3_stmt = build_bitvm3_settlement_statement(
        network_code,
        chain_genesis,
        &batch_witness.rows[0],
        &journal,
        assertion_txid,
        0,
        program_hash,
        vk_hash,
        policy_hash,
    )?;
    let bitvm3_statement = bitvm3_stmt.to_json_record();

    let honesty = VerificationHonestyFlags::native_only();
    let report = OracleBoundMnr03NovaReport {
        protocol: "SatsHedgeZero SHZ-MNR-03 + Native Pyth Pro + Nova v2 / BitVM3".to_owned(),
        network: network_label.to_owned(),
        anchor_height,
        anchor_block_hash_hex: anchor_block_hash_hex.to_owned(),
        bob_online_during_clearing_or_proving: false,
        pyth_pro_epoch: BoundPythProEpochSummary {
            feed_id: pyth_receipt.feed_id,
            channel_id: pyth_receipt.channel_id,
            publish_time_us: pyth_receipt.publish_time_us,
            feed_update_time_us: pyth_receipt.feed_update_time_us,
            price_e8: pyth_receipt.raw_price_mantissa,
            whole_price_usd: pyth_receipt.whole_price_usd,
            confidence_e8: pyth_receipt.confidence_mantissa as u64,
            registry_epoch: pyth_receipt.registry_epoch,
            signer_pubkey_hex: pyth_receipt.signer_pubkey_hex.clone(),
            signed_payload_sha256_hex: hex::encode(pyth_receipt.signed_payload_sha256),
            receipt_hash_hex: hex::encode(pyth_receipt.receipt_hash),
            session_hash_hex: hex::encode(session_hash),
            near_finality_verified: false,
        },
        mnr03_clearing: mnr03_assembled.receipt.clone(),
        mnr03_atomic_clearing_raw_segwit_tx_hex: hex::encode(
            mnr03_assembled.signed_clearing_tx.serialize_segwit(),
        ),
        batch_witness_bytes_len: batch_witness_bytes.len(),
        journal: JournalSummaryJson::from_journal(&journal),
        row_transcripts_600b_hex,
        nova_expected_statement,
        secq_claims_verified_count,
        bitvm3_statement,
        external_nova_snark_receipt: None,
        honesty,
    };

    Ok(OracleBoundMnr03NovaArtifacts {
        pyth_receipt,
        session_hash,
        mnr03_assembled,
        batch_witness,
        batch_witness_bytes,
        journal,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{
        ProjectivePoint,
        elliptic_curve::{bigint::U256, ops::Reduce},
    };
    use shz_oracle::pyth_lazer::{
        PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS,
        build_signed_pyth_pro_btc_usd_envelope,
    };
    use shz_utxoref::mnr03::{Mnr03ScaleParams, build_mnr03_bob_offline_origination};

    fn p2tr_vec(seed: u8) -> Vec<u8> {
        let pk = pubkey_x_from_secret(&[seed; 32]).unwrap();
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&pk);
        v
    }

    #[test]
    fn test_oracle_bound_mnr03_nova_ceremony_with_bob_offline_and_tamper_rejection() {
        let alice_sk = [0x11u8; 32];
        let carol_sk = [0x23u8; 32];
        let guard_sk = [0x24u8; 32];
        let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();
        let batch_oracles = [[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]];

        let t_60k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(60_000));
        let params = Mnr03ScaleParams::macro_regtest_33k(150);

        // `bob_sk` exists ONLY inside this origination block!
        let orig = {
            let bob_sk_ephemeral = [0x22u8; 32];
            build_mnr03_bob_offline_origination(
                &params,
                &alice_sk,
                &bob_sk_ephemeral,
                &carol_sk,
                guard_pk,
                [(&"01".repeat(32), 0), (&"02".repeat(32), 0), (&"03".repeat(32), 0)],
                p2tr_vec(0x41),
                p2tr_vec(0x42),
                p2tr_vec(0x43),
                p2tr_vec(0x44),
                &[(60_000, ProjectivePoint::GENERATOR * t_60k)],
            )
            .unwrap()
        };

        // Native Pyth Pro Ed25519 envelope attesting $60,000.00000000
        let pyth_sk = [0x88u8; 32];
        let (pyth_env, pyth_pk) = build_signed_pyth_pro_btc_usd_envelope(
            &pyth_sk,
            1_795_500_000_000_000,
            1_795_500_000_000_000,
            PYTH_PRO_CHANNEL_FIXED_200MS,
            PYTH_PRO_BTC_USD_FEED_ID,
            6_000_000_000_000, // $60,000 * 1e8
            -8,
            1_200_000_000,
        );
        let reg = PinnedPythSignerRegistry::new_static(vec![pyth_pk]).unwrap();

        let artifacts = build_oracle_bound_mnr03_nova_ceremony(
            &orig,
            0,
            &t_60k,
            &pyth_env,
            &reg,
            &PythProBtcUsdPolicy::default(),
            1_795_500_001_000_000,
            &alice_sk,
            &carol_sk,
            &guard_sk,
            batch_oracles,
            BitcoinNetworkCode::Regtest,
            150,
            BITCOIN_REGTEST_GENESIS_HASH_HEX,
            7,
        )
        .unwrap();

        assert!(!artifacts.report.bob_online_during_clearing_or_proving);
        assert_eq!(artifacts.report.journal.row_count, 3);
        assert_eq!(artifacts.report.secq_claims_verified_count, 18);
        assert_eq!(
            artifacts.report.bitvm3_statement.assertion_txid_hex,
            artifacts.report.mnr03_clearing.atomic_clearing_txid_hex
        );
        assert_eq!(
            artifacts.report.journal.batch_id_hex,
            artifacts.report.pyth_pro_epoch.session_hash_hex
        );
        assert!(!artifacts.report.pyth_pro_epoch.near_finality_verified);
        assert!(!artifacts.report.honesty.production_ready);

        // Wrong Pyth price ($61,000 vs $60,000 clearing mark) MUST fail closed!
        let (wrong_price_env, _) = build_signed_pyth_pro_btc_usd_envelope(
            &pyth_sk,
            1_795_500_000_000_000,
            1_795_500_000_000_000,
            PYTH_PRO_CHANNEL_FIXED_200MS,
            PYTH_PRO_BTC_USD_FEED_ID,
            6_100_000_000_000,
            -8,
            1_200_000_000,
        );
        assert!(
            build_oracle_bound_mnr03_nova_ceremony(
                &orig,
                0,
                &t_60k,
                &wrong_price_env,
                &reg,
                &PythProBtcUsdPolicy::default(),
                1_795_500_001_000_000,
                &alice_sk,
                &carol_sk,
                &guard_sk,
                batch_oracles,
                BitcoinNetworkCode::Regtest,
                150,
                BITCOIN_REGTEST_GENESIS_HASH_HEX,
                7,
            )
            .is_err()
        );
    }
}
