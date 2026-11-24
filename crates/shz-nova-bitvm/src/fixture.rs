//! Deterministic public test fixtures for `lnm-batch-statement`.
//!
//! Ported from MIT `lnm-batch-statement` (`patrickdugan/zk-rusto-no-bitcoino` @ `f6a8d12`).
//! These values are public test material only; they supply no deployed wallet, oracle, or UTXO.

use k256::schnorr::SigningKey;

use crate::error::{NovaBitvmError, Result};
use crate::merkle::{SparseNullifierTree, accepted_contracts_root, outcome_root_and_path};
use crate::statement::{
    BatchContext, BatchWitness, DlcSummary, Hash, JournalPins, MAX_ROWS, OracleAttestation,
    Outcome, Row, Script, Sig, batch_consent_message, oracle_message, outpoint_nullifier, sha256,
    summary_digest, tagged_hash, unsigned_batch_transaction,
};
use crate::taproot::derive_funding_script;

fn key(number: u32) -> SigningKey {
    let mut bytes = [0; 32];
    bytes[28..].copy_from_slice(&number.to_be_bytes());
    SigningKey::from_bytes(&bytes).expect("small nonzero fixture scalar")
}

pub fn fixture_pubkey(number: u32) -> Hash {
    key(number).verifying_key().to_bytes().into()
}

pub fn fixture_sign(number: u32, digest: &Hash) -> Sig {
    key(number)
        .sign_raw(digest, &[0; 32])
        .expect("valid fixed fixture signing input")
        .to_bytes()
}

pub fn fixture_p2tr_script(number: u32) -> Script {
    let mut result = [0; 34];
    result[..2].copy_from_slice(&[0x51, 0x20]);
    result[2..].copy_from_slice(&fixture_pubkey(number));
    result
}

pub fn fixture_hash(label: &str, index: usize) -> Hash {
    tagged_hash("known-fixture", format!("{label}:{index}").as_bytes())
}

fn secret_number(public: &Hash) -> Result<u32> {
    for number in [11, 12, 31, 32, 33] {
        if fixture_pubkey(number) == *public {
            return Ok(number);
        }
    }
    Err(NovaBitvmError::Statement(
        "key is outside the known fixture key set".to_owned(),
    ))
}

/// Refresh fixture application signatures without repairing altered roots, transactions,
/// payouts, paths, or context. Useful for adversarial tests that must reach later constraints.
pub fn resign_batch(batch: &mut BatchWitness) -> Result<()> {
    for row in &mut batch.rows {
        let s = &row.summary;
        let digest = summary_digest(s);
        row.summary_signatures = [
            fixture_sign(secret_number(&s.trader_key)?, &digest),
            fixture_sign(secret_number(&s.maker_key)?, &digest),
        ];
        let consent = batch_consent_message(&batch.context, s);
        row.batch_signatures = [
            fixture_sign(secret_number(&s.trader_key)?, &consent),
            fixture_sign(secret_number(&s.maker_key)?, &consent),
        ];
        let message = oracle_message(s, &row.outcome);
        for attestation in &mut row.oracle_attestations {
            if attestation.oracle_index >= 3 {
                return Err(NovaBitvmError::Statement(
                    "fixture oracle index out of range".to_owned(),
                ));
            }
            let public = &s.oracle_keys[attestation.oracle_index as usize];
            attestation.signature = fixture_sign(secret_number(public)?, &message);
        }
    }
    Ok(())
}

pub fn demo_batch(count: usize) -> Result<BatchWitness> {
    if count == 0 || count > MAX_ROWS {
        return Err(NovaBitvmError::Statement(
            "fixture row count must be in 1..32".to_owned(),
        ));
    }
    let mut oracle_keys = [fixture_pubkey(31), fixture_pubkey(32), fixture_pubkey(33)];
    oracle_keys.sort();
    let funding_script = derive_funding_script(&fixture_pubkey(11), &fixture_pubkey(12), 144)?;
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let mut summary = DlcSummary {
            salt: fixture_hash("salt", index),
            contract_id: fixture_hash("contract", index),
            plan_digest: fixture_hash("plan", index),
            recovery_digest: fixture_hash("recovery", index),
            funding_txid: fixture_hash("synthetic-funding", index),
            funding_vout: 0,
            collateral_sats: 401_330,
            funding_script,
            trader_key: fixture_pubkey(11),
            maker_key: fixture_pubkey(12),
            trader_script: fixture_p2tr_script(21),
            maker_script: fixture_p2tr_script(22),
            anchor_script: fixture_p2tr_script(23),
            oracle_keys,
            oracle_event_id: fixture_hash("oracle-event", index),
            outcome_root: [0; 32],
            outcome_count: 3,
            maturity_height: 1000,
            refund_height: 1200,
            refund_csv: 144,
        };
        // Payouts mirror the UTXORef LNMarkets example: USD 1,000 inverse long
        // entered at USD 100,000, with USD 90k/100k/110k enumerated outcomes.
        let payouts = [(88_889, 311_111), (200_000, 200_000), (290_909, 109_091)];
        let outcomes: Vec<_> = payouts
            .iter()
            .enumerate()
            .map(|(outcome_index, (trader, maker))| Outcome {
                index: outcome_index as u32,
                message: fixture_hash(&format!("outcome-{index}"), outcome_index),
                trader_sats: *trader,
                maker_sats: *maker,
                anchor_sats: 330,
                fee_sats: 1000,
            })
            .collect();
        let selected = index % outcomes.len();
        let (root, path) = outcome_root_and_path(&summary, &outcomes, selected)?;
        summary.outcome_root = root;
        rows.push(Row {
            summary,
            summary_signatures: [[0; 64]; 2],
            outcome: outcomes[selected].clone(),
            outcome_siblings: path,
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
        });
    }
    rows.sort_by_key(|row| (row.summary.funding_txid, row.summary.funding_vout));
    let accepted_root = accepted_contracts_root(&rows)?;
    let mut tree = SparseNullifierTree::new();
    let old_root = tree.root();
    for row in &mut rows {
        let nullifier = outpoint_nullifier(&row.summary);
        row.nullifier_siblings = tree.proof(&nullifier);
        tree.insert(&nullifier)?;
    }
    let transaction = unsigned_batch_transaction(&rows)?;
    let context = BatchContext {
        epoch: 1,
        batch_id: fixture_hash("batch-id", count),
        evaluation_height: 1010,
        valid_until_height: 1100,
        accepted_contracts_root: accepted_root,
        old_nullifier_root: old_root,
        new_nullifier_root: tree.root(),
        batch_tx_digest: sha256(&transaction),
        row_count: count as u32,
    };
    let mut witness = BatchWitness { context, rows };
    resign_batch(&mut witness)?;
    Ok(witness)
}

pub fn journal_pins(context: &BatchContext) -> JournalPins {
    JournalPins {
        epoch: context.epoch,
        batch_id: context.batch_id,
        evaluation_height: context.evaluation_height,
        valid_until_height: context.valid_until_height,
        row_count: context.row_count,
        accepted_contracts_root: context.accepted_contracts_root,
        old_nullifier_root: context.old_nullifier_root,
        batch_tx_digest: context.batch_tx_digest,
    }
}
