//! Durable reservation book guards: replay sets come from the book's own durable state,
//! confirmation is bound to the reserved snapshot, and every rejection leaves the book
//! byte-identical. Synthetic outpoints only.
use shz_dlc::BtcOutPoint;
use shz_margin::CollateralAsset;
use shz_utxoref::UtxoRefError;
use shz_utxoref::pnl_batch::*;

fn op(b: u8) -> BtcOutPoint { BtcOutPoint { txid: [b; 32], vout: 0 } }
fn vault(id: &str, utxo: u8, sats: u64) -> VaultRecord {
    VaultRecord { id: id.into(), netting_set_id: "ns".into(), change_script_pubkey: vec![0x51, 0x20], fee_sats: 0, protected_sats: 0,
        utxos: vec![FundedVaultUtxo { outpoint: op(utxo), sats, script_pubkey: vec![0x51, 0x20] }] }
}
fn account(id: &str, vault: &str, equity: u64) -> AccountRecord {
    AccountRecord { id: id.into(), netting_set_id: "ns".into(), vault_id: vault.into(), equity_sats: equity, locked_sats: 0, payout_sats: 0, payout_script_pubkey: None }
}
/// Two vaults (one UTXO each), two accounts, one obligation a -> b; b's vault retains it via a route.
fn snap(epoch: u64, prev: [u8; 32], utxos: (u8, u8), ob: &str, spent: Vec<BtcOutPoint>, consumed: Vec<String>) -> PnlBatchSnapshotV1 {
    PnlBatchSnapshotV1 {
        network: "regtest".into(), epoch_id: epoch, previous_state_root: prev,
        netting_sets: vec![NettingSetSpec { id: "ns".into(), collateral: CollateralAsset::VanillaBtc }],
        vaults: vec![vault("va", utxos.0, 50_000), vault("vb", utxos.1, 50_000)],
        accounts: vec![account("a", "va", 50_000), account("b", "vb", 50_000)],
        obligations: vec![RealizedObligation { id: ob.into(), netting_set_id: "ns".into(), from_account_id: "a".into(), to_account_id: "b".into(), sats: 1_000 }],
        consumed_obligation_ids: consumed, spent_outpoints: spent,
        routes: vec![PermittedRoute { from_vault_id: "va".into(), to_target: RouteTarget::Vault("vb".into()), capacity_sats: 10_000 }],
    }
}
fn dump(b: &DurablePnlBatchBook) -> String { serde_json::to_string(b).unwrap() }
fn settle(book: &mut DurablePnlBatchBook, s: &PnlBatchSnapshotV1, txid: &str) {
    let h = book.reserve_before_signing(&book.head_hash.clone(), s).unwrap();
    let h = book.record_signed_outcome(&h, Ok((txid.into(), vec![2, 0]))).unwrap();
    book.confirm_active_chain(&h, txid, s).unwrap();
}
fn epoch1() -> (DurablePnlBatchBook, PnlBatchSnapshotV1) {
    let mut book = DurablePnlBatchBook::new_genesis("guards", [0xAB; 32]);
    let s1 = snap(1, [0xAB; 32], (1, 2), "o1", vec![], vec![]);
    settle(&mut book, &s1, "aa");
    (book, s1)
}

#[test]
fn reservation_checks_inputs_against_the_books_spent_outpoints() {
    let (mut book, _) = epoch1();
    assert_eq!(book.spent_outpoints, vec![op(1), op(2)]);
    let before = dump(&book);
    // Epoch 2 reuses epoch-1 UTXO 1; the caller's snapshot omits it from its replay set.
    let s2 = snap(2, book.ledger_state_root, (1, 3), "o2", vec![], vec!["o1".into()]);
    let r = book.reserve_before_signing(&book.head_hash.clone(), &s2);
    assert_eq!(r, Err(UtxoRefError::ReplayDetected("vault UTXO already spent in book")));
    assert_eq!(dump(&book), before, "rejection mutates nothing");
    // Same with the full history in the snapshot (the solver rejects it too).
    let s2 = snap(2, book.ledger_state_root, (1, 3), "o2", vec![op(1), op(2)], vec!["o1".into()]);
    assert!(matches!(book.reserve_before_signing(&book.head_hash.clone(), &s2), Err(UtxoRefError::ReplayDetected(_))));
    assert_eq!(dump(&book), before);
}

#[test]
fn reservation_requires_the_snapshot_to_carry_the_books_history() {
    let (mut book, _) = epoch1();
    let before = dump(&book);
    for (spent, consumed) in [(vec![], vec!["o1".to_string()]), (vec![op(1), op(2)], vec![]), (vec![op(1)], vec!["o1".into()])] {
        let s2 = snap(2, book.ledger_state_root, (3, 4), "o2", spent, consumed);
        assert_eq!(book.reserve_before_signing(&book.head_hash.clone(), &s2),
            Err(UtxoRefError::ReplayDetected("snapshot replay sets omit the book's settled history")));
        assert_eq!(dump(&book), before);
    }
    // Obligation replay is still caught from the book.
    let s2 = snap(2, book.ledger_state_root, (3, 4), "o1", vec![op(1), op(2)], vec![]);
    assert_eq!(book.reserve_before_signing(&book.head_hash.clone(), &s2), Err(UtxoRefError::ReplayDetected("obligation already settled in book")));
    assert_eq!(dump(&book), before);
    // Fresh UTXOs with the full history settle.
    let s2 = snap(2, book.ledger_state_root, (3, 4), "o2", vec![op(1), op(2)], vec!["o1".into()]);
    settle(&mut book, &s2, "bb");
    assert_eq!((book.last_settled_epoch, book.spent_outpoints.len(), book.consumed_obligation_ids.len()), (2, 4, 2));
}

#[test]
fn confirmation_is_bound_to_the_reserved_snapshot() {
    let mut book = DurablePnlBatchBook::new_genesis("guards", [0xAB; 32]);
    let s1 = snap(1, [0xAB; 32], (1, 2), "o1", vec![], vec![]);
    let h = book.reserve_before_signing(&book.head_hash.clone(), &s1).unwrap();
    let h = book.record_signed_outcome(&h, Ok(("aa".into(), vec![2, 0]))).unwrap();
    let before = dump(&book);
    // A different snapshot (other obligation, other UTXOs) would mark the wrong replay sets.
    let other = snap(1, [0xAB; 32], (7, 8), "evil", vec![], vec![]);
    assert_eq!(book.confirm_active_chain(&h, "aa", &other), Err(UtxoRefError::SnapshotMismatch));
    assert_eq!(dump(&book), before, "substituted snapshot rejected without mutation");
    // A substituted snapshot with the wrong txid is still rejected without freezing.
    assert_eq!(book.confirm_active_chain(&h, "zz", &other), Err(UtxoRefError::SnapshotMismatch));
    assert_eq!(dump(&book), before);
    book.confirm_active_chain(&h, "aa", &s1).unwrap();
    assert!(book.consumed_obligation_ids.contains("o1") && !book.consumed_obligation_ids.contains("evil"));
    assert_eq!(book.spent_outpoints, vec![op(1), op(2)]);
    // Wrong txid with the right snapshot freezes, as before.
    let s2 = snap(2, book.ledger_state_root, (3, 4), "o2", vec![op(1), op(2)], vec!["o1".into()]);
    let h = book.reserve_before_signing(&book.head_hash.clone(), &s2).unwrap();
    let h = book.record_signed_outcome(&h, Ok(("bb".into(), vec![2, 0]))).unwrap();
    assert_eq!(book.confirm_active_chain(&h, "cc", &s2), Err(UtxoRefError::BookFrozen));
    assert!(matches!(book.state, BookAuthState::Frozen { .. }));
    assert_eq!(book.spent_outpoints.len(), 2);
}

#[test]
fn restart_at_every_state_resumes_identically() {
    let s1 = snap(1, [0xAB; 32], (1, 2), "o1", vec![], vec![]);
    let restart = |b: &DurablePnlBatchBook| -> DurablePnlBatchBook { serde_json::from_str(&dump(b)).unwrap() };
    let mut live = DurablePnlBatchBook::new_genesis("guards", [0xAB; 32]);
    let mut book = restart(&live);
    let h = book.reserve_before_signing(&book.head_hash.clone(), &s1).unwrap();
    let mut book = restart(&book);
    let h = book.record_signed_outcome(&h, Ok(("aa".into(), vec![2, 0]))).unwrap();
    let mut book = restart(&book);
    // The restarted book still binds confirmation to the reserved snapshot.
    assert_eq!(book.confirm_active_chain(&h, "aa", &snap(1, [0xAB; 32], (7, 8), "x", vec![], vec![])), Err(UtxoRefError::SnapshotMismatch));
    book.confirm_active_chain(&h, "aa", &s1).unwrap();
    settle(&mut live, &s1, "aa");
    assert_eq!(dump(&restart(&book)), dump(&live));
    // After restart the spent set still guards reservation.
    let mut book = restart(&book);
    let s2 = snap(2, book.ledger_state_root, (2, 3), "o2", vec![], vec!["o1".into()]);
    assert_eq!(book.reserve_before_signing(&book.head_hash.clone(), &s2), Err(UtxoRefError::ReplayDetected("vault UTXO already spent in book")));
}

#[test]
fn concurrent_reservations_admit_exactly_one() {
    let (book, _) = epoch1();
    let head = book.head_hash;
    let a = snap(2, book.ledger_state_root, (3, 4), "o2", vec![op(1), op(2)], vec!["o1".into()]);
    let b = snap(2, book.ledger_state_root, (5, 6), "o3", vec![op(1), op(2)], vec!["o1".into()]);
    // Two writers race on the same expected head against one durable book.
    let mut shared = book.clone();
    shared.reserve_before_signing(&head, &a).unwrap();
    let after_a = dump(&shared);
    assert_eq!(shared.reserve_before_signing(&head, &b), Err(UtxoRefError::HeadHashMismatch));
    assert_eq!(shared.reserve_before_signing(&shared.head_hash.clone(), &b), Err(UtxoRefError::ReservationActive));
    assert_eq!(dump(&shared), after_a);
    let BookAuthState::ReservedBeforeSigning { snapshot_hash, .. } = &shared.state else { panic!() };
    assert_eq!(*snapshot_hash, a.snapshot_hash());
}

#[test]
fn reorg_freeze_blocks_reservation_and_confirmation() {
    let mut book = DurablePnlBatchBook::new_genesis("guards", [0xAB; 32]);
    let s1 = snap(1, [0xAB; 32], (1, 2), "o1", vec![], vec![]);
    let h = book.reserve_before_signing(&book.head_hash.clone(), &s1).unwrap();
    let _ = book.record_signed_outcome(&h, Ok(("aa".into(), vec![2, 0]))).unwrap();
    book.freeze_on_reorg("reorg below the clearing block");
    let frozen = dump(&book);
    assert_eq!(book.confirm_active_chain(&book.head_hash.clone(), "aa", &s1), Err(UtxoRefError::InvalidBookTransition));
    assert_eq!(book.reserve_before_signing(&book.head_hash.clone(), &s1), Err(UtxoRefError::BookFrozen));
    assert_eq!(dump(&book), frozen);
    assert!(book.spent_outpoints.is_empty() && book.consumed_obligation_ids.is_empty() && book.last_settled_epoch == 0);
}
