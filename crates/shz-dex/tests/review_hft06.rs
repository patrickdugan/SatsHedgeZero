//! HFT-06 security review reproductions against 20a8edc (Lightning fee ledger).

use shz_dex::routing::ln_fees::*;
use shz_dlc::pubkey_x_from_secret;
use std::fs;

fn pk(n: u8) -> [u8; 32] {
    pubkey_x_from_secret(&[n; 32]).unwrap()
}
fn rpolicy() -> RecipientPolicy {
    RecipientPolicy { version: 1, oracle_operators: vec![(pk(1), 1), (pk(2), 1)], upkeep: (pk(3), 1000), router: pk(4) }
}
fn group() -> GroupCommit {
    GroupCommit { max_obligations: 1000, max_delay_us: 10 }
}

/// F-08: the fee WAL is hash-chained, so a torn or edited tail fails closed, but a file
/// cut back at a frame boundary (restored backup, rolled-back volume) is a valid prefix.
/// `FeeLedger::open` has no pinned tip, unlike `DurableTieredRouter::open_pinned`, so the
/// rollback is accepted and the already-instructed obligations are emitted a second time.
#[test]
fn rolled_back_fee_journal_does_not_reissue_settlement_instructions() {
    let dir = std::env::temp_dir().join(format!("shz-review-fees-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fees.wal");
    let pin;
    let first = {
        let mut l = FeeLedger::create(&path, 1, rpolicy(), group()).unwrap();
        l.record(LedgerEvent::Accrue { sequence: 1, digest: [5; 32], oracle_due: 7_000, router_due: 3_000 }).unwrap();
        l.record(LedgerEvent::Commit { sequence: 1, digest: [5; 32], fee_evidence: vec![], at_us: 100 }).unwrap();
        let before_instruct = fs::metadata(&path).unwrap().len();
        let first = l.poll(1_000).unwrap();
        assert!(!first.is_empty(), "instructions were emitted and journaled");
        pin = Some(l.tip());
        drop(l);
        // Roll the journal back by exactly one frame (the Instruct record).
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..before_instruct as usize]).unwrap();
        first
    };
    let reopened = FeeLedger::open_pinned(&path, 1, rpolicy(), group(), pin);
    let reissued = match reopened {
        Err(LedgerError::Rollback) => Vec::new(), // rollback below the pinned tip detected
        Err(e) => panic!("unexpected error {e}"),
        Ok(mut l) => l.poll(2_000).unwrap(),
    };
    let _ = fs::remove_dir_all(&dir);
    assert!(
        reissued.is_empty(),
        "after a one-frame rollback the ledger re-emitted {} settlement instructions totalling {} sats (first emission: {} sats)",
        reissued.len(),
        reissued.iter().map(|i| i.amount_sats).sum::<u64>(),
        first.iter().map(|i| i.amount_sats).sum::<u64>()
    );
}

/// F-08: `Instruct` does not deduplicate its sequence list, so the emitted amount is the
/// outstanding amount times the number of repeats.
#[test]
fn instruct_with_repeated_sequence_does_not_multiply_the_amount() {
    let mut l = FeeLedger::in_memory(1, rpolicy(), group()).unwrap();
    l.record(LedgerEvent::Accrue { sequence: 1, digest: [5; 32], oracle_due: 7_000, router_due: 3_000 }).unwrap();
    l.record(LedgerEvent::Commit { sequence: 1, digest: [5; 32], fee_evidence: vec![], at_us: 100 }).unwrap();
    if l.record(LedgerEvent::Instruct { at_us: 200, sequences: vec![1, 1] }).is_err() {
        return; // fixed by rejecting the duplicate
    }
    let total: u64 = l.emission(0).unwrap().iter().map(|i| i.amount_sats).sum();
    assert_eq!(total, 10_000, "instruction total is not the committed 10,000 sats");
}
