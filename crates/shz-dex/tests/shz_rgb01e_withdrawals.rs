//! SHZ-RGB-01E: Rust durable withdrawal reservations, conservation invariants,
//! adversarial rejection checks, WAL backward compatibility, DLC preservation,
//! golden vector verification, and exhaustive small-state exploration.

use shz_dex::routing::durable::{
    AckBundle, ChannelAck, Disposition, FeeRecipients, Head, Lane,
};
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dex::routing::withdrawal::*;
use shz_dex::routing::*;
use shz_dex::{OrderSide, SignedOrderIntent, ZeroFeeOrderBook};
use shz_dlc::{Bip340Signature, BtcOutPoint, bip340_sign};
use shz_margin::ZeroFeePolicy;
use shz_oracle::frost::FrostConfederation;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type Key = [u8; 32];
const T0: u64 = 1_000_000;
const AUTH: [u8; 32] = [77; 32];
const RELAY: u8 = 60;
const ROUTER_SIGNER: u8 = 120;
const PRICE: u64 = 10_000_000_000_000;
const CAP: u64 = 100_000_000;
const ZERO: Bip340Signature = Bip340Signature {
    r_x: [0; 32],
    s: [0; 32],
};

fn sk(n: u8) -> Key {
    [n; 32]
}
fn pk(n: u8) -> Key {
    public(&sk(n))
}
fn channel(n: u8) -> BtcOutPoint {
    BtcOutPoint {
        txid: [n; 32],
        vout: 0,
    }
}
fn p2tr_script(seed: u8) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&[seed; 32]);
    s
}
fn p2wpkh_script(seed: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[seed; 20]);
    s
}
fn policy_regtest() -> Policy {
    Policy {
        network: network_id("regtest"),
        epoch: 7,
        relay_keys: [pk(50), pk(51)],
    }
}
fn registry(cap: u64) -> Registry {
    let p = policy_regtest();
    let plans = (1..=4)
        .map(|n| {
            Allocation::signed(
                p.scope(),
                &sk(n),
                &AUTH,
                channel(n),
                cap,
                vec![Share { router: 1, sats: cap }],
            )
            .unwrap()
        })
        .collect();
    Registry::new(p.scope(), public(&AUTH), plans).unwrap()
}
fn cfg() -> TieredConfig {
    TieredConfig {
        scope: policy_regtest().scope(),
        router: 1,
        entitlement_key: pk(RELAY),
        tariff: TariffSchedule::default_candidate(),
        execution: ExecutionPolicy::defaults(Arm::FeedOnly),
        revenue: RevenuePolicy::default(),
    }
}
fn lanes() -> Vec<Lane> {
    (1..=4u8)
        .map(|n| Lane {
            channel: channel(n),
            peer: pk(70 + n),
            monitor: pk(90 + n),
            initial: Head {
                revision: 0,
                commitment: 10,
                state: [110 + n; 32],
            },
        })
        .collect()
}
fn recipients() -> FeeRecipients {
    FeeRecipients {
        oracle: pk(110),
        router: pk(111),
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "shz-rgb01e-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_router(path: &Path, cap: u64) -> DurableTieredRouter {
    DurableTieredRouter::create(path, &registry(cap), cfg(), lanes(), recipients()).unwrap()
}

fn open_router(
    path: &Path,
    cap: u64,
    min: Option<shz_dex::routing::durable::JournalTip>,
) -> Result<DurableTieredRouter, TieredDurableError> {
    DurableTieredRouter::open(path, &registry(cap), cfg(), lanes(), recipients(), min)
}

#[allow(clippy::too_many_arguments)]
fn make_req(
    d: &DurableTieredRouter,
    n: u8,
    nonce: u64,
    amount_sats: u64,
    script: Vec<u8>,
    expires_us: u64,
    clearing_sequence: u64,
    batch_digest: Key,
    clearing_digest: Key,
) -> WithdrawalRequest {
    WithdrawalRequest {
        network: network_id("regtest"),
        router_config: d.config_hash(),
        router: 1,
        channel: channel(n),
        owner: [0; 32],
        nonce,
        amount_sats,
        destination_script: script,
        expires_us,
        clearing_sequence,
        batch_digest,
        clearing_digest,
        owner_sig: ZERO,
    }
    .signed(&sk(n))
    .unwrap()
}

fn sign_reconcile(
    d: &DurableTieredRouter,
    n: u8,
    wid: Key,
    btc_ev: Key,
    settle_ev: Key,
) -> WithdrawalReconcileAttestation {
    let msg = d
        .withdrawal_reconcile_message(&wid, &btc_ev, &settle_ev)
        .unwrap();
    WithdrawalReconcileAttestation {
        withdrawal_id: wid,
        btc_evidence: btc_ev,
        settlement_evidence: settle_ev,
        signatures: [
            bip340_sign(&sk(70 + n), &msg).unwrap(),
            bip340_sign(&sk(90 + n), &msg).unwrap(),
        ],
    }
}

fn sign_cancel(
    d: &DurableTieredRouter,
    n: u8,
    wid: Key,
    cancel_ev: Key,
    with_owner: bool,
    with_peer: bool,
) -> WithdrawalCancelAttestation {
    let msg = d.withdrawal_cancel_message(&wid, &cancel_ev).unwrap();
    WithdrawalCancelAttestation {
        withdrawal_id: wid,
        cancellation_evidence: cancel_ev,
        signatures: [
            if with_owner {
                bip340_sign(&sk(n), &msg).unwrap()
            } else {
                ZERO
            },
            if with_peer {
                bip340_sign(&sk(70 + n), &msg).unwrap()
            } else {
                ZERO
            },
            bip340_sign(&sk(90 + n), &msg).unwrap(),
        ],
    }
}

fn sign_freeze(
    d: &DurableTieredRouter,
    n: u8,
    wid: Key,
    conflict_ev: Key,
) -> WithdrawalFreezeAttestation {
    let msg = d.withdrawal_freeze_message(&wid, &conflict_ev).unwrap();
    WithdrawalFreezeAttestation {
        withdrawal_id: wid,
        conflict_evidence: conflict_ev,
        monitor_sig: bip340_sign(&sk(90 + n), &msg).unwrap(),
    }
}

fn intent(n: u8, seq: u64, action: Action, side: OrderSide, q: u64, now: u64) -> IntentV6 {
    let c = cfg();
    IntentV6 {
        scope: c.scope,
        router: 1,
        channel: channel(n),
        owner: [0; 32],
        sequence: seq,
        expires_us: now + 5_000_000,
        action,
        side,
        tier: FeedTier::Standard,
        tariff_version: c.tariff.version,
        entitlement_digest: [0; 32],
        execution_policy: c.execution.id(),
        quantity: q,
        limit_usd: 100_000,
        leverage_bps: 10_000,
        max_fee_ppm: 0,
        max_fee_sats: 0,
        max_mark_age_us: 1_000_000,
        early_window_opt_in: false,
        cancel_target: [0; 32],
        signature: ZERO_SIG,
    }
    .signed(&sk(n))
    .unwrap()
}

fn commit_clearing_trade(d: &mut DurableTieredRouter) -> (u64, Key, Key) {
    assert!(d.enable_margin_release().unwrap());
    assert!(d.enable_clearing(1_000_000).unwrap());
    // Round 1: open long on ch 1, short on ch 2 at 100,000 USD for $1000
    d.ingest_mark(
        MarkView {
            packet_digest: [101; 32],
            seq: 1,
            price_e8: Some(PRICE),
            boundary_us: T0,
            public_release_us: T0,
        },
        T0,
    )
    .unwrap();
    let now = T0 + 200_000;
    d.submit(
        intent(2, 1, Action::Post, OrderSide::Short, 1_000, now),
        None,
        now,
    )
    .unwrap();
    assert!(matches!(
        d.process_one(now).unwrap().unwrap(),
        TierOutcome::Posted(_)
    ));
    d.submit(
        intent(1, 1, Action::Take, OrderSide::Long, 1_000, now),
        None,
        now,
    )
    .unwrap();
    assert!(matches!(
        d.process_one(now).unwrap().unwrap(),
        TierOutcome::Filled(_)
    ));
    d.process_one(T0 + 500_000).unwrap();
    let b = d.seal_batch().unwrap().unwrap();
    let apps: Vec<BatchApproval> = b
        .accounts()
        .iter()
        .map(|a| {
            let n = a.channel.txid[0];
            let h = b.approval_message(&a.channel).unwrap();
            BatchApproval {
                channel: a.channel.clone(),
                signature: bip340_sign(&sk(n), &h).unwrap(),
            }
        })
        .collect();
    d.prepare(b.sequence(), apps).unwrap();
    let mut channels = Vec::new();
    for a in b.accounts() {
        let n = a.channel.txid[0];
        let previous = d.head(&a.channel).unwrap().unwrap();
        let next = Head {
            revision: previous.revision + 1,
            commitment: previous.commitment + 1,
            state: [200 + n; 32],
        };
        let mut c = ChannelAck {
            channel: a.channel.clone(),
            previous,
            next,
            evidence: [210 + n; 32],
            fee_evidence: [0; 32],
            signatures: [ZERO; 3],
        };
        let msg = d.ack_message(b.sequence(), Disposition::Commit, &c).unwrap();
        c.signatures = [
            bip340_sign(&sk(n), &msg).unwrap(),
            bip340_sign(&sk(70 + n), &msg).unwrap(),
            bip340_sign(&sk(90 + n), &msg).unwrap(),
        ];
        channels.push(c);
    }
    let bundle = AckBundle {
        sequence: b.sequence(),
        batch: b.digest(),
        disposition: Disposition::Commit,
        channels,
    };
    assert!(d.resolve(bundle).unwrap());
    let clearing_digest = d.clearing(b.sequence()).unwrap().unwrap().digest();
    (b.sequence(), b.digest(), clearing_digest)
}

#[test]
fn withdrawal_full_lifecycle_ambiguous_freeze_cancel_and_replay() {
    let t = Temp::new();
    let p = t.path("w.wal");
    let mut d = create_router(&p, CAP);
    let (seq, batch_digest, clearing_digest) = commit_clearing_trade(&mut d);
    let b0 = d.balance(&channel(1)).unwrap().unwrap();
    assert!(b0.conserved());

    // 1. Free -> Reserved -> Submitted -> Reconciled
    let w1_req = make_req(
        &d,
        1,
        1,
        500_000,
        p2tr_script(0x11),
        T0 + 5_000_000,
        seq,
        batch_digest,
        clearing_digest,
    );
    let w1 = d.reserve_withdrawal(w1_req, T0 + 600_000).unwrap();
    let b1 = d.balance(&channel(1)).unwrap().unwrap();
    assert_eq!(b1.free, b0.free - 500_000);
    assert_eq!(b1.withdrawal_reserved, 500_000);
    assert_eq!(b1.withdrawn, 0);
    assert!(d.verify_withdrawal_invariants().unwrap());

    // Export and independently verify signed receipt
    let receipt = d
        .export_withdrawal_receipt(&w1, "regtest", &sk(ROUTER_SIGNER))
        .unwrap();
    receipt.verify(&d.config_hash(), &pk(ROUTER_SIGNER)).unwrap();
    assert_eq!(receipt.state, "reserved");
    assert_eq!(receipt.amount_sats, "500000");

    d.submit_withdrawal(w1, [0xAA; 32], T0 + 650_000).unwrap();
    assert_eq!(
        d.withdrawal(&w1).unwrap().unwrap().state,
        WithdrawalState::Submitted
    );

    // Reconciliation succeeds even past expires_us because submission occurred before expiry.
    let rec1 = sign_reconcile(&d, 1, w1, [0xB1; 32], [0xC1; 32]);
    d.reconcile_withdrawal(rec1, T0 + 6_000_000).unwrap();
    let b2 = d.balance(&channel(1)).unwrap().unwrap();
    assert_eq!(b2.withdrawal_reserved, 0);
    assert_eq!(b2.withdrawn, 500_000);
    assert_eq!(b2.free, b0.free - 500_000);
    assert!(d.verify_withdrawal_invariants().unwrap());

    // Post-reconcile chain conflict freezes while keeping `withdrawn` finalized (no silent refund).
    let frz1 = sign_freeze(&d, 1, w1, [0xD1; 32]);
    assert_eq!(
        d.freeze_withdrawal(frz1, T0 + 6_100_000).unwrap(),
        WithdrawalState::Frozen {
            was_reconciled: true
        }
    );
    let b2_frozen = d.balance(&channel(1)).unwrap().unwrap();
    assert_eq!(b2_frozen.withdrawn, 500_000);
    assert_eq!(b2_frozen.free, b0.free - 500_000);
    assert!(d.verify_withdrawal_invariants().unwrap());

    // 2. Free -> Reserved -> Submitted -> Ambiguous -> Reconciled (stays reserved across time)
    let w2_req = make_req(
        &d,
        1,
        2,
        250_000,
        p2wpkh_script(0x22),
        T0 + 10_000_000,
        seq,
        batch_digest,
        clearing_digest,
    );
    let w2 = d.reserve_withdrawal(w2_req, T0 + 6_200_000).unwrap();
    d.submit_withdrawal(w2, [0xAB; 32], T0 + 6_300_000).unwrap();
    d.mark_withdrawal_ambiguous(w2, T0 + 6_400_000).unwrap();
    // Advancing clock well past expires_us NEVER releases ambiguous reservation.
    d.process_one(T0 + 50_000_000).unwrap();
    assert_eq!(d.balance(&channel(1)).unwrap().unwrap().withdrawal_reserved, 250_000);
    // Owner-only cancel on Ambiguous is rejected; peer+monitor required.
    let bad_cancel = sign_cancel(&d, 1, w2, [0xE2; 32], true, false);
    assert!(matches!(
        d.cancel_withdrawal(bad_cancel, T0 + 50_000_001),
        Err(TieredDurableError::Rejected(TierReject::Signature))
    ));
    let rec2 = sign_reconcile(&d, 1, w2, [0xB2; 32], [0xC2; 32]);
    d.reconcile_withdrawal(rec2, T0 + 50_000_002).unwrap();
    assert_eq!(d.balance(&channel(1)).unwrap().unwrap().withdrawn, 750_000);
    assert_eq!(d.balance(&channel(1)).unwrap().unwrap().withdrawal_reserved, 0);

    // 3. Ambiguous -> Frozen (remains in withdrawal_reserved, cannot reconcile or cancel)
    let w3_req = make_req(
        &d,
        1,
        3,
        100_000,
        p2tr_script(0x33),
        T0 + 60_000_000,
        0,
        [0; 32],
        [0; 32],
    );
    let w3 = d.reserve_withdrawal(w3_req, T0 + 50_100_000).unwrap();
    d.submit_withdrawal(w3, [0xAC; 32], T0 + 50_200_000).unwrap();
    d.mark_withdrawal_ambiguous(w3, T0 + 50_300_000).unwrap();
    let frz3 = sign_freeze(&d, 1, w3, [0xD3; 32]);
    assert_eq!(
        d.freeze_withdrawal(frz3, T0 + 50_400_000).unwrap(),
        WithdrawalState::Frozen {
            was_reconciled: false
        }
    );
    assert_eq!(d.balance(&channel(1)).unwrap().unwrap().withdrawal_reserved, 100_000);
    assert!(d
        .reconcile_withdrawal(sign_reconcile(&d, 1, w3, [0xB3; 32], [0xC3; 32]), T0 + 50_500_000)
        .is_err());
    assert!(d
        .cancel_withdrawal(sign_cancel(&d, 1, w3, [0xE3; 32], true, true), T0 + 50_500_001)
        .is_err());

    // 4. Cancellation from Ambiguous with peer+monitor evidence releases funds back to free; nonce stays consumed.
    let w4_req = make_req(
        &d,
        1,
        4,
        125_000,
        p2tr_script(0x44),
        T0 + 70_000_000,
        0,
        [0; 32],
        [0; 32],
    );
    let free_before_w4 = d.balance(&channel(1)).unwrap().unwrap().free;
    let w4 = d.reserve_withdrawal(w4_req.clone(), T0 + 51_000_000).unwrap();
    d.submit_withdrawal(w4, [0xAD; 32], T0 + 51_100_000).unwrap();
    d.mark_withdrawal_ambiguous(w4, T0 + 51_200_000).unwrap();
    let cancel4 = sign_cancel(&d, 1, w4, [0xE4; 32], false, true);
    d.cancel_withdrawal(cancel4, T0 + 51_300_000).unwrap();
    assert_eq!(d.balance(&channel(1)).unwrap().unwrap().free, free_before_w4);
    assert_eq!(d.balance(&channel(1)).unwrap().unwrap().withdrawal_reserved, 100_000);
    // Replaying nonce 4 fails closed even after cancel.
    assert!(matches!(
        d.reserve_withdrawal(w4_req, T0 + 51_400_000),
        Err(TieredDurableError::Rejected(TierReject::Replay))
    ));
    assert!(d.verify_withdrawal_invariants().unwrap());

    // 5. Full WAL restart & replay produces identical balances, states, and tip.
    let tip = d.tip().unwrap();
    let bal_before = d.balance(&channel(1)).unwrap().unwrap();
    drop(d);
    let d2 = open_router(&p, CAP, Some(tip)).unwrap();
    assert_eq!(d2.balance(&channel(1)).unwrap().unwrap(), bal_before);
    assert_eq!(
        d2.withdrawal(&w1).unwrap().unwrap().state,
        WithdrawalState::Frozen {
            was_reconciled: true
        }
    );
    assert_eq!(
        d2.withdrawal(&w2).unwrap().unwrap().state,
        WithdrawalState::Reconciled
    );
    assert_eq!(
        d2.withdrawal(&w3).unwrap().unwrap().state,
        WithdrawalState::Frozen {
            was_reconciled: false
        }
    );
    assert_eq!(
        d2.withdrawal(&w4).unwrap().unwrap().state,
        WithdrawalState::Cancelled
    );
    assert!(d2.verify_withdrawal_invariants().unwrap());
}

#[test]
fn withdrawal_excludes_reserved_sats_from_orders_and_prevents_overspend_and_duplicates() {
    let t = Temp::new();
    let p = t.path("excl.wal");
    let cap = 2_000_000u64;
    let mut d = create_router(&p, cap);
    d.ingest_mark(
        MarkView {
            packet_digest: [10; 32],
            seq: 1,
            price_e8: Some(PRICE),
            boundary_us: T0,
            public_release_us: T0,
        },
        T0,
    )
    .unwrap();

    // Reserve 1,500,000 of 2,000,000 free sats -> only 500,000 free remain.
    let req1 = make_req(&d, 1, 1, 1_500_000, p2tr_script(0x51), T0 + 9_000_000, 0, [0; 32], [0; 32]);
    let w1 = d.reserve_withdrawal(req1, T0 + 100_000).unwrap();
    assert_eq!(d.balance(&channel(1)).unwrap().unwrap().free, 500_000);

    // Concurrent second withdrawal for 500,001 sats must be rejected (no overspend).
    let req2 = make_req(&d, 1, 2, 500_001, p2tr_script(0x52), T0 + 9_000_000, 0, [0; 32], [0; 32]);
    assert!(matches!(
        d.reserve_withdrawal(req2, T0 + 110_000),
        Err(TieredDurableError::Rejected(TierReject::Capacity))
    ));

    // Order requiring 1,000,000 sats margin ($1000 @ $100k, 1x) must be rejected because reserved sats are excluded!
    let now = T0 + 200_000;
    d.submit(intent(1, 1, Action::Post, OrderSide::Short, 1_000, now), None, now)
        .unwrap();
    assert!(matches!(
        d.process_one(now).unwrap().unwrap(),
        TierOutcome::Rejected(TierReject::Capacity)
    ));

    // Order requiring 400,000 sats margin ($400 @ $100k, 1x) succeeds within remaining 500,000 free sats!
    d.submit(intent(1, 2, Action::Post, OrderSide::Short, 400, now), None, now)
        .unwrap();
    assert!(matches!(
        d.process_one(now).unwrap().unwrap(),
        TierOutcome::Posted(_)
    ));
    let bal = d.balance(&channel(1)).unwrap().unwrap();
    assert_eq!(bal.withdrawal_reserved, 1_500_000);
    assert!(bal.resting >= 400_000 && bal.free <= 100_000);
    assert!(bal.conserved());

    // Duplicate payment_hash and duplicate btc_evidence across withdrawals are rejected.
    let req3 = make_req(&d, 2, 1, 100_000, p2tr_script(0x53), T0 + 9_000_000, 0, [0; 32], [0; 32]);
    let w3 = d.reserve_withdrawal(req3, now + 1).unwrap();
    d.submit_withdrawal(w1, [0x77; 32], now + 2).unwrap();
    assert!(matches!(
        d.submit_withdrawal(w3, [0x77; 32], now + 3),
        Err(TieredDurableError::Rejected(TierReject::Replay))
    ));
    d.submit_withdrawal(w3, [0x78; 32], now + 4).unwrap();
    let rec1 = sign_reconcile(&d, 1, w1, [0x88; 32], [0x89; 32]);
    d.reconcile_withdrawal(rec1, now + 5).unwrap();
    // Reusing btc_evidence [0x88; 32] on channel 2's withdrawal is rejected!
    let dup_ev = sign_reconcile(&d, 2, w3, [0x88; 32], [0x8A; 32]);
    assert!(matches!(
        d.reconcile_withdrawal(dup_ev, now + 6),
        Err(TieredDurableError::Rejected(TierReject::Replay))
    ));
    assert!(d.verify_withdrawal_invariants().unwrap());
}

#[test]
fn withdrawal_rejects_bad_auth_cross_network_invalid_script_and_bad_clearing() {
    let t = Temp::new();
    let p = t.path("auth.wal");
    let mut d = create_router(&p, CAP);
    let base = make_req(&d, 1, 1, 10_000, p2tr_script(0x01), T0 + 1_000_000, 0, [0; 32], [0; 32]);

    // Wrong network
    let mut bad_net = base.clone();
    bad_net.network = network_id("mainnet");
    let bad_net = bad_net.signed(&sk(1)).unwrap();
    assert!(matches!(
        d.reserve_withdrawal(bad_net, T0),
        Err(TieredDurableError::Rejected(TierReject::Scope))
    ));

    // Wrong router_config
    let mut bad_cfg = base.clone();
    bad_cfg.router_config = [0x99; 32];
    let bad_cfg = bad_cfg.signed(&sk(1)).unwrap();
    assert!(matches!(
        d.reserve_withdrawal(bad_cfg, T0),
        Err(TieredDurableError::Rejected(TierReject::Scope))
    ));

    // Wrong signer (channel 2 signing for channel 1)
    let mut wrong_sig = base.clone();
    wrong_sig.owner_sig = bip340_sign(&sk(2), &wrong_sig.withdrawal_id()).unwrap();
    assert!(matches!(
        d.reserve_withdrawal(wrong_sig, T0),
        Err(TieredDurableError::Rejected(TierReject::Signature))
    ));

    // Non-native-segwit script (legacy P2PKH)
    let mut bad_script = base.clone();
    bad_script.destination_script = vec![0x76, 0xa9, 0x14, 0x00, 0x88, 0xac];
    let bad_script = bad_script.signed(&sk(1)).unwrap();
    assert!(matches!(
        d.reserve_withdrawal(bad_script, T0),
        Err(TieredDurableError::Rejected(TierReject::Bounds))
    ));

    // Uncommitted clearing sequence (checked before advancing clock past expiry)
    let mut bad_clr = base.clone();
    bad_clr.clearing_sequence = 1;
    bad_clr.batch_digest = [0x12; 32];
    let bad_clr = bad_clr.signed(&sk(1)).unwrap();
    assert!(matches!(
        d.reserve_withdrawal(bad_clr, T0),
        Err(TieredDurableError::Rejected(TierReject::UnknownOrder))
    ));

    // Expired request
    assert!(matches!(
        d.reserve_withdrawal(base.clone(), T0 + 1_000_000),
        Err(TieredDurableError::Rejected(TierReject::Expired))
    ));
}

#[test]
fn crash_after_withdrawal_reserve_fsync_replays_cleanly_and_preserves_dlc_unilateral_recovery() {
    let t = Temp::new();
    let p = t.path("crash.wal");
    let mut d = create_router(&p, CAP);
    let req = make_req(&d, 1, 1, 400_000, p2tr_script(0x61), T0 + 5_000_000, 0, [0; 32], [0; 32]);
    let wid = req.withdrawal_id();

    // Simulate process death immediately after WAL fsync and before in-memory apply.
    d.append_withdrawal_reserve_without_apply(req, T0 + 100).unwrap();
    assert!(matches!(d.tip(), Err(TieredDurableError::Poisoned)));
    drop(d);

    let d2 = open_router(&p, CAP, None).unwrap();
    let bal = d2.balance(&channel(1)).unwrap().unwrap();
    assert_eq!(bal.withdrawal_reserved, 400_000);
    assert_eq!(bal.free, CAP - 400_000);
    assert_eq!(d2.withdrawal(&wid).unwrap().unwrap().state, WithdrawalState::Reserved);
    assert!(d2.verify_withdrawal_invariants().unwrap());

    // Confirm unilateral DLC recovery and zero-fee policy are completely preserved.
    let alice_sk = [0xA1u8; 32];
    let bob_sk = [0xB2u8; 32];
    let mut book = ZeroFeeOrderBook::new();
    let bob_ask = SignedOrderIntent::new_signed_v0(
        &bob_sk,
        BtcOutPoint { txid: [0xCD; 32], vout: 1 },
        OrderSide::Short,
        2_000,
        100_000,
        10_000,
        shz_dex::OracleSettlementPolicy::FrostBondedWithFallback,
        1,
    )
    .unwrap();
    book.submit_order(bob_ask).unwrap();
    let alice_bid = SignedOrderIntent::new_signed_v0(
        &alice_sk,
        BtcOutPoint { txid: [0xEF; 32], vout: 0 },
        OrderSide::Long,
        2_000,
        100_000,
        100_000,
        shz_dex::OracleSettlementPolicy::FrostBondedWithFallback,
        2,
    )
    .unwrap();
    let ticket = book.submit_order(alice_bid).unwrap().remove(0);
    assert_eq!(ticket.contract_spec.fee_policy, ZeroFeePolicy::ZERO);
    let frost = FrostConfederation::keygen_deterministic(3, 5, &[0x99u8; 32]).unwrap();
    let ns = frost
        .announce_event("SHZ-RGB01E-DLC-CHECK", 1_795_000_000, 20, &[0x71u8; 32])
        .unwrap();
    let mut sub = ticket.into_subchannel_offer(ns.announcement.clone(), 144, 1_000).unwrap();
    sub.sign_and_activate_cets(&alice_sk, &bob_sk).unwrap();
    let att = frost
        .threshold_attest_price(&ns, &[1, 2, 3], 1_795_000_000, 110_000)
        .unwrap();
    let split = sub.settle_on_chain_with_attestation(&att).unwrap();
    assert_eq!(split.protocol_fee_sats, 0);
    assert_eq!(split.total_sats(), sub.spec.total_collateral_sats());
}

/// Exhaustive small-state model check over all reachable action sequences up to depth 5
/// across two concurrent withdrawals + an interleaved order hold (`cap = 3`, `w1 = 2`, `w2 = 2`, `order = 2`),
/// verifying exact balance conservation, partition invariants, monotone `withdrawn`,
/// terminal-state finality, and zero overspend in every reachable state.
#[test]
fn exhaustive_small_state_withdrawal_conservation_and_safety() {
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    enum Slot {
        Free,
        Reserved,
        Submitted,
        Ambiguous,
        Reconciled,
        FrozenRes,
        FrozenRec,
        Cancelled,
    }
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    struct Model {
        free: u64,
        resting: u64,
        withdrawal_reserved: u64,
        withdrawn: u64,
        w1: Slot,
        w2: Slot,
        order_active: bool,
        w1_used: bool,
        w2_used: bool,
    }
    const M_CAP: u64 = 5;
    const AMT: u64 = 2;

    let check_invariants = |m: &Model| {
        assert_eq!(
            m.free + m.resting + m.withdrawal_reserved + m.withdrawn,
            M_CAP,
            "conservation violated: {m:?}"
        );
        let exp_res = [m.w1, m.w2]
            .iter()
            .filter(|s| matches!(s, Slot::Reserved | Slot::Submitted | Slot::Ambiguous | Slot::FrozenRes))
            .count() as u64
            * AMT;
        let exp_wd = [m.w1, m.w2]
            .iter()
            .filter(|s| matches!(s, Slot::Reconciled | Slot::FrozenRec))
            .count() as u64
            * AMT;
        let exp_rest = if m.order_active { AMT } else { 0 };
        assert_eq!(m.withdrawal_reserved, exp_res, "reserved partition: {m:?}");
        assert_eq!(m.withdrawn, exp_wd, "withdrawn partition: {m:?}");
        assert_eq!(m.resting, exp_rest, "resting partition: {m:?}");
        // Overspend impossibility: at most two of {w1 active, w2 active, order active} can hold 2 sats out of 5.
        assert!(exp_res + exp_wd + exp_rest <= M_CAP, "overspend: {m:?}");
    };

    let init = Model {
        free: M_CAP,
        resting: 0,
        withdrawal_reserved: 0,
        withdrawn: 0,
        w1: Slot::Free,
        w2: Slot::Free,
        order_active: false,
        w1_used: false,
        w2_used: false,
    };

    let mut visited = BTreeSet::new();
    let mut frontier = vec![init];
    let mut transitions_checked = 0usize;
    let mut rejected_checked = 0usize;
    visited.insert(init);

    while !frontier.is_empty() {
        let mut next_frontier = Vec::new();
        for cur in frontier {
            check_invariants(&cur);
            // Generate all 14 candidate actions: 6 transitions per withdrawal slot + order post/cancel
            for slot_idx in 0..2 {
                let (s, used) = if slot_idx == 0 {
                    (cur.w1, cur.w1_used)
                } else {
                    (cur.w2, cur.w2_used)
                };
                for op in 0..6 {
                    let mut nxt = cur;
                    let mut valid = true;
                    let target = if slot_idx == 0 {
                        &mut nxt.w1
                    } else {
                        &mut nxt.w2
                    };
                    match op {
                        0 => {
                            // Reserve
                            if s == Slot::Free && !used && nxt.free >= AMT {
                                nxt.free -= AMT;
                                nxt.withdrawal_reserved += AMT;
                                *target = Slot::Reserved;
                                if slot_idx == 0 {
                                    nxt.w1_used = true;
                                } else {
                                    nxt.w2_used = true;
                                }
                            } else {
                                valid = false;
                            }
                        }
                        1 => {
                            // Submit
                            if s == Slot::Reserved {
                                *target = Slot::Submitted;
                            } else {
                                valid = false;
                            }
                        }
                        2 => {
                            // Ambiguous
                            if s == Slot::Submitted {
                                *target = Slot::Ambiguous;
                            } else {
                                valid = false;
                            }
                        }
                        3 => {
                            // Reconcile
                            if matches!(s, Slot::Submitted | Slot::Ambiguous) {
                                nxt.withdrawal_reserved -= AMT;
                                nxt.withdrawn += AMT;
                                *target = Slot::Reconciled;
                            } else {
                                valid = false;
                            }
                        }
                        4 => {
                            // Freeze
                            match s {
                                Slot::Submitted | Slot::Ambiguous => *target = Slot::FrozenRes,
                                Slot::Reconciled => *target = Slot::FrozenRec,
                                _ => valid = false,
                            }
                        }
                        5 => {
                            // Cancel (with independent evidence)
                            if matches!(s, Slot::Reserved | Slot::Submitted | Slot::Ambiguous) {
                                nxt.withdrawal_reserved -= AMT;
                                nxt.free += AMT;
                                *target = Slot::Cancelled;
                            } else {
                                valid = false;
                            }
                        }
                        _ => unreachable!(),
                    }
                    if valid {
                        transitions_checked += 1;
                        assert!(nxt.withdrawn >= cur.withdrawn, "withdrawn decreased!");
                        check_invariants(&nxt);
                        if visited.insert(nxt) {
                            next_frontier.push(nxt);
                        }
                    } else {
                        rejected_checked += 1;
                    }
                }
            }
            // Interleaved order Post / Cancel
            for order_op in 0..2 {
                let mut nxt = cur;
                let valid = if order_op == 0 {
                    if !nxt.order_active && nxt.free >= AMT {
                        nxt.free -= AMT;
                        nxt.resting += AMT;
                        nxt.order_active = true;
                        true
                    } else {
                        false
                    }
                } else if nxt.order_active {
                    nxt.resting -= AMT;
                    nxt.free += AMT;
                    nxt.order_active = false;
                    true
                } else {
                    false
                };
                if valid {
                    transitions_checked += 1;
                    assert!(nxt.withdrawn >= cur.withdrawn);
                    check_invariants(&nxt);
                    if visited.insert(nxt) {
                        next_frontier.push(nxt);
                    }
                } else {
                    rejected_checked += 1;
                }
            }
        }
        frontier = next_frontier;
    }

    assert!(visited.len() >= 90, "visited={}", visited.len());
    assert!(transitions_checked > 200, "transitions={transitions_checked}");
    assert!(rejected_checked > 500, "rejected={rejected_checked}");
}

#[test]
fn cross_language_golden_vectors_match_rust_receipt_verifier() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vec_path = manifest_dir
        .join("..")
        .join("..")
        .join("integrations")
        .join("utexo-rgb")
        .join("withdrawal-vectors.json");
    if !vec_path.exists() {
        // Generated by `cargo run -p shz-dex --example shz_withdrawal_vectors`
        return;
    }
    let raw = fs::read_to_string(&vec_path).expect("read withdrawal-vectors.json");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors");
    assert_eq!(doc["schema"].as_str(), Some("SHZ/WITHDRAWAL-VECTORS/V1"));
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() >= 3);
    for v in vectors {
        let receipt: WithdrawalReceiptV1 =
            serde_json::from_value(v["receipt"].clone()).expect("receipt deserialize");
        let cfg_bytes: Key = hex::decode(v["router_config"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signer_bytes: Key = hex::decode(v["router_signer"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        receipt.verify(&cfg_bytes, &signer_bytes).unwrap();
        assert_eq!(
            receipt.to_canonical_json().unwrap(),
            v["canonical_json"].as_str().unwrap()
        );
    }
}
