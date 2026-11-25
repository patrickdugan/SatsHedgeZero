//! HFT-06 end-to-end: signed synthetic provider reports -> native verification
//! and 200 ms collator slots -> durable trusted-relay certification -> tiered
//! hub release -> client TieredReceiver -> MarkView -> DurableTieredRouter
//! admission and matching -> 100 ms batch -> authenticated Commit ->
//! recipient-specific fee ledger. One process, synthetic keys and funds.
#![allow(clippy::too_many_arguments)]
use shz_dex::OrderSide;
use shz_dex::routing::durable::{AckBundle, ChannelAck, Disposition, FeeRecipients, Head, Lane};
use shz_dex::routing::ln_fees::*;
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dex::routing::*;
use shz_dlc::{BtcOutPoint, bip340_sign};
use shz_oracle::collator::{Collator, fixture};
use shz_oracle::hft_packets::Mark;
use shz_relay::authority::{DurableSignLock, PacketAuthority, TrustedRelaySigner};
use shz_relay::client::{Accepted, TieredReceiver};
use shz_relay::envelope::{CertifiedPacket, PacketVerifier};
use shz_relay::hub::{Delivery, Hub};
use shz_relay::schedule::{ReleasePolicy, Tier};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

type Key = [u8; 32];
const ORIGIN: u64 = 1_800_000_000_000_000;
const AUTH: [u8; 32] = [77; 32];
const FEED_OPERATOR: u8 = 60;
const CAP: u64 = 100_000_000;

fn sk(n: u8) -> Key {
    [n; 32]
}
fn pk(n: u8) -> Key {
    public(&sk(n))
}
fn channel(n: u8) -> BtcOutPoint {
    BtcOutPoint { txid: [n; 32], vout: 0 }
}
fn router_policy() -> Policy {
    Policy { network: [99; 32], epoch: 7, relay_keys: [pk(50), pk(51)] }
}
fn registry() -> Registry {
    let p = router_policy();
    let plans = (1..=4)
        .map(|n| Allocation::signed(p.scope(), &sk(n), &AUTH, channel(n), CAP * 2, vec![Share { router: 1, sats: CAP }]).unwrap())
        .collect();
    Registry::new(p.scope(), public(&AUTH), plans).unwrap()
}
fn cfg() -> TieredConfig {
    TieredConfig {
        scope: router_policy().scope(),
        router: 1,
        entitlement_key: pk(FEED_OPERATOR),
        tariff: TariffSchedule::default_candidate(),
        execution: ExecutionPolicy::defaults(Arm::FeedOnly),
        revenue: RevenuePolicy::default(),
    }
}
fn lanes() -> Vec<Lane> {
    (1..=4u8).map(|n| Lane { channel: channel(n), peer: pk(70 + n), monitor: pk(90 + n), initial: Head { revision: 0, commitment: 10, state: [110 + n; 32] } }).collect()
}
fn grant(n: u8, tier: FeedTier) -> Entitlement {
    Entitlement { client: pk(n), tier, tariff_version: 1, valid_from_us: 0, valid_until_us: ORIGIN + 60_000_000, relay_key: [0; 32], signature: ZERO_SIG }
        .signed(&sk(FEED_OPERATOR))
        .unwrap()
}
fn intent(n: u8, seq: u64, action: Action, side: OrderSide, tier: FeedTier, limit: u64, ent: Option<&Entitlement>, opt_in: bool) -> IntentV6 {
    let c = cfg();
    IntentV6 {
        scope: c.scope,
        router: 1,
        channel: channel(n),
        owner: [0; 32],
        sequence: seq,
        expires_us: ORIGIN + 30_000_000,
        action,
        side,
        tier,
        tariff_version: c.tariff.version,
        entitlement_digest: ent.map(|e| e.digest()).unwrap_or([0; 32]),
        execution_policy: c.execution.id(),
        quantity: 1_000,
        limit_usd: limit,
        leverage_bps: 10_000,
        max_fee_ppm: c.tariff.rate_ppm(tier, action),
        max_fee_sats: 100_000,
        max_mark_age_us: 1_000_000,
        early_window_opt_in: opt_in,
        cancel_target: [0; 32],
        signature: ZERO_SIG,
    }
    .signed(&sk(n))
    .unwrap()
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("shz-hft06-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn reports_to_relay_to_router_to_fee_ledger() {
    let tmp = Temp::new();
    // 1. Collator over signed synthetic Pyth/Chainlink reports.
    let policy = fixture::policy(ORIGIN);
    let mut collator = Collator::new(fixture::config(), policy.clone()).unwrap();
    let mut slots = Vec::new();
    let rec = fixture::recording(ORIGIN, 4, 7);
    for r in &rec {
        slots.extend(collator.ingest(r).0);
    }
    slots.extend(collator.close_through(rec.last().unwrap().arrival_us).unwrap());
    assert!(slots.len() >= 19);

    // 2. Durable trusted-relay certification and tiered release.
    let mut signer = TrustedRelaySigner::new(&policy, [0x99; 32], DurableSignLock::open(&tmp.0.join("relay.lock")).unwrap()).unwrap();
    let verifier = PacketVerifier::trusted(policy.clone(), signer.public_key()).unwrap();
    let release = ReleasePolicy::default();
    let mut hub = Hub::new(verifier.clone(), release, 128);
    let (_, mut prem_rx) = hub.subscribe(Tier::Premium, 128, None, 0).unwrap();
    let (_, mut std_rx) = hub.subscribe(Tier::Standard, 128, None, 0).unwrap();
    let mut certified: BTreeMap<u64, CertifiedPacket> = BTreeMap::new();
    for s in &slots {
        let c = signer.certify(s.packet.as_ref().unwrap()).unwrap();
        certified.insert(s.seq, c.clone());
        hub.publish(c, s.boundary_us + 3_000).unwrap();
    }
    while let Some(t) = hub.next_due() {
        hub.deliver_due(t);
    }
    let drain = |rx: &mut tokio::sync::mpsc::Receiver<Arc<Delivery>>| -> Vec<Arc<Delivery>> { std::iter::from_fn(|| rx.try_recv().ok()).collect() };
    let prem = drain(&mut prem_rx);
    let stdd = drain(&mut std_rx);
    assert_eq!(prem.len(), slots.len());
    assert_eq!(stdd.len(), slots.len());
    let std_release: BTreeMap<u64, u64> = stdd.iter().map(|d| (d.seq, d.release_at_us)).collect();
    for (p, s) in prem.iter().zip(&stdd) {
        assert_eq!(p.certified, s.certified, "every tier receives the same canonical packet");
        assert!(s.release_at_us >= s.boundary_us + 200_000 && p.release_at_us < s.release_at_us);
    }

    // 3. Premium client verifies and turns usable VALID packets into router marks.
    let mut rx = TieredReceiver::new(verifier.clone(), Tier::Premium, release);
    let mut marks = Vec::new();
    for d in &prem {
        let c = CertifiedPacket::try_from(&d.certified).unwrap();
        if let Accepted::Usable(digest) = rx.accept(&c, d.release_at_us, 0).unwrap() {
            assert_eq!(digest, certified[&d.seq].digest());
            if matches!(c.packet().mark, Mark::Valid { .. }) {
                marks.push((MarkView::from_packet(c.packet(), d.boundary_us, std_release[&d.seq]), d.release_at_us));
            }
        }
    }
    // Two VALID marks at least two slots apart.
    let (m1, t1) = marks[0];
    let (m2, t2) = marks.iter().find(|(m, _)| m.boundary_us >= m1.boundary_us + 400_000).cloned().expect("second VALID mark");
    let limit = |m: &MarkView| m.price_e8.unwrap() / 100_000_000;

    // 4. Durable tiered router: a public-only standard maker is protected from a
    //    premium taker acting on the still-privileged m2; an opted-in premium maker fills.
    let mut d = DurableTieredRouter::create(&tmp.0.join("router.wal"), &registry(), cfg(), lanes(), FeeRecipients { oracle: pk(110), router: pk(111) }).unwrap();
    d.ingest_mark(m1, t1).unwrap();
    let std_post = m1.boundary_us + 200_001;
    d.submit(intent(1, 1, Action::Post, OrderSide::Short, FeedTier::Standard, limit(&m1), None, false), None, std_post).unwrap();
    assert!(matches!(d.process_one(std_post).unwrap().unwrap(), TierOutcome::Posted(_)));
    d.ingest_mark(m2, t2).unwrap();
    assert!(t2 < m2.public_release_us, "m2 is privileged at t2");
    let taker_ent = grant(2, FeedTier::Premium);
    d.submit(intent(2, 1, Action::Take, OrderSide::Long, FeedTier::Premium, limit(&m1).max(limit(&m2)) + 50, Some(&taker_ent), false), Some(taker_ent.clone()), t2).unwrap();
    assert!(matches!(d.process_one(t2).unwrap().unwrap(), TierOutcome::Rejected(TierReject::EarlyWindowProtected)));

    let maker_ent = grant(3, FeedTier::Premium);
    d.submit(intent(3, 1, Action::Post, OrderSide::Short, FeedTier::Premium, limit(&m2), Some(&maker_ent), true), Some(maker_ent.clone()), t2).unwrap();
    assert!(matches!(d.process_one(t2).unwrap().unwrap(), TierOutcome::Posted(_)));
    d.submit(intent(2, 2, Action::Take, OrderSide::Long, FeedTier::Premium, limit(&m2) + 50, Some(&taker_ent), false), Some(taker_ent), t2).unwrap();
    let fill = match d.process_one(t2).unwrap().unwrap() {
        TierOutcome::Filled(f) => f,
        other => panic!("expected fill, got {other:?}"),
    };
    assert!(fill.early_window);
    assert_eq!(fill.packet_digest, certified[&m2.seq].digest(), "fill binds the relay-certified packet digest");
    assert_eq!(fill.mark_seq, m2.seq);
    assert_eq!((fill.maker_tier, fill.taker_tier), (FeedTier::Premium, FeedTier::Premium));
    assert!(fill.fill.maker_fee_sats > 0 && fill.fill.taker_fee_sats > fill.fill.maker_fee_sats);

    // 5. 100 ms batch -> approvals -> authenticated Commit.
    d.process_one(t2 + 200_000).unwrap();
    let batch = d.seal_batch().unwrap().expect("window elapsed");
    let approvals = batch
        .accounts()
        .iter()
        .map(|a| BatchApproval { channel: a.channel.clone(), signature: bip340_sign(&sk(a.channel.txid[0]), &batch.approval_message(&a.channel).unwrap()).unwrap() })
        .collect();
    d.prepare(batch.sequence(), approvals).unwrap();
    let mut channels = Vec::new();
    for a in batch.accounts() {
        let n = a.channel.txid[0];
        let previous = d.head(&a.channel).unwrap().unwrap();
        let next = Head { revision: previous.revision + 1, commitment: previous.commitment + 1, state: [200 + n; 32] };
        let mut fee_evidence = [0u8; 32];
        fee_evidence[0] = n;
        fee_evidence[31] = 9;
        let mut c = ChannelAck { channel: a.channel.clone(), previous, next, evidence: [150 + n; 32], fee_evidence, signatures: [ZERO_SIG; 3] };
        let h = d.ack_message(batch.sequence(), Disposition::Commit, &c).unwrap();
        c.signatures = [bip340_sign(&sk(n), &h).unwrap(), bip340_sign(&sk(70 + n), &h).unwrap(), bip340_sign(&sk(90 + n), &h).unwrap()];
        channels.push(c);
    }
    let bundle = AckBundle { sequence: batch.sequence(), batch: batch.digest(), disposition: Disposition::Commit, channels };
    assert!(d.resolve(bundle.clone()).unwrap());

    // 6. Recipient-specific ledger: accrued -> committed, collected only on receipt.
    let rp = RecipientPolicy { version: 1, oracle_operators: vec![(pk(120), 3), (pk(121), 1)], upkeep: (pk(123), 1_000), router: pk(124) };
    let mut ledger = FeeLedger::create(&tmp.0.join("fees.wal"), 1, rp, GroupCommit { max_obligations: 1_000, max_delay_us: 1_000_000 }).unwrap();
    assert!(ledger.observe_batch(&batch).unwrap());
    let accrued: u64 = [120, 121, 123, 124].iter().map(|&n| ledger.totals(&pk(n)).accrued).sum();
    assert_eq!(accrued as u128, batch.oracle_due_sats() + batch.router_due_sats());
    assert_eq!([120, 121, 123, 124].iter().map(|&n| ledger.totals(&pk(n)).committed).sum::<u64>(), 0);
    assert!(ledger.observe_resolution(&d, &bundle, t2 + 300_000).unwrap());
    let committed: u64 = [120, 121, 123, 124].iter().map(|&n| ledger.totals(&pk(n)).committed).sum();
    assert_eq!(committed, fill.fill.maker_fee_sats + fill.fill.taker_fee_sats);
    assert_eq!(ledger.totals(&pk(124)).committed as u128, batch.router_due_sats());
    assert_eq!(ledger.totals(&pk(124)).collected, 0);
    let r = ledger.reconcile(&d).unwrap();
    assert!(r.clean(), "{:?}", r.mismatches);
}
