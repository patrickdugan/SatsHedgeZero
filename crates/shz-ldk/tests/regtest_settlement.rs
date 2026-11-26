//! G-LN-1a on regtest: four LDK nodes (venue + three accounts) on Bitcoin Core, one funded
//! channel per lane. The venue router clears batches multilaterally (V3); each batch's net
//! settlement vector is moved through the channels, both parties' persisted monitors are
//! checked against the clearing ledger, and the V3 acknowledgements carrying the monitor
//! evidence resolve the batch.
//!
//! Needs Bitcoin Core: `SHZ_BITCOIND=<path to bitcoind> cargo test -p shz-ldk -- --ignored`.
//! `SHZ_LDK_RECEIPT=<file>` writes a JSON receipt of every batch.
use shz_dex::OrderSide;
use shz_dex::routing::durable::{AckBundle, Disposition, FeeRecipients, Lane};
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dex::routing::*;
use shz_dlc::{Bip340Signature, BtcOutPoint, bip340_sign, tagged_hash};
use shz_ldk::{Bitcoind, LaneSettlement, LdkNode, LdkSettlement, Side, attest};
use shz_ldk::node::wait_until;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

type Key = [u8; 32];
const T0: u64 = 1_000_000;
const AUTH: Key = [77; 32];
const CAP: u64 = 100_000_000;
const X1: u32 = 10_000;
const X100: u32 = 1_000_000;
const FUND: u64 = 50_000;
const CHANNEL_SATS: u64 = 1_000_000;
const PUSH_SATS: u64 = 400_000;
const VENUE_KEY: u8 = 70;
const MONITOR_KEY: u8 = 90;

fn sk(n: u8) -> Key {
    [n; 32]
}
fn pk(n: u8) -> Key {
    public(&sk(n))
}
fn policy() -> Policy {
    Policy { network: [99; 32], epoch: 7, relay_keys: [pk(50), pk(51)] }
}
fn cfg() -> TieredConfig {
    TieredConfig {
        scope: policy().scope(),
        router: 1,
        entitlement_key: pk(60),
        tariff: TariffSchedule::default_candidate(),
        execution: ExecutionPolicy::defaults(Arm::FeedOnly),
        revenue: RevenuePolicy::default(),
    }
}

/// Accounts 1..=3; `lane[n-1]` is account n's channel funding outpoint.
struct Venue {
    d: DurableTieredRouter,
    lanes: Vec<BtcOutPoint>,
    round: u64,
    seq: u64,
}

impl Venue {
    fn n_of(&self, c: &BtcOutPoint) -> u8 {
        self.lanes.iter().position(|l| l == c).expect("lane") as u8 + 1
    }
    #[allow(clippy::too_many_arguments)]
    fn intent(&mut self, n: u8, action: Action, side: OrderSide, q: u64, price: u64, lev: u32, now: u64) -> IntentV6 {
        let c = cfg();
        self.seq += 1;
        IntentV6 {
            scope: c.scope,
            router: 1,
            channel: self.lanes[n as usize - 1].clone(),
            owner: [0; 32],
            sequence: self.seq,
            expires_us: now + 5_000_000,
            action,
            side,
            tier: FeedTier::Standard,
            tariff_version: c.tariff.version,
            entitlement_digest: [0; 32],
            execution_policy: c.execution.id(),
            quantity: q,
            limit_usd: price,
            leverage_bps: lev,
            max_fee_ppm: c.tariff.rate_ppm(FeedTier::Standard, action),
            max_fee_sats: 100_000,
            max_mark_age_us: 1_000_000,
            early_window_opt_in: false,
            cancel_target: [0; 32],
            signature: ZERO_SIG,
        }
        .signed(&sk(n))
        .unwrap()
    }
    /// `maker` rests a quote, `taker` takes it; the window is sealed and approved (Prepared).
    fn seal(&mut self, maker: u8, taker: u8, taker_side: OrderSide, q: u64, price: u64, lev: (u32, u32)) -> Batch {
        self.round += 1;
        let t = T0 + self.round * 1_000_000;
        let now = t + 200_000;
        let mark = MarkView {
            packet_digest: tagged_hash(b"test/mark", &self.round.to_le_bytes()),
            seq: self.round,
            price_e8: Some(price * 100_000_000),
            boundary_us: t,
            public_release_us: t,
        };
        self.d.ingest_mark(mark, t).unwrap();
        let maker_side = if taker_side == OrderSide::Long { OrderSide::Short } else { OrderSide::Long };
        let i = self.intent(maker, Action::Post, maker_side, q, price, lev.0, now);
        self.d.submit(i, None, now).unwrap();
        assert!(matches!(self.d.process_one(now).unwrap().unwrap(), TierOutcome::Posted(_)));
        let i = self.intent(taker, Action::Take, taker_side, q, price, lev.1, now);
        self.d.submit(i, None, now).unwrap();
        let out = self.d.process_one(now).unwrap().unwrap();
        assert!(matches!(out, TierOutcome::Filled(_)), "{out:?}");
        self.d.process_one(t + 500_000).unwrap();
        let b = self.d.seal_batch().unwrap().expect("window elapsed");
        let approvals = b
            .accounts()
            .iter()
            .map(|a| BatchApproval {
                channel: a.channel.clone(),
                signature: bip340_sign(&sk(self.n_of(&a.channel)), &b.approval_message(&a.channel).unwrap()).unwrap(),
            })
            .collect();
        self.d.prepare(b.sequence(), approvals).unwrap();
        b
    }
    fn realized(&self, n: u8) -> i64 {
        self.d.balance(&self.lanes[n as usize - 1]).unwrap().unwrap().realized_pnl
    }
}

/// Field order is drop order: nodes stop before the runtime, bitcoind last.
struct Net {
    venue: Arc<LdkNode>,
    owners: Vec<Arc<LdkNode>>,
    _rt: tokio::runtime::Runtime,
    _btc: Bitcoind,
}

impl Net {
    fn sync(&self) {
        self.venue.sync();
        for o in &self.owners {
            o.sync();
        }
    }
}

fn scratch() -> PathBuf {
    let p = std::env::temp_dir().join(format!("shz-ldk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Venue node opens one channel to each account node, pushing `PUSH_SATS` so the account can
/// pay losses; funding is mined and every channel is usable on both sides.
fn network(dir: &std::path::Path) -> Net {
    let bitcoind = PathBuf::from(std::env::var_os("SHZ_BITCOIND").expect("set SHZ_BITCOIND to a bitcoind 31.x binary"));
    let btc = Bitcoind::spawn(&bitcoind, dir.join("bitcoind"));
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let venue = LdkNode::start("venue", [200; 32], dir.join("venue"), btc.rpc.clone(), &rt);
    let owners: Vec<_> = (1..=3u8)
        .map(|n| LdkNode::start(&format!("acct{n}"), [200 + n; 32], dir.join(format!("acct{n}")), btc.rpc.clone(), &rt))
        .collect();
    for (i, o) in owners.iter().enumerate() {
        venue.connect(o, &rt);
        venue.cm.create_channel(o.node_id(), CHANNEL_SATS, PUSH_SATS * 1000, i as u128 + 1, None, None).expect("open");
    }
    wait_until(Duration::from_secs(60), || {
        let pool: serde_json::Value = serde_json::from_str(&btc.rpc.call(&["getrawmempool"]).unwrap()).unwrap();
        pool.as_array().map(|a| a.len()) == Some(owners.len())
    })
    .expect("three funding transactions broadcast");
    btc.rpc.mine(6);
    let net = Net { venue, owners, _rt: rt, _btc: btc };
    wait_until(Duration::from_secs(60), || {
        net.sync();
        net.owners.iter().all(|o| {
            net.venue.channel_with(&o.node_id()).is_some_and(|c| c.is_usable)
                && o.channel_with(&net.venue.node_id()).is_some_and(|c| c.is_usable)
        })
    })
    .expect("channels usable");
    net
}

/// maker, taker, taker side, price, (maker, taker) leverage
type Trade = (u8, u8, OrderSide, u64, (u32, u32));

fn sign(n: u8, h: &Key) -> Bip340Signature {
    bip340_sign(&sk(n), h).unwrap()
}

/// One committed batch: clearing previewed, nets moved through LDK, every signer attests its
/// own journal, the V3 bundle resolves, and both nodes' persisted balances equal the ledger.
fn run(v: &mut Venue, s: &mut LdkSettlement, net: &Net, venue_journal: &std::path::Path, b: Batch, receipt: &mut Vec<serde_json::Value>) {
    let seq = b.sequence();
    let plan = v.d.planned_clearing(seq).unwrap().expect("clearing active, batch prepared");
    let before: Vec<i64> = (1..=3).map(|n| v.realized(n)).collect();
    let settled = s.settle(seq, &plan).expect("lanes settle");
    let mut channels = Vec::new();
    for (a, st) in b.accounts().iter().zip(&settled) {
        assert_eq!(a.channel, st.channel);
        let n = v.n_of(&a.channel);
        let mut ack = st.ack(v.d.head(&a.channel).unwrap().unwrap());
        // Owner, venue (pinned peer) and monitor each check their own durable journal first.
        attest(&s.owner_journal(&a.channel).unwrap(), st, Side::Owner, &ack.evidence).expect("owner attests");
        attest(venue_journal, st, Side::Venue, &ack.evidence).expect("venue attests");
        attest(venue_journal, st, Side::Venue, &ack.evidence).and(attest(&s.owner_journal(&a.channel).unwrap(), st, Side::Owner, &ack.evidence)).expect("monitor attests");
        let h = v.d.ack_message(seq, Disposition::Commit, &ack).unwrap();
        ack.signatures = [sign(n, &h), sign(VENUE_KEY, &h), sign(MONITOR_KEY, &h)];
        channels.push(ack);
    }
    let bundle = AckBundle { sequence: seq, batch: b.digest(), disposition: Disposition::Commit, channels };
    assert!(v.d.resolve(bundle).unwrap());
    let committed = v.d.clearing(seq).unwrap().unwrap();
    assert_eq!(*committed, plan, "the committed clearing is the one the channels moved");
    assert_eq!(committed.rows.iter().map(|r| r.net).sum::<i64>() + committed.pool_net(), 0);
    // Ledger against the channels: each account's realized PnL is exactly what its channel
    // gained; the venue's side of each channel moved by the opposite amount.
    let mut venue_delta = 0i64;
    let mut lanes_json = Vec::new();
    for n in 1..=3u8 {
        let c = &v.lanes[n as usize - 1];
        let (moved, vbase, obase) = s.lane_totals(c).unwrap();
        let cid = net.venue.channel_with(&net.owners[n as usize - 1].node_id()).unwrap().channel_id.0;
        let vrec = net.venue.persister.latest(&cid).unwrap();
        let orec = net.owners[n as usize - 1].persister.latest(&cid).unwrap();
        let realized = v.realized(n);
        assert_eq!(moved, realized, "lane {n}: channel moved vs ledger realized PnL");
        assert_eq!(orec.holder_sats as i64 - obase as i64, realized, "lane {n}: owner monitor");
        assert_eq!(vbase as i64 - vrec.holder_sats as i64, realized, "lane {n}: venue monitor");
        venue_delta += vrec.holder_sats as i64 - vbase as i64;
        let row = committed.rows.iter().find(|r| r.channel == *c);
        if let Some(r) = row {
            assert_eq!(realized - before[n as usize - 1], r.net);
        }
        lanes_json.push(serde_json::json!({
            "lane": n, "net": row.map(|r| r.net), "realized_pnl": realized,
            "owner_sats": orec.holder_sats, "venue_sats": vrec.holder_sats,
            "owner_update_id": orec.update_id, "venue_update_id": vrec.update_id,
        }));
    }
    let sum = v.d.clearing_summary().unwrap().unwrap();
    assert_eq!(sum.identity, 0);
    assert_eq!(venue_delta as i128, sum.cash as i128 - sum.fund0 as i128, "venue channels moved by the pool's cash change");
    let evidence: Vec<String> = settled.iter().map(|x| hex::encode(x.evidence())).collect();
    receipt.push(serde_json::json!({
        "sequence": seq, "layer": format!("{:?}", committed.layer), "pool_net": committed.pool_net(),
        "fund": sum.fund, "cash": sum.cash, "clearing_digest": hex::encode(committed.digest()),
        "evidence": evidence, "lanes": lanes_json,
    }));
}

#[test]
#[ignore = "needs Bitcoin Core: SHZ_BITCOIND=<path to bitcoind>"]
fn ldk_lanes_move_the_cleared_net_amounts() {
    let dir = scratch();
    let net = network(&dir);
    let mut s = LdkSettlement::new(net.venue.clone());
    let lanes: Vec<BtcOutPoint> = net.owners.iter().map(|o| s.bind(o.clone()).expect("bind lane")).collect();
    let p = policy();
    let plans = (1..=3u8)
        .map(|n| Allocation::signed(p.scope(), &sk(n), &AUTH, lanes[n as usize - 1].clone(), CAP, vec![Share { router: 1, sats: CAP }]).unwrap())
        .collect();
    let registry = Registry::new(p.scope(), public(&AUTH), plans).unwrap();
    let router_lanes = lanes
        .iter()
        .map(|c| Lane { channel: c.clone(), peer: pk(VENUE_KEY), monitor: pk(MONITOR_KEY), initial: s.initial_head(c).unwrap() })
        .collect();
    let recipients = FeeRecipients { oracle: pk(110), router: pk(111) };
    let mut d = DurableTieredRouter::create(&dir.join("router.wal"), &registry, cfg(), router_lanes, recipients).unwrap();
    assert!(d.enable_margin_release().unwrap());
    assert!(d.enable_clearing(FUND).unwrap());
    let mut v = Venue { d, lanes: lanes.clone(), round: 0, seq: 0 };
    let venue_journal = net.venue.persister.journal_path().to_path_buf();
    let mut receipt = Vec::new();

    // A1 shape: 1 long 100x vs 2; 1 sells to 3 past its bankruptcy price (loss collected,
    // shortfall to the fund); 2 buys back from 3 (3's gain paid from the pool and fund).
    let trades: [Trade; 6] = [
        (2, 1, OrderSide::Long, 100_000, (X1, X100)),
        (3, 1, OrderSide::Short, 98_000, (X1, X1)),
        (3, 2, OrderSide::Long, 100_000, (X1, X1)),
        // A2 shape: 2 short 100x vs 1; 2 buys from 3 past bankruptcy; 1 sells to 3.
        (1, 2, OrderSide::Short, 100_000, (X1, X100)),
        (3, 2, OrderSide::Long, 102_000, (X1, X1)),
        (3, 1, OrderSide::Short, 104_000, (X1, X1)),
    ];
    for (i, (maker, taker, side, price, lev)) in trades.into_iter().enumerate() {
        let b = v.seal(maker, taker, side, 1000, price, lev);
        run(&mut v, &mut s, &net, &venue_journal, b, &mut receipt);
        if i == 1 {
            // A ledger amount one sat off what the persisted monitor shows is refused by the
            // signer, as is evidence that names another settlement.
            let plan_seq = v.d.next_resolution().unwrap() - 1;
            let c = v.d.clearing(plan_seq).unwrap().unwrap().clone();
            let st: LaneSettlement = s.settle(plan_seq, &c).unwrap().remove(0);
            let ev = st.evidence();
            let mut off = st.clone();
            off.owner_expected += 1;
            let oj = s.owner_journal(&st.channel).unwrap();
            assert!(matches!(attest(&oj, &off, Side::Owner, &off.evidence()), Err(shz_ldk::AttestError::Balance { .. })));
            assert_eq!(attest(&oj, &st, Side::Owner, &[1; 32]), Err(shz_ldk::AttestError::Evidence));
            assert_eq!(attest(&oj, &st, Side::Owner, &ev), Ok(()));
        }
    }
    let realized: Vec<i64> = (1..=3).map(|n| v.realized(n)).collect();
    let sum = v.d.clearing_summary().unwrap().unwrap();
    // A1 + A2 with a 50,000 sat fund: 1 −10,000 then +38,462; 2 −10,000; 3 +20,408 −18,854.
    assert_eq!(realized, vec![28_462, -10_000, 1_554]);
    assert_eq!(sum.cash, FUND as i64 - realized.iter().sum::<i64>());
    let out = serde_json::json!({
        "lanes": lanes.iter().map(|c| format!("{}:{}", hex::encode(c.txid), c.vout)).collect::<Vec<_>>(),
        "fund0": FUND, "fund_after": sum.fund, "cash_after": sum.cash, "realized": realized,
        "batches": receipt,
    });
    if let Some(p) = std::env::var_os("SHZ_LDK_RECEIPT") {
        std::fs::write(p, serde_json::to_vec_pretty(&out).unwrap()).unwrap();
    }
    eprintln!("{}", serde_json::to_string_pretty(&out).unwrap());
    drop(v);
    drop(net);
    let _ = std::fs::remove_dir_all(&dir);
}
