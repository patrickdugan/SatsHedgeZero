//! Real V3 clearing traces: a `DurableTieredRouter` with margin release and clearing on,
//! driven through post / take / seal / prepare / resolve with signed approvals and lane
//! acknowledgements (the harness of `crates/shz-dex/tests/hft06_clearing.rs`). Every
//! committed batch is recorded with the clearing state before it, its rows' inputs, the
//! real `BatchClearing` and the state after it. Synthetic funds only.
use crate::clearing_step::{Key, PoolState, RowIn};
use serde::{Deserialize, Serialize};
use shz_dex::routing::clearing::BatchClearing;
use shz_dex::routing::durable::{AckBundle, ChannelAck, Disposition, FeeRecipients, Head, Lane};
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dex::routing::*;
use shz_dex::OrderSide;
use shz_dlc::{bip340_sign, tagged_hash, Bip340Signature, BtcOutPoint};
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const T0: u64 = 1_000_000;
const AUTH: [u8; 32] = [77; 32];
const CAP: u64 = 100_000_000;
const ZERO: Bip340Signature = Bip340Signature { r_x: [0; 32], s: [0; 32] };
pub const X1: u32 = 10_000;
pub const X8: u32 = 80_000;
pub const X10: u32 = 100_000;
pub const X100: u32 = 1_000_000;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn pk(n: u8) -> [u8; 32] {
    public(&sk(n))
}
pub fn channel(n: u8) -> BtcOutPoint {
    BtcOutPoint { txid: [n; 32], vout: 0 }
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

static COUNTER: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let base = std::env::var_os("LIGHTNINGER_TRACE_TMP").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let p = base.join(format!("lightninger-clear-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One committed batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchRecord {
    pub seq: u64,
    /// State before the batch (`chain` left zero; the folding code fills it in).
    pub pre: PoolState,
    pub rows: Vec<RowIn>,
    pub report: BatchClearing,
    pub digest: [u8; 32],
    pub post: PoolState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trace {
    pub name: String,
    pub accounts: u8,
    pub table: usize,
    pub batches: Vec<BatchRecord>,
}

impl Trace {
    pub fn layers(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for b in &self.batches {
            let s = format!("{:?}", b.report.layer);
            if !v.contains(&s) {
                v.push(s);
            }
        }
        v
    }
    pub fn max_rows(&self) -> usize {
        self.batches.iter().map(|b| b.rows.len()).max().unwrap_or(0)
    }
}

pub struct Venue {
    d: DurableTieredRouter,
    _t: Temp,
    n: u8,
    table: usize,
    round: u64,
    seq: Cell<u64>,
    /// Scripted scenarios: every post and take must fill.
    pub strict: bool,
    pub batches: Vec<BatchRecord>,
}

impl Venue {
    /// `n` accounts (channels `[1;32]..[n;32]`), margin release on, clearing on with `fund`
    /// unless `None` (enable later with [`Venue::enable_clearing`]). `table` slots in the
    /// circuit's account table (`>= n`).
    pub fn new(n: u8, table: usize, fund: Option<u64>) -> Self {
        assert!(table >= n as usize);
        let t = Temp::new();
        let p = policy();
        let plans = (1..=n)
            .map(|i| Allocation::signed(p.scope(), &sk(i), &AUTH, channel(i), CAP, vec![Share { router: 1, sats: CAP }]).unwrap())
            .collect();
        let reg = Registry::new(p.scope(), public(&AUTH), plans).unwrap();
        let lanes: Vec<Lane> = (1..=n)
            .map(|i| Lane { channel: channel(i), peer: pk(70 + i), monitor: pk(90 + i), initial: Head { revision: 0, commitment: 10, state: [110 + i; 32] } })
            .collect();
        let mut d = DurableTieredRouter::create(&t.0.join("router.wal"), &reg, cfg(), lanes, FeeRecipients { oracle: pk(110), router: pk(111) }).unwrap();
        assert!(d.enable_margin_release().unwrap());
        if let Some(f) = fund {
            assert!(d.enable_clearing(f).unwrap());
        }
        Self { d, _t: t, n, table, round: 0, seq: Cell::new(0), strict: true, batches: Vec::new() }
    }

    pub fn enable_clearing(&mut self, fund: u64) {
        assert!(self.d.enable_clearing(fund).unwrap());
    }

    fn intent(&self, n: u8, action: Action, side: OrderSide, q: u64, price: u64, lev: u32, now: u64) -> IntentV6 {
        let c = cfg();
        self.seq.set(self.seq.get() + 1);
        IntentV6 {
            scope: c.scope,
            router: 1,
            channel: channel(n),
            owner: [0; 32],
            sequence: self.seq.get(),
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

    /// The circuit's account table: the venue's channels, then sentinel keys.
    pub fn keys(&self) -> Vec<Key> {
        let mut k: Vec<Key> = (1..=self.n).map(|i| ([i; 32], 0u32)).collect();
        for s in 0..(self.table - self.n as usize) {
            k.push(([0xff; 32], s as u32));
        }
        k
    }

    fn state(&self, seq: u64) -> PoolState {
        let s = self.d.clearing_summary().unwrap().expect("clearing on");
        let c = self.d.clearing_state().unwrap().unwrap();
        let keys = self.keys();
        let claims = keys.iter().map(|k| c.claim(&BtcOutPoint { txid: k.0, vout: k.1 })).collect();
        PoolState { seq, cash: s.cash, fund: s.fund, carry: s.carry, book: s.book, claims, keys, chain: [0; 32] }
    }

    /// One window: `fills` of `(maker, taker, taker_side, usd, (maker_lev, taker_lev))` at
    /// `price`, then seal, approve, acknowledge, commit. Records the batch if clearing is on.
    pub fn window(&mut self, price: u64, fills: &[(u8, u8, OrderSide, u64, (u32, u32))]) {
        self.round += 1;
        let t = T0 + self.round * 1_000_000;
        let now = t + 200_000;
        self.d
            .ingest_mark(
                MarkView { packet_digest: tagged_hash(b"lightninger/mark", &self.round.to_le_bytes()), seq: self.round, price_e8: Some(price * 100_000_000), boundary_us: t, public_release_us: t },
                t,
            )
            .unwrap();
        let mut filled = 0;
        for &(maker, taker, side, q, lev) in fills {
            let ms = if side == OrderSide::Long { OrderSide::Short } else { OrderSide::Long };
            let posted = self.d.submit(self.intent(maker, Action::Post, ms, q, price, lev.0, now), None, now).ok().and_then(|_| self.d.process_one(now).unwrap());
            let id = match posted {
                Some(TierOutcome::Posted(id)) => id,
                other => {
                    assert!(!self.strict, "post {maker}: {other:?}");
                    continue;
                }
            };
            let took = self.d.submit(self.intent(taker, Action::Take, side, q, price, lev.1, now), None, now).ok().and_then(|_| self.d.process_one(now).unwrap());
            if matches!(took, Some(TierOutcome::Filled(_))) {
                filled += 1;
                continue;
            }
            assert!(!self.strict, "take {taker}: {took:?}");
            let cancel = IntentV6 { cancel_target: id, ..self.intent(maker, Action::Cancel, ms, q, price, lev.0, now) }.signed(&sk(maker)).unwrap();
            if self.d.submit(cancel, None, now).is_ok() {
                let _ = self.d.process_one(now);
            }
        }
        if filled == 0 {
            self.d.process_one(t + 500_000).unwrap();
            if let Some(b) = self.d.seal_batch().unwrap() {
                panic!("empty window sealed batch {}", b.sequence());
            }
            return;
        }
        self.d.process_one(t + 500_000).unwrap();
        let b = self.d.seal_batch().unwrap().expect("window elapsed");
        let approvals: Vec<BatchApproval> = b
            .accounts()
            .iter()
            .map(|a| BatchApproval { channel: a.channel.clone(), signature: bip340_sign(&sk(a.channel.txid[0]), &b.approval_message(&a.channel).unwrap()).unwrap() })
            .collect();
        self.d.prepare(b.sequence(), approvals).unwrap();
        let clearing = self.d.clearing_active().unwrap();
        let pre = clearing.then(|| self.state(b.sequence()));
        let mut channels = Vec::new();
        for a in b.accounts() {
            let n = a.channel.txid[0];
            let previous = self.d.head(&a.channel).unwrap().unwrap();
            let mut next = previous;
            next.revision += 1;
            next.commitment += 1;
            next.state = tagged_hash(b"lightninger/state", &[&[n][..], &b.sequence().to_le_bytes()].concat());
            let mut c = ChannelAck {
                channel: a.channel.clone(),
                previous,
                next,
                evidence: tagged_hash(b"lightninger/evidence", &[&[n][..], &b.sequence().to_le_bytes()].concat()),
                fee_evidence: [0; 32],
                signatures: [ZERO; 3],
            };
            let h = self.d.ack_message(b.sequence(), Disposition::Commit, &c).unwrap();
            c.signatures = [bip340_sign(&sk(n), &h).unwrap(), bip340_sign(&sk(70 + n), &h).unwrap(), bip340_sign(&sk(90 + n), &h).unwrap()];
            channels.push(c);
        }
        assert!(self.d.resolve(AckBundle { sequence: b.sequence(), batch: b.digest(), disposition: Disposition::Commit, channels }).unwrap());
        if let Some(pre) = pre {
            let report = self.d.clearing(b.sequence()).unwrap().expect("clearing row").clone();
            let post = self.state(b.sequence() + 1);
            assert_eq!(post.identity(), 0, "router identity");
            let keys = self.keys();
            let rows = report
                .rows
                .iter()
                .map(|r| RowIn { slot: keys.iter().position(|k| k.0 == r.channel.txid && k.1 == r.channel.vout).expect("account in table"), pnl: r.pnl, released: r.released })
                .collect();
            let digest = report.digest();
            self.batches.push(BatchRecord { seq: b.sequence(), pre, rows, report, digest, post });
        }
    }

    pub fn trade(&mut self, maker: u8, taker: u8, side: OrderSide, q: u64, price: u64, lev: (u32, u32)) {
        self.window(price, &[(maker, taker, side, q, lev)]);
    }

    pub fn net(&self, n: u8) -> i64 {
        self.d.position(&channel(n)).unwrap().unwrap().net_usd()
    }

    /// Close every open position at `price`, longs against shorts.
    pub fn flatten(&mut self, price: u64) {
        while let (Some(l), Some(s)) = ((1..=self.n).find(|&i| self.net(i) > 0), (1..=self.n).find(|&i| self.net(i) < 0)) {
            let q = self.net(l).min(-self.net(s)) as u64;
            self.trade(s, l, OrderSide::Short, q, price, (X1, X1));
        }
        assert!((1..=self.n).all(|i| self.net(i) == 0));
    }

    pub fn finish(self, name: &str) -> Trace {
        Trace { name: name.into(), accounts: self.n, table: self.table, batches: self.batches }
    }
}

use OrderSide::{Long, Short};

/// The liquidation-drill price path (docs/SHZ_LIQUIDATION_DRILL.md) on the router:
/// A/B/C/D (1..4) open longs at 10x/10x/8x/10x against makers 5 and 6 at 100k, the mark
/// falls to 92k (A closes inside its margin), gaps to 88k (B and C close past bankruptcy),
/// recovers to 100k, and the book unwinds. With `fund > 0` the fund absorbs the
/// shortfalls; with `fund == 0` they are carried and haircut the next gains.
pub fn liquidation_drill(fund: u64, table: usize) -> Trace {
    let mut v = Venue::new(6, table, Some(fund));
    v.window(100_000, &[(5, 1, Long, 1000, (X1, X10)), (6, 2, Long, 1000, (X1, X10))]);
    v.window(100_000, &[(5, 3, Long, 1000, (X1, X8)), (6, 4, Long, 1000, (X1, X10))]);
    v.window(92_000, &[(5, 1, Short, 1000, (X1, X1))]);
    v.window(88_000, &[(6, 2, Short, 1000, (X1, X1)), (5, 3, Short, 1000, (X1, X1))]);
    v.window(100_000, &[(6, 4, Short, 1000, (X1, X1))]);
    v.flatten(100_000);
    v.finish(&format!("liquidation_drill_fund{fund}"))
}

/// A winner is owed a deferred claim (fund 0, the matching loser has not closed), then
/// loses more than its released margin: the loss takes its own claim (OwnClaim).
pub fn own_claim(table: usize) -> Trace {
    let mut v = Venue::new(4, table, Some(0));
    v.trade(2, 1, Long, 1000, 100_000, (X1, X1));
    v.trade(3, 1, Short, 1000, 110_000, (X1, X1));
    v.trade(2, 1, Long, 1000, 110_000, (X1, X100));
    v.trade(3, 1, Short, 1000, 100_000, (X1, X1));
    v.flatten(100_000);
    v.finish("own_claim")
}

/// V2 history first (audit finding A1 leaves the venue 10,408 sats short), then clearing
/// with no fund: the pool starts with negative cash and a carried deficit.
pub fn legacy_deficit(table: usize) -> Trace {
    let mut v = Venue::new(4, table, None);
    v.trade(2, 1, Long, 1000, 100_000, (X1, X100));
    v.trade(3, 1, Short, 1000, 98_000, (X1, X1));
    v.trade(3, 2, Long, 1000, 100_000, (X1, X1));
    v.enable_clearing(0);
    v.trade(2, 4, Long, 2000, 100_000, (X1, X1));
    v.trade(3, 4, Short, 2000, 104_000, (X1, X1));
    v.flatten(104_000);
    v.finish("legacy_deficit")
}

/// A seeded random walk over `n` accounts with mixed leverage, up to two fills per window.
pub fn random_walk(n: u8, table: usize, fund: u64, windows: usize, seed: u64) -> Trace {
    let mut v = Venue::new(n, table, Some(fund));
    v.strict = false;
    let mut x = seed | 1;
    let mut next = move |m: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % m
    };
    const LEVS: [u32; 4] = [X1, X8, X10, X100];
    let mut price = 100_000u64;
    for _ in 0..windows {
        price = (price as i64 + next(9_000) as i64 - 4_500).clamp(70_000, 140_000) as u64;
        let fills = 1 + next(2) as usize;
        let mut used = Vec::new();
        let mut f = Vec::new();
        for _ in 0..fills {
            let maker = 1 + next(n as u64) as u8;
            let taker = 1 + next(n as u64) as u8;
            if maker == taker || used.contains(&maker) || used.contains(&taker) {
                continue;
            }
            used.extend([maker, taker]);
            let side = if next(2) == 0 { Long } else { Short };
            f.push((maker, taker, side, 200 + next(1200), (LEVS[next(4) as usize], LEVS[next(4) as usize])));
        }
        if !f.is_empty() {
            v.window(price, &f);
        }
    }
    v.strict = true;
    v.flatten(price);
    v.finish(&format!("random_walk_n{n}_fund{fund}_seed{seed}"))
}

/// Committed batches of the live venue as a trace: `v` is `ops/venue-bench/dlc_demo/fill.mjs`
/// output (`status_before.clearing` and one explorer `batch`) or `{status_before, batches: [..]}`
/// with consecutive explorer batches. The pre-state of the first batch is the venue's clearing
/// summary taken before its fill; each later pre-state is the previous post-state. The account
/// table holds the batches' channels in first-appearance order, then sentinels. Deferred claims
/// must be zero venue-wide (per-account claims are not in the explorer JSON).
pub fn from_venue(v: &serde_json::Value, table: usize) -> Result<Trace, String> {
    let s = &v["status_before"]["clearing"];
    let batches: Vec<&serde_json::Value> = match v["batches"].as_array() {
        Some(a) => a.iter().map(|b| b.get("batch").unwrap_or(b)).collect(),
        None => vec![&v["batch"]["batch"]],
    };
    let int = |x: &serde_json::Value, k: &str| x[k].as_i64().ok_or(format!("{k} missing"));
    if int(s, "claims")? != 0 {
        return Err("venue has deferred claims: per-account claims are not in the explorer JSON".into());
    }
    let reports: Vec<(u64, BatchClearing)> = batches
        .iter()
        .map(|b| {
            if b["phase"] != "committed" {
                return Err(format!("batch {} is not committed", b["seq"]));
            }
            let r: BatchClearing = serde_json::from_value(b["clearing"].clone()).map_err(|e| format!("clearing: {e}"))?;
            Ok((b["seq"].as_u64().ok_or("seq")?, r))
        })
        .collect::<Result<_, String>>()?;
    let mut keys: Vec<crate::clearing_step::Key> = Vec::new();
    for (_, r) in &reports {
        for row in &r.rows {
            let k = (row.channel.txid, row.channel.vout);
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    // The step requires the table in ascending (txid, vout) order (the BTreeMap order clear walks
    // claims in); `(txid, vout)` tuple order is the order of `key_limbs`.
    keys.sort();
    let n = keys.len();
    if n > table {
        return Err(format!("{n} accounts do not fit a table of {table}"));
    }
    if keys.first().is_some_and(|k| k.0 == [0xff; 32]) || keys.last().is_some_and(|k| k.0 == [0xff; 32]) {
        return Err("an account txid collides with the sentinel keys".into());
    }
    for s in 0..(table - n) {
        keys.push(([0xff; 32], s as u32));
    }
    let mut pre = PoolState {
        seq: reports[0].0,
        cash: int(s, "cash")?,
        fund: int(s, "fund")? as u64,
        carry: int(s, "carry")? as u64,
        book: int(s, "book")? as i128,
        claims: vec![0; table],
        keys: keys.clone(),
        chain: [0; 32],
    };
    if pre.identity() != 0 {
        return Err(format!("venue summary identity {} != 0", pre.identity()));
    }
    let mut out = Vec::new();
    for (seq, report) in reports {
        if seq != pre.seq || report.cash_before != pre.cash {
            return Err(format!("batch {seq} does not follow state {} (cash {} vs {})", pre.seq, report.cash_before, pre.cash));
        }
        if report.claims_after != 0 || !report.claim_haircuts.is_empty() {
            return Err(format!("batch {seq} leaves deferred claims"));
        }
        let rows: Vec<RowIn> = report
            .rows
            .iter()
            .map(|r| RowIn { slot: keys.iter().position(|k| k.0 == r.channel.txid && k.1 == r.channel.vout).unwrap(), pnl: r.pnl, released: r.released })
            .collect();
        let pnl: i128 = report.rows.iter().map(|r| r.pnl as i128).sum();
        let post = PoolState {
            seq: seq + 1,
            cash: report.cash_after,
            fund: report.fund_after,
            carry: report.carry_after,
            book: pre.book - pnl,
            claims: vec![0; table],
            keys: keys.clone(),
            chain: [0; 32],
        };
        if post.identity() != 0 {
            return Err(format!("batch {seq} post identity {} != 0", post.identity()));
        }
        let digest = report.digest();
        out.push(BatchRecord { seq, pre: pre.clone(), rows, report, digest, post: post.clone() });
        pre = post;
    }
    Ok(Trace { name: v["name"].as_str().unwrap_or("venue").to_string(), accounts: n as u8, table, batches: out })
}
