//! Venue core: one durable tiered router, account registration, order intake,
//! settlement plumbing (approvals, simulated channel acknowledgements, fee
//! ledger) and the read views the UI and explorer use.

use std::{
    collections::{BTreeMap, VecDeque},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use serde_json::{Value, json};
use shz_dex::{
    OrderSide,
    routing::{
        Action, Allocation, Balance, Batch, BatchApproval, Policy, Registry, Scope, Share,
        durable::{AckBundle, ChannelAck, Disposition, FeeRecipients, Head, Lane, Phase},
        ln_fees::{FeeLedger, GroupCommit, RecipientPolicy},
        public,
        tiered::{
            Arm, Entitlement, ExecutionPolicy, FeedTier, IntentV6, MarkView, RevenuePolicy, TariffSchedule,
            TierOutcome, TieredConfig, ZERO_SIG,
        },
        tiered_durable::{ABORT_AFTER_US, DurableTieredRouter},
    },
};
use shz_dlc::{Bip340Signature, BtcOutPoint, bip340_sign, bip340_verify, tagged_hash};

pub mod agents;
pub mod collateral;
pub mod options;
pub mod spot;

pub type Key = [u8; 32];
pub const ROUTER_ID: u32 = 1;
pub const MARKET: &str = "SHZ-BTCUSD-INV";
pub const DEMO_CAP_SATS: u64 = 200_000;
/// Clearing fund for multilateral clearing (V3): the venue's own sats on its clearing ledger that
/// pay winners before their losers close and absorb shortfalls before any haircut. On testnet this
/// is a ledger amount; the settlement adapter is simulated, so no on-chain output backs it.
pub const CLEARING_FUND_SATS: u64 = 1_000_000;
const MAX_TRADES: usize = 2_000;
const MAX_PACKETS: usize = 600;

pub fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_micros() as u64
}
pub fn h(k: &[u8]) -> String {
    hex::encode(k)
}
pub fn parse_key(s: &str) -> Result<Key, String> {
    hex::decode(s).map_err(|_| "bad hex".to_string())?.try_into().map_err(|_| "expected 32 bytes".to_string())
}
pub fn parse_sig(s: &str) -> Result<Bip340Signature, String> {
    let b = hex::decode(s).map_err(|_| "bad hex".to_string())?;
    if b.len() != 64 {
        return Err("expected 64-byte signature".into());
    }
    Ok(Bip340Signature { r_x: b[..32].try_into().unwrap(), s: b[32..].try_into().unwrap() })
}
fn sig_hex(s: &Bip340Signature) -> String {
    hex::encode(s.to_bytes())
}
fn outpoint_json(o: &BtcOutPoint) -> Value {
    json!({"txid": h(&o.txid), "vout": o.vout})
}

/// Venue-held keys, all derived from one 32-byte seed kept in the state dir.
pub struct Keys {
    seed: Key,
    pub authority_sk: Key,
    pub entitlement_sk: Key,
}
impl Keys {
    fn derive(seed: &Key, label: &str) -> Key {
        let mut ctr = 0u32;
        loop {
            let mut b = seed.to_vec();
            b.extend(label.as_bytes());
            b.extend(ctr.to_le_bytes());
            let k = tagged_hash(b"SHZ/VENUE/KEY/V1", &b);
            if shz_dlc::pubkey_x_from_secret(&k).is_ok() {
                return k;
            }
            ctr += 1;
        }
    }
    pub fn new(seed: Key) -> Self {
        Self { authority_sk: Self::derive(&seed, "authority"), entitlement_sk: Self::derive(&seed, "entitlement"), seed }
    }
    fn lane_sk(&self, role: &str, c: &BtcOutPoint) -> Key {
        Self::derive(&self.seed, &format!("{role}:{}:{}", h(&c.txid), c.vout))
    }
    fn named(&self, label: &str) -> Key {
        Self::derive(&self.seed, label)
    }
}

#[derive(Clone)]
pub struct AccountMeta {
    pub owner: Key,
    pub outpoint: BtcOutPoint,
    pub kind: String,
    pub cap_sats: u64,
    pub label: String,
}

struct Draft {
    allocation: Allocation,
    meta: AccountMeta,
}

#[derive(Clone)]
pub struct IntentRec {
    pub intent: IntentV6,
    pub status: String,
    pub remaining: u64,
    pub accepted_us: u64,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct PacketRec {
    pub seq: u64,
    pub slot_us: u64,
    pub status: String,
    pub median_e8: Option<u64>,
    pub digest: Key,
    pub signers: Value,
    pub verified: bool,
    pub received_us: u64,
}

#[derive(Clone)]
pub struct TradeRec {
    pub id: Key,
    pub maker_id: Key,
    pub ts_us: u64,
    pub price_usd: u64,
    pub qty_usd: u64,
    pub taker_side: OrderSide,
    pub maker_tier: FeedTier,
    pub taker_tier: FeedTier,
    pub maker_owner: Key,
    pub taker_owner: Key,
    pub packet: Option<PacketRec>,
    pub binding: Key,
    pub maker_entitlement: Key,
    pub taker_entitlement: Key,
    pub maker_fee_sats: u64,
    pub taker_fee_sats: u64,
    pub oracle_due_sats: u64,
    pub router_due_sats: u64,
    pub long_margin_sats: u64,
    pub short_margin_sats: u64,
    pub early_window: bool,
    pub batch_seq: Option<u64>,
}

pub struct BatchRec {
    pub seq: u64,
    pub digest: Key,
    pub phase: String,
    pub legs: Vec<Key>,
    pub accounts: Vec<(BtcOutPoint, Key, u64, u64)>,
    pub oracle_due: u128,
    pub router_due: u128,
    pub window: (u64, u64),
    approvals: BTreeMap<(Key, u32), Bip340Signature>,
    acks: Vec<ChannelAck>,
    pub created_us: u64,
    /// Venue clock when this process saw the batch reach prepared / committed (or aborted,
    /// in `committed_us`, for a deadline abort).
    pub prepared_us: Option<u64>,
    pub committed_us: Option<u64>,
    /// Channels whose approval / lane-ack owner slot an agent signed, with the grant.
    pub delegated: BTreeMap<(Key, u32), Key>,
    pub ack_delegated: BTreeMap<(Key, u32), Key>,
}

#[derive(Clone)]
pub struct PendingSig {
    pub id: String,
    pub owner: Key,
    pub kind: String,
    pub message: Key,
    pub context: Value,
}

pub struct Venue {
    pub keys: Keys,
    pub scope: Scope,
    pub cfg: TieredConfig,
    pub group_key: Key,
    pub relay_url: String,
    router: DurableTieredRouter,
    ledger: FeeLedger,
    pub accounts: BTreeMap<Key, AccountMeta>,
    drafts: BTreeMap<String, Draft>,
    pub intents: BTreeMap<Key, IntentRec>,
    pending_queue: BTreeMap<(u64, u64), Key>,
    pending_cancels: BTreeMap<(u64, u64), Key>,
    arrival: u64,
    /// Execution times of fills not yet sealed into a batch.
    unsealed: VecDeque<u64>,
    entitlements: BTreeMap<Key, Entitlement>,
    pub trades: VecDeque<TradeRec>,
    pub batches: BTreeMap<u64, BatchRec>,
    pub packets: VecDeque<PacketRec>,
    pub mark: Option<PacketRec>,
    pub pending: BTreeMap<String, PendingSig>,
    pub candles: BTreeMap<u64, [f64; 5]>,
    log: File,
    pub events: Vec<Value>,
    pub wallets: crate::wallet::Wallets,
    /// Last risk state per account with open lots, and when it first went below maintenance.
    risk_state: BTreeMap<Key, (crate::risk::State, Option<u64>)>,
    /// Options (`--options`): `None` keeps every option endpoint off.
    pub opts: Option<options::OptState>,
    /// Option records of the venue log (`opt_*`), folded in when options are switched on.
    opt_log: Vec<Value>,
    /// Spot (`--spot`, on top of options): `None` keeps every spot endpoint off.
    pub spot: Option<spot::SpotState>,
    /// Delegated agent keys (`--agents`): `None` keeps every agent endpoint off.
    pub agents: Option<agents::AgentState>,
    /// Agent records of the venue log (`agent_*`), folded in when agents are switched on.
    agent_log: Vec<Value>,
    /// On-chain collateral accounts (`--collateral-chain`): `None` keeps them off.
    pub coll: Option<collateral::CollState>,
    /// Collateral records of the venue log (`coll_*`), folded in when collateral is switched on.
    coll_log: Vec<Value>,
}

fn venue_scope(keys: &Keys) -> (Scope, Policy) {
    let p = Policy {
        network: tagged_hash(b"SHZ/VENUE/NETWORK/V1", b"testnet4"),
        epoch: 1,
        relay_keys: [public(&keys.named("relay-a")), public(&keys.named("relay-b"))],
    };
    (p.scope(), p)
}

pub fn demo_outpoint(owner: &Key) -> BtcOutPoint {
    BtcOutPoint { txid: tagged_hash(b"SHZ/VENUE/DEMO-OUTPOINT/V1", owner), vout: 0 }
}

impl Venue {
    pub fn open(state: &Path, group_key: Key, relay_url: String) -> Result<Self, String> {
        std::fs::create_dir_all(state).map_err(|e| e.to_string())?;
        let seed_path = state.join("venue.seed");
        if !seed_path.exists() {
            let mut s = [0u8; 32];
            getrandom(&mut s)?;
            std::fs::write(&seed_path, hex::encode(s)).map_err(|e| e.to_string())?;
        }
        let seed = parse_key(std::fs::read_to_string(&seed_path).map_err(|e| e.to_string())?.trim())?;
        let keys = Keys::new(seed);
        let (scope, _policy) = venue_scope(&keys);
        let cfg = TieredConfig {
            scope,
            router: ROUTER_ID,
            entitlement_key: public(&keys.entitlement_sk),
            tariff: TariffSchedule::default_candidate(),
            execution: ExecutionPolicy::defaults(Arm::FeedOnly),
            revenue: RevenuePolicy::default(),
        };
        let recipients = FeeRecipients { oracle: public(&keys.named("rcpt-oracle")), router: public(&keys.named("rcpt-router")) };
        let registry = Registry::new(scope, public(&keys.authority_sk), vec![]).map_err(|e| format!("{e:?}"))?;
        let jpath = state.join("router.wal");
        let mut router = if jpath.exists() {
            DurableTieredRouter::open(&jpath, &registry, cfg.clone(), vec![], recipients, None).map_err(|e| format!("router journal: {e}"))?
        } else {
            DurableTieredRouter::create(&jpath, &registry, cfg.clone(), vec![], recipients).map_err(|e| format!("router journal: {e}"))?
        };
        // Margin release: journaled once. On a journal that predates it, positions are rebuilt
        // from every committed batch and the offset margin is released before anything else runs.
        router.enable_margin_release().map_err(|e| format!("margin release: {e}"))?;
        // Multilateral clearing (docs/SHZ_VENUE_CLEARING.md): journaled once; an existing journal is
        // folded in and acks switch to the V3 tag.
        router.enable_clearing(CLEARING_FUND_SATS).map_err(|e| format!("clearing: {e}"))?;
        // Closing loans (journaled separately): a take that reduces the position borrows its leg
        // margin from the lots it closes, so an account with no free margin can still close.
        router.enable_closing_loans().map_err(|e| format!("closing loans: {e}"))?;
        let rp = RecipientPolicy {
            version: 1,
            oracle_operators: (1..=5).map(|i| (public(&keys.named(&format!("oracle-op-{i}"))), 1)).collect(),
            upkeep: (public(&keys.named("upkeep")), 1_000),
            router: recipients.router,
        };
        let group = GroupCommit { max_obligations: 64, max_delay_us: 60_000_000 };
        let lpath = state.join("fees.wal");
        let ledger = if lpath.exists() {
            FeeLedger::open(&lpath, ROUTER_ID, rp, group).map_err(|e| format!("fee ledger: {e:?}"))?
        } else {
            FeeLedger::create(&lpath, ROUTER_ID, rp, group).map_err(|e| format!("fee ledger: {e:?}"))?
        };
        let vpath = state.join("venue.jsonl");
        let prior: Vec<Value> = if vpath.exists() {
            BufReader::new(File::open(&vpath).map_err(|e| e.to_string())?)
                .lines()
                .map_while(Result::ok)
                .filter_map(|l| serde_json::from_str(&l).ok())
                .collect()
        } else {
            vec![]
        };
        let log = OpenOptions::new().create(true).append(true).open(&vpath).map_err(|e| e.to_string())?;
        let mut v = Self {
            keys,
            scope,
            cfg,
            group_key,
            relay_url,
            router,
            ledger,
            accounts: BTreeMap::new(),
            drafts: BTreeMap::new(),
            intents: BTreeMap::new(),
            pending_queue: BTreeMap::new(),
            pending_cancels: BTreeMap::new(),
            arrival: 0,
            unsealed: VecDeque::new(),
            entitlements: BTreeMap::new(),
            trades: VecDeque::new(),
            batches: BTreeMap::new(),
            packets: VecDeque::new(),
            mark: None,
            pending: BTreeMap::new(),
            candles: BTreeMap::new(),
            log,
            events: vec![],
            wallets: Default::default(),
            risk_state: BTreeMap::new(),
            opts: None,
            opt_log: vec![],
            spot: None,
            agents: None,
            agent_log: vec![],
            coll: None,
            coll_log: vec![],
        };
        // Account metadata is restored from the venue log; the router replays its own journal.
        for e in prior {
            if e["kind"].as_str().is_some_and(|k| k.starts_with("opt_")) {
                v.opt_log.push(e);
                continue;
            }
            if e["kind"].as_str().is_some_and(|k| k.starts_with("agent_")) {
                v.agent_log.push(e);
                continue;
            }
            if e["kind"].as_str().is_some_and(|k| k.starts_with("coll_")) {
                v.coll_log.push(e);
                continue;
            }
            if e["kind"] == "wallet_link" {
                v.restore_link(&e);
            }
            if e["kind"] == "account" {
                let owner = parse_key(e["owner"].as_str().unwrap_or(""))?;
                let txid = parse_key(e["outpoint"]["txid"].as_str().unwrap_or(""))?;
                let meta = AccountMeta {
                    owner,
                    outpoint: BtcOutPoint { txid, vout: e["outpoint"]["vout"].as_u64().unwrap_or(0) as u32 },
                    kind: e["account_kind"].as_str().unwrap_or("demo").into(),
                    cap_sats: e["cap_sats"].as_u64().unwrap_or(0),
                    label: e["label"].as_str().unwrap_or("").into(),
                };
                v.accounts.insert(owner, meta);
            }
        }
        v.restore_from_router()?;
        Ok(v)
    }

    /// Rebuild the read views from the router's own journaled state after a restart:
    /// resting quotes, sealed batches with their fills, and the signatures each
    /// unresolved batch still needs. Packets and rejected intents are not retained.
    fn restore_from_router(&mut self) -> Result<(), String> {
        let r = self.router.router().map_err(|e| e.to_string())?;
        let now = now_us();
        let quotes: Vec<(IntentV6, u64)> = r.resting_quotes().into_iter().map(|(i, q)| (i.clone(), q)).collect();
        let last_batch = r.batch_sequence();
        for (i, remaining) in quotes {
            self.intents.insert(i.id(), IntentRec { intent: i, status: "resting".into(), remaining, accepted_us: now, reason: Some("restored".into()) });
        }
        for seq in 1..=last_batch {
            let Some((b, phase)) = self.router.batch(seq).map_err(|e| e.to_string())? else { continue };
            let b = b.clone();
            for f in b.legs() {
                let taker_side = if f.maker_side == OrderSide::Long { OrderSide::Short } else { OrderSide::Long };
                self.trades.push_front(TradeRec {
                    id: f.taker_id, maker_id: f.maker_id, ts_us: f.execution_us, price_usd: f.spec.entry_price_usd, qty_usd: f.spec.usd_notional,
                    taker_side, maker_tier: FeedTier::Standard, taker_tier: FeedTier::Standard, maker_owner: f.maker_owner, taker_owner: f.taker_owner,
                    packet: None, binding: f.mark_id, maker_entitlement: [0; 32], taker_entitlement: [0; 32],
                    maker_fee_sats: f.maker_fee_sats, taker_fee_sats: f.taker_fee_sats, oracle_due_sats: f.oracle_due_sats, router_due_sats: f.router_due_sats,
                    long_margin_sats: f.spec.long_margin_sats, short_margin_sats: f.spec.short_margin_sats, early_window: false, batch_seq: Some(seq),
                });
                let minute = f.execution_us / 60_000_000 * 60_000;
                let px = f.spec.entry_price_usd as f64;
                let c = self.candles.entry(minute).or_insert([px, px, px, px, 0.0]);
                c[1] = c[1].max(px);
                c[2] = c[2].min(px);
                c[3] = px;
                c[4] += f.spec.usd_notional as f64 / px;
            }
            self.on_batch(b);
            let new_phase = match phase {
                Phase::Sealed => continue,
                // Approvals are already journaled; advance_settlement regenerates the acks.
                Phase::Prepared => "restored-prepared",
                Phase::Committed => "committed",
                Phase::Aborted => "aborted",
            };
            self.pending.retain(|_, p| p.context["batch_seq"].as_u64() != Some(seq));
            let rec = self.batches.get_mut(&seq).unwrap();
            rec.phase = new_phase.into();
            if phase == Phase::Prepared {
                let keys: Vec<_> = rec.accounts.iter().map(|(c, _, _, _)| (c.txid, c.vout)).collect();
                for k in keys {
                    rec.approvals.insert(k, ZERO_SIG);
                }
            }
        }
        self.trades.make_contiguous().sort_by_key(|t| std::cmp::Reverse(t.ts_us));
        self.advance_settlement(now)?;
        self.events.clear();
        Ok(())
    }

    pub(crate) fn persist(&mut self, e: Value) {
        let _ = writeln!(self.log, "{e}");
        let _ = self.log.sync_data();
    }
    pub(crate) fn emit(&mut self, e: Value) {
        self.events.push(e);
    }

    /// Drain pending stream events; per-change `book` notices collapse into one
    /// event carrying the current book snapshot.
    pub fn drain_events(&mut self) -> Vec<String> {
        let evs: Vec<Value> = std::mem::take(&mut self.events);
        let mut out: Vec<String> = evs.iter().filter(|e| e["type"] != "book").map(|e| e.to_string()).collect();
        if evs.iter().any(|e| e["type"] == "account") {
            out.retain(|e| !e.starts_with("{\"type\":\"account\""));
            out.push(json!({"type": "account"}).to_string());
        }
        if evs.iter().any(|e| e["type"] == "book") {
            let mut b = self.book(25);
            b["type"] = json!("book");
            out.push(b.to_string());
        }
        out
    }

    pub fn template(&self) -> Value {
        json!({
            "market": MARKET,
            "scope": {"network": h(&self.scope.network), "epoch": self.scope.epoch, "policy": h(&self.scope.policy)},
            "router": ROUTER_ID,
            "tariff_version": self.cfg.tariff.version,
            "execution_policy": h(&self.router_policy_id()),
            "tariff": {"maker_ppm": self.cfg.tariff.maker_ppm, "taker_ppm": self.cfg.tariff.taker_ppm},
            "max_mark_age_us": 15_000_000u64,
            "leverage_bps": {"min": 1_000, "max": 100_000},
            "collar_bps": 200,
            "entitlement_key": h(&self.cfg.entitlement_key),
            "authority_key": h(&public(&self.keys.authority_sk)),
            "group_key": h(&self.group_key),
        })
    }
    fn router_policy_id(&self) -> Key {
        self.router.router().map(|r| r.execution_policy_id()).unwrap_or([0; 32])
    }

    // ------------------------------------------------------------ marks ----
    pub fn ingest_packet(&mut self, p: PacketRec) -> Result<(), String> {
        if self.mark.as_ref().is_some_and(|m| m.seq >= p.seq) {
            return Ok(());
        }
        let now = now_us().max(self.router.router().map(|r| r.clock_us()).unwrap_or(0));
        let mv = MarkView {
            packet_digest: p.digest,
            seq: p.seq,
            price_e8: p.median_e8,
            boundary_us: p.slot_us.min(now),
            public_release_us: p.slot_us.min(now),
        };
        self.router.ingest_mark(mv, now).map_err(|e| format!("mark: {e}"))?;
        if let Some(m) = p.median_e8 {
            let minute = p.slot_us / 60_000_000 * 60_000;
            let px = m as f64 / 1e8;
            let c = self.candles.entry(minute).or_insert([px, px, px, px, 0.0]);
            if c[4] == 0.0 {
                // No trade yet this minute: the oracle mark draws the candle.
                c[1] = c[1].max(px);
                c[2] = c[2].min(px);
                c[3] = px;
            }
        }
        self.packets.push_back(p.clone());
        while self.packets.len() > MAX_PACKETS {
            self.packets.pop_front();
        }
        self.emit(json!({"type": "mark", "mark": packet_json(&p)}));
        self.mark = Some(p);
        self.update_risk(now);
        Ok(())
    }

    // ------------------------------------------------------------- risk ----
    fn clearing_on(&self) -> bool {
        self.router.clearing_active().unwrap_or(false)
    }

    fn mark_usd(&self) -> Option<u64> {
        self.mark.as_ref().and_then(|m| m.median_e8).map(|m| (m + 50_000_000) / 100_000_000)
    }

    fn lots_of(&self, owner: &Key) -> Vec<shz_dex::routing::positions::Lot> {
        self.accounts.get(owner)
            .and_then(|a| self.router.position(&a.outpoint).ok().flatten())
            .map(|p| p.lots().copied().collect())
            .unwrap_or_default()
    }

    /// Recompute every account's risk state at the current mark; emit `risk` on a change and
    /// start the liquidation-auction clock when an account first goes below maintenance.
    fn update_risk(&mut self, now: u64) {
        let Some(mark) = self.mark_usd() else { return };
        let clearing = self.clearing_on();
        let owners: Vec<Key> = self.accounts.keys().copied().collect();
        for owner in owners {
            let lots = self.lots_of(&owner);
            let st = crate::risk::state(&lots, mark, clearing);
            let prev = self.risk_state.get(&owner).copied();
            if st == crate::risk::State::Flat && prev.is_none() {
                continue;
            }
            let since = match (st.reduce_only(), prev) {
                (true, Some((_, Some(t)))) => Some(t),
                (true, _) => Some(now),
                (false, _) => None,
            };
            if prev.map(|p| p.0) != Some(st) {
                let ratio = crate::risk::margin_bps(&lots, mark, clearing);
                self.emit(json!({"type": "risk", "owner": h(&owner), "state": st.name(), "margin_bps": ratio, "mark_usd": mark}));
            }
            if st == crate::risk::State::Flat {
                self.risk_state.remove(&owner);
            } else {
                self.risk_state.insert(owner, (st, since));
            }
        }
    }

    /// Signed USD (long +) of this account's fills whose batch has not committed, and whether any
    /// fill of the account is still unsettled (unsealed, sealed or prepared; aborted fills never settle).
    fn unsettled_of(&self, owner: &Key) -> (i64, bool) {
        let (mut net, mut any) = (0i64, false);
        for t in &self.trades {
            let sign = if t.taker_owner == *owner {
                if t.taker_side == OrderSide::Long { 1 } else { -1 }
            } else if t.maker_owner == *owner {
                if t.taker_side == OrderSide::Long { -1 } else { 1 }
            } else {
                continue;
            };
            let phase = t.batch_seq.and_then(|s| self.batches.get(&s)).map(|b| b.phase.as_str());
            if matches!(phase, Some("committed") | Some("aborted")) {
                continue;
            }
            net += sign * t.qty_usd as i64;
            any = true;
        }
        (net, any)
    }

    pub fn risk_view(&self, owner: &Key) -> Value {
        let lots = self.lots_of(owner);
        let since = self.risk_state.get(owner).and_then(|r| r.1);
        let elapsed = since.map(|t| now_us().saturating_sub(t) / 1_000);
        crate::risk::view(&lots, self.mark_usd(), elapsed, self.clearing_on())
    }

    // ---------------------------------------------------- registration ----
    pub fn register_draft(&mut self, owner: Key, kind: &str, outpoint: Option<BtcOutPoint>, utxo_value: Option<u64>) -> Result<Value, String> {
        shz_dlc::lift_x_even(&owner).map_err(|_| "owner is not a valid x-only key")?;
        if self.accounts.contains_key(&owner) {
            return Err("owner already has an account".into());
        }
        if self.coll.is_some() && kind != "collateral" {
            return Err("this venue takes on-chain collateral only: deposit to your collateral address, then register kind collateral".into());
        }
        let (outpoint, cap, label) = match kind {
            "demo" => (demo_outpoint(&owner), DEMO_CAP_SATS, "TESTNET DEMO CREDIT".to_string()),
            "collateral" => self.collateral_draft_source(&owner)?,
            "utxo" => {
                let o = outpoint.ok_or("utxo account needs an outpoint")?;
                let v = utxo_value.ok_or("utxo value unverified")?;
                (o, v, "testnet4 UTXO".to_string())
            }
            _ => return Err("kind must be demo, utxo or collateral".into()),
        };
        if self.accounts.values().any(|a| a.outpoint == outpoint) {
            return Err("outpoint already registered".into());
        }
        let allocation = Allocation {
            scope: self.scope,
            owner,
            channel: outpoint.clone(),
            total_sats: cap,
            shares: vec![Share { router: ROUTER_ID, sats: cap }],
            owner_sig: ZERO_SIG,
            authority_sig: ZERO_SIG,
        };
        let digest = allocation.digest().map_err(|e| format!("{e:?}"))?;
        let draft_id = h(&tagged_hash(b"SHZ/VENUE/DRAFT/V1", &[digest.as_slice(), &now_us().to_le_bytes()].concat()))[..24].to_string();
        let meta = AccountMeta { owner, outpoint: outpoint.clone(), kind: kind.into(), cap_sats: cap, label: label.clone() };
        self.drafts.insert(draft_id.clone(), Draft { allocation, meta });
        Ok(json!({"allocation_digest": h(&digest), "draft_id": draft_id, "cap_sats": cap, "outpoint": outpoint_json(&outpoint), "label": label}))
    }

    pub fn register(&mut self, draft_id: &str, owner_sig: Bip340Signature) -> Result<Value, String> {
        let Draft { mut allocation, meta } = self.drafts.remove(draft_id).ok_or("unknown or used draft")?;
        let digest = allocation.digest().map_err(|e| format!("{e:?}"))?;
        bip340_verify(&allocation.owner, &digest, &owner_sig).map_err(|_| "owner signature does not verify")?;
        allocation.owner_sig = owner_sig;
        allocation.authority_sig = bip340_sign(&self.keys.authority_sk, &digest).map_err(|e| e.to_string())?;
        let c = allocation.channel.clone();
        let lane = Lane {
            channel: c.clone(),
            peer: public(&self.keys.lane_sk("peer", &c)),
            monitor: public(&self.keys.lane_sk("monitor", &c)),
            initial: Head { revision: 0, commitment: 0, state: tagged_hash(b"SHZ/VENUE/LANE-GENESIS/V1", &[c.txid.as_slice(), &c.vout.to_le_bytes()].concat()) },
        };
        self.router.register(allocation, lane).map_err(|e| format!("register: {e}"))?;
        self.persist(json!({"kind": "account", "owner": h(&meta.owner), "outpoint": outpoint_json(&meta.outpoint),
                            "account_kind": meta.kind, "cap_sats": meta.cap_sats, "label": meta.label}));
        self.accounts.insert(meta.owner, meta.clone());
        if meta.kind == "collateral" {
            self.collateral_registered(&meta.owner)?;
        }
        Ok(self.account_view(&meta.owner))
    }

    pub fn entitlement(&mut self, owner: Key, tier: FeedTier) -> Result<Value, String> {
        if tier == FeedTier::Standard {
            return Err("standard needs no entitlement".into());
        }
        let now = now_us();
        let e = Entitlement {
            client: owner,
            tier,
            tariff_version: self.cfg.tariff.version,
            valid_from_us: now.saturating_sub(60_000_000),
            valid_until_us: now + 86_400_000_000,
            relay_key: [0; 32],
            signature: ZERO_SIG,
        }
        .signed(&self.keys.entitlement_sk)
        .map_err(|e| format!("{e:?}"))?;
        let d = e.digest();
        self.entitlements.insert(d, e.clone());
        Ok(json!({"digest": h(&d), "tier": tier_name(tier), "valid_until_us": e.valid_until_us, "label": "TESTNET ENTITLEMENT"}))
    }

    // ----------------------------------------------------------- intake ----
    pub fn intent_from_json(&self, j: &Value) -> Result<IntentV6, String> {
        let s = |k: &str| j[k].as_str().ok_or_else(|| format!("missing {k}"));
        let u = |k: &str| j[k].as_u64().ok_or_else(|| format!("missing {k}"));
        let action = match s("action")? {
            "post" => Action::Post,
            "take" => Action::Take,
            "cancel" => Action::Cancel,
            _ => return Err("bad action".into()),
        };
        let side = match s("side")? {
            "long" => OrderSide::Long,
            "short" => OrderSide::Short,
            _ => return Err("bad side".into()),
        };
        let tier = parse_tier(s("tier")?)?;
        let zero = [0u8; 32];
        Ok(IntentV6 {
            scope: self.scope,
            router: ROUTER_ID,
            channel: BtcOutPoint { txid: parse_key(j["channel"]["txid"].as_str().ok_or("missing channel")?)?, vout: j["channel"]["vout"].as_u64().ok_or("missing vout")? as u32 },
            owner: parse_key(s("owner")?)?,
            sequence: u("sequence")?,
            expires_us: u("expires_us")?,
            action,
            side,
            tier,
            tariff_version: self.cfg.tariff.version,
            entitlement_digest: j["entitlement_digest"].as_str().map(parse_key).transpose()?.unwrap_or(zero),
            execution_policy: self.router_policy_id(),
            quantity: u("quantity")?,
            limit_usd: u("limit_usd")?,
            leverage_bps: u("leverage_bps")? as u32,
            max_fee_ppm: u("max_fee_ppm")? as u32,
            max_fee_sats: u("max_fee_sats")?,
            max_mark_age_us: u("max_mark_age_us")?,
            early_window_opt_in: j["early_window_opt_in"].as_bool().unwrap_or(false),
            cancel_target: j["cancel_target"].as_str().map(parse_key).transpose()?.unwrap_or(zero),
            signature: j["signature"].as_str().map(parse_sig).transpose()?.unwrap_or(ZERO_SIG),
        })
    }

    pub fn submit(&mut self, i: IntentV6) -> Result<Value, String> {
        self.submit_with(i, None)
    }

    /// `submit`, signed by the owner (`grant == None`) or by the agent of `grant` (router agent path).
    pub fn submit_with(&mut self, i: IntentV6, grant: Option<Key>) -> Result<Value, String> {
        self.wallet_check(&i.owner)?;
        if i.action != Action::Cancel {
            self.collateral_gate(&i.owner)?;
            let lots = self.lots_of(&i.owner);
            let (unsettled, in_flight) = self.unsettled_of(&i.owner);
            // One closing loan in flight per account (docs/SHZ_LIQUIDATION_DRILL.md F1): a take that
            // reduces the position borrows margin from the lots it closes, and a second loan taken
            // before the first batch resolves breaks that batch's balance check for every account.
            let reduces = lots.first().is_some_and(|l| l.side != i.side);
            if i.action == Action::Take && reduces && in_flight {
                return Err("a previous fill of this account is still settling: a take that reduces the position waits until it commits".into());
            }
            crate::risk::gate(&lots, self.mark_usd(), i.side, i.quantity, self.clearing_on(), unsettled)?;
        }
        let id = i.id();
        let ent = (i.tier != FeedTier::Standard).then(|| self.entitlements.get(&i.entitlement_digest).cloned()).flatten();
        let now = now_us().max(self.router.router().map(|r| r.clock_us()).unwrap_or(0));
        let due = match grant {
            Some(g) => self.router.submit_agent(i.clone(), ent, now, g),
            None => self.router.submit(i.clone(), ent, now),
        }
        .map_err(|e| format!("{e}"))?;
        self.arrival += 1;
        let q = if i.action == Action::Cancel { &mut self.pending_cancels } else { &mut self.pending_queue };
        q.insert((due, self.arrival), id);
        self.intents.insert(id, IntentRec { intent: i, status: "queued".into(), remaining: 0, accepted_us: now, reason: None });
        Ok(json!({"id": h(&id), "due_us": due}))
    }

    /// Mirror of `TieredRouter::process_one` ordering: due cancels first, then
    /// the earliest due post or take, both keyed by (due, arrival).
    fn next_processed(&mut self, now: u64) -> Option<Key> {
        let cancel_due = self.pending_cancels.first_key_value().is_some_and(|(k, _)| k.0 <= now);
        let q = if cancel_due { &mut self.pending_cancels } else { &mut self.pending_queue };
        let (&k, _) = q.first_key_value()?;
        if k.0 > now {
            return None;
        }
        q.remove(&k)
    }

    /// Process everything due, seal batches, advance settlement.
    pub fn tick(&mut self) -> Result<(), String> {
        // Every router call is journaled and fsync'd, so call only when there is work:
        // a due intent, a resting quote to expire, or an elapsed batch window.
        let now = now_us().max(self.router.router().map(|r| r.clock_us()).unwrap_or(0));
        let expired: Vec<Key> = self.intents.iter().filter(|(_, r)| r.status == "resting" && r.intent.expires_us <= now).map(|(k, _)| *k).collect();
        let due = |v: &Self| {
            v.pending_cancels.first_key_value().is_some_and(|(k, _)| k.0 <= now) || v.pending_queue.first_key_value().is_some_and(|(k, _)| k.0 <= now)
        };
        if due(self) || !expired.is_empty() {
            loop {
                let expected = if due(self) { self.next_processed(now) } else { None };
                let out = self.router.process_one(now).map_err(|e| format!("process: {e}"))?;
                let Some(out) = out else { break };
                self.apply_outcome(expected, out, now);
                if !due(self) {
                    break;
                }
            }
        }
        for k in expired {
            if let Some(r) = self.intents.get_mut(&k) {
                r.status = "expired".into();
            }
            self.emit(json!({"type": "book"}));
        }
        // A 100 ms window seals once the router clock has passed its end.
        while let Some(end) = self.unsealed.front().map(|&t| (t / 100_000 + 1) * 100_000).filter(|&e| e <= now) {
            if self.router.router().map(|r| r.clock_us()).unwrap_or(0) < end {
                // Advance the router clock once (journaled) so the window can seal.
                if let Some(out) = self.router.process_one(now).map_err(|e| format!("process: {e}"))? {
                    self.apply_outcome(None, out, now);
                }
            }
            match self.router.seal_batch().map_err(|e| format!("seal: {e}"))? {
                Some(b) => {
                    let end = b.window().1;
                    while self.unsealed.front().is_some_and(|&t| t < end) {
                        self.unsealed.pop_front();
                    }
                    self.on_batch(b);
                }
                None => break,
            }
        }
        self.advance_settlement(now)?;
        self.options_advance(now)?;
        Ok(())
    }

    fn apply_outcome(&mut self, expected: Option<Key>, out: TierOutcome, now: u64) {
        match out {
            TierOutcome::Posted(id) => {
                if let Some(r) = self.intents.get_mut(&id) {
                    r.status = "resting".into();
                    r.remaining = r.intent.quantity;
                }
                self.emit(json!({"type": "book"}));
            }
            TierOutcome::Cancelled(target) => {
                if let Some(r) = self.intents.get_mut(&target) {
                    r.status = "cancelled".into();
                    r.remaining = 0;
                }
                if let Some(c) = expected.and_then(|e| self.intents.get_mut(&e)) {
                    c.status = "done".into();
                }
                self.emit(json!({"type": "book"}));
            }
            TierOutcome::Filled(tf) => {
                let f = &tf.fill;
                let qty = f.spec.usd_notional;
                if let Some(m) = self.intents.get_mut(&f.maker_id) {
                    m.remaining = m.remaining.saturating_sub(qty);
                    if m.remaining == 0 {
                        m.status = "filled".into();
                    }
                }
                if let Some(t) = self.intents.get_mut(&f.taker_id) {
                    t.status = "filled".into();
                }
                let taker_side = if f.maker_side == OrderSide::Long { OrderSide::Short } else { OrderSide::Long };
                let packet = self.packets.iter().rev().find(|p| p.digest == tf.packet_digest).cloned();
                let tr = TradeRec {
                    id: f.taker_id,
                    maker_id: f.maker_id,
                    ts_us: f.execution_us,
                    price_usd: f.spec.entry_price_usd,
                    qty_usd: qty,
                    taker_side,
                    maker_tier: tf.maker_tier,
                    taker_tier: tf.taker_tier,
                    maker_owner: f.maker_owner,
                    taker_owner: f.taker_owner,
                    packet,
                    binding: f.mark_id,
                    maker_entitlement: tf.maker_entitlement,
                    taker_entitlement: tf.taker_entitlement,
                    maker_fee_sats: f.maker_fee_sats,
                    taker_fee_sats: f.taker_fee_sats,
                    oracle_due_sats: f.oracle_due_sats,
                    router_due_sats: f.router_due_sats,
                    long_margin_sats: f.spec.long_margin_sats,
                    short_margin_sats: f.spec.short_margin_sats,
                    early_window: tf.early_window,
                    batch_seq: None,
                };
                self.unsealed.push_back(f.execution_us);
                let minute = f.execution_us / 60_000_000 * 60_000;
                let px = f.spec.entry_price_usd as f64;
                let vol = qty as f64 / px;
                let c = self.candles.entry(minute).or_insert([px, px, px, px, 0.0]);
                if c[4] == 0.0 {
                    *c = [px, px, px, px, 0.0];
                }
                c[1] = c[1].max(px);
                c[2] = c[2].min(px);
                c[3] = px;
                c[4] += vol;
                self.emit(json!({"type": "trade", "trade": trade_json(&tr)}));
                self.emit(json!({"type": "book"}));
                self.trades.push_front(tr);
                while self.trades.len() > MAX_TRADES {
                    self.trades.pop_back();
                }
            }
            TierOutcome::Rejected(r) => {
                if let Some(rec) = expected.and_then(|e| self.intents.get_mut(&e)) {
                    rec.status = "rejected".into();
                    rec.reason = Some(format!("{r:?}"));
                }
            }
        }
        let _ = now;
        self.emit(json!({"type": "account"}));
    }

    // ------------------------------------------------------- settlement ----
    fn on_batch(&mut self, b: Batch) {
        let seq = b.sequence();
        let legs: Vec<Key> = b.legs().iter().map(|f| f.taker_id).collect();
        for t in self.trades.iter_mut().filter(|t| legs.contains(&t.id)) {
            t.batch_seq = Some(seq);
        }
        let accounts: Vec<_> = b.accounts().iter().map(|a| (a.channel.clone(), a.owner, a.margin_sats, a.fee_sats)).collect();
        for (c, owner, _, _) in &accounts {
            let msg = b.approval_message(c).expect("account in batch");
            let id = format!("{seq}:approval:{}:{}", h(&c.txid), c.vout);
            self.pending.insert(id.clone(), PendingSig { id, owner: *owner, kind: "batch_approval".into(), message: msg,
                context: json!({"batch_seq": seq, "batch_digest": h(&b.digest()), "channel": outpoint_json(c)}) });
        }
        let _ = self.ledger.observe_batch(&b);
        self.batches.insert(seq, BatchRec {
            seq,
            digest: b.digest(),
            phase: "sealed".into(),
            legs,
            accounts,
            oracle_due: b.oracle_due_sats(),
            router_due: b.router_due_sats(),
            window: b.window(),
            approvals: BTreeMap::new(),
            acks: vec![],
            created_us: now_us(),
            prepared_us: None,
            committed_us: None,
            delegated: BTreeMap::new(),
            ack_delegated: BTreeMap::new(),
        });
        self.emit(json!({"type": "batch", "seq": seq, "phase": "sealed"}));
        self.emit(json!({"type": "account"})); // approvals are now pending
    }

    pub fn add_signatures(&mut self, owner: Key, items: &[(String, Bip340Signature)]) -> Result<usize, String> {
        self.wallet_check(&owner)?;
        let mut n = 0;
        for (id, sig) in items {
            let Some(p) = self.pending.get(id).cloned() else { continue };
            if p.owner != owner {
                return Err(format!("{id} belongs to another owner"));
            }
            bip340_verify(&owner, &p.message, sig).map_err(|_| format!("{id}: signature does not verify"))?;
            if p.kind == "option_ack" {
                self.option_ack_signed(&p, *sig)?;
                self.pending.remove(id);
                n += 1;
                continue;
            }
            let seq = p.context["batch_seq"].as_u64().unwrap_or(0);
            let Some(b) = self.batches.get_mut(&seq) else { continue };
            let c = &p.context["channel"];
            let key = (parse_key(c["txid"].as_str().unwrap_or(""))?, c["vout"].as_u64().unwrap_or(0) as u32);
            match p.kind.as_str() {
                "batch_approval" => {
                    b.approvals.insert(key, *sig);
                }
                "channel_ack" => {
                    if let Some(a) = b.acks.iter_mut().find(|a| (a.channel.txid, a.channel.vout) == key) {
                        a.signatures[0] = *sig;
                    }
                }
                _ => {}
            }
            self.pending.remove(id);
            n += 1;
        }
        let now = now_us();
        self.advance_settlement(now)?;
        self.options_advance(now)?;
        Ok(n)
    }

    /// Batches resolve strictly in order: approvals -> prepare -> simulated
    /// channel acks (peer + monitor signed by the venue adapter, owner by the
    /// client) -> resolve(Commit) -> fee ledger.
    fn advance_settlement(&mut self, now: u64) -> Result<(), String> {
        loop {
            let next = self.router.next_resolution().map_err(|e| e.to_string())?;
            let Some(b) = self.batches.get(&next) else { return Ok(()) };
            match b.phase.as_str() {
                "sealed" | "restored-prepared" if b.approvals.len() == b.accounts.len() => {
                    if b.phase == "sealed" {
                        let approvals: Vec<BatchApproval> = b.accounts.iter().map(|(c, _, _, _)| BatchApproval {
                            channel: c.clone(),
                            signature: b.approvals[&(c.txid, c.vout)],
                        }).collect();
                        let delegated: Vec<(BtcOutPoint, Key)> = b.delegated.iter().map(|(k, g)| (BtcOutPoint { txid: k.0, vout: k.1 }, *g)).collect();
                        if delegated.is_empty() {
                            self.router.prepare(next, approvals).map_err(|e| format!("prepare: {e}"))?;
                        } else if let Err(e) = self.router.prepare_delegated(next, approvals, delegated) {
                            // The grant lapsed or was revoked after the agent signed: its
                            // approvals go back to the owner (or the deadline abort).
                            self.undelegate(next, false, &e.to_string());
                            continue;
                        }
                    }
                    let accounts = b.accounts.clone();
                    let digest = b.digest;
                    let mut acks = vec![];
                    for (c, owner, _, fee) in &accounts {
                        let head = self.router.head(c).map_err(|e| e.to_string())?.ok_or("lane missing")?;
                        let tag = |t: &[u8]| tagged_hash(t, &[digest.as_slice(), &c.txid, &c.vout.to_le_bytes()].concat());
                        let mut ack = ChannelAck {
                            channel: c.clone(),
                            previous: head,
                            next: Head { revision: head.revision + 1, commitment: head.commitment + 1, state: tag(b"SHZ/VENUE/SIMULATED-STATE/V1") },
                            evidence: tag(b"SHZ/VENUE/SIMULATED-MONITOR/V1"),
                            fee_evidence: if *fee > 0 { tag(b"SHZ/VENUE/SIMULATED-FEE-RECEIPT/V1") } else { [0; 32] },
                            signatures: [ZERO_SIG; 3],
                        };
                        let msg = self.router.ack_message(next, Disposition::Commit, &ack).map_err(|e| e.to_string())?;
                        ack.signatures[1] = bip340_sign(&self.keys.lane_sk("peer", c), &msg).map_err(|e| e.to_string())?;
                        ack.signatures[2] = bip340_sign(&self.keys.lane_sk("monitor", c), &msg).map_err(|e| e.to_string())?;
                        let id = format!("{next}:ack:{}:{}", h(&c.txid), c.vout);
                        self.pending.insert(id.clone(), PendingSig { id, owner: *owner, kind: "channel_ack".into(), message: msg,
                            context: json!({"batch_seq": next, "batch_digest": h(&digest), "channel": outpoint_json(c),
                                            "next_commitment": head.commitment + 1, "adapter": "simulated (venue-held peer and monitor keys)"}) });
                        acks.push(ack);
                    }
                    let b = self.batches.get_mut(&next).unwrap();
                    b.acks = acks;
                    b.phase = "prepared".into();
                    b.prepared_us = Some(now_us());
                    self.emit(json!({"type": "batch", "seq": next, "phase": "prepared"}));
                    self.emit(json!({"type": "account"})); // channel acks are now pending
                }
                "prepared" if !b.acks.is_empty() && b.acks.iter().all(|a| a.signatures[0] != ZERO_SIG) => {
                    let bundle = AckBundle { sequence: next, batch: b.digest, disposition: Disposition::Commit, channels: b.acks.clone() };
                    let (phase, end) = (b.phase.clone(), b.window.1);
                    let delegated: Vec<(BtcOutPoint, Key)> = b.ack_delegated.iter().map(|(k, g)| (BtcOutPoint { txid: k.0, vout: k.1 }, *g)).collect();
                    let res = if delegated.is_empty() { self.router.resolve(bundle.clone()) } else { self.router.resolve_delegated(bundle.clone(), delegated) };
                    if let (Err(e), false) = (&res, b.ack_delegated.is_empty()) {
                        let e = e.to_string();
                        self.undelegate(next, true, &e);
                        continue;
                    }
                    if let Err(e) = res {
                        // A fully signed head batch whose resolve errors must not hold the
                        // venue for ever: past the abort deadline it is aborted like any other.
                        if self.deadline_abort(next, &phase, end, now)? {
                            continue;
                        }
                        return Err(format!("resolve: {e}"));
                    }
                    let _ = self.ledger.observe_resolution(&self.router, &bundle, now);
                    let b = self.batches.get_mut(&next).unwrap();
                    b.phase = "committed".into();
                    b.committed_us = Some(now_us());
                    self.emit(json!({"type": "batch", "seq": next, "phase": "committed"}));
                }
                _ => {
                    let (phase, end) = (b.phase.clone(), b.window.1);
                    if !self.deadline_abort(next, &phase, end, now)? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Delegated signatures of batch `seq` the router refused (grant revoked or expired since):
    /// clear them and post the owner's pending signatures again.
    fn undelegate(&mut self, seq: u64, acks: bool, why: &str) {
        let Some(b) = self.batches.get_mut(&seq) else { return };
        let keys: Vec<(Key, u32)> = if acks { std::mem::take(&mut b.ack_delegated).into_keys().collect() } else { std::mem::take(&mut b.delegated).into_keys().collect() };
        let digest = b.digest;
        let mut repost = vec![];
        for k in &keys {
            let c = BtcOutPoint { txid: k.0, vout: k.1 };
            if acks {
                if let Some(a) = b.acks.iter_mut().find(|a| (a.channel.txid, a.channel.vout) == *k) {
                    a.signatures[0] = ZERO_SIG;
                }
            } else {
                b.approvals.remove(k);
            }
            let owner = b.accounts.iter().find(|(ch, _, _, _)| (ch.txid, ch.vout) == *k).map(|x| x.1);
            if let Some(owner) = owner {
                repost.push((c, owner));
            }
        }
        for (c, owner) in repost {
            let (id, kind, msg) = if acks {
                let Some(a) = self.batches[&seq].acks.iter().find(|a| a.channel == c).cloned() else { continue };
                let Ok(m) = self.router.ack_message(seq, Disposition::Commit, &a) else { continue };
                (format!("{seq}:ack:{}:{}", h(&c.txid), c.vout), "channel_ack", m)
            } else {
                let Ok(Some((batch, _))) = self.router.batch(seq) else { continue };
                let Some(m) = batch.approval_message(&c) else { continue };
                (format!("{seq}:approval:{}:{}", h(&c.txid), c.vout), "batch_approval", m)
            };
            self.pending.insert(id.clone(), PendingSig { id, owner, kind: kind.into(), message: msg,
                context: json!({"batch_seq": seq, "batch_digest": h(&digest), "channel": outpoint_json(&c), "agent_refused": why}) });
        }
        self.emit(json!({"type": "account"}));
    }

    /// The head batch has waited `ABORT_AFTER_US` past its window for approvals or acks:
    /// fence and abort it with the adapter's peer and monitor signatures so later batches
    /// can resolve. Nothing moves on any channel; every debit returns to free, and the
    /// maker quotes behind its fills are cancelled by the router.
    fn deadline_abort(&mut self, next: u64, phase: &str, window_end: u64, now: u64) -> Result<bool, String> {
        let deadline = window_end.saturating_add(ABORT_AFTER_US);
        if !matches!(phase, "sealed" | "prepared" | "restored-prepared") || now < deadline {
            return Ok(false);
        }
        if self.router.router().map(|r| r.clock_us()).unwrap_or(0) < deadline {
            // Advance the router clock (journaled) to the deadline the router checks.
            if let Some(out) = self.router.process_one(now).map_err(|e| format!("process: {e}"))? {
                self.apply_outcome(None, out, now);
            }
        }
        let rec = &self.batches[&next];
        let (accounts, digest) = (rec.accounts.clone(), rec.digest);
        let mut channels = vec![];
        for (c, _, _, _) in &accounts {
            let head = self.router.head(c).map_err(|e| e.to_string())?.ok_or("lane missing")?;
            let mut ack = ChannelAck {
                channel: c.clone(),
                previous: head,
                next: Head { revision: head.revision + 1, commitment: head.commitment, state: head.state },
                evidence: tagged_hash(b"SHZ/VENUE/SIMULATED-CANCEL/V1", &[digest.as_slice(), &c.txid, &c.vout.to_le_bytes()].concat()),
                fee_evidence: [0; 32],
                signatures: [ZERO_SIG; 3],
            };
            let msg = self.router.ack_message(next, Disposition::FencedAbort, &ack).map_err(|e| e.to_string())?;
            ack.signatures[1] = bip340_sign(&self.keys.lane_sk("peer", c), &msg).map_err(|e| e.to_string())?;
            ack.signatures[2] = bip340_sign(&self.keys.lane_sk("monitor", c), &msg).map_err(|e| e.to_string())?;
            channels.push(ack);
        }
        let bundle = AckBundle { sequence: next, batch: digest, disposition: Disposition::FencedAbort, channels };
        self.router.expire(bundle.clone()).map_err(|e| format!("deadline abort: {e}"))?;
        let _ = self.ledger.observe_resolution(&self.router, &bundle, now);
        self.pending.retain(|_, p| p.context["batch_seq"].as_u64() != Some(next));
        let makers: Vec<Key> = self.trades.iter().filter(|t| t.batch_seq == Some(next)).map(|t| t.maker_id).collect();
        for m in makers {
            if let Some(r) = self.intents.get_mut(&m).filter(|r| r.status == "resting") {
                r.status = "cancelled".into();
                r.remaining = 0;
            }
        }
        let b = self.batches.get_mut(&next).unwrap();
        b.phase = "aborted".into();
        b.committed_us = Some(now_us());
        self.emit(json!({"type": "batch", "seq": next, "phase": "aborted"}));
        self.emit(json!({"type": "account"}));
        self.emit(json!({"type": "book"}));
        Ok(true)
    }

    // ------------------------------------------------------------ views ----
    pub fn balance(&self, owner: &Key) -> Option<Balance> {
        let a = self.accounts.get(owner)?;
        self.router.balance(&a.outpoint).ok().flatten()
    }

    pub fn book(&self, depth: usize) -> Value {
        let now = now_us();
        let mut bids: BTreeMap<u64, (u64, u32)> = BTreeMap::new();
        let mut asks: BTreeMap<u64, (u64, u32)> = BTreeMap::new();
        for r in self.intents.values().filter(|r| r.status == "resting" && r.remaining > 0 && r.intent.expires_us > now) {
            let m = if r.intent.side == OrderSide::Long { &mut bids } else { &mut asks };
            let e = m.entry(r.intent.limit_usd).or_default();
            e.0 += r.remaining;
            e.1 += 1;
        }
        json!({
            "bids": bids.iter().rev().take(depth).map(|(p, (q, n))| json!([p, q, n])).collect::<Vec<_>>(),
            "asks": asks.iter().take(depth).map(|(p, (q, n))| json!([p, q, n])).collect::<Vec<_>>(),
            "mark": self.mark.as_ref().map(packet_json),
        })
    }

    /// Position from the router's committed lots (margin release), plus fills whose batch
    /// has not committed yet. Unrealized PnL is the exact DLC payout of the open lots at
    /// the mark minus their margin.
    pub fn position(&self, owner: &Key) -> Value {
        let Some(a) = self.accounts.get(owner) else { return json!(null) };
        let pos = self.router.position(&a.outpoint).ok().flatten().unwrap_or_default();
        let (mut unsettled, mut gross) = (0i64, 0u64);
        for t in &self.trades {
            if t.batch_seq.and_then(|s| self.batches.get(&s)).is_some_and(|b| b.phase == "aborted") {
                continue; // fenced and aborted: the fill never settled
            }
            let sign = if t.taker_owner == *owner {
                if t.taker_side == OrderSide::Long { 1 } else { -1 }
            } else if t.maker_owner == *owner {
                if t.taker_side == OrderSide::Long { -1 } else { 1 }
            } else {
                continue;
            };
            gross += t.qty_usd;
            let phase = t.batch_seq.and_then(|s| self.batches.get(&s)).map(|b| b.phase.as_str());
            if phase != Some("committed") {
                unsettled += sign * t.qty_usd as i64;
            }
        }
        let mark_usd = self.mark_usd();
        let margin = pos.margin();
        let unreal = mark_usd.filter(|_| margin > 0 || pos.net_usd() != 0).map(|m| pos.value_at(m) as i64 - margin as i64);
        let lots: Vec<Value> = pos.lots().map(|l| json!({"side": side_name(l.side), "qty_usd": l.qty, "entry_usd": l.price, "margin_sats": l.margin, "counterparty_margin_sats": l.opp_margin})).collect();
        let realized = self.balance(owner).map(|b| b.realized_pnl).unwrap_or(0);
        json!({"net_usd": pos.net_usd() + unsettled, "committed_net_usd": pos.net_usd(), "unsettled_usd": unsettled,
               "avg_entry_usd": pos.avg_entry_usd(), "unrealized_sats": unreal, "margin_sats": margin, "lots": lots,
               "realized_pnl_sats": realized, "gross_traded_usd": gross, "risk": self.risk_view(owner),
               "deferred_claim_sats": self.router.clearing_state().ok().flatten().map(|c| c.claim(&a.outpoint))})
    }

    /// Highest admitted intent sequence of the account per book: the perpetual router and the
    /// options desk (options and spot share one counter). A client's next intent on that book
    /// must carry a greater sequence; every client uses the microsecond clock (docs/SHZ_AGENT_API.md).
    pub fn sequences(&self, owner: &Key) -> Value {
        let Some(a) = self.accounts.get(owner) else { return Value::Null };
        let perp = self.router.router().ok().and_then(|r| r.account_sequence(&a.outpoint)).unwrap_or(0);
        let desk = self.router.options().ok().flatten().and_then(|d| d.account(&(a.outpoint.txid, a.outpoint.vout)).map(|x| x.last_sequence)).unwrap_or(0);
        json!({"perp": perp, "option": desk, "spot": desk, "unit": "microseconds since the Unix epoch"})
    }

    pub fn account_view(&self, owner: &Key) -> Value {
        let Some(a) = self.accounts.get(owner) else { return json!(null) };
        let b = self.balance(owner);
        let open: Vec<Value> = self.intents.iter().filter(|(_, r)| r.intent.owner == *owner && (r.status == "resting" || r.status == "queued"))
            .map(|(id, r)| intent_json(id, r)).collect();
        let fills: Vec<Value> = self.trades.iter().filter(|t| t.maker_owner == *owner || t.taker_owner == *owner).take(200).map(trade_json).collect();
        let pending: Vec<Value> = self.pending.values().filter(|p| p.owner == *owner)
            .map(|p| json!({"id": p.id, "kind": p.kind, "message": h(&p.message), "context": p.context})).collect();
        let recent: Vec<Value> = self.intents.iter().filter(|(_, r)| r.intent.owner == *owner && r.status == "rejected").rev().take(20)
            .map(|(id, r)| intent_json(id, r)).collect();
        json!({
            "owner": h(owner), "label": a.label, "kind": a.kind, "outpoint": outpoint_json(&a.outpoint), "cap_sats": a.cap_sats,
            "balance": b.map(|b| balance_json(&b)),
            "position": self.position(owner), "open_orders": open, "fills": fills, "rejected": recent, "pending_signatures": pending,
            "wallet_link": self.wallet_link_view(owner),
            "sequences": self.sequences(owner),
            "options": self.opts.as_ref().map(|_| self.options_account(owner)),
            "spot": self.spot.as_ref().map(|_| self.spot_account(owner)),
            "collateral": self.coll.as_ref().and_then(|_| self.collateral_view(owner).ok()),
        })
    }

    pub fn status(&self) -> Value {
        let r = self.router.router().ok();
        let tip = self.router.tip().ok();
        json!({
            "market": MARKET,
            "mark": self.mark.as_ref().map(packet_json),
            "group_key": h(&self.group_key),
            "relay": self.relay_url,
            "router": r.map(|r| json!({"clock_us": r.clock_us(), "resting": r.resting(), "batch_sequence": r.batch_sequence(), "fills": r.fill_count()})),
            "accounts": self.accounts.len(),
            "journal": tip.map(|t| json!({"records": t.records, "digest": h(&t.digest)})),
            "margin_release": self.router.margin_release_active().unwrap_or(false),
            "clearing": self.router.clearing_summary().ok().flatten(),
            "closing_loans": self.router.closing_loans_active().unwrap_or(false),
            "options": self.options_summary(),
            "spot": self.spot_summary(),
            "agents": self.agents_summary(),
            "collateral": self.collateral_summary(),
            "production_ready": false,
            "network": self.coll.as_ref().map(|c| c.cfg.net.name()).unwrap_or("testnet4"),
        })
    }

    pub fn ledger_totals(&self) -> Value {
        let mut out = vec![];
        for (k, t) in self.ledger.all_totals() {
            out.push(json!({"recipient": h(&k), "accrued": t.accrued, "committed": t.committed, "collected": t.collected, "outstanding": t.outstanding, "reversed": t.reversed}));
        }
        json!(out)
    }
    pub fn ledger_batch_state(&self, seq: u64) -> Option<String> {
        self.ledger.batch_state(seq).map(|s| format!("{s:?}"))
    }
    pub fn journal(&self) -> Value {
        let tip = self.router.tip().ok();
        json!({"tip": tip.map(|t| json!({"records": t.records, "digest": h(&t.digest)})), "config_hash": h(&self.router.config_hash()),
               "next_resolution": self.router.next_resolution().ok()})
    }

    pub fn fill_explorer(&self, id: &Key) -> Value {
        let Some(t) = self.trades.iter().find(|t| t.id == *id) else { return json!(null) };
        let policy = self.router_policy_id();
        let mut pre = t.packet.as_ref().map(|p| p.digest).unwrap_or([0; 32]).to_vec();
        pre.extend(self.cfg.tariff.version.to_le_bytes());
        pre.extend(policy);
        pre.extend(t.maker_entitlement);
        pre.extend(t.taker_entitlement);
        let recomputed = tagged_hash(b"SHZ/HFT06/FILL-BINDING/V1", &pre);
        let batch = t.batch_seq.and_then(|s| self.batches.get(&s));
        json!({
            "trade": trade_json(t),
            "taker_intent": self.intents.get(&t.id).map(|r| intent_json(&t.id, r)),
            "maker_intent": self.intents.get(&t.maker_id).map(|r| intent_json(&t.maker_id, r)),
            "packet": t.packet.as_ref().map(packet_json),
            "binding": {"mark_id": h(&t.binding), "recomputed": h(&recomputed), "matches": recomputed == t.binding,
                        "preimage": {"packet_digest": t.packet.as_ref().map(|p| h(&p.digest)), "tariff_version": self.cfg.tariff.version,
                                     "execution_policy": h(&policy), "maker_entitlement": h(&t.maker_entitlement), "taker_entitlement": h(&t.taker_entitlement)}},
            "fees": {"maker_fee_sats": t.maker_fee_sats, "taker_fee_sats": t.taker_fee_sats, "oracle_due_sats": t.oracle_due_sats, "router_due_sats": t.router_due_sats},
            "margins": {"long_margin_sats": t.long_margin_sats, "short_margin_sats": t.short_margin_sats},
            "batch": batch.map(|b| self.batch_json(b)),
            "ledger_state": t.batch_seq.and_then(|s| self.ledger_batch_state(s)),
            "settlement_note": "Batches are acknowledged by a simulated channel adapter (venue-held peer and monitor keys); no Lightning channel exists yet.",
        })
    }

    pub fn batch_json(&self, b: &BatchRec) -> Value {
        json!({
            "seq": b.seq, "digest": h(&b.digest), "phase": b.phase, "window_us": [b.window.0, b.window.1],
            "legs": b.legs.iter().map(|k| h(k)).collect::<Vec<_>>(),
            "accounts": b.accounts.iter().map(|(c, o, m, f)| json!({"channel": outpoint_json(c), "owner": h(o), "margin_sats": m, "fee_sats": f,
                "approved": b.approvals.contains_key(&(c.txid, c.vout))})).collect::<Vec<_>>(),
            "acks": b.acks.iter().map(|a| json!({"channel": outpoint_json(&a.channel), "previous_commitment": a.previous.commitment,
                "next_commitment": a.next.commitment, "evidence": h(&a.evidence), "fee_evidence": h(&a.fee_evidence),
                "owner_signed": a.signatures[0] != ZERO_SIG, "peer_signature": sig_hex(&a.signatures[1]), "monitor_signature": sig_hex(&a.signatures[2])})).collect::<Vec<_>>(),
            "oracle_due_sats": b.oracle_due as u64, "router_due_sats": b.router_due as u64,
            "ledger_state": self.ledger_batch_state(b.seq),
            "created_us": b.created_us,
            "prepared_us": b.prepared_us,
            "committed_us": b.committed_us,
            "settlements": self.router.settlements(b.seq).map(|rows| rows.iter().map(|(c, s)| json!({
                "channel": outpoint_json(c),
                "owner": b.accounts.iter().find(|(x, _, _, _)| x == c).map(|(_, o, _, _)| h(o)),
                "opened_margin_sats": s.opened_margin, "closed_leg_margin_sats": s.closed_leg_margin,
                "released_margin_sats": s.released_margin, "payout_sats": s.payout, "realized_pnl_sats": s.realized_pnl(),
                "closed_usd": s.closed_usd, "net_before_usd": s.net_before, "net_after_usd": s.net_after, "margin_after_sats": s.margin_after,
            })).collect::<Vec<_>>()).unwrap_or_default(),
            "clearing": self.router.clearing(b.seq).ok().flatten(),
        })
    }
}

pub fn balance_json(b: &Balance) -> Value {
    json!({"cap": b.cap, "free": b.free, "resting": b.resting, "pending": b.pending, "committed": b.committed,
           "paid_fees": b.paid_fees, "realized_pnl": b.realized_pnl, "equity": b.equity() as i64})
}

pub fn parse_tier(s: &str) -> Result<FeedTier, String> {
    Ok(match s {
        "standard" => FeedTier::Standard,
        "intermediate" => FeedTier::Intermediate,
        "premium" => FeedTier::Premium,
        _ => return Err("bad tier".into()),
    })
}
pub fn tier_name(t: FeedTier) -> &'static str {
    match t {
        FeedTier::Standard => "standard",
        FeedTier::Intermediate => "intermediate",
        FeedTier::Premium => "premium",
    }
}
fn side_name(s: OrderSide) -> &'static str {
    if s == OrderSide::Long { "long" } else { "short" }
}
pub fn packet_json(p: &PacketRec) -> Value {
    json!({"seq": p.seq, "slot_us": p.slot_us, "status": p.status, "median_e8": p.median_e8,
           "price_usd": p.median_e8.map(|m| m as f64 / 1e8), "digest": h(&p.digest), "signers": p.signers,
           "verified": p.verified, "age_s": (now_us().saturating_sub(p.slot_us)) as f64 / 1e6, "received_us": p.received_us})
}
pub fn trade_json(t: &TradeRec) -> Value {
    json!({"id": h(&t.id), "maker_id": h(&t.maker_id), "ts_us": t.ts_us, "price_usd": t.price_usd, "qty_usd": t.qty_usd,
           "taker_side": side_name(t.taker_side), "maker_tier": tier_name(t.maker_tier), "taker_tier": tier_name(t.taker_tier),
           "maker_owner": h(&t.maker_owner), "taker_owner": h(&t.taker_owner),
           "packet_seq": t.packet.as_ref().map(|p| p.seq), "packet_digest": t.packet.as_ref().map(|p| h(&p.digest)),
           "batch_seq": t.batch_seq, "early_window": t.early_window,
           "maker_fee_sats": t.maker_fee_sats, "taker_fee_sats": t.taker_fee_sats})
}
pub fn intent_json(id: &Key, r: &IntentRec) -> Value {
    let i = &r.intent;
    json!({"id": h(id), "status": r.status, "reason": r.reason, "action": match i.action { Action::Post => "post", Action::Take => "take", Action::Cancel => "cancel" },
           "side": side_name(i.side), "tier": tier_name(i.tier), "quantity": i.quantity, "remaining": r.remaining, "limit_usd": i.limit_usd,
           "leverage_bps": i.leverage_bps, "sequence": i.sequence, "expires_us": i.expires_us, "owner": h(&i.owner),
           "accepted_us": r.accepted_us, "early_window_opt_in": i.early_window_opt_in, "signature": sig_hex(&i.signature)})
}

pub(crate) fn getrandom(buf: &mut [u8]) -> Result<(), String> {
    // k256's OS RNG (rand_core getrandom feature via the workspace) is not a direct dep here;
    // read the OS RNG through a fresh SigningKey's entropy path.
    use k256::elliptic_curve::rand_core::{OsRng, RngCore};
    OsRng.try_fill_bytes(buf).map_err(|e| e.to_string())
}
