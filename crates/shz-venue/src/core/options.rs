//! Options on the venue (docs/SHZ_OPTIONS_COMBOS.md, docs/SHZ_VENUE_OPTIONS.md). Off unless
//! the venue starts with `--options`.
//!
//! * Series are listed from the FROST relay's announced DLC events: a strike grid around the
//!   oracle mark, BTC calls, BTC puts and (with `--stable-usdt`) cash-secured USDT puts. The
//!   announcement's threshold signature is checked before anything is journaled.
//! * Orders are signed `IntentV7` (single legs and all-or-none combos with per-asset limits).
//! * Every option trade or expiry batch is staged by the router and commits only when the
//!   owner, peer and monitor of every lane in it sign that lane's V4 acknowledgement. The
//!   venue adds the peer and monitor signatures from its lane keys (the simulated channel
//!   adapter, as for perpetual acks) and posts one pending owner signature per lane; the
//!   browser signs those like perpetual acks. A batch left unsigned `ABORT_AFTER_US` is
//!   fence-aborted with peer and monitor signatures.
//! * A listed event whose oracle attestation appears on the relay expires automatically.
//! * Stablecoin deposits and withdrawals are the simulated TAP/RGB adapter: nothing moves
//!   on chain.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use shz_dex::routing::{
    Action, Scope,
    durable::Disposition,
    options::{
        AssetLimit, IntentV7, LegOrder, MAX_LEGS, OPTION_INTENT_VERSION, OptionAck, OptionAckBundle, OptionBatch, OptionBatchKind,
        OptionOutcome, Series, SettleAsset, StableProtocol,
    },
    tiered::ZERO_SIG,
    tiered_durable::ABORT_AFTER_US,
};
use shz_dlc::{BtcOutPoint, OracleAnnouncement, OracleAttestation, bip340_sign, bip340_verify, tagged_hash};
use shz_margin::payoff::{self, Leg, OptionKind, PriceDomain};

use super::{Key, PendingSig, ROUTER_ID, Venue, h, now_us, outpoint_json, parse_key, parse_sig, sig_hex};

/// Digits of the relay's DLC events (`dlc_oracle.NUM_BITS`): outcome domain [1, 2^20 - 1] USD.
pub const NUM_BITS: u8 = 20;
/// An event is listed only while its maturity is at least this far ahead.
pub const LIST_LEAD_US: u64 = 60_000_000;
/// Most unexpired events listed at once (the relay keeps four ahead).
pub const MAX_EVENTS: usize = 4;
/// Strikes on each side of the at-the-money strike.
pub const STRIKES_EACH_SIDE: i64 = 2;
/// Contract size the views quote in: BTC series 100 USD notional, stable series 0.01 BTC.
pub const BTC_CONTRACT: u64 = 100;
pub const STABLE_CONTRACT: u64 = 1_000_000;
/// After an expiry batch is fence-aborted (a holder did not sign), wait this long to retry.
pub const EXPIRY_RETRY_US: u64 = 30_000_000;
const ANN_TAG: &[u8] = b"SHZ/DLC/ANNOUNCEMENT/V1";
/// Owner authorization of a collateral move (fund, defund, deposit, withdraw).
pub const TRANSFER_TAG: &[u8] = b"SHZ/VENUE/OPTIONS-TRANSFER/V1";
const MAX_TRANSFER_AHEAD_US: u64 = 600_000_000;

pub struct EventRec {
    pub maturity_unix: u64,
    pub status: String,
    pub price_usd: Option<u64>,
    pub retry_after_us: u64,
}

pub struct OptBatchRec {
    /// Venue-local batch number (an aborted batch's router sequence is reused by the next one).
    pub n: u64,
    pub batch: OptionBatch,
    pub phase: String,
    pub staged_us: u64,
    pub resolved_us: Option<u64>,
    pub acks: Vec<OptionAck>,
}

pub struct OptIntentRec {
    pub intent: IntentV7,
    pub status: String,
    pub accepted_us: u64,
    pub reason: Option<String>,
    pub batch: Option<u64>,
}

#[derive(Default)]
pub struct OptState {
    pub usdt: Option<SettleAsset>,
    pub events: BTreeMap<String, EventRec>,
    pub intents: BTreeMap<Key, OptIntentRec>,
    pub batches: Vec<OptBatchRec>,
    staged: Option<usize>,
    nonces: BTreeMap<Key, u64>,
    pub last_premium: BTreeMap<Key, u64>,
}
impl OptState {
    /// Venue number of the batch (option or spot) staged for acknowledgement.
    pub fn staged_n(&self) -> Option<u64> {
        self.staged.map(|i| self.batches[i].n)
    }
}

// ------------------------------------------------------------- encodings ----

fn put_asset(a: &SettleAsset, b: &mut Vec<u8>) {
    match a {
        SettleAsset::Btc => b.push(1),
        SettleAsset::Stable { protocol, id, decimals } => {
            b.push(2);
            b.push(*protocol as u8);
            b.extend(id);
            b.push(*decimals);
        }
    }
}

/// Message an owner signs to move option collateral: op (1 fund, 2 defund, 3 deposit,
/// 4 withdraw), owner, asset, amount (base units), expiry (also the per-owner nonce).
pub fn transfer_digest(op: u8, owner: &Key, asset: &SettleAsset, amount: u64, expires_us: u64) -> Key {
    let mut b = vec![op];
    b.extend(owner);
    put_asset(asset, &mut b);
    b.extend(amount.to_le_bytes());
    b.extend(expires_us.to_le_bytes());
    tagged_hash(TRANSFER_TAG, &b)
}

pub fn transfer_op(name: &str) -> Option<u8> {
    Some(match name {
        "fund" => 1,
        "defund" => 2,
        "deposit" => 3,
        "withdraw" => 4,
        _ => return None,
    })
}

pub fn asset_from_json(v: &Value) -> Result<SettleAsset, String> {
    match v["kind"].as_str() {
        Some("btc") => Ok(SettleAsset::Btc),
        Some("stable") => {
            let protocol = match v["protocol"].as_str() {
                Some("rgb") => StableProtocol::Rgb,
                Some("tap") => StableProtocol::Tap,
                _ => return Err("asset.protocol must be rgb or tap".into()),
            };
            let id = parse_key(v["id"].as_str().ok_or("asset.id required")?)?;
            let decimals = v["decimals"].as_u64().filter(|d| *d <= 18).ok_or("asset.decimals required")? as u8;
            Ok(SettleAsset::Stable { protocol, id, decimals })
        }
        _ => Err("asset.kind must be btc or stable".into()),
    }
}

fn kind_name(k: OptionKind) -> &'static str {
    match k {
        OptionKind::Call => "call",
        OptionKind::Put => "put",
    }
}

fn contract_qty(a: &SettleAsset) -> u64 {
    if *a == SettleAsset::Btc { BTC_CONTRACT } else { STABLE_CONTRACT }
}

fn leg_of(s: &Series, long: bool, qty: u64) -> Leg {
    match s.asset {
        SettleAsset::Btc => Leg::InverseOption { kind: s.kind, long, qty_usd: qty, strike_usd: s.strike_usd, premium_sats: 0 },
        SettleAsset::Stable { .. } => Leg::LinearOption { kind: s.kind, long, qty_btc_e8: qty, strike_usd: s.strike_usd, premium_usd: 0 },
    }
}

/// Worst-case loss of one contract written (sold), premium excluded, in the asset's base units.
pub fn short_worst_case(s: &Series, domain: PriceDomain) -> u128 {
    payoff::max_loss(&[leg_of(s, false, contract_qty(&s.asset))], s.asset.payoff_asset(), domain) * s.asset.scale()
}

/// Largest "nice" step (1, 2 or 5 times a power of ten) not above 1% of the mark.
pub fn strike_step(mark_usd: u64) -> u64 {
    let target = (mark_usd / 100).max(1);
    let mut p = 1u64;
    while p * 10 <= target {
        p *= 10;
    }
    [5 * p, 2 * p, p].into_iter().find(|s| *s <= target).unwrap_or(1)
}

/// Strike grid around the mark: the at-the-money strike and `STRIKES_EACH_SIDE` each side.
pub fn strike_grid(mark_usd: u64, domain: PriceDomain) -> Vec<u64> {
    let step = strike_step(mark_usd);
    let atm = (mark_usd + step / 2) / step * step;
    (-STRIKES_EACH_SIDE..=STRIKES_EACH_SIDE)
        .map(|k| atm as i64 + k * step as i64)
        .filter(|k| *k >= domain.p_min as i64 && *k <= domain.p_max as i64)
        .map(|k| k as u64)
        .collect()
}

/// Check a relay DLC event (dlc_coord.py `/v1/dlc/event/{id}`): the announcement digest is the
/// tagged hash of the canonical core, signed by `oracle` with the core's announcement nonce,
/// and the `shz_dlc` serde form matches the core.
pub fn verify_announcement(ev: &Value, oracle: &Key) -> Result<OracleAnnouncement, String> {
    let core = &ev["core"];
    // serde_json maps are sorted: the same bytes as json.dumps(sort_keys, compact separators).
    let canonical = serde_json::to_string(core).map_err(|e| e.to_string())?;
    let digest = tagged_hash(ANN_TAG, canonical.as_bytes());
    if ev["announcement_digest"].as_str() != Some(h(&digest).as_str()) {
        return Err("announcement digest does not match the core".into());
    }
    let sig = parse_sig(ev["announcement_signature"].as_str().ok_or("announcement_signature missing")?)?;
    if Some(sig.r_x) != core["announcement_nonce_x"].as_str().and_then(|s| parse_key(s).ok()) {
        return Err("announcement signature does not use the announcement nonce".into());
    }
    if core["oracle_pubkey_x"].as_str() != Some(h(oracle).as_str()) {
        return Err("event is not announced by the pinned oracle key".into());
    }
    bip340_verify(oracle, &digest, &sig).map_err(|_| "announcement signature does not verify")?;
    let ann: OracleAnnouncement = serde_json::from_value(ev["shz_dlc_announcement"].clone()).map_err(|e| format!("shz_dlc_announcement: {e}"))?;
    let nonces: Vec<String> = ann.digit_nonces_x.iter().map(|n| h(n)).collect();
    let core_nonces: Vec<String> = core["digit_nonces_x"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    if Some(ann.event_id.as_str()) != core["event_id"].as_str()
        || Some(ann.maturity_unix) != core["maturity_unix"].as_u64()
        || ann.oracle_pubkey_x != *oracle
        || nonces != core_nonces
        || core["num_bits"].as_u64() != Some(NUM_BITS as u64)
        || ann.num_bits() != NUM_BITS
    {
        return Err("shz_dlc_announcement does not match the signed core".into());
    }
    Ok(ann)
}

fn opt_err(e: impl std::fmt::Display) -> String {
    let s = e.to_string();
    if s.ends_with(": Hold") { "an option batch is still settling: retry in a moment".into() } else { s }
}

impl Venue {
    fn opt(&self) -> Result<&OptState, String> {
        self.opts.as_ref().ok_or_else(|| "options are off on this venue".to_string())
    }
    fn opt_mut(&mut self) -> Result<&mut OptState, String> {
        self.opts.as_mut().ok_or_else(|| "options are off on this venue".to_string())
    }
    fn desk_clock(&self) -> u64 {
        self.router.options().ok().flatten().map(|d| d.clock()).unwrap_or(0)
    }
    fn owner_of_channel(&self, c: &BtcOutPoint) -> Option<Key> {
        self.accounts.values().find(|a| a.outpoint == *c).map(|a| a.owner)
    }

    pub fn asset_code(&self, a: &SettleAsset) -> String {
        match a {
            SettleAsset::Btc => "BTC".into(),
            SettleAsset::Stable { protocol, id, .. } => {
                if self.opts.as_ref().and_then(|o| o.usdt.as_ref()) == Some(a) {
                    "USDT".into()
                } else {
                    format!("{}:{}", if *protocol == StableProtocol::Rgb { "rgb" } else { "tap" }, &h(id)[..12])
                }
            }
        }
    }
    pub fn asset_json(&self, a: &SettleAsset) -> Value {
        match a {
            SettleAsset::Btc => json!({"kind": "btc", "code": "BTC", "unit": "sat"}),
            SettleAsset::Stable { protocol, id, decimals } => json!({
                "kind": "stable", "protocol": if *protocol == StableProtocol::Rgb { "rgb" } else { "tap" }, "id": h(id), "decimals": decimals,
                "code": self.asset_code(a), "unit": "base unit", "adapter": "simulated (no on-chain transfer)"}),
        }
    }

    /// Switch options on (journaled once each): desk on the pinned oracle key, combos, the C3
    /// acknowledgement round, and the demo USDT asset. Rebuilds the venue's option views from
    /// the router (committed batches; a staged batch gets its signatures again).
    pub fn options_enable(&mut self, usdt_contract: Option<Key>) -> Result<Value, String> {
        let a = self.router.enable_options(self.group_key, NUM_BITS).map_err(|e| format!("enable options: {e}"))?;
        let desk_oracle = self.router.options().map_err(|e| e.to_string())?.map(|d| d.oracle);
        if desk_oracle != Some(self.group_key) {
            return Err("the journal's options desk is pinned to another oracle key".into());
        }
        let b = self.router.enable_combos().map_err(|e| format!("enable combos: {e}"))?;
        let c = self.router.enable_option_acks().map_err(|e| format!("enable option acks: {e}"))?;
        // Expiry and void batches are a function of the oracle's signature: they commit on the
        // adapter's peer and monitor signatures, so an offline holder cannot hold them.
        let d = self.router.enable_ownerless_expiry().map_err(|e| format!("enable ownerless expiry: {e}"))?;
        let mut st = OptState::default();
        let mut registered = false;
        if let Some(id) = usdt_contract {
            let asset = SettleAsset::Stable { protocol: StableProtocol::Rgb, id, decimals: 6 };
            if !self.router.options().map_err(|e| e.to_string())?.is_some_and(|d| d.registered(&asset)) {
                self.router.register_stable(asset).map_err(|e| format!("register USDT: {e}"))?;
                registered = true;
            }
            st.usdt = Some(asset);
        }
        if a || b || c || d || registered {
            self.persist(json!({"kind": "options_enabled", "oracle": h(&self.group_key), "num_bits": NUM_BITS,
                                "usdt_rgb_contract": usdt_contract.map(|k| h(&k)), "ts_us": now_us()}));
        }
        // Venue log: transfer nonces, option intents (the last record per id wins) and every
        // resolved option batch, committed or aborted, under its venue number.
        let mut recs: BTreeMap<u64, OptBatchRec> = BTreeMap::new();
        // Records of other desks on the options desk (spot) stay for their own enable step.
        let mut rest = vec![];
        for e in std::mem::take(&mut self.opt_log) {
            match e["kind"].as_str() {
                Some("opt_nonce") => {
                    if let (Some(Ok(o)), Some(x)) = (e["owner"].as_str().map(parse_key), e["expires_us"].as_u64()) {
                        let n = st.nonces.entry(o).or_insert(0);
                        *n = (*n).max(x);
                    }
                }
                Some("opt_intent") => {
                    let (Some(Ok(id)), Ok(intent)) = (e["id"].as_str().map(parse_key), serde_json::from_value::<IntentV7>(e["intent"].clone())) else { continue };
                    st.intents.insert(id, OptIntentRec { intent, status: e["status"].as_str().unwrap_or("").into(), accepted_us: e["accepted_us"].as_u64().unwrap_or(0),
                                                         reason: e["reason"].as_str().map(str::to_string), batch: e["batch"].as_u64() });
                }
                Some("opt_batch") => {
                    let (Some(n), Ok(batch)) = (e["n"].as_u64(), serde_json::from_value::<OptionBatch>(e["batch"].clone())) else { continue };
                    let acks = serde_json::from_value(e["acks"].clone()).unwrap_or_default();
                    recs.insert(n, OptBatchRec { n, batch, phase: e["phase"].as_str().unwrap_or("").into(), staged_us: e["staged_us"].as_u64().unwrap_or(0),
                                                 resolved_us: e["resolved_us"].as_u64(), acks });
                }
                _ => rest.push(e.clone()),
            }
        }
        self.opt_log = rest;
        {
            // A batch the router committed without a venue record (a journal from before these
            // records, or a crash between the commit and its record) is appended.
            let desk = self.router.options().map_err(|e| e.to_string())?.ok_or("options desk missing")?;
            for seq in 1..=desk.batch_count() {
                let Some(b) = desk.batch(seq) else { continue };
                let d = b.digest();
                if !recs.values().any(|r| r.phase == "committed" && r.batch.digest() == d) {
                    let n = recs.keys().next_back().map_or(0, |k| *k) + 1;
                    recs.insert(n, OptBatchRec { n, batch: b.clone(), phase: "committed".into(), staged_us: 0, resolved_us: None, acks: vec![] });
                }
            }
        }
        st.batches = recs.into_values().collect();
        for r in st.batches.iter().filter(|r| r.phase == "committed") {
            for f in &r.batch.fills {
                st.last_premium.insert(f.series, f.premium_milli);
            }
        }
        self.opts = Some(st);
        if let Some(b) = self.router.pending_option().map_err(|e| e.to_string())?.cloned() {
            self.on_option_staged(b, now_us())?;
        }
        self.events.clear();
        Ok(self.options_summary())
    }

    pub fn options_summary(&self) -> Value {
        let Some(st) = &self.opts else { return json!({"enabled": false}) };
        json!({"enabled": true, "oracle": h(&self.group_key), "num_bits": NUM_BITS, "usdt": st.usdt.map(|a| self.asset_json(&a)),
               "combos": true, "acks": self.router.option_acks_active().unwrap_or(false), "ownerless_expiry": self.router.ownerless_expiry_active().unwrap_or(false),
               "staged": st.staged.map(|i| st.batches[i].n)})
    }

    // ---------------------------------------------------------- listing ----

    /// Event ids the options feed should fetch from the relay: announced events not yet listed
    /// whose maturity is far enough ahead, and listed events past maturity not yet settled.
    pub fn options_feed_wants(&self, listing: &Value, now: u64) -> Vec<String> {
        let Some(st) = &self.opts else { return vec![] };
        let Ok(Some(desk)) = self.router.options() else { return vec![] };
        let listed: std::collections::BTreeSet<String> = desk.series_ids().filter_map(|id| desk.series(id)).map(|(s, _)| s.event_id.clone()).collect();
        let open: std::collections::BTreeSet<String> =
            desk.series_ids().filter_map(|id| desk.series(id)).filter(|(_, settled)| settled.is_none()).map(|(s, _)| s.event_id.clone()).collect();
        let mut want = vec![];
        let upcoming = |e: &String| st.events.get(e).is_some_and(|r| r.maturity_unix * 1_000_000 > now);
        let mut slots = MAX_EVENTS.saturating_sub(listed.iter().filter(|e| upcoming(e)).count());
        for e in listing["events"].as_array().into_iter().flatten() {
            let (Some(id), Some(m)) = (e["event_id"].as_str(), e["maturity_unix"].as_u64()) else { continue };
            if listed.contains(id) {
                continue;
            }
            if e["status"] == "announced" && m * 1_000_000 > now + LIST_LEAD_US && slots > 0 && self.mark_usd().is_some() {
                want.push(id.to_string());
                slots -= 1;
            }
        }
        for e in &open {
            let rec = st.events.get(e);
            let matured = rec.is_none_or(|r| r.maturity_unix * 1_000_000 <= now);
            if matured && rec.is_none_or(|r| now >= r.retry_after_us) && !want.contains(e) {
                want.push(e.clone());
            }
        }
        want
    }

    /// Apply one relay DLC event: list its series (announced, maturity ahead) or expire them
    /// (attested). Returns what was done.
    pub fn options_apply_event(&mut self, ev: &Value, now: u64) -> Result<Value, String> {
        self.opt()?;
        let id = ev["core"]["event_id"].as_str().ok_or("event without core.event_id")?.to_string();
        let maturity = ev["core"]["maturity_unix"].as_u64().ok_or("event without core.maturity_unix")?;
        let status = ev["status"].as_str().unwrap_or("").to_string();
        let price = ev["attestation"]["price_usd"].as_u64();
        {
            let st = self.opt_mut()?;
            let r = st.events.entry(id.clone()).or_insert(EventRec { maturity_unix: maturity, status: status.clone(), price_usd: None, retry_after_us: 0 });
            r.maturity_unix = maturity;
            if r.status != "settled" {
                r.status = status.clone();
                r.price_usd = price;
            }
        }
        let (listed, open): (Vec<Key>, Vec<Key>) = {
            let desk = self.router.options().map_err(|e| e.to_string())?.ok_or("options desk missing")?;
            let of_event: Vec<(Key, bool)> =
                desk.series_ids().filter_map(|k| desk.series(k).filter(|(s, _)| s.event_id == id).map(|(_, settled)| (*k, settled.is_none()))).collect();
            (of_event.iter().map(|x| x.0).collect(), of_event.iter().filter(|x| x.1).map(|x| x.0).collect())
        };
        if listed.is_empty() {
            if status != "announced" || maturity * 1_000_000 <= now + LIST_LEAD_US {
                return Ok(json!({"event_id": id, "action": "none"}));
            }
            let ann = verify_announcement(ev, &self.group_key)?;
            let mark = self.mark_usd().ok_or("no oracle mark yet")?;
            let domain = PriceDomain::from_bits(NUM_BITS);
            let usdt = self.opt()?.usdt;
            let mut n = 0;
            for k in strike_grid(mark, domain) {
                let mut series = vec![
                    Series { kind: OptionKind::Call, asset: SettleAsset::Btc, strike_usd: k, event_id: id.clone() },
                    Series { kind: OptionKind::Put, asset: SettleAsset::Btc, strike_usd: k, event_id: id.clone() },
                ];
                if let Some(u) = usdt {
                    series.push(Series { kind: OptionKind::Put, asset: u, strike_usd: k, event_id: id.clone() });
                }
                for s in series {
                    self.router.list_series(s, ann.clone()).map_err(|e| format!("list series: {e}"))?;
                    n += 1;
                }
            }
            self.emit(json!({"type": "options_series", "event_id": id, "listed": n}));
            return Ok(json!({"event_id": id, "action": "listed", "series": n, "mark_usd": mark}));
        }
        if open.is_empty() {
            if let Some(r) = self.opt_mut()?.events.get_mut(&id) {
                r.status = "settled".into();
            }
            return Ok(json!({"event_id": id, "action": "settled"}));
        }
        if status == "unattestable" && self.opt()?.staged.is_none() {
            // The oracle's signed notice (dlc_coord.py declare_unattestable): every open series
            // on the event is void, legs return with no payoff, collateral is freed.
            let notice = parse_sig(ev["unattestable_signature"].as_str().ok_or("unattestable event without unattestable_signature")?)?;
            let b = self.router.void_event(id.clone(), notice).map_err(opt_err)?;
            if self.router.pending_option().map_err(|e| e.to_string())?.is_some() {
                self.on_option_staged(b.clone(), now)?;
            } else {
                self.record_option_batch(b.clone(), "committed", now);
            }
            return Ok(json!({"event_id": id, "action": "voiding", "option_seq": b.sequence}));
        }
        if status != "attested" || self.opt()?.staged.is_some() {
            return Ok(json!({"event_id": id, "action": "waiting", "status": status}));
        }
        let att: OracleAttestation = serde_json::from_value(ev["shz_dlc_attestation"].clone()).map_err(|e| format!("shz_dlc_attestation: {e}"))?;
        let b = self.router.expire_series(open[0], att).map_err(opt_err)?;
        let staged = self.router.pending_option().map_err(|e| e.to_string())?.is_some();
        if staged {
            self.on_option_staged(b.clone(), now)?;
        } else {
            self.record_option_batch(b.clone(), "committed", now);
        }
        Ok(json!({"event_id": id, "action": "expiring", "option_seq": b.sequence}))
    }

    // ------------------------------------------------------------ intake ----

    pub fn option_intent_from_json(&self, j: &Value) -> Result<IntentV7, String> {
        intent_v7_from_json(j, self.scope, ROUTER_ID)
    }
}

/// IntentV7 from its JSON form (docs/SHZ_VENUE_OPTIONS.md); scope and router are the venue's.
pub fn intent_v7_from_json(j: &Value, scope: Scope, router: u32) -> Result<IntentV7, String> {
    let s = |k: &str| j[k].as_str().ok_or_else(|| format!("missing {k}"));
    let u = |k: &str| j[k].as_u64().ok_or_else(|| format!("missing {k}"));
    let version = j["version"].as_u64().unwrap_or(OPTION_INTENT_VERSION as u64) as u32;
    let action = match s("action")? {
        "post" => Action::Post,
        "take" => Action::Take,
        "cancel" => Action::Cancel,
        _ => return Err("bad action".into()),
    };
    let raw_legs = j["legs"].as_array().cloned().unwrap_or_default();
    if raw_legs.len() > MAX_LEGS {
        return Err(format!("at most {MAX_LEGS} legs"));
    }
    let legs = raw_legs
        .iter()
        .map(|l| {
            Ok(LegOrder {
                series: parse_key(l["series"].as_str().ok_or("leg.series required")?)?,
                long: l["long"].as_bool().ok_or("leg.long required")?,
                qty: l["qty"].as_u64().ok_or("leg.qty required")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let other_limits = j["other_limits"]
        .as_array()
        .map(|a| a.iter().map(|l| Ok(AssetLimit { asset: asset_from_json(&l["asset"])?, premium_milli: l["premium_milli"].as_i64().ok_or("other_limits.premium_milli required")? })).collect::<Result<Vec<_>, String>>())
        .transpose()?
        .unwrap_or_default();
    let zero = [0u8; 32];
    Ok(IntentV7 {
        version,
        scope,
        router,
        channel: BtcOutPoint { txid: parse_key(j["channel"]["txid"].as_str().ok_or("missing channel")?)?, vout: j["channel"]["vout"].as_u64().ok_or("missing vout")? as u32 },
        owner: parse_key(s("owner")?)?,
        sequence: u("sequence")?,
        expires_us: u("expires_us")?,
        action,
        legs,
        premium_milli: j["premium_milli"].as_i64().unwrap_or(0),
        other_limits,
        cancel_target: j["cancel_target"].as_str().map(parse_key).transpose()?.unwrap_or(zero),
        signature: j["signature"].as_str().map(parse_sig).transpose()?.unwrap_or(ZERO_SIG),
    })
}

impl Venue {

    pub fn option_submit(&mut self, i: IntentV7) -> Result<Value, String> {
        self.opt()?;
        self.wallet_check(&i.owner)?;
        let id = i.id();
        let now = now_us().max(self.desk_clock());
        let series: Vec<Key> = i.legs.iter().map(|l| l.series).collect();
        let out = self.router.submit_option(i.clone(), now).map_err(opt_err)?;
        let cancelled = if let OptionOutcome::Cancelled(t) = &out { Some(*t) } else { None };
        let (status, outcome, batch_n) = match out {
            OptionOutcome::Posted(_) => ("resting", "posted", None),
            OptionOutcome::Cancelled(t) => {
                if let Some(r) = self.opt_mut()?.intents.get_mut(&t) {
                    r.status = "cancelled".into();
                }
                ("done", "cancelled", None)
            }
            OptionOutcome::Staged(b) => {
                let n = self.on_option_staged(*b, now)?;
                ("staged", "staged", Some(n))
            }
            OptionOutcome::Filled(b) => {
                let n = self.record_option_batch(*b, "committed", now);
                ("filled", "filled", Some(n))
            }
        };
        self.opt_mut()?.intents.insert(id, OptIntentRec { intent: i, status: status.into(), accepted_us: now, reason: None, batch: batch_n });
        self.persist_intent(&id);
        if let Some(t) = cancelled {
            self.persist_intent(&t);
        }
        for s in series {
            self.emit(json!({"type": "option_book", "series": h(&s)}));
        }
        self.emit(json!({"type": "account"}));
        Ok(json!({"id": h(&id), "outcome": outcome, "batch": batch_n}))
    }

    /// Owner-signed collateral move between the perpetual allocation and the options
    /// sub-account (fund/defund, sats) or through the simulated stablecoin adapter
    /// (deposit/withdraw, base units).
    pub fn option_transfer(&mut self, op_name: &str, j: &Value) -> Result<Value, String> {
        self.opt()?;
        let op = transfer_op(op_name).ok_or("unknown transfer")?;
        let owner = parse_key(j["owner"].as_str().ok_or("owner required")?)?;
        let amount = j["amount"].as_u64().filter(|a| *a > 0).ok_or("amount required (base units, > 0)")?;
        let expires = j["expires_us"].as_u64().ok_or("expires_us required")?;
        let sig = parse_sig(j["signature"].as_str().ok_or("signature required")?)?;
        let asset = if op <= 2 { SettleAsset::Btc } else { asset_from_json(&j["asset"])? };
        if op > 2 && asset == SettleAsset::Btc {
            return Err("deposit and withdraw move a registered stablecoin; BTC moves with fund/defund".into());
        }
        let now = now_us();
        if expires <= now || expires > now + MAX_TRANSFER_AHEAD_US {
            return Err("expires_us must be in the next 10 minutes".into());
        }
        if self.opt()?.nonces.get(&owner).is_some_and(|n| expires <= *n) {
            return Err("expires_us must increase with every transfer (replay)".into());
        }
        let digest = transfer_digest(op, &owner, &asset, amount, expires);
        bip340_verify(&owner, &digest, &sig).map_err(|_| "transfer signature does not verify")?;
        self.wallet_check(&owner)?;
        let ch = self.accounts.get(&owner).ok_or("no such account")?.outpoint.clone();
        // The nonce is durable (fsync) before the move: a crash after it can only burn the
        // nonce, never let the same signed transfer run twice.
        self.persist(json!({"kind": "opt_nonce", "owner": h(&owner), "expires_us": expires}));
        self.opt_mut()?.nonces.insert(owner, expires);
        match op {
            1 => self.router.fund_options(ch, amount),
            2 => self.router.defund_options(ch, amount),
            3 => self.router.deposit_stable(ch, asset, amount),
            _ => self.router.withdraw_stable(ch, asset, amount),
        }
        .map_err(opt_err)?;
        self.emit(json!({"type": "account"}));
        Ok(json!({"accepted": op_name, "amount": amount, "asset": self.asset_json(&asset), "options": self.options_account(&owner)}))
    }

    // ------------------------------------------------- acknowledgement round ----

    /// The router staged `b`: post one pending owner signature per lane over its V4 Commit
    /// message and hold the adapter's peer and monitor signatures. Returns the batch number.
    pub(crate) fn on_option_staged(&mut self, b: OptionBatch, now: u64) -> Result<u64, String> {
        let n = self.opt()?.batches.last().map_or(0, |r| r.n) + 1;
        let digest = b.digest();
        let ownerless = self.ownerless(&b);
        let mut acks = vec![];
        for c in b.channels() {
            let msg = self.router.option_ack_message(Disposition::Commit, &c).map_err(|e| e.to_string())?;
            let peer = bip340_sign(&self.keys.lane_sk("peer", &c), &msg).map_err(|e| e.to_string())?;
            let monitor = bip340_sign(&self.keys.lane_sk("monitor", &c), &msg).map_err(|e| e.to_string())?;
            let owner = self.owner_of_channel(&c).ok_or("option lane without a venue account")?;
            let rows: Vec<Value> = b.clearing.iter().filter_map(|ac| ac.report.rows.iter().find(|r| r.channel == c).map(|r| json!({"asset": self.asset_code(&ac.asset), "net": r.net, "paid": r.paid, "collected": r.collected}))).collect();
            let id = format!("opt{n}:ack:{}:{}", h(&c.txid), c.vout);
            if !ownerless {
                self.pending.insert(id.clone(), PendingSig { id, owner, kind: "option_ack".into(), message: msg,
                context: json!({"option_batch": n, "option_seq": b.sequence, "batch_digest": h(&digest), "channel": outpoint_json(&c),
                                "batch_kind": batch_kind_name(&b), "rows": rows, "adapter": "simulated (venue-held peer and monitor keys)"}) });
            }
            acks.push(OptionAck { channel: c, signatures: [ZERO_SIG, peer, monitor] });
        }
        let st = self.opt_mut()?;
        st.batches.push(OptBatchRec { n, batch: b, phase: "staged".into(), staged_us: now, resolved_us: None, acks });
        st.staged = Some(st.batches.len() - 1);
        let view = self.option_batch_json(self.opt()?.batches.last().unwrap());
        self.emit(json!({"type": "option_batch", "phase": "staged", "batch": view}));
        self.emit(json!({"type": "account"}));
        self.options_advance(now)?;
        Ok(n)
    }

    /// Record a batch the router committed without a staging round (acknowledgements off).
    fn record_option_batch(&mut self, b: OptionBatch, phase: &str, now: u64) -> u64 {
        let Some(st) = self.opts.as_mut() else { return 0 };
        let n = st.batches.last().map_or(0, |r| r.n) + 1;
        st.batches.push(OptBatchRec { n, batch: b, phase: phase.into(), staged_us: now, resolved_us: Some(now), acks: vec![] });
        let i = st.batches.len() - 1;
        self.after_option_resolution(i, now);
        n
    }

    pub(crate) fn option_ack_signed(&mut self, p: &PendingSig, sig: shz_dlc::Bip340Signature) -> Result<(), String> {
        let n = p.context["option_batch"].as_u64().unwrap_or(0);
        let c = &p.context["channel"];
        let key = (parse_key(c["txid"].as_str().unwrap_or(""))?, c["vout"].as_u64().unwrap_or(0) as u32);
        let st = self.opt_mut()?;
        let Some(i) = st.staged.filter(|&i| st.batches[i].n == n) else { return Ok(()) };
        if let Some(a) = st.batches[i].acks.iter_mut().find(|a| (a.channel.txid, a.channel.vout) == key) {
            a.signatures[0] = sig;
        }
        Ok(())
    }

    /// Commit the staged option batch once every lane's owner signed, or fence-abort it with
    /// the adapter's signatures `ABORT_AFTER_US` after staging.
    pub(crate) fn options_advance(&mut self, now: u64) -> Result<(), String> {
        let Some(st) = &self.opts else { return Ok(()) };
        let Some(i) = st.staged else { return Ok(()) };
        let rec = &st.batches[i];
        let clock = now.max(self.desk_clock());
        let deadline = now >= rec.staged_us.saturating_add(ABORT_AFTER_US);
        if self.ownerless(&rec.batch) || rec.acks.iter().all(|a| a.signatures[0] != ZERO_SIG) {
            let bundle = OptionAckBundle { sequence: rec.batch.sequence, batch: rec.batch.digest(), disposition: Disposition::Commit, acks: rec.acks.clone() };
            match self.router.resolve_option(bundle, clock) {
                Ok(_) => {
                    self.finish_option(i, "committed", now);
                    return Ok(());
                }
                Err(e) if !deadline => return Err(format!("resolve option batch: {e}")),
                Err(_) => {}
            }
        } else if !deadline {
            return Ok(());
        }
        let (batch, channels) = (rec.batch.clone(), rec.batch.channels());
        let mut acks = vec![];
        for c in channels {
            let msg = self.router.option_ack_message(Disposition::FencedAbort, &c).map_err(|e| e.to_string())?;
            let peer = bip340_sign(&self.keys.lane_sk("peer", &c), &msg).map_err(|e| e.to_string())?;
            let monitor = bip340_sign(&self.keys.lane_sk("monitor", &c), &msg).map_err(|e| e.to_string())?;
            acks.push(OptionAck { channel: c, signatures: [ZERO_SIG, peer, monitor] });
        }
        let bundle = OptionAckBundle { sequence: batch.sequence, batch: batch.digest(), disposition: Disposition::FencedAbort, acks };
        self.router.resolve_option(bundle, clock).map_err(|e| format!("abort option batch: {e}"))?;
        self.finish_option(i, "aborted", now);
        Ok(())
    }

    fn finish_option(&mut self, i: usize, phase: &str, now: u64) {
        let Some(st) = self.opts.as_mut() else { return };
        st.staged = None;
        let rec = &mut st.batches[i];
        rec.phase = phase.into();
        rec.resolved_us = Some(now);
        let n = rec.n;
        self.pending.retain(|_, p| p.context["option_batch"].as_u64() != Some(n));
        self.after_option_resolution(i, now);
    }

    fn after_option_resolution(&mut self, i: usize, now: u64) {
        let Some(st) = self.opts.as_ref() else { return };
        let (n, phase, batch) = {
            let r = &st.batches[i];
            (r.n, r.phase.clone(), r.batch.clone())
        };
        let committed = phase == "committed";
        // Makers whose quote still rests after the batch (partially filled).
        let resting: std::collections::BTreeSet<Key> = match self.router.options() {
            Ok(Some(d)) => batch
                .fills
                .iter()
                .filter(|f| st.intents.get(&f.maker).and_then(|r| r.intent.legs.first()).is_some_and(|l| d.depth(&f.series, l.long).iter().any(|q| q.0 == f.maker)))
                .map(|f| f.maker)
                .collect(),
            _ => Default::default(),
        };
        let st = self.opts.as_mut().unwrap();
        let mut changed: Vec<Key> = vec![];
        match &batch.kind {
            OptionBatchKind::Trade { taker } => {
                if let Some(r) = st.intents.get_mut(taker) {
                    r.status = if committed { "filled".into() } else { "aborted".into() };
                    r.batch = Some(n);
                    changed.push(*taker);
                }
                // An abort pulls every maker quote of the batch (the router cancels them).
                for f in &batch.fills {
                    if committed {
                        st.last_premium.insert(f.series, f.premium_milli);
                    }
                    let Some(r) = st.intents.get_mut(&f.maker).filter(|r| r.status == "resting" || r.status == "partially filled") else { continue };
                    if committed {
                        r.status = if resting.contains(&f.maker) { "partially filled".into() } else { "filled".into() };
                    } else {
                        r.status = "cancelled".into();
                        r.reason = Some("pulled: its fill was in an aborted option batch".into());
                    }
                    r.batch = Some(n);
                    changed.push(f.maker);
                }
            }
            // Spot intents are the spot module's (`spot_resolved`, below).
            OptionBatchKind::Spot { .. } => {}
            OptionBatchKind::Expiry { event_id, price_usd, .. } => {
                if let Some(r) = st.events.get_mut(event_id) {
                    if committed {
                        r.status = if batch.kind.is_void() { "void".into() } else { "settled".into() };
                        r.price_usd = Some(*price_usd).filter(|p| *p > 0);
                    } else {
                        r.retry_after_us = now + EXPIRY_RETRY_US;
                    }
                }
            }
        }
        self.persist_batch(i);
        for id in changed {
            self.persist_intent(&id);
        }
        let view = self.option_batch_json(&self.opts.as_ref().unwrap().batches[i]);
        self.emit(json!({"type": "option_batch", "phase": phase, "batch": view.clone()}));
        if committed {
            for f in &view["fills"].as_array().cloned().unwrap_or_default() {
                self.emit(json!({"type": "option_fill", "batch": n, "fill": f}));
            }
            if let OptionBatchKind::Expiry { event_id, series, price_usd } = &batch.kind {
                self.emit(json!({"type": "option_expiry", "event_id": event_id, "price_usd": price_usd, "void": batch.kind.is_void(), "series": series.iter().map(|s| h(s)).collect::<Vec<_>>(),
                                 "batch": n, "clearing": view["clearing"].clone()}));
            }
        }
        if matches!(batch.kind, OptionBatchKind::Spot { .. }) {
            self.spot_resolved(n, &batch, committed, now);
        }
        let touched: std::collections::BTreeSet<Key> = batch.fills.iter().map(|f| f.series).collect();
        for s in touched {
            self.emit(json!({"type": "option_book", "series": h(&s)}));
        }
        self.emit(json!({"type": "account"}));
    }

    /// Expiry and void batches commit without owner signatures once ownerless expiry is on;
    /// trade and spot batches never do.
    fn ownerless(&self, b: &OptionBatch) -> bool {
        matches!(b.kind, OptionBatchKind::Expiry { .. }) && self.router.ownerless_expiry_active().unwrap_or(false)
    }

    fn persist_intent(&mut self, id: &Key) {
        let Some(r) = self.opts.as_ref().and_then(|o| o.intents.get(id)) else { return };
        let e = json!({"kind": "opt_intent", "id": h(id), "intent": serde_json::to_value(&r.intent).unwrap_or(Value::Null), "status": r.status,
                       "reason": r.reason, "batch": r.batch, "accepted_us": r.accepted_us});
        self.persist(e);
    }
    fn persist_batch(&mut self, i: usize) {
        let Some(r) = self.opts.as_ref().and_then(|o| o.batches.get(i)) else { return };
        let e = json!({"kind": "opt_batch", "n": r.n, "phase": r.phase, "staged_us": r.staged_us, "resolved_us": r.resolved_us,
                       "batch": serde_json::to_value(&r.batch).unwrap_or(Value::Null), "acks": serde_json::to_value(&r.acks).unwrap_or(Value::Null)});
        self.persist(e);
    }

    // ------------------------------------------------------------- views ----

    pub fn option_batch_json(&self, r: &OptBatchRec) -> Value {
        let b = &r.batch;
        let side = |c: &BtcOutPoint| json!({"channel": outpoint_json(c), "owner": self.owner_of_channel(c).map(|k| h(&k))});
        let (kind, extra) = match &b.kind {
            OptionBatchKind::Trade { taker } => ("trade", json!({"taker": h(taker)})),
            OptionBatchKind::Spot { taker } => ("spot", json!({"taker": h(taker)})),
            OptionBatchKind::Expiry { event_id, series, price_usd } => (batch_kind_name(b), json!({"event_id": event_id, "price_usd": price_usd, "series": series.iter().map(|s| h(s)).collect::<Vec<_>>()})),
        };
        json!({
            "n": r.n, "seq": b.sequence, "kind": kind, "detail": extra, "phase": r.phase, "digest": h(&b.digest()),
            "staged_us": r.staged_us, "resolved_us": r.resolved_us,
            "fills": b.fills.iter().map(|f| json!({"series": h(&f.series), "asset": self.asset_code(&f.asset), "long": side(&f.long), "short": side(&f.short),
                "maker": h(&f.maker), "taker": h(&f.taker), "qty": f.qty, "premium_milli": f.premium_milli, "premium": f.premium})).collect::<Vec<_>>(),
            "spot": b.spot.iter().map(|f| json!({"seller": side(&f.seller), "buyer": side(&f.buyer), "maker": h(&f.maker), "taker": h(&f.taker),
                "taker_side": if f.taker_buys { "buy" } else { "sell" }, "sats": f.sats, "price": f.price, "quote_units": f.quote_units})).collect::<Vec<_>>(),
            "clearing": b.clearing.iter().map(|c| json!({"asset": self.asset_code(&c.asset), "digest": h(&c.report.digest()),
                "rows": c.report.rows.iter().map(|x| json!({"channel": outpoint_json(&x.channel), "owner": self.owner_of_channel(&x.channel).map(|k| h(&k)),
                    "pnl": x.pnl, "collected": x.collected, "paid": x.paid, "net": x.net})).collect::<Vec<_>>(),
                "cash_before": c.report.cash_before, "cash_after": c.report.cash_after, "pool_net": c.report.pool_net(), "fund_after": c.report.fund_after,
                "layer": format!("{:?}", c.report.layer)})).collect::<Vec<_>>(),
            "acks": r.acks.iter().map(|a| json!({"channel": outpoint_json(&a.channel), "owner_signed": a.signatures[0] != ZERO_SIG,
                "peer_signature": sig_hex(&a.signatures[1]), "monitor_signature": sig_hex(&a.signatures[2])})).collect::<Vec<_>>(),
        })
    }

    pub fn option_batches(&self, limit: usize) -> Value {
        let Some(st) = &self.opts else { return json!([]) };
        json!(st.batches.iter().rev().take(limit).map(|r| self.option_batch_json(r)).collect::<Vec<_>>())
    }

    fn series_json(&self, id: &Key, s: &Series, settled: Option<u64>) -> Value {
        let desk = self.router.options().ok().flatten();
        let domain = PriceDomain::from_bits(NUM_BITS);
        let best = |long: bool| desk.and_then(|d| d.depth(id, long).first().map(|(_, p, q)| json!({"premium_milli": p, "qty": q})));
        let maturity = self.opts.as_ref().and_then(|o| o.events.get(&s.event_id)).map(|e| e.maturity_unix);
        json!({
            "id": h(id), "kind": kind_name(s.kind), "asset": self.asset_json(&s.asset), "asset_code": self.asset_code(&s.asset),
            "strike_usd": s.strike_usd, "event_id": s.event_id, "maturity_unix": maturity, "settled_price_usd": settled, "void": settled == Some(0),
            "contract_qty": contract_qty(&s.asset), "qty_unit": if s.asset == SettleAsset::Btc { "usd" } else { "btc_e8" },
            "premium_unit": if s.asset == SettleAsset::Btc { "millisat per unit" } else { "thousandth of a base unit per unit" },
            "bid": best(true), "ask": best(false),
            "last_premium_milli": self.opts.as_ref().and_then(|o| o.last_premium.get(id)),
            "worst_case_per_contract": {"short": short_worst_case(s, domain) as u64, "long": 0, "note": "base units of the settlement asset, premium excluded; the long's worst case is the premium it pays"},
            "margin_per_contract": {"short": short_worst_case(s, domain) as u64, "long": 0},
        })
    }

    pub fn options_series_view(&self) -> Value {
        let Some(st) = &self.opts else { return json!({"enabled": false}) };
        let Ok(Some(desk)) = self.router.options() else { return json!({"enabled": false}) };
        let mut series: Vec<(Key, Series, Option<u64>)> = desk.series_ids().filter_map(|k| desk.series(k).map(|(s, x)| (*k, s.clone(), x))).collect();
        series.sort_by(|a, b| (a.1.event_id.clone(), a.1.strike_usd, kind_name(a.1.kind), self.asset_code(&a.1.asset)).cmp(&(b.1.event_id.clone(), b.1.strike_usd, kind_name(b.1.kind), self.asset_code(&b.1.asset))));
        let mut assets = vec![self.asset_json(&SettleAsset::Btc)];
        for (a, pool) in desk.stable_pools() {
            let mut j = self.asset_json(a);
            j["pool"] = json!({"cash": pool.cash, "fund": pool.fund});
            assets.push(j);
        }
        json!({
            "enabled": true, "mark_usd": self.mark_usd(), "oracle": h(&self.group_key), "num_bits": NUM_BITS,
            "domain": {"p_min": desk.domain.p_min, "p_max": desk.domain.p_max}, "assets": assets,
            "staged": st.staged.map(|i| st.batches[i].n),
            "events": st.events.iter().map(|(id, e)| json!({"event_id": id, "maturity_unix": e.maturity_unix, "status": e.status, "price_usd": e.price_usd})).collect::<Vec<_>>(),
            "series": series.iter().map(|(k, s, x)| self.series_json(k, s, *x)).collect::<Vec<_>>(),
        })
    }

    pub fn options_book(&self, series: &Key, depth: usize) -> Result<Value, String> {
        self.opt()?;
        let desk = self.router.options().map_err(|e| e.to_string())?.ok_or("options desk missing")?;
        let (s, settled) = desk.series(series).ok_or("no such series")?;
        let agg = |long: bool| {
            let mut m: Vec<(i64, u64, u32)> = vec![];
            for (_, p, q) in desk.depth(series, long) {
                match m.last_mut() {
                    Some(x) if x.0 == p => {
                        x.1 += q;
                        x.2 += 1
                    }
                    _ => m.push((p, q, 1)),
                }
            }
            m.into_iter().take(depth).map(|(p, q, n)| json!([p, q, n])).collect::<Vec<_>>()
        };
        Ok(json!({"series": self.series_json(series, s, settled), "bids": agg(true), "asks": agg(false)}))
    }

    /// The account's options sub-account: balances per asset with the collateral each needs,
    /// legs, open quotes, fills and the option acknowledgements still waiting for its key.
    pub fn options_account(&self, owner: &Key) -> Value {
        let (Some(st), Some(a)) = (&self.opts, self.accounts.get(owner)) else { return json!(null) };
        let Ok(Some(desk)) = self.router.options() else { return json!(null) };
        let k = (a.outpoint.txid, a.outpoint.vout);
        let acct = desk.account(&k);
        let mut assets: Vec<SettleAsset> = vec![SettleAsset::Btc];
        assets.extend(desk.stable_pools().map(|(x, _)| *x));
        let balances: Vec<Value> = assets
            .iter()
            .map(|x| {
                let b = acct.map(|ac| ac.balance(x)).unwrap_or_default();
                json!({"asset": self.asset_code(x), "descriptor": self.asset_json(x), "free": b.free, "locked": b.locked, "realized": b.realized,
                       "required": desk.required(&k, x) as u64})
            })
            .collect();
        let legs: Vec<Value> = acct
            .map(|ac| {
                ac.legs.iter().filter(|(_, n)| **n != 0).filter_map(|(sid, n)| {
                    desk.series(sid).map(|(s, settled)| json!({"series": h(sid), "kind": kind_name(s.kind), "asset": self.asset_code(&s.asset), "strike_usd": s.strike_usd,
                        "event_id": s.event_id, "maturity_unix": st.events.get(&s.event_id).map(|e| e.maturity_unix), "net": n, "settled_price_usd": settled, "void": settled == Some(0)}))
                }).collect()
            })
            .unwrap_or_default();
        let mut open = vec![];
        for sid in desk.series_ids() {
            for long in [true, false] {
                for (qid, p, q) in desk.depth(sid, long) {
                    if st.intents.get(&qid).is_some_and(|r| r.intent.owner == *owner) {
                        open.push(json!({"id": h(&qid), "series": h(sid), "long": long, "premium_milli": p, "remaining": q}));
                    }
                }
            }
        }
        let fills: Vec<Value> = st.batches.iter().rev()
            .flat_map(|r| r.batch.fills.iter().filter(|f| f.long == a.outpoint || f.short == a.outpoint).map(move |f| (r, f)))
            .take(200)
            .map(|(r, f)| json!({"batch": r.n, "phase": r.phase, "series": h(&f.series), "asset": self.asset_code(&f.asset), "side": if f.long == a.outpoint { "long" } else { "short" },
                                 "qty": f.qty, "premium_milli": f.premium_milli, "premium": f.premium, "taker": h(&f.taker)}))
            .collect();
        let mut mine: Vec<(&Key, &OptIntentRec)> = st.intents.iter().filter(|(_, r)| r.intent.owner == *owner).collect();
        mine.sort_by_key(|(_, r)| std::cmp::Reverse(r.accepted_us));
        let intents: Vec<Value> = mine.into_iter().take(50)
            .map(|(id, r)| json!({"id": h(id), "status": r.status, "reason": r.reason, "batch": r.batch, "action": match r.intent.action { Action::Post => "post", Action::Take => "take", Action::Cancel => "cancel" },
                                  "legs": r.intent.legs.iter().map(|l| json!({"series": h(&l.series), "long": l.long, "qty": l.qty})).collect::<Vec<_>>(), "premium_milli": r.intent.premium_milli,
                                  "accepted_us": r.accepted_us})).collect();
        let pending: Vec<Value> = self.pending.values().filter(|p| p.owner == *owner && p.kind == "option_ack")
            .map(|p| json!({"id": p.id, "kind": p.kind, "message": h(&p.message), "context": p.context})).collect();
        json!({"balances": balances, "legs": legs, "fully_funded": desk.fully_funded(&k), "open_orders": open, "fills": fills, "intents": intents,
               "pending_signatures": pending, "last_sequence": acct.map(|x| x.last_sequence).unwrap_or(0)})
    }
}

fn batch_kind_name(b: &OptionBatch) -> &'static str {
    match b.kind {
        OptionBatchKind::Trade { .. } => "trade",
        OptionBatchKind::Spot { .. } => "spot",
        _ if b.kind.is_void() => "void",
        OptionBatchKind::Expiry { .. } => "expiry",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with ui/venue/test/options.test.mjs: the JS encoder must give the same ids.
    #[test]
    fn shared_intent_v7_and_transfer_vector() {
        let v: Value = serde_json::from_str(include_str!("../../../../ui/venue/test/options_vector.json")).unwrap();
        let sc = &v["scope"];
        let scope = Scope { network: parse_key(sc["network"].as_str().unwrap()).unwrap(), epoch: sc["epoch"].as_u64().unwrap(), policy: parse_key(sc["policy"].as_str().unwrap()).unwrap() };
        let router = v["router"].as_u64().unwrap() as u32;
        for c in v["intents"].as_array().unwrap() {
            let i = intent_v7_from_json(&c["intent"], scope, router).unwrap();
            assert_eq!(h(&i.id()), c["id"].as_str().unwrap(), "{}", c["name"]);
            // the intent's signature (made by the JS signer) verifies under its owner
            bip340_verify(&i.owner, &i.id(), &i.signature).unwrap();
        }
        for c in v["transfers"].as_array().unwrap() {
            let asset = if c["asset"].is_null() { SettleAsset::Btc } else { asset_from_json(&c["asset"]).unwrap() };
            let d = transfer_digest(transfer_op(c["op"].as_str().unwrap()).unwrap(), &parse_key(c["owner"].as_str().unwrap()).unwrap(), &asset, c["amount"].as_u64().unwrap(), c["expires_us"].as_u64().unwrap());
            assert_eq!(h(&d), c["digest"].as_str().unwrap(), "{}", c["op"]);
        }
    }

    /// Events fetched read-only from the public relay (GET /v1/dlc/event/{id}, 2026-11-27):
    /// the announcement check and the attestation parse must accept the relay's real format.
    #[test]
    fn live_relay_events_verify() {
        let group = parse_key("403c496669cba966c14d989711a2a16026c7c295305301e5c61b96eb718cfdb8").unwrap();
        let announced: Value = serde_json::from_str(include_str!("fixtures/live_dlc_announced_20261127T0200Z.json")).unwrap();
        let attested: Value = serde_json::from_str(include_str!("fixtures/live_dlc_attested_20261127T0100Z.json")).unwrap();
        let a = verify_announcement(&announced, &group).unwrap();
        assert_eq!(a.event_id, "SHZ-BTCUSD-20261127T0200Z");
        assert_eq!(a.num_bits(), NUM_BITS);
        let b = verify_announcement(&attested, &group).unwrap();
        let att: OracleAttestation = serde_json::from_value(attested["shz_dlc_attestation"].clone()).unwrap();
        att.verify_against(&b).unwrap();
        assert_eq!(att.price_usd, attested["attestation"]["price_usd"].as_u64().unwrap());
        assert_eq!(att.price_usd, 60_614);
        // an attestation of one event does not verify against another event's announcement
        assert!(att.verify_against(&a).is_err());
        // any edit of the signed core, or another oracle key, is refused
        let mut bad = announced.clone();
        bad["core"]["maturity_unix"] = json!(a.maturity_unix + 900);
        assert!(verify_announcement(&bad, &group).is_err());
        let mut bad = announced.clone();
        bad["shz_dlc_announcement"]["digit_nonces_x"][0][0] = json!(0);
        assert!(verify_announcement(&bad, &group).is_err());
        assert!(verify_announcement(&announced, &[7; 32]).is_err());
        // the testnet mark is near 60,600: strikes 59,500 .. 61,500 in steps of 500
        assert_eq!(strike_grid(60_614, PriceDomain::from_bits(NUM_BITS)), vec![59_500, 60_000, 60_500, 61_000, 61_500]);
    }

    /// An event the relay marks unattestable (dlc_coord.py declare_unattestable shape: status
    /// "unattestable", unattestable_signature hex) is voided on the oracle's notice: no payoff,
    /// premium stays paid, collateral freed, and it commits with the holders offline (ownerless).
    /// No live relay event has this status yet, so the event JSON is constructed and signed by a
    /// test oracle key.
    #[test]
    fn unattestable_notice_voids_the_event_with_holders_offline() {
        use shz_dex::routing::{options::unattestable_message, public};
        let dir = std::env::temp_dir().join(format!("shz-venue-opt-void-{}", now_us()));
        let oracle_sk = [9u8; 32];
        let oracle = public(&oracle_sk);
        let mut v = Venue::open(&dir, oracle, "http://127.0.0.1:9".into()).unwrap();
        v.options_enable(None).unwrap();
        assert!(v.router.ownerless_expiry_active().unwrap());
        let (msk, tsk) = ([3u8; 32], [4u8; 32]);
        for sk in [&msk, &tsk] {
            let owner = public(sk);
            let d = v.register_draft(owner, "demo", None, None).unwrap();
            let dig = parse_key(d["allocation_digest"].as_str().unwrap()).unwrap();
            v.register(d["draft_id"].as_str().unwrap(), bip340_sign(sk, &dig).unwrap()).unwrap();
            let exp = now_us() + 300_000_000;
            let td = transfer_digest(1, &owner, &SettleAsset::Btc, 150_000, exp);
            v.option_transfer("fund", &json!({"owner": h(&owner), "amount": 150_000, "expires_us": exp, "signature": sig_hex(&bip340_sign(sk, &td).unwrap())})).unwrap();
        }
        let ev_id = "SHZ-BTCUSD-20261127T0300Z";
        let ann = OracleAnnouncement { event_id: ev_id.into(), maturity_unix: 1, oracle_pubkey_x: oracle, digit_nonces_x: vec![[1; 32]; NUM_BITS as usize] };
        let call = v.router.list_series(Series { kind: OptionKind::Call, asset: SettleAsset::Btc, strike_usd: 100_000, event_id: ev_id.into() }, ann).unwrap();
        let mk = |v: &Venue, sk: &Key, action: Action, long: bool, seq: u64, premium: i64| {
            IntentV7 { version: OPTION_INTENT_VERSION, scope: v.scope, router: ROUTER_ID, channel: v.accounts[&public(sk)].outpoint.clone(), owner: [0; 32], sequence: seq,
                       expires_us: now_us() + 600_000_000, action, legs: vec![LegOrder { series: call, long, qty: 100 }], premium_milli: premium,
                       other_limits: vec![], cancel_target: [0; 32], signature: ZERO_SIG }.signed(sk).unwrap()
        };
        v.option_submit(mk(&v, &msk, Action::Post, false, 1, 3000)).unwrap();
        v.option_submit(mk(&v, &tsk, Action::Take, true, 1, 300_000)).unwrap();
        for sk in [&msk, &tsk] {
            let owner = public(sk);
            let items: Vec<(String, shz_dlc::Bip340Signature)> = v.pending.values().filter(|p| p.owner == owner).map(|p| (p.id.clone(), bip340_sign(sk, &p.message).unwrap())).collect();
            v.add_signatures(owner, &items).unwrap();
        }
        let bal = |v: &Venue, sk: &Key| {
            let a = &v.accounts[&public(sk)].outpoint;
            v.router.options().unwrap().unwrap().account(&(a.txid, a.vout)).unwrap().balance(&SettleAsset::Btc)
        };
        assert!(bal(&v, &msk).locked > 90_000);
        let (t_before, m_before) = (bal(&v, &tsk), bal(&v, &msk));
        // a notice signed by another key is refused; the oracle's notice voids the event
        let ev = |sig: &shz_dlc::Bip340Signature| json!({"core": {"event_id": ev_id, "maturity_unix": 1}, "status": "unattestable",
            "unattestable_digest": h(&unattestable_message(ev_id)), "unattestable_signature": sig_hex(sig)});
        let forged = bip340_sign(&[8; 32], &unattestable_message(ev_id)).unwrap();
        assert!(v.options_apply_event(&ev(&forged), now_us()).is_err());
        let notice = bip340_sign(&oracle_sk, &unattestable_message(ev_id)).unwrap();
        let r = v.options_apply_event(&ev(&notice), now_us()).unwrap();
        assert_eq!(r["action"], "voiding");
        // committed at once with no owner signature (both holders "offline": nothing was signed)
        let st = v.opts.as_ref().unwrap();
        let last = st.batches.last().unwrap();
        assert_eq!((last.phase.as_str(), batch_kind_name(&last.batch)), ("committed", "void"));
        assert!(last.acks.iter().all(|a| a.signatures[0] == ZERO_SIG));
        assert!(last.batch.clearing.iter().all(|c| c.report.rows.iter().all(|r| r.net == 0)));
        assert_eq!(st.events[ev_id].status, "void");
        let (t_after, m_after) = (bal(&v, &tsk), bal(&v, &msk));
        assert_eq!((t_after.realized, t_after.locked), (t_before.realized, 0), "premium stays paid");
        assert_eq!((m_after.locked, m_after.free + m_after.locked), (0, m_before.free + m_before.locked), "collateral freed, nothing paid out");
        assert_eq!(v.options_series_view()["series"][0]["void"], true);
        assert_eq!(v.options_account(&public(&tsk))["legs"], json!([]));
        drop(v);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restart: transfer nonces (fsync'd before the move), aborted and committed option batches
    /// with their venue numbers, and the option intent history all come back from the venue log.
    #[test]
    fn restart_restores_nonces_aborted_batches_and_intents() {
        use shz_dex::routing::public;
        let dir = std::env::temp_dir().join(format!("shz-venue-opt-persist-{}", now_us()));
        let oracle = public(&[9; 32]);
        let usdt = [0xab; 32];
        let (msk, tsk) = ([3u8; 32], [4u8; 32]);
        let reg = |v: &mut Venue, sk: &Key| {
            let owner = public(sk);
            let d = v.register_draft(owner, "demo", None, None).unwrap();
            let dig = parse_key(d["allocation_digest"].as_str().unwrap()).unwrap();
            v.register(d["draft_id"].as_str().unwrap(), bip340_sign(sk, &dig).unwrap()).unwrap();
            owner
        };
        let xfer = |v: &mut Venue, sk: &Key, amount: u64, expires: u64| {
            let owner = public(sk);
            let d = transfer_digest(1, &owner, &SettleAsset::Btc, amount, expires);
            v.option_transfer("fund", &json!({"owner": h(&owner), "amount": amount, "expires_us": expires, "signature": sig_hex(&bip340_sign(sk, &d).unwrap())}))
        };
        let mut seq = 1_000u64;
        let mut intent = |v: &Venue, sk: &Key, action: Action, series: Key, long: bool, qty: u64, premium: i64| {
            seq += 1;
            let a = &v.accounts[&public(sk)];
            IntentV7 { version: OPTION_INTENT_VERSION, scope: v.scope, router: ROUTER_ID, channel: a.outpoint.clone(), owner: [0; 32], sequence: seq,
                       expires_us: now_us() + 600_000_000, action, legs: vec![LegOrder { series, long, qty }], premium_milli: premium,
                       other_limits: vec![], cancel_target: [0; 32], signature: ZERO_SIG }
                .signed(sk)
                .unwrap()
        };
        let sign_acks = |v: &mut Venue, sks: &[Key]| {
            for sk in sks {
                let owner = public(sk);
                let items: Vec<(String, shz_dlc::Bip340Signature)> = v.pending.values().filter(|p| p.owner == owner && p.kind == "option_ack")
                    .map(|p| (p.id.clone(), bip340_sign(sk, &p.message).unwrap())).collect();
                v.add_signatures(owner, &items).unwrap();
            }
        };
        let (n1, n2, used_nonce, post1, take1, post2, take2);
        {
            let mut v = Venue::open(&dir, oracle, "http://127.0.0.1:9".into()).unwrap();
            v.options_enable(Some(usdt)).unwrap();
            let (m, t) = (reg(&mut v, &msk), reg(&mut v, &tsk));
            let ann = OracleAnnouncement { event_id: "E".into(), maturity_unix: 2_000_000_000, oracle_pubkey_x: oracle, digit_nonces_x: vec![[1; 32]; NUM_BITS as usize] };
            let call = v.router.list_series(Series { kind: OptionKind::Call, asset: SettleAsset::Btc, strike_usd: 100_000, event_id: "E".into() }, ann).unwrap();
            used_nonce = now_us() + 300_000_000;
            xfer(&mut v, &msk, 150_000, used_nonce).unwrap();
            xfer(&mut v, &tsk, 40_000, used_nonce).unwrap();
            // 1: the taker never signs: fence-aborted at the deadline
            let p1 = intent(&v, &msk, Action::Post, call, false, 100, 3000);
            post1 = p1.id();
            v.option_submit(p1).unwrap();
            let t1 = intent(&v, &tsk, Action::Take, call, true, 100, 300_000);
            take1 = t1.id();
            assert_eq!(v.option_submit(t1).unwrap()["outcome"], "staged");
            sign_acks(&mut v, &[msk]);
            v.options_advance(now_us() + ABORT_AFTER_US + 1).unwrap();
            // 2: both sign: committed
            let p2 = intent(&v, &msk, Action::Post, call, false, 100, 3000);
            post2 = p2.id();
            v.option_submit(p2).unwrap();
            let t2 = intent(&v, &tsk, Action::Take, call, true, 60, 300_000);
            take2 = t2.id();
            assert_eq!(v.option_submit(t2).unwrap()["outcome"], "staged");
            sign_acks(&mut v, &[msk, tsk]);
            let st = v.opts.as_ref().unwrap();
            assert_eq!(st.batches.iter().map(|r| (r.n, r.phase.as_str())).collect::<Vec<_>>(), vec![(1, "aborted"), (2, "committed")]);
            n1 = st.batches[0].batch.digest();
            n2 = st.batches[1].batch.digest();
            assert_eq!(st.intents[&post2].status, "partially filled");
            let _ = (m, t);
        }
        let mut v = Venue::open(&dir, oracle, "http://127.0.0.1:9".into()).unwrap();
        v.options_enable(Some(usdt)).unwrap();
        let st = v.opts.as_ref().unwrap();
        let got: Vec<(u64, &str, Key)> = st.batches.iter().map(|r| (r.n, r.phase.as_str(), r.batch.digest())).collect();
        assert_eq!(got, vec![(1, "aborted", n1), (2, "committed", n2)]);
        assert!(st.batches[0].acks.iter().any(|a| a.signatures[0] == ZERO_SIG), "aborted batch keeps its unsigned lane");
        assert!(st.batches[1].acks.iter().all(|a| a.signatures[0] != ZERO_SIG));
        let status = |id: &Key| st.intents[id].status.clone();
        assert_eq!((status(&post1), status(&take1), status(&post2), status(&take2)), ("cancelled".into(), "aborted".into(), "partially filled".into(), "filled".into()));
        assert_eq!(st.intents[&take2].batch, Some(2));
        // the account view lists the restored history newest first
        let view = v.options_account(&public(&tsk));
        assert_eq!(view["intents"][0]["id"], h(&take2));
        // a signed transfer cannot be replayed after the restart
        let e = xfer(&mut v, &msk, 150_000, used_nonce).unwrap_err();
        assert!(e.contains("replay"), "{e}");
        xfer(&mut v, &msk, 1, used_nonce + 1).unwrap();
        drop(v);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strike_grid_centres_on_the_mark() {
        let d = PriceDomain::from_bits(NUM_BITS);
        assert_eq!(strike_step(100_000), 1_000);
        assert_eq!(strike_step(91_234), 500);
        assert_eq!(strike_grid(100_400, d), vec![98_000, 99_000, 100_000, 101_000, 102_000]);
        assert_eq!(strike_grid(91_234, d), vec![90_000, 90_500, 91_000, 91_500, 92_000]);
        assert_eq!(strike_grid(150, d), vec![148, 149, 150, 151, 152]);
    }

    #[test]
    fn short_call_worst_case_is_bounded_by_the_domain() {
        let d = PriceDomain::from_bits(NUM_BITS);
        let call = Series { kind: OptionKind::Call, asset: SettleAsset::Btc, strike_usd: 100_000, event_id: "E".into() };
        // 100 USD * 1e8 * (1/100000 - 1/1048575) sats
        let w = short_worst_case(&call, d);
        assert!((90_460..=90_470).contains(&w), "{w}");
        let usdt = SettleAsset::Stable { protocol: StableProtocol::Rgb, id: [7; 32], decimals: 6 };
        let put = Series { kind: OptionKind::Put, asset: usdt, strike_usd: 98_000, event_id: "E".into() };
        // 0.01 BTC cash-secured at 98,000 (down to the 1 USD floor): (98000 - 1) * 0.01 USDT
        assert_eq!(short_worst_case(&put, d), 979_990_000);
    }
}
