//! Delegated agent keys on the venue (docs/SHZ_AGENT_API.md), behind `--agents`.
//!
//! The router holds the authority (grants, revocations, which intents an agent signed, and
//! the rule that an agent signs the owner's acknowledgement only for its own legs). This
//! module adds the numeric limits the owner signed into the grant, checked at intake before
//! anything reaches the router journal: notional per order and per rolling 24 h, open
//! orders, orders per minute, price collar against the mark. Accepted agent orders are
//! recorded as `agent_use` lines in the venue log, so the daily notional survives a restart.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{Value, json};
use shz_dex::routing::{
    Action,
    agents::{AGENT_GRANT_VERSION, AgentGrant, AgentLimits, AgentRevocation, INSTRUMENT_ALL, INSTRUMENT_OPTIONS, INSTRUMENT_PERPS, INSTRUMENT_SPOT, MAX_GRANT_US},
    options::{IntentV7, SettleAsset, SpotIntent},
    tiered::IntentV6,
};
use shz_dlc::{BtcOutPoint, bip340_verify};

use super::{Key, ROUTER_ID, Venue, h, now_us, outpoint_json, parse_key, parse_sig, sig_hex};

pub const DAY_US: u64 = 86_400_000_000;
const MINUTE_US: u64 = 60_000_000;
/// Limits a grant may ask for at most (the venue refuses a larger grant at draft time).
pub const CEILING: AgentLimits = AgentLimits {
    max_order_notional_usd: 100_000,
    max_daily_notional_usd: 1_000_000,
    max_open_orders: 200,
    max_orders_per_minute: 600,
    collar_bps: 2_000,
};

/// A refused agent request: a stable machine code, a message and details.
#[derive(Debug, Clone)]
pub struct AgentError {
    pub code: &'static str,
    pub message: String,
    pub details: Value,
}
impl AgentError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), details: Value::Null }
    }
    pub fn with(mut self, d: Value) -> Self {
        self.details = d;
        self
    }
}
impl From<String> for AgentError {
    fn from(m: String) -> Self {
        AgentError::new("venue.rejected", m)
    }
}
type AR<T> = Result<T, AgentError>;

#[derive(Default)]
pub struct Usage {
    /// (accepted_us, notional_usd) of every order accepted in the last 24 h.
    pub day: VecDeque<(u64, u64)>,
    /// Submissions (orders and cancels) in the last minute.
    pub minute: VecDeque<u64>,
    pub accepted: u64,
    pub refused: u64,
}
impl Usage {
    fn trim(&mut self, now: u64) {
        while self.day.front().is_some_and(|(t, _)| *t + DAY_US <= now) {
            self.day.pop_front();
        }
        while self.minute.front().is_some_and(|t| *t + MINUTE_US <= now) {
            self.minute.pop_front();
        }
    }
}

#[derive(Default)]
pub struct AgentState {
    pub usage: BTreeMap<Key, Usage>,
    pub labels: BTreeMap<Key, String>,
}

pub fn instrument_bit(name: &str) -> Option<u8> {
    match name {
        "perps" | "perp" => Some(INSTRUMENT_PERPS),
        "options" | "option" => Some(INSTRUMENT_OPTIONS),
        "spot" => Some(INSTRUMENT_SPOT),
        _ => None,
    }
}
pub fn instrument_names(bits: u8) -> Vec<&'static str> {
    [(INSTRUMENT_PERPS, "perps"), (INSTRUMENT_OPTIONS, "options"), (INSTRUMENT_SPOT, "spot")].iter().filter(|(b, _)| bits & b != 0).map(|(_, n)| *n).collect()
}

pub fn limits_json(l: &AgentLimits) -> Value {
    json!({"max_order_notional_usd": l.max_order_notional_usd, "max_daily_notional_usd": l.max_daily_notional_usd,
           "max_open_orders": l.max_open_orders, "max_orders_per_minute": l.max_orders_per_minute, "collar_bps": l.collar_bps})
}
fn limits_from_json(j: &Value) -> AR<AgentLimits> {
    let u = |k: &str| j[k].as_u64().ok_or_else(|| AgentError::new("request.invalid", format!("limits.{k} required (integer)")));
    let l = AgentLimits {
        max_order_notional_usd: u("max_order_notional_usd")?,
        max_daily_notional_usd: u("max_daily_notional_usd")?,
        max_open_orders: u("max_open_orders")?.min(u32::MAX as u64) as u32,
        max_orders_per_minute: u("max_orders_per_minute")?.min(u32::MAX as u64) as u32,
        collar_bps: u("collar_bps")?.min(u32::MAX as u64) as u32,
    };
    Ok(l)
}

/// Grant JSON (the wire form the SDKs sign; `id` is `AgentGrant::id`).
pub fn grant_json(g: &AgentGrant) -> Value {
    json!({
        "version": g.version, "scope": {"network": h(&g.scope.network), "epoch": g.scope.epoch, "policy": h(&g.scope.policy)},
        "router": g.router, "channel": outpoint_json(&g.channel), "owner": h(&g.owner), "agent": h(&g.agent),
        "nonce": g.nonce, "issued_us": g.issued_us, "expires_us": g.expires_us,
        "instruments": instrument_names(g.instruments), "may_withdraw": g.may_withdraw, "limits": limits_json(&g.limits),
        "signature": sig_hex(&g.signature),
    })
}
pub fn grant_from_json(j: &Value, scope: shz_dex::routing::Scope) -> AR<AgentGrant> {
    let bad = |m: &str| AgentError::new("request.invalid", m.to_string());
    let s = |k: &str| j[k].as_str().ok_or_else(|| bad(&format!("grant.{k} required")));
    let u = |k: &str| j[k].as_u64().ok_or_else(|| bad(&format!("grant.{k} required")));
    let mut bits = 0u8;
    for n in j["instruments"].as_array().ok_or_else(|| bad("grant.instruments required"))? {
        bits |= instrument_bit(n.as_str().unwrap_or("")).ok_or_else(|| bad("grant.instruments: perps, options, spot"))?;
    }
    Ok(AgentGrant {
        version: u("version")? as u32,
        scope,
        router: u("router")? as u32,
        channel: BtcOutPoint {
            txid: parse_key(j["channel"]["txid"].as_str().ok_or_else(|| bad("grant.channel required"))?).map_err(|e| bad(&e))?,
            vout: j["channel"]["vout"].as_u64().ok_or_else(|| bad("grant.channel.vout required"))? as u32,
        },
        owner: parse_key(s("owner")?).map_err(|e| bad(&e))?,
        agent: parse_key(s("agent")?).map_err(|e| bad(&e))?,
        nonce: u("nonce")?,
        issued_us: u("issued_us")?,
        expires_us: u("expires_us")?,
        instruments: bits,
        may_withdraw: j["may_withdraw"].as_bool().unwrap_or(false),
        limits: limits_from_json(&j["limits"])?,
        signature: parse_sig(j["signature"].as_str().unwrap_or("")).map_err(|e| bad(&e))?,
    })
}
/// One agent order on the wire: which book it goes to, decoded.
pub enum AgentOrder {
    Perp(IntentV6),
    Option(IntentV7),
    Spot(SpotIntent),
}
impl AgentOrder {
    pub fn id(&self) -> Key {
        match self {
            AgentOrder::Perp(i) => i.id(),
            AgentOrder::Option(i) => i.id(),
            AgentOrder::Spot(i) => i.id(),
        }
    }
    fn owner(&self) -> Key {
        match self {
            AgentOrder::Perp(i) => i.owner,
            AgentOrder::Option(i) => i.owner,
            AgentOrder::Spot(i) => i.owner,
        }
    }
    fn action(&self) -> Action {
        match self {
            AgentOrder::Perp(i) => i.action,
            AgentOrder::Option(i) => i.action,
            AgentOrder::Spot(i) => i.action,
        }
    }
    fn signature(&self) -> shz_dlc::Bip340Signature {
        match self {
            AgentOrder::Perp(i) => i.signature,
            AgentOrder::Option(i) => i.signature,
            AgentOrder::Spot(i) => i.signature,
        }
    }
    pub fn instrument(&self) -> u8 {
        match self {
            AgentOrder::Perp(_) => INSTRUMENT_PERPS,
            AgentOrder::Option(_) => INSTRUMENT_OPTIONS,
            AgentOrder::Spot(_) => INSTRUMENT_SPOT,
        }
    }
}

impl Venue {
    fn ag(&self) -> AR<&AgentState> {
        self.agents.as_ref().ok_or_else(|| AgentError::new("agents.off", "agents are off on this venue (start it with --agents)"))
    }

    /// `--agents`: journal `EnableAgents` once and fold in the `agent_*` venue log lines.
    pub fn agents_enable(&mut self) -> Result<Value, String> {
        let journaled = self.router.enable_agents().map_err(|e| format!("enable agents: {e}"))?;
        let mut st = AgentState::default();
        let now = now_us();
        for e in std::mem::take(&mut self.agent_log) {
            let Ok(g) = parse_key(e["grant"].as_str().unwrap_or("")) else { continue };
            match e["kind"].as_str() {
                Some("agent_use") => {
                    let (t, n) = (e["ts_us"].as_u64().unwrap_or(0), e["notional_usd"].as_u64().unwrap_or(0));
                    if t + DAY_US > now {
                        st.usage.entry(g).or_default().day.push_back((t, n));
                    }
                }
                Some("agent_label") => {
                    st.labels.insert(g, e["label"].as_str().unwrap_or("").chars().take(64).collect());
                }
                _ => {}
            }
        }
        let grants = self.router.agents().ok().flatten().map(|b| b.grants().count()).unwrap_or(0);
        self.agents = Some(st);
        Ok(json!({"journaled_enable": journaled, "grants": grants}))
    }

    pub fn agents_summary(&self) -> Value {
        match (&self.agents, self.router.agents().ok().flatten()) {
            (Some(_), Some(b)) => {
                let now = self.agent_clock();
                json!({"enabled": true, "grants": b.grants().count(), "active": b.grants().filter(|(_, s)| s.active_at(now)).count()})
            }
            _ => json!({"enabled": false}),
        }
    }

    /// Router clock (journaled) or wall time, whichever is later: grant expiry is judged on it.
    pub fn agent_clock(&self) -> u64 {
        now_us().max(self.router.router().map(|r| r.clock_us()).unwrap_or(0))
    }

    /// An unsigned grant for the owner to review and sign (`id` is the digest to sign).
    pub fn agent_grant_draft(&self, j: &Value) -> AR<Value> {
        self.ag()?;
        let bad = |m: String| AgentError::new("request.invalid", m);
        let owner = parse_key(j["owner"].as_str().unwrap_or("")).map_err(|e| bad(format!("owner: {e}")))?;
        let agent = parse_key(j["agent"].as_str().unwrap_or("")).map_err(|e| bad(format!("agent: {e}")))?;
        let a = self.accounts.get(&owner).ok_or_else(|| AgentError::new("account.unknown", "no such account"))?;
        let mut bits = 0u8;
        for n in j["instruments"].as_array().ok_or_else(|| bad("instruments required".into()))? {
            bits |= instrument_bit(n.as_str().unwrap_or("")).ok_or_else(|| bad("instruments: perps, options, spot".into()))?;
        }
        if bits & INSTRUMENT_OPTIONS != 0 && self.opts.is_none() {
            return Err(AgentError::new("instrument.off", "options are off on this venue"));
        }
        if bits & INSTRUMENT_SPOT != 0 && self.spot.is_none() {
            return Err(AgentError::new("instrument.off", "spot is off on this venue"));
        }
        let limits = limits_from_json(&j["limits"])?;
        let c = &CEILING;
        if limits.max_order_notional_usd > c.max_order_notional_usd || limits.max_daily_notional_usd > c.max_daily_notional_usd || limits.max_open_orders > c.max_open_orders
            || limits.max_orders_per_minute > c.max_orders_per_minute || limits.collar_bps > c.collar_bps
        {
            return Err(AgentError::new("grant.limits_too_high", "a limit is above the venue ceiling").with(json!({"ceiling": limits_json(c)})));
        }
        let now = self.agent_clock();
        let ttl = j["expires_in_s"].as_u64().unwrap_or(86_400).saturating_mul(1_000_000);
        if ttl == 0 || ttl > MAX_GRANT_US {
            return Err(bad(format!("expires_in_s must be 1..={}", MAX_GRANT_US / 1_000_000)));
        }
        let book = self.router.agents().ok().flatten();
        let nonce = book.map(|b| b.grants_of(&a.outpoint).iter().map(|s| s.grant.nonce).max().unwrap_or(0)).unwrap_or(0) + 1;
        let g = AgentGrant {
            version: AGENT_GRANT_VERSION, scope: self.scope, router: ROUTER_ID, channel: a.outpoint.clone(), owner, agent, nonce, issued_us: now,
            expires_us: now + ttl, instruments: bits & INSTRUMENT_ALL, may_withdraw: false, limits, signature: super::ZERO_SIG,
        };
        let mut gj = grant_json(&g);
        gj.as_object_mut().unwrap().remove("signature");
        Ok(json!({"grant": gj, "id": h(&g.id()), "consent": consent_text(&g), "label": j["label"].as_str().unwrap_or("")}))
    }

    /// Admit an owner-signed grant (router-journaled).
    pub fn agent_grant_create(&mut self, j: &Value) -> AR<Value> {
        self.ag()?;
        let g = grant_from_json(&j["grant"], self.scope)?;
        if !self.accounts.contains_key(&g.owner) {
            return Err(AgentError::new("account.unknown", "no such account"));
        }
        bip340_verify(&g.owner, &g.id(), &g.signature).map_err(|_| AgentError::new("grant.signature", "the owner's signature over the grant id does not verify"))?;
        self.wallet_check(&g.owner)?;
        let now = self.agent_clock();
        let id = self.router.grant_agent(g.clone(), now).map_err(|e| AgentError::new("grant.rejected", format!("{e}")))?;
        let label: String = j["label"].as_str().unwrap_or("").chars().take(64).collect();
        if !label.is_empty() {
            self.persist(json!({"kind": "agent_label", "grant": h(&id), "label": label}));
            self.agents.as_mut().unwrap().labels.insert(id, label);
        }
        self.emit(json!({"type": "agent_grant", "grant": h(&id), "owner": h(&g.owner), "status": "active"}));
        Ok(self.agent_grant_view(&id).unwrap_or(Value::Null))
    }

    /// Owner-signed revocation: the router pulls the agent's resting and queued orders in the
    /// same journal record; the venue's views follow.
    pub fn agent_grant_revoke(&mut self, j: &Value) -> AR<Value> {
        self.ag()?;
        let bad = |m: String| AgentError::new("request.invalid", m);
        let r = &j["revocation"];
        let rev = AgentRevocation {
            version: r["version"].as_u64().unwrap_or(AGENT_GRANT_VERSION as u64) as u32,
            scope: self.scope,
            router: r["router"].as_u64().unwrap_or(ROUTER_ID as u64) as u32,
            grant: parse_key(r["grant"].as_str().unwrap_or("")).map_err(|e| bad(format!("grant: {e}")))?,
            owner: parse_key(r["owner"].as_str().unwrap_or("")).map_err(|e| bad(format!("owner: {e}")))?,
            issued_us: r["issued_us"].as_u64().ok_or_else(|| bad("issued_us required".into()))?,
            signature: parse_sig(r["signature"].as_str().unwrap_or("")).map_err(bad)?,
        };
        bip340_verify(&rev.owner, &rev.id(), &rev.signature).map_err(|_| AgentError::new("grant.signature", "the owner's signature over the revocation id does not verify"))?;
        let now = self.agent_clock();
        let (pulled, dropped) = self.router.revoke_agent(rev.clone(), now).map_err(|e| AgentError::new("grant.rejected", format!("{e}")))?;
        let set: BTreeSet<Key> = pulled.iter().copied().collect();
        // Perpetual mirror: pulled quotes are cancelled, dropped queue entries leave the
        // venue's due-order mirror so it stays aligned with the router's queue.
        for id in &pulled {
            if let Some(rec) = self.intents.get_mut(id).filter(|r| r.status == "resting" || r.status == "queued") {
                rec.status = "cancelled".into();
                rec.remaining = 0;
                rec.reason = Some("grant revoked".into());
            }
        }
        let dset: BTreeSet<Key> = dropped.iter().copied().collect();
        self.pending_queue.retain(|_, id| !dset.contains(id));
        self.pending_cancels.retain(|_, id| !dset.contains(id));
        let mut opt_changed = vec![];
        if let Some(st) = self.opts.as_mut() {
            for (id, r) in st.intents.iter_mut().filter(|(id, r)| set.contains(*id) && (r.status == "resting" || r.status == "partially filled")) {
                r.status = "cancelled".into();
                r.reason = Some("grant revoked".into());
                opt_changed.push(*id);
            }
        }
        let mut spot_changed = vec![];
        if let Some(s) = self.spot.as_mut() {
            for (id, r) in s.intents.iter_mut().filter(|(id, r)| set.contains(*id) && r.status == "resting") {
                r.status = "cancelled".into();
                r.reason = Some("grant revoked".into());
                spot_changed.push(*id);
            }
        }
        for id in opt_changed {
            self.persist_intent(&id);
        }
        for id in spot_changed {
            self.persist_spot_intent(&id);
        }
        self.emit(json!({"type": "agent_grant", "grant": h(&rev.grant), "owner": h(&rev.owner), "status": "revoked"}));
        self.emit(json!({"type": "book"}));
        self.emit(json!({"type": "spot_book"}));
        self.emit(json!({"type": "account"}));
        Ok(json!({"revoked": h(&rev.grant), "revoked_us": now, "orders_pulled": pulled.iter().map(|k| h(k)).collect::<Vec<_>>(), "queued_dropped": dropped.len()}))
    }

    pub fn agent_grant_view(&self, id: &Key) -> Option<Value> {
        let s = self.router.agents().ok().flatten()?.grant(id)?;
        let now = self.agent_clock();
        let usage = self.agents.as_ref().and_then(|a| a.usage.get(id));
        let status = if s.revoked_us.is_some() { "revoked" } else if now >= s.grant.expires_us { "expired" } else { "active" };
        let day = usage.map(|u| u.day.iter().filter(|(t, _)| *t + DAY_US > now).map(|(_, n)| *n).sum::<u64>()).unwrap_or(0);
        let minute = usage.map(|u| u.minute.iter().filter(|t| **t + MINUTE_US > now).count()).unwrap_or(0);
        Some(json!({
            "id": h(id), "status": status, "grant": grant_json(&s.grant), "admitted_us": s.admitted_us, "revoked_us": s.revoked_us,
            "label": self.agents.as_ref().and_then(|a| a.labels.get(id)).cloned().unwrap_or_default(),
            "consent": consent_text(&s.grant),
            "usage": {"day_notional_usd": day, "day_remaining_usd": s.grant.limits.max_daily_notional_usd.saturating_sub(day),
                      "orders_last_minute": minute, "open_orders": self.agent_open_orders(id), "accepted": usage.map_or(0, |u| u.accepted), "refused": usage.map_or(0, |u| u.refused)},
        }))
    }

    pub fn agent_grants_of(&self, owner: Option<&Key>, agent: Option<&Key>) -> AR<Value> {
        self.ag()?;
        let Some(book) = self.router.agents().ok().flatten() else { return Ok(json!([])) };
        let ids: Vec<Key> = book.grants().filter(|(_, s)| owner.is_none_or(|o| s.grant.owner == *o) && agent.is_none_or(|a| s.grant.agent == *a)).map(|(k, _)| *k).collect();
        Ok(json!(ids.iter().filter_map(|k| self.agent_grant_view(k)).collect::<Vec<_>>()))
    }

    /// Orders an agent signed under `grant` that are still open (perpetual queued or resting,
    /// option quote resting, spot order resting).
    pub fn agent_open_orders(&self, grant: &Key) -> usize {
        let Some(book) = self.router.agents().ok().flatten() else { return 0 };
        let mine = |id: &Key| book.signer_of(id) == Some(*grant);
        let perp = self.intents.iter().filter(|(id, r)| (r.status == "resting" || r.status == "queued") && r.intent.action != Action::Cancel && mine(id)).count();
        let opt = self.opts.as_ref().map_or(0, |st| st.intents.iter().filter(|(id, r)| (r.status == "resting" || r.status == "partially filled") && mine(id)).count());
        let spot = self.spot.as_ref().map_or(0, |s| s.intents.iter().filter(|(id, r)| r.status == "resting" && mine(id)).count());
        perp + opt + spot
    }

    /// Orders of `grant` with their status, newest first.
    pub fn agent_orders(&self, grant: &Key, limit: usize) -> AR<Value> {
        self.ag()?;
        let Some(book) = self.router.agents().ok().flatten() else { return Ok(json!([])) };
        let mine = |id: &Key| book.signer_of(id) == Some(*grant);
        let mut out: Vec<(u64, Value)> = vec![];
        for (id, r) in self.intents.iter().filter(|(id, _)| mine(id)) {
            out.push((r.accepted_us, json!({"id": h(id), "instrument": "perp", "status": r.status, "reason": r.reason, "remaining": r.remaining, "intent": super::intent_json(id, r)})));
        }
        if let Some(st) = &self.opts {
            for (id, r) in st.intents.iter().filter(|(id, _)| mine(id)) {
                out.push((r.accepted_us, json!({"id": h(id), "instrument": "option", "status": r.status, "reason": r.reason, "batch": r.batch})));
            }
        }
        if let Some(s) = &self.spot {
            for (id, r) in s.intents.iter().filter(|(id, _)| mine(id)) {
                out.push((r.accepted_us, json!({"id": h(id), "instrument": "spot", "status": r.status, "reason": r.reason, "batch": r.batch, "filled_sats": r.filled})));
            }
        }
        out.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
        Ok(json!(out.into_iter().take(limit).map(|(_, v)| v).collect::<Vec<_>>()))
    }

    /// USD notional of an order at the mark (see `AgentLimits`).
    fn agent_notional(&self, o: &AgentOrder, mark: u64) -> AR<u64> {
        Ok(match o {
            AgentOrder::Perp(i) => i.quantity,
            AgentOrder::Spot(i) => (i.qty_sats as u128 * mark as u128 / 100_000_000) as u64,
            AgentOrder::Option(i) => {
                let desk = self.router.options().ok().flatten().ok_or_else(|| AgentError::new("instrument.off", "options are off"))?;
                let mut n: u128 = 0;
                for l in &i.legs {
                    let (s, _) = desk.series(&l.series).ok_or_else(|| AgentError::new("order.invalid", "unknown series"))?;
                    n += if s.asset == SettleAsset::Btc { l.qty as u128 } else { l.qty as u128 * mark as u128 / 100_000_000 };
                }
                n.min(u64::MAX as u128) as u64
            }
        })
    }

    /// The limit checks for one agent order, then the router (agent path), then usage.
    pub fn agent_submit(&mut self, grant: Key, o: AgentOrder) -> AR<Value> {
        self.ag()?;
        let now = self.agent_clock();
        let r = self.agent_check(&grant, &o, now);
        let st = self.agents.as_mut().unwrap();
        let u = st.usage.entry(grant).or_default();
        u.trim(now);
        let notional = match r {
            Ok(n) => n,
            Err(e) => {
                u.refused += 1;
                return Err(e);
            }
        };
        u.minute.push_back(now);
        let res = match o {
            AgentOrder::Perp(i) => self.submit_with(i, Some(grant)),
            AgentOrder::Option(i) => self.option_submit_with(i, Some(grant)),
            AgentOrder::Spot(i) => self.spot_submit_with(i, Some(grant)),
        };
        let u = self.agents.as_mut().unwrap().usage.entry(grant).or_default();
        match res {
            Ok(v) => {
                u.accepted += 1;
                if notional > 0 {
                    u.day.push_back((now, notional));
                    self.persist(json!({"kind": "agent_use", "grant": h(&grant), "ts_us": now, "notional_usd": notional}));
                }
                Ok(v)
            }
            Err(e) => {
                u.refused += 1;
                Err(AgentError::new("venue.rejected", e))
            }
        }
    }

    fn agent_check(&self, grant: &Key, o: &AgentOrder, now: u64) -> AR<u64> {
        let book = self.router.agents().ok().flatten().ok_or_else(|| AgentError::new("agents.off", "agents are off"))?;
        let s = book.grant(grant).ok_or_else(|| AgentError::new("grant.unknown", "no such grant"))?;
        let g = &s.grant;
        if s.revoked_us.is_some() {
            return Err(AgentError::new("grant.revoked", "the owner revoked this grant").with(json!({"revoked_us": s.revoked_us})));
        }
        if now >= g.expires_us {
            return Err(AgentError::new("grant.expired", "this grant has expired").with(json!({"expires_us": g.expires_us})));
        }
        if !g.allows(o.instrument()) {
            return Err(AgentError::new("grant.instrument", "this grant does not cover the instrument").with(json!({"instruments": instrument_names(g.instruments)})));
        }
        if o.owner() != g.owner {
            return Err(AgentError::new("grant.account", "the intent's owner is not the grant's account owner"));
        }
        let sig = o.signature();
        bip340_verify(&g.agent, &o.id(), &sig).map_err(|_| AgentError::new("order.signature", "the agent's signature over the intent id does not verify (sign with the agent key, owner field = account owner)"))?;
        let l = &g.limits;
        let u = self.agents.as_ref().and_then(|a| a.usage.get(grant));
        let minute = u.map_or(0, |u| u.minute.iter().filter(|t| **t + MINUTE_US > now).count());
        if minute as u64 >= l.max_orders_per_minute as u64 {
            return Err(AgentError::new("limit.rate", "orders-per-minute limit reached").with(json!({"limit": l.max_orders_per_minute, "retry_after_ms": 1_000})));
        }
        if o.action() == Action::Cancel {
            return Ok(0);
        }
        let open = self.agent_open_orders(grant);
        if open as u64 >= l.max_open_orders as u64 {
            return Err(AgentError::new("limit.open_orders", "open-orders limit reached").with(json!({"limit": l.max_open_orders, "open": open})));
        }
        let mark = self.mark_usd().ok_or_else(|| AgentError::new("market.no_mark", "no mark yet: the venue cannot evaluate the grant's limits"))?;
        let collar = |px_usd: u64| -> AR<()> {
            let dev = (px_usd as i128 - mark as i128).unsigned_abs() * 10_000;
            if dev > mark as u128 * l.collar_bps as u128 {
                return Err(AgentError::new("limit.collar", "price is outside the grant's collar around the mark").with(json!({"mark_usd": mark, "price_usd": px_usd, "collar_bps": l.collar_bps})));
            }
            Ok(())
        };
        match o {
            AgentOrder::Perp(i) => collar(i.limit_usd)?,
            AgentOrder::Spot(i) => {
                let dec = self.spot.as_ref().and_then(|s| match s.pair.quote { SettleAsset::Stable { decimals, .. } => Some(decimals), _ => None }).unwrap_or(6);
                collar(i.price / 10u64.pow(dec as u32))?
            }
            AgentOrder::Option(_) => {}
        }
        let n = self.agent_notional(o, mark)?;
        if n > l.max_order_notional_usd {
            return Err(AgentError::new("limit.order_notional", "order notional is above the grant's per-order limit").with(json!({"notional_usd": n, "limit": l.max_order_notional_usd})));
        }
        let day = u.map_or(0, |u| u.day.iter().filter(|(t, _)| *t + DAY_US > now).map(|(_, n)| *n).sum::<u64>());
        if day + n > l.max_daily_notional_usd {
            return Err(AgentError::new("limit.daily_notional", "order would exceed the grant's 24 h notional").with(json!({"day_notional_usd": day, "notional_usd": n, "limit": l.max_daily_notional_usd})));
        }
        Ok(n)
    }

    // --------------------------------------------------- delegated acks ----

    /// Pending owner signatures of `grant`'s account that its agent may sign (the router's rule).
    pub fn agent_pending_acks(&self, grant: &Key) -> AR<Value> {
        self.ag()?;
        let book = self.router.agents().ok().flatten().ok_or_else(|| AgentError::new("agents.off", "agents are off"))?;
        let s = book.grant(grant).ok_or_else(|| AgentError::new("grant.unknown", "no such grant"))?;
        let owner = s.grant.owner;
        let now = self.agent_clock();
        let items: Vec<Value> = self
            .pending
            .values()
            .filter(|p| p.owner == owner && self.agent_may_sign(grant, p, now))
            .map(|p| json!({"id": p.id, "kind": p.kind, "message": h(&p.message), "context": p.context}))
            .collect();
        Ok(json!(items))
    }

    fn agent_may_sign(&self, grant: &Key, p: &super::PendingSig, now: u64) -> bool {
        let c = &p.context["channel"];
        let Ok(txid) = parse_key(c["txid"].as_str().unwrap_or("")) else { return false };
        let ch = BtcOutPoint { txid, vout: c["vout"].as_u64().unwrap_or(0) as u32 };
        match p.kind.as_str() {
            "batch_approval" | "channel_ack" => p.context["batch_seq"].as_u64().is_some_and(|seq| self.router.agent_may_ack(seq, &ch, grant).unwrap_or(false)),
            "option_ack" => self.router.agent_may_ack_option(&ch, grant, now.max(self.router.options().ok().flatten().map(|d| d.clock()).unwrap_or(0))).unwrap_or(false),
            _ => false,
        }
    }

    /// Agent signatures for pending owner signatures of its account (batch approvals, lane acks,
    /// option and spot acks). Each must verify under the agent key and be one the router lets
    /// the agent sign; the batch then resolves through the delegated router events.
    pub fn agent_sign_acks(&mut self, grant: Key, items: &[(String, shz_dlc::Bip340Signature)]) -> AR<Value> {
        self.ag()?;
        let book = self.router.agents().ok().flatten().ok_or_else(|| AgentError::new("agents.off", "agents are off"))?;
        let s = book.grant(&grant).ok_or_else(|| AgentError::new("grant.unknown", "no such grant"))?;
        let (owner, agent) = (s.grant.owner, s.grant.agent);
        let now = self.agent_clock();
        let mut accepted = 0;
        let mut refused = vec![];
        for (id, sig) in items {
            let Some(p) = self.pending.get(id).cloned() else {
                refused.push(json!({"id": id, "code": "ack.unknown", "message": "no such pending signature (already signed, or resolved)"}));
                continue;
            };
            if p.owner != owner || !self.agent_may_sign(&grant, &p, now) {
                refused.push(json!({"id": id, "code": "ack.outside_grant", "message": "this batch has legs on the account the agent did not sign, or the grant is not live"}));
                continue;
            }
            if bip340_verify(&agent, &p.message, sig).is_err() {
                refused.push(json!({"id": id, "code": "ack.signature", "message": "signature does not verify under the agent key"}));
                continue;
            }
            let c = &p.context["channel"];
            let key = (parse_key(c["txid"].as_str().unwrap_or("")).map_err(AgentError::from)?, c["vout"].as_u64().unwrap_or(0) as u32);
            match p.kind.as_str() {
                "option_ack" => {
                    self.option_ack_signed(&p, *sig)?;
                    if let Some(st) = self.opts.as_mut() {
                        let n = p.context["option_batch"].as_u64().unwrap_or(0);
                        if let Some(r) = st.batches.iter_mut().find(|r| r.n == n) {
                            r.delegated.insert(key, grant);
                        }
                    }
                }
                kind => {
                    let seq = p.context["batch_seq"].as_u64().unwrap_or(0);
                    let Some(b) = self.batches.get_mut(&seq) else { continue };
                    if kind == "batch_approval" {
                        b.approvals.insert(key, *sig);
                        b.delegated.insert(key, grant);
                    } else if let Some(a) = b.acks.iter_mut().find(|a| (a.channel.txid, a.channel.vout) == key) {
                        a.signatures[0] = *sig;
                        b.ack_delegated.insert(key, grant);
                    }
                }
            }
            self.pending.remove(id);
            accepted += 1;
        }
        let now = now_us();
        self.advance_settlement(now)?;
        self.options_advance(now)?;
        Ok(json!({"accepted": accepted, "refused": refused}))
    }
}

/// What the owner is agreeing to, in words (shown before signing).
pub fn consent_text(g: &AgentGrant) -> String {
    let l = &g.limits;
    format!(
        "Allow agent key {}… to trade {} on account {}… (testnet) until {} UTC: at most ${} notional per order and ${} per rolling 24 h, {} open orders, {} orders per minute, prices within {:.2}% of the mark. It can sign batch acknowledgements only for its own trades. It cannot withdraw, transfer or move collateral. You can revoke it at any time.",
        &h(&g.agent)[..16],
        instrument_names(g.instruments).join(", "),
        &h(&g.owner)[..16],
        fmt_utc(g.expires_us),
        l.max_order_notional_usd,
        l.max_daily_notional_usd,
        l.max_open_orders,
        l.max_orders_per_minute,
        l.collar_bps as f64 / 100.0
    )
}

fn fmt_utc(us: u64) -> String {
    let secs = us / 1_000_000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", rem / 3_600, rem % 3_600 / 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::PacketRec;
    use shz_dex::{OrderSide, routing::{public, tiered::FeedTier}};
    use shz_dlc::bip340_sign;

    #[test]
    fn utc_format() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00");
        assert_eq!(fmt_utc(1_764_201_600_000_000), "2025-11-27 00:00");
    }

    const OWNER: Key = [3; 32];
    const AGENT: Key = [33; 32];

    /// sdk/vectors/agent_vectors.json: grant and revocation ids and the agent-signed intent ids
    /// (perpetual, two-leg option combo with a stable limit, spot) the Python and TypeScript
    /// SDKs must reproduce, with this signer's signatures for their verifiers.
    /// `SHZ_WRITE_VECTORS=1` rewrites the file; otherwise it must match.
    #[test]
    fn shared_agent_vectors() {
        use shz_dex::routing::{
            Scope,
            options::{AssetLimit, LegOrder, OPTION_INTENT_VERSION, SPOT_INTENT_VERSION, StableProtocol},
        };
        let scope = Scope { network: [0x11; 32], epoch: 7, policy: [0x22; 32] };
        let (owner, agent) = (public(&OWNER), public(&AGENT));
        let channel = BtcOutPoint { txid: [0x44; 32], vout: 1 };
        let (tariff_version, policy, pair) = (1u32, [0x55u8; 32], [0x66u8; 32]);
        let tpl = json!({"scope": {"network": h(&scope.network), "epoch": scope.epoch, "policy": h(&scope.policy)}, "router": ROUTER_ID,
                         "tariff_version": tariff_version, "execution_policy": h(&policy), "spot_pair": h(&pair)});
        let g = AgentGrant {
            version: AGENT_GRANT_VERSION, scope, router: ROUTER_ID, channel: channel.clone(), owner: [0; 32], agent, nonce: 3, issued_us: 1_764_201_600_000_000,
            expires_us: 1_764_288_000_000_000, instruments: INSTRUMENT_PERPS | INSTRUMENT_SPOT, may_withdraw: false,
            limits: AgentLimits { max_order_notional_usd: 250, max_daily_notional_usd: 5_000, max_open_orders: 8, max_orders_per_minute: 30, collar_bps: 150 },
            signature: super::super::ZERO_SIG,
        }
        .signed(&OWNER)
        .unwrap();
        let r = AgentRevocation { version: AGENT_GRANT_VERSION, scope, router: ROUTER_ID, grant: g.id(), owner: [0; 32], issued_us: 1_764_210_000_123_456, signature: super::super::ZERO_SIG }
            .signed(&OWNER)
            .unwrap();
        let mut perp = IntentV6 {
            scope, router: ROUTER_ID, channel: channel.clone(), owner, sequence: 42, expires_us: 1_764_201_660_000_000, action: Action::Post, side: OrderSide::Short,
            tier: FeedTier::Standard, tariff_version, entitlement_digest: [0; 32], execution_policy: policy, quantity: 150, limit_usd: 91_250, leverage_bps: 50_000,
            max_fee_ppm: 20, max_fee_sats: 1_000, max_mark_age_us: 20_000_000, early_window_opt_in: false, cancel_target: [0; 32], signature: super::super::ZERO_SIG,
        };
        perp.signature = bip340_sign(&AGENT, &perp.id()).unwrap();
        let usdt = SettleAsset::Stable { protocol: StableProtocol::Rgb, id: [0x77; 32], decimals: 6 };
        let mut opt = IntentV7 {
            version: OPTION_INTENT_VERSION, scope, router: ROUTER_ID, channel: channel.clone(), owner, sequence: 43, expires_us: 1_764_201_660_000_000, action: Action::Take,
            legs: vec![LegOrder { series: [0x88; 32], long: true, qty: 100 }, LegOrder { series: [0x99; 32], long: false, qty: 100 }],
            premium_milli: -1_500, other_limits: vec![AssetLimit { asset: usdt, premium_milli: 2_000_000 }], cancel_target: [0; 32], signature: super::super::ZERO_SIG,
        };
        opt.signature = bip340_sign(&AGENT, &opt.id()).unwrap();
        let mut spot = SpotIntent {
            version: SPOT_INTENT_VERSION, scope, router: ROUTER_ID, channel: channel.clone(), owner, sequence: 44, expires_us: 1_764_201_660_000_000, action: Action::Post,
            pair, buy: true, qty_sats: 25_000, price: 90_100_000_000, cancel_target: [0; 32], signature: super::super::ZERO_SIG,
        };
        spot.signature = bip340_sign(&AGENT, &spot.id()).unwrap();
        let ch = outpoint_json(&channel);
        let v = json!({
            "description": "Shared agent vectors (crates/shz-venue/src/core/agents.rs shared_agent_vectors). Ids are exact; signatures are the Rust signer's (deterministic nonce, not BIP340 aux) and must verify.",
            "keys": {"owner_sk": h(&OWNER), "owner_pk": h(&owner), "agent_sk": h(&AGENT), "agent_pk": h(&agent)},
            "template": tpl,
            "grant": {"wire": grant_json(&g), "id": h(&g.id())},
            "revocation": {"wire": {"version": r.version, "router": r.router, "grant": h(&r.grant), "owner": h(&r.owner), "issued_us": r.issued_us, "signature": sig_hex(&r.signature)}, "id": h(&r.id())},
            "perp": {"intent": {"channel": ch, "owner": h(&owner), "sequence": 42, "expires_us": perp.expires_us, "action": "post", "side": "short", "tier": "standard",
                                "quantity": 150, "limit_usd": 91_250, "leverage_bps": 50_000, "max_fee_ppm": 20, "max_fee_sats": 1_000, "max_mark_age_us": 20_000_000,
                                "early_window_opt_in": false, "cancel_target": h(&[0; 32]), "signature": sig_hex(&perp.signature)}, "id": h(&perp.id())},
            "option": {"intent": {"version": 7, "channel": ch, "owner": h(&owner), "sequence": 43, "expires_us": opt.expires_us, "action": "take",
                                  "legs": [{"series": h(&[0x88; 32]), "long": true, "qty": 100}, {"series": h(&[0x99; 32]), "long": false, "qty": 100}],
                                  "premium_milli": -1_500, "other_limits": [{"asset": {"kind": "stable", "protocol": "rgb", "id": h(&[0x77; 32]), "decimals": 6}, "premium_milli": 2_000_000}],
                                  "cancel_target": h(&[0; 32]), "signature": sig_hex(&opt.signature)}, "id": h(&opt.id())},
            "spot": {"intent": {"version": 8, "channel": ch, "owner": h(&owner), "sequence": 44, "expires_us": spot.expires_us, "action": "post", "pair": h(&pair), "buy": true,
                                "qty_sats": 25_000, "price": 90_100_000_000u64, "cancel_target": h(&[0; 32]), "signature": sig_hex(&spot.signature)}, "id": h(&spot.id())},
        });
        // The wire forms decode back to the same structures (venue decoders).
        assert_eq!(grant_from_json(&v["grant"]["wire"], scope).unwrap(), g);
        assert_eq!(super::super::options::intent_v7_from_json(&v["option"]["intent"], scope, ROUTER_ID).unwrap(), opt);
        assert_eq!(super::super::spot::spot_intent_from_json(&v["spot"]["intent"], scope, ROUTER_ID, &pair).unwrap(), spot);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/vectors/agent_vectors.json");
        let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
        if std::env::var("SHZ_WRITE_VECTORS").is_ok() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &text).unwrap();
        }
        let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("sdk/vectors/agent_vectors.json (SHZ_WRITE_VECTORS=1 writes it)")).unwrap();
        assert_eq!(on_disk, v, "sdk/vectors/agent_vectors.json is stale");
    }

    fn mark(v: &mut Venue, seq: u64, usd: u64) {
        let now = now_us();
        v.ingest_packet(PacketRec { seq, slot_us: now - 2_000_000, status: "VALID".into(), median_e8: Some(usd * 100_000_000), digest: [seq as u8; 32], signers: json!([]), verified: true, received_us: now }).unwrap();
    }
    fn register(v: &mut Venue, sk: &Key) -> Key {
        let owner = public(sk);
        let d = v.register_draft(owner, "demo", None, None).unwrap();
        let dig = parse_key(d["allocation_digest"].as_str().unwrap()).unwrap();
        v.register(d["draft_id"].as_str().unwrap(), bip340_sign(sk, &dig).unwrap()).unwrap();
        owner
    }
    fn grant(v: &mut Venue, limits: Value, ttl_s: u64) -> AR<Key> {
        let d = v.agent_grant_draft(&json!({"owner": h(&public(&OWNER)), "agent": h(&public(&AGENT)), "instruments": ["perps"], "limits": limits, "expires_in_s": ttl_s, "label": "test bot"}))?;
        let id = parse_key(d["id"].as_str().unwrap()).unwrap();
        let mut g = d["grant"].clone();
        g["signature"] = json!(sig_hex(&bip340_sign(&OWNER, &id).unwrap()));
        let out = v.agent_grant_create(&json!({"grant": g, "label": "test bot"}))?;
        assert_eq!(out["id"], h(&id));
        Ok(id)
    }
    fn revoke(v: &mut Venue, g: &Key) -> AR<Value> {
        let r = AgentRevocation { version: AGENT_GRANT_VERSION, scope: v.scope, router: ROUTER_ID, grant: *g, owner: [0; 32], issued_us: now_us(), signature: super::super::ZERO_SIG }.signed(&OWNER).unwrap();
        v.agent_grant_revoke(&json!({"revocation": {"version": r.version, "router": r.router, "grant": h(&r.grant), "owner": h(&r.owner), "issued_us": r.issued_us, "signature": sig_hex(&r.signature)}}))
    }
    struct Seq(u64);
    impl Seq {
        #[allow(clippy::too_many_arguments)]
        fn perp(&mut self, v: &Venue, signer: &Key, action: Action, side: OrderSide, qty: u64, px: u64, cancel: Key) -> IntentV6 {
            self.0 += 1;
            let owner = public(&OWNER);
            let c = action == Action::Cancel;
            let mut i = IntentV6 {
                scope: v.scope, router: ROUTER_ID, channel: v.accounts[&owner].outpoint.clone(), owner, sequence: self.0, expires_us: now_us() + 600_000_000,
                action, side, tier: FeedTier::Standard, tariff_version: v.cfg.tariff.version, entitlement_digest: [0; 32], execution_policy: v.router_policy_id(),
                quantity: qty, limit_usd: px, leverage_bps: if c { 0 } else { 100_000 }, max_fee_ppm: if c { 0 } else { v.cfg.tariff.rate_ppm(FeedTier::Standard, action) },
                max_fee_sats: if c { 0 } else { 100_000 }, max_mark_age_us: if c { 0 } else { 30_000_000 }, early_window_opt_in: false, cancel_target: cancel, signature: super::super::ZERO_SIG,
            };
            i.signature = bip340_sign(signer, &i.id()).unwrap();
            i
        }
    }
    fn code(r: AR<Value>) -> &'static str {
        match r {
            Err(e) => e.code,
            Ok(v) => panic!("accepted: {v}"),
        }
    }

    /// Every numeric limit, signature, replay, revocation, expiry and restart, at the venue.
    #[test]
    fn venue_enforces_every_grant_limit() {
        let dir = std::env::temp_dir().join(format!("shz-venue-agents-{}", now_us()));
        let limits = json!({"max_order_notional_usd": 100, "max_daily_notional_usd": 250, "max_open_orders": 3, "max_orders_per_minute": 6, "collar_bps": 300});
        let g;
        {
            let mut v = Venue::open(&dir, [7; 32], "http://127.0.0.1:9".into()).unwrap();
            // Off until enabled: no journal record is written.
            let tip = v.router.tip().unwrap();
            assert_eq!(v.agent_grant_draft(&json!({})).unwrap_err().code, "agents.off");
            assert_eq!(v.router.tip().unwrap(), tip);
            assert_eq!(v.agents_enable().unwrap()["journaled_enable"], true);
            register(&mut v, &OWNER);
            // Above the venue ceiling; withdraw is never grantable (a draft always says false).
            let huge = json!({"max_order_notional_usd": 10_000_000, "max_daily_notional_usd": 10_000_000, "max_open_orders": 1, "max_orders_per_minute": 1, "collar_bps": 1});
            assert_eq!(grant(&mut v, huge, 60).unwrap_err().code, "grant.limits_too_high");
            g = grant(&mut v, limits.clone(), 3_600).unwrap();
            let view = v.agent_grant_view(&g).unwrap();
            assert_eq!((view["status"].as_str(), view["grant"]["may_withdraw"].as_bool()), (Some("active"), Some(false)));
            assert!(view["consent"].as_str().unwrap().contains("cannot withdraw"));
            let mut s = Seq(0);
            let o = AgentOrder::Perp;
            // No mark yet: limits cannot be evaluated.
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 100, 90_000, [0; 32])))), "market.no_mark");
            mark(&mut v, 1, 90_000);
            // Owner signature on the agent path; an unknown grant id.
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &OWNER, Action::Post, OrderSide::Long, 100, 90_000, [0; 32])))), "order.signature");
            assert_eq!(code(v.agent_submit([9; 32], o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 100, 90_000, [0; 32])))), "grant.unknown");
            // Per-order notional and the collar (3 % of 90,000 = 2,700).
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 101, 90_000, [0; 32])))), "limit.order_notional");
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 100, 86_000, [0; 32])))), "limit.collar");
            // Two orders of 100 rest; 60 more would pass 250 in 24 h; 50 fits.
            let a = s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 100, 89_000, [0; 32]);
            let (a_id, replay) = (a.id(), a.clone());
            v.agent_submit(g, o(a)).unwrap();
            v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 100, 88_900, [0; 32]))).unwrap();
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 60, 88_800, [0; 32])))), "limit.daily_notional");
            v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 50, 88_800, [0; 32]))).unwrap();
            v.tick().unwrap();
            // Open orders: three rest.
            assert_eq!(v.agent_open_orders(&g), 3);
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 1, 88_800, [0; 32])))), "limit.open_orders");
            // The agent cancels its own order (a cancel never counts as notional).
            let cx = s.perp(&v, &AGENT, Action::Cancel, OrderSide::Long, 0, 0, a_id);
            let cx_again = cx.clone();
            v.agent_submit(g, o(cx)).unwrap();
            v.tick().unwrap();
            assert_eq!(v.intents[&a_id].status, "cancelled");
            // Replays of accepted intents: a post would pass the 24 h notional and is refused
            // first; the cancel's old sequence is refused by the router.
            assert_eq!(code(v.agent_submit(g, o(replay))), "limit.daily_notional");
            assert_eq!(code(v.agent_submit(g, o(cx_again))), "venue.rejected");
            // Rate: 3 orders, 1 cancel, the replay attempt and 1 more cancel reach 6 per minute.
            v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Cancel, OrderSide::Long, 0, 0, a_id))).unwrap();
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Cancel, OrderSide::Long, 0, 0, a_id)))), "limit.rate");
            v.tick().unwrap();
            let u = v.agent_grant_view(&g).unwrap();
            assert_eq!(u["usage"]["day_notional_usd"], 250);
            assert_eq!(u["usage"]["open_orders"], 2);
            // Revocation pulls the two resting orders at once.
            let r = revoke(&mut v, &g).unwrap();
            assert!(r["orders_pulled"].as_array().unwrap().len() >= 2, "{r}");
            assert_eq!(v.agent_open_orders(&g), 0);
            assert_eq!(v.router.router().unwrap().resting(), 0);
            assert_eq!(code(v.agent_submit(g, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 1, 89_000, [0; 32])))), "grant.revoked");
            assert_eq!(code(revoke(&mut v, &g)), "grant.rejected");
            // Expiry: a one-second grant.
            let g2 = grant(&mut v, limits.clone(), 1).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1_100));
            assert_eq!(code(v.agent_submit(g2, o(s.perp(&v, &AGENT, Action::Post, OrderSide::Long, 1, 89_000, [0; 32])))), "grant.expired");
            assert_eq!(v.agent_grant_view(&g2).unwrap()["status"], "expired");
        }
        // Restart: the router replays grants and the revocation; the venue log the 24 h usage.
        let mut v = Venue::open(&dir, [7; 32], "http://127.0.0.1:9".into()).unwrap();
        assert_eq!(v.agents_enable().unwrap()["journaled_enable"], false);
        let u = v.agent_grant_view(&g).unwrap();
        assert_eq!((u["status"].as_str(), u["usage"]["day_notional_usd"].as_u64(), u["label"].as_str()), (Some("revoked"), Some(250), Some("test bot")));
        drop(v);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
