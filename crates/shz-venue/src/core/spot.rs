//! BTC/USDT spot on the venue (docs/SHZ_SPOT.md). Off unless the venue starts with `--spot`
//! (which needs `--options` and `--stable-usdt`): the spot market lives on the router's
//! options desk and shares its per-account asset wallet.
//!
//! * One pair, BTC against the venue's demo USDT (RGB, 6 decimals): 1,000-sat lots and a
//!   0.1 USDT tick, so every fill's USDT amount is exact. Prices are USDT base units per BTC.
//! * Orders are signed `SpotIntent` (version 8). Post rests and locks its side (BTC for a
//!   sell, USDT for a buy); Take fills immediately at the makers' prices (IOC); Cancel unlocks.
//! * A take is one spot batch staged by the router and committed through the same V4
//!   acknowledgement round as option batches (owner, peer, monitor of every lane; venue
//!   batch numbers are shared with options). Both legs move in that one commit, or the batch
//!   is fence-aborted `ABORT_AFTER_US` after staging and neither moves.
//! * Settlement is on the venue ledger. USDT is a simulated adapter credit; nothing moves on
//!   chain. The on-chain path is RGB-02 (atomic BTC/RGB swaps over Lightning), not built here.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use shz_dex::routing::{
    Action, Scope,
    options::{OptionBatch, OptionBatchKind, OptionOutcome, SPOT_INTENT_VERSION, SettleAsset, SpotIntent, SpotPair},
    tiered::ZERO_SIG,
};
use shz_dlc::BtcOutPoint;

use super::{Key, ROUTER_ID, Venue, h, now_us, outpoint_json, parse_key, parse_sig};

/// Chart and API instrument id of the spot pair (relay-only in the vendored chart).
pub const SPOT_MARKET: &str = "SHZ-BTCUSDT-SPOT";
pub const LOT_SATS: u64 = 1_000;
/// 0.1 USDT in base units (6 decimals).
pub const TICK: u64 = 100_000;

pub struct SpotIntentRec {
    pub intent: SpotIntent,
    pub status: String,
    pub accepted_us: u64,
    pub reason: Option<String>,
    pub batch: Option<u64>,
    /// Sats filled across committed batches.
    pub filled: u64,
}

pub struct SpotState {
    pub pair: SpotPair,
    pub id: Key,
    pub intents: BTreeMap<Key, SpotIntentRec>,
    /// Minute (ms) -> [open, high, low, close, volume BTC], prices in USDT per BTC.
    pub candles: BTreeMap<u64, [f64; 5]>,
}

fn spot_err(e: impl std::fmt::Display) -> String {
    let s = e.to_string();
    if s.ends_with(": Hold") { "an option or spot batch is still settling: retry in a moment".into() } else { s }
}
fn action_name(a: Action) -> &'static str {
    match a {
        Action::Post => "post",
        Action::Take => "take",
        Action::Cancel => "cancel",
    }
}

/// SpotIntent from its JSON form (docs/SHZ_SPOT.md); scope and router are the venue's, the
/// pair defaults to `pair`.
pub fn spot_intent_from_json(j: &Value, scope: Scope, router: u32, pair: &Key) -> Result<SpotIntent, String> {
    let u = |k: &str| j[k].as_u64().ok_or_else(|| format!("missing {k}"));
    let action = match j["action"].as_str().ok_or("missing action")? {
        "post" => Action::Post,
        "take" => Action::Take,
        "cancel" => Action::Cancel,
        _ => return Err("bad action".into()),
    };
    let buy = match (j["buy"].as_bool(), j["side"].as_str()) {
        (Some(b), _) => b,
        (None, Some("buy")) => true,
        (None, Some("sell")) => false,
        (None, None) if action == Action::Cancel => false,
        _ => return Err("buy (bool) or side (buy|sell) required".into()),
    };
    Ok(SpotIntent {
        version: j["version"].as_u64().unwrap_or(SPOT_INTENT_VERSION as u64) as u32,
        scope,
        router,
        channel: BtcOutPoint { txid: parse_key(j["channel"]["txid"].as_str().ok_or("missing channel")?)?, vout: j["channel"]["vout"].as_u64().ok_or("missing vout")? as u32 },
        owner: parse_key(j["owner"].as_str().ok_or("missing owner")?)?,
        sequence: u("sequence")?,
        expires_us: u("expires_us")?,
        action,
        pair: j["pair"].as_str().map(parse_key).transpose()?.unwrap_or(*pair),
        buy,
        qty_sats: j["qty_sats"].as_u64().unwrap_or(0),
        price: j["price"].as_u64().unwrap_or(0),
        cancel_target: j["cancel_target"].as_str().map(parse_key).transpose()?.unwrap_or([0; 32]),
        signature: j["signature"].as_str().map(parse_sig).transpose()?.unwrap_or(ZERO_SIG),
    })
}

fn add_candle(candles: &mut BTreeMap<u64, [f64; 5]>, ts_us: u64, price: u64, sats: u64) {
    let minute = ts_us / 60_000_000 * 60_000;
    let px = price as f64 / 1e6;
    let c = candles.entry(minute).or_insert([px, px, px, px, 0.0]);
    c[1] = c[1].max(px);
    c[2] = c[2].min(px);
    c[3] = px;
    c[4] += sats as f64 / 1e8;
}

impl Venue {
    fn spot_st(&self) -> Result<&SpotState, String> {
        self.spot.as_ref().ok_or_else(|| "spot is off on this venue".to_string())
    }

    /// Switch spot on (journaled once each: `EnableSpot`, `ListSpotPair`) on top of options
    /// with the demo USDT asset, and rebuild the spot views from the venue log and the
    /// committed spot batches.
    pub fn spot_enable(&mut self) -> Result<Value, String> {
        let quote = self.opts.as_ref().ok_or("spot needs --options")?.usdt.ok_or("spot needs --stable-usdt")?;
        let pair = SpotPair { quote, lot_sats: LOT_SATS, tick: TICK };
        let id = pair.id();
        let a = self.router.enable_spot().map_err(|e| format!("enable spot: {e}"))?;
        let listed = self.router.options().map_err(|e| e.to_string())?.and_then(|d| d.spot()).is_some_and(|s| s.pair(&id).is_some());
        if !listed {
            self.router.list_spot_pair(pair).map_err(|e| format!("list spot pair: {e}"))?;
        }
        if a || !listed {
            self.persist(json!({"kind": "spot_enabled", "pair": h(&id), "lot_sats": LOT_SATS, "tick": TICK, "ts_us": now_us()}));
        }
        let mut st = SpotState { pair, id, intents: BTreeMap::new(), candles: BTreeMap::new() };
        for e in std::mem::take(&mut self.opt_log) {
            if e["kind"] != "opt_spot_intent" {
                continue;
            }
            let (Some(Ok(id)), Ok(intent)) = (e["id"].as_str().map(parse_key), serde_json::from_value::<SpotIntent>(e["intent"].clone())) else { continue };
            st.intents.insert(id, SpotIntentRec { intent, status: e["status"].as_str().unwrap_or("").into(), accepted_us: e["accepted_us"].as_u64().unwrap_or(0),
                                                  reason: e["reason"].as_str().map(str::to_string), batch: e["batch"].as_u64(), filled: e["filled"].as_u64().unwrap_or(0) });
        }
        let resting: std::collections::BTreeSet<Key> = self.router.options().ok().flatten().and_then(|d| d.spot())
            .map(|s| [true, false].iter().flat_map(|b| s.depth(&id, *b)).map(|q| q.0).collect()).unwrap_or_default();
        let mut fixed = vec![];
        for r in self.opts.as_ref().map(|o| o.batches.as_slice()).unwrap_or(&[]) {
            if r.phase == "committed" {
                for f in &r.batch.spot {
                    add_candle(&mut st.candles, r.resolved_us.unwrap_or(r.staged_us), f.price, f.sats);
                }
            }
            // A spot batch resolved while spot was not yet switched back on (restart past the
            // deadline): its intents still read "staged".
            if let OptionBatchKind::Spot { taker } = r.batch.kind
                && r.phase != "staged"
                && st.intents.get(&taker).is_some_and(|x| x.status == "staged")
            {
                fixed.extend(mark_resolved(&mut st, r.n, &r.batch, r.phase == "committed", &resting));
            }
        }
        self.spot = Some(st);
        for id in fixed {
            self.persist_spot_intent(&id);
        }
        Ok(self.spot_summary())
    }

    pub fn spot_summary(&self) -> Value {
        let Some(s) = &self.spot else { return json!({"enabled": false}) };
        json!({"enabled": true, "market": SPOT_MARKET, "pair": h(&s.id), "base": self.asset_json(&SettleAsset::Btc), "quote": self.asset_json(&s.pair.quote),
               "lot_sats": s.pair.lot_sats, "tick": s.pair.tick, "price_unit": "quote base units per BTC", "size_unit": "sats",
               "settlement": "venue ledger; USDT is a simulated adapter credit, nothing moves on chain (on-chain path: RGB-02 atomic BTC/RGB swaps, blocked upstream)"})
    }

    pub fn spot_intent_from_json(&self, j: &Value) -> Result<SpotIntent, String> {
        spot_intent_from_json(j, self.scope, ROUTER_ID, &self.spot_st()?.id)
    }

    pub fn spot_submit(&mut self, i: SpotIntent) -> Result<Value, String> {
        self.spot_st()?;
        self.wallet_check(&i.owner)?;
        let id = i.id();
        let now = now_us().max(self.router.options().ok().flatten().map(|d| d.clock()).unwrap_or(0));
        let out = self.router.submit_spot(i.clone(), now).map_err(spot_err)?;
        let (status, outcome, batch_n, cancelled) = match out {
            OptionOutcome::Posted(_) => ("resting", "posted", None, None),
            OptionOutcome::Cancelled(t) => ("done", "cancelled", None, Some(t)),
            OptionOutcome::Staged(b) => {
                let fills = b.spot.len();
                let n = self.on_option_staged(*b, now)?;
                self.emit(json!({"type": "spot_batch", "phase": "staged", "n": n, "fills": fills}));
                ("staged", "staged", Some(n), None)
            }
            OptionOutcome::Filled(_) => return Err("spot batch committed without the acknowledgement round".into()),
        };
        let s = self.spot.as_mut().unwrap();
        s.intents.insert(id, SpotIntentRec { intent: i, status: status.into(), accepted_us: now, reason: None, batch: batch_n, filled: 0 });
        if let Some(r) = cancelled.and_then(|t| s.intents.get_mut(&t)) {
            r.status = "cancelled".into();
        }
        self.persist_spot_intent(&id);
        if let Some(t) = cancelled {
            self.persist_spot_intent(&t);
        }
        self.emit(json!({"type": "spot_book"}));
        self.emit(json!({"type": "account"}));
        Ok(json!({"id": h(&id), "outcome": outcome, "batch": batch_n}))
    }

    fn persist_spot_intent(&mut self, id: &Key) {
        let Some(r) = self.spot.as_ref().and_then(|s| s.intents.get(id)) else { return };
        let e = json!({"kind": "opt_spot_intent", "id": h(id), "intent": serde_json::to_value(&r.intent).unwrap_or(Value::Null), "status": r.status,
                       "reason": r.reason, "batch": r.batch, "accepted_us": r.accepted_us, "filled": r.filled});
        self.persist(e);
    }

    /// A staged spot batch resolved (venue batch `n`): intent statuses, tape, candles, events.
    pub(crate) fn spot_resolved(&mut self, n: u64, batch: &OptionBatch, committed: bool, now: u64) {
        let OptionBatchKind::Spot { taker } = batch.kind else { return };
        let resting: std::collections::BTreeSet<Key> = match self.router.options() {
            Ok(Some(d)) => d.spot().map(|s| [true, false].iter().flat_map(|b| s.depth(&self.spot.as_ref().map_or([0; 32], |x| x.id), *b)).map(|q| q.0).collect()).unwrap_or_default(),
            _ => Default::default(),
        };
        let Some(s) = self.spot.as_mut() else { return };
        let changed = mark_resolved(s, n, batch, committed, &resting);
        if committed {
            for f in &batch.spot {
                add_candle(&mut s.candles, now, f.price, f.sats);
            }
        }
        for id in changed {
            self.persist_spot_intent(&id);
        }
        if committed {
            for f in &batch.spot {
                let t = self.spot_fill_json(n, now, f);
                self.emit(json!({"type": "spot_trade", "trade": t}));
            }
        }
        let _ = taker;
        self.emit(json!({"type": "spot_batch", "phase": if committed { "committed" } else { "aborted" }, "n": n, "fills": batch.spot.len()}));
        self.emit(json!({"type": "spot_book"}));
    }
}

/// Intent statuses after spot batch `n` resolved; returns the intents that changed.
fn mark_resolved(s: &mut SpotState, n: u64, batch: &OptionBatch, committed: bool, resting: &std::collections::BTreeSet<Key>) -> Vec<Key> {
    let OptionBatchKind::Spot { taker } = batch.kind else { return vec![] };
    {
        let mut changed = vec![taker];
        if let Some(r) = s.intents.get_mut(&taker) {
            r.batch = Some(n);
            if committed {
                r.filled = batch.spot.iter().map(|f| f.sats).sum();
                r.status = if r.filled == r.intent.qty_sats { "filled".into() } else { "partially filled".into() };
                if r.filled < r.intent.qty_sats {
                    r.reason = Some(format!("immediate-or-cancel: {} of {} sats filled, the rest dropped", r.filled, r.intent.qty_sats));
                }
            } else {
                r.status = "aborted".into();
                r.reason = Some("its spot batch was fence-aborted: neither leg moved".into());
            }
        }
        for f in &batch.spot {
            let Some(r) = s.intents.get_mut(&f.maker) else { continue };
            if committed {
                r.filled += f.sats;
                r.status = if resting.contains(&f.maker) { "partially filled".into() } else { "filled".into() };
            } else {
                r.status = "cancelled".into();
                r.reason = Some("pulled: its fill was in an aborted spot batch; its lock returned to free".into());
            }
            r.batch = Some(n);
            changed.push(f.maker);
        }
        changed.dedup();
        changed
    }
}

impl Venue {
    fn spot_fill_json(&self, n: u64, ts_us: u64, f: &shz_dex::routing::options::SpotFill) -> Value {
        let side = |c: &BtcOutPoint| json!({"channel": outpoint_json(c), "owner": self.accounts.values().find(|a| a.outpoint == *c).map(|a| h(&a.owner))});
        json!({"batch": n, "ts_us": ts_us, "price": f.price, "price_usdt": f.price as f64 / 1e6, "sats": f.sats, "quote_units": f.quote_units,
               "taker_side": if f.taker_buys { "buy" } else { "sell" }, "maker": h(&f.maker), "taker": h(&f.taker), "seller": side(&f.seller), "buyer": side(&f.buyer)})
    }

    // ------------------------------------------------------------- views ----

    pub fn spot_book(&self, depth: usize) -> Result<Value, String> {
        let s = self.spot_st()?;
        let desk = self.router.options().map_err(|e| e.to_string())?.and_then(|d| d.spot()).ok_or("spot desk missing")?;
        let agg = |buy: bool| {
            let mut m: Vec<(u64, u64, u32)> = vec![];
            for (_, p, q, _) in desk.depth(&s.id, buy) {
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
        let last = self.spot_trades(1);
        Ok(json!({"pair": self.spot_summary(), "bids": agg(true), "asks": agg(false), "last": last.first().cloned(), "mark_usd": self.mark_usd(),
                  "staged": self.opts.as_ref().and_then(|o| o.staged_n())}))
    }

    /// Committed spot fills, newest first.
    pub fn spot_trades(&self, limit: usize) -> Vec<Value> {
        let Some(o) = &self.opts else { return vec![] };
        o.batches.iter().rev().filter(|r| r.phase == "committed" && matches!(r.batch.kind, OptionBatchKind::Spot { .. }))
            .flat_map(|r| r.batch.spot.iter().rev().map(move |f| (r, f)))
            .take(limit)
            .map(|(r, f)| self.spot_fill_json(r.n, r.resolved_us.unwrap_or(r.staged_us), f))
            .collect()
    }

    /// The account's spot view: wallet per asset (free, spot-locked, option-locked), open
    /// orders, fills, intents and the spot acknowledgements still waiting for its key.
    pub fn spot_account(&self, owner: &Key) -> Value {
        let (Some(s), Some(a), Some(o)) = (&self.spot, self.accounts.get(owner), &self.opts) else { return json!(null) };
        let Ok(Some(desk)) = self.router.options() else { return json!(null) };
        let Some(sd) = desk.spot() else { return json!(null) };
        let k = (a.outpoint.txid, a.outpoint.vout);
        let balances: Vec<Value> = [SettleAsset::Btc, s.pair.quote].iter().map(|x| {
            let b = desk.account(&k).map(|ac| ac.balance(x)).unwrap_or_default();
            json!({"asset": self.asset_code(x), "descriptor": self.asset_json(x), "free": b.free, "spot_locked": sd.locked(&k, x), "option_locked": b.locked})
        }).collect();
        let mut open = vec![];
        for buy in [true, false] {
            for (id, p, q, c) in sd.depth(&s.id, buy) {
                if c == a.outpoint {
                    open.push(json!({"id": h(&id), "side": if buy { "buy" } else { "sell" }, "price": p, "remaining_sats": q,
                                     "qty_sats": s.intents.get(&id).map(|r| r.intent.qty_sats)}));
                }
            }
        }
        let fills: Vec<Value> = o.batches.iter().rev()
            .filter(|r| matches!(r.batch.kind, OptionBatchKind::Spot { .. }))
            .flat_map(|r| r.batch.spot.iter().filter(|f| f.seller == a.outpoint || f.buyer == a.outpoint).map(move |f| (r, f)))
            .take(200)
            .map(|(r, f)| json!({"batch": r.n, "phase": r.phase, "side": if f.buyer == a.outpoint { "buy" } else { "sell" }, "price": f.price, "sats": f.sats,
                                 "quote_units": f.quote_units, "role": if (f.buyer == a.outpoint) == f.taker_buys { "taker" } else { "maker" }, "ts_us": r.resolved_us}))
            .collect();
        let mut mine: Vec<(&Key, &SpotIntentRec)> = s.intents.iter().filter(|(_, r)| r.intent.owner == *owner).collect();
        mine.sort_by_key(|(_, r)| std::cmp::Reverse(r.accepted_us));
        let intents: Vec<Value> = mine.into_iter().take(50).map(|(id, r)| json!({"id": h(id), "status": r.status, "reason": r.reason, "batch": r.batch,
            "action": action_name(r.intent.action), "side": if r.intent.buy { "buy" } else { "sell" }, "qty_sats": r.intent.qty_sats, "price": r.intent.price,
            "filled_sats": r.filled, "accepted_us": r.accepted_us})).collect();
        let pending: Vec<Value> = self.pending.values().filter(|p| p.owner == *owner && p.kind == "option_ack" && p.context["batch_kind"] == "spot")
            .map(|p| json!({"id": p.id, "kind": p.kind, "message": h(&p.message), "context": p.context})).collect();
        json!({"pair": h(&s.id), "balances": balances, "open_orders": open, "fills": fills, "intents": intents, "pending_signatures": pending,
               "last_sequence": desk.account(&k).map(|x| x.last_sequence).unwrap_or(0)})
    }
}

#[cfg(test)]
mod tests {
    use super::super::options::transfer_digest;
    use super::super::sig_hex;
    use super::*;
    use shz_dex::routing::{public, tiered_durable::ABORT_AFTER_US};
    use shz_dlc::{bip340_sign, bip340_verify};

    /// Shared with ui/venue/test/spot.test.mjs: the JS encoder and signer give the same ids.
    #[test]
    fn shared_spot_intent_vector() {
        let v: Value = serde_json::from_str(include_str!("../../../../ui/venue/test/spot_vector.json")).unwrap();
        let sc = &v["scope"];
        let scope = Scope { network: parse_key(sc["network"].as_str().unwrap()).unwrap(), epoch: sc["epoch"].as_u64().unwrap(), policy: parse_key(sc["policy"].as_str().unwrap()).unwrap() };
        let router = v["router"].as_u64().unwrap() as u32;
        for c in v["intents"].as_array().unwrap() {
            let i = spot_intent_from_json(&c["intent"], scope, router, &[0; 32]).unwrap();
            assert_eq!(h(&i.id()), c["id"].as_str().unwrap(), "{}", c["name"]);
            bip340_verify(&i.owner, &i.id(), &i.signature).unwrap();
        }
    }

    /// The venue round end to end: a maker's resting sell, a take staged as a spot batch whose
    /// owner acknowledgements arrive as pending signatures, commit moving both legs, an unsigned
    /// take fence-aborted at the deadline with the maker unlocked and the taker untouched, and a
    /// restart that restores intents, batches, the tape and the candles.
    #[test]
    fn spot_round_commit_abort_and_restart() {
        let dir = std::env::temp_dir().join(format!("shz-venue-spot-{}", now_us()));
        let oracle = public(&[9; 32]);
        let usdt = [0xab; 32];
        let (msk, tsk) = ([3u8; 32], [4u8; 32]);
        let asset = json!({"kind": "stable", "protocol": "rgb", "id": h(&usdt), "decimals": 6});
        let mut exp = now_us() + 300_000_000;
        let mut xfer = |v: &mut Venue, sk: &Key, op: &str, amount: u64| {
            exp += 1;
            let owner = public(sk);
            let a = if op == "fund" { SettleAsset::Btc } else { super::super::options::asset_from_json(&asset).unwrap() };
            let d = transfer_digest(super::super::options::transfer_op(op).unwrap(), &owner, &a, amount, exp);
            v.option_transfer(op, &json!({"owner": h(&owner), "amount": amount, "expires_us": exp, "asset": asset, "signature": sig_hex(&bip340_sign(sk, &d).unwrap())})).unwrap();
        };
        let mut seq = 5_000u64;
        let mut intent = |v: &Venue, sk: &Key, action: Action, buy: bool, qty: u64, price: u64, target: Key| {
            seq += 1;
            let s = v.spot.as_ref().unwrap();
            SpotIntent { version: SPOT_INTENT_VERSION, scope: v.scope, router: ROUTER_ID, channel: v.accounts[&public(sk)].outpoint.clone(), owner: [0; 32], sequence: seq,
                         expires_us: now_us() + 600_000_000, action, pair: s.id, buy, qty_sats: qty, price, cancel_target: target, signature: ZERO_SIG }.signed(sk).unwrap()
        };
        let sign = |v: &mut Venue, sk: &Key| {
            let owner = public(sk);
            let items: Vec<(String, shz_dlc::Bip340Signature)> = v.pending.values().filter(|p| p.owner == owner && p.kind == "option_ack")
                .map(|p| (p.id.clone(), bip340_sign(sk, &p.message).unwrap())).collect();
            v.add_signatures(owner, &items).unwrap();
        };
        let wallet = |v: &Venue, sk: &Key| -> Vec<(u64, u64)> {
            let a = v.spot_account(&public(sk));
            a["balances"].as_array().unwrap().iter().map(|b| (b["free"].as_u64().unwrap(), b["spot_locked"].as_u64().unwrap())).collect()
        };
        let (ask, take1, take2, tape);
        {
            let mut v = Venue::open(&dir, oracle, "http://127.0.0.1:9".into()).unwrap();
            assert!(v.spot_enable().is_err(), "spot needs options with USDT");
            v.options_enable(Some(usdt)).unwrap();
            assert_eq!(v.spot_summary()["enabled"], false);
            v.spot_enable().unwrap();
            for sk in [&msk, &tsk] {
                let owner = public(sk);
                let d = v.register_draft(owner, "demo", None, None).unwrap();
                let dig = parse_key(d["allocation_digest"].as_str().unwrap()).unwrap();
                v.register(d["draft_id"].as_str().unwrap(), bip340_sign(sk, &dig).unwrap()).unwrap();
            }
            xfer(&mut v, &msk, "fund", 150_000);
            xfer(&mut v, &tsk, "deposit", 500_000_000);
            // maker: sell 0.001 BTC at 90,000 USDT
            let p = intent(&v, &msk, Action::Post, false, 100_000, 90_000_000_000, [0; 32]);
            ask = p.id();
            assert_eq!(v.spot_submit(p).unwrap()["outcome"], "posted");
            assert_eq!(wallet(&v, &msk), vec![(50_000, 100_000), (0, 0)]);
            assert_eq!(v.spot_book(10).unwrap()["asks"], json!([[90_000_000_000u64, 100_000, 1]]));
            // a post-only bid that crosses is refused
            assert!(v.spot_submit(intent(&v, &tsk, Action::Post, true, 1_000, 90_000_000_000, [0; 32])).is_err());
            // take 0.0004 BTC: staged, one pending owner ack per lane
            let t = intent(&v, &tsk, Action::Take, true, 40_000, 90_000_000_000, [0; 32]);
            take1 = t.id();
            assert_eq!(v.spot_submit(t).unwrap()["outcome"], "staged");
            let pend = v.spot_account(&public(&tsk))["pending_signatures"].as_array().unwrap().len();
            assert_eq!(pend, 1);
            assert_eq!(wallet(&v, &tsk), vec![(0, 0), (500_000_000, 0)], "nothing moves while staged");
            sign(&mut v, &msk);
            assert_eq!(v.opts.as_ref().unwrap().batches[0].phase, "staged");
            sign(&mut v, &tsk);
            assert_eq!(v.opts.as_ref().unwrap().batches[0].phase, "committed");
            assert_eq!(wallet(&v, &tsk), vec![(40_000, 0), (464_000_000, 0)]);
            assert_eq!(wallet(&v, &msk), vec![(50_000, 60_000), (36_000_000, 0)]);
            assert_eq!(v.spot.as_ref().unwrap().intents[&ask].status, "partially filled");
            assert_eq!(v.spot.as_ref().unwrap().intents[&take1].status, "filled");
            let b = v.option_batch_json(&v.opts.as_ref().unwrap().batches[0]);
            assert_eq!(b["kind"], "spot");
            assert_eq!(b["clearing"].as_array().unwrap().iter().map(|c| c["asset"].as_str().unwrap()).collect::<Vec<_>>(), vec!["BTC", "USDT"]);
            // take 0.0005 BTC (more than rests): the taker never signs, aborted at the deadline
            let t = intent(&v, &tsk, Action::Take, true, 100_000, 90_000_000_000, [0; 32]);
            take2 = t.id();
            v.spot_submit(t).unwrap();
            sign(&mut v, &msk);
            v.options_advance(now_us() + ABORT_AFTER_US + 1).unwrap();
            assert_eq!(v.opts.as_ref().unwrap().batches[1].phase, "aborted");
            assert_eq!(wallet(&v, &tsk), vec![(40_000, 0), (464_000_000, 0)], "taker untouched");
            assert_eq!(wallet(&v, &msk), vec![(110_000, 0), (36_000_000, 0)], "maker's lock back in free");
            assert_eq!(v.spot.as_ref().unwrap().intents[&ask].status, "cancelled");
            assert_eq!(v.spot.as_ref().unwrap().intents[&take2].status, "aborted");
            assert!(v.spot_book(10).unwrap()["asks"].as_array().unwrap().is_empty());
            tape = json!(v.spot_trades(10));
            assert_eq!(tape.as_array().unwrap().len(), 1);
            assert_eq!(tape[0]["quote_units"], 36_000_000);
            assert_eq!(v.spot.as_ref().unwrap().candles.values().next().unwrap()[3], 90_000.0);
        }
        let mut v = Venue::open(&dir, oracle, "http://127.0.0.1:9".into()).unwrap();
        v.options_enable(Some(usdt)).unwrap();
        v.spot_enable().unwrap();
        let s = v.spot.as_ref().unwrap();
        assert_eq!((s.intents[&ask].status.as_str(), s.intents[&take1].status.as_str(), s.intents[&take2].status.as_str()), ("cancelled", "filled", "aborted"));
        assert_eq!(s.candles.len(), 1);
        assert_eq!(json!(v.spot_trades(10)), tape);
        assert_eq!(v.opts.as_ref().unwrap().batches.iter().map(|r| r.phase.as_str()).collect::<Vec<_>>(), vec!["committed", "aborted"]);
        assert_eq!(wallet(&v, &msk), vec![(110_000, 0), (36_000_000, 0)]);
        assert_eq!(v.spot_account(&public(&tsk))["intents"][0]["id"], h(&take2));
        drop(v);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
