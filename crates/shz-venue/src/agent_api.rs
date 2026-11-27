//! Agent API v1 (docs/SHZ_AGENT_API.md; spec docs/agent-api/openapi.json). One method
//! table, served as REST under `/agent/v1/*` and as JSON-RPC 2.0 over WebSocket at
//! `/agent/v1/ws`. Reads are public; every write is authenticated by its own signature
//! (owner-signed grants and revocations, agent-signed intents and acknowledgements), so no
//! API keys or sessions exist. Per-client token-bucket rate limits, idempotency keys on
//! writes, structured errors, and sequenced subscriptions with resync.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{net::TcpStream, sync::broadcast};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use crate::core::{
    MARKET, Venue,
    agents::{AgentError, AgentOrder, CEILING, limits_json},
    h, now_us, packet_json, parse_key, parse_sig, trade_json,
};
use crate::http::App;

pub const API_VERSION: &str = "agent/v1";
pub const SPEC: &str = include_str!("../../../docs/agent-api/openapi.json");
/// Token bucket per client: sustained requests per second and burst.
pub const RATE_PER_S: f64 = 20.0;
pub const BURST: f64 = 60.0;
const IDEM_TTL_US: u64 = 86_400_000_000;
const IDEM_MAX: usize = 20_000;
const RING: usize = 1_000;

/// (JSON-RPC method, REST verb and path, writes state).
pub struct MethodDef {
    pub name: &'static str,
    pub verb: &'static str,
    pub path: &'static str,
    pub write: bool,
}
const fn m(name: &'static str, verb: &'static str, path: &'static str, write: bool) -> MethodDef {
    MethodDef { name, verb, path, write }
}
pub const METHODS: &[MethodDef] = &[
    m("server.info", "GET", "/agent/v1/info", false),
    m("server.time", "GET", "/agent/v1/time", false),
    m("market.list", "GET", "/agent/v1/markets", false),
    m("market.book", "GET", "/agent/v1/book", false),
    m("market.trades", "GET", "/agent/v1/trades", false),
    m("market.mark", "GET", "/agent/v1/mark", false),
    m("options.chain", "GET", "/agent/v1/options/chain", false),
    m("account.get", "GET", "/agent/v1/account", false),
    m("grant.list", "GET", "/agent/v1/grants", false),
    m("grant.get", "GET", "/agent/v1/grant", false),
    m("grant.draft", "POST", "/agent/v1/grants/draft", false),
    m("grant.create", "POST", "/agent/v1/grants", true),
    m("grant.revoke", "POST", "/agent/v1/grants/revoke", true),
    m("order.place", "POST", "/agent/v1/orders", true),
    m("order.cancel", "POST", "/agent/v1/orders/cancel", true),
    m("order.replace", "POST", "/agent/v1/orders/replace", true),
    m("order.list", "GET", "/agent/v1/orders", false),
    m("ack.pending", "GET", "/agent/v1/acks", false),
    m("ack.submit", "POST", "/agent/v1/acks", true),
    m("intent.id", "POST", "/agent/v1/intent-id", false),
];
/// WebSocket-only methods.
pub const WS_METHODS: &[&str] = &["subscribe", "unsubscribe", "resync"];
/// Subscription channels and the venue event types each carries.
pub const CHANNELS: &[(&str, &[&str])] = &[
    ("book", &["book"]),
    ("trades", &["trade", "spot_trade", "option_fill"]),
    ("mark", &["mark"]),
    ("spot.book", &["spot_book"]),
    ("options.book", &["option_book", "options_series"]),
    ("batches", &["batch", "option_batch", "spot_batch", "option_expiry"]),
    ("account", &["account", "risk"]),
    ("grants", &["agent_grant"]),
];
/// Every error code a method can return (the spec's `ErrorCode` enum must equal this).
pub const ERROR_CODES: &[&str] = &[
    "request.invalid", "method.unknown", "rate_limited", "idempotency.mismatch", "agents.off", "instrument.off", "market.no_mark",
    "account.unknown", "grant.unknown", "grant.signature", "grant.rejected", "grant.revoked", "grant.expired", "grant.instrument",
    "grant.account", "grant.limits_too_high", "order.invalid", "order.signature", "limit.rate", "limit.open_orders", "limit.collar",
    "limit.order_notional", "limit.daily_notional", "ack.unknown", "ack.outside_grant", "ack.signature", "venue.rejected", "channel.unknown",
];

pub fn http_status(code: &str) -> u16 {
    match code {
        "request.invalid" | "order.invalid" | "channel.unknown" => 400,
        "order.signature" | "grant.signature" | "ack.signature" => 401,
        "grant.revoked" | "grant.expired" | "grant.instrument" | "grant.account" | "ack.outside_grant" => 403,
        "account.unknown" | "grant.unknown" | "method.unknown" | "ack.unknown" | "agents.off" | "instrument.off" => 404,
        "idempotency.mismatch" | "venue.rejected" | "grant.rejected" => 409,
        "rate_limited" | "limit.rate" => 429,
        "market.no_mark" => 503,
        c if c.starts_with("limit.") || c == "grant.limits_too_high" => 422,
        _ => 400,
    }
}
fn rpc_code(code: &str) -> i64 {
    match code {
        "request.invalid" => -32602,
        "method.unknown" => -32601,
        _ => -32000 - http_status(code) as i64,
    }
}
fn retryable(code: &str) -> bool {
    matches!(code, "rate_limited" | "limit.rate" | "market.no_mark")
}
pub fn error_json(e: &AgentError) -> Value {
    json!({"code": e.code, "message": e.message, "details": e.details, "retryable": retryable(e.code)})
}

// ------------------------------------------------------------- state ----

struct Bucket {
    tokens: f64,
    last: Instant,
}
pub struct RateInfo {
    pub ok: bool,
    pub remaining: u64,
    pub reset_ms: u64,
}
struct IdemEntry {
    at_us: u64,
    digest: [u8; 32],
    out: Result<Value, AgentError>,
}
pub struct Notif {
    pub channel: &'static str,
    pub seq: u64,
    pub data: Value,
}
#[derive(Default)]
struct Ring {
    seq: u64,
    items: VecDeque<Arc<Notif>>,
}

pub struct ApiState {
    buckets: StdMutex<HashMap<String, Bucket>>,
    idem: StdMutex<(HashMap<String, IdemEntry>, VecDeque<String>)>,
    rings: StdMutex<BTreeMap<&'static str, Ring>>,
    pub tx: broadcast::Sender<Arc<Notif>>,
}
impl Default for ApiState {
    fn default() -> Self {
        Self { buckets: Default::default(), idem: Default::default(), rings: Default::default(), tx: broadcast::channel(4_096).0 }
    }
}
impl ApiState {
    pub fn take(&self, key: &str) -> RateInfo {
        let mut m = self.buckets.lock().unwrap();
        if m.len() > 50_000 {
            m.retain(|_, b| b.last.elapsed() < Duration::from_secs(60));
        }
        let b = m.entry(key.to_string()).or_insert(Bucket { tokens: BURST, last: Instant::now() });
        let now = Instant::now();
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * RATE_PER_S).min(BURST);
        b.last = now;
        let ok = b.tokens >= 1.0;
        if ok {
            b.tokens -= 1.0;
        }
        let reset_ms = if b.tokens >= 1.0 { 0 } else { ((1.0 - b.tokens) / RATE_PER_S * 1000.0).ceil() as u64 };
        RateInfo { ok, remaining: b.tokens.floor() as u64, reset_ms }
    }
    fn idem_get(&self, key: &str, digest: &[u8; 32]) -> Option<Result<Value, AgentError>> {
        let m = self.idem.lock().unwrap();
        let e = m.0.get(key)?;
        if e.at_us + IDEM_TTL_US <= now_us() {
            return None;
        }
        if &e.digest != digest {
            return Some(Err(AgentError::new("idempotency.mismatch", "this Idempotency-Key was used with different parameters")));
        }
        Some(e.out.clone())
    }
    fn idem_put(&self, key: String, digest: [u8; 32], out: &Result<Value, AgentError>) {
        let mut m = self.idem.lock().unwrap();
        let now = now_us();
        while m.1.len() >= IDEM_MAX || m.1.front().is_some_and(|k| m.0.get(k).is_none_or(|e| e.at_us + IDEM_TTL_US <= now)) {
            let Some(k) = m.1.pop_front() else { break };
            m.0.remove(&k);
        }
        if m.0.insert(key.clone(), IdemEntry { at_us: now, digest, out: out.clone() }).is_none() {
            m.1.push_back(key);
        }
    }
    /// Classify one venue event, number it on its channel and fan it out.
    pub fn publish(&self, raw: &str) {
        let Ok(data) = serde_json::from_str::<Value>(raw) else { return };
        let ty = data["type"].as_str().unwrap_or("");
        let Some((ch, _)) = CHANNELS.iter().find(|(_, tys)| tys.contains(&ty)) else { return };
        let n = {
            let mut r = self.rings.lock().unwrap();
            let ring = r.entry(ch).or_default();
            ring.seq += 1;
            let n = Arc::new(Notif { channel: ch, seq: ring.seq, data });
            ring.items.push_back(n.clone());
            while ring.items.len() > RING {
                ring.items.pop_front();
            }
            n
        };
        let _ = self.tx.send(n);
    }
    /// The bus fell behind the venue: advance every channel so subscribers see a gap.
    pub fn gap(&self) {
        let mut r = self.rings.lock().unwrap();
        for (ch, _) in CHANNELS {
            r.entry(ch).or_default().seq += 1;
        }
    }
    pub fn seq(&self, ch: &str) -> u64 {
        self.rings.lock().unwrap().get(ch).map_or(0, |r| r.seq)
    }
    /// Events of `ch` after `since`, if the ring still holds every one of them.
    fn since(&self, ch: &str, since: u64) -> Option<Vec<Value>> {
        let r = self.rings.lock().unwrap();
        let ring = r.get(ch)?;
        let items: Vec<&Arc<Notif>> = ring.items.iter().filter(|n| n.seq > since).collect();
        let mut want = since + 1;
        for n in &items {
            if n.seq != want {
                return None;
            }
            want += 1;
        }
        (want == ring.seq + 1).then(|| items.iter().map(|n| json!({"seq": n.seq, "data": n.data})).collect())
    }
}

/// Number every venue event for the agent stream.
pub async fn run_bus(app: Arc<App>) {
    let mut rx = app.events.subscribe();
    loop {
        match rx.recv().await {
            Ok(s) => app.agent.publish(&s),
            Err(broadcast::error::RecvError::Lagged(_)) => app.agent.gap(),
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

// ------------------------------------------------------------ params ----

fn bad(m: impl Into<String>) -> AgentError {
    AgentError::new("request.invalid", m)
}
fn pkey(p: &Value, k: &str) -> Result<[u8; 32], AgentError> {
    parse_key(p[k].as_str().ok_or_else(|| bad(format!("{k} required (32-byte hex)")))?).map_err(|e| bad(format!("{k}: {e}")))
}
fn pkey_opt(p: &Value, k: &str) -> Result<Option<[u8; 32]>, AgentError> {
    p[k].as_str().filter(|s| !s.is_empty()).map(|s| parse_key(s).map_err(|e| bad(format!("{k}: {e}")))).transpose()
}
/// Integer parameter given as a JSON number or a decimal string (REST query).
fn pnum(p: &Value, k: &str, d: u64) -> u64 {
    p[k].as_u64().or_else(|| p[k].as_str().and_then(|s| s.parse().ok())).unwrap_or(d)
}
fn instrument(p: &Value) -> String {
    p["instrument"].as_str().unwrap_or("perp").to_string()
}
fn mark_usd(v: &Venue) -> Option<u64> {
    v.mark.as_ref().and_then(|m| m.median_e8).map(|m| (m + 50_000_000) / 100_000_000)
}
fn decode(v: &Venue, inst: &str, j: &Value) -> Result<AgentOrder, AgentError> {
    let r = match inst {
        "perp" => v.intent_from_json(j).map(AgentOrder::Perp),
        "option" => {
            if v.opts.is_none() {
                return Err(AgentError::new("instrument.off", "options are off on this venue"));
            }
            v.option_intent_from_json(j).map(AgentOrder::Option)
        }
        "spot" => {
            if v.spot.is_none() {
                return Err(AgentError::new("instrument.off", "spot is off on this venue"));
            }
            v.spot_intent_from_json(j).map(AgentOrder::Spot)
        }
        _ => return Err(bad("instrument: perp, option or spot")),
    };
    r.map_err(|e| AgentError::new("order.invalid", e))
}
fn is_cancel(j: &Value) -> bool {
    j["action"] == "cancel"
}
fn opt_view(x: Value, code: &'static str, m: &str) -> Result<Value, AgentError> {
    if x.is_null() { Err(AgentError::new(code, m.to_string())) } else { Ok(x) }
}

// ----------------------------------------------------------- methods ----

/// One API call. Writes are idempotent per `idempotency_key` (REST: `Idempotency-Key`).
pub async fn call(app: &App, method: &str, p: &Value, idem: Option<&str>) -> Result<Value, AgentError> {
    let def = METHODS.iter().find(|d| d.name == method).ok_or_else(|| AgentError::new("method.unknown", format!("unknown method {method}")))?;
    let key = idem.or(p["idempotency_key"].as_str()).filter(|k| !k.is_empty() && k.len() <= 128);
    if let (true, Some(k)) = (def.write, key) {
        let mut q = p.clone();
        if let Some(o) = q.as_object_mut() {
            o.remove("idempotency_key");
        }
        let digest: [u8; 32] = Sha256::digest(q.to_string().as_bytes()).into();
        let scope = p["grant"].as_str().or(p["grant"]["owner"].as_str()).or(p["revocation"]["owner"].as_str()).unwrap_or("");
        let ik = format!("{method}|{scope}|{k}");
        if let Some(out) = app.agent.idem_get(&ik, &digest) {
            return out.map(|mut v| {
                if let Some(o) = v.as_object_mut() {
                    o.insert("idempotent_replay".into(), json!(true));
                }
                v
            });
        }
        let out = run(app, method, p).await;
        app.agent.idem_put(ik, digest, &out);
        return out;
    }
    run(app, method, p).await
}

async fn run(app: &App, method: &str, p: &Value) -> Result<Value, AgentError> {
    match method {
        "server.info" => {
            let v = app.venue.lock().await;
            Ok(json!({
                "api_version": API_VERSION, "network": "testnet4", "production_ready": false, "market": MARKET,
                "agents": v.agents_summary(), "options": v.opts.is_some(), "spot": v.spot.is_some(),
                "rate_limit": {"per_second": RATE_PER_S, "burst": BURST, "scope": "per client address on every /api, /v1, /agent/v1 request and WebSocket upgrade (behind the local proxy: the right-most X-Forwarded-For hop); direct local processes are not limited"},
                "grant_ceiling": limits_json(&CEILING),
                "methods": METHODS.iter().map(|d| json!({"method": d.name, "rest": format!("{} {}", d.verb, d.path), "write": d.write})).collect::<Vec<_>>(),
                "error_codes": ERROR_CODES,
                "ws": {"path": "/agent/v1/ws", "methods": WS_METHODS, "channels": CHANNELS.iter().map(|c| c.0).collect::<Vec<_>>()},
                "demo_assets": ["USDT on this venue is a labelled demo asset (simulated RGB adapter), not a real stablecoin"],
            }))
        }
        "server.time" => {
            let v = app.venue.lock().await;
            Ok(json!({"server_us": now_us(), "router_clock_us": v.agent_clock()}))
        }
        "market.list" => {
            let v = app.venue.lock().await;
            let mut inst = vec![json!({"instrument": "perp", "market": MARKET})];
            if v.opts.is_some() {
                inst.push(json!({"instrument": "option", "chain": "/agent/v1/options/chain"}));
            }
            if v.spot.is_some() {
                inst.push(json!({"instrument": "spot", "market": crate::core::spot::SPOT_MARKET}));
            }
            Ok(json!({"instruments": inst, "perp": v.template(), "options": v.options_summary(), "spot": v.spot_summary()}))
        }
        "market.book" => {
            let depth = pnum(p, "depth", 25).min(200) as usize;
            let v = app.venue.lock().await;
            match instrument(p).as_str() {
                "perp" => Ok(v.book(depth)),
                "spot" => v.spot_book(depth).map_err(|e| AgentError::new("instrument.off", e)),
                s if s.starts_with("option:") => {
                    let k = parse_key(&s[7..]).map_err(|e| bad(format!("series: {e}")))?;
                    v.options_book(&k, depth).map_err(|e| AgentError::new("instrument.off", e))
                }
                _ => Err(bad("instrument: perp, spot or option:<series id>")),
            }
        }
        "market.trades" => {
            let limit = pnum(p, "limit", 100).min(1000) as usize;
            let v = app.venue.lock().await;
            match instrument(p).as_str() {
                "perp" => Ok(json!(v.trades.iter().take(limit).map(trade_json).collect::<Vec<_>>())),
                "spot" if v.spot.is_some() => Ok(json!(v.spot_trades(limit))),
                "option" if v.opts.is_some() => Ok(v.option_batches(limit)),
                "spot" | "option" => Err(AgentError::new("instrument.off", "instrument is off on this venue")),
                _ => Err(bad("instrument: perp, spot or option")),
            }
        }
        "market.mark" => {
            let v = app.venue.lock().await;
            Ok(json!({"mark": v.mark.as_ref().map(packet_json), "mark_usd": mark_usd(&v)}))
        }
        "options.chain" => {
            let v = app.venue.lock().await;
            if v.opts.is_none() {
                return Err(AgentError::new("instrument.off", "options are off on this venue"));
            }
            Ok(v.options_series_view())
        }
        "account.get" => {
            let owner = pkey(p, "owner")?;
            let v = app.venue.lock().await;
            let mut a = opt_view(v.account_view(&owner), "account.unknown", "no such account")?;
            a["risk"] = v.risk_view(&owner);
            if v.agents.is_some() {
                a["grants"] = v.agent_grants_of(Some(&owner), None)?;
            }
            Ok(a)
        }
        "grant.list" => {
            let (o, a) = (pkey_opt(p, "owner")?, pkey_opt(p, "agent")?);
            if o.is_none() && a.is_none() {
                return Err(bad("owner or agent required"));
            }
            app.venue.lock().await.agent_grants_of(o.as_ref(), a.as_ref())
        }
        "grant.get" => {
            let id = pkey(p, "id")?;
            let v = app.venue.lock().await;
            if v.agents.is_none() {
                return Err(AgentError::new("agents.off", "agents are off on this venue (start it with --agents)"));
            }
            v.agent_grant_view(&id).ok_or_else(|| AgentError::new("grant.unknown", "no such grant"))
        }
        "grant.draft" => app.venue.lock().await.agent_grant_draft(p),
        "grant.create" => app.venue.lock().await.agent_grant_create(p),
        "grant.revoke" => app.venue.lock().await.agent_grant_revoke(p),
        "order.place" | "order.cancel" => {
            let grant = pkey(p, "grant")?;
            let mut v = app.venue.lock().await;
            let o = decode(&v, &instrument(p), &p["intent"])?;
            if (method == "order.cancel") != is_cancel(&p["intent"]) {
                return Err(bad(if method == "order.cancel" { "order.cancel takes an intent with action \"cancel\"" } else { "use order.cancel for an intent with action \"cancel\"" }));
            }
            v.agent_submit(grant, o)
        }
        "order.replace" => {
            let grant = pkey(p, "grant")?;
            let inst = instrument(p);
            let mut v = app.venue.lock().await;
            let (c, n) = (decode(&v, &inst, &p["cancel"])?, decode(&v, &inst, &p["place"])?);
            if !is_cancel(&p["cancel"]) || is_cancel(&p["place"]) {
                return Err(bad("replace takes a cancel intent and a post/take intent"));
            }
            let cancelled = v.agent_submit(grant, c)?;
            let placed = v.agent_submit(grant, n).map_err(|e| {
                let d = json!({"cancel": cancelled.clone(), "place_error": error_json(&e)});
                AgentError { details: d, ..e }
            })?;
            Ok(json!({"cancel": cancelled, "place": placed}))
        }
        "order.list" => {
            let grant = pkey(p, "grant")?;
            app.venue.lock().await.agent_orders(&grant, pnum(p, "limit", 100).min(500) as usize)
        }
        "ack.pending" => {
            let grant = pkey(p, "grant")?;
            app.venue.lock().await.agent_pending_acks(&grant)
        }
        "ack.submit" => {
            let grant = pkey(p, "grant")?;
            let items: Vec<(String, shz_dlc::Bip340Signature)> = p["items"]
                .as_array()
                .ok_or_else(|| bad("items required"))?
                .iter()
                .map(|it| Ok((it["id"].as_str().unwrap_or("").to_string(), parse_sig(it["signature"].as_str().unwrap_or("")).map_err(bad)?)))
                .collect::<Result<_, AgentError>>()?;
            app.venue.lock().await.agent_sign_acks(grant, &items)
        }
        "intent.id" => {
            let v = app.venue.lock().await;
            let o = decode(&v, &instrument(p), &p["intent"])?;
            Ok(json!({"id": h(&o.id())}))
        }
        _ => Err(AgentError::new("method.unknown", format!("unknown method {method}"))),
    }
}

fn is_loopback(peer: &str) -> bool {
    peer.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        v4 => v4.is_loopback(),
    })
}

/// `X-Forwarded-For` values of a request head, in order (one per header line).
pub fn forwarded_values(head: &str) -> Vec<String> {
    head.lines()
        .filter_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("x-forwarded-for")).map(|(_, v)| v.trim().to_string()))
        .collect()
}

/// The client a request is charged to, for the per-address rate limit.
///
/// * A non-loopback peer is the client; any `X-Forwarded-For` it sends is ignored.
/// * A loopback peer is the venue's own reverse proxy (Caddy on the same host), which appends the
///   address it accepted the connection from to `X-Forwarded-For`: the client is the right-most
///   hop of the last header. Hops to its left are whatever the client sent and are never trusted.
///   `X-Real-IP` is not read (a client can set it and the proxy passes it through).
/// * A loopback peer with no `X-Forwarded-For` is a local process talking to the venue directly
///   (the market makers on the host, drills): `None`, not rate limited.
pub fn client_addr(peer: &str, forwarded: &[String]) -> Option<String> {
    if !is_loopback(peer) {
        return Some(peer.to_string());
    }
    forwarded.last().and_then(|v| v.rsplit(',').map(str::trim).find(|s| !s.is_empty())).map(str::to_string)
}

/// Take one request from `client`'s bucket; `None` for an unlimited local client.
pub fn limit(app: &App, client: &Option<String>) -> Option<RateInfo> {
    client.as_ref().map(|c| app.agent.take(&format!("ip:{c}")))
}

/// Rate headers for a reply (scope `address`, or `local` when not limited).
pub fn rate_headers(rate: &Option<RateInfo>) -> Vec<(String, String)> {
    match rate {
        Some(r) => {
            let mut h = vec![
                ("X-RateLimit-Limit".to_string(), format!("{}", BURST as u64)),
                ("X-RateLimit-Remaining".to_string(), r.remaining.to_string()),
                ("X-RateLimit-Reset".to_string(), format!("{:.3}", r.reset_ms as f64 / 1000.0)),
                ("X-RateLimit-Scope".to_string(), "address".to_string()),
            ];
            if !r.ok {
                h.push(("Retry-After".to_string(), r.reset_ms.div_ceil(1000).max(1).to_string()));
            }
            h
        }
        None => vec![("X-RateLimit-Scope".to_string(), "local".to_string())],
    }
}
pub fn rate_limited_error(r: &RateInfo) -> AgentError {
    AgentError::new("rate_limited", "request rate above the per-client limit").with(json!({"retry_after_ms": r.reset_ms}))
}

// -------------------------------------------------------------- REST ----

pub struct RestReply {
    pub code: u16,
    pub headers: Vec<(String, String)>,
    pub ctype: &'static str,
    pub body: Vec<u8>,
}

fn query_params(query: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        m.insert(k.to_string(), json!(v.replace("%3A", ":").replace("%3a", ":").replace("%2F", "/")));
    }
    m
}

/// One REST call. `rate` is the per-address bucket result the HTTP front end already took for
/// this request (a refused one never reaches here).
pub async fn rest(app: &App, verb: &str, path: &str, query: &str, head: &str, body: &[u8], rate: &Option<RateInfo>) -> RestReply {
    if path == "/agent/v1/openapi.json" && verb == "GET" {
        return RestReply { code: 200, headers: vec![], ctype: "application/json", body: SPEC.as_bytes().to_vec() };
    }
    let reply = |code: u16, headers: Vec<(String, String)>, v: Value| RestReply { code, headers, ctype: "application/json", body: v.to_string().into_bytes() };
    let Some(def) = METHODS.iter().find(|d| d.path == path && d.verb == verb) else {
        let e = if METHODS.iter().any(|d| d.path == path) {
            AgentError::new("method.unknown", format!("{verb} is not allowed on {path}"))
        } else {
            AgentError::new("method.unknown", format!("no route {path}"))
        };
        return reply(if METHODS.iter().any(|d| d.path == path) { 405 } else { 404 }, vec![], json!({"error": error_json(&e)}));
    };
    let mut params = query_params(query);
    if !body.is_empty() {
        match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(o)) => params.extend(o),
            _ => return reply(400, vec![], json!({"error": error_json(&bad("body must be a JSON object"))})),
        }
    }
    let p = Value::Object(params);
    let idem = head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("idempotency-key")).map(|(_, v)| v.trim().to_string()));
    let mut headers = rate_headers(rate);
    headers.push(("X-Agent-Api".to_string(), API_VERSION.to_string()));
    match call(app, def.name, &p, idem.as_deref()).await {
        Ok(v) => reply(200, headers, v),
        Err(e) => {
            if e.code == "limit.rate" {
                headers.push(("Retry-After".to_string(), "1".to_string()));
            }
            reply(http_status(e.code), headers, json!({"error": error_json(&e)}))
        }
    }
}

// --------------------------------------------------------- JSON-RPC ----

type Tx = SplitSink<WebSocketStream<TcpStream>, Message>;
type Rx = SplitStream<WebSocketStream<TcpStream>>;

fn rpc_err(id: &Value, e: &AgentError) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": rpc_code(e.code), "message": e.message, "data": error_json(e)}})
}

fn snapshot(v: &Venue, ch: &str) -> Value {
    match ch {
        "book" => v.book(25),
        "spot.book" => v.spot_book(25).unwrap_or(Value::Null),
        "trades" => json!(v.trades.iter().take(50).map(trade_json).collect::<Vec<_>>()),
        "mark" => json!({"mark": v.mark.as_ref().map(packet_json), "mark_usd": mark_usd(v)}),
        "options.book" => if v.opts.is_some() { v.options_series_view() } else { Value::Null },
        "batches" => json!(v.batches.values().rev().take(20).map(|b| v.batch_json(b)).collect::<Vec<_>>()),
        _ => Value::Null,
    }
}

/// One JSON-RPC request (or notification, without `id`); `None` for a notification.
async fn handle(app: &App, req: &Value, subs: &mut BTreeMap<&'static str, ()>, client: &Option<String>) -> Option<Value> {
    let id = req.get("id").cloned();
    let reply_id = id.clone().unwrap_or(Value::Null);
    if req["jsonrpc"] != "2.0" || !req["method"].is_string() {
        return Some(json!({"jsonrpc": "2.0", "id": reply_id, "error": {"code": -32600, "message": "invalid request"}}));
    }
    let method = req["method"].as_str().unwrap();
    let p = if req["params"].is_null() { json!({}) } else { req["params"].clone() };
    // Every JSON-RPC request is charged to the connection's client, like a REST request.
    let rate = limit(app, client);
    let out: Result<Value, AgentError> = if let Some(r) = rate.as_ref().filter(|r| !r.ok) {
        Err(rate_limited_error(r))
    } else {
        match method {
            "subscribe" | "unsubscribe" => {
                let names: Vec<String> = p["channels"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                let mut res = vec![];
                let mut err = None;
                for n in &names {
                    match CHANNELS.iter().find(|c| c.0 == n.as_str()) {
                        Some((c, _)) => {
                            if method == "subscribe" {
                                subs.insert(c, ());
                            } else {
                                subs.remove(c);
                            }
                            res.push(json!({"channel": c, "seq": app.agent.seq(c)}));
                        }
                        None => err = Some(AgentError::new("channel.unknown", format!("unknown channel {n}")).with(json!({"channels": CHANNELS.iter().map(|c| c.0).collect::<Vec<_>>()}))),
                    }
                }
                match err {
                    Some(e) => Err(e),
                    None if names.is_empty() => Err(bad("channels required")),
                    None => Ok(json!({"channels": res})),
                }
            }
            "resync" => match CHANNELS.iter().find(|c| Some(c.0) == p["channel"].as_str()) {
                None => Err(AgentError::new("channel.unknown", "unknown channel")),
                Some((c, _)) => {
                    let since = p["since"].as_u64();
                    match since.and_then(|s| app.agent.since(c, s)) {
                        Some(events) => Ok(json!({"channel": c, "seq": app.agent.seq(c), "replay": events})),
                        None => {
                            // Sequence read before the snapshot: the snapshot is at least as new.
                            let seq = app.agent.seq(c);
                            let v = app.venue.lock().await;
                            Ok(json!({"channel": c, "seq": seq, "snapshot": snapshot(&v, c)}))
                        }
                    }
                }
            },
            _ => call(app, method, &p, None).await,
        }
    };
    let id = id?;
    Some(match out {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err(e) => rpc_err(&id, &e),
    })
}

pub async fn ws(app: Arc<App>, mut tx: Tx, mut rx: Rx, client: Option<String>) {
    let mut bus = app.agent.tx.subscribe();
    let mut subs: BTreeMap<&'static str, ()> = BTreeMap::new();
    let hello = json!({"jsonrpc": "2.0", "method": "hello", "params": {"api_version": API_VERSION, "server_us": now_us(),
        "channels": CHANNELS.iter().map(|c| c.0).collect::<Vec<_>>(), "methods": METHODS.iter().map(|d| d.name).chain(WS_METHODS.iter().copied()).collect::<Vec<_>>()}});
    if tx.send(Message::text(hello.to_string())).await.is_err() {
        return;
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            n = bus.recv() => match n {
                Ok(n) => {
                    if !subs.contains_key(n.channel) { continue }
                    let f = json!({"jsonrpc": "2.0", "method": "subscription", "params": {"channel": n.channel, "seq": n.seq, "data": n.data}});
                    if tx.send(Message::text(f.to_string())).await.is_err() { break }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // This connection fell behind: tell it which channels to resync.
                    let chans: Vec<Value> = subs.keys().map(|c| json!({"channel": c, "seq": app.agent.seq(c)})).collect();
                    let f = json!({"jsonrpc": "2.0", "method": "gap", "params": {"channels": chans}});
                    if tx.send(Message::text(f.to_string())).await.is_err() { break }
                }
                Err(_) => break,
            },
            _ = heartbeat.tick() => {
                let f = json!({"jsonrpc": "2.0", "method": "heartbeat", "params": {"server_us": now_us(),
                    "seq": subs.keys().map(|c| (c.to_string(), json!(app.agent.seq(c)))).collect::<serde_json::Map<_, _>>()}});
                if tx.send(Message::text(f.to_string())).await.is_err() { break }
            }
            m = rx.next() => {
                let text = match m {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) | Some(Ok(Message::Frame(_))) => continue,
                    _ => break,
                };
                let reply = match serde_json::from_str::<Value>(&text) {
                    Err(_) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})),
                    Ok(Value::Array(reqs)) if !reqs.is_empty() && reqs.len() <= 50 => {
                        let mut out = vec![];
                        for r in &reqs {
                            if let Some(x) = handle(&app, r, &mut subs, &client).await { out.push(x) }
                        }
                        (!out.is_empty()).then(|| json!(out))
                    }
                    Ok(Value::Array(_)) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "batch must hold 1..=50 requests"}})),
                    Ok(r) => handle(&app, &r, &mut subs, &client).await,
                };
                if let Some(r) = reply && tx.send(Message::text(r.to_string())).await.is_err() { break }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checked-in OpenAPI document and this method table describe the same API: every
    /// REST route is a path+verb in the spec with the matching `x-rpc-method`, every spec
    /// operation is routed, the WS methods and channels are listed, and the error-code enum
    /// equals `ERROR_CODES`.
    #[test]
    fn openapi_spec_matches_the_method_table() {
        let spec: Value = serde_json::from_str(SPEC).expect("openapi.json parses");
        assert!(spec["openapi"].as_str().unwrap().starts_with("3.1"));
        let paths = spec["paths"].as_object().unwrap();
        let mut seen = 0;
        for (path, ops) in paths {
            for (verb, op) in ops.as_object().unwrap() {
                if path == "/agent/v1/openapi.json" {
                    continue;
                }
                let d = METHODS.iter().find(|d| d.path == path && d.verb.eq_ignore_ascii_case(verb)).unwrap_or_else(|| panic!("spec op {verb} {path} is not routed"));
                assert_eq!(op["x-rpc-method"].as_str(), Some(d.name), "{verb} {path}");
                assert!(op["responses"]["200"].is_object(), "{verb} {path} documents its 200");
                assert!(op["responses"]["default"].is_object(), "{verb} {path} documents its error");
                seen += 1;
            }
        }
        assert_eq!(seen, METHODS.len(), "every route is in the spec");
        let ws = &spec["x-websocket"];
        let wm: Vec<&str> = ws["methods"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(wm, WS_METHODS);
        let ch: Vec<&str> = ws["channels"].as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let mut want: Vec<&str> = CHANNELS.iter().map(|c| c.0).collect();
        want.sort();
        let mut got = ch.clone();
        got.sort();
        assert_eq!(got, want);
        let codes: Vec<&str> = spec["components"]["schemas"]["ErrorCode"]["enum"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(codes, ERROR_CODES);
        for c in ERROR_CODES {
            let s = http_status(c);
            assert!((400..600).contains(&s), "{c}");
        }
    }

    #[test]
    fn client_address_behind_a_loopback_proxy() {
        let ca = |peer: &str, head: &str| client_addr(peer, &forwarded_values(head));
        // Caddy appends the address it accepted the connection from: the right-most hop.
        let spoofed = "POST /agent/v1/orders HTTP/1.1\r\nX-Forwarded-For: 6.6.6.6, 203.0.113.7\r\nX-Real-IP: 198.51.100.2";
        assert_eq!(ca("127.0.0.1", spoofed).as_deref(), Some("203.0.113.7"), "client-sent hops to the left are ignored");
        assert_eq!(ca("::1", spoofed).as_deref(), Some("203.0.113.7"));
        assert_eq!(ca("::ffff:127.0.0.1", spoofed).as_deref(), Some("203.0.113.7"));
        // Two header lines: the proxy's is the last.
        assert_eq!(ca("127.0.0.1", "GET / HTTP/1.1\r\nX-Forwarded-For: 6.6.6.6\r\nX-Forwarded-For: 203.0.113.9").as_deref(), Some("203.0.113.9"));
        // X-Real-IP is never read; a local process with no forwarding header is not limited.
        assert_eq!(ca("127.0.0.1", "GET / HTTP/1.1\r\nX-Real-IP: 198.51.100.2"), None);
        assert_eq!(ca("127.0.0.1", "GET / HTTP/1.1"), None);
        // A non-loopback peer is its own client whatever it sends.
        assert_eq!(ca("192.0.2.9", spoofed).as_deref(), Some("192.0.2.9"), "spoofed X-Forwarded-For from a remote peer is ignored");
        assert_eq!(ca("10.1.2.3", "GET / HTTP/1.1").as_deref(), Some("10.1.2.3"));
    }

    #[test]
    fn rate_bucket_and_idempotency() {
        let s = ApiState::default();
        for _ in 0..BURST as usize {
            assert!(s.take("k").ok);
        }
        let r = s.take("k");
        assert!(!r.ok && r.reset_ms > 0);
        assert!(s.take("other").ok);
        let ok: Result<Value, AgentError> = Ok(json!({"a": 1}));
        s.idem_put("m|g|1".into(), [1; 32], &ok);
        assert_eq!(s.idem_get("m|g|1", &[1; 32]).unwrap().unwrap(), json!({"a": 1}));
        assert_eq!(s.idem_get("m|g|1", &[2; 32]).unwrap().unwrap_err().code, "idempotency.mismatch");
        assert!(s.idem_get("m|g|2", &[1; 32]).is_none());
    }

    #[test]
    fn bus_sequences_replay_and_gap() {
        let s = ApiState::default();
        for _ in 0..3 {
            s.publish(r#"{"type":"book","bids":[]}"#);
        }
        s.publish(r#"{"type":"trade"}"#);
        s.publish(r#"{"type":"unknown_kind"}"#);
        assert_eq!((s.seq("book"), s.seq("trades"), s.seq("mark")), (3, 1, 0));
        assert_eq!(s.since("book", 1).unwrap().len(), 2);
        assert_eq!(s.since("book", 3).unwrap().len(), 0);
        s.gap();
        assert_eq!(s.seq("book"), 4);
        assert!(s.since("book", 1).is_none(), "a gap forces a snapshot");
    }
}
