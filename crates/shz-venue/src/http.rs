//! HTTP/1.1 + WebSocket front end (no framework): REST API, BitcornWisdom
//! relay protocol, venue event stream, explorer endpoints and static files.

use std::{path::PathBuf, sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use k256::{ProjectivePoint, Scalar, elliptic_curve::PrimeField};
use serde_json::{Value, json};
use shz_dlc::{BtcOutPoint, tagged_hash};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, broadcast},
};
use tokio_tungstenite::tungstenite::{
    Message,
    handshake::server::{Request, Response},
};

use crate::core::{MARKET, Venue, now_us, packet_json, parse_key, parse_sig, parse_tier, trade_json};

pub struct App {
    pub venue: Arc<Mutex<Venue>>,
    pub events: broadcast::Sender<String>,
    pub ui_dir: PathBuf,
    pub mempool_api: String,
}

const INTERVALS: [(&str, u64); 4] = [("1m", 60_000), ("5m", 300_000), ("15m", 900_000), ("1h", 3_600_000)];

pub async fn serve(app: Arc<App>, listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let _ = stream.set_nodelay(true);
        let app = app.clone();
        tokio::spawn(async move {
            let mut peek = [0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.peek(&mut peek)).await {
                Ok(Ok(n)) => n,
                _ => return,
            };
            let head = String::from_utf8_lossy(&peek[..n]).to_ascii_lowercase();
            if head.contains("upgrade: websocket") {
                ws(app, stream).await;
            } else {
                http(app, stream).await;
            }
        });
    }
}

// ------------------------------------------------------------------ http ----

async fn http(app: Arc<App>, mut s: TcpStream) {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let (head_end, content_len) = loop {
        let n = match tokio::time::timeout(Duration::from_secs(10), s.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => return,
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 256 * 1024 {
            return;
        }
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..p]).to_string();
            let cl = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
            break (p + 4, cl.min(256 * 1024));
        }
    };
    while buf.len() < head_end + content_len {
        let n = match tokio::time::timeout(Duration::from_secs(10), s.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        buf.extend_from_slice(&tmp[..n]);
    }
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut parts = head.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let body = &buf[head_end..head_end + content_len];
    let (path, query) = target.split_once('?').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((target.clone(), String::new()));
    let (code, ctype, payload) = if method == "OPTIONS" {
        (204, "text/plain", vec![])
    } else if path.starts_with("/api/") || path.starts_with("/v1/") {
        let (c, v) = api(&app, &method, &path, &query, body).await;
        (c, "application/json", v.to_string().into_bytes())
    } else {
        static_file(&app, &path)
    };
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.write_all(&payload).await;
}

fn static_file(app: &App, path: &str) -> (u16, &'static str, Vec<u8>) {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    if rel.contains("..") || rel.contains('\\') || rel.contains(':') {
        return (400, "text/plain", b"bad path".to_vec());
    }
    let p = app.ui_dir.join(rel);
    match std::fs::read(&p) {
        Ok(b) => {
            let ct = match p.extension().and_then(|e| e.to_str()).unwrap_or("") {
                "html" => "text/html; charset=utf-8",
                "js" | "mjs" => "text/javascript; charset=utf-8",
                "css" => "text/css; charset=utf-8",
                "svg" => "image/svg+xml",
                "json" => "application/json",
                "png" => "image/png",
                _ => "application/octet-stream",
            };
            (200, ct, b)
        }
        Err(_) => (404, "text/plain", b"not found".to_vec()),
    }
}

fn q(query: &str, k: &str) -> Option<String> {
    query.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).map(|(_, b)| b.replace("%3A", ":").replace("%2F", "/")))
}
fn err(code: u16, m: impl ToString) -> (u16, Value) {
    (code, json!({"error": m.to_string()}))
}

async fn api(app: &App, method: &str, path: &str, query: &str, body: &[u8]) -> (u16, Value) {
    let jb: Value = if body.is_empty() { Value::Null } else { serde_json::from_slice(body).unwrap_or(Value::Null) };
    let get = method == "GET";
    let post = method == "POST";
    match (get, post, path) {
        (true, _, "/api/status") => (200, app.venue.lock().await.status()),
        (true, _, "/api/template") => (200, app.venue.lock().await.template()),
        (true, _, "/api/book") => {
            let depth = q(query, "depth").and_then(|d| d.parse().ok()).unwrap_or(25usize).min(200);
            (200, app.venue.lock().await.book(depth))
        }
        (true, _, "/api/trades") => {
            let limit = q(query, "limit").and_then(|d| d.parse().ok()).unwrap_or(100usize).min(1000);
            let v = app.venue.lock().await;
            (200, json!(v.trades.iter().take(limit).map(trade_json).collect::<Vec<_>>()))
        }
        (true, _, p) if p.starts_with("/api/account/") => match parse_key(&p["/api/account/".len()..]) {
            Ok(k) => {
                let v = app.venue.lock().await;
                let view = v.account_view(&k);
                if view.is_null() { err(404, "no such account") } else { (200, view) }
            }
            Err(e) => err(400, e),
        },
        (_, true, "/api/register/draft") => register_draft(app, &jb).await,
        (_, true, "/api/register") => {
            let draft = jb["draft_id"].as_str().unwrap_or("");
            match jb["owner_signature"].as_str().map(parse_sig) {
                Some(Ok(sig)) => {
                    let mut v = app.venue.lock().await;
                    match v.register(draft, sig) {
                        Ok(a) => (200, json!({"account": a})),
                        Err(e) => err(409, e),
                    }
                }
                _ => err(400, "owner_signature required"),
            }
        }
        (_, true, "/api/entitlement") => {
            let owner = jb["owner"].as_str().map(parse_key);
            let tier = jb["tier"].as_str().map(parse_tier);
            match (owner, tier) {
                (Some(Ok(o)), Some(Ok(t))) => match app.venue.lock().await.entitlement(o, t) {
                    Ok(x) => (200, x),
                    Err(e) => err(409, e),
                },
                _ => err(400, "owner and tier required"),
            }
        }
        (_, true, "/api/intent-id") => {
            let v = app.venue.lock().await;
            match v.intent_from_json(&jb["intent"]) {
                Ok(i) => (200, json!({"id": hex::encode(i.id())})),
                Err(e) => err(400, e),
            }
        }
        (_, true, "/api/intents") => {
            let mut v = app.venue.lock().await;
            match v.intent_from_json(&jb["intent"]) {
                Ok(i) => match v.submit(i) {
                    Ok(x) => (200, x),
                    Err(e) => err(409, e),
                },
                Err(e) => err(400, e),
            }
        }
        (_, true, "/api/signatures") => {
            let owner = jb["owner"].as_str().map(parse_key);
            let items: Result<Vec<_>, String> = jb["items"]
                .as_array()
                .map(|a| a.iter().map(|it| Ok((it["id"].as_str().unwrap_or("").to_string(), parse_sig(it["signature"].as_str().unwrap_or(""))?))).collect())
                .unwrap_or(Ok(vec![]));
            match (owner, items) {
                (Some(Ok(o)), Ok(items)) => match app.venue.lock().await.add_signatures(o, &items) {
                    Ok(n) => (200, json!({"accepted": n})),
                    Err(e) => err(409, e),
                },
                _ => err(400, "owner and items required"),
            }
        }
        (true, _, "/v1/candles") => candles(app, query).await,
        (true, _, "/api/explorer/packets") => {
            let limit = q(query, "limit").and_then(|d| d.parse().ok()).unwrap_or(50usize).min(600);
            let v = app.venue.lock().await;
            (200, json!(v.packets.iter().rev().take(limit).map(packet_json).collect::<Vec<_>>()))
        }
        (true, _, p) if p.starts_with("/api/explorer/packet/") => {
            let seq: u64 = p.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let v = app.venue.lock().await;
            let fills: Vec<Value> = v.trades.iter().filter(|t| t.packet.as_ref().is_some_and(|p| p.seq == seq)).map(trade_json).collect();
            match v.packets.iter().find(|p| p.seq == seq) {
                Some(p) => (200, json!({"packet": packet_json(p), "fills": fills})),
                None => err(404, "packet not retained"),
            }
        }
        (true, _, p) if p.starts_with("/api/explorer/fill/") => match parse_key(&p["/api/explorer/fill/".len()..]) {
            Ok(k) => {
                let v = app.venue.lock().await;
                let x = v.fill_explorer(&k);
                if x.is_null() { err(404, "no such fill") } else { (200, x) }
            }
            Err(e) => err(400, e),
        },
        (true, _, "/api/explorer/batches") => {
            let limit = q(query, "limit").and_then(|d| d.parse().ok()).unwrap_or(50usize).min(500);
            let v = app.venue.lock().await;
            (200, json!(v.batches.values().rev().take(limit).map(|b| v.batch_json(b)).collect::<Vec<_>>()))
        }
        (true, _, p) if p.starts_with("/api/explorer/batch/") => {
            let seq: u64 = p.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let v = app.venue.lock().await;
            match v.batches.get(&seq) {
                Some(b) => {
                    let fills: Vec<Value> = v.trades.iter().filter(|t| t.batch_seq == Some(seq)).map(trade_json).collect();
                    (200, json!({"batch": v.batch_json(b), "fills": fills}))
                }
                None => err(404, "no such batch"),
            }
        }
        (true, _, "/api/explorer/accounts") => {
            let v = app.venue.lock().await;
            (200, json!(v.accounts.values().map(|a| json!({
                "owner": hex::encode(a.owner), "kind": a.kind, "label": a.label, "cap_sats": a.cap_sats,
                "outpoint": {"txid": hex::encode(a.outpoint.txid), "vout": a.outpoint.vout},
                "explorer_url": (a.kind == "utxo").then(|| format!("https://mempool.space/testnet4/tx/{}", hex::encode(a.outpoint.txid))),
                "balance": v.balance(&a.owner).map(|b| json!({"cap": b.cap, "free": b.free, "resting": b.resting, "pending": b.pending, "committed": b.committed, "paid_fees": b.paid_fees})),
                "position": v.position(&a.owner),
            })).collect::<Vec<_>>()))
        }
        (true, _, "/api/explorer/journal") => {
            let v = app.venue.lock().await;
            (200, json!({"journal": v.journal(), "fee_ledger": v.ledger_totals()}))
        }
        (true, _, "/api/explorer/dlc") => {
            let relay = app.venue.lock().await.relay_url.clone();
            match crate::feed::relay_get(&relay, "/v1/dlc/events").await {
                Ok(x) => (200, x),
                Err(e) => err(502, e),
            }
        }
        _ => err(404, "not found"),
    }
}

async fn register_draft(app: &App, jb: &Value) -> (u16, Value) {
    let owner = match jb["owner"].as_str().map(parse_key) {
        Some(Ok(o)) => o,
        _ => return err(400, "owner required"),
    };
    let kind = jb["kind"].as_str().unwrap_or("demo").to_string();
    let (outpoint, value) = if kind == "utxo" {
        let txid = match jb["outpoint"]["txid"].as_str().map(parse_key) {
            Some(Ok(t)) => t,
            _ => return err(400, "outpoint.txid required"),
        };
        let vout = jb["outpoint"]["vout"].as_u64().unwrap_or(u64::MAX);
        if vout > u32::MAX as u64 {
            return err(400, "outpoint.vout required");
        }
        match verify_utxo(&app.mempool_api, &owner, &txid, vout as u32).await {
            Ok(v) => (Some(BtcOutPoint { txid, vout: vout as u32 }), Some(v)),
            Err(e) => return err(409, e),
        }
    } else {
        (None, None)
    };
    match app.venue.lock().await.register_draft(owner, &kind, outpoint, value) {
        Ok(x) => (200, x),
        Err(e) => err(409, e),
    }
}

/// BIP341 key-path output key for an x-only internal key with no script tree.
pub fn p2tr_output_key(internal: &[u8; 32]) -> Option<[u8; 32]> {
    let p = shz_dlc::lift_x_even(internal).ok()?;
    let t = tagged_hash(b"TapTweak", internal);
    let ts: Scalar = Option::from(Scalar::from_repr(t.into()))?;
    let q = (p + ProjectivePoint::GENERATOR * ts).to_affine();
    let enc = k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&q, true);
    enc.as_bytes()[1..33].try_into().ok()
}

async fn curl_json(url: String) -> Result<Value, String> {
    let out = tokio::task::spawn_blocking(move || std::process::Command::new("curl").args(["-s", "-m", "10", "-A", "shz-venue/1", &url]).output())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("curl: {e}"))?;
    serde_json::from_slice(&out.stdout).map_err(|_| format!("unexpected response: {}", String::from_utf8_lossy(&out.stdout).chars().take(120).collect::<String>()))
}

/// The outpoint must be unspent and pay P2TR (key path) to the owner's key.
async fn verify_utxo(api: &str, owner: &[u8; 32], txid: &[u8; 32], vout: u32) -> Result<u64, String> {
    let txid_hex = hex::encode(txid);
    let tx = curl_json(format!("{api}/tx/{txid_hex}")).await?;
    let out = tx["vout"].get(vout as usize).ok_or("no such output")?;
    let expected = format!("5120{}", hex::encode(p2tr_output_key(owner).ok_or("bad owner key")?));
    if out["scriptpubkey"].as_str() != Some(expected.as_str()) {
        return Err("output does not pay P2TR to the owner key".into());
    }
    let spent = curl_json(format!("{api}/tx/{txid_hex}/outspend/{vout}")).await?;
    if spent["spent"].as_bool() != Some(false) {
        return Err("output is spent or unknown".into());
    }
    out["value"].as_u64().ok_or_else(|| "missing value".into())
}

fn interval_ms(query: &str) -> Option<(String, u64)> {
    let iv = q(query, "interval").unwrap_or_else(|| "1m".into());
    INTERVALS.iter().find(|(n, _)| *n == iv).map(|(n, ms)| (n.to_string(), *ms))
}

fn candles_for(v: &Venue, ms: u64, limit: usize) -> Vec<Value> {
    let mut agg: std::collections::BTreeMap<u64, [f64; 5]> = std::collections::BTreeMap::new();
    for (&minute, c) in &v.candles {
        let b = minute / ms * ms;
        let e = agg.entry(b).or_insert([c[0], c[1], c[2], c[3], 0.0]);
        e[1] = e[1].max(c[1]);
        e[2] = e[2].min(c[2]);
        e[3] = c[3];
        e[4] += c[4];
    }
    let all: Vec<_> = agg.into_iter().collect();
    let start = all.len().saturating_sub(limit);
    all[start..]
        .iter()
        .map(|(t, c)| json!({"time": t, "open": c[0], "high": c[1], "low": c[2], "close": c[3], "volume": c[4]}))
        .collect()
}

async fn candles(app: &App, query: &str) -> (u16, Value) {
    if q(query, "instrument").as_deref() != Some(MARKET) {
        return err(404, format!("unsupported instrument; this relay serves {MARKET}"));
    }
    let Some((name, ms)) = interval_ms(query) else { return err(400, "unsupported interval") };
    let limit = q(query, "limit").and_then(|d| d.parse().ok()).unwrap_or(900usize).min(900);
    let v = app.venue.lock().await;
    (200, json!({"instrument": MARKET, "interval": name, "candles": candles_for(&v, ms, limit)}))
}

// -------------------------------------------------------------------- ws ----

async fn ws(app: Arc<App>, stream: TcpStream) {
    let mut path = String::new();
    // The callback signature is fixed by tungstenite (its error type is an HTTP response).
    #[allow(clippy::result_large_err)]
    let cb = |req: &Request, resp: Response| {
        path = req.uri().to_string();
        Ok(resp)
    };
    let Ok(ws) = tokio_tungstenite::accept_hdr_async(stream, cb).await else { return };
    let (mut tx, mut rx) = ws.split();
    let (p, query) = path.split_once('?').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((path.clone(), String::new()));
    let mut events = app.events.subscribe();
    let candle_mode = p == "/v1/stream";
    let iv = interval_ms(&query);
    if candle_mode && (q(&query, "instrument").as_deref() != Some(MARKET) || iv.is_none()) {
        let _ = tx.send(Message::text(json!({"type": "error", "error": "unsupported instrument or interval"}).to_string())).await;
        return;
    }
    if !candle_mode {
        let hello = { app.venue.lock().await.status() };
        if tx.send(Message::text(json!({"type": "status", "status": hello}).to_string())).await.is_err() {
            return;
        }
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Ok(ev) = ev else { continue };
                let frame = if candle_mode {
                    let kind: Value = serde_json::from_str(&ev).unwrap_or(Value::Null);
                    if kind["type"] != "trade" && kind["type"] != "mark" { continue }
                    let (name, ms) = iv.clone().unwrap();
                    let last = { candles_for(&*app.venue.lock().await, ms, 1).pop() };
                    match last {
                        Some(c) => json!({"type": "candle", "instrument": MARKET, "interval": name, "candle": c}).to_string(),
                        None => continue,
                    }
                } else { ev };
                if tx.send(Message::text(frame)).await.is_err() { break }
            }
            _ = heartbeat.tick() => {
                let hb = if candle_mode {
                    json!({"type": "heartbeat", "instrument": MARKET, "interval": iv.as_ref().map(|x| x.0.clone())})
                } else {
                    json!({"type": "heartbeat", "server_us": now_us()})
                };
                if tx.send(Message::text(hb.to_string())).await.is_err() { break }
            }
            m = rx.next() => if m.is_none() || matches!(m, Some(Err(_)) | Some(Ok(Message::Close(_)))) { break },
        }
    }
}
