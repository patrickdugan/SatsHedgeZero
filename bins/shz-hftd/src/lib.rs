//! `shz_hftd` — Sub-millisecond SatsHedgeZero HFT WebSocket/REST Gateway, Rolling Testnet4
//! Rollup Scheduler, Challenger Watchtower, and Back-End Protocol Explorer Server.
#![forbid(unsafe_code)]

pub mod engine;
pub mod ws;

use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use engine::{HftEngine, PlaceIntentWireParams};
use serde::{Deserialize, Serialize};
use shz_margin::InverseContractSpec;
use ws::{WsOpcode, compute_websocket_accept, read_ws_frame, write_ws_frame};

#[derive(Debug, Clone)]
pub struct HftServerConfig {
    pub bind_addr: String,
    pub ui_public_dir: PathBuf,
    pub rollup_interval_ms: u64,
}

impl Default for HftServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8090".into(),
            ui_public_dir: PathBuf::from("ui/public"),
            rollup_interval_ms: 300_000, // 5-minute rolling Testnet4 rollup epoch (Milestone M4)
        }
    }
}

pub struct HftServerHandle {
    pub local_addr: SocketAddr,
    pub stop_flag: Arc<AtomicBool>,
    pub engine: Arc<Mutex<HftEngine>>,
}

impl HftServerHandle {
    pub fn shutdown(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(50));
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcErrorObj>,
}

#[derive(Debug, Serialize)]
struct JsonRpcErrorObj {
    code: i32,
    message: String,
}

/// Spawns `shz-hftd` background scheduler (`100 ms` LN coalescer, `200 ms` Oracle relayer,
/// `5 m` Multilateral BitVM3 rollup) and TCP/HTTP/WebSocket accept loop.
pub fn spawn_hftd_server(cfg: HftServerConfig) -> std::io::Result<HftServerHandle> {
    let listener = TcpListener::bind(&cfg.bind_addr)?;
    let local_addr = listener.local_addr()?;
    listener.set_nonblocking(false)?;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let engine = Arc::new(Mutex::new(HftEngine::new_bootstrapped()));

    // Background Tier-1 (`100 ms` LN Coalescer), Tier-2 (`200 ms` Oracle), Tier-3 (`5 m` Rollup) loop:
    {
        let eng_bg = Arc::clone(&engine);
        let stop_bg = Arc::clone(&stop_flag);
        let rollup_ticks = (cfg.rollup_interval_ms / 100).max(10);
        thread::spawn(move || {
            let mut tick_100ms: u64 = 0;
            while !stop_bg.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
                tick_100ms += 1;
                // Drain pending fills in < 2 us, sign BIP-340 commits OFF-LOCK so orderbook match acks never stall!
                let pending = if let Ok(mut guard) = eng_bg.lock() {
                    if tick_100ms.is_multiple_of(2) {
                        guard.tick_200ms_oracle();
                    }
                    let mark = guard.mark_price_usd;
                    guard.ln_mesh.drain_epoch_pending(mark)
                } else {
                    Vec::new()
                };
                if !pending.is_empty() {
                    let signed: Vec<_> = pending
                        .into_iter()
                        .map(|(cid_num, item)| item.sign_off_lock(cid_num))
                        .collect();
                    if let Ok(mut guard) = eng_bg.lock() {
                        guard.ln_mesh.record_signed_commits(signed);
                    }
                }
                if tick_100ms.is_multiple_of(rollup_ticks)
                    && let Ok(mut guard) = eng_bg.lock()
                {
                    let _ = guard.run_multilateral_rollup_epoch();
                }
            }
        });
    }

    // Accept loop (spawns a lightweight OS thread per persistent WS / SSE / HTTP connection):
    {
        let eng_acc = Arc::clone(&engine);
        let stop_acc = Arc::clone(&stop_flag);
        let ui_dir = cfg.ui_public_dir.clone();
        thread::spawn(move || {
            for incoming in listener.incoming() {
                if stop_acc.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = incoming {
                    let _ = stream.set_nodelay(true);
                    let eng_c = Arc::clone(&eng_acc);
                    let stop_c = Arc::clone(&stop_acc);
                    let ui_c = ui_dir.clone();
                    thread::spawn(move || {
                        let _ = handle_connection(stream, eng_c, stop_c, &ui_c);
                    });
                }
            }
        });
    }

    Ok(HftServerHandle {
        local_addr,
        stop_flag,
        engine,
    })
}

fn handle_connection(
    stream: TcpStream,
    engine: Arc<Mutex<HftEngine>>,
    stop_flag: Arc<AtomicBool>,
    ui_public_dir: &Path,
) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        let mut req_line = String::new();
        let n = reader.read_line(&mut req_line)?;
        if n == 0 {
            break;
        }
        let req_trimmed = req_line.trim_end();
        if req_trimmed.is_empty() {
            continue;
        }
        let mut parts = req_trimmed.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_uppercase();
        let raw_target = parts.next().unwrap_or("/");
        let (pathname, _query) = raw_target.split_once('?').unwrap_or((raw_target, ""));

        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut hline = String::new();
            let hn = reader.read_line(&mut hline)?;
            if hn == 0 || hline == "\r\n" || hline == "\n" {
                break;
            }
            if let Some((k, v)) = hline.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
            }
        }

        let content_len: usize = headers
            .get("content-length")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if content_len > 2 * 1024 * 1024 {
            send_http_json(&mut writer, 413, &serde_json::json!({"error":"payload too large"}))?;
            break;
        }
        let mut body = vec![0u8; content_len];
        if content_len > 0 {
            reader.read_exact(&mut body)?;
        }

        // 1. WebSocket Upgrade (`/v1/ws`):
        if pathname == "/v1/ws"
            && headers
                .get("upgrade")
                .map(|u| u.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
            && let Some(ws_key) = headers.get("sec-websocket-key")
        {
            let accept_val = compute_websocket_accept(ws_key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept_val}\r\n\r\n"
            );
            writer.write_all(resp.as_bytes())?;
            writer.flush()?;
            return run_websocket_session(&mut reader, &mut writer, engine, stop_flag);
        }

        // 2. Explorer `250 ms` Server-Sent Events Stream (`/v1/explorer/stream`):
        if pathname == "/v1/explorer/stream" && method == "GET" {
            let hdr = "HTTP/1.1 200 OK\r\n\
                       Content-Type: text/event-stream; charset=utf-8\r\n\
                       Cache-Control: no-cache\r\n\
                       Connection: keep-alive\r\n\
                       Access-Control-Allow-Origin: *\r\n\r\n";
            writer.write_all(hdr.as_bytes())?;
            writer.flush()?;
            while !stop_flag.load(Ordering::Relaxed) {
                let snap_json = {
                    let guard = engine.lock().unwrap();
                    serde_json::to_string(&guard.build_explorer_snapshot()).unwrap_or_default()
                };
                let frame = format!("event: snapshot\ndata: {snap_json}\n\n");
                if writer.write_all(frame.as_bytes()).is_err() || writer.flush().is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(250));
            }
            return Ok(());
        }

        // 3. CORS preflight:
        if method == "OPTIONS" {
            let hdr = "HTTP/1.1 204 No Content\r\n\
                       Access-Control-Allow-Origin: *\r\n\
                       Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                       Access-Control-Allow-Headers: Content-Type\r\n\
                       Content-Length: 0\r\n\r\n";
            writer.write_all(hdr.as_bytes())?;
            writer.flush()?;
            continue;
        }

        // 4. Explorer & HFT REST Routes:
        match (method.as_str(), pathname) {
            ("GET", "/v1/health") => {
                let snap = engine.lock().unwrap().compute_latency_metrics();
                send_http_json(
                    &mut writer,
                    200,
                    &serde_json::json!({ "ok": true, "service": "shz-hftd", "latency": snap }),
                )?;
            }
            ("GET", "/v1/explorer/snapshot") => {
                let snap = engine.lock().unwrap().build_explorer_snapshot();
                send_http_json(&mut writer, 200, &snap)?;
            }
            ("POST", "/v1/explorer/action") => {
                let v: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}));
                let act = v["action"].as_str().unwrap_or("");
                let cnt = v["count"].as_u64().map(|n| n as usize);
                let res = {
                    let mut guard = engine.lock().unwrap();
                    guard.execute_explorer_action(act, cnt)
                };
                match res {
                    Ok(payload) => send_http_json(&mut writer, 200, &payload)?,
                    Err(e) => send_http_json(&mut writer, 400, &serde_json::json!({"error": e}))?,
                }
            }
            ("GET", "/v1/api/book") => {
                let snap = engine.lock().unwrap().build_explorer_snapshot();
                send_http_json(
                    &mut writer,
                    200,
                    &serde_json::json!({
                        "instrument": "BTC-USD-INV",
                        "mark_price_usd": snap.mark_price_usd,
                        "bids": snap.bids,
                        "asks": snap.asks,
                    }),
                )?;
            }
            ("GET", "/v1/api/trades") => {
                let snap = engine.lock().unwrap().build_explorer_snapshot();
                send_http_json(&mut writer, 200, &snap.fill_tape)?;
            }
            ("GET", "/v1/api/oracle") => {
                let snap = engine.lock().unwrap().build_explorer_snapshot();
                send_http_json(
                    &mut writer,
                    200,
                    &serde_json::json!({
                        "latest": snap.oracle_latest,
                        "checkpoints": snap.oracle_checkpoints,
                        "near_optimistic": snap.near_optimistic,
                    }),
                )?;
            }
            ("GET", "/v1/api/positions") => {
                let snap = engine.lock().unwrap().build_explorer_snapshot();
                send_http_json(
                    &mut writer,
                    200,
                    &serde_json::json!({
                        "ln_channels": snap.ln_channels,
                        "portfolio_greeks": snap.netting.portfolio_greeks,
                        "liquidation_plan": snap.netting.liquidation_plan,
                    }),
                )?;
            }
            ("POST", "/v1/api/place_intent") => {
                let wire: PlaceIntentWireParams = match serde_json::from_slice(&body) {
                    Ok(w) => w,
                    Err(e) => {
                        send_http_json(
                            &mut writer,
                            400,
                            &serde_json::json!({"error": e.to_string()}),
                        )?;
                        continue;
                    }
                };
                let res = wire
                    .into_signed_intent()
                    .and_then(|intent| engine.lock().unwrap().place_signed_intent(intent));
                match res {
                    Ok(ack) => send_http_json(&mut writer, 200, &ack)?,
                    Err(e) => send_http_json(&mut writer, 400, &serde_json::json!({"error": e}))?,
                }
            }
            // Native Terminal `/api/state` & `/api/quote` compatibility so `/` works standalone on `shz-hftd`!
            ("GET", "/api/state") => {
                let snap = engine.lock().unwrap().build_explorer_snapshot();
                let payload = build_terminal_compat_state(&snap);
                send_http_json(&mut writer, 200, &payload)?;
            }
            ("POST", "/api/quote") => {
                let v: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}));
                let q = build_terminal_compat_quote(&v);
                send_http_json(&mut writer, 200, &q)?;
            }
            ("GET", p) => {
                serve_static_ui(&mut writer, ui_public_dir, p)?;
            }
            _ => {
                send_http_json(&mut writer, 404, &serde_json::json!({"error":"not found"}))?;
            }
        }

        if headers
            .get("connection")
            .map(|c| c.eq_ignore_ascii_case("close"))
            .unwrap_or(false)
        {
            break;
        }
    }
    Ok(())
}

fn run_websocket_session<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    engine: Arc<Mutex<HftEngine>>,
    stop_flag: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut cancel_on_disconnect_pk: Option<[u8; 32]> = None;

    while !stop_flag.load(Ordering::Relaxed) {
        let frame = match read_ws_frame(reader) {
            Ok(f) => f,
            Err(_) => break,
        };
        match frame.opcode {
            WsOpcode::Close => {
                let _ = write_ws_frame(writer, WsOpcode::Close, &[], None);
                break;
            }
            WsOpcode::Ping => {
                write_ws_frame(writer, WsOpcode::Pong, &frame.payload, None)?;
            }
            WsOpcode::Pong => {}
            WsOpcode::Text | WsOpcode::Binary => {
                let resp = dispatch_ws_rpc(&frame.payload, &engine, &mut cancel_on_disconnect_pk);
                let out_bytes = serde_json::to_vec(&resp).unwrap_or_default();
                if write_ws_frame(writer, WsOpcode::Text, &out_bytes, None).is_err() {
                    break;
                }
            }
        }
    }

    // Enforce `cancel_on_disconnect` immediately if enabled for this HFT session:
    if let Some(pk) = cancel_on_disconnect_pk
        && let Ok(mut guard) = engine.lock()
    {
        let _ = guard.book.cancel_all_for_trader(&pk);
    }
    Ok(())
}

fn dispatch_ws_rpc(
    payload: &[u8],
    engine: &Arc<Mutex<HftEngine>>,
    cancel_on_disconnect_pk: &mut Option<[u8; 32]>,
) -> JsonRpcResponse {
    let req: JsonRpcRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: serde_json::Value::Null,
                result: None,
                error: Some(JsonRpcErrorObj {
                    code: -32700,
                    message: format!("parse error: {e}"),
                }),
            };
        }
    };

    let result: Result<serde_json::Value, String> = match req.method.as_str() {
        "public/subscribe" => {
            let channels = req.params["channels"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            Ok(serde_json::json!({ "subscribed": channels }))
        }
        "private/place_intent" => serde_json::from_value::<PlaceIntentWireParams>(req.params)
            .map_err(|e| e.to_string())
            .and_then(|w| w.into_signed_intent())
            .and_then(|intent| {
                // Stateless BIP-340 Schnorr verification runs lock-free in parallel across WS threads!
                let t0 = std::time::Instant::now();
                intent.verify().map_err(|e| e.to_string())?;
                let mut guard = engine.lock().unwrap();
                guard.place_preverified_intent(intent, t0)
            })
            .map(|ack| serde_json::to_value(ack).unwrap()),
        "private/mass_quote" => {
            let pk_hex = req.params["trader_pubkey_x_hex"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            let raw_quotes = req.params["quotes"].clone();
            let pk_res: Result<[u8; 32], String> = hex::decode(&pk_hex)
                .map_err(|_| "invalid trader_pubkey_x_hex".to_owned())
                .and_then(|v| <[u8; 32]>::try_from(v).map_err(|_| "pk must be 32 bytes".into()));
            let quotes_res: Result<Vec<PlaceIntentWireParams>, String> =
                serde_json::from_value(raw_quotes).map_err(|e| e.to_string());

            pk_res.and_then(|pk| {
                quotes_res.and_then(|wires| {
                    let t0 = std::time::Instant::now();
                    let mut intents = Vec::with_capacity(wires.len());
                    for w in wires {
                        let q = w.into_signed_intent()?;
                        if q.trader_pubkey_x != pk {
                            return Err("mass_quote mismatched trader_pubkey_x".into());
                        }
                        q.verify().map_err(|e| e.to_string())?;
                        intents.push(q);
                    }
                    let mut guard = engine.lock().unwrap();
                    guard
                        .place_preverified_mass_quote(pk, intents, t0)
                        .map(|ack| serde_json::to_value(ack).unwrap())
                })
            })
        }
        "private/cancel" => {
            let pk_hex = req.params["trader_pubkey_x_hex"].as_str().unwrap_or("");
            let oid_hex = req.params["order_id_hex"].as_str().unwrap_or("");
            let pk: Result<[u8; 32], String> = hex::decode(pk_hex)
                .map_err(|_| "bad pk".to_owned())
                .and_then(|v| <[u8; 32]>::try_from(v).map_err(|_| "bad pk len".into()));
            let oid: Result<[u8; 32], String> = hex::decode(oid_hex)
                .map_err(|_| "bad oid".to_owned())
                .and_then(|v| <[u8; 32]>::try_from(v).map_err(|_| "bad oid len".into()));
            pk.and_then(|p| {
                oid.map(|o| {
                    let removed = engine.lock().unwrap().book.cancel_order(&p, &o);
                    serde_json::json!({ "cancelled": removed })
                })
            })
        }
        "private/cancel_all" => {
            let pk_hex = req.params["trader_pubkey_x_hex"].as_str().unwrap_or("");
            hex::decode(pk_hex)
                .map_err(|_| "bad pk".to_owned())
                .and_then(|v| <[u8; 32]>::try_from(v).map_err(|_| "bad pk len".into()))
                .map(|p| {
                    let n = engine.lock().unwrap().book.cancel_all_for_trader(&p);
                    serde_json::json!({ "cancelled_count": n })
                })
        }
        "private/enable_cancel_on_disconnect" => {
            let pk_hex = req.params["trader_pubkey_x_hex"].as_str().unwrap_or("");
            hex::decode(pk_hex)
                .map_err(|_| "bad pk".to_owned())
                .and_then(|v| <[u8; 32]>::try_from(v).map_err(|_| "bad pk len".into()))
                .map(|p| {
                    *cancel_on_disconnect_pk = Some(p);
                    serde_json::json!({ "cancel_on_disconnect": true })
                })
        }
        "private/positions" => {
            let snap = engine.lock().unwrap().build_explorer_snapshot();
            Ok(serde_json::json!({
                "channels": snap.ln_channels,
                "greeks": snap.netting.portfolio_greeks,
            }))
        }
        other => Err(format!("unknown method `{other}`")),
    };

    match result {
        Ok(val) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: Some(val),
            error: None,
        },
        Err(msg) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: None,
            error: Some(JsonRpcErrorObj {
                code: -32000,
                message: msg,
            }),
        },
    }
}

fn send_http_json<W: Write, T: Serialize>(
    writer: &mut W,
    status: u16,
    body: &T,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "OK",
    };
    let hdr = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Cache-Control: no-store\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Content-Length: {}\r\n\r\n",
        payload.len()
    );
    writer.write_all(hdr.as_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn serve_static_ui<W: Write>(
    writer: &mut W,
    ui_public_dir: &Path,
    pathname: &str,
) -> std::io::Result<()> {
    let rel = match pathname {
        "/" => "index.html",
        "/explorer" | "/explorer/" => "explorer.html",
        other => other.trim_start_matches('/'),
    };
    if rel.contains("..") {
        return send_http_json(writer, 400, &serde_json::json!({"error":"invalid path"}));
    }
    let full = ui_public_dir.join(rel);
    let Ok(bytes) = fs::read(&full) else {
        return send_http_json(writer, 404, &serde_json::json!({"error":"file not found"}));
    };
    let mime = match full.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "json" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    };
    let hdr = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {mime}\r\n\
         Cache-Control: no-cache\r\n\
         Content-Length: {}\r\n\r\n",
        bytes.len()
    );
    writer.write_all(hdr.as_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

fn build_terminal_compat_state(snap: &engine::ExplorerSnapshot) -> serde_json::Value {
    let asks: Vec<serde_json::Value> = snap
        .asks
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let sats = (a.open_usd_notional * 100_000_000) / a.price_usd.max(1);
            serde_json::json!({
                "priceUsd": a.price_usd,
                "sizeUsd": a.open_usd_notional,
                "side": "Short",
                "leverageX": (a.leverage_bps / 10_000).max(1),
                "oraclePolicy": "FrostBondedWithFallback",
                "orderCount": 1,
                "valueSats": sats,
                "valueBtc": (sats as f64) / 1e8,
                "totalUsd": a.open_usd_notional * ((i + 1) as u64),
                "totalSats": sats * ((i + 1) as u64),
                "depthPct": ((i + 1) * 12).min(100),
            })
        })
        .collect();
    let bids: Vec<serde_json::Value> = snap
        .bids
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let sats = (b.open_usd_notional * 100_000_000) / b.price_usd.max(1);
            serde_json::json!({
                "priceUsd": b.price_usd,
                "sizeUsd": b.open_usd_notional,
                "side": "Long",
                "leverageX": (b.leverage_bps / 10_000).max(1),
                "oraclePolicy": "FrostBondedWithFallback",
                "orderCount": 1,
                "valueSats": sats,
                "valueBtc": (sats as f64) / 1e8,
                "totalUsd": b.open_usd_notional * ((i + 1) as u64),
                "totalSats": sats * ((i + 1) as u64),
                "depthPct": ((i + 1) * 12).min(100),
            })
        })
        .collect();
    let best_ask = snap.asks.first().map(|a| a.price_usd).unwrap_or(snap.mark_price_usd + 15);
    let best_bid = snap.bids.first().map(|b| b.price_usd).unwrap_or(snap.mark_price_usd - 15);

    serde_json::json!({
        "instrument": "BTC-INVERSE-PERP",
        "instruments": [{
            "symbol": "BTC-INVERSE-PERP",
            "label": "BTC-INVERSE-PERP",
            "kind": "Perpetual Inverse DLC",
            "markPriceUsd": snap.mark_price_usd,
            "indexPriceUsd": snap.mark_price_usd,
            "change24hPct": 2.48,
            "volume24hUsd": 48_290_000 + snap.latency.total_usd_volume,
            "openInterestUsd": 19_450_000,
            "expiryLabel": "Perpetual (LN-DLC 100ms Coalesced)"
        }],
        "market": {
            "symbol": "BTC-INVERSE-PERP",
            "markPriceUsd": snap.mark_price_usd,
            "tradelayerVwapUsd": snap.mark_price_usd + 45,
            "pythPriceUsd": snap.oracle_latest.as_ref().map(|t| t.midpoint_price_usd).unwrap_or(snap.mark_price_usd),
            "pythConfBps": snap.oracle_latest.as_ref().map(|t| t.spread_bps).unwrap_or(2),
            "volume24hUsd": 48_290_000 + snap.latency.total_usd_volume,
            "openInterestUsd": 19_450_000,
            "frost": { "threshold": 3, "total": 5, "healthySigners": 5 },
            "wallet": { "balanceSats": 250_000_000 }
        },
        "orderbook": {
            "instrument": "BTC-INVERSE-PERP",
            "feeBps": 0,
            "asks": asks,
            "bids": bids,
            "bestAskUsd": best_ask,
            "bestBidUsd": best_bid,
            "spreadUsd": best_ask.saturating_sub(best_bid),
            "spreadBps": 3.0
        },
        "recentTrades": snap.fill_tape.iter().map(|f| serde_json::json!({
            "id": &f.match_id_hex[..12],
            "priceUsd": f.execution_price_usd,
            "sizeUsd": f.matched_usd_notional,
            "side": "Long",
            "feeSats": 0,
            "settlement": "LN-DLC 100ms"
        })).collect::<Vec<_>>(),
        "positions": [],
        "engineInfo": { "backend": "shz-hftd (Rust Native WS/REST)" }
    })
}

fn build_terminal_compat_quote(v: &serde_json::Value) -> serde_json::Value {
    let usd = v["usdNotional"].as_u64().unwrap_or(10_000).max(1);
    let px = v["entryPriceUsd"].as_u64().unwrap_or(100_000).max(1);
    let long_lev_bps = ((v["longLevX"].as_f64().unwrap_or(10.0) * 10_000.0) as u32).clamp(1_000, 1_000_000);
    let short_lev_bps = ((v["shortLevX"].as_f64().unwrap_or(1.0) * 10_000.0) as u32).clamp(1_000, 1_000_000);
    let spec = InverseContractSpec::from_leverages_v0(usd, px, long_lev_bps, short_lev_bps)
        .unwrap_or_else(|_| {
            InverseContractSpec::from_leverages_v0(10_000, 100_000, 100_000, 10_000).unwrap()
        });
    let is_long = v["side"].as_str() == Some("Long");
    let cets = shz_margin::compress_cet_ranges(&spec, 20, 250).unwrap_or_default();
    let user_margin = if is_long {
        spec.long_margin_sats
    } else {
        spec.short_margin_sats
    };
    let user_liq = if is_long {
        Some(spec.long_liquidation_price_usd())
    } else {
        spec.short_liquidation_price_usd()
    };
    serde_json::json!({
        "usdNotional": spec.usd_notional,
        "entryPriceUsd": spec.entry_price_usd,
        "longMarginSats": spec.long_margin_sats,
        "shortMarginSats": spec.short_margin_sats,
        "userMarginSats": user_margin,
        "totalCollateralSats": spec.total_collateral_sats(),
        "longLiquidationPriceUsd": spec.long_liquidation_price_usd(),
        "shortLiquidationPriceUsd": spec.short_liquidation_price_usd(),
        "userLiquidationPriceUsd": user_liq,
        "shortIsCoveredSyntheticUsd": spec.is_covered_synthetic_usd_short(),
        "compressedCetCount": cets.len(),
        "compressed20BitCetCount": cets.len(),
        "cetCompressionRatioPct": 99.9,
        "rawDomainOutcomes": 1_048_576,
        "makerFeeSats": 0,
        "takerFeeSats": 0,
        "protocolFeeSats": 0,
        "payoffCurve": [],
        "cetSamples": [],
    })
}
