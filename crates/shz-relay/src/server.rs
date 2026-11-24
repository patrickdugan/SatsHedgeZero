//! Tokio runtime: collator producer, certification, scheduled delivery,
//! authenticated WebSocket subscriptions and an HTTP health/metrics/
//! checkpoint endpoint.
//!
//! WebSocket protocol (JSON text frames):
//! 1. server -> `{"type":"challenge","nonce":hex,"relay_id":hex,"server_us":u64}`
//! 2. client -> `{"type":"auth","client_id":str,"signature":hex64}` (BIP340 over
//!    `tagged_hash("SHZ/HFT06/RELAY-AUTH/V1", relay_id || nonce || client_id)`)
//! 3. client -> `{"type":"subscribe","from_seq":u64|null}`
//! 4. server -> `{"type":"ready","tier":..,"last_seq":..}` then `{"type":"packet",..Delivery}`
//!    frames; client may send `{"type":"checkpoint","seq":u64|null}`.
//!
//! A lagging client is closed with code 1008 reason "lagging"; it reconnects
//! and resumes with `from_seq` (or re-anchors from a checkpoint).

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use shz_oracle::collator::{Collator, CollatorConfig, RawReport, SlotRecord};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc},
};
use tokio_tungstenite::tungstenite::{
    Message,
    protocol::{CloseFrame, frame::coding::CloseCode},
};

use crate::{
    authority::PacketAuthority,
    client::{ClientEntry, verify_auth},
    envelope::Hash,
    hub::{Delivery, Hub},
    metrics::LogHistogram,
    schedule::{MonoClock, Tier},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Auth { client_id: String, signature: String },
    Subscribe { from_seq: Option<u64> },
    Checkpoint { seq: Option<u64> },
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Challenge { nonce: String, relay_id: String, server_us: u64 },
    Ready { tier: Tier, last_seq: Option<u64> },
    Packet(Delivery),
    Checkpoint { packet: Option<Delivery> },
    Pong { server_us: u64 },
    Error { reason: String },
}

/// Pipeline timings measured by the producer.
#[derive(Debug, Default, Clone)]
pub struct PipelineMetrics {
    /// Native verification + normalization per report.
    pub ingest_us: LogHistogram,
    /// Durable lock + signature per slot.
    pub certify_us: LogHistogram,
    pub reports: u64,
    pub rejected_reports: u64,
    pub slots: u64,
    pub valid_slots: u64,
    pub hold_slots: [u64; 3],
    pub lock_bytes: u64,
}

pub struct Shared {
    pub hub: Mutex<Hub>,
    pub clock: MonoClock,
    pub notify: Notify,
    pub relay_id: Hash,
    pub clients: BTreeMap<String, ClientEntry>,
    pub connections: Mutex<BTreeMap<String, u32>>,
    pub subscriber_queue: usize,
    pub pipeline: Mutex<PipelineMetrics>,
    pub shutdown: tokio::sync::watch::Sender<bool>,
}

/// Sleep until `target_us` on the shared monotonic clock. Coarse OS timers
/// (e.g. 15.6 ms on default Windows) are avoided for the final 2 ms by
/// yielding in a loop, so delivery timing reflects the schedule rather than
/// the platform timer granularity.
pub async fn sleep_until(clock: &MonoClock, target_us: u64) {
    loop {
        let now = clock.now_us();
        if now >= target_us {
            return;
        }
        let left = target_us - now;
        if left > 3_000 {
            tokio::time::sleep(Duration::from_micros(left - 2_000)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }
}

/// Feed reports (already in arrival order, arrival times on `clock`) to the
/// collator, close slots on time, certify and publish. Returns when the
/// report source is exhausted and `until_us` has passed.
pub async fn run_producer(
    shared: Arc<Shared>,
    cfg: CollatorConfig,
    policy: shz_oracle::hft_packets::Policy,
    mut authority: Box<dyn PacketAuthority>,
    mut reports: mpsc::Receiver<RawReport>,
    until_us: u64,
) -> Result<(), String> {
    let mut collator = Collator::new(cfg, policy).map_err(|e| e.to_string())?;
    let mut pending: Option<RawReport> = None;
    let mut source_done = false;
    loop {
        if pending.is_none() && !source_done {
            match reports.try_recv() {
                Ok(r) => pending = Some(r),
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => source_done = true,
            }
        }
        let boundary = collator.next_boundary_us();
        if boundary > until_us && (source_done || pending.is_none() && shared.clock.now_us() > until_us) {
            break;
        }
        let closed: Vec<SlotRecord> = match &pending {
            Some(r) if r.arrival_us <= boundary => {
                sleep_until(&shared.clock, r.arrival_us).await;
                let r = pending.take().unwrap();
                let t0 = shared.clock.now_us();
                let (closed, res) = collator.ingest(&r);
                let mut pm = shared.pipeline.lock().unwrap();
                pm.ingest_us.record(shared.clock.now_us() - t0);
                pm.reports += 1;
                if res.is_err() {
                    pm.rejected_reports += 1;
                }
                closed
            }
            _ => {
                // Wait for the boundary, or for a report that arrives first.
                if pending.is_none() && !source_done {
                    let wait = tokio::time::timeout(Duration::from_micros(boundary.saturating_sub(shared.clock.now_us()).max(1)), reports.recv());
                    match wait.await {
                        Ok(Some(r)) => {
                            pending = Some(r);
                            continue;
                        }
                        Ok(None) => {
                            source_done = true;
                            continue;
                        }
                        Err(_) => {}
                    }
                }
                sleep_until(&shared.clock, boundary).await;
                collator.close_through(boundary).map_err(|e| format!("{e:?}"))?
            }
        };
        for slot in closed {
            let packet = slot.packet.clone().expect("fresh slot carries packet");
            let t0 = shared.clock.now_us();
            let cert = authority.certify(&packet).map_err(|e| e.to_string())?;
            let certified_us = shared.clock.now_us();
            {
                let mut pm = shared.pipeline.lock().unwrap();
                pm.certify_us.record(certified_us - t0);
                pm.slots += 1;
                pm.lock_bytes += 80;
                match slot.hold {
                    None => pm.valid_slots += 1,
                    Some(r) => pm.hold_slots[r as usize - 1] += 1,
                }
            }
            shared.hub.lock().unwrap().publish(cert, certified_us).map_err(|e| e.to_string())?;
            shared.notify.notify_one();
        }
    }
    Ok(())
}

/// Release scheduler: deliver every due packet on time.
pub async fn run_delivery(shared: Arc<Shared>) {
    let mut stop = shared.shutdown.subscribe();
    loop {
        let next = {
            let mut hub = shared.hub.lock().unwrap();
            hub.deliver_due(shared.clock.now_us());
            hub.next_due()
        };
        match next {
            Some(t) => {
                tokio::select! {
                    _ = sleep_until(&shared.clock, t) => {}
                    _ = shared.notify.notified() => {}
                    _ = stop.changed() => return,
                }
            }
            None => {
                tokio::select! {
                    _ = shared.notify.notified() => {}
                    _ = stop.changed() => return,
                }
            }
        }
    }
}

pub async fn serve_ws(shared: Arc<Shared>, listener: TcpListener) {
    let mut stop = shared.shutdown.subscribe();
    loop {
        tokio::select! {
            r = listener.accept() => {
                if let Ok((stream, addr)) = r {
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(handle_ws(shared.clone(), stream, addr));
                }
            }
            _ = stop.changed() => return,
        }
    }
}

fn text(m: &ServerMsg) -> Message {
    Message::text(serde_json::to_string(m).expect("serializable"))
}

async fn handle_ws(shared: Arc<Shared>, stream: TcpStream, _addr: SocketAddr) {
    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
    let (mut tx, mut rx) = ws.split();
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let challenge = ServerMsg::Challenge { nonce: hex::encode(nonce), relay_id: hex::encode(shared.relay_id), server_us: shared.clock.now_us() };
    if tx.send(text(&challenge)).await.is_err() {
        return;
    }
    let read = |m: Option<Result<Message, _>>| -> Option<ClientMsg> {
        let m: Message = m?.ok()?;
        serde_json::from_str(m.to_text().ok()?).ok()
    };
    let auth = tokio::time::timeout(Duration::from_secs(5), rx.next()).await.ok().and_then(read);
    let entry: Option<ClientEntry> = match auth {
        Some(ClientMsg::Auth { client_id, signature }) => {
            let sig = hex::decode(&signature)
                .ok()
                .filter(|v| v.len() == 64)
                .map(|v| shz_dlc::Bip340Signature { r_x: v[..32].try_into().unwrap(), s: v[32..].try_into().unwrap() });
            match (shared.clients.get(&client_id), sig) {
                (Some(e), Some(sig)) if verify_auth(e, &shared.relay_id, &nonce, &sig) => Some(e.clone()),
                _ => None,
            }
        }
        _ => None,
    };
    let Some(entry) = entry else {
        shared.hub.lock().unwrap().metrics.auth_failures += 1;
        let _ = tx.send(text(&ServerMsg::Error { reason: "authentication failed".into() })).await;
        return;
    };
    let admitted = {
        let mut conns = shared.connections.lock().unwrap();
        let n = conns.entry(entry.id.clone()).or_default();
        if *n >= entry.max_connections {
            false
        } else {
            *n += 1;
            true
        }
    };
    if !admitted {
        let _ = tx.send(text(&ServerMsg::Error { reason: "connection limit".into() })).await;
        return;
    }
    let release_conn = |shared: &Shared, id: &str| {
        if let Some(n) = shared.connections.lock().unwrap().get_mut(id) {
            *n = n.saturating_sub(1);
        }
    };
    let from_seq = match tokio::time::timeout(Duration::from_secs(5), rx.next()).await.ok().and_then(read) {
        Some(ClientMsg::Subscribe { from_seq }) => from_seq,
        _ => {
            release_conn(&shared, &entry.id);
            return;
        }
    };
    let sub = shared.hub.lock().unwrap().subscribe(entry.tier, shared.subscriber_queue, from_seq, shared.clock.now_us());
    let (sub_id, mut packets) = match sub {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(text(&ServerMsg::Error { reason: e.to_string() })).await;
            release_conn(&shared, &entry.id);
            return;
        }
    };
    let last_seq = shared.hub.lock().unwrap().last().map(|l| l.0);
    let mut stop = shared.shutdown.subscribe();
    if tx.send(text(&ServerMsg::Ready { tier: entry.tier, last_seq })).await.is_ok() {
        loop {
            tokio::select! {
                _ = stop.changed() => {
                    let _ = tx.send(Message::Close(Some(CloseFrame { code: CloseCode::Away, reason: "shutdown".into() }))).await;
                    break;
                }
                d = packets.recv() => match d {
                    Some(d) => {
                        let msg = text(&ServerMsg::Packet((*d).clone()));
                        let n = msg.len() as u64;
                        if tx.send(msg).await.is_err() { break }
                        shared.hub.lock().unwrap().metrics.bytes_out += n;
                    }
                    None => {
                        let _ = tx.send(Message::Close(Some(CloseFrame { code: CloseCode::Policy, reason: "lagging".into() }))).await;
                        break;
                    }
                },
                m = rx.next() => match read(m) {
                    Some(ClientMsg::Checkpoint { seq }) => {
                        let cp = shared.hub.lock().unwrap().checkpoint(entry.tier, seq, shared.clock.now_us()).map(|d| (*d).clone());
                        if tx.send(text(&ServerMsg::Checkpoint { packet: cp })).await.is_err() { break }
                    }
                    Some(ClientMsg::Ping) => {
                        if tx.send(text(&ServerMsg::Pong { server_us: shared.clock.now_us() })).await.is_err() { break }
                    }
                    Some(_) => {}
                    None => break,
                },
            }
        }
    }
    shared.hub.lock().unwrap().drop_sub(sub_id, false);
    release_conn(&shared, &entry.id);
}

/// Minimal read-only HTTP/1.1: `/healthz`, `/metrics`,
/// `/v1/checkpoint/latest`, `/v1/checkpoint/<seq>` (public = standard tier).
pub async fn serve_http(shared: Arc<Shared>, listener: TcpListener) {
    let mut stop = shared.shutdown.subscribe();
    loop {
        tokio::select! {
            r = listener.accept() => {
                if let Ok((mut s, _)) = r {
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 2048];
                        let n = match tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await { Ok(Ok(n)) => n, _ => return };
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                        let (code, ctype, body) = route(&shared, req.starts_with("GET "), &path);
                        let resp = format!("HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = s.write_all(resp.as_bytes()).await;
                    });
                }
            }
            _ = stop.changed() => return,
        }
    }
}

fn route(shared: &Shared, get: bool, path: &str) -> (&'static str, &'static str, String) {
    if !get {
        return ("405 Method Not Allowed", "text/plain", "GET only\n".into());
    }
    let now = shared.clock.now_us();
    match path {
        "/healthz" => {
            let hub = shared.hub.lock().unwrap();
            let last = hub.last().map(|l| l.0);
            let m = &hub.metrics;
            let body = serde_json::json!({
                "status": "ok",
                "last_seq": last,
                "published": m.published,
                "late_certificates": m.late_certificates,
                "equivocations": m.equivocations,
                "subscribers": m.active_subscribers,
                "wall_clock_offset_us": shared.clock.wall_offset_us(),
                "production_ready": false,
            });
            ("200 OK", "application/json", body.to_string())
        }
        "/metrics" => {
            let mut s = shared.hub.lock().unwrap().metrics.prometheus();
            let pm = shared.pipeline.lock().unwrap();
            s.push_str(&format!("shz_collator_reports_total {}\nshz_collator_rejected_reports_total {}\nshz_collator_slots_total {}\nshz_collator_valid_slots_total {}\n", pm.reports, pm.rejected_reports, pm.slots, pm.valid_slots));
            ("200 OK", "text/plain; version=0.0.4", s)
        }
        p if p.starts_with("/v1/checkpoint/") => {
            let arg = &p["/v1/checkpoint/".len()..];
            let seq = if arg == "latest" { None } else { match arg.parse() { Ok(s) => Some(s), Err(_) => return ("400 Bad Request", "text/plain", "bad seq\n".into()) } };
            match shared.hub.lock().unwrap().checkpoint(Tier::Standard, seq, now) {
                Some(d) => ("200 OK", "application/json", serde_json::to_string(&*d).unwrap()),
                None => ("404 Not Found", "text/plain", "not released or not retained\n".into()),
            }
        }
        _ => ("404 Not Found", "text/plain", "not found\n".into()),
    }
}
