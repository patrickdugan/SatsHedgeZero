//! Oracle mark feed: reads the FROST relay's Server-Sent Events stream and
//! hands the router only packets whose group signature verifies.

use std::{sync::Arc, time::Duration};

use serde_json::Value;
use shz_dlc::{Bip340Signature, bip340_verify, tagged_hash};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{Mutex, broadcast},
};

use crate::core::{Key, PacketRec, Venue, now_us, parse_key};

const SIGNING_TAG: &[u8] = b"SHZ/PUBLIC-RELAY-PACKET/V1";

/// Verify one relay packet: digest = tagged hash of the canonical body (serde_json
/// maps are sorted, matching the relay's `sort_keys` + compact separators), BIP340
/// signature under the pinned group key.
pub fn verify_packet(pkt: &Value, group: &Key) -> Result<PacketRec, String> {
    let body = &pkt["body"];
    let canonical = serde_json::to_string(body).map_err(|e| e.to_string())?;
    let msg = tagged_hash(SIGNING_TAG, canonical.as_bytes());
    if pkt["digest"].as_str() != Some(hex::encode(msg).as_str()) {
        return Err("digest does not match the body".into());
    }
    let sig = hex::decode(pkt["signature"].as_str().unwrap_or("")).map_err(|_| "bad signature hex")?;
    if sig.len() != 64 {
        return Err("bad signature length".into());
    }
    let sig = Bip340Signature { r_x: sig[..32].try_into().unwrap(), s: sig[32..].try_into().unwrap() };
    bip340_verify(group, &msg, &sig).map_err(|_| "group signature does not verify")?;
    let status = body["status"].as_str().unwrap_or("HOLD").to_string();
    Ok(PacketRec {
        seq: body["seq"].as_u64().ok_or("missing seq")?,
        slot_us: body["slot_us"].as_u64().ok_or("missing slot_us")?,
        median_e8: if status == "VALID" { body["median_e8"].as_u64() } else { None },
        status,
        digest: msg,
        signers: pkt["frost_signers"].clone(),
        verified: true,
        received_us: now_us(),
    })
}

fn split_url(url: &str) -> Result<(String, String), String> {
    let rest = url.strip_prefix("http://").ok_or("relay URL must be http:// (packets are verified by signature)")?;
    let (host, path) = rest.split_once('/').map(|(h, p)| (h.to_string(), format!("/{p}"))).unwrap_or((rest.to_string(), "/".into()));
    Ok((host, path.trim_end_matches('/').to_string()))
}

async fn get_json(host: &str, path: &str) -> Result<Value, String> {
    let mut s = TcpStream::connect(host).await.map_err(|e| e.to_string())?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf).await.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|x| x.1).ok_or("bad response")?;
    serde_json::from_str(body).map_err(|e| e.to_string())
}

/// Proxy helper for the explorer (DLC events live on the relay).
pub async fn relay_get(relay: &str, path: &str) -> Result<Value, String> {
    let (host, base) = split_url(relay)?;
    get_json(&host, &format!("{base}{path}")).await
}

pub async fn run(venue: Arc<Mutex<Venue>>, relay: String, events: broadcast::Sender<String>) {
    let Ok((host, base)) = split_url(&relay) else { return };
    let mut backoff = 1u64;
    loop {
        // Pin check: the relay's advertised key must equal the configured group key.
        let group = venue.lock().await.group_key;
        match get_json(&host, &format!("{base}/v1/pubkey")).await {
            Ok(v) if v["pubkey_bip340"].as_str().and_then(|s| parse_key(s).ok()) == Some(group) => {}
            Ok(v) => {
                eprintln!("relay advertises key {} but the venue pins {}; refusing its packets", v["pubkey_bip340"], hex::encode(group));
            }
            Err(e) => eprintln!("relay pubkey: {e}"),
        }
        if let Ok(latest) = get_json(&host, &format!("{base}/v1/latest")).await {
            ingest(&venue, &events, &latest, &group).await;
        }
        match TcpStream::connect(&host).await {
            Ok(mut s) => {
                let req = format!("GET {base}/v1/stream HTTP/1.1\r\nHost: {host}\r\nAccept: text/event-stream\r\n\r\n");
                if s.write_all(req.as_bytes()).await.is_ok() {
                    backoff = 1;
                    let mut lines = BufReader::new(s).lines();
                    while let Ok(Ok(Some(line))) = tokio::time::timeout(Duration::from_secs(45), lines.next_line()).await {
                        if let Some(data) = line.strip_prefix("data: ")
                            && let Ok(pkt) = serde_json::from_str::<Value>(data)
                        {
                            ingest(&venue, &events, &pkt, &group).await;
                        }
                    }
                }
            }
            Err(e) => eprintln!("relay connect: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

async fn ingest(venue: &Arc<Mutex<Venue>>, events: &broadcast::Sender<String>, pkt: &Value, group: &Key) {
    match verify_packet(pkt, group) {
        Ok(p) => {
            let mut v = venue.lock().await;
            if let Err(e) = v.ingest_packet(p) {
                eprintln!("{e}");
            }
            for e in v.drain_events() {
                let _ = events.send(e);
            }
        }
        Err(e) => eprintln!("rejected relay packet: {e}"),
    }
}
