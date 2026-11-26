//! Live provider connectors (feature `live`). Credentials come only from the
//! environment. Each received frame is stamped with the shared monotonic
//! clock on receipt and forwarded raw; authentication happens in the
//! collator with the pinned registries from the configuration.
//!
//! Wire assumptions (from provider documentation; not exercised against the
//! live services in this repository because no credentials are available):
//! * Pyth Pro/Lazer: `GET <pyth_url>` with `Authorization: Bearer <token>`,
//!   subscribe `{"type":"subscribe","subscriptionId":1,"priceFeedIds":[1],
//!   "properties":["price","exponent","confidence","feedUpdateTimestamp"],
//!   "formats":["solana"],"deliveryFormat":"json","channel":"fixed_rate@200ms",
//!   "jsonBinaryEncoding":"hex"}`; updates carry `solana.data` (hex).
//! * Chainlink Data Streams: `GET <chainlink_url>?feedIDs=<id>` with HMAC
//!   headers; messages carry `report.fullReport` (0x-hex).

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use shz_oracle::{
    chainlink_streams::{ChainlinkStreamPolicy, PinnedDonRegistry, data_streams_auth_signature},
    collator::{CollatorConfig, RawReport, SourceKind},
    pyth_lazer::{PinnedPythSignerRegistry, PythProBtcUsdPolicy},
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};

use crate::{
    config::{ENV_CHAINLINK_ID, ENV_CHAINLINK_SECRET, ENV_PYTH_TOKEN, SourceConfig, h32},
    schedule::MonoClock,
};

pub fn collator_config(src: &SourceConfig) -> Result<CollatorConfig, String> {
    let SourceConfig::Live { chainlink_feed_id, pyth_signers, chainlink_don, .. } = src else { return Err("not a live source".into()) };
    let signers = pyth_signers.iter().map(|s| h32(s)).collect::<Result<Vec<_>, _>>()?;
    Ok(CollatorConfig {
        pyth_registry: PinnedPythSignerRegistry::new_static(signers).map_err(|e| e.to_string())?,
        pyth_policy: PythProBtcUsdPolicy::default(),
        chainlink_registry: PinnedDonRegistry::new(chainlink_don.clone()).map_err(|e| e.to_string())?,
        chainlink_policy: ChainlinkStreamPolicy { feed_id: h32(chainlink_feed_id)?, max_age_us: 3_000_000, max_future_skew_us: 100_000, max_spread_bps: 50 },
        max_future_skew_us: 100_000,
        retain_slots: 10_000,
    })
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing environment variable {name}"))
}

pub fn spawn_connectors(src: &SourceConfig, clock: MonoClock, tx: mpsc::Sender<RawReport>) -> Result<(), String> {
    let SourceConfig::Live { pyth_url, chainlink_url, chainlink_feed_id, .. } = src else { return Err("not a live source".into()) };
    let token = env(ENV_PYTH_TOKEN)?;
    let cl_id = env(ENV_CHAINLINK_ID)?;
    let cl_secret = env(ENV_CHAINLINK_SECRET)?;
    tokio::spawn(pyth_loop(pyth_url.clone(), token, clock, tx.clone()));
    tokio::spawn(chainlink_loop(chainlink_url.clone(), chainlink_feed_id.clone(), cl_id, cl_secret, clock, tx));
    Ok(())
}

async fn backoff(attempt: &mut u32) {
    let ms = (250u64 << (*attempt).min(6)).min(15_000);
    *attempt += 1;
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

async fn pyth_loop(url: String, token: String, clock: MonoClock, tx: mpsc::Sender<RawReport>) {
    let mut attempt = 0;
    loop {
        let Ok(mut req) = url.as_str().into_client_request() else { return };
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
            req.headers_mut().insert("Authorization", v);
        }
        if let Ok((mut ws, _)) = tokio_tungstenite::connect_async(req).await {
            attempt = 0;
            let sub = serde_json::json!({
                "type": "subscribe", "subscriptionId": 1, "priceFeedIds": [1],
                "properties": ["price", "exponent", "confidence", "feedUpdateTimestamp"],
                "formats": ["solana"], "deliveryFormat": "json", "channel": "fixed_rate@200ms",
                "jsonBinaryEncoding": "hex"
            });
            if ws.send(Message::text(sub.to_string())).await.is_ok() {
                while let Some(Ok(m)) = ws.next().await {
                    let arrival_us = clock.now_us();
                    let Ok(t) = m.to_text() else { continue };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(t) else { continue };
                    if let Some(hexdata) = v.pointer("/solana/data").and_then(|d| d.as_str()) {
                        if let Ok(bytes) = hex::decode(hexdata) {
                            if tx.send(RawReport { source: SourceKind::PythPro, arrival_us, bytes }).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
        backoff(&mut attempt).await;
    }
}

async fn chainlink_loop(base: String, feed: String, id: String, secret: String, clock: MonoClock, tx: mpsc::Sender<RawReport>) {
    let mut attempt = 0;
    loop {
        let url = format!("{base}?feedIDs={feed}");
        let path = url.find("/api/").map(|i| url[i..].to_string()).unwrap_or_else(|| format!("/api/v1/ws?feedIDs={feed}"));
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        let sig = data_streams_auth_signature("GET", &path, b"", &id, ts, secret.as_bytes());
        let Ok(mut req) = url.as_str().into_client_request() else { return };
        for (k, v) in [("Authorization", id.clone()), ("X-Authorization-Timestamp", ts.to_string()), ("X-Authorization-Signature-SHA256", sig)] {
            if let Ok(v) = HeaderValue::from_str(&v) {
                req.headers_mut().insert(k, v);
            }
        }
        if let Ok((mut ws, _)) = tokio_tungstenite::connect_async(req).await {
            attempt = 0;
            while let Some(Ok(m)) = ws.next().await {
                let arrival_us = clock.now_us();
                let Ok(t) = m.to_text() else { continue };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(t) else { continue };
                if let Some(full) = v.pointer("/report/fullReport").and_then(|d| d.as_str()) {
                    if let Ok(bytes) = hex::decode(full.trim_start_matches("0x")) {
                        if tx.send(RawReport { source: SourceKind::ChainlinkStreams, arrival_us, bytes }).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
        backoff(&mut attempt).await;
    }
}
