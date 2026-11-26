//! shz-venue: testnet trading venue on the HFT-06 tiered router.
//!
//!   shz-venue [--listen 127.0.0.1:8095] [--state ./venue-state] [--ui ui/venue]
//!             [--relay http://170.75.168.145:8091]
//!             [--group-key 403c4966...fdb8]
//!             [--mempool-api https://mempool.space/testnet4/api]

mod core;
mod feed;
mod http;
mod wallet;

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::{Mutex, broadcast};

const DEFAULT_GROUP_KEY: &str = "403c496669cba966c14d989711a2a16026c7c295305301e5c61b96eb718cfdb8";

fn args() -> BTreeMap<String, String> {
    let v: Vec<String> = std::env::args().skip(1).collect();
    v.chunks(2).filter_map(|c| Some((c.first()?.trim_start_matches("--").to_string(), c.get(1).cloned().unwrap_or_default()))).collect()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let a = args();
    let listen = a.get("listen").cloned().unwrap_or("127.0.0.1:8095".into());
    let state = PathBuf::from(a.get("state").cloned().unwrap_or("venue-state".into()));
    let ui = PathBuf::from(a.get("ui").cloned().unwrap_or("ui/venue".into()));
    let relay = a.get("relay").cloned().unwrap_or("http://170.75.168.145:8091".into());
    let group = core::parse_key(a.get("group-key").map(String::as_str).unwrap_or(DEFAULT_GROUP_KEY)).expect("group key: 32-byte hex");
    let mempool = a.get("mempool-api").cloned().unwrap_or("https://mempool.space/testnet4/api".into());

    let venue = match core::Venue::open(&state, group, relay.clone()) {
        Ok(v) => Arc::new(Mutex::new(v)),
        Err(e) => {
            eprintln!("open venue: {e}");
            std::process::exit(1)
        }
    };
    let (events, _) = broadcast::channel::<String>(4_096);
    tokio::spawn(feed::run(venue.clone(), relay.clone(), events.clone()));

    // Matching and settlement tick.
    {
        let venue = venue.clone();
        let events = events.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(20));
            loop {
                iv.tick().await;
                let mut v = venue.lock().await;
                if let Err(e) = v.tick() {
                    eprintln!("tick: {e}");
                }
                for e in v.drain_events() {
                    let _ = events.send(e);
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap_or_else(|e| {
        eprintln!("listen {listen}: {e}");
        std::process::exit(1)
    });
    eprintln!("shz-venue {} relay={relay} state={} ui={} network=testnet4 production_ready=false", listener.local_addr().unwrap(), state.display(), ui.display());
    let app = Arc::new(http::App { venue, events, ui_dir: ui, mempool_api: mempool });
    tokio::select! {
        _ = http::serve(app, listener) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
