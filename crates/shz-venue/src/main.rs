//! shz-venue: testnet trading venue on the HFT-06 tiered router.
//!
//!   shz-venue [--listen 127.0.0.1:8095] [--state ./venue-state] [--ui ui/venue]
//!             [--relay http://170.75.168.145:8091]
//!             [--group-key 403c4966...fdb8]
//!             [--mempool-api https://mempool.space/testnet4/api]
//!             [--options [--stable-usdt <RGB contract id, 32-byte hex>] [--spot]] [--agents]
//!
//! Options are off unless `--options` is given. Switching them on journals EnableOptions,
//! EnableCombos and EnableOptionAcks (and RegisterStable for `--stable-usdt`) in the router
//! journal of the state dir; series list from the relay's announced DLC events.
//! `--spot` (needs `--options --stable-usdt`) journals EnableSpot and ListSpotPair: the
//! BTC/USDT spot market on the options desk (docs/SHZ_SPOT.md). Off by default.
//! `--agents` journals EnableAgents once and opens the agent API's write methods
//! (docs/SHZ_AGENT_API.md): owner-signed grants for delegated agent keys. Off by default;
//! the agent API's read methods are served either way.
//!
//!   [--collateral-chain regtest|testnet4 --bitcoind-rpc http://127.0.0.1:18443
//!    --bitcoind-auth-file <file: user:password, or a .cookie> --batcher-key <x-only hex>
//!    [--refund-blocks 432] [--min-conf 1] [--min-lock refund-blocks/2] [--chain-poll-ms 15000]]
//!
//! `--collateral-chain` replaces demo credit with on-chain collateral accounts
//! (docs/SHZ_MVP_COLLATERAL.md): deposit addresses `account(T, B, h)`, a bitcoind watcher that
//! credits deposits after `--min-conf`, per-epoch settlement packages the owners co-sign, and
//! withdrawals paid by the next settlement. Demo registration is refused while it is on.

mod agent_api;
mod core;
mod feed;
mod http;
mod risk;
mod wallet;

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::{Mutex, broadcast};

const DEFAULT_GROUP_KEY: &str = "403c496669cba966c14d989711a2a16026c7c295305301e5c61b96eb718cfdb8";

/// `--key value` pairs; a `--flag` followed by another `--key` (or nothing) has an empty value.
fn args() -> BTreeMap<String, String> {
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < v.len() {
        let k = v[i].trim_start_matches("--").to_string();
        match v.get(i + 1).filter(|x| !x.starts_with("--")) {
            Some(x) => {
                out.insert(k, x.clone());
                i += 2;
            }
            None => {
                out.insert(k, String::new());
                i += 1;
            }
        }
    }
    out
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
    if a.contains_key("options") {
        let usdt = match a.get("stable-usdt").map(|s| core::parse_key(s)) {
            None => None,
            Some(Ok(k)) => Some(k),
            Some(Err(e)) => {
                eprintln!("--stable-usdt: {e}");
                std::process::exit(1)
            }
        };
        match venue.lock().await.options_enable(usdt) {
            Ok(s) => eprintln!("options on: {s}"),
            Err(e) => {
                eprintln!("options: {e}");
                std::process::exit(1)
            }
        }
        tokio::spawn(feed::run_options(venue.clone(), relay.clone(), events.clone()));
    } else if a.contains_key("stable-usdt") {
        eprintln!("--stable-usdt needs --options");
        std::process::exit(1)
    }
    if a.contains_key("spot") {
        // Spot lives on the options desk and trades BTC against the demo USDT asset.
        match venue.lock().await.spot_enable() {
            Ok(s) => eprintln!("spot on: {s}"),
            Err(e) => {
                eprintln!("spot: {e}");
                std::process::exit(1)
            }
        }
    }
    if a.contains_key("agents") {
        match venue.lock().await.agents_enable() {
            Ok(s) => eprintln!("agents on: {s}"),
            Err(e) => {
                eprintln!("agents: {e}");
                std::process::exit(1)
            }
        }
    }
    if let Some(chain) = a.get("collateral-chain") {
        let cfg = collateral_cfg(&a, chain).unwrap_or_else(|e| {
            eprintln!("collateral: {e}");
            std::process::exit(1)
        });
        match venue.lock().await.collateral_enable(cfg) {
            Ok(s) => eprintln!("collateral on: {s}"),
            Err(e) => {
                eprintln!("collateral: {e}");
                std::process::exit(1)
            }
        }
        tokio::spawn(core::collateral::run(venue.clone()));
    }
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
    let network = venue.lock().await.coll.as_ref().map(|c| c.cfg.net.name()).unwrap_or("testnet4");
    eprintln!("shz-venue {} relay={relay} state={} ui={} network={network} production_ready=false", listener.local_addr().unwrap(), state.display(), ui.display());
    let app = Arc::new(http::App { venue, events, ui_dir: ui, mempool_api: mempool, agent: Default::default() });
    tokio::spawn(agent_api::run_bus(app.clone()));
    tokio::select! {
        _ = http::serve(app, listener) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

fn collateral_cfg(a: &BTreeMap<String, String>, chain: &str) -> Result<core::collateral::ChainCfg, String> {
    let net = core::collateral::Net::parse(chain)?;
    let rpc_url = a.get("bitcoind-rpc").cloned().ok_or("--bitcoind-rpc required")?;
    let auth_file = a.get("bitcoind-auth-file").ok_or("--bitcoind-auth-file required")?;
    let rpc_auth = std::fs::read_to_string(auth_file).map_err(|e| format!("--bitcoind-auth-file: {e}"))?.trim().to_string();
    if !rpc_auth.contains(':') {
        return Err("--bitcoind-auth-file must hold user:password (or a bitcoind .cookie)".into());
    }
    let batcher = core::parse_key(a.get("batcher-key").ok_or("--batcher-key required")?)?;
    shz_dlc::lift_x_even(&batcher).map_err(|_| "--batcher-key is not a valid x-only key")?;
    let n = |k: &str, d: u64| -> Result<u64, String> { a.get(k).map(|s| s.parse::<u64>().map_err(|_| format!("--{k}: number"))).unwrap_or(Ok(d)) };
    let refund_blocks = n("refund-blocks", 432)? as u32;
    let min_lock = n("min-lock", refund_blocks as u64 / 2)? as u32;
    if min_lock == 0 || min_lock > refund_blocks {
        return Err("--min-lock must be in 1..=refund-blocks".into());
    }
    Ok(core::collateral::ChainCfg { net, rpc_url, rpc_auth, rpc_auth_file: Some(auth_file.clone()), batcher, refund_blocks, min_conf: n("min-conf", 1)?.max(1) as u32, min_lock, poll_ms: n("chain-poll-ms", 15_000)? })
}
