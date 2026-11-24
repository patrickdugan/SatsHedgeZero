//! Assemble and start a relay from a [`RelayConfig`].

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use shz_oracle::collator::{CollatorConfig, RawReport, fixture};
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};

use crate::{
    authority::{DurableSignLock, LocalFederation, PacketAuthority, TrustedRelaySigner, ensure_key_separation},
    config::{ENV_DEV_FEDERATION, RelayConfig, SourceConfig, h32, relay_signing_key},
    envelope::{Hash, PacketVerifier, SecurityMode},
    hub::Hub,
    schedule::MonoClock,
    server::{PipelineMetrics, Shared, run_delivery, run_producer, serve_http, serve_ws},
};

pub struct RunningRelay {
    pub ws_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub shared: Arc<Shared>,
    pub policy: shz_oracle::hft_packets::Policy,
    pub verifier: PacketVerifier,
    pub producer: JoinHandle<Result<(), String>>,
    pub tasks: Vec<JoinHandle<()>>,
}

impl RunningRelay {
    pub fn shutdown(&self) {
        let _ = self.shared.shutdown.send(true);
    }
}

pub struct StartOptions {
    /// Stop producing after this many seconds of slots (None = run forever).
    pub run_seconds: Option<u64>,
    /// Signing key override (benchmarks/tests); production reads env.
    pub relay_key: Option<Hash>,
    /// Collator config override (live mode builds it from the config file).
    pub collator: Option<CollatorConfig>,
}

fn relay_id(policy_id: &Hash, relay_key: &Hash) -> Hash {
    let mut b = policy_id.to_vec();
    b.extend(relay_key);
    shz_dlc::tagged_hash(b"SHZ/HFT06/RELAY-ID/V1", &b)
}

pub async fn start(cfg: RelayConfig, opts: StartOptions) -> Result<RunningRelay, String> {
    std::fs::create_dir_all(&cfg.state_dir).map_err(|e| format!("state_dir: {e}"))?;
    // Clock and slot origin. Recorded data keeps its signed timestamps, so the
    // relay runs on a monotonic clock anchored in recorded time.
    let (clock, origin, reports): (MonoClock, u64, Vec<RawReport>) = match &cfg.source {
        SourceConfig::Synthetic { .. } => {
            let clock = MonoClock::new();
            let origin = if cfg.policy.origin_us != 0 { cfg.policy.origin_us } else { (clock.now_us() / 1_000_000 + 2) * 1_000_000 };
            (clock, origin, Vec::new())
        }
        SourceConfig::Recorded { path, recorded_origin_us } => {
            let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let reports: Vec<RawReport> = raw.lines().filter(|l| !l.trim().is_empty()).map(serde_json::from_str).collect::<Result<_, _>>().map_err(|e| format!("recording: {e}"))?;
            let first = reports.first().map(|r| r.arrival_us).ok_or("empty recording")?;
            (MonoClock::at(first.saturating_sub(500_000)), *recorded_origin_us, reports)
        }
        SourceConfig::Live { .. } => {
            #[cfg(not(feature = "live"))]
            return Err("live source requires building with --features live".into());
            #[cfg(feature = "live")]
            {
                let clock = MonoClock::new();
                let origin = if cfg.policy.origin_us != 0 { cfg.policy.origin_us } else { (clock.now_us() / 1_000_000 + 2) * 1_000_000 };
                (clock, origin, Vec::new())
            }
        }
    };
    let policy = cfg.packet_policy(origin)?;
    let policy_id = policy.id().map_err(|e| format!("{e:?}"))?;
    let collator_cfg = match (&opts.collator, &cfg.source) {
        (Some(c), _) => c.clone(),
        (None, SourceConfig::Live { .. }) => {
            #[cfg(feature = "live")]
            {
                crate::live::collator_config(&cfg.source)?
            }
            #[cfg(not(feature = "live"))]
            unreachable!()
        }
        (None, _) => fixture::config(),
    };

    let (authority, verifier, key_for_id): (Box<dyn PacketAuthority>, PacketVerifier, Hash) = match cfg.mode {
        SecurityMode::TrustedRelay => {
            let sk = match opts.relay_key {
                Some(k) => k,
                None => relay_signing_key()?,
            };
            let lock = DurableSignLock::open(&cfg.state_dir.join("relay-signer.lock")).map_err(|e| e.to_string())?;
            let signer = TrustedRelaySigner::new(&policy, sk, lock).map_err(|e| e.to_string())?;
            let pk = signer.public_key();
            if let Some(g) = &cfg.frost_maturity_group_key {
                ensure_key_separation(&h32(g)?, &[pk]).map_err(|e| e.to_string())?;
            }
            (Box::new(signer), PacketVerifier::trusted(policy.clone(), pk).map_err(|e| e.to_string())?, pk)
        }
        SecurityMode::Federated => {
            if std::env::var(ENV_DEV_FEDERATION).as_deref() != Ok("1") {
                return Err(format!(
                    "federated mode: member vote transport is an external gate; set {ENV_DEV_FEDERATION}=1 to run the five fixture signers in-process (development only)"
                ));
            }
            if let Some(g) = &cfg.frost_maturity_group_key {
                ensure_key_separation(&h32(g)?, &policy.members).map_err(|e| e.to_string())?;
            }
            let fed = LocalFederation::new(&policy, &fixture::FEDERATION_SECRETS, &cfg.state_dir.join("federation")).map_err(|e| e.to_string())?;
            (Box::new(fed), PacketVerifier::federated(policy.clone()).map_err(|e| e.to_string())?, policy.members[0])
        }
    };

    let mut hub = Hub::new(verifier.clone(), cfg.release, cfg.history);
    hub.attach_log(&cfg.state_dir.join(format!("checkpoints-{}.jsonl", hex::encode(&policy_id[..8])))).map_err(|e| e.to_string())?;
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let shared = Arc::new(Shared {
        hub: Mutex::new(hub),
        clock,
        notify: Default::default(),
        relay_id: relay_id(&policy_id, &key_for_id),
        clients: cfg.clients.iter().map(|c| (c.id.clone(), c.clone())).collect::<BTreeMap<_, _>>(),
        connections: Mutex::new(BTreeMap::new()),
        subscriber_queue: cfg.subscriber_queue,
        pipeline: Mutex::new(PipelineMetrics::default()),
        shutdown,
    });

    let ws = TcpListener::bind(&cfg.ws_listen).await.map_err(|e| format!("ws_listen {}: {e}", cfg.ws_listen))?;
    let http = TcpListener::bind(&cfg.http_listen).await.map_err(|e| format!("http_listen {}: {e}", cfg.http_listen))?;
    let ws_addr = ws.local_addr().map_err(|e| e.to_string())?;
    let http_addr = http.local_addr().map_err(|e| e.to_string())?;

    let (rtx, rrx) = mpsc::channel::<RawReport>(4_096);
    match &cfg.source {
        SourceConfig::Live { .. } => {
            #[cfg(feature = "live")]
            crate::live::spawn_connectors(&cfg.source, shared.clock, rtx)?;
        }
        SourceConfig::Synthetic { seed } => {
            // Generate signed synthetic reports in 10 s chunks ahead of time.
            let (seed, end) = (*seed, opts.run_seconds.map(|s| origin + (s + 1) * 1_000_000).unwrap_or(u64::MAX));
            tokio::task::spawn_blocking(move || {
                let mut from = origin.saturating_sub(400_000);
                while from < end {
                    let to = (from + 10_000_000).min(end);
                    for r in fixture::recording_range(origin, from, to, seed) {
                        if rtx.blocking_send(r).is_err() {
                            return;
                        }
                    }
                    from = to;
                }
            });
        }
        SourceConfig::Recorded { .. } => {
            tokio::spawn(async move {
                for r in reports {
                    if rtx.send(r).await.is_err() {
                        break;
                    }
                }
            });
        }
    }
    let until = opts.run_seconds.map(|s| origin + s * 1_000_000).unwrap_or(u64::MAX);
    let producer = tokio::spawn(run_producer(shared.clone(), collator_cfg, policy.clone(), authority, rrx, until));
    let tasks = vec![
        tokio::spawn(run_delivery(shared.clone())),
        tokio::spawn(serve_ws(shared.clone(), ws)),
        tokio::spawn(serve_http(shared.clone(), http)),
    ];
    Ok(RunningRelay { ws_addr, http_addr, shared, policy, verifier, producer, tasks })
}

/// Deterministic offline replay (CI): returns the closed slots and stats.
pub fn replay(cfg: CollatorConfig, policy: shz_oracle::hft_packets::Policy, reports: &[RawReport]) -> Result<(Vec<shz_oracle::collator::SlotRecord>, shz_oracle::collator::Collator), String> {
    let mut c = shz_oracle::collator::Collator::new(cfg, policy).map_err(|e| e.to_string())?;
    let mut slots = Vec::new();
    for r in reports {
        slots.extend(c.ingest(r).0);
    }
    if let Some(last) = reports.last() {
        slots.extend(c.close_through(last.arrival_us).map_err(|e| format!("{e:?}"))?);
    }
    Ok((slots, c))
}

pub fn load_recording(path: &Path) -> Result<Vec<RawReport>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    raw.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).map_err(|e| format!("recording: {e}"))).collect()
}
