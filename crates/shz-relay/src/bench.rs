//! End-to-end loopback benchmark: synthetic signed reports -> native
//! verification/normalization -> 200 ms slot -> durable certification ->
//! tiered release -> authenticated WebSocket delivery -> client signature
//! verification. All timestamps come from ONE monotonic clock in one
//! process, so cross-host clock uncertainty is NOT measured here.

use std::{collections::BTreeMap, time::Duration};

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio_tungstenite::tungstenite::Message;

use crate::{
    client::{ClientEntry, TieredReceiver, sign_auth},
    config::{PolicyConfig, RelayConfig, SourceConfig},
    envelope::{CertifiedPacket, SecurityMode},
    metrics::{Summary, exact_summary},
    schedule::{ReleasePolicy, Tier},
    server::{ClientMsg, ServerMsg},
    service::{StartOptions, start},
};

#[derive(Debug, Clone)]
pub struct BenchOptions {
    pub clients_per_tier: usize,
    pub seconds: u64,
    pub mode: SecurityMode,
    pub release: ReleasePolicy,
    pub state_dir: std::path::PathBuf,
    /// One client per tier is made slow (sleeps per message) to exercise backpressure.
    pub slow_client: bool,
    /// Federated mode over the network vote transport: five member tasks
    /// (own collator, own lock, own key) connect to the relay over loopback
    /// WebSockets instead of the in-process development signers.
    pub remote_members: bool,
}

#[derive(Debug, Serialize)]
pub struct FederationReceipt {
    pub transport: &'static str,
    pub members: usize,
    pub certified: u64,
    pub quorum_timeouts: u64,
    pub skipped_slots: u64,
    pub votes_accepted: u64,
    pub disagreements: u64,
    pub refusals: u64,
    pub equivocations: u64,
}

#[derive(Debug, Serialize)]
pub struct TierResult {
    pub clients: usize,
    pub received: u64,
    pub expected: u64,
    pub lost: u64,
    pub verify_failures: u64,
    /// Client receive time minus slot boundary.
    pub recv_after_boundary: Summary,
    /// Client receive time minus scheduled release.
    pub recv_after_release: Summary,
    /// Client-side signature verification time.
    pub client_verify: Summary,
}

#[derive(Debug, Serialize)]
pub struct BenchReceipt {
    pub schema: &'static str,
    pub synthetic: bool,
    pub production_ready: bool,
    pub platform: String,
    pub mode: SecurityMode,
    pub release: ReleasePolicy,
    pub seconds: u64,
    pub slots: u64,
    pub valid_slots: u64,
    pub hold_slots: [u64; 3],
    pub reports: u64,
    pub rejected_reports: u64,
    pub ingest_verify_normalize: Summary,
    /// Proposal broadcast to quorum certificate (remote) or lock + signatures (local).
    pub certify_durable: Summary,
    /// Slot boundary to certificate formed (what the premium tier waits for).
    pub certify_after_boundary: Summary,
    pub federation: Option<FederationReceipt>,
    pub server_send_after_release: BTreeMap<&'static str, Summary>,
    pub tiers: BTreeMap<&'static str, TierResult>,
    /// Per-sequence realized lead, first receiving client of each tier.
    pub realized_lead_premium_vs_standard: Summary,
    pub realized_lead_premium_vs_intermediate: Summary,
    pub realized_lead_intermediate_vs_standard: Summary,
    pub deliveries_per_second: f64,
    pub bytes_out: u64,
    pub bytes_per_delivery: f64,
    pub checkpoint_log_bytes_per_slot: f64,
    pub signer_lock_bytes_per_slot: f64,
    pub lagging_disconnects: u64,
    pub late_certificates: u64,
    pub clock_uncertainty_note: &'static str,
}

struct ClientRecord {
    tier: Tier,
    first_seq: Option<u64>,
    last_seq: u64,
    seqs: Vec<u64>,
    recv: BTreeMap<u64, u64>,
    after_boundary: Vec<u64>,
    after_release: Vec<u64>,
    verify: Vec<u64>,
    verify_failures: u64,
}

pub async fn run(opts: BenchOptions) -> Result<BenchReceipt, String> {
    let _ = std::fs::remove_dir_all(&opts.state_dir);
    let fixture_policy = shz_oracle::collator::fixture::policy(1);
    let mut clients = Vec::new();
    let mut secrets = Vec::new();
    for tier in Tier::ALL {
        for i in 0..opts.clients_per_tier {
            let sk = shz_dlc::tagged_hash(b"SHZ/HFT06/BENCH-CLIENT", format!("{}-{i}", tier.name()).as_bytes());
            let id = format!("{}-{i}", tier.name());
            clients.push(ClientEntry { id: id.clone(), tier, pubkey: hex::encode(shz_dlc::pubkey_x_from_secret(&sk).map_err(|e| e.to_string())?), max_connections: 1 });
            secrets.push((id, tier, sk));
        }
    }
    let cfg = RelayConfig {
        mode: opts.mode,
        policy: PolicyConfig {
            network: hex::encode(fixture_policy.network),
            market: hex::encode(fixture_policy.market),
            epoch: fixture_policy.epoch,
            origin_us: 0,
            members: fixture_policy.members.map(hex::encode),
        },
        release: opts.release,
        ws_listen: "127.0.0.1:0".into(),
        http_listen: "127.0.0.1:0".into(),
        state_dir: opts.state_dir.clone(),
        history: 10_000,
        subscriber_queue: 64,
        clients,
        source: SourceConfig::Synthetic { seed: 20261124 },
        member_listen: None,
        frost_maturity_group_key: None,
    };
    let remote = opts.remote_members && opts.mode == SecurityMode::Federated;
    let mut cfg = cfg;
    if remote {
        // Members and relay must agree on slot 1: fix the origin up front.
        let now_us = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_micros() as u64;
        cfg.policy.origin_us = (now_us / 1_000_000 + 4) * 1_000_000;
        cfg.member_listen = Some("127.0.0.1:0".into());
    }
    let member_cfg_base = cfg.clone();
    let relay = start(
        cfg,
        StartOptions { run_seconds: Some(opts.seconds), relay_key: Some([0x5e; 32]), collator: None, dev_federation: Some(opts.mode == SecurityMode::Federated && !remote) },
    )
    .await?;
    let mut members = Vec::new();
    if remote {
        let addr = relay.member_addr.ok_or("member endpoint not bound")?;
        for i in 0..5usize {
            let mc = crate::member::MemberConfig {
                member: i as u8,
                relay_url: format!("ws://{addr}"),
                policy: member_cfg_base.policy.clone(),
                state_dir: opts.state_dir.join(format!("members/m{i}")),
                source: SourceConfig::Synthetic { seed: 20261124 },
                reconnect_ms: 100,
            };
            let secret = shz_oracle::collator::fixture::FEDERATION_SECRETS[i];
            members.push(crate::member::start_member(mc, secret, crate::member::MemberOptions { collator: None, run_seconds: Some(opts.seconds) }).await?);
        }
    }
    let url = format!("ws://{}", relay.ws_addr);
    let mut handles = Vec::new();
    for (n, (id, tier, sk)) in secrets.into_iter().enumerate() {
        let url = url.clone();
        let shared = relay.shared.clone();
        let verifier = relay.verifier.clone();
        let release = opts.release;
        let slow = opts.slow_client && n % opts.clients_per_tier == opts.clients_per_tier - 1 && opts.clients_per_tier > 1;
        handles.push(tokio::spawn(async move {
            let mut rec = ClientRecord { tier, first_seq: None, last_seq: 0, seqs: Vec::new(), recv: BTreeMap::new(), after_boundary: Vec::new(), after_release: Vec::new(), verify: Vec::new(), verify_failures: 0 };
            let Ok((mut ws, _)) = tokio_tungstenite::connect_async(&url).await else { return rec };
            let Some(Ok(m)) = ws.next().await else { return rec };
            let Ok(ServerMsg::Challenge { nonce, relay_id, .. }) = serde_json::from_str(m.to_text().unwrap_or("")) else { return rec };
            let n: [u8; 32] = hex::decode(nonce).unwrap().try_into().unwrap();
            let r: [u8; 32] = hex::decode(relay_id).unwrap().try_into().unwrap();
            let sig = sign_auth(&sk, &r, &n, &id);
            let auth = ClientMsg::Auth { client_id: id, signature: hex::encode(sig.to_bytes()) };
            let _ = ws.send(Message::text(serde_json::to_string(&auth).unwrap())).await;
            let _ = ws.send(Message::text(serde_json::to_string(&ClientMsg::Subscribe { from_seq: None }).unwrap())).await;
            let mut rx = TieredReceiver::new(verifier, tier, release);
            while let Some(Ok(m)) = ws.next().await {
                let now = shared.clock.now_us();
                let Ok(text) = m.to_text() else { break };
                let Ok(msg) = serde_json::from_str::<ServerMsg>(text) else { continue };
                if let ServerMsg::Packet(d) = msg {
                    rec.after_boundary.push(now.saturating_sub(d.boundary_us));
                    rec.after_release.push(now.saturating_sub(d.release_at_us));
                    rec.recv.insert(d.seq, now);
                    rec.first_seq.get_or_insert(d.seq);
                    rec.last_seq = d.seq;
                    rec.seqs.push(d.seq);
                    let t0 = shared.clock.now_us();
                    let ok = CertifiedPacket::try_from(&d.certified).ok().map(|c| rx.accept(&c, now, 0).is_ok()).unwrap_or(false);
                    rec.verify.push(shared.clock.now_us() - t0);
                    if !ok {
                        rec.verify_failures += 1;
                    }
                    if slow {
                        tokio::time::sleep(Duration::from_millis(900)).await;
                    }
                }
            }
            rec
        }));
    }
    let produced = relay.producer.await.map_err(|e| e.to_string())?;
    produced?;
    // Let the last standard release drain, then close every socket.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let _ = relay.shared.shutdown.send(true);
    for m in members {
        m.shutdown().await;
    }
    let mut records = Vec::new();
    for h in handles {
        if let Ok(Ok(r)) = tokio::time::timeout(Duration::from_secs(10), h).await {
            records.push(r);
        }
    }
    for t in &relay.tasks {
        t.abort();
    }

    let hub = relay.shared.hub.lock().unwrap();
    let pm = relay.shared.pipeline.lock().unwrap().clone();
    let published: Vec<u64> = (1..=hub.last().map(|l| l.0).unwrap_or(0)).collect();
    let mut tiers = BTreeMap::new();
    let mut first_recv: [BTreeMap<u64, u64>; 3] = Default::default();
    for tier in Tier::ALL {
        let rs: Vec<&ClientRecord> = records.iter().filter(|r| r.tier == tier).collect();
        let (mut ab, mut ar, mut vf) = (Vec::new(), Vec::new(), Vec::new());
        let (mut received, mut expected, mut failures) = (0u64, 0u64, 0u64);
        for r in &rs {
            ab.extend(&r.after_boundary);
            ar.extend(&r.after_release);
            vf.extend(&r.verify);
            received += r.seqs.len() as u64;
            failures += r.verify_failures;
            if let Some(f) = r.first_seq {
                // Expected: every published seq from the first received one
                // through the last that was released to this tier.
                expected += published.iter().filter(|&&s| s >= f && s <= r.last_seq.max(f)).count() as u64;
            }
            for (&seq, &t) in &r.recv {
                let e = first_recv[tier.idx()].entry(seq).or_insert(t);
                *e = (*e).min(t);
            }
        }
        tiers.insert(
            tier.name(),
            TierResult {
                clients: rs.len(),
                received,
                expected,
                lost: expected.saturating_sub(received),
                verify_failures: failures,
                recv_after_boundary: exact_summary(&mut ab),
                recv_after_release: exact_summary(&mut ar),
                client_verify: exact_summary(&mut vf),
            },
        );
    }
    let lead = |a: usize, b: usize| {
        let mut v: Vec<u64> = first_recv[a].iter().filter_map(|(s, ta)| first_recv[b].get(s).map(|tb| tb.saturating_sub(*ta))).collect();
        exact_summary(&mut v)
    };
    let total_deliveries: u64 = hub.metrics.deliveries.iter().sum();
    let log_bytes: u64 = std::fs::read_dir(&opts.state_dir)
        .map(|d| d.filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("checkpoints-")).filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum())
        .unwrap_or(0);
    let lock_bytes: u64 = walk_size(&opts.state_dir, "lock");
    let slots = pm.slots.max(1) as f64;
    let mut send = BTreeMap::new();
    for t in Tier::ALL {
        send.insert(t.name(), hub.metrics.send_after_release[t.idx()].summary());
    }
    Ok(BenchReceipt {
        schema: "shz-hft06-relay-bench/v1",
        synthetic: true,
        production_ready: false,
        platform: format!(
            "{}-{} (loopback, single process{})",
            std::env::consts::OS,
            std::env::consts::ARCH,
            if remote { ", relay + 5 member tasks over WebSocket" } else { "" }
        ),
        mode: opts.mode,
        release: opts.release,
        seconds: opts.seconds,
        slots: pm.slots,
        valid_slots: pm.valid_slots,
        hold_slots: pm.hold_slots,
        reports: pm.reports,
        rejected_reports: pm.rejected_reports,
        ingest_verify_normalize: pm.ingest_us.summary(),
        certify_durable: pm.certify_us.summary(),
        certify_after_boundary: hub.metrics.certify_after_boundary.summary(),
        federation: relay.shared.fed.as_ref().map(|f| {
            let s = f.snapshot();
            FederationReceipt {
                transport: "websocket-loopback",
                members: 5,
                certified: s.metrics.certified,
                quorum_timeouts: s.metrics.quorum_timeouts,
                skipped_slots: hub.metrics.skipped_slots,
                votes_accepted: s.metrics.votes_accepted,
                disagreements: s.metrics.disagreements,
                refusals: s.metrics.refusals,
                equivocations: s.metrics.equivocations,
            }
        }),
        server_send_after_release: send,
        tiers,
        realized_lead_premium_vs_standard: lead(0, 2),
        realized_lead_premium_vs_intermediate: lead(0, 1),
        realized_lead_intermediate_vs_standard: lead(1, 2),
        deliveries_per_second: total_deliveries as f64 / opts.seconds.max(1) as f64,
        bytes_out: hub.metrics.bytes_out,
        bytes_per_delivery: hub.metrics.bytes_out as f64 / total_deliveries.max(1) as f64,
        checkpoint_log_bytes_per_slot: log_bytes as f64 / slots,
        signer_lock_bytes_per_slot: lock_bytes as f64 / slots,
        lagging_disconnects: hub.metrics.lagging_disconnects,
        late_certificates: hub.metrics.late_certificates,
        clock_uncertainty_note: "single process, one monotonic clock: clock uncertainty 0 by construction; cross-host uncertainty unmeasured",
    })
}

fn walk_size(dir: &std::path::Path, ext: &str) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    rd.filter_map(|e| e.ok())
        .map(|e| {
            let p = e.path();
            if p.is_dir() {
                walk_size(&p, ext)
            } else if p.extension().is_some_and(|x| x == ext) {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            } else {
                0
            }
        })
        .sum()
}
