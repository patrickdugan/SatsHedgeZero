//! G-FED-1: relay plus five independent member tasks over loopback WebSockets.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use shz_oracle::{
    collator::fixture,
    hft_packets::{Mark, Packet},
};
use shz_relay::{
    client::{ClientEntry, TieredReceiver, sign_auth},
    config::{PolicyConfig, RelayConfig, SourceConfig},
    envelope::{CertifiedPacket, Hash, PacketVerifier, SecurityMode},
    hub::Delivery,
    member::{MemberConfig, MemberOptions, MemberRunning, start_member},
    remote::{MemberToRelay, RelayToMember, sig_to_hex, sign_member_auth},
    schedule::{ReleasePolicy, Tier},
    server::{ClientMsg, ServerMsg},
    service::{RunningRelay, StartOptions, start},
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tokio_tungstenite::tungstenite::Message;

const SEED: u64 = 20261124;
const CLIENT_KEY: Hash = [0x33; 32];

struct Net {
    relay: RunningRelay,
    policy: PolicyConfig,
    dir: PathBuf,
    members: Vec<Option<MemberRunning>>,
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("shz-remote-fed-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn net(name: &str, mode: SecurityMode, member_listen: bool) -> Net {
    let dir = tmpdir(name);
    let fp = fixture::policy(1);
    let now_us = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;
    let policy = PolicyConfig {
        network: hex::encode(fp.network),
        market: hex::encode(fp.market),
        epoch: fp.epoch,
        origin_us: (now_us / 1_000_000 + 2) * 1_000_000,
        members: fp.members.map(hex::encode),
    };
    let cfg = RelayConfig {
        mode,
        policy: policy.clone(),
        release: ReleasePolicy::default(),
        ws_listen: "127.0.0.1:0".into(),
        http_listen: "127.0.0.1:0".into(),
        state_dir: dir.join("relay"),
        history: 10_000,
        subscriber_queue: 256,
        clients: vec![ClientEntry {
            id: "t-premium".into(),
            tier: Tier::Premium,
            pubkey: hex::encode(shz_dlc::pubkey_x_from_secret(&CLIENT_KEY).unwrap()),
            max_connections: 4,
        }],
        source: SourceConfig::Synthetic { seed: SEED },
        member_listen: member_listen.then(|| "127.0.0.1:0".to_string()),
        frost_maturity_group_key: None,
    };
    let relay = start(cfg, StartOptions { run_seconds: Some(120), relay_key: Some([0x5e; 32]), collator: None, dev_federation: Some(false) }).await.unwrap();
    Net { relay, policy, dir, members: (0..5).map(|_| None).collect() }
}

impl Net {
    async fn member(&mut self, i: usize, seed: u64) {
        let cfg = MemberConfig {
            member: i as u8,
            relay_url: format!("ws://{}", self.relay.member_addr.unwrap()),
            policy: self.policy.clone(),
            state_dir: self.dir.join(format!("m{i}")),
            source: SourceConfig::Synthetic { seed },
            reconnect_ms: 100,
        };
        let m = start_member(cfg, fixture::FEDERATION_SECRETS[i], MemberOptions { collator: None, run_seconds: Some(120) }).await.unwrap();
        self.members[i] = Some(m);
    }
    async fn all_members(&mut self) {
        for i in 0..5 {
            self.member(i, SEED).await;
        }
    }
    async fn stop_member(&mut self, i: usize) {
        self.members[i].take().unwrap().shutdown().await;
    }
    fn published(&self) -> u64 {
        self.relay.shared.hub.lock().unwrap().metrics.published
    }
    fn fed(&self) -> shz_relay::remote::FedSnapshot {
        self.relay.shared.fed.as_ref().unwrap().snapshot()
    }
    async fn finish(self) {
        self.relay.shutdown();
        self.relay.producer.abort();
        for m in self.members.into_iter().flatten() {
            m.shutdown().await;
        }
        for t in &self.relay.tasks {
            t.abort();
        }
    }
    /// Subscribe a premium client; deliveries accumulate in the returned vector.
    async fn subscribe(&self) -> Arc<Mutex<Vec<Delivery>>> {
        let out = Arc::new(Mutex::new(Vec::new()));
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{}", self.relay.ws_addr)).await.unwrap();
        let Some(Ok(m)) = ws.next().await else { panic!("no challenge") };
        let Ok(ServerMsg::Challenge { nonce, relay_id, .. }) = serde_json::from_str(m.to_text().unwrap()) else { panic!("bad challenge") };
        let sig = sign_auth(&CLIENT_KEY, &hex::decode(relay_id).unwrap().try_into().unwrap(), &hex::decode(nonce).unwrap().try_into().unwrap(), "t-premium");
        ws.send(Message::text(serde_json::to_string(&ClientMsg::Auth { client_id: "t-premium".into(), signature: hex::encode(sig.to_bytes()) }).unwrap())).await.unwrap();
        ws.send(Message::text(serde_json::to_string(&ClientMsg::Subscribe { from_seq: None }).unwrap())).await.unwrap();
        let sink = out.clone();
        tokio::spawn(async move {
            while let Some(Ok(m)) = ws.next().await {
                if let Ok(ServerMsg::Packet(d)) = serde_json::from_str::<ServerMsg>(m.to_text().unwrap_or("")) {
                    sink.lock().unwrap().push(d);
                }
            }
        });
        out
    }
    fn verifier(&self) -> PacketVerifier {
        PacketVerifier::federated(self.relay.policy.clone()).unwrap()
    }
}

async fn wait_for(secs: u64, what: &str, mut f: impl FnMut() -> bool) {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(tokio::time::Instant::now() < end, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

/// Feed deliveries through a client receiver: every certificate verifies and
/// every packet links to the previous accepted digest (skips allowed).
fn replay(net: &Net, ds: &[Delivery]) -> usize {
    let mut rx = TieredReceiver::new(net.verifier(), Tier::Premium, ReleasePolicy::default());
    let mut jumps = 0;
    let mut last = 0;
    for d in ds {
        let c = CertifiedPacket::try_from(&d.certified).unwrap();
        assert_eq!(c.mode(), SecurityMode::Federated);
        rx.accept(&c, d.release_at_us, 0).unwrap_or_else(|e| panic!("seq {} rejected: {e:?}", d.seq));
        if last != 0 && d.seq > last + 1 {
            jumps += 1;
        }
        last = d.seq;
    }
    jumps
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificates_form_and_clients_receive_federated_packets() {
    let mut n = net("form", SecurityMode::Federated, true).await;
    n.all_members().await;
    let got = n.subscribe().await;
    wait_for(40, "8 certified packets at the client", || got.lock().unwrap().len() >= 8).await;
    let ds = got.lock().unwrap().clone();
    replay(&n, &ds);
    for d in &ds {
        let CertifiedPacket::Federated(c) = CertifiedPacket::try_from(&d.certified).unwrap() else { panic!("not federated") };
        assert_eq!(c.votes.len(), 4);
    }
    assert!(serde_json::to_string(&ds[0].certified).unwrap().contains("\"mode\":\"federated\""));
    // Consecutive packets are chained.
    for w in ds.windows(2) {
        if w[1].seq == w[0].seq + 1 {
            let c1 = CertifiedPacket::try_from(&w[1].certified).unwrap();
            assert_eq!(hex::encode(c1.packet().previous), w[0].digest);
        }
    }
    let health = http_get(n.relay.http_addr, "/healthz").await;
    assert!(health.contains("\"members_connected\":[true,true,true,true,true]"), "{health}");
    assert!(health.contains("\"federation\""), "{health}");
    let metrics = http_get(n.relay.http_addr, "/metrics").await;
    assert!(metrics.contains("shz_relay_quorum_timeouts_total"), "{metrics}");
    n.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_disagreeing_member_still_yields_quorum_with_four() {
    let mut n = net("disagree", SecurityMode::Federated, true).await;
    for i in 0..5 {
        // Member 2 authenticates a different feed (different seed), so its
        // rebuilt VALID packets differ from the relay's.
        n.member(i, if i == 2 { SEED + 1 } else { SEED }).await;
    }
    let got = n.subscribe().await;
    let valid_seen = |ds: &[Delivery]| ds.iter().filter(|d| matches!(CertifiedPacket::try_from(&d.certified).unwrap().packet().mark, Mark::Valid { .. })).count();
    wait_for(60, "three VALID certified packets", || valid_seen(&got.lock().unwrap()) >= 3).await;
    let ds = got.lock().unwrap().clone();
    replay(&n, &ds);
    for d in &ds {
        let CertifiedPacket::Federated(c) = CertifiedPacket::try_from(&d.certified).unwrap() else { panic!() };
        assert!(c.votes.len() >= 4);
        if matches!(c.packet.mark, Mark::Valid { .. }) {
            assert!(c.votes.iter().all(|v| v.member != 2), "the disagreeing member must not vote on a VALID packet");
        }
    }
    let snap = n.fed();
    assert!(snap.metrics.disagreements >= 3, "{snap:?}");
    assert!(n.members[2].as_ref().unwrap().stats.disagreements.load(std::sync::atomic::Ordering::Relaxed) >= 3);
    n.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_members_down_times_out_then_recovers_with_a_linked_jump() {
    let mut n = net("outage", SecurityMode::Federated, true).await;
    n.all_members().await;
    let got = n.subscribe().await;
    wait_for(40, "three certificates", || n.published() >= 3).await;
    let high_before = n.members[3].as_ref().unwrap().core.lock().unwrap().lock_high_water();
    n.stop_member(3).await;
    n.stop_member(4).await;
    wait_for(10, "two quorum timeouts", || n.fed().metrics.quorum_timeouts >= 2).await;
    let frozen = n.published();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(n.published(), frozen, "no certificate may form with three members");
    assert!(n.fed().metrics.quorum_timeouts >= 3);
    // Members come back (new processes' worth of state: same lock files).
    n.member(3, SEED).await;
    n.member(4, SEED).await;
    assert!(n.members[3].as_ref().unwrap().core.lock().unwrap().lock_high_water() >= high_before, "restart keeps the durable lock");
    wait_for(40, "recovery", || n.published() >= frozen + 3).await;
    assert!(n.relay.shared.hub.lock().unwrap().metrics.skipped_slots >= 1);
    let ds = got.lock().unwrap().clone();
    let jumps = replay(&n, &ds);
    assert!(jumps >= 1, "the client sees a linked jump over the abandoned slots");
    n.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certification_starts_with_genesis_once_quorum_exists() {
    let mut n = net("genesis", SecurityMode::Federated, true).await;
    for i in 0..3 {
        n.member(i, SEED).await;
    }
    let got = n.subscribe().await;
    wait_for(20, "quorum timeouts without quorum", || n.fed().metrics.quorum_timeouts >= 2).await;
    assert_eq!(n.published(), 0);
    n.member(3, SEED).await;
    wait_for(40, "genesis then live packets", || got.lock().unwrap().len() >= 3).await;
    let ds = got.lock().unwrap().clone();
    assert_eq!(ds[0].seq, 1, "the first certificate is the genesis packet");
    assert!(ds[0].late, "genesis certified after its deadline is flagged late");
    assert!(ds[1].seq > 1);
    replay(&n, &ds);
    n.finish().await;
}

async fn raw_member_ws(addr: SocketAddr) -> (tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, Hash, Hash) {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}")).await.unwrap();
    let Some(Ok(m)) = ws.next().await else { panic!("no frame") };
    let Ok(RelayToMember::Challenge { nonce, relay_id, .. }) = serde_json::from_str(m.to_text().unwrap()) else { panic!("no challenge") };
    (ws, hex::decode(nonce).unwrap().try_into().unwrap(), hex::decode(relay_id).unwrap().try_into().unwrap())
}

async fn next_relay_msg(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>) -> Option<RelayToMember> {
    let m = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.ok()??.ok()?;
    serde_json::from_str(m.to_text().ok()?).ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_member_keys_are_refused() {
    let n = net("unknown", SecurityMode::Federated, true).await;
    let addr = n.relay.member_addr.unwrap();
    // A key that is in no policy slot, claiming slot 0.
    let (mut ws, nonce, relay_id) = raw_member_ws(addr).await;
    let sig = sign_member_auth(&[0x66; 32], &relay_id, &nonce, 0);
    ws.send(Message::text(serde_json::to_string(&MemberToRelay::Auth { member: 0, signature: sig_to_hex(&sig) }).unwrap())).await.unwrap();
    assert!(matches!(next_relay_msg(&mut ws).await, Some(RelayToMember::Error { reason }) if reason.contains("authentication")));
    // A real member key claiming a different member's slot.
    let (mut ws, nonce, relay_id) = raw_member_ws(addr).await;
    let sig = sign_member_auth(&fixture::FEDERATION_SECRETS[1], &relay_id, &nonce, 0);
    ws.send(Message::text(serde_json::to_string(&MemberToRelay::Auth { member: 0, signature: sig_to_hex(&sig) }).unwrap())).await.unwrap();
    assert!(matches!(next_relay_msg(&mut ws).await, Some(RelayToMember::Error { .. })));
    // An index outside the policy.
    let (mut ws, nonce, relay_id) = raw_member_ws(addr).await;
    let sig = sign_member_auth(&fixture::FEDERATION_SECRETS[1], &relay_id, &nonce, 9);
    ws.send(Message::text(serde_json::to_string(&MemberToRelay::Auth { member: 9, signature: sig_to_hex(&sig) }).unwrap())).await.unwrap();
    assert!(matches!(next_relay_msg(&mut ws).await, Some(RelayToMember::Error { .. })));
    // A valid signature on another nonce (replay across connections).
    let (_, old_nonce, _) = raw_member_ws(addr).await;
    let (mut ws, _nonce, relay_id) = raw_member_ws(addr).await;
    let sig = sign_member_auth(&fixture::FEDERATION_SECRETS[0], &relay_id, &old_nonce, 0);
    ws.send(Message::text(serde_json::to_string(&MemberToRelay::Auth { member: 0, signature: sig_to_hex(&sig) }).unwrap())).await.unwrap();
    assert!(matches!(next_relay_msg(&mut ws).await, Some(RelayToMember::Error { .. })));
    wait_for(5, "auth failures counted", || n.fed().metrics.auth_failures >= 4).await;
    assert_eq!(n.fed().connected, [false; 5]);
    n.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_relay_mode_refuses_member_connections() {
    let n = net("trusted", SecurityMode::TrustedRelay, true).await;
    assert!(n.relay.shared.fed.is_none());
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{}", n.relay.member_addr.unwrap())).await.unwrap();
    let m = ws.next().await.unwrap().unwrap();
    assert!(matches!(serde_json::from_str(m.to_text().unwrap()), Ok(RelayToMember::Error { reason }) if reason.contains("trusted_relay")));
    n.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflicting_votes_are_recorded_as_equivocation_evidence() {
    let mut n = net("equivocation", SecurityMode::Federated, true).await;
    for i in 0..4 {
        n.member(i, SEED).await;
    }
    // Member 4's key without its durable lock: signs two digests for one slot.
    let (mut ws, nonce, relay_id) = raw_member_ws(n.relay.member_addr.unwrap()).await;
    let secret = fixture::FEDERATION_SECRETS[4];
    let sig = sign_member_auth(&secret, &relay_id, &nonce, 4);
    ws.send(Message::text(serde_json::to_string(&MemberToRelay::Auth { member: 4, signature: sig_to_hex(&sig) }).unwrap())).await.unwrap();
    let (seq, digest) = loop {
        if let RelayToMember::Proposal(p) = next_relay_msg(&mut ws).await.expect("proposal") { break (p.seq, Packet::try_from(&p.packet).unwrap().digest()) }
    };
    let alt: Hash = shz_dlc::tagged_hash(b"TEST/ALT", &digest);
    for d in [digest, alt] {
        let s = shz_dlc::bip340_sign(&secret, &d).unwrap();
        ws.send(Message::text(serde_json::to_string(&MemberToRelay::Vote { seq, digest: hex::encode(d), signature: sig_to_hex(&s) }).unwrap())).await.unwrap();
    }
    wait_for(10, "equivocation recorded", || n.fed().metrics.equivocations == 1).await;
    let snap = n.fed();
    assert_eq!(snap.evidence.len(), 1);
    assert_eq!((snap.evidence[0].seq, snap.evidence[0].member), (seq, 4));
    // An unsigned or forged second vote is not evidence.
    let forged = shz_dlc::bip340_sign(&[0x55; 32], &alt).unwrap();
    ws.send(Message::text(serde_json::to_string(&MemberToRelay::Vote { seq, digest: hex::encode(alt), signature: sig_to_hex(&forged) }).unwrap())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(n.fed().metrics.equivocations, 1);
    let health = http_get(n.relay.http_addr, "/healthz").await;
    assert!(health.contains("\"member_equivocations\":1") && health.contains(&hex::encode(alt)), "{health}");
    let metrics = http_get(n.relay.http_addr, "/metrics").await;
    assert!(metrics.contains("shz_relay_member_equivocations_total 1"), "{metrics}");
    n.finish().await;
}

#[tokio::test]
async fn federated_start_without_transport_or_dev_flag_is_refused() {
    let dir = tmpdir("refused");
    let fp = fixture::policy(1);
    let cfg = RelayConfig {
        mode: SecurityMode::Federated,
        policy: PolicyConfig { network: hex::encode(fp.network), market: hex::encode(fp.market), epoch: 1, origin_us: 0, members: fp.members.map(hex::encode) },
        release: ReleasePolicy::default(),
        ws_listen: "127.0.0.1:0".into(),
        http_listen: "127.0.0.1:0".into(),
        state_dir: dir,
        history: 100,
        subscriber_queue: 16,
        clients: vec![],
        source: SourceConfig::Synthetic { seed: 1 },
        member_listen: None,
        frost_maturity_group_key: None,
    };
    let err = start(cfg, StartOptions { run_seconds: Some(1), relay_key: None, collator: None, dev_federation: Some(false) }).await.err().unwrap();
    assert!(err.contains("member_listen"), "{err}");
}
