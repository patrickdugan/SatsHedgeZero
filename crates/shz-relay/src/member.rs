//! Independent federation member process (gate G-FED-1).
//!
//! A member holds exactly one member key and its own [`DurableSignLock`], and
//! runs its OWN collator over its OWN source feed: it authenticates raw
//! provider reports itself and rebuilds every slot packet. It connects to the
//! relay's vote endpoint ([`crate::remote`]), receives the relay's proposal for
//! a slot and signs only when the proposal digest equals the digest of the
//! packet it built itself for that sequence (with `previous` taken from the
//! verified parent certificate the proposal carries). A different digest is
//! reported as `disagree` and nothing is signed. The durable lock is written
//! and synced before any signature leaves [`MemberCore::on_proposal`].

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use shz_dlc::Bip340Signature;
use shz_oracle::{
    collator::{Collator, CollatorConfig, RawReport, fixture},
    hft_packets::{Certificate, Packet, Policy, Signer},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite::Message;

use crate::{
    authority::{AuthorityError, DurableSignLock},
    config::{PolicyConfig, SourceConfig, h32},
    envelope::Hash,
    remote::{MemberToRelay, ProposalMsg, RelayToMember, sig_to_hex, sign_member_auth, wire_to_cert},
    schedule::MonoClock,
    server::sleep_until,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberConfig {
    /// Index of this member's key in `policy.members`.
    pub member: u8,
    /// `ws://host:port` of the relay's member endpoint.
    pub relay_url: String,
    /// Must equal the relay's policy and carry an explicit nonzero `origin_us`.
    pub policy: PolicyConfig,
    /// Holds `member<i>.lock` (the durable one-vote-per-slot lock).
    pub state_dir: PathBuf,
    /// This member's own feed. Never shared with the relay.
    pub source: SourceConfig,
    #[serde(default = "default_reconnect_ms")]
    pub reconnect_ms: u64,
}
fn default_reconnect_ms() -> u64 {
    250
}

impl MemberConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let cfg: Self = serde_json::from_str(&raw).map_err(|e| format!("member config: {e}"))?;
        if cfg.member > 4 {
            return Err("member index must be 0..=4".into());
        }
        if cfg.policy.origin_us == 0 {
            return Err("member policy requires an explicit origin_us shared with the relay".into());
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Voted { digest: Hash, signature: Bip340Signature },
    Disagree { own_digest: Hash, proposal_digest: Hash },
    Refused(String),
    /// The member's own collator has not closed this slot yet.
    NotReady,
}

const KEEP_PACKETS: usize = 4_096;

/// Decision logic of one member, independent of any transport.
pub struct MemberCore {
    member: u8,
    policy: Policy,
    policy_id: Hash,
    signer: Signer,
    lock: DurableSignLock,
    packets: BTreeMap<u64, Packet>,
    newest: u64,
    /// Highest verified certified parent seen: (seq, digest).
    parent: Option<(u64, Hash)>,
}

impl MemberCore {
    pub fn new(policy: &Policy, member: u8, secret: Hash, lock: DurableSignLock) -> Result<Self, String> {
        let signer = Signer::new(policy, member, secret).map_err(|e| format!("member key does not match policy.members[{member}]: {e:?}"))?;
        let policy_id = policy.id().map_err(|e| format!("{e:?}"))?;
        Ok(Self { member, policy: policy.clone(), policy_id, signer, lock, packets: BTreeMap::new(), newest: 0, parent: None })
    }

    pub fn member(&self) -> u8 {
        self.member
    }
    pub fn lock_high_water(&self) -> u64 {
        self.lock.high_water()
    }

    /// Record a packet from this member's own collator.
    pub fn push_packet(&mut self, p: Packet) {
        self.newest = self.newest.max(p.seq);
        self.packets.insert(p.seq, p);
        while self.packets.len() > KEEP_PACKETS {
            self.packets.pop_first();
        }
    }

    /// A certificate announced by the relay: verified once, ratchets the parent.
    pub fn note_certified(&mut self, c: &Certificate) -> Result<(), String> {
        let d = c.packet.digest();
        match self.parent {
            Some((s, pd)) if s == c.packet.seq && pd == d => return Ok(()),
            Some((s, _)) if c.packet.seq <= s => return Ok(()),
            _ => {}
        }
        c.verify(&self.policy).map_err(|e| format!("certificate rejected: {e:?}"))?;
        self.parent = Some((c.packet.seq, d));
        Ok(())
    }

    pub fn on_proposal(&mut self, seq: u64, proposed: &Packet, parent: Option<&Certificate>) -> Outcome {
        if proposed.seq != seq || proposed.policy != self.policy_id {
            return Outcome::Refused("proposal outside this policy or inconsistent sequence".into());
        }
        match parent {
            None => {
                if seq != 1 || proposed.previous != [0; 32] || self.parent.is_some() {
                    return Outcome::Refused("proposal without a certified parent".into());
                }
            }
            Some(c) => {
                let pd = c.packet.digest();
                if c.packet.seq >= seq || proposed.previous != pd {
                    return Outcome::Refused("proposal does not chain to its parent certificate".into());
                }
                match self.parent {
                    Some((s, d)) if s == c.packet.seq && d == pd => {}
                    Some((s, _)) if c.packet.seq <= s => return Outcome::Refused("stale or conflicting parent certificate".into()),
                    _ => {
                        if let Err(e) = c.verify(&self.policy) {
                            return Outcome::Refused(format!("parent certificate invalid: {e:?}"));
                        }
                        self.parent = Some((c.packet.seq, pd));
                    }
                }
            }
        }
        let Some(own) = self.packets.get(&seq) else {
            return if seq > self.newest { Outcome::NotReady } else { Outcome::Refused("no locally built packet for this sequence".into()) };
        };
        let mine = Packet { previous: proposed.previous, ..own.clone() };
        let (own_digest, proposal_digest) = (mine.digest(), proposed.digest());
        if own_digest != proposal_digest {
            return Outcome::Disagree { own_digest, proposal_digest };
        }
        // Durable, synced lock first; only then does a signature exist.
        if let Err(e) = self.lock.lock(seq, &own_digest) {
            return Outcome::Refused(match e {
                AuthorityError::Equivocation(_) => format!("already signed a different digest for sequence {seq}"),
                e => e.to_string(),
            });
        }
        match self.signer.vote(&self.policy, &mine) {
            Ok(v) => Outcome::Voted { digest: own_digest, signature: v.signature },
            Err(e) => Outcome::Refused(format!("own packet fails HFT-04 validation: {e:?}")),
        }
    }
}

#[derive(Debug, Default)]
pub struct MemberStats {
    pub votes: AtomicU64,
    pub disagreements: AtomicU64,
    pub refusals: AtomicU64,
    pub connects: AtomicU64,
    pub last_voted_seq: AtomicU64,
    pub slots_built: AtomicU64,
    pub last_error: Mutex<String>,
}

pub struct MemberRunning {
    pub stats: Arc<MemberStats>,
    pub core: Arc<Mutex<MemberCore>>,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl MemberRunning {
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
    /// Stop and wait for the member's tasks to end (releases the lock file).
    pub async fn shutdown(self) {
        self.stop();
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
    }
}

#[derive(Default)]
pub struct MemberOptions {
    /// Collator config override (tests, live).
    pub collator: Option<CollatorConfig>,
    /// Stop after this many seconds of slots past the origin (None = run until stopped).
    pub run_seconds: Option<u64>,
}

pub async fn start_member(cfg: MemberConfig, secret: Hash, opts: MemberOptions) -> Result<MemberRunning, String> {
    std::fs::create_dir_all(&cfg.state_dir).map_err(|e| format!("state_dir: {e}"))?;
    let origin = cfg.policy.origin_us;
    if origin == 0 {
        return Err("member policy requires an explicit origin_us shared with the relay".into());
    }
    let policy = cfg.policy.to_policy(origin)?;
    let lock = DurableSignLock::open(&cfg.state_dir.join(format!("member{}.lock", cfg.member))).map_err(|e| e.to_string())?;
    let core = Arc::new(Mutex::new(MemberCore::new(&policy, cfg.member, secret, lock)?));
    let (rtx, rrx) = mpsc::channel::<RawReport>(4_096);
    let clock = match &cfg.source {
        SourceConfig::Synthetic { seed } => {
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
            MonoClock::new()
        }
        SourceConfig::Recorded { path, recorded_origin_us } => {
            if *recorded_origin_us != origin {
                return Err("recorded_origin_us must equal policy.origin_us".into());
            }
            let reports = crate::service::load_recording(path)?;
            let first = reports.first().map(|r| r.arrival_us).ok_or("empty recording")?;
            tokio::spawn(async move {
                for r in reports {
                    if rtx.send(r).await.is_err() {
                        break;
                    }
                }
            });
            MonoClock::at(first.saturating_sub(500_000))
        }
        SourceConfig::Live { .. } => {
            #[cfg(not(feature = "live"))]
            return Err("live source requires building with --features live".into());
            #[cfg(feature = "live")]
            {
                let clock = MonoClock::new();
                crate::live::spawn_connectors(&cfg.source, clock, rtx)?;
                clock
            }
        }
    };
    let collator_cfg = match (opts.collator, &cfg.source) {
        (Some(c), _) => c,
        #[cfg(feature = "live")]
        (None, SourceConfig::Live { .. }) => crate::live::collator_config(&cfg.source)?,
        (None, _) => fixture::config(),
    };
    let until = opts.run_seconds.map(|s| origin + s * 1_000_000).unwrap_or(u64::MAX);
    let (stop, stop_rx) = watch::channel(false);
    let (newest_tx, newest_rx) = watch::channel(0u64);
    let stats = Arc::new(MemberStats::default());
    let replay = !matches!(cfg.source, SourceConfig::Live { .. });
    let pump = tokio::spawn(pump(clock, collator_cfg, policy.clone(), rrx, until, replay, core.clone(), newest_tx, stop_rx.clone(), stats.clone()));
    let link = tokio::spawn(connect_loop(cfg, secret, core.clone(), newest_rx, stop_rx, clock, stats.clone()));
    Ok(MemberRunning { stats, core, stop, tasks: vec![pump, link] })
}

/// The member's own collation: authenticate raw reports, close slots on the
/// clock, hand each rebuilt packet to the core. A `replay` source (recorded or
/// synthetic, timestamps on the clock's scale) may still be producing history
/// when this member starts late: a boundary already in the past is closed only
/// after the source has delivered the reports that precede it, otherwise slots
/// would close empty and the later reports would be rejected as clock regressions.
#[allow(clippy::too_many_arguments)]
async fn pump(
    clock: MonoClock,
    cfg: CollatorConfig,
    policy: Policy,
    mut reports: mpsc::Receiver<RawReport>,
    until_us: u64,
    replay: bool,
    core: Arc<Mutex<MemberCore>>,
    newest: watch::Sender<u64>,
    stop: watch::Receiver<bool>,
    stats: Arc<MemberStats>,
) {
    let Ok(mut collator) = Collator::new(cfg, policy) else { return };
    let mut pending: Option<RawReport> = None;
    let mut source_done = false;
    while !*stop.borrow() {
        if pending.is_none() && !source_done {
            match reports.try_recv() {
                Ok(r) => pending = Some(r),
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => source_done = true,
            }
        }
        let boundary = collator.next_boundary_us();
        if boundary > until_us && (source_done || pending.is_none() && clock.now_us() > until_us) {
            break;
        }
        let closed = match &pending {
            Some(r) if r.arrival_us <= boundary => {
                sleep_until(&clock, r.arrival_us).await;
                let r = pending.take().unwrap();
                collator.ingest(&r).0
            }
            _ => {
                if pending.is_none() && !source_done {
                    let behind = replay && boundary <= clock.now_us();
                    let limit = if behind { Duration::from_secs(30) } else { Duration::from_micros(boundary.saturating_sub(clock.now_us()).max(1)) };
                    let wait = tokio::time::timeout(limit, reports.recv());
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
                sleep_until(&clock, boundary).await;
                match collator.close_through(boundary) {
                    Ok(c) => c,
                    Err(_) => break,
                }
            }
        };
        for slot in closed {
            if let Some(p) = slot.packet {
                let seq = p.seq;
                core.lock().unwrap().push_packet(p);
                stats.slots_built.fetch_add(1, Ordering::Relaxed);
                let _ = newest.send(seq);
            }
        }
    }
}

async fn connect_loop(
    cfg: MemberConfig,
    secret: Hash,
    core: Arc<Mutex<MemberCore>>,
    mut newest: watch::Receiver<u64>,
    mut stop: watch::Receiver<bool>,
    clock: MonoClock,
    stats: Arc<MemberStats>,
) {
    while !*stop.borrow() {
        if let Err(e) = session(&cfg, &secret, &core, &mut newest, &mut stop, &clock, &stats).await {
            *stats.last_error.lock().unwrap() = e;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(cfg.reconnect_ms)) => {}
            _ = stop.changed() => {}
        }
    }
}

async fn session(
    cfg: &MemberConfig,
    secret: &Hash,
    core: &Arc<Mutex<MemberCore>>,
    newest: &mut watch::Receiver<u64>,
    stop: &mut watch::Receiver<bool>,
    clock: &MonoClock,
    stats: &MemberStats,
) -> Result<(), String> {
    let (mut ws, _) = tokio_tungstenite::connect_async(cfg.relay_url.as_str()).await.map_err(|e| format!("connect: {e}"))?;
    let first = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.map_err(|_| "no challenge")?;
    let Some(Ok(m)) = first else { return Err("no challenge".into()) };
    let (nonce, relay_id) = match serde_json::from_str(m.to_text().map_err(|e| e.to_string())?) {
        Ok(RelayToMember::Challenge { nonce, relay_id, .. }) => (h32(&nonce)?, h32(&relay_id)?),
        Ok(RelayToMember::Error { reason }) => return Err(format!("relay: {reason}")),
        _ => return Err("unexpected first frame".into()),
    };
    let sig = sign_member_auth(secret, &relay_id, &nonce, cfg.member);
    let auth = MemberToRelay::Auth { member: cfg.member, signature: sig_to_hex(&sig) };
    ws.send(Message::text(serde_json::to_string(&auth).unwrap())).await.map_err(|e| e.to_string())?;
    stats.connects.fetch_add(1, Ordering::Relaxed);
    loop {
        let m = tokio::select! {
            _ = stop.changed() => return Ok(()),
            m = ws.next() => m,
        };
        let Some(Ok(m)) = m else { return Err("relay closed the connection".into()) };
        let Ok(t) = m.to_text() else { continue };
        match serde_json::from_str::<RelayToMember>(t) {
            Ok(RelayToMember::Proposal(p)) => {
                let Some(reply) = answer(&p, core, newest, stop, clock, stats).await else { return Ok(()) };
                ws.send(Message::text(serde_json::to_string(&reply).unwrap())).await.map_err(|e| e.to_string())?;
            }
            Ok(RelayToMember::Certified { certified }) => {
                if let Ok(c) = wire_to_cert(&certified) {
                    let _ = core.lock().unwrap().note_certified(&c);
                }
            }
            Ok(RelayToMember::Error { reason }) => return Err(format!("relay: {reason}")),
            _ => {}
        }
    }
}

/// Decide one proposal. `None` means the member is stopping.
async fn answer(
    p: &ProposalMsg,
    core: &Arc<Mutex<MemberCore>>,
    newest: &mut watch::Receiver<u64>,
    stop: &mut watch::Receiver<bool>,
    clock: &MonoClock,
    stats: &MemberStats,
) -> Option<MemberToRelay> {
    let refuse = |reason: &str| {
        stats.refusals.fetch_add(1, Ordering::Relaxed);
        Some(MemberToRelay::Refuse { seq: p.seq, reason: reason.into() })
    };
    let Ok(packet) = Packet::try_from(&p.packet) else { return refuse("malformed packet") };
    let parent = match p.parent.as_ref().map(wire_to_cert).transpose() {
        Ok(c) => c,
        Err(_) => return refuse("malformed parent certificate"),
    };
    let outcome = loop {
        let o = core.lock().unwrap().on_proposal(p.seq, &packet, parent.as_ref());
        if o != Outcome::NotReady {
            break o;
        }
        let now = clock.now_us();
        if now >= p.deadline_us {
            break Outcome::Refused("own packet for this sequence not built before the deadline".into());
        }
        tokio::select! {
            r = newest.changed() => if r.is_err() { break Outcome::Refused("collator stopped".into()) },
            _ = tokio::time::sleep(Duration::from_micros(p.deadline_us - now)) => {}
            _ = stop.changed() => return None,
        }
    };
    Some(match outcome {
        Outcome::Voted { digest, signature } => {
            stats.votes.fetch_add(1, Ordering::Relaxed);
            stats.last_voted_seq.store(p.seq, Ordering::Relaxed);
            MemberToRelay::Vote { seq: p.seq, digest: hex::encode(digest), signature: sig_to_hex(&signature) }
        }
        Outcome::Disagree { own_digest, proposal_digest } => {
            stats.disagreements.fetch_add(1, Ordering::Relaxed);
            MemberToRelay::Disagree { seq: p.seq, own_digest: hex::encode(own_digest), proposal_digest: hex::encode(proposal_digest) }
        }
        Outcome::Refused(r) => {
            stats.refusals.fetch_add(1, Ordering::Relaxed);
            MemberToRelay::Refuse { seq: p.seq, reason: r }
        }
        Outcome::NotReady => unreachable!(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shz_oracle::hft_packets::{Mark, Source};

    fn policy() -> Policy {
        Policy {
            network: [9; 32],
            market: [8; 32],
            epoch: 1,
            origin_us: 10_000_000,
            members: std::array::from_fn(|i| shz_dlc::pubkey_x_from_secret(&[(i + 1) as u8; 32]).unwrap()),
        }
    }
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("shz-member-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn valid(p: &Policy, seq: u64, previous: Hash, price: u64) -> Packet {
        let t = p.fast_at(seq).unwrap();
        Packet {
            policy: p.id().unwrap(),
            seq,
            previous,
            mark: Mark::Valid {
                pyth: Source { report: [1; 32], published_us: t - 20_000, price_e8: price },
                chainlink: Source { report: [2; 32], published_us: t - 30_000, price_e8: price + 1_000_000 },
            },
        }
    }
    fn core(dir: &Path, member: u8) -> MemberCore {
        let p = policy();
        MemberCore::new(&p, member, [(member + 1); 32], DurableSignLock::open(&dir.join(format!("m{member}.lock"))).unwrap()).unwrap()
    }
    /// A real 4-of-5 certificate for `packet`.
    fn cert(p: &Policy, packet: Packet) -> Certificate {
        let mut ss: Vec<_> = (0..5).map(|i| Signer::new(p, i, [(i + 1); 32]).unwrap()).collect();
        let votes = ss.iter_mut().take(4).map(|s| s.vote(p, &packet).unwrap()).collect();
        Certificate { packet, votes }
    }

    #[test]
    fn votes_only_on_its_own_independently_built_digest() {
        let p = policy();
        let d = tmp("own");
        let mut m = core(&d, 0);
        let own = valid(&p, 1, [0; 32], 10_000_000_000_000);
        assert_eq!(m.on_proposal(1, &own, None), Outcome::NotReady);
        m.push_packet(own.clone());
        assert!(matches!(m.on_proposal(1, &own, None), Outcome::Voted { .. }));
        // A relay proposal with a different price is a disagreement, not a vote.
        let mut m2 = core(&tmp("own2"), 1);
        m2.push_packet(own.clone());
        let tampered = valid(&p, 1, [0; 32], 10_100_000_000_000);
        assert!(matches!(m2.on_proposal(1, &tampered, None), Outcome::Disagree { own_digest, proposal_digest } if own_digest == own.digest() && proposal_digest == tampered.digest()));
        assert_eq!(m2.lock_high_water(), 0, "a disagreeing member signs nothing and locks nothing");
    }

    #[test]
    fn rebuilds_with_the_parent_digest_and_rejects_bad_parents() {
        let p = policy();
        let d = tmp("parent");
        let mut m = core(&d, 2);
        let g = valid(&p, 1, [0; 32], 10_000_000_000_000);
        let gc = cert(&p, g.clone());
        // The member's own chain linked seq 2 to its own seq 1; the proposal skips to seq 3 on the certified parent.
        let own2 = valid(&p, 2, g.digest(), 10_000_000_000_000);
        let own3 = valid(&p, 3, own2.digest(), 10_000_000_000_000);
        m.push_packet(own2.clone());
        m.push_packet(own3.clone());
        let proposed3 = Packet { previous: g.digest(), ..own3.clone() };
        assert!(matches!(m.on_proposal(3, &proposed3, Some(&gc)), Outcome::Voted { .. }));
        // previous must be the parent digest.
        let bad = Packet { previous: [7; 32], ..own3.clone() };
        assert!(matches!(m.on_proposal(3, &bad, Some(&gc)), Outcome::Refused(_)));
        // Parent whose signatures are tampered.
        let mut forged = gc.clone();
        forged.packet.mark = Mark::Hold { reason: 2 };
        let mut m2 = core(&tmp("parent2"), 3);
        m2.push_packet(own3.clone());
        let p_forged = Packet { previous: forged.packet.digest(), ..own3.clone() };
        assert!(matches!(m2.on_proposal(3, &p_forged, Some(&forged)), Outcome::Refused(r) if r.contains("invalid")));
        // No parent is admissible only for genesis.
        assert!(matches!(m2.on_proposal(3, &own3, None), Outcome::Refused(_)));
        // A stale parent (older than one already accepted) is refused.
        let own4 = valid(&p, 4, [0; 32], 10_000_000_000_000);
        let g2 = cert(&p, valid(&p, 2, g.digest(), 10_000_000_000_000));
        let own5 = valid(&p, 5, g2.packet.digest(), 10_000_000_000_000);
        let mut m3 = core(&tmp("parent3"), 4);
        m3.push_packet(own5.clone());
        m3.push_packet(Packet { previous: g.digest(), ..own4.clone() });
        assert!(matches!(m3.on_proposal(5, &own5, Some(&g2)), Outcome::Voted { .. }));
        let stale = Packet { previous: g.digest(), ..own4.clone() };
        assert!(matches!(m3.on_proposal(4, &stale, Some(&gc)), Outcome::Refused(r) if r.contains("stale")));
    }

    #[test]
    fn restart_refuses_a_different_digest_for_a_signed_sequence() {
        let p = policy();
        let d = tmp("restart");
        let a = valid(&p, 7, [5; 32], 10_000_000_000_000);
        let b = valid(&p, 7, [5; 32], 10_050_000_000_000);
        let parent = cert(&p, valid(&p, 1, [0; 32], 10_000_000_000_000));
        let (pa, pb) = (Packet { previous: parent.packet.digest(), ..a.clone() }, Packet { previous: parent.packet.digest(), ..b.clone() });
        {
            let mut m = core(&d, 0);
            m.push_packet(a.clone());
            assert!(matches!(m.on_proposal(7, &pa, Some(&parent)), Outcome::Voted { .. }));
        }
        // Process restart: fresh core on the same lock file, a different local view of slot 7.
        let mut m = core(&d, 0);
        assert_eq!(m.lock_high_water(), 7);
        m.push_packet(b.clone());
        match m.on_proposal(7, &pb, Some(&parent)) {
            Outcome::Refused(r) => assert!(r.contains("already signed"), "{r}"),
            o => panic!("restarted member signed a second digest: {o:?}"),
        }
        // The same digest is idempotent after restart; an older slot is refused.
        let mut m = core(&d, 0);
        m.push_packet(a.clone());
        assert!(matches!(m.on_proposal(7, &pa, Some(&parent)), Outcome::Voted { .. }));
        let old = valid(&p, 6, [5; 32], 10_000_000_000_000);
        m.push_packet(old.clone());
        assert!(matches!(m.on_proposal(6, &Packet { previous: parent.packet.digest(), ..old }, Some(&parent)), Outcome::Refused(_)));
    }

    #[test]
    fn member_key_must_match_policy() {
        let p = policy();
        let lock = DurableSignLock::open(&tmp("key").join("x.lock")).unwrap();
        assert!(MemberCore::new(&p, 0, [0x77; 32], lock).is_err());
    }
}
