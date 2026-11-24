//! Transport-agnostic relay core: verifies certified packets, enforces
//! sequence continuity and replay/equivocation rules, schedules per-tier
//! release of the same canonical packet, applies backpressure, and serves
//! tier-gated catch-up and checkpoints. The server module only moves bytes.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, VecDeque},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use shz_oracle::hft_packets::Mark;
use thiserror::Error;
use tokio::sync::mpsc;

use crate::{
    envelope::{CertifiedPacket, EnvelopeError, Hash, PacketVerifier, SecurityMode, WireCertified},
    metrics::RelayMetrics,
    schedule::{ReleasePolicy, Tier},
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HubError {
    #[error("verification: {0}")]
    Verify(#[from] EnvelopeError),
    #[error("sequence gap: expected {expected}, got {got}")]
    Gap { expected: u64, got: u64 },
    #[error("previous-digest mismatch at {0}")]
    Chain(u64),
    #[error("conflicting certified packet for sequence {0}")]
    Equivocation(u64),
    #[error("requested sequence {0} is older than retained history; re-anchor from a checkpoint")]
    TooOld(u64),
    #[error("checkpoint log: {0}")]
    Io(String),
}

/// One outbound message, identical bytes for every subscriber of a tier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delivery {
    pub tier: Tier,
    pub seq: u64,
    pub digest: String,
    pub boundary_us: u64,
    pub certified_us: u64,
    pub release_at_us: u64,
    pub late: bool,
    pub certified: WireCertified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogRecord {
    seq: u64,
    boundary_us: u64,
    certified_us: u64,
    certified: WireCertified,
}

struct Entry {
    seq: u64,
    digest: Hash,
    boundary_us: u64,
    certified_us: u64,
    release: [(u64, bool); 3],
    wire: WireCertified,
    sent: [Option<Arc<Delivery>>; 3],
}

impl Entry {
    fn delivery(&mut self, t: Tier) -> Arc<Delivery> {
        let (release_at_us, late) = self.release[t.idx()];
        self.sent[t.idx()]
            .get_or_insert_with(|| {
                Arc::new(Delivery {
                    tier: t,
                    seq: self.seq,
                    digest: hex::encode(self.digest),
                    boundary_us: self.boundary_us,
                    certified_us: self.certified_us,
                    release_at_us,
                    late,
                    certified: self.wire.clone(),
                })
            })
            .clone()
    }
}

pub type SubId = u64;

struct Sub {
    tier: Tier,
    tx: mpsc::Sender<Arc<Delivery>>,
    /// Live delivery starts after catch-up delivered everything up to here.
    live_from: u64,
}

pub struct Hub {
    verifier: PacketVerifier,
    release: ReleasePolicy,
    last: Option<(u64, Hash)>,
    history: VecDeque<Entry>,
    history_cap: usize,
    queue: BinaryHeap<Reverse<(u64, u64, Tier)>>,
    subs: BTreeMap<SubId, Sub>,
    next_sub: SubId,
    log: Option<File>,
    pub metrics: RelayMetrics,
}

pub enum Published {
    New(Hash),
    Duplicate,
}

impl Hub {
    pub fn new(verifier: PacketVerifier, release: ReleasePolicy, history_cap: usize) -> Self {
        Self {
            verifier,
            release,
            last: None,
            history: VecDeque::new(),
            history_cap: history_cap.max(16),
            queue: BinaryHeap::new(),
            subs: BTreeMap::new(),
            next_sub: 1,
            log: None,
            metrics: RelayMetrics::default(),
        }
    }

    pub fn release_policy(&self) -> &ReleasePolicy {
        &self.release
    }
    pub fn last(&self) -> Option<(u64, Hash)> {
        self.last
    }
    /// The most recent certified packet still retained (restores the parent
    /// of a remote federation after a relay restart).
    pub fn last_certified(&self) -> Option<CertifiedPacket> {
        let e = self.history.back()?;
        CertifiedPacket::try_from(&e.wire).ok()
    }

    /// Open (and replay) an append-only checkpoint log. Each record is
    /// re-verified; any corruption or chain break fails closed.
    pub fn attach_log(&mut self, path: &Path) -> Result<usize, HubError> {
        let mut n = 0;
        if path.exists() {
            let f = File::open(path).map_err(|e| HubError::Io(e.to_string()))?;
            for line in BufReader::new(f).lines() {
                let line = line.map_err(|e| HubError::Io(e.to_string()))?;
                let rec: LogRecord = serde_json::from_str(&line).map_err(|e| HubError::Io(e.to_string()))?;
                let c = CertifiedPacket::try_from(&rec.certified)?;
                let boundary = self.verifier.policy().fast_at(c.packet().seq).ok();
                if rec.seq != c.packet().seq || boundary != Some(rec.boundary_us) {
                    return Err(HubError::Io("checkpoint record does not match its certified packet".into()));
                }
                self.insert(c, rec.boundary_us, rec.certified_us, false)?;
                n += 1;
            }
            // Restored history is released (historical); nothing is re-queued.
            self.queue.clear();
            for e in self.history.iter_mut() {
                for t in Tier::ALL {
                    e.delivery(t);
                }
            }
        }
        self.log = Some(OpenOptions::new().create(true).append(true).open(path).map_err(|e| HubError::Io(e.to_string()))?);
        Ok(n)
    }

    /// Verify and accept the next certified packet.
    pub fn publish(&mut self, c: CertifiedPacket, certified_us: u64) -> Result<Published, HubError> {
        let boundary = self.verifier.policy().fast_at(c.packet().seq).map_err(|e| HubError::Verify(EnvelopeError::Packet(e)))?;
        match self.insert(c, boundary, certified_us, true) {
            Ok(p) => Ok(p),
            Err(e) => {
                match &e {
                    HubError::Equivocation(_) => self.metrics.equivocations += 1,
                    HubError::Gap { .. } | HubError::Chain(_) => self.metrics.gaps += 1,
                    _ => self.metrics.rejected += 1,
                }
                Err(e)
            }
        }
    }

    fn insert(&mut self, c: CertifiedPacket, boundary_us: u64, certified_us: u64, live: bool) -> Result<Published, HubError> {
        let digest = self.verifier.verify(&c)?;
        let seq = c.packet().seq;
        if let Some((ls, ld)) = self.last {
            if seq <= ls {
                let known = self.history.iter().find(|e| e.seq == seq).map(|e| e.digest);
                return match known {
                    Some(d) if d == digest => {
                        self.metrics.duplicates += 1;
                        Ok(Published::Duplicate)
                    }
                    Some(_) => Err(HubError::Equivocation(seq)),
                    None => Err(HubError::TooOld(seq)),
                };
            }
            if seq != ls + 1 {
                // A federated certificate may skip uncertified slots, but only
                // by linking to the last certified digest: nothing certified
                // can lie between, so the chain stays unforked.
                let linked_skip = self.verifier.mode() == SecurityMode::Federated && seq > ls + 1 && c.packet().previous == ld;
                if !linked_skip {
                    return Err(HubError::Gap { expected: ls + 1, got: seq });
                }
                self.metrics.skipped_slots += seq - ls - 1;
            } else if c.packet().previous != ld {
                return Err(HubError::Chain(seq));
            }
        }
        if live {
            if let Some(log) = self.log.as_mut() {
                let rec = LogRecord { seq, boundary_us, certified_us, certified: (&c).into() };
                let mut line = serde_json::to_string(&rec).map_err(|e| HubError::Io(e.to_string()))?;
                line.push('\n');
                log.write_all(line.as_bytes()).and_then(|_| log.sync_data()).map_err(|e| HubError::Io(e.to_string()))?;
            }
        }
        let release = Tier::ALL.map(|t| self.release.release_at(t, boundary_us, certified_us));
        if release[0].1 {
            self.metrics.late_certificates += 1;
        }
        if matches!(c.packet().mark, Mark::Hold { .. }) {
            self.metrics.hold_packets += 1;
        }
        self.metrics.certify_after_boundary.record(certified_us.saturating_sub(boundary_us));
        for t in Tier::ALL {
            self.queue.push(Reverse((release[t.idx()].0, seq, t)));
        }
        self.history.push_back(Entry {
            seq,
            digest,
            boundary_us,
            certified_us,
            release,
            wire: (&c).into(),
            sent: [None, None, None],
        });
        while self.history.len() > self.history_cap {
            self.history.pop_front();
        }
        self.last = Some((seq, digest));
        self.metrics.published += 1;
        Ok(Published::New(digest))
    }

    /// Next scheduled release instant, if any.
    pub fn next_due(&self) -> Option<u64> {
        self.queue.peek().map(|Reverse((t, _, _))| *t)
    }

    /// Deliver everything due at `now_us`. A full subscriber queue is a
    /// lagging client: it is disconnected (never blocks the hub, never
    /// silently skips a packet) and must resume via catch-up.
    pub fn deliver_due(&mut self, now_us: u64) -> usize {
        let mut sent = 0;
        while let Some(&Reverse((at, seq, tier))) = self.queue.peek() {
            if at > now_us {
                break;
            }
            self.queue.pop();
            let Some(entry) = self.history.iter_mut().find(|e| e.seq == seq) else { continue };
            let d = entry.delivery(tier);
            self.metrics.send_after_boundary[tier.idx()].record(now_us.saturating_sub(d.boundary_us));
            self.metrics.send_after_release[tier.idx()].record(now_us.saturating_sub(d.release_at_us));
            let mut dead = Vec::new();
            for (id, s) in self.subs.iter().filter(|(_, s)| s.tier == tier && seq > s.live_from) {
                match s.tx.try_send(d.clone()) {
                    Ok(()) => {
                        sent += 1;
                        self.metrics.deliveries[tier.idx()] += 1;
                    }
                    Err(_) => dead.push(*id),
                }
            }
            for id in dead {
                self.drop_sub(id, true);
            }
        }
        sent
    }

    /// Register a subscriber. With `from_seq`, every retained packet with
    /// `seq >= from_seq` that is ALREADY released for this tier at `now_us`
    /// is queued first (no early leak through catch-up); later packets
    /// arrive live in order.
    pub fn subscribe(&mut self, tier: Tier, capacity: usize, from_seq: Option<u64>, now_us: u64) -> Result<(SubId, mpsc::Receiver<Arc<Delivery>>), HubError> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let mut live_from = self.last.map(|l| l.0).unwrap_or(0);
        if let Some(from) = from_seq {
            if let Some(first) = self.history.front() {
                if from < first.seq {
                    return Err(HubError::TooOld(from));
                }
            }
            let mut backlog = Vec::new();
            for e in self.history.iter_mut().filter(|e| e.seq >= from) {
                if e.release[tier.idx()].0 <= now_us && (e.sent[tier.idx()].is_some() || e.release[tier.idx()].0 <= now_us) {
                    backlog.push(e.delivery(tier));
                } else {
                    break;
                }
            }
            live_from = backlog.last().map(|d| d.seq).unwrap_or(from.saturating_sub(1));
            if backlog.len() > capacity {
                return Err(HubError::TooOld(from));
            }
            for d in backlog {
                tx.try_send(d).expect("capacity checked");
            }
        }
        let id = self.next_sub;
        self.next_sub += 1;
        self.subs.insert(id, Sub { tier, tx, live_from });
        self.metrics.active_subscribers[tier.idx()] += 1;
        Ok((id, rx))
    }

    pub fn drop_sub(&mut self, id: SubId, lagging: bool) {
        if let Some(s) = self.subs.remove(&id) {
            self.metrics.active_subscribers[s.tier.idx()] -= 1;
            if lagging {
                self.metrics.lagging_disconnects += 1;
            }
        }
    }

    /// Checkpoint for `tier`: the packet only if already released to it.
    pub fn checkpoint(&mut self, tier: Tier, seq: Option<u64>, now_us: u64) -> Option<Arc<Delivery>> {
        let e = match seq {
            Some(s) => self.history.iter_mut().find(|e| e.seq == s)?,
            None => self.history.iter_mut().rev().find(|e| e.release[tier.idx()].0 <= now_us)?,
        };
        (e.release[tier.idx()].0 <= now_us).then(|| e.delivery(tier))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        authority::{DurableSignLock, PacketAuthority, TrustedRelaySigner},
        envelope::sign_trusted,
    };
    use shz_oracle::hft_packets::{Packet, Policy};

    pub fn policy() -> Policy {
        Policy {
            network: [9; 32],
            market: [8; 32],
            epoch: 1,
            origin_us: 10_000_000,
            members: std::array::from_fn(|i| shz_dlc::pubkey_x_from_secret(&[(i + 1) as u8; 32]).unwrap()),
        }
    }
    const SK: Hash = [0x99; 32];
    fn hub() -> Hub {
        let p = policy();
        Hub::new(PacketVerifier::trusted(p, shz_dlc::pubkey_x_from_secret(&SK).unwrap()).unwrap(), ReleasePolicy::default(), 64)
    }
    fn chain(n: u64) -> Vec<CertifiedPacket> {
        let p = policy();
        let mut prev = [0; 32];
        (1..=n)
            .map(|seq| {
                let pk = Packet { policy: p.id().unwrap(), seq, previous: prev, mark: Mark::Hold { reason: 1 } };
                prev = pk.digest();
                CertifiedPacket::Trusted(sign_trusted(&p.id().unwrap(), &SK, pk).unwrap())
            })
            .collect()
    }
    fn b(seq: u64) -> u64 {
        10_000_000 + (seq - 1) * 200_000
    }

    #[test]
    fn tiers_receive_same_packet_at_scheduled_times() {
        let mut h = hub();
        let (_, mut p) = h.subscribe(Tier::Premium, 8, None, 0).unwrap();
        let (_, mut i) = h.subscribe(Tier::Intermediate, 8, None, 0).unwrap();
        let (_, mut s) = h.subscribe(Tier::Standard, 8, None, 0).unwrap();
        let c = chain(1).remove(0);
        h.publish(c, b(1) + 3_000).unwrap();
        assert_eq!(h.deliver_due(b(1) + 3_000), 1);
        assert!(i.try_recv().is_err() && s.try_recv().is_err());
        let dp = p.try_recv().unwrap();
        h.deliver_due(b(1) + 101_999);
        assert!(i.try_recv().is_err());
        h.deliver_due(b(1) + 102_000);
        let di = i.try_recv().unwrap();
        h.deliver_due(b(1) + 202_000);
        let ds = s.try_recv().unwrap();
        assert_eq!(dp.certified, ds.certified);
        assert_eq!(di.digest, ds.digest);
        assert_eq!((dp.release_at_us, di.release_at_us, ds.release_at_us), (b(1) + 3_000, b(1) + 102_000, b(1) + 202_000));
    }

    #[test]
    fn replay_gap_equivocation_and_mode() {
        let mut h = hub();
        let c = chain(3);
        h.publish(c[0].clone(), b(1)).unwrap();
        assert!(matches!(h.publish(c[0].clone(), b(1)), Ok(Published::Duplicate)));
        assert_eq!(h.publish(c[2].clone(), b(3)).err(), Some(HubError::Gap { expected: 2, got: 3 }));
        // Same seq, different content.
        let p = policy();
        let alt = Packet { policy: p.id().unwrap(), seq: 1, previous: [0; 32], mark: Mark::Hold { reason: 2 } };
        let alt = CertifiedPacket::Trusted(sign_trusted(&p.id().unwrap(), &SK, alt).unwrap());
        assert_eq!(h.publish(alt, b(1)).err(), Some(HubError::Equivocation(1)));
        // Broken previous link.
        let bad = Packet { policy: p.id().unwrap(), seq: 2, previous: [7; 32], mark: Mark::Hold { reason: 1 } };
        let bad = CertifiedPacket::Trusted(sign_trusted(&p.id().unwrap(), &SK, bad).unwrap());
        assert_eq!(h.publish(bad, b(2)).err(), Some(HubError::Chain(2)));
        // Federated-labelled input refused by a trusted hub.
        let mut f = crate::authority::LocalFederation::new(&p, &std::array::from_fn(|i| [(i + 1) as u8; 32]), &std::env::temp_dir().join(format!("shz-hub-fed-{}", std::process::id()))).unwrap();
        let fc = f.certify(&Packet { policy: p.id().unwrap(), seq: 2, previous: c[0].digest(), mark: Mark::Hold { reason: 1 } }).unwrap();
        assert_eq!(h.publish(fc, b(2)).err(), Some(HubError::Verify(EnvelopeError::ModeMismatch)));
        assert_eq!(h.metrics.equivocations, 1);
    }

    #[test]
    fn federated_hub_accepts_only_linked_skips() {
        use shz_oracle::hft_packets::{Certificate, Signer};
        let p = policy();
        let mut ss: Vec<_> = (0..5).map(|i| Signer::new(&p, i, [(i + 1) as u8; 32]).unwrap()).collect();
        let cert = |ss: &mut Vec<Signer>, seq: u64, previous: Hash| {
            let pk = Packet { policy: p.id().unwrap(), seq, previous, mark: Mark::Hold { reason: 1 } };
            let votes = ss.iter_mut().take(4).map(|s| s.vote(&p, &pk).unwrap()).collect();
            CertifiedPacket::Federated(Certificate { packet: pk, votes })
        };
        let mut h = Hub::new(PacketVerifier::federated(p.clone()).unwrap(), ReleasePolicy::default(), 64);
        let c1 = cert(&mut ss, 1, [0; 32]);
        h.publish(c1.clone(), b(1)).unwrap();
        // seq 4 linked to seq 1: accepted, slots 2 and 3 counted as skipped.
        let c4 = cert(&mut ss, 4, c1.digest());
        h.publish(c4.clone(), b(4)).unwrap();
        assert_eq!(h.metrics.skipped_slots, 2);
        assert_eq!(h.last().unwrap().0, 4);
        // A skip that does not link to the last certified digest is a gap.
        let bad = cert(&mut ss, 7, c1.digest());
        assert_eq!(h.publish(bad, b(7)).err(), Some(HubError::Gap { expected: 5, got: 7 }));
        // The trusted hub never accepts a skip, linked or not.
        let mut t = hub();
        let tc = chain(3);
        t.publish(tc[0].clone(), b(1)).unwrap();
        assert!(matches!(t.publish(tc[2].clone(), b(3)).err(), Some(HubError::Gap { .. })));
    }

    #[test]
    fn catch_up_never_leaks_unreleased_packets() {
        let mut h = hub();
        for (k, c) in chain(5).into_iter().enumerate() {
            h.publish(c, b(k as u64 + 1) + 1_000).unwrap();
        }
        // At b(5)+2ms: standard has released 1..=4 (release b(k)+202ms <= b(4)+202ms).
        let now = b(5) + 2_000;
        let (_, mut s) = h.subscribe(Tier::Standard, 16, Some(1), now).unwrap();
        let got: Vec<u64> = std::iter::from_fn(|| s.try_recv().ok()).map(|d| d.seq).collect();
        assert_eq!(got, vec![1, 2, 3, 4]);
        let (_, mut p) = h.subscribe(Tier::Premium, 16, Some(1), now).unwrap();
        assert_eq!(std::iter::from_fn(|| p.try_recv().ok()).count(), 5);
        assert!(h.checkpoint(Tier::Standard, Some(5), now).is_none());
        assert!(h.checkpoint(Tier::Premium, Some(5), now).is_some());
        assert_eq!(h.checkpoint(Tier::Standard, None, now).unwrap().seq, 4);
        // Live after catch-up: seq 5 arrives exactly once for standard.
        h.deliver_due(b(5) + 300_000);
        let live: Vec<u64> = std::iter::from_fn(|| s.try_recv().ok()).map(|d| d.seq).collect();
        assert_eq!(live, vec![5]);
    }

    #[test]
    fn lagging_subscriber_is_disconnected_not_blocking() {
        let mut h = hub();
        let (_, mut slow) = h.subscribe(Tier::Premium, 2, None, 0).unwrap();
        let (_, mut fast) = h.subscribe(Tier::Premium, 64, None, 0).unwrap();
        for (k, c) in chain(5).into_iter().enumerate() {
            let t = b(k as u64 + 1);
            h.publish(c, t).unwrap();
            h.deliver_due(t);
            fast.try_recv().unwrap();
        }
        assert_eq!(h.metrics.lagging_disconnects, 1);
        assert_eq!(std::iter::from_fn(|| slow.try_recv().ok()).count(), 2);
        assert!(slow.try_recv().is_err());
    }

    #[test]
    fn checkpoint_log_restores_chain_after_restart() {
        let dir = std::env::temp_dir().join(format!("shz-hub-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("checkpoints.jsonl");
        let c = chain(4);
        {
            let mut h = hub();
            h.attach_log(&path).unwrap();
            for (k, x) in c.iter().take(3).enumerate() {
                h.publish(x.clone(), b(k as u64 + 1)).unwrap();
            }
        }
        let mut h = hub();
        assert_eq!(h.attach_log(&path).unwrap(), 3);
        assert_eq!(h.last().unwrap().0, 3);
        h.publish(c[3].clone(), b(4)).unwrap();
        // Corrupt a byte: restart fails closed.
        let mut raw = std::fs::read_to_string(&path).unwrap();
        raw = raw.replacen("\"seq\":2", "\"seq\":9", 1);
        std::fs::write(&path, raw).unwrap();
        assert!(hub().attach_log(&path).is_err());
        let _ = TrustedRelaySigner::new(&policy(), SK, DurableSignLock::open(&dir.join("l")).unwrap()).unwrap();
    }
}
