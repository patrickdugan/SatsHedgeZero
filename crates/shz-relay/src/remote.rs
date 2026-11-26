//! Relay side of the federation vote transport (gate G-FED-1).
//!
//! Five independent member processes (see [`crate::member`]) connect to the
//! relay's vote endpoint. For every slot the relay broadcasts a *proposal*;
//! each member votes only when the proposal equals the packet it rebuilt on
//! its own from its own authenticated source feed. The relay verifies every
//! vote, assembles the HFT-04 4-of-5 certificate with [`FederatedCollector`]
//! and publishes it.
//!
//! Wire protocol (JSON text frames over WebSocket):
//! 1. relay -> member `{"type":"challenge","nonce":hex,"relay_id":hex,"server_us":u64}`
//! 2. member -> relay `{"type":"auth","member":0..4,"signature":hex64}`, BIP340 by the
//!    policy member key over `tagged_hash("SHZ/HFT06/MEMBER-AUTH/V1", relay_id || nonce || member)`.
//!    The registry is `policy.members`; there is no other way to be admitted.
//! 3. relay -> member `{"type":"ready","last_certified":u64|null}`, then per slot
//!    `{"type":"proposal","seq","packet","parent":Certified|null,"deadline_us"}`
//!    and, once a certificate forms, `{"type":"certified","certified":..}`.
//! 4. member -> relay `{"type":"vote","seq","digest","signature"}`,
//!    `{"type":"disagree","seq","own_digest","proposal_digest"}` or
//!    `{"type":"refuse","seq","reason"}`.
//!
//! **Chaining rule.** `previous` of a packet is the digest of the last
//! *certified* packet, never of the last proposed one. The proposal carries
//! that parent certificate; a member verifies it (4-of-5, once per
//! certificate), requires `parent.seq < seq`, `proposal.previous == digest(parent)`
//! and a parent that is not older than any parent it has already seen, then
//! rebuilds its own packet for `seq` with `previous` set to that parent digest
//! and compares digests. A slot that misses quorum by its certification
//! deadline is abandoned (`quorum_timeouts`); the next proposal links to the
//! last certified packet and its `seq` jumps over the abandoned slots. The hub
//! and the tiered receiver accept such a jump only in federated mode and only
//! when `previous` equals the last accepted digest, so the chain cannot fork.
//! Before any certificate exists the only admissible proposal is `seq = 1`
//! with `previous = 0` (genesis), proposed from the collator's slot-1 record.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use shz_dlc::{Bip340Signature, bip340_sign, bip340_verify, tagged_hash};
use shz_oracle::hft_packets::{Certificate, Packet, Policy, Vote};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc, watch},
};
use tokio_tungstenite::tungstenite::Message;

use crate::{
    authority::FederatedCollector,
    envelope::{CertifiedPacket, Hash, WireCertified, WirePacket},
    schedule::MonoClock,
};

pub fn member_auth_message(relay_id: &Hash, nonce: &Hash, member: u8) -> Hash {
    let mut b = Vec::with_capacity(65);
    b.extend(relay_id);
    b.extend(nonce);
    b.push(member);
    tagged_hash(b"SHZ/HFT06/MEMBER-AUTH/V1", &b)
}

pub fn sign_member_auth(secret: &Hash, relay_id: &Hash, nonce: &Hash, member: u8) -> Bip340Signature {
    bip340_sign(secret, &member_auth_message(relay_id, nonce, member)).expect("valid member key")
}

pub fn sig_to_hex(s: &Bip340Signature) -> String {
    hex::encode(s.to_bytes())
}

pub fn sig_from_hex(s: &str) -> Option<Bip340Signature> {
    let v = hex::decode(s).ok().filter(|v| v.len() == 64)?;
    Some(Bip340Signature { r_x: v[..32].try_into().ok()?, s: v[32..].try_into().ok()? })
}

pub fn cert_to_wire(c: &Certificate) -> WireCertified {
    WireCertified::from(&CertifiedPacket::Federated(c.clone()))
}

pub fn wire_to_cert(w: &WireCertified) -> Result<Certificate, String> {
    match CertifiedPacket::try_from(w).map_err(|e| e.to_string())? {
        CertifiedPacket::Federated(c) => Ok(c),
        CertifiedPacket::Trusted(_) => Err("trusted packet where a federated certificate is required".into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalMsg {
    pub seq: u64,
    pub packet: WirePacket,
    pub parent: Option<WireCertified>,
    /// Absolute certification deadline on the relay's (unix-anchored) clock.
    pub deadline_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToMember {
    Challenge { nonce: String, relay_id: String, server_us: u64 },
    Ready { last_certified: Option<u64> },
    Proposal(ProposalMsg),
    Certified { certified: WireCertified },
    Error { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MemberToRelay {
    Auth { member: u8, signature: String },
    Vote { seq: u64, digest: String, signature: String },
    Disagree { seq: u64, own_digest: String, proposal_digest: String },
    Refuse { seq: u64, reason: String },
}

/// Two valid signatures by one member over different digests for one slot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Evidence {
    pub seq: u64,
    pub member: u8,
    pub digest_a: String,
    pub digest_b: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FedMetrics {
    pub quorum_timeouts: u64,
    pub certified: u64,
    pub votes_accepted: u64,
    pub votes_rejected: u64,
    pub off_proposal_votes: u64,
    pub equivocations: u64,
    pub disagreements: u64,
    pub refusals: u64,
    pub auth_failures: u64,
    pub connects: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FedSnapshot {
    pub metrics: FedMetrics,
    pub connected: [bool; 5],
    pub evidence: Vec<Evidence>,
    pub parent_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertifyError {
    /// No quorum by the certification deadline; the slot is abandoned.
    Timeout { seq: u64 },
    /// A certificate at or above this sequence already exists.
    AlreadyCertified,
    /// No certified parent exists and `seq != 1`.
    NoParent,
}

struct Conn {
    id: u64,
    tx: mpsc::UnboundedSender<Arc<String>>,
}

struct Current {
    packet: Packet,
    digest: Hash,
    text: Arc<String>,
}

struct Inner {
    collector: FederatedCollector,
    parent: Option<Certificate>,
    current: Option<Current>,
    cert: Option<Certificate>,
    conns: [Option<Conn>; 5],
    next_conn: u64,
    seen: BTreeMap<(u64, u8), Hash>,
    evidence: Vec<Evidence>,
    metrics: FedMetrics,
}

pub struct RemoteFed {
    policy: Policy,
    relay_id: Hash,
    clock: MonoClock,
    inner: Mutex<Inner>,
    notify: Notify,
}

const SEEN_WINDOW: u64 = 2_048;
const EVIDENCE_CAP: usize = 256;

impl RemoteFed {
    pub fn new(policy: Policy, relay_id: Hash, clock: MonoClock, parent: Option<Certificate>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                collector: FederatedCollector::new(policy.clone()),
                parent,
                current: None,
                cert: None,
                conns: Default::default(),
                next_conn: 1,
                seen: BTreeMap::new(),
                evidence: Vec::new(),
                metrics: FedMetrics::default(),
            }),
            policy,
            relay_id,
            clock,
            notify: Notify::new(),
        }
    }

    pub fn parent_seq(&self) -> Option<u64> {
        self.inner.lock().unwrap().parent.as_ref().map(|c| c.packet.seq)
    }

    pub fn snapshot(&self) -> FedSnapshot {
        let g = self.inner.lock().unwrap();
        FedSnapshot {
            metrics: g.metrics.clone(),
            connected: std::array::from_fn(|i| g.conns[i].is_some()),
            evidence: g.evidence.clone(),
            parent_seq: g.parent.as_ref().map(|c| c.packet.seq),
        }
    }

    pub fn prometheus(&self) -> String {
        let s = self.snapshot();
        let m = &s.metrics;
        let mut out = String::new();
        for (k, v) in [
            ("quorum_timeouts", m.quorum_timeouts),
            ("member_certified", m.certified),
            ("member_votes_accepted", m.votes_accepted),
            ("member_votes_rejected", m.votes_rejected),
            ("member_off_proposal_votes", m.off_proposal_votes),
            ("member_equivocations", m.equivocations),
            ("member_disagreements", m.disagreements),
            ("member_refusals", m.refusals),
            ("member_auth_failures", m.auth_failures),
            ("member_connects", m.connects),
        ] {
            out.push_str(&format!("shz_relay_{k}_total {v}\n"));
        }
        for (i, c) in s.connected.iter().enumerate() {
            out.push_str(&format!("shz_relay_member_connected{{member=\"{i}\"}} {}\n", *c as u8));
        }
        out
    }

    pub fn health_json(&self) -> serde_json::Value {
        let s = self.snapshot();
        serde_json::json!({
            "members_connected": s.connected,
            "quorum_timeouts": s.metrics.quorum_timeouts,
            "member_equivocations": s.metrics.equivocations,
            "member_disagreements": s.metrics.disagreements,
            "member_auth_failures": s.metrics.auth_failures,
            "member_equivocation_evidence": s.evidence,
        })
    }

    /// Propose `packet` (its `previous` is rewritten to the digest of the
    /// last certified packet) and wait for four valid votes until `deadline_us`.
    pub async fn certify(&self, mut packet: Packet, deadline_us: u64) -> Result<Certificate, CertifyError> {
        let seq = packet.seq;
        {
            let mut g = self.inner.lock().unwrap();
            let parent = g.parent.clone();
            match &parent {
                Some(par) if par.packet.seq >= seq => return Err(CertifyError::AlreadyCertified),
                Some(par) => packet.previous = par.packet.digest(),
                None if seq != 1 => return Err(CertifyError::NoParent),
                None => packet.previous = [0; 32],
            }
            let msg = RelayToMember::Proposal(ProposalMsg {
                seq,
                packet: (&packet).into(),
                parent: parent.as_ref().map(cert_to_wire),
                deadline_us,
            });
            let text = Arc::new(serde_json::to_string(&msg).expect("serializable"));
            g.cert = None;
            g.current = Some(Current { digest: packet.digest(), packet, text: text.clone() });
            for c in g.conns.iter().flatten() {
                let _ = c.tx.send(text.clone());
            }
        }
        loop {
            if let Some(cert) = self.finish(seq) {
                return Ok(cert);
            }
            let now = self.clock.now_us();
            if now >= deadline_us {
                let mut g = self.inner.lock().unwrap();
                if g.cert.is_none() {
                    g.current = None;
                    g.collector.prune_below(seq + 1);
                    g.metrics.quorum_timeouts += 1;
                    return Err(CertifyError::Timeout { seq });
                }
                continue;
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_micros(deadline_us - now)) => {}
            }
        }
    }

    /// Adopt a formed certificate as the new parent and tell the members.
    fn finish(&self, seq: u64) -> Option<Certificate> {
        let mut g = self.inner.lock().unwrap();
        let cert = g.cert.take()?;
        g.parent = Some(cert.clone());
        g.current = None;
        g.collector.prune_below(seq + 1);
        g.metrics.certified += 1;
        let text = Arc::new(serde_json::to_string(&RelayToMember::Certified { certified: cert_to_wire(&cert) }).expect("serializable"));
        for c in g.conns.iter().flatten() {
            let _ = c.tx.send(text.clone());
        }
        Some(cert)
    }

    /// Register an authenticated member connection (replacing any earlier
    /// one for the same member) and queue the proposal in flight.
    fn register(&self, member: u8) -> (u64, mpsc::UnboundedReceiver<Arc<String>>, Option<u64>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut g = self.inner.lock().unwrap();
        let id = g.next_conn;
        g.next_conn += 1;
        if let Some(cur) = &g.current {
            let _ = tx.send(cur.text.clone());
        }
        g.conns[member as usize] = Some(Conn { id, tx });
        g.metrics.connects += 1;
        let last = g.parent.as_ref().map(|c| c.packet.seq);
        (id, rx, last)
    }

    fn unregister(&self, member: u8, id: u64) {
        let mut g = self.inner.lock().unwrap();
        if g.conns[member as usize].as_ref().is_some_and(|c| c.id == id) {
            g.conns[member as usize] = None;
        }
    }

    fn note_auth_failure(&self) {
        self.inner.lock().unwrap().metrics.auth_failures += 1;
    }

    /// Verify and account a member vote.
    pub fn on_vote(&self, member: u8, seq: u64, digest: Hash, signature: Bip340Signature) {
        let Some(key) = self.policy.members.get(member as usize) else { return };
        let mut g = self.inner.lock().unwrap();
        if bip340_verify(key, &digest, &signature).is_err() {
            g.metrics.votes_rejected += 1;
            return;
        }
        match g.seen.get(&(seq, member)).copied() {
            Some(prev) if prev != digest => {
                g.metrics.equivocations += 1;
                if g.evidence.len() < EVIDENCE_CAP {
                    g.evidence.push(Evidence { seq, member, digest_a: hex::encode(prev), digest_b: hex::encode(digest) });
                }
                return;
            }
            // A member may vote again on the same digest when a slot is re-proposed (genesis).
            Some(_) => {}
            None => {
                g.seen.insert((seq, member), digest);
                while g.seen.first_key_value().is_some_and(|((s, _), _)| s + SEEN_WINDOW < seq) {
                    g.seen.pop_first();
                }
                g.metrics.votes_accepted += 1;
            }
        }
        let Some((packet, matches)) = g.current.as_ref().map(|c| (c.packet.clone(), c.packet.seq == seq && c.digest == digest)) else {
            g.metrics.off_proposal_votes += 1;
            return;
        };
        if !matches {
            g.metrics.off_proposal_votes += 1;
            return;
        }
        if g.cert.is_some() {
            return;
        }
        if let Some(cert) = g.collector.add_vote(&packet, Vote { member, signature }) {
            g.cert = Some(cert);
            drop(g);
            self.notify.notify_one();
        }
    }

    fn on_disagree(&self) {
        self.inner.lock().unwrap().metrics.disagreements += 1;
    }
    fn on_refuse(&self) {
        self.inner.lock().unwrap().metrics.refusals += 1;
    }
}

fn text(m: &RelayToMember) -> Message {
    Message::text(serde_json::to_string(m).expect("serializable"))
}

/// Accept member connections on `listener`. With `fed = None` (trusted-relay
/// mode) every connection receives an error and is closed.
pub async fn serve_members(fed: Option<Arc<RemoteFed>>, listener: TcpListener, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            r = listener.accept() => {
                if let Ok((stream, _)) = r {
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(handle_member(fed.clone(), stream, stop.clone()));
                }
            }
            _ = stop.changed() => return,
        }
    }
}

async fn handle_member(fed: Option<Arc<RemoteFed>>, stream: TcpStream, mut stop: watch::Receiver<bool>) {
    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
    let (mut tx, mut rx) = ws.split();
    let Some(fed) = fed else {
        let _ = tx.send(text(&RelayToMember::Error { reason: "relay is in trusted_relay mode: member connections refused".into() })).await;
        let _ = tx.close().await;
        return;
    };
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let challenge = RelayToMember::Challenge { nonce: hex::encode(nonce), relay_id: hex::encode(fed.relay_id), server_us: fed.clock.now_us() };
    if tx.send(text(&challenge)).await.is_err() {
        return;
    }
    let first = tokio::time::timeout(Duration::from_secs(5), rx.next()).await.ok().flatten();
    let parsed = first.and_then(|m| m.ok()).and_then(|m| serde_json::from_str::<MemberToRelay>(m.to_text().ok()?).ok());
    let member = match parsed {
        Some(MemberToRelay::Auth { member, signature }) => {
            let ok = fed.policy.members.get(member as usize).zip(sig_from_hex(&signature)).is_some_and(|(key, sig)| {
                bip340_verify(key, &member_auth_message(&fed.relay_id, &nonce, member), &sig).is_ok()
            });
            ok.then_some(member)
        }
        _ => None,
    };
    let Some(member) = member else {
        fed.note_auth_failure();
        let _ = tx.send(text(&RelayToMember::Error { reason: "authentication failed".into() })).await;
        return;
    };
    let (id, mut out, last) = fed.register(member);
    if tx.send(text(&RelayToMember::Ready { last_certified: last })).await.is_ok() {
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                m = out.recv() => match m {
                    Some(m) => if tx.send(Message::text(m.as_str().to_owned())).await.is_err() { break },
                    None => break, // superseded by a newer connection
                },
                m = rx.next() => {
                    let Some(Ok(m)) = m else { break };
                    let Ok(t) = m.to_text() else { continue };
                    match serde_json::from_str::<MemberToRelay>(t) {
                        Ok(MemberToRelay::Vote { seq, digest, signature }) => {
                            let d: Option<Hash> = hex::decode(&digest).ok().and_then(|v| v.try_into().ok());
                            if let (Some(d), Some(sig)) = (d, sig_from_hex(&signature)) {
                                fed.on_vote(member, seq, d, sig);
                            }
                        }
                        Ok(MemberToRelay::Disagree { .. }) => fed.on_disagree(),
                        Ok(MemberToRelay::Refuse { .. }) => fed.on_refuse(),
                        _ => {}
                    }
                }
            }
        }
    }
    fed.unregister(member, id);
}
