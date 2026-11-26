//! Channel adapter: moves each lane's cleared net amount through its LDK channel and binds
//! the persisted monitor state of both channel parties to the lane's V3 acknowledgement.
use crate::journal::{LaneJournal, MonitorRecord};
use crate::node::{LdkNode, wait_until};
use lightning::events::Event;
use lightning::ln::types::ChannelId;
use lightning::ln::channelmanager::{PaymentId, RecentPaymentDetails};
use lightning::types::payment::PaymentPreimage;
use sha2::{Digest, Sha256};
use shz_dex::routing::clearing::BatchClearing;
use shz_dex::routing::durable::{ChannelAck, Head};
use shz_dlc::{Bip340Signature, BtcOutPoint, tagged_hash};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// `ChannelAck::evidence` of a lane settled through LDK.
pub const EVIDENCE_TAG: &[u8] = b"SHZ/HFT06/LDK-MONITOR/V1";
/// `Head::state` chain: `tagged_hash(STATE_TAG, previous state ‖ evidence)`.
pub const STATE_TAG: &[u8] = b"SHZ/HFT06/LDK-LANE-STATE/V1";
const PAYMENT_ID_TAG: &[u8] = b"SHZ/HFT06/LDK-PAYMENT-ID/V1";
const PREIMAGE_TAG: &[u8] = b"SHZ/HFT06/LDK-PREIMAGE/V1";
const ZERO_SIG: Bip340Signature = Bip340Signature { r_x: [0; 32], s: [0; 32] };
const TIMEOUT: Duration = Duration::from_secs(60);

type Outpoint = ([u8; 32], u32);
fn op(c: &BtcOutPoint) -> Outpoint {
    (c.txid, c.vout)
}

#[derive(Debug, Error)]
pub enum SettleError {
    #[error("no lane bound for channel {0:?}")]
    UnknownLane(BtcOutPoint),
    #[error("lane {channel:?}: net {net} sats exceeds the paying side's balance")]
    Liquidity { channel: BtcOutPoint, net: i64 },
    #[error("lane {channel:?}: payment failed: {reason}")]
    Payment { channel: BtcOutPoint, reason: String },
    #[error("lane {channel:?}: persisted monitors did not reach the cleared balance: {reason}")]
    Monitor { channel: BtcOutPoint, reason: String },
    #[error("no channel between the venue and {0}")]
    NoChannel(String),
    #[error("adapter state file: {0}")]
    State(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("journal unreadable: {0}")]
    Journal(String),
    #[error("record not in the signer's own journal")]
    NotJournaled,
    #[error("a later channel update supersedes the record")]
    Superseded,
    #[error("persisted balance {found} sats, cleared ledger says {expected}")]
    Balance { found: u64, expected: u64 },
    #[error("HTLC still pending on the persisted state")]
    Pending,
    #[error("evidence digest does not match the settlement")]
    Evidence,
}

/// Which side of the channel a record or a signer belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The venue node (clearing pool); signs as the lane's pinned peer.
    Venue,
    /// The account's node; signs as the lane's owner.
    Owner,
}

/// Everything one lane did for one batch, and the records that prove it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneSettlement {
    pub sequence: u64,
    pub channel: BtcOutPoint,
    /// `ClearingRow::net`: positive pays the account, negative collects from it.
    pub net: i64,
    /// Keysend payment hash (zero when `net == 0`).
    pub payment_hash: [u8; 32],
    /// Venue-side and owner-side monitor records after the update.
    pub venue: MonitorRecord,
    pub owner: MonitorRecord,
    /// Holder balances the cleared ledger implies for each side.
    pub venue_expected: u64,
    pub owner_expected: u64,
}

impl LaneSettlement {
    /// `tagged_hash("SHZ/HFT06/LDK-MONITOR/V1", sequence ‖ channel ‖ net ‖ payment hash ‖
    /// venue record digest ‖ owner record digest)`.
    pub fn evidence(&self) -> [u8; 32] {
        let mut b = Vec::with_capacity(180);
        b.extend(self.sequence.to_le_bytes());
        b.extend(self.channel.txid);
        b.extend(self.channel.vout.to_le_bytes());
        b.extend(self.net.to_le_bytes());
        b.extend(self.payment_hash);
        b.extend(self.venue.digest());
        b.extend(self.owner.digest());
        tagged_hash(EVIDENCE_TAG, &b)
    }

    /// The lane's unsigned acknowledgement: the logical revision and the commitment counter
    /// advance by one, the state hash chains the evidence. `fee_evidence` is zero; fee receipts
    /// are a separate gate, so a lane whose batch fee is non-zero cannot resolve with this ack.
    pub fn ack(&self, previous: Head) -> ChannelAck {
        let evidence = self.evidence();
        let mut s = Vec::with_capacity(64);
        s.extend(previous.state);
        s.extend(evidence);
        ChannelAck {
            channel: self.channel.clone(),
            previous,
            next: Head {
                revision: previous.revision + 1,
                commitment: previous.commitment + 1,
                state: tagged_hash(STATE_TAG, &s),
            },
            evidence,
            fee_evidence: [0; 32],
            signatures: [ZERO_SIG; 3],
        }
    }

    pub fn record(&self, side: Side) -> &MonitorRecord {
        match side {
            Side::Venue => &self.venue,
            Side::Owner => &self.owner,
        }
    }
    pub fn expected(&self, side: Side) -> u64 {
        match side {
            Side::Venue => self.venue_expected,
            Side::Owner => self.owner_expected,
        }
    }
}

/// Check a signer runs before it signs a lane's acknowledgement, against its own durable
/// journal file (re-read and hash-chain verified, not the in-memory index): the record the
/// settlement names for this side is journaled, no later channel update superseded it, no
/// HTLC is pending on it, it shows the balance the cleared ledger implies, and `evidence` is
/// the digest of this settlement.
pub fn attest(journal: &Path, s: &LaneSettlement, side: Side, evidence: &[u8; 32]) -> Result<(), AttestError> {
    if s.evidence() != *evidence {
        return Err(AttestError::Evidence);
    }
    let rec = s.record(side);
    let records = LaneJournal::read(journal).map_err(|e| AttestError::Journal(e.to_string()))?;
    if !records.iter().any(|r| r == rec) {
        return Err(AttestError::NotJournaled);
    }
    let last = records.iter().rev().find(|r| r.channel_id == rec.channel_id).expect("record present");
    if last.update_id != rec.update_id || last.holder_sats != rec.holder_sats {
        return Err(AttestError::Superseded);
    }
    if !rec.settled() {
        return Err(AttestError::Pending);
    }
    if rec.holder_sats != s.expected(side) {
        return Err(AttestError::Balance { found: rec.holder_sats, expected: s.expected(side) });
    }
    Ok(())
}

struct Lane {
    owner: Arc<LdkNode>,
    channel_id: [u8; 32],
    venue_base: u64,
    owner_base: u64,
    /// Σ net moved on this lane through batch `last_seq` (inclusive).
    moved: i64,
    last_seq: u64,
    last_hash: [u8; 32],
    /// Payment attempts made so far (ids and preimages are derived per attempt).
    attempts: u32,
    /// Payment of the batch in flight: `(sequence, attempt, payment hash)`.
    inflight: Option<(u64, u32, [u8; 32])>,
}

/// The venue's LDK channel adapter. One lane = one channel between the venue node and one
/// account node; the lane's `BtcOutPoint` is the channel's funding outpoint.
///
/// Its lane state (baselines, Σ net moved, last settled batch, the payment in flight) is
/// written to `state` (fsynced, atomic rename) before every payment and after every lane, so
/// a restarted venue resumes a batch with [`LdkSettlement::load`].
pub struct LdkSettlement {
    venue: Arc<LdkNode>,
    lanes: BTreeMap<Outpoint, Lane>,
    done: BTreeMap<(u64, Outpoint), LaneSettlement>,
    state: PathBuf,
    salt: [u8; 32],
    /// How long one lane may wait for its payment and for both monitors.
    pub timeout: Duration,
}

impl LdkSettlement {
    pub fn new(venue: Arc<LdkNode>, state: PathBuf) -> Self {
        let mut salt = [0u8; 32];
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        salt.copy_from_slice(&tagged_hash(b"SHZ/HFT06/LDK-SALT/V1", &[&now.to_le_bytes()[..], venue.node_id().serialize().as_slice()].concat()));
        Self { venue, lanes: BTreeMap::new(), done: BTreeMap::new(), state, salt, timeout: TIMEOUT }
    }

    /// Reloads a venue's adapter after a restart; `owners` are the (possibly restarted)
    /// account nodes, matched to lanes by node id.
    pub fn load(venue: Arc<LdkNode>, owners: &[Arc<LdkNode>], state: PathBuf) -> std::io::Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&state)?).map_err(std::io::Error::other)?;
        let h32 = |x: &serde_json::Value| -> [u8; 32] { hex::decode(x.as_str().unwrap()).unwrap().try_into().unwrap() };
        let mut s = Self::new(venue, state);
        s.salt = h32(&v["salt"]);
        for l in v["lanes"].as_array().unwrap() {
            let owner_id = l["owner"].as_str().unwrap();
            let owner = owners.iter().find(|o| hex::encode(o.node_id().serialize()) == owner_id).expect("owner node").clone();
            let inflight = l["inflight"].as_array().map(|a| (a[0].as_u64().unwrap(), a[1].as_u64().unwrap() as u32, h32(&a[2])));
            s.lanes.insert(
                (h32(&l["txid"]), l["vout"].as_u64().unwrap() as u32),
                Lane {
                    owner,
                    channel_id: h32(&l["channel_id"]),
                    venue_base: l["venue_base"].as_u64().unwrap(),
                    owner_base: l["owner_base"].as_u64().unwrap(),
                    moved: l["moved"].as_i64().unwrap(),
                    last_seq: l["last_seq"].as_u64().unwrap(),
                    last_hash: h32(&l["last_hash"]),
                    attempts: l["attempts"].as_u64().unwrap() as u32,
                    inflight,
                },
            );
        }
        Ok(s)
    }

    fn save(&self) -> Result<(), SettleError> {
        let lanes: Vec<_> = self
            .lanes
            .iter()
            .map(|((txid, vout), l)| {
                serde_json::json!({
                    "txid": hex::encode(txid), "vout": vout, "channel_id": hex::encode(l.channel_id),
                    "owner": hex::encode(l.owner.node_id().serialize()),
                    "venue_base": l.venue_base, "owner_base": l.owner_base, "moved": l.moved,
                    "last_seq": l.last_seq, "last_hash": hex::encode(l.last_hash), "attempts": l.attempts,
                    "inflight": l.inflight.map(|(s, a, h)| serde_json::json!([s, a, hex::encode(h)])),
                })
            })
            .collect();
        let doc = serde_json::json!({ "salt": hex::encode(self.salt), "lanes": lanes });
        let tmp = self.state.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            std::io::Write::write_all(&mut f, &serde_json::to_vec(&doc).unwrap())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &self.state)
        };
        write().map_err(|e| SettleError::State(e.to_string()))
    }

    /// Binds the venue's (usable, settled) channel with `owner` as a lane. The holder
    /// balances journaled now are the lane's baseline: the cleared ledger starts here.
    pub fn bind(&mut self, owner: Arc<LdkNode>) -> Result<BtcOutPoint, SettleError> {
        let ch = self
            .venue
            .channel_with(&owner.node_id())
            .filter(|c| c.is_usable)
            .ok_or_else(|| SettleError::NoChannel(owner.name.clone()))?;
        let funding = ch.funding_txo.ok_or_else(|| SettleError::NoChannel(owner.name.clone()))?;
        let channel = BtcOutPoint {
            txid: lightning::bitcoin::hashes::Hash::to_byte_array(funding.txid),
            vout: funding.index as u32,
        };
        let cid = ch.channel_id.0;
        let (v, o) = settled_pair(&self.venue, &owner, &cid)
            .map_err(|reason| SettleError::Monitor { channel: channel.clone(), reason })?;
        self.lanes.insert(
            op(&channel),
            Lane {
                owner,
                channel_id: cid,
                venue_base: v.holder_sats,
                owner_base: o.holder_sats,
                moved: 0,
                last_seq: 0,
                last_hash: [0; 32],
                attempts: 0,
                inflight: None,
            },
        );
        self.save()?;
        Ok(channel)
    }

    /// Replaces a lane's account node after that node restarted.
    pub fn rebind_owner(&mut self, owner: Arc<LdkNode>) {
        for l in self.lanes.values_mut() {
            if l.owner.node_id() == owner.node_id() {
                l.owner = owner.clone();
            }
        }
    }

    /// Initial lane head: commitment 0, state bound to the baseline records of both sides.
    pub fn initial_head(&self, channel: &BtcOutPoint) -> Option<Head> {
        let l = self.lanes.get(&op(channel))?;
        let v = self.venue.persister.latest(&l.channel_id)?;
        let o = l.owner.persister.latest(&l.channel_id)?;
        let mut b = Vec::with_capacity(72);
        b.extend(channel.txid);
        b.extend(channel.vout.to_le_bytes());
        b.extend(v.digest());
        b.extend(o.digest());
        Some(Head { revision: 0, commitment: 0, state: tagged_hash(STATE_TAG, &b) })
    }

    /// Σ net moved on `channel` so far, and its baselines `(venue, owner)`.
    pub fn lane_totals(&self, channel: &BtcOutPoint) -> Option<(i64, u64, u64)> {
        self.lanes.get(&op(channel)).map(|l| (l.moved, l.venue_base, l.owner_base))
    }

    pub fn owner_journal(&self, channel: &BtcOutPoint) -> Option<std::path::PathBuf> {
        self.lanes.get(&op(channel)).map(|l| l.owner.persister.journal_path().to_path_buf())
    }

    /// Moves every row's `net` of a prepared batch's clearing on its lane and returns one
    /// settlement per row, in row (batch account) order.
    ///
    /// Lanes settle one after another. A lane that fails leaves the lanes before it moved and
    /// the batch unresolved (nothing is signed). Calling `settle` again with the same batch,
    /// also after a venue or account node restarted, resumes it: for each lane it first waits
    /// until no HTLC and no outbound payment is pending on either node, then reads both
    /// persisted balances. At the pre-batch balance the lane is paid (a new attempt); at the
    /// post-batch balance it already moved and is not paid again; any other balance is an error.
    pub fn settle(&mut self, sequence: u64, clearing: &BatchClearing) -> Result<Vec<LaneSettlement>, SettleError> {
        let mut out = Vec::with_capacity(clearing.rows.len());
        for row in &clearing.rows {
            let key = (sequence, op(&row.channel));
            if let Some(s) = self.done.get(&key) {
                out.push(s.clone());
                continue;
            }
            let s = self.settle_lane(sequence, &row.channel, row.net)?;
            self.done.insert(key, s.clone());
            out.push(s);
        }
        Ok(out)
    }

    fn settle_lane(&mut self, sequence: u64, channel: &BtcOutPoint, net: i64) -> Result<LaneSettlement, SettleError> {
        let venue = self.venue.clone();
        let timeout = self.timeout;
        let key = op(channel);
        let lane = self.lanes.get(&key).ok_or_else(|| SettleError::UnknownLane(channel.clone()))?;
        let (owner, cid) = (lane.owner.clone(), lane.channel_id);
        let mon = |reason: String| SettleError::Monitor { channel: channel.clone(), reason };
        let at = |moved: i64| -> Result<(u64, u64), SettleError> {
            let v = lane.venue_base as i128 - moved as i128;
            let o = lane.owner_base as i128 + moved as i128;
            if v < 0 || o < 0 {
                return Err(SettleError::Liquidity { channel: channel.clone(), net });
            }
            Ok((v as u64, o as u64))
        };
        if lane.last_seq >= sequence {
            // Settled earlier (before a restart of this adapter).
            let (ve, oe) = at(lane.moved)?;
            let (v, o) = settled_pair(&venue, &owner, &cid).map_err(mon)?;
            if (v.holder_sats, o.holder_sats) != (ve, oe) {
                return Err(mon(format!("lane settled for batch {} but balances are {} / {}", lane.last_seq, v.holder_sats, o.holder_sats)));
            }
            return Ok(LaneSettlement { sequence, channel: channel.clone(), net, payment_hash: lane.last_hash, venue: v, owner: o, venue_expected: ve, owner_expected: oe });
        }
        let pre = at(lane.moved)?;
        let post = at(lane.moved + net)?;
        // Quiescent: nothing in flight on the channel or in either node's outbound payments.
        let mut state = Err(String::new());
        wait_until(timeout, || {
            let pending = [&venue, &owner].iter().any(|n| {
                n.cm.list_recent_payments().iter().any(|p| matches!(p, RecentPaymentDetails::Pending { .. }))
            });
            state = if pending { Err("outbound payment pending".into()) } else { settled_pair(&venue, &owner, &cid) };
            state.is_ok()
        })
        .map_err(|_| mon(state.clone().unwrap_err()))?;
        let (v, o) = state.unwrap();
        let now = (v.holder_sats, o.holder_sats);
        let mut payment_hash = [0; 32];
        if net != 0 && now == post {
            // Moved before a crash: the in-flight record names the payment.
            payment_hash = lane.inflight.filter(|f| f.0 == sequence).map(|f| f.2).unwrap_or([0; 32]);
        } else if now != pre {
            return Err(mon(format!("balances {} / {} are neither pre-batch {pre:?} nor post-batch {post:?}", now.0, now.1)));
        } else if net != 0 {
            let attempt = lane.attempts + 1;
            let mut b = Vec::with_capacity(80);
            b.extend(sequence.to_le_bytes());
            b.extend(channel.txid);
            b.extend(channel.vout.to_le_bytes());
            b.extend(attempt.to_le_bytes());
            let id = PaymentId(tagged_hash(PAYMENT_ID_TAG, &b));
            let preimage = PaymentPreimage(tagged_hash(PREIMAGE_TAG, &[&self.salt[..], &b].concat()));
            payment_hash = Sha256::digest(preimage.0).into();
            let lane = self.lanes.get_mut(&key).unwrap();
            lane.attempts = attempt;
            lane.inflight = Some((sequence, attempt, payment_hash));
            self.save()?;
            let (payer, payee) = if net > 0 { (&venue, &owner) } else { (&owner, &venue) };
            let fail = |reason: String| SettleError::Payment { channel: channel.clone(), reason };
            let hash = payer.pay(payee.node_id(), net.unsigned_abs() * 1000, id, preimage).map_err(fail)?;
            let mut outcome = None;
            wait_until(timeout, || {
                outcome = payer.events().into_iter().find_map(|e| match e {
                    Event::PaymentSent { payment_id: Some(p), payment_preimage, payment_hash: h, .. } if p == id => {
                        Some(Ok((payment_preimage, h)))
                    }
                    Event::PaymentFailed { payment_id: p, reason, .. } if p == id => Some(Err(format!("{reason:?}"))),
                    _ => None,
                });
                outcome.is_some()
            })
            .map_err(fail)?;
            let (got, h) = outcome.unwrap().map_err(fail)?;
            if <[u8; 32]>::from(Sha256::digest(got.0)) != h.0 || h.0 != payment_hash || hash.0 != payment_hash {
                return Err(fail("preimage does not hash to the payment hash".into()));
            }
        }
        let (venue_expected, owner_expected) = if net != 0 { post } else { pre };
        let mut last = Err(String::new());
        wait_until(timeout, || {
            last = settled_pair(&venue, &owner, &cid).and_then(|(v, o)| {
                if v.holder_sats == venue_expected && o.holder_sats == owner_expected {
                    Ok((v, o))
                } else {
                    Err(format!("venue {} / owner {} sats, expected {venue_expected} / {owner_expected}", v.holder_sats, o.holder_sats))
                }
            });
            last.is_ok()
        })
        .map_err(|_| mon(last.clone().unwrap_err()))?;
        let (v, o) = last.unwrap();
        let lane = self.lanes.get_mut(&key).unwrap();
        lane.moved += net;
        lane.last_seq = sequence;
        lane.last_hash = payment_hash;
        lane.inflight = None;
        self.save()?;
        Ok(LaneSettlement {
            sequence,
            channel: channel.clone(),
            net,
            payment_hash,
            venue: v,
            owner: o,
            venue_expected,
            owner_expected,
        })
    }
}

/// Latest journaled records of both sides of channel `cid`, once neither side has an HTLC in
/// flight, neither the channel manager nor the persisted monitor.
fn settled_pair(venue: &LdkNode, owner: &LdkNode, cid: &[u8; 32]) -> Result<(MonitorRecord, MonitorRecord), String> {
    for (node, peer) in [(venue, owner), (owner, venue)] {
        let ch = node.channel_with(&peer.node_id()).ok_or("channel gone")?;
        if !ch.pending_inbound_htlcs.is_empty() || !ch.pending_outbound_htlcs.is_empty() {
            return Err(format!("{}: HTLC in flight", node.name));
        }
    }
    let v = venue.persister.latest(cid).ok_or("venue monitor not journaled")?;
    let o = owner.persister.latest(cid).ok_or("owner monitor not journaled")?;
    if !v.settled() || !o.settled() {
        return Err("HTLC on a persisted monitor".into());
    }
    // The journaled record must be the monitor's current state, not one a queued write trails.
    for (node, rec) in [(venue, &v), (owner, &o)] {
        let live = node.chain_monitor.get_monitor(ChannelId(*cid)).map(|m| m.get_latest_update_id());
        if live != Ok(rec.update_id) {
            return Err(format!("{}: monitor update not yet journaled", node.name));
        }
    }
    Ok((v, o))
}
