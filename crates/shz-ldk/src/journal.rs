//! Commitment evidence from LDK monitor persistence.
//!
//! LDK reports no commitment number or `revoke_and_ack` through its events, so the evidence
//! comes from the one place every channel state change must pass before LDK proceeds: the
//! `Persist` implementation of its `ChainMonitor`. [`JournalingPersist`] wraps the real
//! persister. After the inner persister has stored the monitor durably it derives a
//! [`MonitorRecord`] from the monitor it just stored and appends that record to a hash-chained,
//! fsynced lane journal; only then does it report `Completed` to LDK. A channel state that the
//! counterparty can see (LDK sends `commitment_signed` / `revoke_and_ack` only after the monitor
//! update completed) therefore always has a journal record.
use lightning::chain::chainmonitor::Persist;
use lightning::chain::channelmonitor::{Balance, ChannelMonitor, ChannelMonitorUpdate};
use lightning::chain::ChannelMonitorUpdateStatus;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::util::persist::MonitorName;
use lightning::util::ser::Writeable;
use sha2::{Digest, Sha256};
use shz_dlc::tagged_hash;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Tag of [`MonitorRecord::digest`].
pub const RECORD_TAG: &[u8] = b"SHZ/HFT06/LDK-MONITOR-RECORD/V1";
const FRAME_TAG: &[u8] = b"SHZ/HFT06/LDK-LANE-JOURNAL/V1";
const MAGIC: &[u8; 8] = b"SHZLDKJ1";

/// What one persisted channel monitor shows: which monitor, which update, the exact bytes
/// written (by hash), and the holder balance those bytes commit to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorRecord {
    /// `ChannelMonitor::persistence_key()` (`<funding txid>_<index>` for V1 channels).
    pub monitor_name: String,
    pub channel_id: [u8; 32],
    /// Funding outpoint; txid in internal byte order (`Txid::to_byte_array`).
    pub funding_txid: [u8; 32],
    pub funding_vout: u16,
    /// `ChannelMonitor::get_latest_update_id()`: monotone per channel.
    pub update_id: u64,
    /// SHA-256 of the serialized monitor, as handed to the inner persister.
    pub monitor_sha256: [u8; 32],
    /// Holder balance on the current holder commitment (`Balance::ClaimableOnChannelClose`),
    /// excluding the commitment transaction fee and any HTLC.
    pub holder_sats: u64,
    /// Sum of the HTLC fields of `ClaimableOnChannelClose` plus every other balance entry:
    /// zero exactly when no HTLC is in flight on the persisted state.
    pub pending_htlc_msat: u64,
    pub other_balances: u32,
}

impl MonitorRecord {
    pub fn from_monitor<S: EcdsaChannelSigner>(monitor: &ChannelMonitor<S>) -> Self {
        let bytes = monitor.encode();
        let funding = monitor.get_funding_txo();
        let (mut holder_sats, mut pending_htlc_msat, mut other_balances) = (0, 0, 0);
        for b in monitor.get_claimable_balances() {
            match &b {
                Balance::ClaimableOnChannelClose {
                    outbound_payment_htlc_rounded_msat,
                    outbound_forwarded_htlc_rounded_msat,
                    inbound_claiming_htlc_rounded_msat,
                    inbound_htlc_rounded_msat,
                    ..
                } => {
                    holder_sats += b.claimable_amount_satoshis();
                    pending_htlc_msat += outbound_payment_htlc_rounded_msat
                        + outbound_forwarded_htlc_rounded_msat
                        + inbound_claiming_htlc_rounded_msat
                        + inbound_htlc_rounded_msat;
                }
                other => {
                    other_balances += 1;
                    pending_htlc_msat += other.claimable_amount_satoshis() * 1000;
                }
            }
        }
        Self {
            monitor_name: monitor.persistence_key().to_string(),
            channel_id: monitor.channel_id().0,
            funding_txid: lightning::bitcoin::hashes::Hash::to_byte_array(funding.txid),
            funding_vout: funding.index,
            update_id: monitor.get_latest_update_id(),
            monitor_sha256: Sha256::digest(&bytes).into(),
            holder_sats,
            pending_htlc_msat,
            other_balances,
        }
    }

    /// No HTLC on the persisted holder state: the balance is final for this update.
    pub fn settled(&self) -> bool {
        self.pending_htlc_msat == 0 && self.other_balances == 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(160);
        b.extend((self.monitor_name.len() as u16).to_le_bytes());
        b.extend(self.monitor_name.as_bytes());
        b.extend(self.channel_id);
        b.extend(self.funding_txid);
        b.extend(self.funding_vout.to_le_bytes());
        b.extend(self.update_id.to_le_bytes());
        b.extend(self.monitor_sha256);
        b.extend(self.holder_sats.to_le_bytes());
        b.extend(self.pending_htlc_msat.to_le_bytes());
        b.extend(self.other_balances.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = b;
        let mut take = |n: usize| -> Option<&[u8]> {
            if r.len() < n {
                return None;
            }
            let (h, t) = r.split_at(n);
            r = t;
            Some(h)
        };
        let n = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        let monitor_name = String::from_utf8(take(n)?.to_vec()).ok()?;
        let rec = Self {
            monitor_name,
            channel_id: take(32)?.try_into().ok()?,
            funding_txid: take(32)?.try_into().ok()?,
            funding_vout: u16::from_le_bytes(take(2)?.try_into().ok()?),
            update_id: u64::from_le_bytes(take(8)?.try_into().ok()?),
            monitor_sha256: take(32)?.try_into().ok()?,
            holder_sats: u64::from_le_bytes(take(8)?.try_into().ok()?),
            pending_htlc_msat: u64::from_le_bytes(take(8)?.try_into().ok()?),
            other_balances: u32::from_le_bytes(take(4)?.try_into().ok()?),
        };
        if take(1).is_some() {
            return None;
        }
        Some(rec)
    }

    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(RECORD_TAG, &self.encode())
    }
}

/// Append-only, hash-chained, fsynced journal of [`MonitorRecord`]s.
///
/// File: 8-byte magic, then frames `len:u32 LE ‖ record ‖ digest`, where
/// `digest = tagged_hash(FRAME_TAG, previous digest ‖ frame number ‖ record)`. A torn or
/// altered frame fails the whole read; nothing is truncated or repaired.
pub struct LaneJournal {
    file: File,
    tip: [u8; 32],
    frames: u64,
}

impl LaneJournal {
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
        file.write_all(MAGIC)?;
        file.sync_all()?;
        Ok(Self { file, tip: [0; 32], frames: 0 })
    }

    /// Every record in `path`, verifying the chain.
    pub fn read(path: &Path) -> io::Result<Vec<MonitorRecord>> {
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "lane journal corrupt or torn");
        if data.len() < 8 || &data[..8] != MAGIC {
            return Err(bad());
        }
        let (mut at, mut tip, mut n, mut out) = (8usize, [0u8; 32], 0u64, Vec::new());
        while at < data.len() {
            let len = u32::from_le_bytes(data.get(at..at + 4).ok_or_else(bad)?.try_into().unwrap()) as usize;
            let rec = data.get(at + 4..at + 4 + len).ok_or_else(bad)?;
            let dig: [u8; 32] = data.get(at + 4 + len..at + 36 + len).ok_or_else(bad)?.try_into().unwrap();
            if dig != frame_digest(&tip, n, rec) {
                return Err(bad());
            }
            out.push(MonitorRecord::decode(rec).ok_or_else(bad)?);
            tip = dig;
            n += 1;
            at += 36 + len;
        }
        Ok(out)
    }

    pub fn append(&mut self, rec: &MonitorRecord) -> io::Result<()> {
        let body = rec.encode();
        let dig = frame_digest(&self.tip, self.frames, &body);
        let mut frame = Vec::with_capacity(body.len() + 36);
        frame.extend((body.len() as u32).to_le_bytes());
        frame.extend(&body);
        frame.extend(dig);
        self.file.write_all(&frame)?;
        self.file.sync_all()?;
        self.tip = dig;
        self.frames += 1;
        Ok(())
    }
}

fn frame_digest(prev: &[u8; 32], n: u64, rec: &[u8]) -> [u8; 32] {
    let mut b = Vec::with_capacity(40 + rec.len());
    b.extend(prev);
    b.extend(n.to_le_bytes());
    b.extend(rec);
    tagged_hash(FRAME_TAG, &b)
}

/// Durable monitor store: one file per monitor, written to a temporary name, fsynced and
/// renamed over the previous version.
pub struct FilePersist {
    dir: PathBuf,
}

impl FilePersist {
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn write(&self, name: &MonitorName, bytes: &[u8]) -> io::Result<()> {
        let path = self.dir.join(format!("{name}.monitor"));
        let tmp = self.dir.join(format!("{name}.monitor.tmp"));
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &path)
    }
}

impl<S: EcdsaChannelSigner> Persist<S> for FilePersist {
    fn persist_new_channel(&self, name: MonitorName, monitor: &ChannelMonitor<S>) -> ChannelMonitorUpdateStatus {
        match self.write(&name, &monitor.encode()) {
            Ok(()) => ChannelMonitorUpdateStatus::Completed,
            Err(_) => ChannelMonitorUpdateStatus::UnrecoverableError,
        }
    }
    fn update_persisted_channel(
        &self, name: MonitorName, _update: Option<&ChannelMonitorUpdate>, monitor: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        self.persist_new_channel(name, monitor)
    }
    fn archive_persisted_channel(&self, name: MonitorName) {
        let from = self.dir.join(format!("{name}.monitor"));
        let _ = fs::rename(&from, self.dir.join(format!("{name}.archived")));
    }
}

/// `Persist` wrapper that turns every completed monitor write into a lane-journal record.
///
/// Order per call: inner persister writes the monitor; on `Completed` the record is appended
/// and fsynced; only then is `Completed` returned. If the inner persister answers
/// `InProgress` no record is written and `InProgress` is returned: asynchronous persistence
/// has no evidence path in this gate. A journal write failure returns `UnrecoverableError`,
/// which stops LDK from advancing the channel.
pub struct JournalingPersist<P> {
    inner: P,
    journal: Mutex<LaneJournal>,
    path: PathBuf,
    latest: Mutex<HashMap<[u8; 32], MonitorRecord>>,
}

impl<P> JournalingPersist<P> {
    pub fn new(inner: P, journal_path: PathBuf) -> io::Result<Self> {
        Ok(Self {
            inner,
            journal: Mutex::new(LaneJournal::create(&journal_path)?),
            path: journal_path,
            latest: Mutex::new(HashMap::new()),
        })
    }

    pub fn journal_path(&self) -> &Path {
        &self.path
    }

    /// Latest record journaled for `channel_id`.
    pub fn latest(&self, channel_id: &[u8; 32]) -> Option<MonitorRecord> {
        self.latest.lock().unwrap().get(channel_id).cloned()
    }

    fn record<S: EcdsaChannelSigner>(&self, monitor: &ChannelMonitor<S>) -> ChannelMonitorUpdateStatus {
        let rec = MonitorRecord::from_monitor(monitor);
        if self.journal.lock().unwrap().append(&rec).is_err() {
            return ChannelMonitorUpdateStatus::UnrecoverableError;
        }
        self.latest.lock().unwrap().insert(rec.channel_id, rec);
        ChannelMonitorUpdateStatus::Completed
    }
}

impl<S: EcdsaChannelSigner, P: Persist<S>> Persist<S> for JournalingPersist<P> {
    fn persist_new_channel(&self, name: MonitorName, monitor: &ChannelMonitor<S>) -> ChannelMonitorUpdateStatus {
        match self.inner.persist_new_channel(name, monitor) {
            ChannelMonitorUpdateStatus::Completed => self.record(monitor),
            other => other,
        }
    }
    fn update_persisted_channel(
        &self, name: MonitorName, update: Option<&ChannelMonitorUpdate>, monitor: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        match self.inner.update_persisted_channel(name, update, monitor) {
            ChannelMonitorUpdateStatus::Completed => self.record(monitor),
            other => other,
        }
    }
    fn archive_persisted_channel(&self, name: MonitorName) {
        self.inner.archive_persisted_channel(name)
    }
}
