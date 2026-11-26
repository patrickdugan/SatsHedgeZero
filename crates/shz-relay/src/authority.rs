//! Packet certification authorities and durable one-signature-per-slot locks.
//!
//! Key lifecycles are separated by construction:
//! * high-frequency packet keys (trusted relay key, or the five federation
//!   member keys) sign packet digests at 5 Hz and never touch DLC nonces;
//! * the FROST maturity attestation coalition (`shz_oracle::frost`) keeps its
//!   own group key and per-event nonces. [`ensure_key_separation`] rejects a
//!   configuration in which any packet key equals the maturity group key.
//!
//! [`ThresholdPacketSigner`] is the replacement seam for an audited
//! threshold-signing implementation: it yields one BIP340 signature under a
//! group key per (sequence, digest) and must enforce the same one-vote lock.
//! No threshold implementation is provided here.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use shz_dlc::Bip340Signature;
use shz_oracle::hft_packets::{Certificate, Packet, Policy, QUORUM, Vote};
use thiserror::Error;

use crate::envelope::{CertifiedPacket, Hash, SecurityMode, sign_trusted};

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("refusing to sign a second digest for sequence {0}")]
    Equivocation(u64),
    #[error("sequence {seq} is below the durable high-water mark {high}")]
    Regression { seq: u64, high: u64 },
    #[error("signer lock file corrupt or torn; reconcile manually")]
    Corrupt,
    #[error("lock I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("key separation violated: {0}")]
    KeySeparation(&'static str),
}

/// Append-only `seq digest check` lines, fsync'd BEFORE the signature is
/// released. On reopen the full history is replayed; a torn or altered
/// line fails closed. Same (seq, digest) is idempotent; a different digest
/// for a recorded seq, or any seq at/below the high-water mark that is not
/// recorded, is refused.
pub struct DurableSignLock {
    path: PathBuf,
    file: File,
    locks: BTreeMap<u64, Hash>,
    high: u64,
    chain: Hash,
}

fn line_check(chain: &Hash, seq: u64, digest: &Hash) -> Hash {
    let mut b = Vec::with_capacity(72);
    b.extend(chain);
    b.extend(seq.to_le_bytes());
    b.extend(digest);
    shz_dlc::tagged_hash(b"SHZ/HFT06/SIGNER-LOCK/V1", &b)
}

impl DurableSignLock {
    pub fn open(path: &Path) -> Result<Self, AuthorityError> {
        let mut locks = BTreeMap::new();
        let mut high = 0;
        let mut chain = [0u8; 32];
        if path.exists() {
            let raw = std::fs::read(path)?;
            if !raw.is_empty() && *raw.last().unwrap() != b'\n' {
                return Err(AuthorityError::Corrupt);
            }
            for line in BufReader::new(&raw[..]).lines() {
                let line = line?;
                let mut it = line.split(' ');
                let (Some(s), Some(d), Some(c), None) = (it.next(), it.next(), it.next(), it.next()) else {
                    return Err(AuthorityError::Corrupt);
                };
                let seq: u64 = s.parse().map_err(|_| AuthorityError::Corrupt)?;
                let digest: Hash = hex::decode(d).ok().and_then(|v| v.try_into().ok()).ok_or(AuthorityError::Corrupt)?;
                let check = line_check(&chain, seq, &digest);
                if hex::encode(check) != c || seq <= high {
                    return Err(AuthorityError::Corrupt);
                }
                chain = check;
                high = seq;
                locks.insert(seq, digest);
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { path: path.to_path_buf(), file, locks, high, chain })
    }

    pub fn high_water(&self) -> u64 {
        self.high
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Durably lock `(seq, digest)`. Returns once the record is on disk.
    pub fn lock(&mut self, seq: u64, digest: &Hash) -> Result<(), AuthorityError> {
        if let Some(d) = self.locks.get(&seq) {
            return if d == digest { Ok(()) } else { Err(AuthorityError::Equivocation(seq)) };
        }
        if seq <= self.high {
            return Err(AuthorityError::Regression { seq, high: self.high });
        }
        let check = line_check(&self.chain, seq, digest);
        writeln!(self.file, "{seq} {} {}", hex::encode(digest), hex::encode(check))?;
        self.file.sync_all()?;
        self.chain = check;
        self.high = seq;
        self.locks.insert(seq, *digest);
        // Bounded memory: the chain + high-water mark protect older slots.
        while self.locks.len() > 4096 {
            self.locks.pop_first();
        }
        Ok(())
    }
}

pub trait PacketAuthority: Send {
    fn mode(&self) -> SecurityMode;
    fn certify(&mut self, packet: &Packet) -> Result<CertifiedPacket, AuthorityError>;
}

/// Initial deployment: one pinned relay key with a durable slot lock.
pub struct TrustedRelaySigner {
    secret: Hash,
    policy_id: Hash,
    lock: DurableSignLock,
}

impl TrustedRelaySigner {
    pub fn new(policy: &Policy, secret: Hash, lock: DurableSignLock) -> Result<Self, AuthorityError> {
        let pk = shz_dlc::pubkey_x_from_secret(&secret).map_err(|e| AuthorityError::Sign(e.to_string()))?;
        if policy.members.contains(&pk) {
            return Err(AuthorityError::KeySeparation("relay key is a federation member key"));
        }
        Ok(Self { secret, policy_id: policy.id().map_err(|e| AuthorityError::Sign(format!("{e:?}")))?, lock })
    }
    pub fn public_key(&self) -> Hash {
        shz_dlc::pubkey_x_from_secret(&self.secret).expect("validated")
    }
}

impl PacketAuthority for TrustedRelaySigner {
    fn mode(&self) -> SecurityMode {
        SecurityMode::TrustedRelay
    }
    fn certify(&mut self, packet: &Packet) -> Result<CertifiedPacket, AuthorityError> {
        self.lock.lock(packet.seq, &packet.digest())?;
        Ok(CertifiedPacket::Trusted(sign_trusted(&self.policy_id, &self.secret, packet.clone()).map_err(|e| AuthorityError::Sign(e.to_string()))?))
    }
}

/// Collects externally produced member votes into a 4-of-5 certificate.
/// Votes are verified individually on arrival; conflicting votes from one
/// member for one sequence are reported as equivocation evidence.
pub struct FederatedCollector {
    policy: Policy,
    pending: BTreeMap<u64, (Packet, BTreeMap<u8, Vote>)>,
    pub equivocations: Vec<(u64, u8)>,
}

impl FederatedCollector {
    pub fn new(policy: Policy) -> Self {
        Self { policy, pending: BTreeMap::new(), equivocations: Vec::new() }
    }
    /// Returns a certificate once `QUORUM` distinct valid votes on the same digest exist.
    pub fn add_vote(&mut self, packet: &Packet, vote: Vote) -> Option<Certificate> {
        let key = self.policy.members.get(vote.member as usize)?;
        let digest = packet.digest();
        if shz_dlc::bip340_verify(key, &digest, &vote.signature).is_err() {
            return None;
        }
        let entry = self.pending.entry(packet.seq).or_insert_with(|| (packet.clone(), BTreeMap::new()));
        if entry.0.digest() != digest {
            self.equivocations.push((packet.seq, vote.member));
            return None;
        }
        entry.1.insert(vote.member, vote);
        if entry.1.len() >= QUORUM {
            let (packet, votes) = self.pending.remove(&packet.seq).unwrap();
            let cert = Certificate { packet, votes: votes.into_values().take(QUORUM).collect() };
            return cert.verify(&self.policy).ok().map(|_| cert);
        }
        None
    }
    pub fn prune_below(&mut self, seq: u64) {
        self.pending.retain(|s, _| *s >= seq);
    }
}

/// Development-only federation: five in-process signers with durable locks.
/// Production members run independently and submit votes to a collector.
pub struct LocalFederation {
    policy: Policy,
    signers: Vec<(shz_oracle::hft_packets::Signer, DurableSignLock)>,
    collector: FederatedCollector,
}

impl LocalFederation {
    pub fn new(policy: &Policy, secrets: &[Hash; 5], lock_dir: &Path) -> Result<Self, AuthorityError> {
        std::fs::create_dir_all(lock_dir)?;
        let mut signers = Vec::new();
        for (i, s) in secrets.iter().enumerate() {
            let signer = shz_oracle::hft_packets::Signer::new(policy, i as u8, *s).map_err(|e| AuthorityError::Sign(format!("{e:?}")))?;
            signers.push((signer, DurableSignLock::open(&lock_dir.join(format!("member{i}.lock")))?));
        }
        Ok(Self { policy: policy.clone(), signers, collector: FederatedCollector::new(policy.clone()) })
    }
}

impl PacketAuthority for LocalFederation {
    fn mode(&self) -> SecurityMode {
        SecurityMode::Federated
    }
    fn certify(&mut self, packet: &Packet) -> Result<CertifiedPacket, AuthorityError> {
        let digest = packet.digest();
        for (signer, lock) in self.signers.iter_mut().take(QUORUM) {
            lock.lock(packet.seq, &digest)?;
            let vote = signer.vote(&self.policy, packet).map_err(|e| AuthorityError::Sign(format!("{e:?}")))?;
            if let Some(c) = self.collector.add_vote(packet, vote) {
                return Ok(CertifiedPacket::Federated(c));
            }
        }
        Err(AuthorityError::Sign("quorum not reached".into()))
    }
}

/// Replacement seam for an audited threshold signer (e.g. FROST over a
/// *packet-specific* DKG). Implementations must durably enforce one
/// signature per sequence, use nonces disjoint from DLC event nonces, and
/// produce a standard BIP340 signature verifiable against `group_key`.
pub trait ThresholdPacketSigner: Send {
    fn group_key(&self) -> Hash;
    fn sign_packet(&mut self, seq: u64, digest: &Hash) -> Result<Bip340Signature, AuthorityError>;
}

/// Reject configurations where the high-frequency packet keys overlap the
/// FROST maturity attestation group key.
pub fn ensure_key_separation(maturity_group_key: &Hash, packet_keys: &[Hash]) -> Result<(), AuthorityError> {
    if packet_keys.iter().any(|k| k == maturity_group_key) {
        return Err(AuthorityError::KeySeparation("packet key equals FROST maturity group key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::PacketVerifier;
    use shz_oracle::hft_packets::Mark;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("shz-relay-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn policy() -> Policy {
        Policy {
            network: [9; 32],
            market: [8; 32],
            epoch: 1,
            origin_us: 10_000_000,
            members: std::array::from_fn(|i| shz_dlc::pubkey_x_from_secret(&[(i + 1) as u8; 32]).unwrap()),
        }
    }
    fn pk(p: &Policy, seq: u64, prev: Hash, reason: u8) -> Packet {
        Packet { policy: p.id().unwrap(), seq, previous: prev, mark: Mark::Hold { reason } }
    }

    #[test]
    fn durable_lock_survives_restart_and_refuses_equivocation() {
        let d = tmp("lock");
        let p = policy();
        let a = pk(&p, 1, [0; 32], 1);
        {
            let mut s = TrustedRelaySigner::new(&p, [0x99; 32], DurableSignLock::open(&d.join("relay.lock")).unwrap()).unwrap();
            s.certify(&a).unwrap();
            s.certify(&a).unwrap(); // idempotent
        }
        let mut s = TrustedRelaySigner::new(&p, [0x99; 32], DurableSignLock::open(&d.join("relay.lock")).unwrap()).unwrap();
        assert!(matches!(s.certify(&pk(&p, 1, [0; 32], 2)), Err(AuthorityError::Equivocation(1))));
        let b = pk(&p, 3, a.digest(), 1);
        s.certify(&b).unwrap();
        assert!(matches!(s.certify(&pk(&p, 2, a.digest(), 1)), Err(AuthorityError::Regression { .. })));
        let v = PacketVerifier::trusted(p, s.public_key()).unwrap();
        assert!(v.verify(&s.certify(&b).unwrap()).is_ok());
    }

    #[test]
    fn torn_or_edited_lock_fails_closed() {
        let d = tmp("torn");
        let path = d.join("relay.lock");
        let mut l = DurableSignLock::open(&path).unwrap();
        l.lock(1, &[1; 32]).unwrap();
        l.lock(2, &[2; 32]).unwrap();
        drop(l);
        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..full.len() - 3]).unwrap();
        assert!(matches!(DurableSignLock::open(&path), Err(AuthorityError::Corrupt)));
        let text = String::from_utf8(full).unwrap().replacen("0101", "0202", 1);
        std::fs::write(&path, text).unwrap();
        assert!(matches!(DurableSignLock::open(&path), Err(AuthorityError::Corrupt)));
    }

    #[test]
    fn local_federation_certifies_and_restart_keeps_locks() {
        let d = tmp("fed");
        let p = policy();
        let secrets: [Hash; 5] = std::array::from_fn(|i| [(i + 1) as u8; 32]);
        let a = pk(&p, 1, [0; 32], 1);
        {
            let mut f = LocalFederation::new(&p, &secrets, &d).unwrap();
            let c = f.certify(&a).unwrap();
            assert!(PacketVerifier::federated(p.clone()).unwrap().verify(&c).is_ok());
        }
        let mut f = LocalFederation::new(&p, &secrets, &d).unwrap();
        assert!(matches!(f.certify(&pk(&p, 1, [0; 32], 3)), Err(AuthorityError::Equivocation(1))));
    }

    #[test]
    fn collector_flags_equivocating_member() {
        let p = policy();
        let mut c = FederatedCollector::new(p.clone());
        let a = pk(&p, 1, [0; 32], 1);
        let b = pk(&p, 1, [0; 32], 2);
        let sig = |m: u8, x: &Packet| Vote { member: m, signature: shz_dlc::bip340_sign(&[m + 1; 32], &x.digest()).unwrap() };
        assert!(c.add_vote(&a, sig(0, &a)).is_none());
        assert!(c.add_vote(&b, sig(1, &b)).is_none());
        assert_eq!(c.equivocations, vec![(1, 1)]);
        assert!(c.add_vote(&a, sig(1, &a)).is_none());
        assert!(c.add_vote(&a, sig(2, &a)).is_none());
        assert!(c.add_vote(&a, sig(3, &a)).is_some());
        // A forged vote (wrong key) is ignored.
        let mut c = FederatedCollector::new(p.clone());
        assert!(c.add_vote(&a, Vote { member: 0, signature: shz_dlc::bip340_sign(&[0x55; 32], &a.digest()).unwrap() }).is_none());
    }

    #[test]
    fn maturity_key_separation() {
        let frost = shz_oracle::frost::FrostConfederation::keygen_deterministic(3, 5, &[0x42; 32]).unwrap();
        let p = policy();
        assert!(ensure_key_separation(&frost.group_pubkey_x, &p.members).is_ok());
        assert!(ensure_key_separation(&frost.group_pubkey_x, &[frost.group_pubkey_x]).is_err());
    }
}
