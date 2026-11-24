//! Certified packet envelopes with explicitly separated security modes.
//!
//! * [`SecurityMode::TrustedRelay`]: one pinned relay key signs
//!   `tagged_hash("SHZ/HFT06/TRUSTED-RELAY-PACKET/V1", 0x01 || policy || relay_key || packet_digest)`.
//!   This is an initial-deployment trust assumption: the relay operator alone
//!   vouches for the packet.
//! * [`SecurityMode::Federated`]: the HFT-04 4-of-5 BIP340 [`Certificate`],
//!   each member signing the raw packet digest.
//!
//! A trusted-relay packet cannot masquerade as a federated certificate:
//! the verifier is configured with exactly one mode and rejects the other
//! variant; the trusted signature is over a different, domain-separated
//! message; and configuration rejects a relay key that is also a federation
//! member (so a trusted signature can never be counted as a member vote).

use serde::{Deserialize, Serialize};
use shz_dlc::{Bip340Signature, bip340_sign, bip340_verify, pubkey_x_from_secret, tagged_hash};
use shz_oracle::hft_packets::{Certificate, Mark, Packet, Policy, Source, Vote};
use thiserror::Error;

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    TrustedRelay,
    Federated,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("packet security mode does not match the verifier configuration")]
    ModeMismatch,
    #[error("invalid relay configuration: {0}")]
    Config(&'static str),
    #[error("bad signature")]
    Signature,
    #[error("packet rejected by HFT-04 policy: {0:?}")]
    Packet(shz_oracle::hft_packets::Error),
    #[error("malformed wire encoding: {0}")]
    Wire(String),
}

const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf,
    0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

pub fn trusted_message(policy_id: &Hash, relay_key: &Hash, packet_digest: &Hash) -> Hash {
    let mut b = Vec::with_capacity(97);
    b.push(0x01);
    b.extend(policy_id);
    b.extend(relay_key);
    b.extend(packet_digest);
    tagged_hash(b"SHZ/HFT06/TRUSTED-RELAY-PACKET/V1", &b)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPacket {
    pub packet: Packet,
    pub relay_key: Hash,
    pub signature: Bip340Signature,
}

#[derive(Debug, Clone)]
pub enum CertifiedPacket {
    Trusted(TrustedPacket),
    Federated(Certificate),
}

impl CertifiedPacket {
    pub fn mode(&self) -> SecurityMode {
        match self {
            Self::Trusted(_) => SecurityMode::TrustedRelay,
            Self::Federated(_) => SecurityMode::Federated,
        }
    }
    pub fn packet(&self) -> &Packet {
        match self {
            Self::Trusted(t) => &t.packet,
            Self::Federated(c) => &c.packet,
        }
    }
    pub fn digest(&self) -> Hash {
        self.packet().digest()
    }
}

/// Mode-pinned verifier. Exactly one mode per relay deployment.
#[derive(Debug, Clone)]
pub struct PacketVerifier {
    mode: SecurityMode,
    policy: Policy,
    policy_id: Hash,
    relay_key: Option<Hash>,
}

impl PacketVerifier {
    pub fn trusted(policy: Policy, relay_key: Hash) -> Result<Self, EnvelopeError> {
        let policy_id = policy.id().map_err(EnvelopeError::Packet)?;
        if relay_key == [0; 32] || policy.members.contains(&relay_key) {
            return Err(EnvelopeError::Config("relay key must be nonzero and not a federation member"));
        }
        Ok(Self { mode: SecurityMode::TrustedRelay, policy, policy_id, relay_key: Some(relay_key) })
    }
    pub fn federated(policy: Policy) -> Result<Self, EnvelopeError> {
        let policy_id = policy.id().map_err(EnvelopeError::Packet)?;
        Ok(Self { mode: SecurityMode::Federated, policy, policy_id, relay_key: None })
    }
    pub fn mode(&self) -> SecurityMode {
        self.mode
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn policy_id(&self) -> Hash {
        self.policy_id
    }

    pub fn verify(&self, c: &CertifiedPacket) -> Result<Hash, EnvelopeError> {
        if c.mode() != self.mode {
            return Err(EnvelopeError::ModeMismatch);
        }
        match c {
            CertifiedPacket::Federated(cert) => cert.verify(&self.policy).map_err(EnvelopeError::Packet),
            CertifiedPacket::Trusted(t) => {
                let key = self.relay_key.expect("trusted mode has a key");
                if t.relay_key != key || t.packet.policy != self.policy_id {
                    return Err(EnvelopeError::Signature);
                }
                validate_packet(&self.policy, &t.packet)?;
                if t.signature.s >= ORDER {
                    return Err(EnvelopeError::Signature);
                }
                let d = t.packet.digest();
                bip340_verify(&key, &trusted_message(&self.policy_id, &key, &d), &t.signature)
                    .map_err(|_| EnvelopeError::Signature)?;
                Ok(d)
            }
        }
    }
}

/// HFT-04 packet validation is private to `hft_packets`; reuse it by
/// checking through a throwaway single-vote path is not possible, so the
/// relay re-applies the public invariants it relies on (scope, chain shape,
/// HOLD reason range) and the receiver re-validates sources at use.
fn validate_packet(p: &Policy, packet: &Packet) -> Result<(), EnvelopeError> {
    use shz_oracle::hft_packets::{Error, MAX_SOURCE_AGE_US, MAX_SOURCE_SKEW_US};
    let t = p.fast_at(packet.seq).map_err(EnvelopeError::Packet)?;
    if (packet.seq == 1) != (packet.previous == [0; 32]) {
        return Err(EnvelopeError::Packet(Error::Sequence));
    }
    match packet.mark {
        Mark::Hold { reason } if !(1..=3).contains(&reason) => Err(EnvelopeError::Packet(Error::Bounds)),
        Mark::Hold { .. } => Ok(()),
        Mark::Valid { pyth, chainlink } => {
            let bad = pyth.report == chainlink.report
                || [pyth, chainlink].iter().any(|s| {
                    s.report == [0; 32]
                        || s.published_us == 0
                        || s.price_e8 == 0
                        || s.price_e8 > 10_000_000_000_000_000
                        || !t.checked_sub(s.published_us).is_some_and(|a| a <= MAX_SOURCE_AGE_US)
                })
                || pyth.published_us.abs_diff(chainlink.published_us) > MAX_SOURCE_SKEW_US
                || pyth.price_e8.abs_diff(chainlink.price_e8) as u128 * 20_000 > 50 * (pyth.price_e8 as u128 + chainlink.price_e8 as u128);
            if bad { Err(EnvelopeError::Packet(Error::Source)) } else { Ok(()) }
        }
    }
}

pub fn sign_trusted(policy_id: &Hash, secret: &Hash, packet: Packet) -> Result<TrustedPacket, EnvelopeError> {
    let relay_key = pubkey_x_from_secret(secret).map_err(|_| EnvelopeError::Signature)?;
    let msg = trusted_message(policy_id, &relay_key, &packet.digest());
    let signature = bip340_sign(secret, &msg).map_err(|_| EnvelopeError::Signature)?;
    Ok(TrustedPacket { packet, relay_key, signature })
}

// ---------------------------------------------------------------- wire ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSource {
    pub report: String,
    pub published_us: u64,
    pub price_e8: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireMark {
    Valid { pyth: WireSource, chainlink: WireSource },
    Hold { reason: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePacket {
    pub policy: String,
    pub seq: u64,
    pub previous: String,
    pub mark: WireMark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireVote {
    pub member: u8,
    pub signature: String,
}

/// JSON wire form; the `mode` tag is explicit and never inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WireCertified {
    TrustedRelay { packet: WirePacket, relay_key: String, signature: String },
    Federated { packet: WirePacket, votes: Vec<WireVote> },
}

fn h32(s: &str) -> Result<Hash, EnvelopeError> {
    let v = hex::decode(s).map_err(|e| EnvelopeError::Wire(e.to_string()))?;
    v.try_into().map_err(|_| EnvelopeError::Wire("expected 32 bytes".into()))
}
fn sig_hex(s: &Bip340Signature) -> String {
    hex::encode(s.to_bytes())
}
fn sig_from(s: &str) -> Result<Bip340Signature, EnvelopeError> {
    let v = hex::decode(s).map_err(|e| EnvelopeError::Wire(e.to_string()))?;
    if v.len() != 64 {
        return Err(EnvelopeError::Wire("expected 64-byte signature".into()));
    }
    Ok(Bip340Signature { r_x: v[..32].try_into().unwrap(), s: v[32..].try_into().unwrap() })
}

impl From<&Packet> for WirePacket {
    fn from(p: &Packet) -> Self {
        let src = |s: &Source| WireSource { report: hex::encode(s.report), published_us: s.published_us, price_e8: s.price_e8 };
        WirePacket {
            policy: hex::encode(p.policy),
            seq: p.seq,
            previous: hex::encode(p.previous),
            mark: match &p.mark {
                Mark::Valid { pyth, chainlink } => WireMark::Valid { pyth: src(pyth), chainlink: src(chainlink) },
                Mark::Hold { reason } => WireMark::Hold { reason: *reason },
            },
        }
    }
}

impl TryFrom<&WirePacket> for Packet {
    type Error = EnvelopeError;
    fn try_from(w: &WirePacket) -> Result<Self, EnvelopeError> {
        let src = |s: &WireSource| -> Result<Source, EnvelopeError> {
            Ok(Source { report: h32(&s.report)?, published_us: s.published_us, price_e8: s.price_e8 })
        };
        Ok(Packet {
            policy: h32(&w.policy)?,
            seq: w.seq,
            previous: h32(&w.previous)?,
            mark: match &w.mark {
                WireMark::Valid { pyth, chainlink } => Mark::Valid { pyth: src(pyth)?, chainlink: src(chainlink)? },
                WireMark::Hold { reason } => Mark::Hold { reason: *reason },
            },
        })
    }
}

impl From<&CertifiedPacket> for WireCertified {
    fn from(c: &CertifiedPacket) -> Self {
        match c {
            CertifiedPacket::Trusted(t) => WireCertified::TrustedRelay {
                packet: (&t.packet).into(),
                relay_key: hex::encode(t.relay_key),
                signature: sig_hex(&t.signature),
            },
            CertifiedPacket::Federated(c) => WireCertified::Federated {
                packet: (&c.packet).into(),
                votes: c.votes.iter().map(|v| WireVote { member: v.member, signature: sig_hex(&v.signature) }).collect(),
            },
        }
    }
}

impl TryFrom<&WireCertified> for CertifiedPacket {
    type Error = EnvelopeError;
    fn try_from(w: &WireCertified) -> Result<Self, EnvelopeError> {
        Ok(match w {
            WireCertified::TrustedRelay { packet, relay_key, signature } => CertifiedPacket::Trusted(TrustedPacket {
                packet: packet.try_into()?,
                relay_key: h32(relay_key)?,
                signature: sig_from(signature)?,
            }),
            WireCertified::Federated { packet, votes } => CertifiedPacket::Federated(Certificate {
                packet: packet.try_into()?,
                votes: votes
                    .iter()
                    .map(|v| Ok(Vote { member: v.member, signature: sig_from(&v.signature)? }))
                    .collect::<Result<_, EnvelopeError>>()?,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shz_oracle::hft_packets::Signer;

    pub(crate) fn policy() -> Policy {
        Policy {
            network: [9; 32],
            market: [8; 32],
            epoch: 1,
            origin_us: 10_000_000,
            members: std::array::from_fn(|i| pubkey_x_from_secret(&[(i + 1) as u8; 32]).unwrap()),
        }
    }
    fn hold(p: &Policy, seq: u64, previous: Hash) -> Packet {
        Packet { policy: p.id().unwrap(), seq, previous, mark: Mark::Hold { reason: 1 } }
    }

    #[test]
    fn trusted_cannot_masquerade_as_federated() {
        let p = policy();
        let relay_sk = [0x99; 32];
        let relay_pk = pubkey_x_from_secret(&relay_sk).unwrap();
        let t = sign_trusted(&p.id().unwrap(), &relay_sk, hold(&p, 1, [0; 32])).unwrap();
        let fed = PacketVerifier::federated(p.clone()).unwrap();
        let tr = PacketVerifier::trusted(p.clone(), relay_pk).unwrap();
        assert!(tr.verify(&CertifiedPacket::Trusted(t.clone())).is_ok());
        assert_eq!(fed.verify(&CertifiedPacket::Trusted(t.clone())), Err(EnvelopeError::ModeMismatch));
        // Relabel the trusted signature as four "votes": domain separation and
        // membership make it fail federated verification.
        let forged = Certificate {
            packet: t.packet.clone(),
            votes: (0..4).map(|m| Vote { member: m, signature: t.signature }).collect(),
        };
        assert!(fed.verify(&CertifiedPacket::Federated(forged.clone())).is_err());
        assert_eq!(tr.verify(&CertifiedPacket::Federated(forged)), Err(EnvelopeError::ModeMismatch));
        // A relay key equal to a member is refused at configuration time.
        assert!(PacketVerifier::trusted(p.clone(), p.members[0]).is_err());
    }

    #[test]
    fn federated_round_trip_and_tamper() {
        let p = policy();
        let mut ss: Vec<_> = (0..5).map(|i| Signer::new(&p, i, [(i + 1) as u8; 32]).unwrap()).collect();
        let pk = hold(&p, 1, [0; 32]);
        let votes = ss.iter_mut().take(4).map(|s| s.vote(&p, &pk).unwrap()).collect();
        let c = CertifiedPacket::Federated(Certificate { packet: pk, votes });
        let wire = WireCertified::from(&c);
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("\"mode\":\"federated\""));
        let back = CertifiedPacket::try_from(&serde_json::from_str::<WireCertified>(&json).unwrap()).unwrap();
        let fed = PacketVerifier::federated(p).unwrap();
        assert_eq!(fed.verify(&back).unwrap(), c.digest());
        let mut tampered = wire.clone();
        if let WireCertified::Federated { packet, .. } = &mut tampered {
            packet.mark = WireMark::Hold { reason: 2 };
        }
        assert!(fed.verify(&CertifiedPacket::try_from(&tampered).unwrap()).is_err());
    }

    #[test]
    fn trusted_wrong_key_scope_and_bad_hold() {
        let p = policy();
        let sk = [0x99; 32];
        let pk = pubkey_x_from_secret(&sk).unwrap();
        let v = PacketVerifier::trusted(p.clone(), pk).unwrap();
        let other = sign_trusted(&p.id().unwrap(), &[0x98; 32], hold(&p, 1, [0; 32])).unwrap();
        assert_eq!(v.verify(&CertifiedPacket::Trusted(other)), Err(EnvelopeError::Signature));
        let mut bad = hold(&p, 1, [0; 32]);
        bad.mark = Mark::Hold { reason: 9 };
        let t = sign_trusted(&p.id().unwrap(), &sk, bad).unwrap();
        assert!(matches!(v.verify(&CertifiedPacket::Trusted(t)), Err(EnvelopeError::Packet(_))));
        let mut q = p.clone();
        q.epoch = 2;
        let t = sign_trusted(&q.id().unwrap(), &sk, hold(&q, 1, [0; 32])).unwrap();
        assert_eq!(v.verify(&CertifiedPacket::Trusted(t)), Err(EnvelopeError::Signature));
    }
}
