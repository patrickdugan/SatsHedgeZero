//! Client-side tiered receiver and relay authentication.
//!
//! [`TieredReceiver`] generalizes the HFT-04 `Receiver` to three tiers and
//! both security modes. A packet that is validly certified and in sequence
//! but outside the tier's usable window still advances the hash chain
//! (`ChainOnly`) so a late or caught-up packet never wedges the receiver,
//! but no mark is exposed from it. Marks fail closed on HOLD, stale source,
//! clock regression or excessive clock uncertainty.

use serde::{Deserialize, Serialize};
use shz_dlc::{Bip340Signature, bip340_sign, bip340_verify, tagged_hash};
use shz_oracle::hft_packets::{CADENCE_US, MAX_CLOCK_ERROR_US, MAX_SOURCE_AGE_US, Mark, Packet};

use crate::{
    envelope::{CertifiedPacket, EnvelopeError, Hash, PacketVerifier},
    schedule::{ReleasePolicy, Tier},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxError {
    Verify,
    Sequence,
    Clock,
    Hold,
    Stale,
    Window,
    NoPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    Usable(Hash),
    ChainOnly(Hash),
}

pub struct TieredReceiver {
    verifier: PacketVerifier,
    tier: Tier,
    release: ReleasePolicy,
    seq: u64,
    last: Hash,
    anchored: bool,
    packet: Option<Packet>,
    clock: u64,
}

impl TieredReceiver {
    pub fn new(verifier: PacketVerifier, tier: Tier, release: ReleasePolicy) -> Self {
        Self { verifier, tier, release, seq: 0, last: [0; 32], anchored: false, packet: None, clock: 0 }
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }

    fn tick(&mut self, now: u64, err: u64) -> Result<(), RxError> {
        if now < self.clock || err > MAX_CLOCK_ERROR_US || now < err {
            return Err(RxError::Clock);
        }
        self.clock = now;
        Ok(())
    }

    fn window(&self, seq: u64) -> Result<(u64, u64), RxError> {
        let t = self.verifier.policy().fast_at(seq).map_err(|_| RxError::Sequence)?;
        let start = t + self.release.offset_us(self.tier);
        Ok((start, start + CADENCE_US))
    }

    /// Re-anchor at a certified checkpoint (after a disconnect beyond the
    /// relay's retained history). No mark until the next packet arrives.
    pub fn anchor(&mut self, c: &CertifiedPacket) -> Result<(), RxError> {
        let d = self.verifier.verify(c).map_err(|_| RxError::Verify)?;
        if c.packet().seq < self.seq {
            return Err(RxError::Sequence);
        }
        self.seq = c.packet().seq;
        self.last = d;
        self.anchored = true;
        self.packet = None;
        Ok(())
    }

    pub fn accept(&mut self, c: &CertifiedPacket, now: u64, err: u64) -> Result<Accepted, RxError> {
        self.tick(now, err)?;
        let d = self.verifier.verify(c).map_err(|e| match e {
            EnvelopeError::ModeMismatch | EnvelopeError::Signature => RxError::Verify,
            _ => RxError::Verify,
        })?;
        let p = c.packet();
        let first = self.seq == 0 && !self.anchored;
        if !first && (p.seq != self.seq + 1 || p.previous != self.last) {
            return Err(RxError::Sequence);
        }
        self.seq = p.seq;
        self.last = d;
        let (start, end) = self.window(p.seq)?;
        // Conservative both ends under the clock bound.
        if now - err < start || now + err >= end {
            self.packet = None;
            return Ok(Accepted::ChainOnly(d));
        }
        self.packet = Some(p.clone());
        Ok(Accepted::Usable(d))
    }

    /// Current usable mark `(seq, digest, price_e8)`.
    pub fn mark(&mut self, now: u64, err: u64) -> Result<(u64, Hash, u64), RxError> {
        self.tick(now, err)?;
        let p = self.packet.as_ref().ok_or(RxError::NoPacket)?;
        let (start, end) = self.window(p.seq)?;
        if now - err < start || now + err >= end {
            return Err(RxError::Window);
        }
        let Mark::Valid { pyth, chainlink } = p.mark else { return Err(RxError::Hold) };
        if [pyth, chainlink].iter().any(|s| !(now + err).checked_sub(s.published_us).is_some_and(|a| a <= MAX_SOURCE_AGE_US)) {
            return Err(RxError::Stale);
        }
        Ok((p.seq, self.last, p.price().ok_or(RxError::Hold)?))
    }
}

// ---------------------------------------------------------------- auth ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientEntry {
    pub id: String,
    pub tier: Tier,
    /// BIP340 x-only public key, hex.
    pub pubkey: String,
    #[serde(default = "default_max_conn")]
    pub max_connections: u32,
}
fn default_max_conn() -> u32 {
    2
}

pub fn auth_message(relay_id: &Hash, nonce: &Hash, client_id: &str) -> Hash {
    let mut b = Vec::with_capacity(64 + client_id.len());
    b.extend(relay_id);
    b.extend(nonce);
    b.extend(client_id.as_bytes());
    tagged_hash(b"SHZ/HFT06/RELAY-AUTH/V1", &b)
}

pub fn sign_auth(secret: &Hash, relay_id: &Hash, nonce: &Hash, client_id: &str) -> Bip340Signature {
    bip340_sign(secret, &auth_message(relay_id, nonce, client_id)).expect("valid client key")
}

pub fn verify_auth(entry: &ClientEntry, relay_id: &Hash, nonce: &Hash, sig: &Bip340Signature) -> bool {
    let Ok(pk) = hex::decode(&entry.pubkey) else { return false };
    let Ok(pk): Result<Hash, _> = pk.try_into() else { return false };
    bip340_verify(&pk, &auth_message(relay_id, nonce, &entry.id), sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::sign_trusted;
    use shz_oracle::hft_packets::{Policy, Source};

    const SK: Hash = [0x99; 32];
    fn policy() -> Policy {
        Policy {
            network: [9; 32],
            market: [8; 32],
            epoch: 1,
            origin_us: 10_000_000,
            members: std::array::from_fn(|i| shz_dlc::pubkey_x_from_secret(&[(i + 1) as u8; 32]).unwrap()),
        }
    }
    fn chain(n: u64, valid: bool) -> Vec<CertifiedPacket> {
        let p = policy();
        let mut prev = [0; 32];
        (1..=n)
            .map(|seq| {
                let t = p.fast_at(seq).unwrap();
                let mark = if valid {
                    Mark::Valid {
                        pyth: Source { report: [1; 32], published_us: t - 20_000, price_e8: 10_000_000_000_000 },
                        chainlink: Source { report: [2; 32], published_us: t - 30_000, price_e8: 10_001_000_000_000 },
                    }
                } else {
                    Mark::Hold { reason: 1 }
                };
                let pk = Packet { policy: p.id().unwrap(), seq, previous: prev, mark };
                prev = pk.digest();
                CertifiedPacket::Trusted(sign_trusted(&p.id().unwrap(), &SK, pk).unwrap())
            })
            .collect()
    }
    fn rx(tier: Tier) -> TieredReceiver {
        TieredReceiver::new(PacketVerifier::trusted(policy(), shz_dlc::pubkey_x_from_secret(&SK).unwrap()).unwrap(), tier, ReleasePolicy::default())
    }

    #[test]
    fn windows_per_tier_and_fail_closed() {
        let c = chain(3, true);
        let t1 = 10_000_000;
        let mut prem = rx(Tier::Premium);
        let mut mid = rx(Tier::Intermediate);
        let mut std_ = rx(Tier::Standard);
        assert!(matches!(prem.accept(&c[0], t1 + 5_000, 5_000).unwrap(), Accepted::Usable(_)));
        assert!(prem.mark(t1 + 5_000, 5_000).is_ok());
        assert!(matches!(mid.accept(&c[0], t1 + 104_999, 5_000).unwrap(), Accepted::ChainOnly(_)));
        assert_eq!(mid.mark(t1 + 104_999, 5_000), Err(RxError::NoPacket));
        assert!(matches!(std_.accept(&c[0], t1 + 205_000, 5_000).unwrap(), Accepted::Usable(_)));
        assert!(std_.mark(t1 + 205_000, 5_000).is_ok());
        // Premium mark expires at the next boundary even without a new packet.
        assert_eq!(prem.mark(t1 + 195_001, 5_000), Err(RxError::Window));
        // Clock regression and excessive uncertainty.
        assert_eq!(prem.mark(t1 + 1, 5_000), Err(RxError::Clock));
        assert_eq!(prem.accept(&c[1], t1 + 300_000, 6_000), Err(RxError::Clock));
        // Out of order / replay.
        assert_eq!(prem.accept(&c[2], t1 + 405_000, 5_000), Err(RxError::Sequence));
        assert_eq!(prem.accept(&c[0], t1 + 405_000, 5_000), Err(RxError::Sequence));
    }

    #[test]
    fn late_packet_advances_chain_and_anchor_resumes() {
        let c = chain(4, false);
        let t1 = 10_000_000;
        let mut r = rx(Tier::Premium);
        r.accept(&c[0], t1 + 5_000, 1_000).unwrap();
        // Packet 2 arrives late (after its premium window): chain-only.
        assert!(matches!(r.accept(&c[1], t1 + 401_000, 1_000).unwrap(), Accepted::ChainOnly(_)));
        assert!(matches!(r.accept(&c[2], t1 + 405_000 + 5_000, 1_000).unwrap(), Accepted::Usable(_)));
        assert_eq!(r.mark(t1 + 410_000, 1_000), Err(RxError::Hold));
        // A fresh receiver anchors at checkpoint 3 and continues at 4.
        let mut r2 = rx(Tier::Premium);
        r2.anchor(&c[2]).unwrap();
        assert!(r2.accept(&c[3], t1 + 605_000, 1_000).is_ok());
    }

    #[test]
    fn auth_challenge_binds_relay_nonce_and_client() {
        let sk = [0x33; 32];
        let e = ClientEntry { id: "alice".into(), tier: Tier::Premium, pubkey: hex::encode(shz_dlc::pubkey_x_from_secret(&sk).unwrap()), max_connections: 1 };
        let relay = [1; 32];
        let n = [2; 32];
        let s = sign_auth(&sk, &relay, &n, "alice");
        assert!(verify_auth(&e, &relay, &n, &s));
        assert!(!verify_auth(&e, &relay, &[3; 32], &s));
        assert!(!verify_auth(&e, &[4; 32], &n, &s));
        let bob = ClientEntry { id: "bob".into(), ..e.clone() };
        assert!(!verify_auth(&bob, &relay, &n, &s));
    }
}
