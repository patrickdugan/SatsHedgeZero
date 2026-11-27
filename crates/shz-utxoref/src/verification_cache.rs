//! Experimental, process-local memoization of the pure BIP-340 verification relation.
//! A successful lookup says nothing about spendability, authorization policy or finality.
//! Always recompute the signing digest from canonical transaction/context bytes first.
use std::collections::VecDeque;
use shz_dlc::{bip340_verify, Bip340Signature, DlcError};

/// Bounded pilot; do not let request-controlled sizes allocate arbitrary memory.
pub const MAX_ENTRIES: usize = 4096;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerificationStats {
    pub hits: u64,
    pub misses: u64,
    pub rejected: u64,
    pub evictions: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    pubkey: [u8; 32],
    digest: [u8; 32],
    signature: [u8; 64],
}

/// Positive-only LRU cache for one fixed verifier implementation and 32-byte digests.
/// Intentionally has no import, persistence, insert-success or authorization API.
pub struct SchnorrVerificationCache {
    capacity: usize,
    entries: VecDeque<Key>,
    stats: VerificationStats,
}
impl SchnorrVerificationCache {
    pub fn new(capacity: usize) -> Option<Self> {
        if capacity > MAX_ENTRIES { return None; }
        Some(Self { capacity, entries: VecDeque::with_capacity(capacity), stats: VerificationStats::default() })
    }
    pub fn stats(&self) -> VerificationStats { self.stats }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn clear(&mut self) { self.entries.clear(); }
    pub fn verify(&mut self, pubkey: &[u8; 32], digest: &[u8; 32], sig: &Bip340Signature) -> Result<(), DlcError> {
        let key = Key { pubkey: *pubkey, digest: *digest, signature: sig.to_bytes() };
        if let Some(pos) = self.entries.iter().position(|e| e == &key) {
            let hit = self.entries.remove(pos).expect("position from this deque");
            self.entries.push_back(hit);
            self.stats.hits = self.stats.hits.saturating_add(1);
            return Ok(());
        }
        self.stats.misses = self.stats.misses.saturating_add(1);
        if let Err(e) = bip340_verify(pubkey, digest, sig) {
            self.stats.rejected = self.stats.rejected.saturating_add(1);
            return Err(e);
        }
        if self.capacity != 0 {
            if self.entries.len() == self.capacity {
                self.entries.pop_front();
                self.stats.evictions = self.stats.evictions.saturating_add(1);
            }
            self.entries.push_back(key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shz_dlc::{bip340_sign, pubkey_x_from_secret};

    #[test]
    fn exact_tuple_only_and_no_negative_admission() {
        let sk = [1u8; 32];
        let pk = pubkey_x_from_secret(&sk).unwrap();
        let wrong_pk = pubkey_x_from_secret(&[2u8; 32]).unwrap();
        let digest = [3u8; 32];
        let wrong_digest = [4u8; 32];
        let sig = bip340_sign(&sk, &digest).unwrap();
        let mut cache = SchnorrVerificationCache::new(2).unwrap();
        assert!(cache.verify(&pk, &digest, &sig).is_ok());
        assert!(cache.verify(&pk, &digest, &sig).is_ok());
        for _ in 0..2 {
            assert!(cache.verify(&pk, &wrong_digest, &sig).is_err());
            assert!(cache.verify(&wrong_pk, &digest, &sig).is_err());
        }
        let mut bad_sig = sig;
        bad_sig.s[31] ^= 1;
        assert!(cache.verify(&pk, &digest, &bad_sig).is_err());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.stats(), VerificationStats { hits: 1, misses: 6, rejected: 5, evictions: 0 });
    }

    #[test]
    fn bounded_eviction_and_disabled_path() {
        let sk = [1u8; 32];
        let pk = pubkey_x_from_secret(&sk).unwrap();
        let d1 = [1u8; 32];
        let d2 = [2u8; 32];
        let s1 = bip340_sign(&sk, &d1).unwrap();
        let s2 = bip340_sign(&sk, &d2).unwrap();
        let mut cache = SchnorrVerificationCache::new(1).unwrap();
        for (d,s) in [(&d1,&s1),(&d2,&s2),(&d1,&s1)] {
            cache.verify(&pk,d,s).unwrap();
        }
        assert_eq!(cache.stats().misses,3);
        assert_eq!(cache.stats().evictions,2);
        assert_eq!(cache.len(),1);
        cache.clear();
        assert!(cache.is_empty());
        let mut off = SchnorrVerificationCache::new(0).unwrap();
        for _ in 0..2 { off.verify(&pk,&d1,&s1).unwrap(); }
        assert_eq!(off.stats().misses,2);
        assert_eq!(off.stats().hits,0);
        assert!(off.is_empty());
        assert!(SchnorrVerificationCache::new(MAX_ENTRIES+1).is_none());
    }
}
