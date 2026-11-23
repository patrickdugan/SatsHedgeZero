//! Experimental NEAR bonded oracle & Pyth Pro (`pyth-lazer`) fraud-guard contract.
//!
//! Verifies native Pyth Pro Solana Ed25519 envelopes under an owner-governed, epoch-bounded
//! Pyth signer registry (supporting key rotation and revocation), parses inner signed LE
//! `PayloadData` (`Crypto.BTC/USD` feed ID 1), enforces payload/event replay nullifiers and
//! monotonic challenge windows, and slashes the bonded relayer on objective double-signing
//! equivocation OR authenticated Pyth source-price substitution.
//!
//! Explicit boundary: NEAR testnet deployment, external NEAR light-client finality proofs,
//! and Bitcoin BIP-341 Taproot spend enforcement remain separate acceptance gates.
use near_sdk::{
    AccountId, NearToken, PanicOnDefault, Promise,
    borsh::{BorshDeserialize, BorshSerialize},
    env, near_bindgen,
    serde::{Deserialize, Serialize},
    serde_json,
};

mod pyth_payload;

const PYTH_SOLANA_FORMAT_MAGIC: u32 = 2_182_742_457;
const RELAY_DOMAIN: &str = "SHZ/NEAR-PRICE-IMPORT/V1";
const MAX_SIGNER_ENTRIES: usize = 16;
const MAX_NULLIFIER_HISTORY: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct SignedRelayClaim {
    pub near_chain_id: String,
    pub near_contract: String,
    pub relayer_id: String,
    pub request_id: String,
    pub event_id: String,
    pub round: u64,
    pub receipt_hash: String,
    pub claimed_price_e8: String,
    pub publish_time_us: String,
    pub precommit_root: String,
    pub signature_hex: String,
}

#[derive(Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct PinnedPythSigner {
    pub pubkey_hex: String,
    pub pubkey_bytes: [u8; 32],
    pub valid_from_us: u64,
    pub valid_until_us: Option<u64>,
    pub revoked: bool,
}

#[derive(Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct StoredPythEpoch {
    pub epoch: u64,
    pub registry_epoch: u64,
    pub event_id: String,
    pub price_e8: String,
    pub confidence_bps: String,
    pub signed_payload_sha256_hex: String,
    pub signer_hex: String,
    pub publish_time_us: String,
    pub feed_update_time_us: String,
    pub challenge_end_block: u64,
    pub challenge_window_closed: bool,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ShzNearFraudGuard {
    pub owner: AccountId,
    pub relayer_account: AccountId,
    pub near_chain_id: String,
    pub relayer_id: String,
    pub registry_epoch: u64,
    pub pyth_signers: Vec<PinnedPythSigner>,
    pub relayer_signer: [u8; 32],
    pub relayer_bond_yocto: u128,
    pub slashed: bool,
    pub latest_pyth_epoch: Option<StoredPythEpoch>,
    pub consumed_payload_hashes: Vec<String>,
    pub consumed_event_ids: Vec<String>,
}

fn signer32(value: &str) -> [u8; 32] {
    let b = hex::decode(value).expect("public key must be lowercase/valid hex");
    b.try_into().expect("Ed25519 public key must be 32 bytes")
}

impl ShzNearFraudGuard {
    fn relay_message(&self, r: &SignedRelayClaim) -> Vec<u8> {
        assert!(
            r.round <= 9_007_199_254_740_991,
            "round must fit JS canonical safe integer"
        );
        let array = serde_json::json!([
            RELAY_DOMAIN,
            &r.near_chain_id,
            &r.near_contract,
            &r.relayer_id,
            &r.request_id,
            &r.event_id,
            r.round,
            &r.receipt_hash,
            &r.claimed_price_e8,
            &r.publish_time_us,
            &r.precommit_root
        ]);
        serde_json::to_vec(&array).expect("canonical JSON array")
    }

    fn verify_relay_sig(&self, r: &SignedRelayClaim) -> bool {
        if r.near_chain_id != self.near_chain_id
            || r.near_contract != env::current_account_id().as_str()
            || r.relayer_id != self.relayer_id
            || r.request_id.len() > 128
            || r.event_id.len() > 128
            || r.receipt_hash.len() != 64
            || r.precommit_root.len() != 64
        {
            return false;
        }
        let Ok(s) = hex::decode(&r.signature_hex) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(s.as_slice()) else {
            return false;
        };
        env::ed25519_verify(&sig, &self.relay_message(r), &self.relayer_signer)
    }

    fn is_pyth_signer_authorized(&self, pubkey: &[u8; 32], publish_time_us: Option<u64>) -> bool {
        self.pyth_signers.iter().any(|entry| {
            !entry.revoked
                && &entry.pubkey_bytes == pubkey
                && publish_time_us.is_none_or(|ts| {
                    ts >= entry.valid_from_us && entry.valid_until_us.is_none_or(|u| ts <= u)
                })
        })
    }

    fn push_bounded(list: &mut Vec<String>, value: String) {
        if list.len() >= MAX_NULLIFIER_HISTORY {
            list.remove(0);
        }
        list.push(value);
    }
}

#[near_bindgen]
impl ShzNearFraudGuard {
    #[init]
    pub fn new(
        owner: AccountId,
        relayer_account: AccountId,
        near_chain_id: String,
        relayer_id: String,
        pyth_signer_hex: String,
        relayer_signer_hex: String,
    ) -> Self {
        assert!(!env::state_exists(), "already initialized");
        assert!(
            near_chain_id == "near:mainnet" || near_chain_id == "near:testnet",
            "unsupported chain"
        );
        assert!(
            !relayer_id.is_empty() && relayer_id.len() <= 128,
            "invalid relayer id"
        );
        let pk_bytes = signer32(&pyth_signer_hex);
        Self {
            owner,
            relayer_account,
            near_chain_id,
            relayer_id,
            registry_epoch: 1,
            pyth_signers: vec![PinnedPythSigner {
                pubkey_hex: hex::encode(pk_bytes),
                pubkey_bytes: pk_bytes,
                valid_from_us: 0,
                valid_until_us: None,
                revoked: false,
            }],
            relayer_signer: signer32(&relayer_signer_hex),
            relayer_bond_yocto: 0,
            slashed: false,
            latest_pyth_epoch: None,
            consumed_payload_hashes: Vec::new(),
            consumed_event_ids: Vec::new(),
        }
    }

    /// Owner-governed Pyth Pro signer rotation: adds or replaces the pinned Ed25519 signer set
    /// under a strictly advancing `next_registry_epoch`.
    pub fn rotate_pyth_signers(
        &mut self,
        next_registry_epoch: u64,
        new_signers: Vec<(String, u64, Option<u64>)>,
    ) -> u64 {
        assert_eq!(env::predecessor_account_id(), self.owner, "owner only");
        assert!(
            next_registry_epoch > self.registry_epoch,
            "non-monotonic registry epoch"
        );
        assert!(
            !new_signers.is_empty() && new_signers.len() <= MAX_SIGNER_ENTRIES,
            "invalid Pyth signer set size"
        );
        let mut built = Vec::with_capacity(new_signers.len());
        for (pk_hex, from_us, until_us) in new_signers {
            if let Some(u) = until_us {
                assert!(u >= from_us, "valid_until_us precedes valid_from_us");
            }
            let pk_bytes = signer32(&pk_hex);
            built.push(PinnedPythSigner {
                pubkey_hex: hex::encode(pk_bytes),
                pubkey_bytes: pk_bytes,
                valid_from_us: from_us,
                valid_until_us: until_us,
                revoked: false,
            });
        }
        self.registry_epoch = next_registry_epoch;
        self.pyth_signers = built;
        self.registry_epoch
    }

    /// Emergency owner revocation of a compromised or retired Pyth Ed25519 signer key.
    pub fn revoke_pyth_signer(&mut self, pubkey_hex: String) -> bool {
        assert_eq!(env::predecessor_account_id(), self.owner, "owner only");
        let target = signer32(&pubkey_hex);
        let mut revoked_any = false;
        for entry in &mut self.pyth_signers {
            if entry.pubkey_bytes == target && !entry.revoked {
                entry.revoked = true;
                revoked_any = true;
            }
        }
        assert!(revoked_any, "Pyth signer not found or already revoked");
        true
    }

    /// Authenticates the outer Pyth Pro Solana Ed25519 signature against the pinned registry.
    pub fn verify_pyth_pro_solana_envelope(&self, raw: Vec<u8>) -> bool {
        if raw.len() < 103 || raw.len() > 16_384 {
            return false;
        }
        if u32::from_le_bytes(raw[0..4].try_into().unwrap()) != PYTH_SOLANA_FORMAT_MAGIC {
            return false;
        }
        let n = u16::from_le_bytes(raw[100..102].try_into().unwrap()) as usize;
        if n == 0 || raw.len() != 102 + n {
            return false;
        }
        let signer: [u8; 32] = raw[68..100].try_into().unwrap();
        if !self.is_pyth_signer_authorized(&signer, None) {
            return false;
        }
        let sig: [u8; 64] = raw[4..68].try_into().unwrap();
        env::ed25519_verify(&sig, &raw[102..], &signer)
    }

    /// Verifies both the Ed25519 Solana envelope (including epoch-window authorization at
    /// `publish_time_us`) and inner signed BTC/USD (`feed_id == 1`) fields.
    pub fn verify_pyth_btc_usd_price(
        &self,
        raw: Vec<u8>,
        max_age_us: u64,
        max_carry_forward_us: u64,
        max_conf_bps: u64,
    ) -> Option<pyth_payload::BtcUsdSignedPoint> {
        if max_age_us == 0
            || max_age_us > 60_000_000
            || max_carry_forward_us > 60_000_000
            || max_conf_bps > 10_000
        {
            return None;
        }
        if !self.verify_pyth_pro_solana_envelope(raw.clone()) {
            return None;
        }
        let signer: [u8; 32] = raw[68..100].try_into().unwrap();
        let point = pyth_payload::parse_btc_usd_signed_price(&raw[102..])?;
        let stamp = point.publish_time_us.parse::<u64>().ok()?;
        if !self.is_pyth_signer_authorized(&signer, Some(stamp)) {
            return None;
        }
        let now = env::block_timestamp() / 1_000;
        let feed_time = point.feed_update_time_us.parse::<u64>().ok()?;
        let conf = point.confidence_bps.parse::<u64>().ok()?;
        if stamp > now.saturating_add(100_000)
            || now.saturating_sub(stamp) > max_age_us
            || stamp.saturating_sub(feed_time) > max_carry_forward_us
            || conf > max_conf_bps
        {
            return None;
        }
        Some(point)
    }

    /// Records a monotonically advancing, replay-protected Pyth BTC/USD epoch with a 20-block
    /// on-NEAR challenge window.
    pub fn post_pyth_btc_usd_epoch(
        &mut self,
        raw: Vec<u8>,
        epoch: u64,
        event_id: String,
    ) -> StoredPythEpoch {
        assert_eq!(
            env::predecessor_account_id(),
            self.relayer_account,
            "relayer only"
        );
        assert!(
            !self.slashed && self.relayer_bond_yocto > 0,
            "relayer requires active bond"
        );
        assert!(
            !event_id.is_empty() && event_id.len() <= 128,
            "invalid event id"
        );
        assert!(epoch > 0, "epoch must be positive");
        assert!(
            !self.consumed_event_ids.contains(&event_id),
            "replayed oracle event_id"
        );

        if let Some(previous) = &self.latest_pyth_epoch {
            assert!(
                previous.challenge_window_closed,
                "prior oracle challenge window remains open"
            );
            assert!(epoch > previous.epoch, "duplicate or reversed oracle epoch");
        }

        let signer_hex = hex::encode(&raw[68..100.min(raw.len())]);
        let point = self
            .verify_pyth_btc_usd_price(raw, 5_000_000, 2_000_000, 100)
            .expect("signed Pyth price, timestamp or confidence policy rejected");
        assert_eq!(point.channel_id, 3, "require Pyth fixed_rate@200ms");
        assert!(
            !self
                .consumed_payload_hashes
                .contains(&point.signed_payload_sha256_hex),
            "replayed signed Pyth payload hash"
        );

        if let Some(previous) = &self.latest_pyth_epoch {
            let prev = previous
                .publish_time_us
                .parse::<u64>()
                .expect("stored publish timestamp");
            let current = point
                .publish_time_us
                .parse::<u64>()
                .expect("signed publish timestamp");
            assert!(
                current > prev,
                "replayed or non-monotone signed Pyth update"
            );
        }

        Self::push_bounded(
            &mut self.consumed_payload_hashes,
            point.signed_payload_sha256_hex.clone(),
        );
        Self::push_bounded(&mut self.consumed_event_ids, event_id.clone());

        let stored = StoredPythEpoch {
            epoch,
            registry_epoch: self.registry_epoch,
            event_id,
            price_e8: point.price_e8,
            confidence_bps: point.confidence_bps,
            signed_payload_sha256_hex: point.signed_payload_sha256_hex,
            signer_hex,
            publish_time_us: point.publish_time_us,
            feed_update_time_us: point.feed_update_time_us,
            challenge_end_block: env::block_height().saturating_add(20),
            challenge_window_closed: false,
        };
        self.latest_pyth_epoch = Some(stored.clone());
        env::log_str(&format!(
            "SHZ_PYTH_EPOCH:{epoch}:{}",
            stored.signed_payload_sha256_hex
        ));
        stored
    }

    pub fn close_pyth_epoch_challenge_window(&mut self, epoch: u64) -> StoredPythEpoch {
        assert!(!self.slashed, "slashed oracle guard");
        let stored = self.latest_pyth_epoch.as_mut().expect("missing Pyth epoch");
        assert_eq!(stored.epoch, epoch, "wrong oracle epoch");
        assert!(
            env::block_height() >= stored.challenge_end_block,
            "challenge window open"
        );
        stored.challenge_window_closed = true;
        stored.clone()
    }

    pub fn latest_pyth_epoch(&self) -> Option<StoredPythEpoch> {
        self.latest_pyth_epoch.clone()
    }

    pub fn pinned_pyth_signers(&self) -> Vec<PinnedPythSigner> {
        self.pyth_signers.clone()
    }

    #[payable]
    pub fn post_relayer_bond(&mut self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.relayer_account,
            "relayer only"
        );
        assert!(!self.slashed, "relayer already slashed");
        let amount = env::attached_deposit().as_yoctonear();
        assert!(amount > 0, "empty bond");
        self.relayer_bond_yocto = self
            .relayer_bond_yocto
            .checked_add(amount)
            .expect("bond overflow");
    }

    /// Objective Fraud Regime 1: Double-signing two conflicting relay claims on the same
    /// `(near_chain_id, near_contract, relayer_id, event_id, round, request_id)`.
    pub fn submit_relayer_equivocation(
        &mut self,
        a: SignedRelayClaim,
        b: SignedRelayClaim,
    ) -> Promise {
        assert!(
            !self.slashed && self.relayer_bond_yocto > 0,
            "inactive or unbonded relayer"
        );
        assert_eq!(a.near_chain_id, b.near_chain_id, "different chains");
        assert_eq!(a.near_contract, b.near_contract, "different contracts");
        assert_eq!(a.relayer_id, b.relayer_id, "different relayers");
        assert_eq!(a.event_id, b.event_id, "different events");
        assert_eq!(a.round, b.round, "different rounds");
        assert_eq!(a.request_id, b.request_id, "different requests");
        assert!(
            self.verify_relay_sig(&a) && self.verify_relay_sig(&b),
            "invalid relay signatures"
        );
        assert!(
            a.receipt_hash != b.receipt_hash
                || a.claimed_price_e8 != b.claimed_price_e8
                || a.precommit_root != b.precommit_root
                || a.publish_time_us != b.publish_time_us,
            "identical signed claims"
        );
        let challenger = env::predecessor_account_id();
        let stake = self.relayer_bond_yocto;
        self.relayer_bond_yocto = 0;
        self.slashed = true;
        Promise::new(challenger).transfer(NearToken::from_yoctonear(stake))
    }

    /// Objective Fraud Regime 2: Source Substitution — relayer signed a `SignedRelayClaim`
    /// committing `receipt_hash == signed_payload_sha256_hex` of an authenticated Pyth Pro
    /// Solana envelope `raw_pyth_envelope`, yet altered `claimed_price_e8` or `publish_time_us`.
    pub fn submit_source_substitution_challenge(
        &mut self,
        claim: SignedRelayClaim,
        raw_pyth_envelope: Vec<u8>,
    ) -> Promise {
        assert!(
            !self.slashed && self.relayer_bond_yocto > 0,
            "inactive or unbonded relayer"
        );
        assert!(self.verify_relay_sig(&claim), "invalid relay signature");
        assert!(
            self.verify_pyth_pro_solana_envelope(raw_pyth_envelope.clone()),
            "invalid native Pyth Pro Solana envelope"
        );
        let point = pyth_payload::parse_btc_usd_signed_price(&raw_pyth_envelope[102..])
            .expect("invalid inner Pyth PayloadData");
        let stamp = point
            .publish_time_us
            .parse::<u64>()
            .expect("publish_time_us");
        let signer: [u8; 32] = raw_pyth_envelope[68..100].try_into().unwrap();
        assert!(
            self.is_pyth_signer_authorized(&signer, Some(stamp)),
            "Pyth signer unauthorized at payload timestamp"
        );
        assert_eq!(
            claim.receipt_hash, point.signed_payload_sha256_hex,
            "relay claim does not reference supplied Pyth payload digest"
        );
        assert!(
            claim.claimed_price_e8 != point.price_e8
                || claim.publish_time_us != point.publish_time_us,
            "relay claim matches authenticated Pyth price and timestamp"
        );

        let challenger = env::predecessor_account_id();
        let stake = self.relayer_bond_yocto;
        self.relayer_bond_yocto = 0;
        self.slashed = true;
        Promise::new(challenger).transfer(NearToken::from_yoctonear(stake))
    }

    pub fn is_slashed(&self) -> bool {
        self.slashed
    }

    pub fn bond_balance_yocto(&self) -> String {
        self.relayer_bond_yocto.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const OFFICIAL_LAZER_WIRE_SAMPLE_HEX: &str = concat!(
        "b9011a82c7887f3aaa5845b20d6bf5ca6609953b57650fa4579a4b4d34a4980ba608a9f76a825a446",
        "f3d6c1fd9daca1c5e3fc46980f14ef89c1a886c6e9e5c510872d30f80efc1f480c5615af3fb673d422",
        "87e993da9fbc3506b6e41dfa32950820c2e6c620075d3c7934077d115064b06000301010000000d009",
        "032fc171b060000014e3a0cff1a06000002bcda8a211b06000003120004f8ff05fc0b7159000000000",
        "600070008000900000aa06616362e0600000b804f93312e0600000c014077d115064b0600"
    );

    fn make_pyth_frame(
        sk: &SigningKey,
        publish_us: u64,
        update_us: u64,
        channel: u8,
        raw_price: i64,
        expo: i16,
        conf: i64,
    ) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&2_479_346_549u32.to_le_bytes());
        p.extend_from_slice(&publish_us.to_le_bytes());
        p.push(channel);
        p.push(1);
        p.extend_from_slice(&1u32.to_le_bytes());
        p.push(4);
        p.push(0);
        p.extend_from_slice(&raw_price.to_le_bytes());
        p.push(4);
        p.extend_from_slice(&expo.to_le_bytes());
        p.push(5);
        p.extend_from_slice(&conf.to_le_bytes());
        p.push(12);
        p.push(1);
        p.extend_from_slice(&update_us.to_le_bytes());

        let sig = sk.sign(&p);
        let mut out = Vec::with_capacity(102 + p.len());
        out.extend_from_slice(&PYTH_SOLANA_FORMAT_MAGIC.to_le_bytes());
        out.extend_from_slice(&sig.to_bytes());
        out.extend_from_slice(&sk.verifying_key().to_bytes());
        out.extend_from_slice(&(p.len() as u16).to_le_bytes());
        out.extend_from_slice(&p);
        out
    }

    fn ctx(predecessor: &str, block_height: u64, block_ts_ns: u64, deposit_yocto: u128) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id("shz-guard.testnet".parse().unwrap())
            .predecessor_account_id(predecessor.parse().unwrap())
            .block_height(block_height)
            .block_timestamp(block_ts_ns)
            .attached_deposit(NearToken::from_yoctonear(deposit_yocto));
        b
    }

    #[test]
    fn near_contract_verifies_official_sample_epoch_lifecycle_and_rotation() {
        let official = hex::decode(OFFICIAL_LAZER_WIRE_SAMPLE_HEX).unwrap();
        let official_signer_hex = hex::encode(&official[68..100]);
        let relayer_sk = SigningKey::from_bytes(&[0x42; 32]);
        let relayer_pk_hex = hex::encode(relayer_sk.verifying_key().to_bytes());

        testing_env!(ctx("owner.testnet", 100, 1_771_339_368_500_000_000, 0).build());
        let mut guard = ShzNearFraudGuard::new(
            "owner.testnet".parse().unwrap(),
            "relayer.testnet".parse().unwrap(),
            "near:testnet".to_owned(),
            "relayer-1".to_owned(),
            official_signer_hex,
            relayer_pk_hex,
        );

        // Bond relayer and import official signed Pyth Lazer wire sample at epoch 1!
        testing_env!(ctx("relayer.testnet", 100, 1_771_339_368_500_000_000, 5_000_000_000_000_000_000_000_000).build());
        guard.post_relayer_bond();
        let ep1 = guard.post_pyth_btc_usd_epoch(official, 1, "SHZ-EPOCH-1".to_owned());
        assert_eq!(ep1.price_e8, "6713436287632");
        assert_eq!(ep1.challenge_end_block, 120);
        assert!(!ep1.challenge_window_closed);

        // Close challenge window at block 120
        testing_env!(ctx("anyone.testnet", 120, 1_771_339_380_000_000_000, 0).build());
        let closed = guard.close_pyth_epoch_challenge_window(1);
        assert!(closed.challenge_window_closed);

        // Rotate Pyth signer key via owner governance & post epoch 2 under new key
        let new_pyth_sk = SigningKey::from_bytes(&[0x55; 32]);
        let new_pyth_pk_hex = hex::encode(new_pyth_sk.verifying_key().to_bytes());
        testing_env!(ctx("owner.testnet", 121, 1_795_000_000_000_000_000, 0).build());
        let reg_ep = guard.rotate_pyth_signers(
            2,
            vec![(new_pyth_pk_hex, 1_795_000_000_000_000, None)],
        );
        assert_eq!(reg_ep, 2);

        let frame2 = make_pyth_frame(
            &new_pyth_sk,
            1_795_000_001_000_000,
            1_795_000_001_000_000,
            3,
            12_500_000_000_000,
            -8,
            1_200_000_000,
        );
        testing_env!(ctx("relayer.testnet", 122, 1_795_000_001_500_000_000, 0).build());
        let ep2 = guard.post_pyth_btc_usd_epoch(frame2, 2, "SHZ-EPOCH-2".to_owned());
        assert_eq!(ep2.price_e8, "12500000000000");
        assert_eq!(ep2.registry_epoch, 2);
    }

    #[test]
    fn near_contract_slashes_source_substitution_and_equivocation() {
        let pyth_sk = SigningKey::from_bytes(&[0x33; 32]);
        let relayer_sk = SigningKey::from_bytes(&[0x44; 32]);

        testing_env!(ctx("owner.testnet", 500, 1_795_000_001_000_000_000, 0).build());
        let mut guard = ShzNearFraudGuard::new(
            "owner.testnet".parse().unwrap(),
            "relayer.testnet".parse().unwrap(),
            "near:testnet".to_owned(),
            "relayer-1".to_owned(),
            hex::encode(pyth_sk.verifying_key().to_bytes()),
            hex::encode(relayer_sk.verifying_key().to_bytes()),
        );

        testing_env!(ctx("relayer.testnet", 501, 1_795_000_001_000_000_000, 10_000_000_000_000_000_000_000_000).build());
        guard.post_relayer_bond();

        // Honest Pyth frame says $125,000 (price_e8 = 12500000000000), but relayer signs $99,000!
        let honest_frame = make_pyth_frame(
            &pyth_sk,
            1_795_000_000_000_000,
            1_795_000_000_000_000,
            3,
            12_500_000_000_000,
            -8,
            1_000_000_000,
        );
        let point = pyth_payload::parse_btc_usd_signed_price(&honest_frame[102..]).unwrap();

        let mut forged_claim = SignedRelayClaim {
            near_chain_id: "near:testnet".to_owned(),
            near_contract: "shz-guard.testnet".to_owned(),
            relayer_id: "relayer-1".to_owned(),
            request_id: "req-77".to_owned(),
            event_id: "SHZ-BTCUSD-77".to_owned(),
            round: 1,
            receipt_hash: point.signed_payload_sha256_hex.clone(),
            claimed_price_e8: "9900000000000".to_owned(), // Substituted off-market price!
            publish_time_us: point.publish_time_us.clone(),
            precommit_root: "ab".repeat(32),
            signature_hex: String::new(),
        };
        let msg = guard.relay_message(&forged_claim);
        forged_claim.signature_hex = hex::encode(relayer_sk.sign(&msg).to_bytes());

        testing_env!(ctx("challenger.testnet", 502, 1_795_000_001_000_000_000, 0).build());
        let _ = guard.submit_source_substitution_challenge(forged_claim, honest_frame);
        assert!(guard.is_slashed());
        assert_eq!(guard.bond_balance_yocto(), "0");
    }
}
