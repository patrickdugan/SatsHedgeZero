//! SHZ-RGB-01E: Native durable BTC withdrawal reservation state machine for `DurableTieredRouter`.
//!
//! State progression:
//! ```text
//! Free -> Reserved -> Submitted -> Reconciled
//!                        |
//!                        v
//!                    Ambiguous -> Reconciled
//!                        |
//!                        v
//!                      Frozen
//! ```
//! Plus independent-evidence cancellation from `Reserved`, `Submitted`, or `Ambiguous` -> `Cancelled`,
//! and post-reconcile conflict alerting `Reconciled -> Frozen` (retaining `withdrawn` without silent refund).
//!
//! Revised conservation invariant:
//! `free + resting + pending + committed + paid_fees + withdrawal_reserved + withdrawn == cap + realized_pnl`
//!
//! Partition invariants per account:
//! - `withdrawal_reserved == sum(w.amount_sats for w in {Reserved, Submitted, Ambiguous, Frozen{was_reconciled: false}})`
//! - `withdrawn == sum(w.amount_sats for w in {Reconciled, Frozen{was_reconciled: true}})`

use super::durable::{JournalTip, LaneState};
use super::tiered::ZERO_SIG;
use super::*;
use shz_dlc::{Bip340Signature, BtcOutPoint, tagged_hash};
use std::collections::{BTreeMap, BTreeSet};

pub const DOMAIN_NETWORK_ID: &[u8] = b"SHZ/NETWORK/V1";
pub const DOMAIN_WITHDRAWAL_REQUEST: &[u8] = b"SHZ/HFT06/WITHDRAWAL-REQ/V1";
pub const DOMAIN_WITHDRAWAL_RECEIPT: &[u8] = b"SHZ/HFT06/WITHDRAWAL-RECEIPT/V1";
pub const DOMAIN_WITHDRAWAL_RECONCILE: &[u8] = b"SHZ/HFT06/WITHDRAWAL-RECONCILE/V1";
pub const DOMAIN_WITHDRAWAL_CANCEL: &[u8] = b"SHZ/HFT06/WITHDRAWAL-CANCEL/V1";
pub const DOMAIN_WITHDRAWAL_FREEZE: &[u8] = b"SHZ/HFT06/WITHDRAWAL-FREEZE/V1";
pub const RECEIPT_SCHEMA_V1: &str = "SHZ/WITHDRAWAL-RECEIPT/V1";

/// Canonical 32-byte network identifier shared with the JS RGB sidecar.
pub fn network_id(name: &str) -> Key {
    tagged_hash(DOMAIN_NETWORK_ID, name.as_bytes())
}

/// Validates that `script` is a canonical native SegWit scriptPubKey:
/// - P2WPKH: `0x00 0x14 <20 bytes>` (22 bytes)
/// - P2WSH:  `0x00 0x20 <32 bytes>` (34 bytes)
/// - P2TR:   `0x51 0x20 <32 bytes>` (34 bytes)
pub fn is_valid_native_segwit_script(script: &[u8]) -> bool {
    (script.len() == 22 && script[0] == 0x00 && script[1] == 0x14)
        || (script.len() == 34 && script[0] == 0x00 && script[1] == 0x20)
        || (script.len() == 34 && script[0] == 0x51 && script[1] == 0x20)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalState {
    Reserved,
    Submitted,
    Ambiguous,
    Reconciled,
    /// `was_reconciled = false` means funds remain locked in `withdrawal_reserved`.
    /// `was_reconciled = true` means a post-reconcile chain conflict flagged an already
    /// finalized debit in `withdrawn` for operator investigation without refunding `free`.
    Frozen {
        was_reconciled: bool,
    },
    Cancelled,
}

impl WithdrawalState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Submitted => "submitted",
            Self::Ambiguous => "ambiguous",
            Self::Reconciled => "reconciled",
            Self::Frozen {
                was_reconciled: false,
            } => "frozen_reserved",
            Self::Frozen {
                was_reconciled: true,
            } => "frozen_reconciled",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn holds_reserved(self) -> bool {
        matches!(
            self,
            Self::Reserved
                | Self::Submitted
                | Self::Ambiguous
                | Self::Frozen {
                    was_reconciled: false
                }
        )
    }

    pub fn holds_withdrawn(self) -> bool {
        matches!(
            self,
            Self::Reconciled
                | Self::Frozen {
                    was_reconciled: true
                }
        )
    }
}

/// Owner BIP340-authorized BTC withdrawal reservation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub network: Key,
    pub router_config: Key,
    pub router: u32,
    pub channel: BtcOutPoint,
    pub owner: Key,
    pub nonce: u64,
    pub amount_sats: u64,
    pub destination_script: Vec<u8>,
    pub expires_us: u64,
    /// Committed batch sequence this withdrawal references (`0` if unbound to a specific batch).
    pub clearing_sequence: u64,
    /// Committed batch digest (`[0; 32]` iff `clearing_sequence == 0`).
    pub batch_digest: Key,
    /// Multilateral clearing vector digest (`[0; 32]` iff `clearing_sequence == 0` or clearing inactive).
    pub clearing_digest: Key,
    pub owner_sig: Bip340Signature,
}

impl WithdrawalRequest {
    /// Canonical binary payload hashed under `DOMAIN_WITHDRAWAL_REQUEST` to derive `withdrawal_id`.
    pub fn preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(192 + self.destination_script.len());
        b.extend_from_slice(&self.network);
        b.extend_from_slice(&self.router_config);
        u32b(&mut b, self.router);
        put_op(&mut b, &self.channel);
        b.extend_from_slice(&self.owner);
        u64b(&mut b, self.nonce);
        u64b(&mut b, self.amount_sats);
        u32b(&mut b, self.destination_script.len() as u32);
        b.extend_from_slice(&self.destination_script);
        u64b(&mut b, self.expires_us);
        u64b(&mut b, self.clearing_sequence);
        b.extend_from_slice(&self.batch_digest);
        b.extend_from_slice(&self.clearing_digest);
        b
    }

    pub fn withdrawal_id(&self) -> Key {
        tagged_hash(DOMAIN_WITHDRAWAL_REQUEST, &self.preimage())
    }

    pub fn signed(mut self, owner_sk: &Key) -> R<Self> {
        self.owner = public(owner_sk);
        let id = self.withdrawal_id();
        self.owner_sig = sign(owner_sk, &id)?;
        Ok(self)
    }

    pub fn verify_owner(&self) -> R<Key> {
        if self.network == [0; 32]
            || self.router_config == [0; 32]
            || self.router == 0
            || self.owner == [0; 32]
            || self.nonce == 0
            || self.amount_sats == 0
            || self.expires_us == 0
            || !is_valid_native_segwit_script(&self.destination_script)
        {
            return Err(Reject::Bounds);
        }
        if self.clearing_sequence == 0 {
            if self.batch_digest != [0; 32] || self.clearing_digest != [0; 32] {
                return Err(Reject::Bounds);
            }
        } else if self.batch_digest == [0; 32] {
            return Err(Reject::Bounds);
        }
        let id = self.withdrawal_id();
        verify(&self.owner, &id, &self.owner_sig)?;
        Ok(id)
    }
}

/// Independent attestation finalizing a submitted or ambiguous withdrawal (`-> Reconciled`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalReconcileAttestation {
    pub withdrawal_id: Key,
    /// Unique external BTC funding/settlement proof digest (never reused across withdrawals or fee receipts).
    pub btc_evidence: Key,
    /// External RGB/rail settlement evidence digest (must differ from `btc_evidence`).
    pub settlement_evidence: Key,
    /// Ordered BIP340 signatures: `[peer_sig, monitor_sig]`.
    pub signatures: [Bip340Signature; 2],
}

/// Independent attestation cancelling a withdrawal and releasing `withdrawal_reserved -> free`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalCancelAttestation {
    pub withdrawal_id: Key,
    /// Unique non-dispatch or irrevocable-cancellation evidence digest.
    pub cancellation_evidence: Key,
    /// Ordered BIP340 signatures: `[owner_sig, peer_sig, monitor_sig]`.
    /// - From `Reserved` (before external dispatch): `owner_sig` + `monitor_sig` required (`peer_sig` may be zero),
    ///   OR after `expires_us`, `peer_sig` + `monitor_sig` (`owner_sig` may be zero).
    /// - From `Submitted` or `Ambiguous`: `peer_sig` + `monitor_sig` are ALWAYS required (any present `owner_sig` must verify).
    pub signatures: [Bip340Signature; 3],
}

/// Independent conflict/reorg attestation freezing a withdrawal (`-> Frozen`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalFreezeAttestation {
    pub withdrawal_id: Key,
    /// Unique chain-conflict or reorg evidence digest.
    pub conflict_evidence: Key,
    /// BIP340 signature by the lane's pinned `monitor`.
    pub monitor_sig: Bip340Signature,
}

/// Durable record of one withdrawal reservation inside `DurableTieredRouter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRecord {
    pub withdrawal_id: Key,
    pub request: WithdrawalRequest,
    pub state: WithdrawalState,
    pub reserved_at_us: u64,
    pub updated_at_us: u64,
    /// Journal tip recorded immediately when this reservation became durable.
    pub reserved_tip: JournalTip,
    pub payment_hash: Option<Key>,
    pub btc_evidence: Option<Key>,
    pub settlement_evidence: Option<Key>,
    pub cancellation_evidence: Option<Key>,
    pub conflict_evidence: Option<Key>,
}

/// Canonical versioned signed withdrawal receipt exported for the RGB sidecar (`SHZ/WITHDRAWAL-RECEIPT/V1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalReceiptV1 {
    pub schema: String,
    pub network: String,
    pub network_id: String,
    pub router_config: String,
    pub router_id: u32,
    pub channel: ReceiptChannel,
    pub owner: String,
    pub nonce: String,
    pub amount_sats: String,
    pub destination_script: String,
    pub reserved_at_us: String,
    pub expires_us: String,
    pub clearing_sequence: String,
    pub batch_digest: String,
    pub clearing_digest: String,
    pub journal_tip: ReceiptTip,
    pub state: String,
    pub withdrawal_id: String,
    pub owner_sig: String,
    pub router_signer: String,
    pub receipt_digest: String,
    pub router_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptChannel {
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptTip {
    pub records: String,
    pub digest: String,
}

pub fn receipt_digest_bytes(
    network_name: &str,
    withdrawal_id: &Key,
    reserved_at_us: u64,
    reserved_tip: &JournalTip,
    state: WithdrawalState,
    router_signer: &Key,
) -> Key {
    let mut b = Vec::with_capacity(128 + network_name.len());
    u32b(&mut b, network_name.len() as u32);
    b.extend_from_slice(network_name.as_bytes());
    b.extend_from_slice(withdrawal_id);
    u64b(&mut b, reserved_at_us);
    u64b(&mut b, reserved_tip.records);
    b.extend_from_slice(&reserved_tip.digest);
    let st = state.as_str().as_bytes();
    u32b(&mut b, st.len() as u32);
    b.extend_from_slice(st);
    b.extend_from_slice(router_signer);
    tagged_hash(DOMAIN_WITHDRAWAL_RECEIPT, &b)
}

impl WithdrawalReceiptV1 {
    /// Builds and signs a canonical `SHZ/WITHDRAWAL-RECEIPT/V1` for a durable `WithdrawalRecord`.
    /// `network_name` MUST hash to `record.request.network` via `network_id(network_name)`.
    pub fn sign_for_record(
        record: &WithdrawalRecord,
        network_name: &str,
        router_signer_sk: &Key,
    ) -> R<Self> {
        if network_id(network_name) != record.request.network {
            return Err(Reject::Scope);
        }
        let router_signer = public(router_signer_sk);
        let digest = receipt_digest_bytes(
            network_name,
            &record.withdrawal_id,
            record.reserved_at_us,
            &record.reserved_tip,
            record.state,
            &router_signer,
        );
        let router_sig = sign(router_signer_sk, &digest)?;
        Ok(Self {
            schema: RECEIPT_SCHEMA_V1.to_string(),
            network: network_name.to_string(),
            network_id: hex::encode(record.request.network),
            router_config: hex::encode(record.request.router_config),
            router_id: record.request.router,
            channel: ReceiptChannel {
                txid: hex::encode(record.request.channel.txid),
                vout: record.request.channel.vout,
            },
            owner: hex::encode(record.request.owner),
            nonce: record.request.nonce.to_string(),
            amount_sats: record.request.amount_sats.to_string(),
            destination_script: hex::encode(&record.request.destination_script),
            reserved_at_us: record.reserved_at_us.to_string(),
            expires_us: record.request.expires_us.to_string(),
            clearing_sequence: record.request.clearing_sequence.to_string(),
            batch_digest: hex::encode(record.request.batch_digest),
            clearing_digest: hex::encode(record.request.clearing_digest),
            journal_tip: ReceiptTip {
                records: record.reserved_tip.records.to_string(),
                digest: hex::encode(record.reserved_tip.digest),
            },
            state: record.state.as_str().to_string(),
            withdrawal_id: hex::encode(record.withdrawal_id),
            owner_sig: hex::encode(record.request.owner_sig.to_bytes()),
            router_signer: hex::encode(router_signer),
            receipt_digest: hex::encode(digest),
            router_sig: hex::encode(router_sig.to_bytes()),
        })
    }

    /// Canonical sorted-key JSON with no insignificant whitespace, matching JS `canonical()`.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let v = serde_json::to_value(self)?;
        serde_json::to_string(&sort_json_value(v))
    }

    /// Independently verifies schema, network binding, owner BIP340 signature, and router BIP340 signature.
    pub fn verify(&self, expected_router_config: &Key, expected_router_signer: &Key) -> R<()> {
        if self.schema != RECEIPT_SCHEMA_V1 {
            return Err(Reject::Scope);
        }
        let net = decode_key(&self.network_id)?;
        if network_id(&self.network) != net {
            return Err(Reject::Scope);
        }
        let router_config = decode_key(&self.router_config)?;
        if router_config != *expected_router_config {
            return Err(Reject::Scope);
        }
        let router_signer = decode_key(&self.router_signer)?;
        if router_signer != *expected_router_signer {
            return Err(Reject::Signature);
        }
        let txid = decode_key(&self.channel.txid)?;
        let owner = decode_key(&self.owner)?;
        let nonce: u64 = self.nonce.parse().map_err(|_| Reject::Bounds)?;
        let amount_sats: u64 = self.amount_sats.parse().map_err(|_| Reject::Bounds)?;
        let destination_script = hex::decode(&self.destination_script).map_err(|_| Reject::Bounds)?;
        let reserved_at_us: u64 = self.reserved_at_us.parse().map_err(|_| Reject::Bounds)?;
        let expires_us: u64 = self.expires_us.parse().map_err(|_| Reject::Bounds)?;
        let clearing_sequence: u64 = self.clearing_sequence.parse().map_err(|_| Reject::Bounds)?;
        let batch_digest = decode_key(&self.batch_digest)?;
        let clearing_digest = decode_key(&self.clearing_digest)?;
        let owner_sig = decode_sig(&self.owner_sig)?;
        let req = WithdrawalRequest {
            network: net,
            router_config,
            router: self.router_id,
            channel: BtcOutPoint {
                txid,
                vout: self.channel.vout,
            },
            owner,
            nonce,
            amount_sats,
            destination_script,
            expires_us,
            clearing_sequence,
            batch_digest,
            clearing_digest,
            owner_sig,
        };
        let computed_id = req.verify_owner()?;
        if computed_id != decode_key(&self.withdrawal_id)? {
            return Err(Reject::Signature);
        }
        let state = match self.state.as_str() {
            "reserved" => WithdrawalState::Reserved,
            "submitted" => WithdrawalState::Submitted,
            "ambiguous" => WithdrawalState::Ambiguous,
            "reconciled" => WithdrawalState::Reconciled,
            "frozen_reserved" => WithdrawalState::Frozen {
                was_reconciled: false,
            },
            "frozen_reconciled" => WithdrawalState::Frozen {
                was_reconciled: true,
            },
            "cancelled" => WithdrawalState::Cancelled,
            _ => return Err(Reject::Bounds),
        };
        let tip = JournalTip {
            records: self.journal_tip.records.parse().map_err(|_| Reject::Bounds)?,
            digest: decode_key(&self.journal_tip.digest)?,
        };
        let computed_digest = receipt_digest_bytes(
            &self.network,
            &computed_id,
            reserved_at_us,
            &tip,
            state,
            &router_signer,
        );
        if computed_digest != decode_key(&self.receipt_digest)? {
            return Err(Reject::Signature);
        }
        let router_sig = decode_sig(&self.router_sig)?;
        verify(&router_signer, &computed_digest, &router_sig)?;
        Ok(())
    }
}

fn decode_key(s: &str) -> R<Key> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Reject::Bounds);
    }
    let bytes = hex::decode(s).map_err(|_| Reject::Bounds)?;
    bytes.try_into().map_err(|_| Reject::Bounds)
}

fn decode_sig(s: &str) -> R<Bip340Signature> {
    if s.len() != 128 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Reject::Signature);
    }
    let bytes = hex::decode(s).map_err(|_| Reject::Signature)?;
    Ok(Bip340Signature {
        r_x: bytes[..32].try_into().map_err(|_| Reject::Signature)?,
        s: bytes[32..].try_into().map_err(|_| Reject::Signature)?,
    })
}

fn sort_json_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (k, val) in sorted {
                out.insert(k, sort_json_value(val));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_value).collect())
        }
        other => other,
    }
}

pub fn reconcile_message(
    router_config: &Key,
    record: &WithdrawalRecord,
    btc_evidence: &Key,
    settlement_evidence: &Key,
) -> Key {
    let mut b = Vec::with_capacity(192);
    b.extend_from_slice(router_config);
    b.extend_from_slice(&record.withdrawal_id);
    put_op(&mut b, &record.request.channel);
    b.extend_from_slice(&record.request.owner);
    u64b(&mut b, record.request.nonce);
    u64b(&mut b, record.request.amount_sats);
    b.extend_from_slice(btc_evidence);
    b.extend_from_slice(settlement_evidence);
    tagged_hash(DOMAIN_WITHDRAWAL_RECONCILE, &b)
}

pub fn cancel_message(
    router_config: &Key,
    record: &WithdrawalRecord,
    cancellation_evidence: &Key,
) -> Key {
    let mut b = Vec::with_capacity(160);
    b.extend_from_slice(router_config);
    b.extend_from_slice(&record.withdrawal_id);
    put_op(&mut b, &record.request.channel);
    b.extend_from_slice(&record.request.owner);
    u64b(&mut b, record.request.nonce);
    u64b(&mut b, record.request.amount_sats);
    b.extend_from_slice(cancellation_evidence);
    tagged_hash(DOMAIN_WITHDRAWAL_CANCEL, &b)
}

pub fn freeze_message(
    router_config: &Key,
    record: &WithdrawalRecord,
    conflict_evidence: &Key,
) -> Key {
    let mut b = Vec::with_capacity(160);
    b.extend_from_slice(router_config);
    b.extend_from_slice(&record.withdrawal_id);
    put_op(&mut b, &record.request.channel);
    b.extend_from_slice(&record.request.owner);
    u64b(&mut b, record.request.nonce);
    u64b(&mut b, record.request.amount_sats);
    b.extend_from_slice(conflict_evidence);
    tagged_hash(DOMAIN_WITHDRAWAL_FREEZE, &b)
}

/// Complete withdrawal book held inside `DurableTieredRouter`'s state.
#[derive(Debug, Default)]
pub(crate) struct WithdrawalBook {
    pub records: BTreeMap<Key, WithdrawalRecord>,
    /// Highest consumed withdrawal nonce per lane outpoint (monotone, never reused even after cancel).
    pub last_nonce: BTreeMap<Outpoint, u64>,
    /// Unique external payment hashes bound to submitted/reconciled withdrawals.
    pub used_payment_hashes: BTreeSet<Key>,
    /// Unique external evidence digests (btc_evidence, settlement_evidence, cancellation_evidence, conflict_evidence).
    pub used_evidence: BTreeSet<Key>,
}

impl WithdrawalBook {
    pub fn record(&self, id: &Key) -> Option<&WithdrawalRecord> {
        self.records.get(id)
    }

    /// Verifies that the per-lane partition invariants hold against every account balance.
    pub fn check_partition(&self, channel: &Outpoint, balance: &Balance) -> bool {
        let mut expected_reserved = 0u64;
        let mut expected_withdrawn = 0u64;
        for w in self.records.values() {
            if op(&w.request.channel) != *channel {
                continue;
            }
            if w.state.holds_reserved() {
                let Some(sum) = expected_reserved.checked_add(w.request.amount_sats) else {
                    return false;
                };
                expected_reserved = sum;
            }
            if w.state.holds_withdrawn() {
                let Some(sum) = expected_withdrawn.checked_add(w.request.amount_sats) else {
                    return false;
                };
                expected_withdrawn = sum;
            }
        }
        balance.conserved()
            && balance.withdrawal_reserved == expected_reserved
            && balance.withdrawn == expected_withdrawn
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        expected_network: Key,
        expected_config: Key,
        expected_router: u32,
        req: WithdrawalRequest,
        account_owner: Key,
        mut balance: Balance,
        now: u64,
        tip: JournalTip,
    ) -> R<(Key, Balance)> {
        if req.network != expected_network
            || req.router_config != expected_config
            || req.router != expected_router
        {
            return Err(Reject::Scope);
        }
        if req.owner != account_owner {
            return Err(Reject::Allocation);
        }
        let id = req.verify_owner()?;
        if now >= req.expires_us {
            return Err(Reject::Expired);
        }
        let lane = op(&req.channel);
        let prev_nonce = self.last_nonce.get(&lane).copied().unwrap_or(0);
        if req.nonce <= prev_nonce || self.records.contains_key(&id) {
            return Err(Reject::Replay);
        }
        if balance.free < req.amount_sats {
            return Err(Reject::Capacity);
        }
        balance.free -= req.amount_sats;
        balance.withdrawal_reserved = balance
            .withdrawal_reserved
            .checked_add(req.amount_sats)
            .ok_or(Reject::Bounds)?;
        if !balance.conserved() {
            return Err(Reject::Bounds);
        }
        self.last_nonce.insert(lane, req.nonce);
        self.records.insert(
            id,
            WithdrawalRecord {
                withdrawal_id: id,
                request: req,
                state: WithdrawalState::Reserved,
                reserved_at_us: now,
                updated_at_us: now,
                reserved_tip: tip,
                payment_hash: None,
                btc_evidence: None,
                settlement_evidence: None,
                cancellation_evidence: None,
                conflict_evidence: None,
            },
        );
        Ok((id, balance))
    }

    pub fn mark_submitted(
        &mut self,
        withdrawal_id: &Key,
        payment_hash: Key,
        now: u64,
    ) -> R<()> {
        if payment_hash == [0; 32] || self.used_payment_hashes.contains(&payment_hash) {
            return Err(Reject::Replay);
        }
        let rec = self
            .records
            .get_mut(withdrawal_id)
            .ok_or(Reject::UnknownOrder)?;
        if rec.state != WithdrawalState::Reserved {
            return Err(Reject::Replay);
        }
        if now >= rec.request.expires_us {
            return Err(Reject::Expired);
        }
        self.used_payment_hashes.insert(payment_hash);
        rec.payment_hash = Some(payment_hash);
        rec.state = WithdrawalState::Submitted;
        rec.updated_at_us = now;
        Ok(())
    }

    pub fn mark_ambiguous(&mut self, withdrawal_id: &Key, now: u64) -> R<()> {
        let rec = self
            .records
            .get_mut(withdrawal_id)
            .ok_or(Reject::UnknownOrder)?;
        if rec.state != WithdrawalState::Submitted {
            return Err(Reject::Replay);
        }
        rec.state = WithdrawalState::Ambiguous;
        rec.updated_at_us = now;
        Ok(())
    }

    pub fn reconcile(
        &mut self,
        router_config: &Key,
        lanes: &BTreeMap<Outpoint, LaneState>,
        spent_fee_receipts: &BTreeSet<Key>,
        att: &WithdrawalReconcileAttestation,
        mut balance: Balance,
        now: u64,
    ) -> R<Balance> {
        let rec = self
            .records
            .get(&att.withdrawal_id)
            .ok_or(Reject::UnknownOrder)?;
        if !matches!(
            rec.state,
            WithdrawalState::Submitted | WithdrawalState::Ambiguous
        ) {
            return Err(Reject::Replay);
        }
        if att.btc_evidence == [0; 32]
            || att.settlement_evidence == [0; 32]
            || att.btc_evidence == att.settlement_evidence
            || self.used_evidence.contains(&att.btc_evidence)
            || self.used_evidence.contains(&att.settlement_evidence)
            || spent_fee_receipts.contains(&att.btc_evidence)
            || spent_fee_receipts.contains(&att.settlement_evidence)
        {
            return Err(Reject::Replay);
        }
        let lane = lanes
            .get(&op(&rec.request.channel))
            .ok_or(Reject::Allocation)?;
        let msg = reconcile_message(
            router_config,
            rec,
            &att.btc_evidence,
            &att.settlement_evidence,
        );
        verify(&lane.peer, &msg, &att.signatures[0])?;
        verify(&lane.monitor, &msg, &att.signatures[1])?;

        let amount = rec.request.amount_sats;
        balance.withdrawal_reserved = balance
            .withdrawal_reserved
            .checked_sub(amount)
            .ok_or(Reject::Capacity)?;
        balance.withdrawn = balance.withdrawn.checked_add(amount).ok_or(Reject::Bounds)?;
        if !balance.conserved() {
            return Err(Reject::Bounds);
        }

        self.used_evidence.insert(att.btc_evidence);
        self.used_evidence.insert(att.settlement_evidence);
        let rec = self.records.get_mut(&att.withdrawal_id).unwrap();
        rec.state = WithdrawalState::Reconciled;
        rec.btc_evidence = Some(att.btc_evidence);
        rec.settlement_evidence = Some(att.settlement_evidence);
        rec.updated_at_us = now;
        Ok(balance)
    }

    pub fn freeze(
        &mut self,
        router_config: &Key,
        lanes: &BTreeMap<Outpoint, LaneState>,
        att: &WithdrawalFreezeAttestation,
        now: u64,
    ) -> R<WithdrawalState> {
        let rec = self
            .records
            .get(&att.withdrawal_id)
            .ok_or(Reject::UnknownOrder)?;
        let was_reconciled = match rec.state {
            WithdrawalState::Submitted | WithdrawalState::Ambiguous => false,
            WithdrawalState::Reconciled => true,
            _ => return Err(Reject::Replay),
        };
        if att.conflict_evidence == [0; 32] || self.used_evidence.contains(&att.conflict_evidence) {
            return Err(Reject::Replay);
        }
        let lane = lanes
            .get(&op(&rec.request.channel))
            .ok_or(Reject::Allocation)?;
        let msg = freeze_message(router_config, rec, &att.conflict_evidence);
        verify(&lane.monitor, &msg, &att.monitor_sig)?;

        self.used_evidence.insert(att.conflict_evidence);
        let next_state = WithdrawalState::Frozen { was_reconciled };
        let rec = self.records.get_mut(&att.withdrawal_id).unwrap();
        rec.state = next_state;
        rec.conflict_evidence = Some(att.conflict_evidence);
        rec.updated_at_us = now;
        Ok(next_state)
    }

    pub fn cancel(
        &mut self,
        router_config: &Key,
        lanes: &BTreeMap<Outpoint, LaneState>,
        att: &WithdrawalCancelAttestation,
        mut balance: Balance,
        now: u64,
    ) -> R<Balance> {
        let rec = self
            .records
            .get(&att.withdrawal_id)
            .ok_or(Reject::UnknownOrder)?;
        if !matches!(
            rec.state,
            WithdrawalState::Reserved | WithdrawalState::Submitted | WithdrawalState::Ambiguous
        ) {
            return Err(Reject::Replay);
        }
        if att.cancellation_evidence == [0; 32]
            || self.used_evidence.contains(&att.cancellation_evidence)
        {
            return Err(Reject::Replay);
        }
        let lane = lanes
            .get(&op(&rec.request.channel))
            .ok_or(Reject::Allocation)?;
        let msg = cancel_message(router_config, rec, &att.cancellation_evidence);
        // Monitor signature is ALWAYS required to prove safe non-dispatch / irrevocable cancellation.
        verify(&lane.monitor, &msg, &att.signatures[2])?;
        let owner_present = att.signatures[0] != ZERO_SIG;
        let peer_present = att.signatures[1] != ZERO_SIG;
        if owner_present {
            verify(&rec.request.owner, &msg, &att.signatures[0])?;
        }
        if peer_present {
            verify(&lane.peer, &msg, &att.signatures[1])?;
        }
        match rec.state {
            WithdrawalState::Reserved => {
                // Before dispatch: either owner+monitor, or peer+monitor once expired.
                let ok = owner_present || (peer_present && now >= rec.request.expires_us);
                if !ok {
                    return Err(Reject::Signature);
                }
            }
            WithdrawalState::Submitted | WithdrawalState::Ambiguous => {
                // Once submitted/ambiguous, independent peer + monitor evidence is mandatory;
                // timeout or owner signature alone can never release funds.
                if !peer_present {
                    return Err(Reject::Signature);
                }
            }
            _ => unreachable!(),
        }

        let amount = rec.request.amount_sats;
        balance.withdrawal_reserved = balance
            .withdrawal_reserved
            .checked_sub(amount)
            .ok_or(Reject::Capacity)?;
        balance.free = balance.free.checked_add(amount).ok_or(Reject::Bounds)?;
        if !balance.conserved() {
            return Err(Reject::Bounds);
        }

        self.used_evidence.insert(att.cancellation_evidence);
        let rec = self.records.get_mut(&att.withdrawal_id).unwrap();
        rec.state = WithdrawalState::Cancelled;
        rec.cancellation_evidence = Some(att.cancellation_evidence);
        rec.updated_at_us = now;
        Ok(balance)
    }
}
