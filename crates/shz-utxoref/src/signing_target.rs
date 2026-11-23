//! `UTXORef`-compatible BIP-341 Taproot DLC funding output, canonical CET/Refund
//! parser (with mandatory 330-sat CPFP anchor check), `TapSighash` script-path
//! derivation, and `TradeLayer/dlc/oracle/announcement/v1` verification.
//!
//! Verified byte-for-byte against `UTXO-Ref/native/dlc-signer/tests/signing_target_vectors.json`.

use k256::{
    AffinePoint, FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{bigint::U256, ff::PrimeField, group::Group, ops::Reduce, sec1::ToEncodedPoint},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dlc::{lift_x_even, tagged_hash};

use crate::UtxoRefError;

pub const UTXOREF_NUMS_DOMAIN: &str = "UTXORef DLC funding NUMS internal key v1";
pub const LEAF_VERSION_TAPSCRIPT: u8 = 0xc0;
pub const DEFAULT_CPFP_ANCHOR_SATS: u64 = 330;
pub const MAX_RAW_TX_BYTES: usize = 100_000;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn reduce_be_bytes(bytes: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes))
}

/// Returns `(x_bytes, y_bytes)` for a non-identity secp256k1 point.
pub fn point_coordinates(point: ProjectivePoint) -> Result<([u8; 32], [u8; 32]), UtxoRefError> {
    if bool::from(point.is_identity()) {
        return Err(UtxoRefError::InvalidCrypto("point at infinity"));
    }
    let encoded = AffinePoint::from(point).to_encoded_point(false);
    let x: [u8; 32] = encoded
        .x()
        .ok_or(UtxoRefError::InvalidCrypto("missing x"))?[..]
        .try_into()
        .map_err(|_| UtxoRefError::InvalidCrypto("malformed x"))?;
    let y: [u8; 32] = encoded
        .y()
        .ok_or(UtxoRefError::InvalidCrypto("missing y"))?[..]
        .try_into()
        .map_err(|_| UtxoRefError::InvalidCrypto("malformed y"))?;
    Ok((x, y))
}

fn compact_size(value: usize) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(value as u32).to_le_bytes());
            out
        }
    }
}

fn push_script_num(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    if value <= 16 {
        return vec![0x50 + value as u8];
    }
    let mut bytes = Vec::new();
    let mut rem = value;
    while rem > 0 {
        bytes.push((rem & 0xff) as u8);
        rem >>= 8;
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(0);
    }
    let mut script = vec![bytes.len() as u8];
    script.extend(bytes);
    script
}

fn sorted_two_of_two_tapscript(first: &[u8; 32], second: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(68);
    script.push(0x20);
    script.extend_from_slice(first);
    script.extend_from_slice(&[0xad, 0x20]); // OP_CHECKSIGVERIFY <32B>
    script.extend_from_slice(second);
    script.push(0xac); // OP_CHECKSIG
    script
}

pub fn tap_leaf_hash(script: &[u8]) -> [u8; 32] {
    let mut payload = vec![LEAF_VERSION_TAPSCRIPT];
    payload.extend(compact_size(script.len()));
    payload.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &payload)
}

pub fn tap_branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    if left <= right {
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
    } else {
        buf[..32].copy_from_slice(right);
        buf[32..].copy_from_slice(left);
    }
    tagged_hash(b"TapBranch", &buf)
}

/// Deterministically derives the unspendable NUMS internal x-only public key used by `UTXORef`.
pub fn utxoref_nums_internal_key() -> Result<[u8; 32], UtxoRefError> {
    for counter in 0..1024u32 {
        let candidate = sha256(format!("{UTXOREF_NUMS_DOMAIN}:{counter}").as_bytes());
        if lift_x_even(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(UtxoRefError::InvalidCrypto("NUMS key derivation exhausted"))
}

/// Exact `UTXORef` two-leaf P2TR DLC funding output (`cet_leaf` + `csv_refund_leaf` under NUMS key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoRefFundingOutput {
    pub internal_xonly: [u8; 32],
    pub party_pubkeys_sorted: [[u8; 32]; 2],
    pub refund_csv_blocks: u16,
    pub cet_leaf_hash: [u8; 32],
    pub refund_leaf_hash: [u8; 32],
    pub tap_merkle_root: [u8; 32],
    pub script_pubkey: Vec<u8>,
}

pub fn derive_utxoref_funding_output(
    party_a: [u8; 32],
    party_b: [u8; 32],
    refund_csv_blocks: u16,
) -> Result<UtxoRefFundingOutput, UtxoRefError> {
    if party_a == party_b {
        return Err(UtxoRefError::InvalidFunding(
            "party x-only pubkeys must be distinct",
        ));
    }
    if refund_csv_blocks == 0 {
        return Err(UtxoRefError::InvalidFunding("refund_csv_blocks must be >= 1"));
    }
    lift_x_even(&party_a).map_err(|_| UtxoRefError::InvalidFunding("invalid party_a x-only key"))?;
    lift_x_even(&party_b).map_err(|_| UtxoRefError::InvalidFunding("invalid party_b x-only key"))?;

    let sorted = if party_a < party_b {
        [party_a, party_b]
    } else {
        [party_b, party_a]
    };

    let internal_xonly = utxoref_nums_internal_key()?;
    if sorted.contains(&internal_xonly) {
        return Err(UtxoRefError::InvalidFunding(
            "party key must not equal NUMS internal key",
        ));
    }

    let cet_script = sorted_two_of_two_tapscript(&sorted[0], &sorted[1]);
    let mut refund_script = push_script_num(refund_csv_blocks as u64);
    refund_script.extend_from_slice(&[0xb2, 0x75]); // OP_CHECKSEQUENCEVERIFY OP_DROP
    refund_script.extend(sorted_two_of_two_tapscript(&sorted[0], &sorted[1]));

    let cet_leaf_hash = tap_leaf_hash(&cet_script);
    let refund_leaf_hash = tap_leaf_hash(&refund_script);
    let tap_merkle_root = tap_branch_hash(&cet_leaf_hash, &refund_leaf_hash);

    let mut tweak_input = [0u8; 64];
    tweak_input[..32].copy_from_slice(&internal_xonly);
    tweak_input[32..].copy_from_slice(&tap_merkle_root);
    let tweak = reduce_be_bytes(tagged_hash(b"TapTweak", &tweak_input));

    let internal_point =
        lift_x_even(&internal_xonly).map_err(|_| UtxoRefError::InvalidCrypto("NUMS lift_x"))?;
    let (output_x, _) = point_coordinates(internal_point + ProjectivePoint::GENERATOR * tweak)?;

    let mut script_pubkey = Vec::with_capacity(34);
    script_pubkey.push(0x51); // OP_1
    script_pubkey.push(0x20); // 32 bytes
    script_pubkey.extend_from_slice(&output_x);

    Ok(UtxoRefFundingOutput {
        internal_xonly,
        party_pubkeys_sorted: sorted,
        refund_csv_blocks,
        cet_leaf_hash,
        refund_leaf_hash,
        tap_merkle_root,
        script_pubkey,
    })
}

/// Canonical single-input unsigned Bitcoin CET or Refund transaction (`version` 2 or TRUC 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedDlcTx {
    pub version: u32,
    pub input_outpoint: [u8; 36],
    pub input_sequence: u32,
    pub outputs: Vec<(u64, Vec<u8>)>,
    pub locktime: u32,
    pub txid_hex: String,
}

impl UnsignedDlcTx {
    pub fn serialize(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(128);
        raw.extend_from_slice(&self.version.to_le_bytes());
        raw.push(0x01); // 1 input
        raw.extend_from_slice(&self.input_outpoint);
        raw.push(0x00); // empty scriptSig
        raw.extend_from_slice(&self.input_sequence.to_le_bytes());
        raw.extend(compact_size(self.outputs.len()));
        for (val, spk) in &self.outputs {
            raw.extend_from_slice(&val.to_le_bytes());
            raw.extend(compact_size(spk.len()));
            raw.extend_from_slice(spk);
        }
        raw.extend_from_slice(&self.locktime.to_le_bytes());
        raw
    }

    pub fn parse_canonical(raw: &[u8]) -> Result<Self, UtxoRefError> {
        if raw.is_empty() || raw.len() > MAX_RAW_TX_BYTES {
            return Err(UtxoRefError::InvalidTransaction("tx size out of bounds"));
        }
        let mut off = 0usize;
        let take = |off: &mut usize, n: usize| -> Result<&[u8], UtxoRefError> {
            if raw.len().saturating_sub(*off) < n {
                return Err(UtxoRefError::InvalidTransaction("truncated raw tx"));
            }
            let s = &raw[*off..*off + n];
            *off += n;
            Ok(s)
        };
        let read_compact = |off: &mut usize| -> Result<usize, UtxoRefError> {
            let p = take(off, 1)?[0];
            let v = match p {
                0..=0xfc => p as u64,
                0xfd => {
                    let x = u16::from_le_bytes(take(off, 2)?.try_into().unwrap()) as u64;
                    if x < 0xfd {
                        return Err(UtxoRefError::InvalidTransaction("non-canonical CompactSize"));
                    }
                    x
                }
                0xfe => {
                    let x = u32::from_le_bytes(take(off, 4)?.try_into().unwrap()) as u64;
                    if x <= 0xffff {
                        return Err(UtxoRefError::InvalidTransaction("non-canonical CompactSize"));
                    }
                    x
                }
                _ => return Err(UtxoRefError::InvalidTransaction("CompactSize too large")),
            };
            if v > MAX_RAW_TX_BYTES as u64 {
                return Err(UtxoRefError::InvalidTransaction("CompactSize exceeds tx max"));
            }
            Ok(v as usize)
        };

        let version = u32::from_le_bytes(take(&mut off, 4)?.try_into().unwrap());
        if version != 2 && version != 3 {
            return Err(UtxoRefError::InvalidTransaction("version must be 2 or 3"));
        }
        if read_compact(&mut off)? != 1 {
            return Err(UtxoRefError::InvalidTransaction(
                "DLC CET/Refund must spend exactly 1 funding input",
            ));
        }
        let input_outpoint: [u8; 36] = take(&mut off, 36)?.try_into().unwrap();
        if read_compact(&mut off)? != 0 {
            return Err(UtxoRefError::InvalidTransaction("scriptSig must be empty"));
        }
        let input_sequence = u32::from_le_bytes(take(&mut off, 4)?.try_into().unwrap());
        let out_count = read_compact(&mut off)?;
        if !(1..=1000).contains(&out_count) {
            return Err(UtxoRefError::InvalidTransaction("outputs must be in 1..=1000"));
        }
        let mut outputs = Vec::with_capacity(out_count);
        for _ in 0..out_count {
            let value = u64::from_le_bytes(take(&mut off, 8)?.try_into().unwrap());
            let spk_len = read_compact(&mut off)?;
            if spk_len < 2 {
                return Err(UtxoRefError::InvalidTransaction("output script < 2 bytes"));
            }
            let spk = take(&mut off, spk_len)?.to_vec();
            outputs.push((value, spk));
        }
        let locktime = u32::from_le_bytes(take(&mut off, 4)?.try_into().unwrap());
        if off != raw.len() {
            return Err(UtxoRefError::InvalidTransaction("trailing bytes in raw tx"));
        }

        let mut txid = sha256(&sha256(raw));
        txid.reverse();
        Ok(Self {
            version,
            input_outpoint,
            input_sequence,
            outputs,
            locktime,
            txid_hex: hex::encode(txid),
        })
    }

    /// Enforces `DLC_SECURITY_ARCHITECTURE_REVIEW.md` #18: the final output of every CET
    /// and Refund must be the committed CPFP anchor output (e.g. 330 sats).
    pub fn verify_cpfp_anchor(
        &self,
        expected_anchor_sats: u64,
        expected_anchor_spk: &[u8],
    ) -> Result<(), UtxoRefError> {
        let (last_val, last_spk) = self
            .outputs
            .last()
            .ok_or(UtxoRefError::InvalidTransaction("missing outputs"))?;
        if *last_val != expected_anchor_sats || last_spk.as_slice() != expected_anchor_spk {
            return Err(UtxoRefError::MissingCommittedAnchor);
        }
        Ok(())
    }

    /// Computes BIP-341 script-path `TapSighash` (`SIGHASH_DEFAULT` = `0x00`) for single-input spend.
    pub fn bip341_script_path_sighash(
        &self,
        funding_value_sats: u64,
        funding_script_pubkey: &[u8],
        tapleaf_hash: &[u8; 32],
    ) -> Result<[u8; 32], UtxoRefError> {
        if funding_script_pubkey.len() != 34 {
            return Err(UtxoRefError::InvalidFunding(
                "funding P2TR scriptPubKey must be 34 bytes",
            ));
        }
        let sha_prevouts = sha256(&self.input_outpoint);
        let sha_amounts = sha256(&funding_value_sats.to_le_bytes());
        let mut spk_ser = compact_size(funding_script_pubkey.len());
        spk_ser.extend_from_slice(funding_script_pubkey);
        let sha_script_pubkeys = sha256(&spk_ser);
        let sha_sequences = sha256(&self.input_sequence.to_le_bytes());

        let mut outs_ser = Vec::new();
        for (value, script) in &self.outputs {
            outs_ser.extend_from_slice(&value.to_le_bytes());
            outs_ser.extend(compact_size(script.len()));
            outs_ser.extend_from_slice(script);
        }
        let sha_outputs = sha256(&outs_ser);

        let mut preimage = Vec::with_capacity(210);
        preimage.extend_from_slice(&[0x00, 0x00]); // epoch 0, SIGHASH_DEFAULT
        preimage.extend_from_slice(&self.version.to_le_bytes());
        preimage.extend_from_slice(&self.locktime.to_le_bytes());
        preimage.extend_from_slice(&sha_prevouts);
        preimage.extend_from_slice(&sha_amounts);
        preimage.extend_from_slice(&sha_script_pubkeys);
        preimage.extend_from_slice(&sha_sequences);
        preimage.extend_from_slice(&sha_outputs);
        preimage.push(0x02); // spend_type = ext_flag (1) * 2 + annex_present (0)
        preimage.extend_from_slice(&0u32.to_le_bytes()); // input_index = 0
        preimage.extend_from_slice(tapleaf_hash);
        preimage.push(0x00); // key_version = 0
        preimage.extend_from_slice(&[0xff; 4]); // codesep_pos = 0xffffffff
        Ok(tagged_hash(b"TapSighash", &preimage))
    }
}

/// Authenticated `tradelayer_dlc_oracle_announcement_v1` envelope compatible with `UTXORef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoRefOracleAnnouncementV1 {
    pub event_id: String,
    pub px: [u8; 32],
    pub rx: [u8; 32],
    pub outcome_messages: Vec<[u8; 32]>,
    pub signature: [u8; 64],
}

fn be_u16_prefixed(bytes: &[u8]) -> Result<Vec<u8>, UtxoRefError> {
    let len = u16::try_from(bytes.len())
        .map_err(|_| UtxoRefError::InvalidAnnouncement("field > 65535 bytes"))?;
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

impl UtxoRefOracleAnnouncementV1 {
    pub fn announcement_digest(&self) -> Result<[u8; 32], UtxoRefError> {
        if self.event_id.is_empty() || self.outcome_messages.is_empty() {
            return Err(UtxoRefError::InvalidAnnouncement("empty event or outcomes"));
        }
        let mut msg = be_u16_prefixed(self.event_id.as_bytes())?;
        msg.extend_from_slice(&self.px);
        msg.extend_from_slice(&self.rx);
        let mut seen = Vec::with_capacity(self.outcome_messages.len());
        for om in &self.outcome_messages {
            if seen.contains(om) {
                return Err(UtxoRefError::InvalidAnnouncement("duplicate outcome digest"));
            }
            msg.extend(be_u16_prefixed(om)?);
            seen.push(*om);
        }
        Ok(tagged_hash(b"TradeLayer/dlc/oracle/announcement/v1", &msg))
    }

    pub fn verify(&self) -> Result<(), UtxoRefError> {
        let digest = self.announcement_digest()?;
        let Ok(pub_pt) = lift_x_even(&self.px) else {
            return Err(UtxoRefError::InvalidAnnouncement("invalid oracle px"));
        };
        let r_x: [u8; 32] = self.signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = self.signature[32..].try_into().unwrap();
        let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(s_bytes))) else {
            return Err(UtxoRefError::InvalidAnnouncement("non-canonical sig scalar"));
        };
        let mut ch_buf = [0u8; 96];
        ch_buf[..32].copy_from_slice(&r_x);
        ch_buf[32..64].copy_from_slice(&self.px);
        ch_buf[64..].copy_from_slice(&digest);
        let e = reduce_be_bytes(tagged_hash(b"BIP0340/challenge", &ch_buf));
        let check = ProjectivePoint::GENERATOR * s - pub_pt * e;
        let (cx, cy) = point_coordinates(check)?;
        if (cy[31] & 1) != 0 || cx != r_x {
            return Err(UtxoRefError::InvalidAnnouncement(
                "announcement BIP340 signature failed",
            ));
        }
        Ok(())
    }

    pub fn outcome_point(&self, outcome: &[u8; 32]) -> Result<ProjectivePoint, UtxoRefError> {
        self.verify()?;
        if !self.outcome_messages.contains(outcome) {
            return Err(UtxoRefError::InvalidAnnouncement(
                "outcome not committed in announcement",
            ));
        }
        let mut ch_buf = [0u8; 96];
        ch_buf[..32].copy_from_slice(&self.rx);
        ch_buf[32..64].copy_from_slice(&self.px);
        ch_buf[64..].copy_from_slice(outcome);
        let e = reduce_be_bytes(tagged_hash(b"BIP0340/challenge", &ch_buf));
        let r_pt =
            lift_x_even(&self.rx).map_err(|_| UtxoRefError::InvalidAnnouncement("invalid rx"))?;
        let p_pt =
            lift_x_even(&self.px).map_err(|_| UtxoRefError::InvalidAnnouncement("invalid px"))?;
        Ok(r_pt + p_pt * e)
    }
}

/// Sums verified `UTXORef` threshold-oracle subset outcome points into a single adaptor point.
pub fn aggregate_subset_adaptor_point(
    announcements: &[UtxoRefOracleAnnouncementV1],
    selected_pubkeys: &[[u8; 32]],
    outcome: &[u8; 32],
) -> Result<ProjectivePoint, UtxoRefError> {
    if selected_pubkeys.is_empty() {
        return Err(UtxoRefError::InvalidAnnouncement("empty oracle subset"));
    }
    let mut sum = ProjectivePoint::IDENTITY;
    for pk in selected_pubkeys {
        let ann = announcements
            .iter()
            .find(|a| &a.px == pk)
            .ok_or(UtxoRefError::InvalidAnnouncement(
                "selected oracle missing from announcements",
            ))?;
        sum += ann.outcome_point(outcome)?;
    }
    if bool::from(sum.is_identity()) {
        return Err(UtxoRefError::InvalidCrypto("sum adaptor point at infinity"));
    }
    Ok(sum)
}
