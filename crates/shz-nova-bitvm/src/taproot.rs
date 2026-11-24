//! `UTXORef` BIP-341 NUMS P2TR 2-party DLC funding script derivation.
//!
//! Ported from MIT `lnm-batch-statement` (`patrickdugan/zk-rusto-no-bitcoino` @ `f6a8d12`).

use k256::elliptic_curve::{
    PrimeField,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

use crate::error::{NovaBitvmError, Result};
use crate::statement::{Hash, Script, sha256};

fn bip_tagged(tag: &str, bytes: &[u8]) -> Hash {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(bytes);
    h.finalize().into()
}

fn lift_x(x: &Hash) -> Result<AffinePoint> {
    let mut bytes = [0; 33];
    bytes[0] = 2;
    bytes[1..].copy_from_slice(x);
    let encoded = EncodedPoint::from_bytes(bytes)
        .map_err(|_| NovaBitvmError::Taproot("invalid compressed point".to_owned()))?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| NovaBitvmError::Taproot("invalid x-only curve point".to_owned()))
}

fn nums_key() -> Result<Hash> {
    // Same construction as UTXO-Ref/dlc_funding_output.js. Every candidate is
    // SHA256 of a public fixed string; no private scalar is chosen here.
    for counter in 0..1024 {
        let x = sha256(format!("UTXORef DLC funding NUMS internal key v1:{counter}").as_bytes());
        if lift_x(&x).is_ok() {
            return Ok(x);
        }
    }
    Err(NovaBitvmError::Taproot(
        "could not derive the pinned NUMS point".to_owned(),
    ))
}

fn script_num(value: u16) -> Vec<u8> {
    if value <= 16 {
        return vec![0x50 + value as u8];
    }
    let mut remaining = value;
    let mut bytes = Vec::new();
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        bytes.push(0);
    }
    let mut result = vec![bytes.len() as u8];
    result.extend(bytes);
    result
}

fn tapleaf(script: &[u8]) -> Hash {
    // Both fixed templates are under 253 bytes, so 1-byte CompactSize is canonical.
    let mut bytes = vec![0xc0, script.len() as u8];
    bytes.extend_from_slice(script);
    bip_tagged("TapLeaf", &bytes)
}

/// Full BIP-341 script-path spend material for the canonical two-party `UTXORef` NUMS P2TR
/// funding output (`cet` 2-of-2 leaf + `refund` CSV 2-of-2 leaf).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingTaprootSpendInfo {
    pub funding_script: Script,
    pub sorted_party_keys: [Hash; 2],
    pub cet_script: Vec<u8>,
    pub cet_leaf_hash: Hash,
    pub cet_control_block: Vec<u8>,
    pub refund_script: Vec<u8>,
    pub refund_leaf_hash: Hash,
    pub refund_control_block: Vec<u8>,
}

/// Derives both the 34-byte `P2TR` `funding_script` and the BIP-341 script-path control blocks
/// required to spend a `UTXORef` / `LNMBAT01` 2-party DLC funding UTXO on Bitcoin Core.
pub fn derive_funding_taproot_spend_info(
    first: &Hash,
    second: &Hash,
    refund_csv: u16,
) -> Result<FundingTaprootSpendInfo> {
    if first == second || refund_csv == 0 {
        return Err(NovaBitvmError::Taproot(
            "two distinct keys and positive CSV are required".to_owned(),
        ));
    }
    lift_x(first)?;
    lift_x(second)?;
    let internal = nums_key()?;
    if *first == internal || *second == internal {
        return Err(NovaBitvmError::Taproot(
            "party key cannot be the NUMS internal key".to_owned(),
        ));
    }
    let (a, b) = if first < second {
        (*first, *second)
    } else {
        (*second, *first)
    };
    let mut cet = vec![0x20];
    cet.extend_from_slice(&a);
    cet.extend_from_slice(&[0xad, 0x20]);
    cet.extend_from_slice(&b);
    cet.push(0xac);
    let mut refund = script_num(refund_csv);
    refund.extend_from_slice(&[0xb2, 0x75]);
    refund.extend_from_slice(&cet);
    let left = tapleaf(&cet);
    let right = tapleaf(&refund);
    let mut branch = Vec::with_capacity(64);
    if left < right {
        branch.extend_from_slice(&left);
        branch.extend_from_slice(&right);
    } else {
        branch.extend_from_slice(&right);
        branch.extend_from_slice(&left);
    }
    let root = bip_tagged("TapBranch", &branch);
    let mut tweak_input = Vec::with_capacity(64);
    tweak_input.extend_from_slice(&internal);
    tweak_input.extend_from_slice(&root);
    let tweak_bytes: FieldBytes = bip_tagged("TapTweak", &tweak_input).into();
    let tweak = Option::<Scalar>::from(Scalar::from_repr(tweak_bytes)).ok_or_else(|| {
        NovaBitvmError::Taproot("Taproot tweak is outside the scalar field".to_owned())
    })?;
    let output = ProjectivePoint::from(lift_x(&internal)?) + ProjectivePoint::GENERATOR * tweak;
    if output == ProjectivePoint::IDENTITY {
        return Err(NovaBitvmError::Taproot(
            "Taproot output point is infinity".to_owned(),
        ));
    }
    let encoded = output.to_affine().to_encoded_point(true);
    let encoded_bytes = encoded.as_bytes();
    let parity_bit = u8::from(encoded_bytes.first().copied() == Some(0x03));
    let x = encoded
        .x()
        .ok_or_else(|| NovaBitvmError::Taproot("missing Taproot x coordinate".to_owned()))?;
    let mut script = [0; 34];
    script[..2].copy_from_slice(&[0x51, 0x20]);
    script[2..].copy_from_slice(x);

    let mut cet_control_block = Vec::with_capacity(65);
    cet_control_block.push(0xc0 | parity_bit);
    cet_control_block.extend_from_slice(&internal);
    cet_control_block.extend_from_slice(&right);

    let mut refund_control_block = Vec::with_capacity(65);
    refund_control_block.push(0xc0 | parity_bit);
    refund_control_block.extend_from_slice(&internal);
    refund_control_block.extend_from_slice(&left);

    Ok(FundingTaprootSpendInfo {
        funding_script: script,
        sorted_party_keys: [a, b],
        cet_script: cet,
        cet_leaf_hash: left,
        cet_control_block,
        refund_script: refund,
        refund_leaf_hash: right,
        refund_control_block,
    })
}

/// Derives the canonical 34-byte P2TR (`0x51 0x20 <x>`) two-party NUMS funding script
/// matching `UTXO-Ref` and `lnm-batch-statement`.
pub fn derive_funding_script(first: &Hash, second: &Hash, refund_csv: u16) -> Result<Script> {
    Ok(derive_funding_taproot_spend_info(first, second, refund_csv)?.funding_script)
}
