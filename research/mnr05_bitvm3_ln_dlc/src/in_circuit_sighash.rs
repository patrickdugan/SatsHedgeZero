//! `Track 4 / Milestone M5`: Constrained In-Circuit `BIP-341 TapSighash` Reconstruction Gadget.
//!
//! Eliminates any external sighash-to-transaction cross-check gap by proving inside R1CS
//! (`BnScalar` over `nova-snark` gadgets) that a 32-byte `TapSighash` digest `m` equals the exact
//! BIP-341 tagged hash `SHA256(SHA256("TapSighash") || SHA256("TapSighash") || SigMsg)` derived
//! directly from the `348`-byte stripped 3-input, 5-output clearing transaction wire bits, the
//! spent prevout values/P2TR scripts, and the `TapLeaf` hash for all 3 modes (`0x83`, `0x01`, `0x00`)!
#![forbid(unsafe_code)]

use ff::Field;
use halo2curves::bn256::Fr as BnScalar;
use nova_snark::frontend::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        sha256::sha256,
    },
    ConstraintSystem, SynthesisError,
};
use sha2::{Digest, Sha256};

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn constant_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|v| (0..8).rev().map(move |j| Boolean::constant((v >> j) & 1 != 0)))
        .collect()
}

fn alloc_bytes_bits<CS: ConstraintSystem<BnScalar>>(
    mut cs: CS,
    bytes: &[u8],
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for (i, b) in bytes.iter().enumerate() {
        for j in (0..8).rev() {
            out.push(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("b{i}_{j}")),
                Some((b >> j) & 1 != 0),
            )?));
        }
    }
    Ok(out)
}

fn enforce_bits_eq<CS: ConstraintSystem<BnScalar>>(
    mut cs: CS,
    a: &[Boolean],
    b: &[Boolean],
) {
    assert_eq!(a.len(), b.len());
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        cs.enforce(
            || format!("bit_eq_{i}"),
            |_| x.lc(CS::one(), BnScalar::ONE) - &y.lc(CS::one(), BnScalar::ONE),
            |lc| lc + CS::one(),
            |lc| lc,
        );
    }
}

/// Synthesizes and constrains in R1CS the exact `BIP-341` script-path `TapSighash` (`ext_flag = 1`)
/// for input `input_index` (`0..3`) and `hash_type` (`0x00`, `0x01`, or `0x83`) directly from the
/// `348`-byte stripped transaction wire bits (`2,784` bits)!
#[allow(clippy::too_many_arguments)]
pub fn synthesize_and_bind_bip341_tapsighash<CS: ConstraintSystem<BnScalar>>(
    mut cs: CS,
    tx_bits_348b: &[Boolean],
    prevout_amounts_sats: &[u64; 3],
    prevout_spks_34b: &[[u8; 34]; 3],
    input_index: usize,
    hash_type: u8,
    tapleaf_hash: &[u8; 32],
    claimed_sighash32: &[u8; 32],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_eq!(tx_bits_348b.len(), 348 * 8);
    assert!(input_index < 3);
    assert!(matches!(hash_type, 0x00 | 0x01 | 0x83));

    let anyone_can_pay = (hash_type & 0x80) == 0x80;
    let base_type = if hash_type == 0x00 { 0x01 } else { hash_type & 0x03 };

    // Byte slices in our 348-byte 3-input, 5-output stripped transaction:
    // version:  `0..4`
    // vin[0]:   outpoint `5..41`, seq `42..46`
    // vin[1]:   outpoint `46..82`, seq `83..87`
    // vin[2]:   outpoint `87..123`, seq `124..128`
    // vout[0..5] (43B each = 8B amt + 1B len 0x22 + 34B P2TR): `129..344`
    // locktime: `344..348`
    let slice_bytes = |start: usize, end: usize| -> &[Boolean] {
        &tx_bits_348b[start * 8..end * 8]
    };

    let amt_bits: [Vec<Boolean>; 3] = [
        alloc_bytes_bits(cs.namespace(|| "amt0"), &prevout_amounts_sats[0].to_le_bytes())?,
        alloc_bytes_bits(cs.namespace(|| "amt1"), &prevout_amounts_sats[1].to_le_bytes())?,
        alloc_bytes_bits(cs.namespace(|| "amt2"), &prevout_amounts_sats[2].to_le_bytes())?,
    ];
    let spk_bits: [Vec<Boolean>; 3] = [
        alloc_bytes_bits(cs.namespace(|| "spk0"), &prevout_spks_34b[0])?,
        alloc_bytes_bits(cs.namespace(|| "spk1"), &prevout_spks_34b[1])?,
        alloc_bytes_bits(cs.namespace(|| "spk2"), &prevout_spks_34b[2])?,
    ];
    let tapleaf_bits = alloc_bytes_bits(cs.namespace(|| "tapleaf"), tapleaf_hash)?;
    let claimed_sh_bits = alloc_bytes_bits(cs.namespace(|| "claimed_sh"), claimed_sighash32)?;

    let tag_hash = sha256_bytes(b"TapSighash");
    let mut preimage = constant_bits(&tag_hash);
    preimage.extend(constant_bits(&tag_hash));
    preimage.extend(constant_bits(&[0x00, hash_type])); // epoch 0 || hash_type
    preimage.extend_from_slice(slice_bytes(0, 4)); // version (4B)
    preimage.extend_from_slice(slice_bytes(344, 348)); // locktime (4B)

    let outp_ranges = [(5usize, 41usize), (46, 82), (87, 123)];
    let seq_ranges = [(42usize, 46usize), (83, 87), (124, 128)];

    if !anyone_can_pay {
        let mut prevouts = Vec::with_capacity(108 * 8);
        let mut amounts = Vec::with_capacity(24 * 8);
        let mut spks = Vec::with_capacity(105 * 8);
        let mut seqs = Vec::with_capacity(12 * 8);
        for k in 0..3 {
            prevouts.extend_from_slice(slice_bytes(outp_ranges[k].0, outp_ranges[k].1));
            amounts.extend(amt_bits[k].iter().cloned());
            spks.extend(constant_bits(&[34u8])); // CompactSize(34) == 0x22
            spks.extend(spk_bits[k].iter().cloned());
            seqs.extend_from_slice(slice_bytes(seq_ranges[k].0, seq_ranges[k].1));
        }
        preimage.extend(sha256(cs.namespace(|| "sha_prevouts"), &prevouts)?);
        preimage.extend(sha256(cs.namespace(|| "sha_amounts"), &amounts)?);
        preimage.extend(sha256(cs.namespace(|| "sha_spks"), &spks)?);
        preimage.extend(sha256(cs.namespace(|| "sha_seqs"), &seqs)?);
    }

    if base_type == 0x01 {
        let outs_bits = slice_bytes(129, 344);
        preimage.extend(sha256(cs.namespace(|| "sha_outputs"), outs_bits)?);
    }

    preimage.extend(constant_bits(&[0x02])); // spend_type = ext_flag (1) * 2

    if anyone_can_pay {
        preimage.extend_from_slice(slice_bytes(
            outp_ranges[input_index].0,
            outp_ranges[input_index].1,
        ));
        preimage.extend(amt_bits[input_index].iter().cloned());
        preimage.extend(constant_bits(&[34u8]));
        preimage.extend(spk_bits[input_index].iter().cloned());
        preimage.extend_from_slice(slice_bytes(
            seq_ranges[input_index].0,
            seq_ranges[input_index].1,
        ));
    } else {
        preimage.extend(constant_bits(&(input_index as u32).to_le_bytes()));
    }

    if base_type == 0x03 {
        let vout_start = 129 + input_index * 43;
        let single_out = slice_bytes(vout_start, vout_start + 43);
        preimage.extend(sha256(cs.namespace(|| "sha_single_output"), single_out)?);
    }

    preimage.extend(tapleaf_bits);
    preimage.extend(constant_bits(&[0x00, 0xff, 0xff, 0xff, 0xff])); // key_version=0, codesep=-1

    let computed_sh = sha256(cs.namespace(|| "tapsighash_sha256"), &preimage)?;
    enforce_bits_eq(cs.namespace(|| "bind_sighash"), &computed_sh, &claimed_sh_bits);
    Ok(computed_sh)
}
