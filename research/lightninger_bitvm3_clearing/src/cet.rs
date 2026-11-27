//! Binding M17 (Bitcoin Script on Nova) to the in-circuit TapSighash and Secq256k1 BIP-340
//! folds, and the joint statement over CET spends and a clearing batch chain.
//!
//! M17 folds an input's script execution and accumulates its claims. With Taproot signature
//! checks deferred (`engine::verify_claims_deferring_taproot`), each signature claim the spend
//! relies on is returned as `(sig, key, key_path, codeseparator register)`. The TapSighash fold
//! in bind mode computes each signature's BIP-341/342 message from the transaction and carries a
//! parameter accumulator over `(input, hash_type, ext, tapleaf, codesep, key, sig, annex)`; the
//! Secq fold checks every `(key, message, sig)` as BIP-340. A verifier accepts the spends when
//! 1. every M17 input fold verifies (program consumed, claims consistent, non-signature claims
//!    checked natively),
//! 2. the parameter accumulator rebuilt from M17's deferred signatures (in input order) equals
//!    the TapSighash fold's, its txid and spent-output commitment are the transaction's, and its
//!    signature count matches,
//! 3. the TapSighash and Secq folds end in the same authorization accumulator.
//! No elliptic-curve operation or signature hash is computed natively.
use crate::gadgets::{le_halves, sha256_native};
use crate::tapsighash_step::{params_next, spent_commitment, ScriptPath, SigSlot, Tx};
use ff::PrimeField;
use halo2curves::bn256::Fr as F;
use m17_nova_script::{circuit::Folded, engine::TaprootSig};

/// The bind-mode slots one M17 input fold relies on, in claim order.
pub fn expected_slots(input: usize, f: &Folded) -> Result<Vec<(SigSlot, Option<ScriptPath>)>, String> {
    let tap = f.prog.tap.as_ref();
    f.deferred
        .iter()
        .map(|d: &TaprootSig| {
            let ht = match d.sig.len() {
                64 => 0,
                65 => d.sig[64],
                n => return Err(format!("signature of {n} bytes")),
            };
            let annex = tap.and_then(|t| t.annex.clone());
            let slot = SigSlot { input, hash_type: ht, annex, sig_rx: d.sig[..32].try_into().unwrap(), sig_s: d.sig[32..64].try_into().unwrap() };
            let key: [u8; 32] = d.key.as_slice().try_into().map_err(|_| "key of other than 32 bytes")?;
            let ext = if d.key_path {
                None
            } else {
                let leaf = tap.and_then(|t| t.tapleaf).ok_or("tapscript signature without a tapleaf")?;
                Some(ScriptPath { key, tapleaf: leaf, codesep: if d.csp == 0 { u32::MAX } else { (d.csp - 1) as u32 } })
            };
            Ok((slot, ext))
        })
        .collect()
}

/// The parameter accumulator of a list of slots (what the bind-mode fold must end in).
pub fn params_of(slots: &[(SigSlot, Option<ScriptPath>)], key_of: impl Fn(usize) -> [u8; 32]) -> [u8; 32] {
    let mut par = [0u8; 32];
    for (s, e) in slots {
        let key = e.as_ref().map_or_else(|| key_of(s.input), |e| e.key);
        par = params_next(&par, s, e.as_ref(), &key);
    }
    par
}

fn limbs(d: &[u8; 32]) -> [F; 2] {
    let (lo, hi) = le_halves(d);
    [F::from_u128(lo), F::from_u128(hi)]
}

/// Checks 2 and 3 of the module doc against the folds' public outputs.
pub fn verify_binding(
    tx: &Tx,
    amounts: &[u64],
    spks: &[Vec<u8>],
    m17_inputs: &[(usize, &Folded)],
    tap_zk: &[F],
    secq_acc: &[u8; 32],
) -> Result<(), String> {
    let mut slots = Vec::new();
    for (input, f) in m17_inputs {
        slots.extend(expected_slots(*input, f)?);
    }
    let par = params_of(&slots, |i| spks[i][2..34].try_into().unwrap());
    if tap_zk.len() != 10 {
        return Err("TapSighash fold is not in bind mode".into());
    }
    if tap_zk[0] != F::from(slots.len() as u64) {
        return Err(format!("TapSighash fold has another signature count than the {} M17 relies on", slots.len()));
    }
    if tap_zk[3..5] != limbs(&tx.txid()) {
        return Err("TapSighash fold is over another transaction".into());
    }
    if tap_zk[5..7] != limbs(&spent_commitment(amounts, spks)) {
        return Err("TapSighash fold commits to other spent outputs".into());
    }
    if tap_zk[8..10] != limbs(&par) {
        return Err("parameter accumulator differs from M17's deferred signatures".into());
    }
    if tap_zk[1..3] != limbs(secq_acc) {
        return Err("TapSighash and Secq folds end in different authorization accumulators".into());
    }
    Ok(())
}

pub const JOINT_TAG: &[u8] = b"LIGHTNINGER/CET-SPENDS+CLEARING/V1";

fn hz<P: PrimeField>(z: &[P]) -> [u8; 32] {
    let mut b = Vec::new();
    for e in z {
        b.extend_from_slice(e.to_repr().as_ref());
    }
    sha256_native(&b)
}

/// `commitment_hash` of the joint statement: the clearing fold's `z_0`/`z_K`, the TapSighash and
/// Secq folds' `z_K`, and each M17 input fold's `z_0`/`z_K`, each as SHA-256 of its 32-byte
/// little-endian field representations, under one tag.
pub fn joint_commitment(clearing_z0: &[F], clearing_zk: &[F], tap_zk: &[F], secq_zk: &[halo2curves::secq256k1::Fq], m17: &[(usize, &Folded)]) -> [u8; 32] {
    let mut b = JOINT_TAG.to_vec();
    for d in [hz(clearing_z0), hz(clearing_zk), hz(tap_zk), hz(secq_zk)] {
        b.extend(d);
    }
    for (i, f) in m17 {
        b.extend((*i as u32).to_le_bytes());
        b.extend(hz(&f.z0));
        b.extend(hz(&f.zn));
    }
    sha256_native(&b)
}
