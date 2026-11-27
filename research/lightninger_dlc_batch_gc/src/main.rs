//! Garbled Groth16 (BN254) verifier instances for the Lightninger DLC batcher's BitVM3 claim graph.
//!
//! - `groth16 <statement_sha256_hex> <out.json>`: the statement-pinned stand-in Groth16 used on
//!   regtest until the SP1 wrap of the batch guest exists. Public inputs are the statement's two
//!   big-endian 128-bit limbs `[hi, lo]`; the circuit fixes them to the limbs of the given statement
//!   as constants, so a proof verifies under this key for that statement and no other. Setup
//!   randomness is derived from the statement (whoever runs setup can forge: this key carries no
//!   soundness beyond "the statement the setup party computed"). Writes key, proof and inputs.
//! - `claim <groth16.json> <claimed_statement_sha256_hex> <seed> <out.json>`: one claim instance.
//!   The claimant garbles gsv's streaming Groth16 verifier for the key (Free-XOR + half gates, AES
//!   gate hasher), commits the BLAKE3 hash of the ciphertext stream and SHA-256 of both output
//!   labels (label0 = reject, label1 = accept), then regarbles into a channel while the challenger
//!   evaluates on the input labels for the proof and the CLAIMED statement's limbs, re-hashing the
//!   ciphertexts it consumes. The evaluated label opens the claim graph's disprove leaf exactly when
//!   it is the reject label.
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use garbled_snark_verifier::{
    Blake3AccumulatingHash, EvaluatedWire, GarbledWire,
    circuit::{
        CircuitBuilder, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    },
    garbled_groth16,
    hashers::{AesCcrGateHasher, GateHasher},
};
use rand::SeedableRng;
use rand_chacha::{ChaCha20Rng, ChaChaRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{thread, time::Instant};

type Fr = ark_bn254::Fr;
type G16 = ark_groth16::Groth16<ark_bn254::Bn254>;
const CAPACITY: usize = 150_000;
const STANDIN_TAG: &[u8] = b"LIGHTNINGER/DLC-BATCH/GROTH16-STANDIN/V1";

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn digest_arg(s: &str) -> [u8; 32] {
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).unwrap_or_else(|| panic!("statement digest must be 64 hex characters: {s}"))
}

/// `[u128_be(d[0..16]), u128_be(d[16..32])]` as BN254 scalars (`split_statement_digest_be_u128`).
fn limbs(d: &[u8; 32]) -> [Fr; 2] {
    let hi = u128::from_be_bytes(d[..16].try_into().unwrap());
    let lo = u128::from_be_bytes(d[16..].try_into().unwrap());
    [Fr::from(hi), Fr::from(lo)]
}

/// Public inputs `[hi, lo]` constrained to the pinned limbs, plus one product so the witness is not
/// empty: `(hi - H) * 1 = 0`, `(lo - L) * 1 = 0`, `hi * lo = p`.
#[derive(Clone)]
struct Pinned {
    pin: [Fr; 2],
    public: Option<[Fr; 2]>,
}

impl ConstraintSynthesizer<Fr> for Pinned {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let v = self.public;
        let hi = cs.new_input_variable(|| v.map(|x| x[0]).ok_or(SynthesisError::AssignmentMissing))?;
        let lo = cs.new_input_variable(|| v.map(|x| x[1]).ok_or(SynthesisError::AssignmentMissing))?;
        let p = cs.new_witness_variable(|| v.map(|x| x[0] * x[1]).ok_or(SynthesisError::AssignmentMissing))?;
        let one = LinearCombination::from(Variable::One);
        cs.enforce_constraint(LinearCombination::from(hi) - (self.pin[0], Variable::One), one.clone(), LinearCombination::zero())?;
        cs.enforce_constraint(LinearCombination::from(lo) - (self.pin[1], Variable::One), one, LinearCombination::zero())?;
        cs.enforce_constraint(LinearCombination::from(hi), LinearCombination::from(lo), LinearCombination::from(p))?;
        Ok(())
    }
}

fn ser<T: CanonicalSerialize>(t: &T) -> String {
    let mut b = Vec::new();
    t.serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}

fn de<T: CanonicalDeserialize>(h: &str) -> T {
    T::deserialize_compressed(&hex::decode(h).unwrap()[..]).unwrap()
}

fn fr_dec(f: &Fr) -> String {
    f.into_bigint().to_string()
}

fn groth16(digest_hex: &str, out: &str) {
    let d = digest_arg(digest_hex);
    let pin = limbs(&d);
    let mut rng = ChaCha20Rng::from_seed(sha256(&[STANDIN_TAG, &d[..]].concat()));
    let t = Instant::now();
    let (pk, vk) = G16::circuit_specific_setup(Pinned { pin, public: None }, &mut rng).expect("setup");
    let proof = G16::prove(&pk, Pinned { pin, public: Some(pin) }, &mut rng).expect("prove");
    let secs = t.elapsed().as_secs_f64();
    assert!(G16::verify(&vk, &pin, &proof).unwrap(), "proof verifies for the pinned statement");
    let mut other = d;
    other[31] ^= 1;
    let other_rejected = !G16::verify(&vk, &limbs(&other), &proof).unwrap();
    assert!(other_rejected);
    let vk_hex = ser(&vk);
    let r = json!({
        "kind": "statement-pinned stand-in Groth16 (BN254, arkworks); public inputs = the statement digest's two big-endian 128-bit limbs",
        "statement_sha256": digest_hex,
        "public_inputs_dec": [fr_dec(&pin[0]), fr_dec(&pin[1])],
        "vk_compressed_hex": vk_hex,
        "vk_sha256": hex::encode(sha256(&hex::decode(&vk_hex).unwrap())),
        "proof_compressed_hex": ser(&proof),
        "native_verify": true,
        "native_verify_other_statement_rejected": other_rejected,
        "setup_and_prove_seconds": secs,
    });
    std::fs::write(out, serde_json::to_string_pretty(&r).unwrap()).unwrap();
    eprintln!("wrote {out}");
}

fn claim(g16_path: &str, claimed_hex: &str, seed: u64, out: &str) {
    let g: Value = serde_json::from_str(&std::fs::read_to_string(g16_path).unwrap()).unwrap();
    let vk: ark_groth16::VerifyingKey<ark_bn254::Bn254> = de(g["vk_compressed_hex"].as_str().unwrap());
    let proof: ark_groth16::Proof<ark_bn254::Bn254> = de(g["proof_compressed_hex"].as_str().unwrap());
    let claimed = digest_arg(claimed_hex);
    let public = limbs(&claimed).to_vec();
    let native = G16::verify(&vk, &public, &proof).unwrap();
    garbled_snark_verifier::warn_if_software_aes();
    let inputs = garbled_groth16::GarblerInput { public_params_len: 2, vk: vk.clone() };

    // 1. the claimant garbles and commits
    let t = Instant::now();
    let commit: StreamingResult<GarbleMode<AesCcrGateHasher, _>, _, GarbledWire> =
        CircuitBuilder::streaming_garbling(inputs.clone(), CAPACITY, seed, Blake3AccumulatingHash::default(), garbled_groth16::verify);
    let garble_s = t.elapsed().as_secs_f64();
    let GarbledWire { label0, label1 } = *commit.output_labels();
    let (l0, l1) = (label0.to_bytes(), label1.to_bytes());
    let ciphertext_commitment = commit.ciphertext_handler_result;
    let true_wire = commit.true_wire_constant.select(true).to_u128();
    let false_wire = commit.false_wire_constant.select(false).to_u128();
    let ev_in = garbled_groth16::EvaluatorInput::new(public.clone(), proof, vk, commit.input_wire_values);
    eprintln!("garbled in {garble_s:.1}s; ciphertext commitment {}", hex::encode(ciphertext_commitment));

    // 2. regarble into a channel; the challenger evaluates and re-hashes the stream
    let (ct_tx, ct_rx) = crossbeam::channel::unbounded();
    let garbler = thread::spawn(move || {
        let _r: StreamingResult<GarbleMode<AesCcrGateHasher, _>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling_with_sender(inputs, CAPACITY, seed, ct_tx, garbled_groth16::verify);
    });
    let gate_hasher = AesCcrGateHasher::from_rng(&mut ChaChaRng::seed_from_u64(seed));
    let (px_tx, px_rx) = crossbeam::channel::unbounded();
    let rehash = thread::spawn(move || {
        let mut h = Blake3AccumulatingHash::default();
        while let Ok(c) = ct_rx.recv() {
            px_tx.send(c).unwrap();
            h.update(c);
        }
        h.finalize()
    });
    let t = Instant::now();
    let ev: StreamingResult<EvaluateMode<AesCcrGateHasher, _>, _, EvaluatedWire> =
        CircuitBuilder::streaming_evaluation(ev_in, CAPACITY, true_wire, false_wire, gate_hasher, px_rx, garbled_groth16::verify);
    let eval_s = t.elapsed().as_secs_f64();
    garbler.join().unwrap();
    let rehashed = rehash.join().unwrap();
    let EvaluatedWire { active_label, value } = ev.output_value;
    let lab = active_label.to_bytes();
    let r = json!({
        "groth16": g16_path.replace('\\', "/"),
        "vk_sha256": g["vk_sha256"],
        "claimed_statement_sha256": claimed_hex,
        "claimed_public_inputs_dec": [fr_dec(&public[0]), fr_dec(&public[1])],
        "native_groth16_verify_on_claimed_statement": native,
        "garbling_seed": seed,
        "gate_hasher": "AES-CCR half gates, Free-XOR (gsv streaming)",
        "ciphertext_commitment_blake3": hex::encode(ciphertext_commitment),
        "ciphertext_stream_rehash_blake3": hex::encode(rehashed),
        "ciphertext_stream_matches_commitment": rehashed == ciphertext_commitment,
        "reject_label_sha256": hex::encode(sha256(&l0)),
        "accept_label_sha256": hex::encode(sha256(&l1)),
        "evaluated_value": value,
        "evaluated_label_hex": hex::encode(lab),
        "evaluated_label_sha256": hex::encode(sha256(&lab)),
        "evaluated_label_is_reject": lab == l0,
        "evaluated_label_is_accept": lab == l1,
        "garble_seconds": garble_s,
        "regarble_and_evaluate_seconds": eval_s,
    });
    assert!(rehashed == ciphertext_commitment, "ciphertext stream differs from the commitment");
    assert_eq!(value, native, "garbled verdict differs from native Groth16 verification");
    assert!(if value { lab == l1 } else { lab == l0 }, "evaluated label is not the committed output label");
    std::fs::write(out, serde_json::to_string_pretty(&r).unwrap()).unwrap();
    eprintln!("evaluated {} in {eval_s:.1}s; wrote {out}", if value { "ACCEPT" } else { "REJECT" });
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("groth16") if a.len() == 4 => groth16(&a[2], &a[3]),
        Some("claim") if a.len() == 6 => claim(&a[2], &a[3], a[4].parse().expect("seed u64"), &a[5]),
        _ => {
            eprintln!("usage: dlc-batch-gc groth16 <statement_sha256_hex> <out.json>\n       dlc-batch-gc claim <groth16.json> <claimed_statement_sha256_hex> <seed> <out.json>");
            std::process::exit(2);
        }
    }
}
