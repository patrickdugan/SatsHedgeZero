use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use bincode::Options;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use ff::Field;
use nova_snark::frontend::{
    AllocatedBit, Boolean, ConstraintSystem, LinearCombination, SynthesisError,
    num::AllocatedNum, sha256,
};
use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::provider::{PallasEngine, VestaEngine, ipa_pc::EvaluationEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use nova_snark::traits::{Engine, circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{Receipt, fixture::Fixture, parse_transaction};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type Pallas = PallasEngine;
type Vesta = VestaEngine;
type Scalar = <Pallas as Engine>::Scalar;
type Spartan<E> = RelaxedR1CSSNARK<E, EvaluationEngine<E>>;
type Proof = CompressedSNARK<Pallas, Vesta, Clearing, Spartan<Pallas>, Spartan<Vesta>>;
type Key = VerifierKey<Pallas, Vesta, Clearing, Spartan<Pallas>, Spartan<Vesta>>;

const STRIPPED_BYTES: usize = 348;
const FIRST_OUTPUT_AMOUNT: usize = 129;
const OUTPUT_BYTES: usize = 43;
const INPUT_ARITY: usize = 13;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug)]
struct Clearing {
    stripped: [u8; STRIPPED_BYTES],
}

fn enforce_packed<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    low_to_high: impl Iterator<Item = Boolean>,
    public: &AllocatedNum<Scalar>,
) {
    let mut place = Scalar::ONE;
    let mut packed = LinearCombination::zero();
    for bit in low_to_high {
        packed = packed + &bit.lc(CS::one(), place);
        place = place.double();
    }
    cs.enforce(|| "packed bytes", |lc| lc + &packed - public.get_variable(), |lc| lc + CS::one(), |lc| lc);
}

impl StepCircuit<Scalar> for Clearing {
    fn arity(&self) -> usize {
        INPUT_ARITY
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        state: &[AllocatedNum<Scalar>],
    ) -> std::result::Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let mut bits = Vec::with_capacity(8 * STRIPPED_BYTES);
        for (index, byte) in self.stripped.iter().enumerate() {
            for shift in (0..8).rev() {
                let bit = AllocatedBit::alloc(
                    cs.namespace(|| format!("byte {index} bit {shift}")),
                    Some((byte >> shift) & 1 == 1),
                )?;
                bits.push(Boolean::from(bit));
            }
        }
        let inner = sha256(cs.namespace(|| "legacy SHA-256"), &bits)?;
        let digest = sha256(cs.namespace(|| "legacy double SHA-256"), &inner)?;
        for (limb, (word, public)) in digest.as_chunks::<128>().0.iter().zip(&state[..2]).enumerate() {
            enforce_packed(cs.namespace(|| format!("TXID limb {limb}")), word.iter().rev().cloned(), public);
        }
        for (index, amount) in state[4..9].iter().enumerate() {
            let start = 8 * (FIRST_OUTPUT_AMOUNT + OUTPUT_BYTES * index);
            let sat_bits = bits[start..start + 64].as_chunks::<8>().0.iter().flat_map(|byte| byte.iter().rev().cloned());
            enforce_packed(cs.namespace(|| format!("output sats {index}")), sat_bits, amount);
        }
        cs.enforce(
            || "funding equals five outputs plus miner fee",
            |lc| {
                let paid = state[4..10].iter().fold(lc, |lc, amount| lc - amount.get_variable());
                state[10..13].iter().fold(paid, |lc, amount| lc + amount.get_variable())
            },
            |lc| lc + CS::one(),
            |lc| lc,
        );
        Ok(state.to_vec())
    }
}

fn digest_limbs(digest: &[u8; 32]) -> impl Iterator<Item = Scalar> + '_ {
    digest.as_chunks::<16>().0.iter().map(|word| {
        word.iter().fold(Scalar::ZERO, |acc, byte| acc * Scalar::from(256) + Scalar::from(u64::from(*byte)))
    })
}

fn public_inputs(fixture: &Fixture, raw: &[u8]) -> Result<(Receipt, Clearing, Vec<Scalar>)> {
    // Native validation authenticates the exact witness and policy binding on
    // every entry into the prover and the independent verifier.
    let receipt = fixture.verify(raw)?;
    let mut tx = parse_transaction(raw)?;
    let txid = tx.compute_txid().to_byte_array();
    for input in &mut tx.input {
        input.witness.clear();
    }
    let stripped = serialize(&tx).try_into().map_err(|_| "unsupported stripped size")?;
    let context: [u8; 32] = hex::decode(&receipt.transaction_commitment)?
        .try_into().map_err(|_| "invalid transaction commitment")?;
    let inputs = digest_limbs(&txid)
        .chain(digest_limbs(&context))
        .chain(receipt.payout_sats.map(Scalar::from))
        .chain([Scalar::from(receipt.fee_sats)])
        .chain(fixture.policy.prevouts.iter().map(|(_, output)| Scalar::from(output.value.to_sat())))
        .collect();
    Ok((receipt, Clearing { stripped }, inputs))
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_ARTIFACT_BYTES)
}

fn read_artifact(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(MAX_ARTIFACT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err("Nova artifact exceeds size limit".into());
    }
    Ok(bytes)
}

#[derive(Serialize)]
pub struct ProofReceipt {
    pub native: Receipt,
    pub nova_backend: &'static str,
    pub nova_txid_verified: bool,
    pub nova_output_values_verified: bool,
    pub nova_funding_conservation_verified: bool,
    pub nova_ambient_context_native: bool,
    pub vk_sha256: String,
    pub proof_sha256: String,
    pub proof_bytes: usize,
    pub verification_seconds: f64,
    pub wrong_txid_claim_refused: bool,
    pub primary_constraints: Option<usize>,
    pub secondary_constraints: Option<usize>,
    pub setup_seconds: Option<f64>,
    pub folding_seconds: Option<f64>,
    pub compression_seconds: Option<f64>,
}

pub fn prove(fixture: &Fixture, raw: &[u8], dir: &Path) -> Result<ProofReceipt> {
    let (_, circuit, inputs) = public_inputs(fixture, raw)?;
    let setup_start = Instant::now();
    let pp = PublicParams::<Pallas, Vesta, Clearing>::setup(
        &circuit, &Spartan::<Pallas>::ck_floor(), &Spartan::<Vesta>::ck_floor(),
    )?;
    let (pk, vk) = Proof::setup(&pp)?;
    let setup_seconds = setup_start.elapsed().as_secs_f64();
    let folding_start = Instant::now();
    let mut folded = RecursiveSNARK::new(&pp, &circuit, &inputs)?;
    folded.prove_step(&pp, &circuit)?;
    if folded.verify(&pp, 1, &inputs)? != inputs {
        return Err("Nova fold returned a different statement".into());
    }
    let folding_seconds = folding_start.elapsed().as_secs_f64();
    let compression_start = Instant::now();
    let proof = Proof::prove(&pp, &pk, &folded)?;
    let compression_seconds = compression_start.elapsed().as_secs_f64();
    let proof_bytes = codec().serialize(&proof)?;
    let key_bytes = codec().serialize(&vk)?;
    let key_hash = hex::encode(Sha256::digest(&key_bytes));

    fs::create_dir(dir)?;
    fs::write(dir.join("proof.bin"), proof_bytes)?;
    fs::write(dir.join("vk.bin"), key_bytes)?;
    let mut receipt = verify_saved(fixture, raw, dir, &key_hash)?;
    receipt.primary_constraints = Some(pp.num_constraints().0);
    receipt.secondary_constraints = Some(pp.num_constraints().1);
    receipt.setup_seconds = Some(setup_seconds);
    receipt.folding_seconds = Some(folding_seconds);
    receipt.compression_seconds = Some(compression_seconds);
    Ok(receipt)
}

/// The trusted digest must come from the verifier's own setup or accepted key
/// manifest. A digest supplied by a prover along with its proof is insufficient.
pub fn verify_saved(fixture: &Fixture, raw: &[u8], dir: &Path, trusted_vk_sha256: &str) -> Result<ProofReceipt> {
    let (native, _, inputs) = public_inputs(fixture, raw)?;
    let key_bytes = read_artifact(&dir.join("vk.bin"))?;
    let vk_sha256 = hex::encode(Sha256::digest(&key_bytes));
    if vk_sha256 != trusted_vk_sha256 {
        return Err("Nova verifier key differs from independently pinned digest".into());
    }
    let vk: Key = codec().deserialize(&key_bytes)?;
    let encoded = read_artifact(&dir.join("proof.bin"))?;
    let proof: Proof = codec().deserialize(&encoded)?;
    let start = Instant::now();
    if proof.verify(&vk, 1, &inputs)? != inputs {
        return Err("Nova output differs from the independently reconstructed statement".into());
    }
    let verification_seconds = start.elapsed().as_secs_f64();
    let mut wrong_claim = inputs;
    wrong_claim[0] += Scalar::ONE;
    if proof.verify(&vk, 1, &wrong_claim).is_ok() {
        return Err("Nova accepted a modified public TXID".into());
    }
    Ok(ProofReceipt {
        native, nova_backend: "Nova Pallas/Vesta Spartan IPA CPU", nova_txid_verified: true,
        nova_output_values_verified: true, nova_funding_conservation_verified: true,
        nova_ambient_context_native: true, vk_sha256, proof_sha256: hex::encode(Sha256::digest(&encoded)),
        proof_bytes: encoded.len(), verification_seconds, wrong_txid_claim_refused: true,
        primary_constraints: None, secondary_constraints: None, setup_seconds: None,
        folding_seconds: None, compression_seconds: None,
    })
}

pub fn key_hash(fixture: &Fixture, raw: &[u8]) -> Result<String> {
    let (_, circuit, _) = public_inputs(fixture, raw)?;
    let pp = PublicParams::<Pallas, Vesta, Clearing>::setup(
        &circuit, &Spartan::<Pallas>::ck_floor(), &Spartan::<Vesta>::ck_floor(),
    )?;
    let (_, vk) = Proof::setup(&pp)?;
    Ok(hex::encode(Sha256::digest(codec().serialize(&vk)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_snark::frontend::test_cs::TestConstraintSystem;

    #[test]
    fn circuit_refuses_wrong_txid_payout_and_fee() {
        let fixture = Fixture::from_trusted_archive(include_str!(
            "../../../../evidence/mnr03_testnet4_bob_offline_receipt.json"
        )).unwrap();
        let (_, circuit, inputs) = public_inputs(&fixture, &fixture.raw).unwrap();
        for changed_slot in [None, Some(0), Some(4), Some(9)] {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let states: Vec<_> = inputs.iter().enumerate().map(|(i, value)| {
                let value = if changed_slot == Some(i) { *value + Scalar::ONE } else { *value };
                AllocatedNum::alloc(cs.namespace(|| format!("public {i}")), || Ok(value)).unwrap()
            }).collect();
            circuit.synthesize(&mut cs, &states).unwrap();
            assert_eq!(cs.is_satisfied(), changed_slot.is_none(), "{:?}", cs.which_is_unsatisfied());
        }
    }
}
