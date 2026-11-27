//! SP1 wrap guest of the Lightninger DLC batcher: runs Nova 0.76.0's `CompressedSNARK::verify` for
//! the V3 clearing fold (Bn256EngineIPA / GrumpkinEngine, Spartan + IPA), then the batch settlement
//! relation (`lightninger_dlc_batch_relation::guest_statement`), and commits the 304-byte
//! `UTXOREF_L2_SETTLEMENT_GROTH16_V0` statement as its public values.
//!
//! Private inputs (`SP1Stdin::write_vec`, in order): the bincode clearing verifier key, the bincode
//! compressed proof, and the bincode `GuestIn` (fold length, table size, `z_0`, the TapSighash
//! fold's `z_K`, the Secq and M17 IO digests, manifest, venue batches, raw settlement).
//!
//! What the guest establishes: the clearing proof verifies from `z_0` over `steps` batches; those
//! batches (each `BatchClearing` in full) chain to its `z_K`; the settlement spends exactly the
//! manifest's accounts and pays each `collateral + sum(net)`; the TapSighash `z_K` names the
//! settlement's txid and spent outputs. The TapSighash, Secq and M17 proofs themselves are not
//! verified here: their IO enters `commitment_hash` as given (verified natively by challengers).
//! The guest panics (no proof exists) on any failure.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ff::PrimeField;
use lightninger_dlc_batch_relation::{guest_statement, sha256, GuestIn};
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, VerifierKey},
    provider::{ipa_pc, Bn256EngineIPA, GrumpkinEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, Engine},
};

type E1 = Bn256EngineIPA;
type E2 = GrumpkinEngine;
type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;

/// Verification never synthesizes the step circuit; only its arity (`7 + 4·table`) is used.
#[derive(Clone, Debug)]
struct Arity(usize);
impl StepCircuit<F> for Arity {
    fn arity(&self) -> usize {
        self.0
    }
    fn synthesize<CS: ConstraintSystem<F>>(&self, _: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        Ok(z.to_vec())
    }
}

pub fn main() {
    let vk_bytes = sp1_zkvm::io::read_vec();
    let proof = sp1_zkvm::io::read_vec();
    let g: GuestIn = bincode::deserialize(&sp1_zkvm::io::read_vec()).expect("guest input decodes");
    assert!(g.table > 0 && g.table <= 64 && g.steps > 0 && g.steps <= 4096, "table or fold length out of range");

    println!("cycle-tracker-report-start: sha256_vk");
    let vk_sha = sha256(&vk_bytes);
    println!("cycle-tracker-report-end: sha256_vk");

    let z0: Vec<F> = g
        .z0
        .iter()
        .map(|c| {
            let mut r = <F as PrimeField>::Repr::default();
            r.as_mut().copy_from_slice(c);
            Option::<F>::from(F::from_repr(r)).expect("canonical z0")
        })
        .collect();

    println!("cycle-tracker-report-start: decode_vk");
    let vk: VerifierKey<E1, E2, Arity, S1, S2> = bincode::deserialize(&vk_bytes).expect("verifier key decodes");
    println!("cycle-tracker-report-end: decode_vk");
    drop(vk_bytes);
    println!("cycle-tracker-report-start: decode_proof");
    let snark: CompressedSNARK<E1, E2, Arity, S1, S2> = bincode::deserialize(&proof).expect("proof decodes");
    println!("cycle-tracker-report-end: decode_proof");

    println!("cycle-tracker-report-start: nova_verify");
    let zk = snark.verify(&vk, g.steps as usize, &z0).expect("Nova verifier rejects the clearing proof");
    println!("cycle-tracker-report-end: nova_verify");

    let zk: Vec<[u8; 32]> = zk.iter().map(|e| e.to_repr().as_ref().try_into().unwrap()).collect();
    println!("cycle-tracker-report-start: settlement_relation");
    let stmt = guest_statement(&g, &zk, &vk_sha).unwrap_or_else(|e| panic!("settlement relation: {e}"));
    println!("cycle-tracker-report-end: settlement_relation");
    sp1_zkvm::io::commit_slice(&stmt);
}
