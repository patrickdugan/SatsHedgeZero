//! Development-only export of a bare MNR05 StepCircuit. Not Nova's augmented
//! setup matrices; the additional equality/parameter binding gate is mandatory.
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::{
    frontend::{num::AllocatedNum, shape_cs::ShapeCS, ConstraintSystem, Index, LinearCombination},
    traits::circuit::StepCircuit,
};
use serde_json::json;
use shz_mnr05_bitvm3_ln_dlc::unified_batch_circuit::{B1, Mnr05UnifiedBatchStep};
use std::{collections::BTreeMap, io::{self, Write}};

const MODULUS: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const MODULUS_MINUS_ONE_BE: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";

fn coeff(x: &Fr) -> String {
    let mut bytes = x.to_repr().as_ref().to_vec();
    bytes.reverse();
    format!("0x{}", hex::encode(bytes))
}

fn terms(lc: &LinearCombination<Fr>, inputs: usize) -> Vec<(usize, String)> {
    let mut acc = BTreeMap::<usize, Fr>::new();
    for (v, c) in lc.iter() {
        let i = match v.get_unchecked() {
            Index::Input(i) => i,
            Index::Aux(i) => inputs.checked_add(i).expect("wire overflow"),
        };
        *acc.entry(i).or_insert(Fr::ZERO) += *c;
    }
    acc.iter().filter(|(_, c)| **c != Fr::ZERO)
        .map(|(i, c)| (*i, coeff(c))).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(coeff(&Fr::ONE), format!("0x{:064x}", 1u64));
    assert_eq!(coeff(&(-Fr::ONE)), format!("0x{MODULUS_MINUS_ONE_BE}"));
    let step = Mnr05UnifiedBatchStep::blank();
    let mut cs = ShapeCS::<B1>::new();
    let mut z = Vec::new();
    for i in 0..step.arity() {
        let n = AllocatedNum::alloc(cs.namespace(|| format!("z_in_{i}")), || Ok(Fr::ZERO))?;
        n.inputize(cs.namespace(|| format!("public_z_in_{i}")))?;
        z.push(n);
    }
    let out = step.synthesize(&mut cs, &z)?;
    assert_eq!(out.len(), step.arity());
    for (i, n) in out.iter().enumerate() {
        n.inputize(cs.namespace(|| format!("public_z_out_{i}")))?;
    }
    let inputs = cs.num_inputs();
    assert_eq!(inputs, 1 + 2 * step.arity(), "unexpected public wire allocation");
    let wires = inputs.checked_add(cs.num_aux()).expect("wire overflow");
    let public: Vec<usize> = (1..inputs).collect();
    // Stream rows rather than constructing a second full matrix.
    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());
    write!(w, "{{\"format\":\"zkl-r1cs-v1\",\"modulus\":{},\"wires\":{},\"public\":{},\"rows\":[",
        json!(MODULUS), wires, json!(public))?;
    for (i, (a, b, c)) in cs.constraints.iter().enumerate() {
        if i != 0 { write!(w, ",")?; }
        serde_json::to_writer(&mut w, &[terms(a, inputs), terms(b, inputs), terms(c, inputs)])?;
    }
    writeln!(w, "]}}")?;
    w.flush()?;
    Ok(())
}
