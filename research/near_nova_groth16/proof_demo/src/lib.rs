//! Real arkworks BN254 Groth16 proof of a bounded Pyth/Chainlink arithmetic mean.
//! Authenticated source signatures, Nova, NEAR finality and Bitcoin enforcement are outside.
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget,
    fields::{fp::FpVar, FieldVar}, prelude::{CondSelectGadget, ToBitsGadget}};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use serde::{Serialize, Deserialize};

pub const SPREAD_BPS: u64=50;
pub const SCALE: u64=100_000_000;

#[derive(Clone, Copy, Debug)]
pub struct PriceMeanCircuit { pub pyth: u64, pub chainlink: u64, pub index: u64 }
impl PriceMeanCircuit {
    pub fn checked_index(pyth:u64, chainlink:u64)-> Option<u64> {
        if pyth==0 || chainlink==0 {return None;}
        let sum=(pyth as u128).checked_add(chainlink as u128)?;
        let diff=pyth.abs_diff(chainlink) as u128;
        if diff.checked_mul(20_000)? > sum.checked_mul(SPREAD_BPS as u128)? {return None;}
        let rounded=(sum+1)/2;
        u64::try_from(rounded).ok()
    }
}

fn bound_fp64(v: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let bits=v.to_bits_le()?;
    for b in bits.into_iter().skip(64) {b.enforce_equal(&Boolean::FALSE)?;}
    Ok(())
}
fn bound_fp96(v: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let bits=v.to_bits_le()?;
    for b in bits.into_iter().skip(96) {b.enforce_equal(&Boolean::FALSE)?;}
    Ok(())
}
impl ConstraintSynthesizer<Fr> for PriceMeanCircuit {
 fn generate_constraints(self,cs:ConstraintSystemRef<Fr>)-> Result<(),SynthesisError> {
    let p=FpVar::<Fr>::new_input(cs.clone(),||Ok(Fr::from(self.pyth)))?;
    let c=FpVar::<Fr>::new_input(cs.clone(),||Ok(Fr::from(self.chainlink)))?;
    let i=FpVar::<Fr>::new_input(cs.clone(),||Ok(Fr::from(self.index)))?;
    for v in [&p,&c,&i] {bound_fp64(v)?;v.is_eq(&FpVar::zero())?.enforce_equal(&Boolean::FALSE)?;}
    let p_first=Boolean::<Fr>::new_witness(cs.clone(),||Ok(self.pyth>=self.chainlink))?;
    let parity=Boolean::<Fr>::new_witness(cs.clone(),||Ok((self.pyth as u128+self.chainlink as u128)%2==1))?;
    let parity_fp=FpVar::conditionally_select(&parity,&FpVar::Constant(Fr::from(1u64)),&FpVar::zero())?;
    (i*Fr::from(2u64)).enforce_equal(&(p.clone()+c.clone()+parity_fp))?;
    let diff=FpVar::<Fr>::new_witness(cs.clone(),||Ok(Fr::from(self.pyth.abs_diff(self.chainlink))))?;
    bound_fp64(&diff)?;
    let signed=FpVar::conditionally_select(&p_first,&(p.clone()-c.clone()),&(c.clone()-p.clone()))?;
    diff.enforce_equal(&signed)?;
    let sum=self.pyth as u128+self.chainlink as u128;
    let abs=self.pyth.abs_diff(self.chainlink) as u128;
    let lhs=(SPREAD_BPS as u128)*sum;
    let rhs=20_000u128*abs;
    let slack=lhs.saturating_sub(rhs);
    let slack_var=FpVar::<Fr>::new_witness(cs,||Ok(Fr::from(slack)))?;
    bound_fp96(&slack_var)?;
    ((p+c)*Fr::from(SPREAD_BPS)-diff*Fr::from(20_000u64)).enforce_equal(&slack_var)?;
    Ok(())
 }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct WireG1 {pub x:[u8;32],pub y:[u8;32]}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct WireG2 {pub x:[[u8;32];2],pub y:[[u8;32];2]}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct WireVk {pub alpha:WireG1,pub beta:WireG2,pub gamma:WireG2,pub delta:WireG2,pub ic:Vec<WireG1>}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct WireProof {pub a:WireG1,pub b:WireG2,pub c:WireG1}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Generated {pub vk:WireVk,pub proof:WireProof,pub inputs:Vec<[u8;32]>,pub native_verified:bool,pub relation:String}

pub fn fr32(f:Fr)->[u8;32]{field32(f)}
fn field32<F: PrimeField>(f:F)->[u8;32]{
 let v=f.into_bigint().to_bytes_le();let mut arr=[0u8;32];arr[..v.len()].copy_from_slice(&v);arr
}
fn wire_g1(p:G1Affine)->WireG1{WireG1{x:field32(p.x),y:field32(p.y)}}
fn wire_g2(p:G2Affine)->WireG2{WireG2{x:[field32(p.x.c0),field32(p.x.c1)],y:[field32(p.y.c0),field32(p.y.c1)]}}

pub fn prove_prices(pyth:u64,chainlink:u64,index:u64)->Generated {
 let circuit=PriceMeanCircuit{pyth,chainlink,index};
 let mut rng=rand::thread_rng();
 let (pk,vk)=Groth16::<Bn254>::circuit_specific_setup(circuit,&mut rng).expect("setup");
 let proof=Groth16::<Bn254>::prove(&pk,circuit,&mut rng).expect("prove");
 let inputs=[Fr::from(pyth),Fr::from(chainlink),Fr::from(index)];
 let verified=Groth16::<Bn254>::verify(&vk,&inputs,&proof).expect("verify");
 Generated{vk:WireVk{alpha:wire_g1(vk.alpha_g1),beta:wire_g2(vk.beta_g2),
   gamma:wire_g2(vk.gamma_g2),delta:wire_g2(vk.delta_g2),ic:vk.gamma_abc_g1.into_iter().map(wire_g1).collect()},
   proof:WireProof{a:wire_g1(proof.a),b:wire_g2(proof.b),c:wire_g1(proof.c)},
   inputs:inputs.into_iter().map(fr32).collect(),native_verified:verified,
   relation:"shz/dual-price-groth16-arithmetic/v1".to_string()}
}

#[cfg(test)]
mod tests {
use super::*;
#[test]fn good_proof_works(){let p=prove_prices(100_000*SCALE,100_200*SCALE,100_100*SCALE);assert!(p.native_verified);assert_eq!(p.inputs.len(),3);}
#[test]fn off_midpoint_fails(){
 let c=PriceMeanCircuit{pyth:100_000*SCALE,chainlink:100_200*SCALE,index:100_101*SCALE};
 let cs=ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();c.generate_constraints(cs.clone()).unwrap();assert!(!cs.is_satisfied().unwrap());
}
#[test]fn spread_too_wide_fails(){
 let c=PriceMeanCircuit{pyth:100_000*SCALE,chainlink:103_000*SCALE,index:101_500*SCALE};
 let cs=ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();c.generate_constraints(cs.clone()).unwrap();assert!(!cs.is_satisfied().unwrap());
}
#[test]fn bounds_and_rounding(){assert_eq!(PriceMeanCircuit::checked_index(10000,10001),Some(10001));assert_eq!(PriceMeanCircuit::checked_index(100_000*SCALE,103_000*SCALE),None);}
}
