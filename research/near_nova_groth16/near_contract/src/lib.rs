//! NEAR BN254 Groth16 verifier pilot. It proves only two-source price arithmetic.
//! It CANNOT verify the existing Pallas/Vesta Nova proof or authorize Bitcoin/DLC spends.
use near_sdk::{borsh::{self,BorshDeserialize,BorshSerialize},env,near_bindgen,
    serde::{Serialize,Deserialize},AccountId,PanicOnDefault};

// Canonical BN254 coordinate (Fq) and scalar (Fr) moduli in big-endian.
const Q_BE: [u8;32] = [0x30,0x64,0x4e,0x72,0xe1,0x31,0xa0,0x29,0xb8,0x50,0x45,0xb6,0x81,0x81,0x58,0x5d,0x97,0x81,0x6a,0x91,0x68,0x71,0xca,0x8d,0x3c,0x20,0x8c,0x16,0xd8,0x7c,0xfd,0x47];
const R_BE: [u8;32] = [0x30,0x64,0x4e,0x72,0xe1,0x31,0xa0,0x29,0xb8,0x50,0x45,0xb6,0x81,0x81,0x58,0x5d,0x28,0x33,0xe8,0x48,0x79,0xb9,0x70,0x91,0x43,0xe1,0xf5,0x93,0xf0,0x00,0x00,0x01];
const PRICE_VK_INPUTS:usize = 3;
const MAX_INDEX_E8:u64 = 10_000_000_000_000_000;

#[derive(Clone,Debug,Serialize,Deserialize,BorshSerialize,BorshDeserialize)]
#[serde(crate="near_sdk::serde")]
pub struct G1 {pub x:[u8;32],pub y:[u8;32]}
#[derive(Clone,Debug,Serialize,Deserialize,BorshSerialize,BorshDeserialize)]
#[serde(crate="near_sdk::serde")]
pub struct G2 {pub x:[[u8;32];2],pub y:[[u8;32];2]}
#[derive(Clone,Debug,Serialize,Deserialize,BorshSerialize,BorshDeserialize)]
#[serde(crate="near_sdk::serde")]
pub struct VerifyingKey {pub alpha:G1,pub beta:G2,pub gamma:G2,pub delta:G2,pub ic:Vec<G1>}
#[derive(Clone,Debug,Serialize,Deserialize,BorshSerialize,BorshDeserialize)]
#[serde(crate="near_sdk::serde")]
pub struct GrothProof {pub a:G1,pub b:G2,pub c:G1}

fn below_modulus_le(v:&[u8;32], modulus_be:&[u8;32])->bool {
 for k in 0..32 {let a=v[31-k];let b=modulus_be[k];if a<b{return true} if a>b{return false}}
 false
}
fn canonical_g1(x:&G1)->bool{below_modulus_le(&x.x,&Q_BE)&&below_modulus_le(&x.y,&Q_BE)}
fn canonical_g2(x:&G2)->bool{
 x.x.iter().chain(x.y.iter()).all(|v|below_modulus_le(v,&Q_BE))
}
fn encode_g1(x:&G1,buf:&mut Vec<u8>){buf.extend_from_slice(&x.x);buf.extend_from_slice(&x.y);}
fn encode_g2(x:&G2,buf:&mut Vec<u8>){for v in x.x.iter().chain(x.y.iter()){buf.extend_from_slice(v)}}

fn pairing_check(vk:&VerifyingKey,proof:&GrothProof,inputs:&[[u8;32]])->bool {
 if vk.ic.len()!=PRICE_VK_INPUTS+1 || inputs.len()!=PRICE_VK_INPUTS {return false}
 if !canonical_g1(&vk.alpha)||!canonical_g2(&vk.beta)||!canonical_g2(&vk.gamma)
    ||!canonical_g2(&vk.delta)||!vk.ic.iter().all(canonical_g1)
    ||!canonical_g1(&proof.a)||!canonical_g1(&proof.c)||!canonical_g2(&proof.b)
    ||!inputs.iter().all(|f|below_modulus_le(f,&R_BE)) {return false}
 // NEAR host ABI: each multiexp term is (G1 x,y; Fr scalar), 96 bytes, all LE.
 let mut data=Vec::with_capacity((inputs.len()+1)*96);
 for (j,p) in vk.ic.iter().enumerate(){encode_g1(p,&mut data);
    if j==0 {data.push(1);data.extend_from_slice(&[0u8;31]);}
    else {data.extend_from_slice(&inputs[j-1]);}
 }
 let acc=env::alt_bn128_g1_multiexp(&data);
 if acc.len()!=64{return false}
 // NEAR G1 sum ABI: (is_negative: u8, G1 x,y), 65 bytes per record.
 let mut neg=Vec::with_capacity(65);neg.push(1);encode_g1(&proof.a,&mut neg);
 let neg_a=env::alt_bn128_g1_sum(&neg);
 if neg_a.len()!=64{return false}
 // Groth16 pairing equality: e(-A,B) e(alpha,beta) e(IC,gamma) e(C,delta) == 1.
 let mut pairs=Vec::with_capacity(4*192);
 pairs.extend_from_slice(&neg_a);encode_g2(&proof.b,&mut pairs);
 encode_g1(&vk.alpha,&mut pairs);encode_g2(&vk.beta,&mut pairs);
 pairs.extend_from_slice(&acc);encode_g2(&vk.gamma,&mut pairs);
 encode_g1(&proof.c,&mut pairs);encode_g2(&vk.delta,&mut pairs);
 env::alt_bn128_pairing_check(&pairs)
}

#[near_bindgen]
#[derive(BorshSerialize,BorshDeserialize,PanicOnDefault)]
pub struct PriceMeanPilot {
    pub admin:AccountId,
    pub verified_key_sha256:String,
    vk:VerifyingKey,
}

#[near_bindgen]
impl PriceMeanPilot {
 #[init]
 pub fn new_price_mean_only(vk:VerifyingKey, expected_vk_sha256:String)->Self {
    assert_eq!(vk.ic.len(),4,"three public price inputs required");
    let binary=borsh::to_vec(&vk).expect("VK bytes");
    let digest=hex::encode(env::sha256(&binary));
    assert_eq!(digest,expected_vk_sha256,"verifying key digest mismatch");
    // Research-only setup. Production deployment must pin this digest and program version in audited governance.
    Self{admin:env::predecessor_account_id(),verified_key_sha256:digest,vk}
 }
 /// Verifies a real Groth16 proof of 64-bit bounded, two-source arithmetic mean and 50bps spread.
 /// Inputs are exactly [Pyth price E8, Chainlink price E8, index price E8], little endian Fr.
 /// The caller is responsible for native Pyth and Chainlink report authentication.
 pub fn verify_price_mean_pilot(&self, proof:GrothProof, inputs:Vec<[u8;32]>)->bool {
    if inputs.len()!=PRICE_VK_INPUTS{return false}
    let mut vals=Vec::with_capacity(3);
    for input in &inputs {
        if input[8..].iter().any(|x|*x!=0){return false}
        let mut b=[0u8;8];b.copy_from_slice(&input[..8]);
        let n=u64::from_le_bytes(b);if n==0||n>MAX_INDEX_E8{return false}
        vals.push(n);
    }
    // A separately deployed, source-authenticated gate must pin Pyth and Chainlink receipts.
    let _=vals;
    pairing_check(&self.vk,&proof,&inputs)
 }
 pub fn can_authorize_nova_decider(&self)->bool {false}
 pub fn proof_relation(&self)->String {"shz/dual-price-groth16-arithmetic/v1".to_string()}
}

#[cfg(test)]
mod tests {
use super::*;
use near_sdk::{test_utils::VMContextBuilder,testing_env};
use shz_groth16_price_proof::{prove_prices,SCALE};
fn setup(){let mut builder=VMContextBuilder::new();
  builder.current_account_id("shz-near-groth16.testnet".parse().unwrap());
  testing_env!(builder.build());}
#[test]
fn accepts_real_bn254_groth16_price_proof_and_rejects_modified_public_price(){
 setup();
 let generated=prove_prices(100_000*SCALE,100_200*SCALE,100_100*SCALE);
 assert!(generated.native_verified);
 let key:VerifyingKey=near_sdk::serde_json::from_value(near_sdk::serde_json::to_value(generated.vk).unwrap()).unwrap();
 let proof:GrothProof=near_sdk::serde_json::from_value(near_sdk::serde_json::to_value(generated.proof).unwrap()).unwrap();
 let digest=hex::encode(env::sha256(&borsh::to_vec(&key).unwrap()));
 let contract=PriceMeanPilot::new_price_mean_only(key,digest);
 assert!(contract.verify_price_mean_pilot(proof.clone(),generated.inputs.clone()));
 let mut modified=generated.inputs;
 modified[2][0]^=1;
 assert!(!contract.verify_price_mean_pilot(proof,modified));
 assert!(!contract.can_authorize_nova_decider());
}
#[test]
fn refuses_bad_vk_pin(){
 setup();
 let generated=prove_prices(100_000*SCALE,100_200*SCALE,100_100*SCALE);
 let key:VerifyingKey=near_sdk::serde_json::from_value(near_sdk::serde_json::to_value(generated.vk).unwrap()).unwrap();
 let r=std::panic::catch_unwind(||PriceMeanPilot::new_price_mean_only(key,"00".repeat(32)));
 assert!(r.is_err());
}
}
