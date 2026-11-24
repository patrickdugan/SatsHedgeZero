//! SHZ-NOVA-IPA-NEAR-01: setup-free transparent inner-product verifier microbenchmark.
//! This verifies a real 4-element BN254 IPA opening under fixed, hash-derived generators.
//! The NEAR host performs curve multiexponentiations. No ceremony or pairings are used.
//! INVARIANT: this does not verify the frozen Pallas/Vesta Nova Spartan/IPA proof,
//! Bitcoin transactions, Pyth / Chainlink provenance, or authorize settlement.
use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize}, env, near_bindgen,
    serde::{Deserialize, Serialize}, AccountId, PanicOnDefault,
};
use num_bigint::BigUint;
mod generators;
use generators::{G_HEX,H_HEX,U_HEX};

const DOM: &[u8] = b"SHZ/NEAR-IPA-BN254/FS/V1";
const FR_DEC: &[u8] = b"21888242871839275222246405745257275088548364400416034343698204186575808495617";
const MAX_PRICE_E8:u64 = 10_000_000_000_000_000;
const MAX_DIFF_BPS:u128 = 50;

#[derive(Serialize,Deserialize,Clone,Debug)]
#[serde(crate="near_sdk::serde")]
pub struct Statement {
    pub epoch_hash_hex:String,
    pub pyth_price_e8:String,
    pub chainlink_price_e8:String,
    pub mean_e8:String,
    pub commitment_hex:String,
}
#[derive(Serialize,Deserialize,Clone,Debug)]
#[serde(crate="near_sdk::serde")]
pub struct IpaProof {
    pub l_hex:Vec<String>,
    pub r_hex:Vec<String>,
    pub a_final_hex:String,
    pub b_final_hex:String,
}

fn modulus()->BigUint {BigUint::parse_bytes(FR_DEC,10).expect("BN254 scalar modulus")}
fn frle(n:&BigUint)->[u8;32] {
    let bytes=n.to_bytes_le(); assert!(bytes.len()<=32,"scalar overflow");
    let mut out=[0u8;32];out[..bytes.len()].copy_from_slice(&bytes);out
}
fn parse32(s:&str)->Option<[u8;32]>{
    if s.len()!=64||!s.as_bytes().iter().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()){return None}
    hex::decode(s).ok()?.try_into().ok()
}
fn parse64(s:&str)->Option<[u8;64]>{
    if s.len()!=128||!s.as_bytes().iter().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()){return None}
    hex::decode(s).ok()?.try_into().ok()
}
fn parse_fr(s:&str,r:&BigUint)->Option<BigUint>{
    let p=parse32(s)?;let v=BigUint::from_bytes_le(&p);(v<*r).then_some(v)
}
fn sha(input:&[u8])->[u8;32]{env::sha256(input).try_into().expect("SHA256 output")}
fn msm(terms:&[(&[u8;64], BigUint)], r:&BigUint)->Option<[u8;64]> {
    if terms.is_empty(){return None}
    let mut data=Vec::with_capacity(terms.len()*96);
    for (p,s) in terms {
        if s>=r{return None}
        data.extend_from_slice(&(*p)[..]);
        data.extend_from_slice(&frle(s));
    }
    // The NEAR host rejects off-curve inputs. It returns exactly one G1 point, x||y LE.
    env::alt_bn128_g1_multiexp(&data).try_into().ok()
}
fn generators()->Option<(Vec<[u8;64]>,Vec<[u8;64]>,[u8;64])>{
    let g=G_HEX.iter().map(|s|parse64(s)).collect::<Option<Vec<_>>>()?;
    let h=H_HEX.iter().map(|s|parse64(s)).collect::<Option<Vec<_>>>()?;
    Some((g,h,parse64(U_HEX)?))
}
fn verify_native(st:&Statement,pf:&IpaProof)->bool {
    let Some(epoch)=parse32(&st.epoch_hash_hex) else{return false};
    let Ok(a)=st.pyth_price_e8.parse::<u64>() else{return false};
    let Ok(b)=st.chainlink_price_e8.parse::<u64>() else{return false};
    let Ok(mean)=st.mean_e8.parse::<u64>() else{return false};
    if a==0||b==0||a>MAX_PRICE_E8||b>MAX_PRICE_E8{return false}
    let sum=a as u128+b as u128;
    if mean as u128 != sum/2{return false}
    if (a.abs_diff(b) as u128)*20_000>MAX_DIFF_BPS*sum{return false}
    let Some(commitment)=parse64(&st.commitment_hex) else{return false};
    if pf.l_hex.len()!=2||pf.r_hex.len()!=2{return false}
    let Some((mut gs,mut hs,u))=generators() else{return false};
    let r=modulus(); let one=BigUint::from(1u8);
    let Some(expected_commitment)=msm(&[
        (&gs[0],BigUint::from(a)),(&gs[1],BigUint::from(b)),
        (&hs[0],one.clone()),(&hs[1],one.clone())],&r)else{return false};
    if commitment!=expected_commitment{return false}
    let c=BigUint::from(sum);
    let Some(mut p)=msm(&[(&commitment,one.clone()),(&u,c.clone())],&r)else{return false};
    let mut seed=Vec::with_capacity(32+DOM.len()+64+32);
    seed.extend_from_slice(DOM);seed.extend_from_slice(&epoch);
    seed.extend_from_slice(&commitment);seed.extend_from_slice(&frle(&c));
    let mut state=sha(&seed);
    for i in 0..2 {
        let Some(l)=parse64(&pf.l_hex[i]) else{return false};
        let Some(rr)=parse64(&pf.r_hex[i]) else{return false};
        let mut preimage=Vec::with_capacity(32+64+64);
        preimage.extend_from_slice(&state);preimage.extend_from_slice(&l);preimage.extend_from_slice(&rr);
        let x=BigUint::from_bytes_be(&sha(&preimage))%&r;
        if x==BigUint::from(0u8){return false}
        let xi=x.modpow(&(&r-BigUint::from(2u8)),&r);
        let x2=(&x*&x)%&r;let xi2=(&xi*&xi)%&r;
        preimage.extend_from_slice(&frle(&x));state=sha(&preimage);
        let Some(new_p)=msm(&[(&l,x2),(&p,one.clone()),(&rr,xi2)],&r) else{return false};
        p=new_p;
        let n=gs.len()/2;
        let mut ng=Vec::with_capacity(n);let mut nh=Vec::with_capacity(n);
        for j in 0..n {
            let Some(g)=msm(&[(&gs[j],xi.clone()),(&gs[n+j],x.clone())],&r)else{return false};
            let Some(h)=msm(&[(&hs[j],x.clone()),(&hs[n+j],xi.clone())],&r)else{return false};
            ng.push(g);nh.push(h);
        }
        gs=ng;hs=nh;
    }
    let Some(af)=parse_fr(&pf.a_final_hex,&r)else{return false};
    let Some(bf)=parse_fr(&pf.b_final_hex,&r)else{return false};
    let product=(&af*&bf)%&r;
    let Some(expected_p)=msm(&[(&gs[0],af),(&hs[0],bf),(&u,product)],&r)else{return false};
    p==expected_p
}

#[near_bindgen]
#[derive(BorshSerialize,BorshDeserialize,PanicOnDefault)]
#[borsh(crate="near_sdk::borsh")]
pub struct TransparentIpaPilot {pub admin:AccountId}

#[near_bindgen]
impl TransparentIpaPilot {
    #[init]
    pub fn new()->Self {Self{admin:env::predecessor_account_id()}}
    /// Research verifier of a public BN254 IPA relation: `c = a·b` for a fixed 4-entry vector.
    /// It recomputes C from caller-supplied prices. Sources and their signatures are NOT verified.
    pub fn verify_ipa(&self,statement:Statement,proof:IpaProof)->bool {verify_native(&statement,&proof)}
    pub fn verifier_relation(&self)->String {"shz/near-transparent-bn254-ipa/v1".into()}
    pub fn can_authorize_nova(&self)->bool {false}
    pub fn can_authorize_dlc_settlement(&self)->bool {false}
}

#[cfg(all(test,not(target_arch="wasm32")))]
mod tests {
    use super::*;
    use near_sdk::{test_utils::VMContextBuilder,testing_env};
    #[derive(Deserialize)]#[serde(crate="near_sdk::serde")]
    struct Fixture {statement:Statement,proof:IpaProof}
    fn run_fixture()->(TransparentIpaPilot,Fixture) {
        let mut context=VMContextBuilder::new();
        context.current_account_id("shz-ipa.testnet".parse().unwrap());
        testing_env!(context.build());
        let fixture:Fixture=near_sdk::serde_json::from_str(include_str!("../../fixtures/valid.json")).unwrap();
        (TransparentIpaPilot::new(),fixture)
    }
    #[test]
    fn real_ipa_proof_accepted_using_near_bn254_host() {
        let (contract,fx)=run_fixture();
        assert!(contract.verify_ipa(fx.statement,fx.proof));
        assert!(!contract.can_authorize_nova());
        assert!(!contract.can_authorize_dlc_settlement());
        println!("Mock host gas consumed: {} (NOT actual near-sandbox gas)",env::used_gas().as_gas());
    }
    #[test]
    fn wrong_public_price_rejected(){let(c,mut f)=run_fixture();f.statement.pyth_price_e8="10000000000001".into();assert!(!c.verify_ipa(f.statement,f.proof));}
    #[test]
    fn mutated_proof_scalar_rejected(){let(c,mut f)=run_fixture();f.proof.a_final_hex.replace_range(0..2,"01");assert!(!c.verify_ipa(f.statement,f.proof));}
    #[test]
    fn wrong_claimed_mean_rejected(){let(c,mut f)=run_fixture();f.statement.mean_e8="10010000000001".into();assert!(!c.verify_ipa(f.statement,f.proof));}
    #[test]
    fn replayed_epoch_hash_rejected(){let(c,mut f)=run_fixture();f.statement.epoch_hash_hex="00".repeat(32);assert!(!c.verify_ipa(f.statement,f.proof));}
    #[test]
    fn malformed_noncanonical_scalar_rejected(){let(c,mut f)=run_fixture();f.proof.a_final_hex="ff".repeat(32);assert!(!c.verify_ipa(f.statement,f.proof));}
    #[test]
    fn operator_cannot_change_source_limit(){let(c,mut f)=run_fixture();f.statement.chainlink_price_e8="10300000000000".into();assert!(!c.verify_ipa(f.statement,f.proof));}
}
