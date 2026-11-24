//! SHZ-IPA02 transparent BN254 inner-product argument for frozen MNR-03 *public state*.
//! This verifies IPA commitments to the archived public accounting tuple, on NEAR WASM.
//! It does not verify Nova's Pallas/Vesta folding, Spartan/IPA proof, Bitcoin spends,
//! or authenticate Pyth/Chainlink source reports. All settlement gates remain disabled.
use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize}, env, near_bindgen,
    serde::{Deserialize, Serialize}, AccountId, PanicOnDefault,
};
use num_bigint::BigUint;
mod generators;
use generators::{G_HEX,H_HEX,U_HEX,FROZEN_ROOT_HEX};

const DOM: &[u8] = b"SHZ/NEAR-IPA02-MNR03-STATE/FS/V2";
const FR_DEC: &[u8] = b"21888242871839275222246405745257275088548364400416034343698204186575808495617";
const PYTH_HASH: &str = "7a0a6d8d97a231fd0adcef7892d29232d131adfe8c92391deb228b9dd598e51e";
const CLEARING_TXID: &str = "ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1";
const JOURNAL_HASH: &str = "d87e089251413e3f47f90c9e3aadb21c98d164798f77b953d19b361402a28a40";
const NOVA_PROOF_HASH: &str = "14e9985b67569c2db18b10eb43e0036cfe76fac21ab2674b35ae6324fe08a043";

#[derive(Serialize,Deserialize,Clone,Debug)]
#[serde(crate="near_sdk::serde")]
pub struct StateStatement {
    pub dimension:usize,
    pub epoch_id:u64,
    pub row_count:u64,
    pub collateral_sats:u64,
    pub payout_sats:u64,
    pub fee_sats:u64,
    pub conservation_claim:u64,
    pub snapshot_root_hex:String,
    pub oracle_receipt_hash_hex:String,
    pub bitcoin_assertion_txid_hex:String,
    pub nova_journal_sha256_hex:String,
    pub nova_proof_sha256_hex:String,
    pub commitment_hex:String,
}
#[derive(Serialize,Deserialize,Clone,Debug)]
#[serde(crate="near_sdk::serde")]
pub struct IpaStateProof {
    pub l_hex:Vec<String>,
    pub r_hex:Vec<String>,
    pub a_final_hex:String,
    pub b_final_hex:String,
}

fn r()->BigUint {BigUint::parse_bytes(FR_DEC,10).expect("BN254 scalar modulus")}
fn frle(n:&BigUint)->[u8;32] {
    let bytes=n.to_bytes_le(); assert!(bytes.len()<=32,"scalar overflow");
    let mut out=[0u8;32];out[..bytes.len()].copy_from_slice(&bytes);out
}
fn hex32(s:&str)->Option<[u8;32]>{
    if s.len()!=64||!s.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()){return None}
    hex::decode(s).ok()?.try_into().ok()
}
fn hex64(s:&str)->Option<[u8;64]>{
    if s.len()!=128||!s.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()){return None}
    hex::decode(s).ok()?.try_into().ok()
}
fn parse_fr(s:&str,r:&BigUint)->Option<BigUint>{let p=hex32(s)?;let v=BigUint::from_bytes_le(&p);(v<*r).then_some(v)}
fn sha(input:&[u8])->[u8;32]{env::sha256(input).try_into().expect("SHA256 output")}
fn msm(terms:&[(&[u8;64],BigUint)],r:&BigUint)->Option<[u8;64]>{
    if terms.is_empty()||terms.len()>65{return None}
    let mut buf=Vec::with_capacity(terms.len()*96);
    for (p,s) in terms {if s>=r{return None}buf.extend_from_slice(*p);buf.extend_from_slice(&frle(s))}
    env::alt_bn128_g1_multiexp(&buf).try_into().ok()
}
fn verify_native(st:&StateStatement,pf:&IpaStateProof)->bool {
    let n=st.dimension;
    if ![8,16,32].contains(&n)||st.epoch_id!=177||st.row_count!=3||
       st.collateral_sats!=3900||st.payout_sats!=3450||st.fee_sats!=450||
       st.conservation_claim!=3||st.collateral_sats.checked_sub(st.payout_sats)!=Some(st.fee_sats){return false}
    if st.snapshot_root_hex!=FROZEN_ROOT_HEX||st.oracle_receipt_hash_hex!=PYTH_HASH||
       st.bitcoin_assertion_txid_hex!=CLEARING_TXID||st.nova_journal_sha256_hex!=JOURNAL_HASH||
       st.nova_proof_sha256_hex!=NOVA_PROOF_HASH{return false}
    let Some(root)=hex32(&st.snapshot_root_hex)else{return false};
    let Some(pyth)=hex32(&st.oracle_receipt_hash_hex)else{return false};
    let Some(txid)=hex32(&st.bitcoin_assertion_txid_hex)else{return false};
    let Some(journal)=hex32(&st.nova_journal_sha256_hex)else{return false};
    let Some(proof_hash)=hex32(&st.nova_proof_sha256_hex)else{return false};
    let Some(commitment)=hex64(&st.commitment_hex)else{return false};
    let rounds=n.trailing_zeros() as usize;
    if pf.l_hex.len()!=rounds||pf.r_hex.len()!=rounds{return false}
    let Some(mut gs)=G_HEX[..n].iter().map(|s|hex64(s)).collect::<Option<Vec<_>>>()else{return false};
    let Some(mut hs)=H_HEX[..n].iter().map(|s|hex64(s)).collect::<Option<Vec<_>>>()else{return false};
    let Some(u)=hex64(U_HEX)else{return false};
    let modulus=r();let one=BigUint::from(1u8);let five=BigUint::from(5u8);
    let rm5=&modulus-&five;
    let Some(expected_commitment)=msm(&[
        (&gs[0],BigUint::from(3u8)),(&gs[1],BigUint::from(3900u64)),
        (&gs[2],BigUint::from(3450u64)),(&gs[3],BigUint::from(450u64)),
        (&hs[0],one.clone()),(&hs[1],five.clone()),
        (&hs[2],rm5.clone()),(&hs[3],rm5)],&modulus)else{return false};
    if commitment!=expected_commitment{return false}
    let c=BigUint::from(st.conservation_claim);
    let Some(mut p)=msm(&[(&commitment,one.clone()),(&u,c.clone())],&modulus)else{return false};
    let mut seed=Vec::with_capacity(256);
    seed.extend_from_slice(DOM);seed.extend_from_slice(&(n as u32).to_le_bytes());
    seed.extend_from_slice(&root);seed.extend_from_slice(&pyth);seed.extend_from_slice(&txid);
    seed.extend_from_slice(&journal);seed.extend_from_slice(&proof_hash);seed.extend_from_slice(&commitment);
    seed.extend_from_slice(&frle(&c));
    let mut state=sha(&seed);
    for i in 0..rounds {
        let Some(l)=hex64(&pf.l_hex[i])else{return false};
        let Some(rr)=hex64(&pf.r_hex[i])else{return false};
        let mut preimage=Vec::with_capacity(192);preimage.extend_from_slice(&state);
        preimage.extend_from_slice(&l);preimage.extend_from_slice(&rr);
        let x=BigUint::from_bytes_be(&sha(&preimage))%&modulus;
        if x==BigUint::from(0u8){return false}
        let xi=x.modpow(&(&modulus-BigUint::from(2u8)),&modulus);
        let x2=(&x*&x)%&modulus;let xi2=(&xi*&xi)%&modulus;
        preimage.extend_from_slice(&frle(&x));state=sha(&preimage);
        let Some(new_p)=msm(&[(&l,x2),(&p,one.clone()),(&rr,xi2)],&modulus)else{return false};
        p=new_p;
        let half=gs.len()/2;
        let mut ng=Vec::with_capacity(half);let mut nh=Vec::with_capacity(half);
        for j in 0..half {
            let Some(g)=msm(&[(&gs[j],xi.clone()),(&gs[half+j],x.clone())],&modulus)else{return false};
            let Some(h)=msm(&[(&hs[j],x.clone()),(&hs[half+j],xi.clone())],&modulus)else{return false};
            ng.push(g);nh.push(h)
        }
        gs=ng;hs=nh;
    }
    let Some(af)=parse_fr(&pf.a_final_hex,&modulus)else{return false};
    let Some(bf)=parse_fr(&pf.b_final_hex,&modulus)else{return false};
    let ab=(&af*&bf)%&modulus;
    let Some(expected_p)=msm(&[(&gs[0],af),(&hs[0],bf),(&u,ab)],&modulus)else{return false};
    p==expected_p
}

#[near_bindgen]
#[derive(BorshSerialize,BorshDeserialize,PanicOnDefault)]
#[borsh(crate="near_sdk::borsh")]
pub struct Mnr03IpaStatePilot {pub admin:AccountId}

#[near_bindgen]
impl Mnr03IpaStatePilot {
    #[init]
    pub fn new()->Self {Self{admin:env::predecessor_account_id()}}
    pub fn verify_frozen_mnr03_public_state(&self,statement:StateStatement,proof:IpaStateProof)->bool {
        verify_native(&statement,&proof)
    }
    pub fn proof_relation(&self)->String {"shz/near-ipa02-frozen-mnr03-state/v2".into()}
    pub fn can_authorize_nova(&self)->bool {false}
    pub fn can_authorize_dlc_settlement(&self)->bool {false}
    pub fn can_authorize_oracle_epoch(&self)->bool {false}
}

#[cfg(all(test,not(target_arch="wasm32")))]
mod tests {
    use super::*;
    use near_sdk::{test_utils::VMContextBuilder,testing_env};
    #[derive(Deserialize)]#[serde(crate="near_sdk::serde")]
    struct Fixture {statement:StateStatement,proof:IpaStateProof}
    fn setup()->Mnr03IpaStatePilot {
        let mut context=VMContextBuilder::new();context.current_account_id("shz-ipa02.testnet".parse().unwrap());
        testing_env!(context.build());Mnr03IpaStatePilot::new()
    }
    fn check(s:&str){let f:Fixture=near_sdk::serde_json::from_str(s).unwrap();let c=setup();assert!(c.verify_frozen_mnr03_public_state(f.statement,f.proof));assert!(!c.can_authorize_nova());assert!(!c.can_authorize_oracle_epoch());assert!(!c.can_authorize_dlc_settlement());}
    #[test]fn real_8_dim_proof(){check(include_str!("../../fixtures/mnr03-8.json"))}
    #[test]fn real_16_dim_proof(){check(include_str!("../../fixtures/mnr03-16.json"))}
    #[test]fn real_32_dim_proof(){check(include_str!("../../fixtures/mnr03-32.json"))}
    #[test]fn bad_oracle_hash_rejected(){let mut f:Fixture=near_sdk::serde_json::from_str(include_str!("../../fixtures/mnr03-8.json")).unwrap();f.statement.oracle_receipt_hash_hex="11".repeat(32);assert!(!setup().verify_frozen_mnr03_public_state(f.statement,f.proof));}
    #[test]fn altered_scalar_rejected(){let mut f:Fixture=near_sdk::serde_json::from_str(include_str!("../../fixtures/mnr03-8.json")).unwrap();f.proof.a_final_hex="00".repeat(32);assert!(!setup().verify_frozen_mnr03_public_state(f.statement,f.proof));}
    #[test]fn changed_collateral_rejected(){let mut f:Fixture=near_sdk::serde_json::from_str(include_str!("../../fixtures/mnr03-8.json")).unwrap();f.statement.collateral_sats+=1;assert!(!setup().verify_frozen_mnr03_public_state(f.statement,f.proof));}
}
