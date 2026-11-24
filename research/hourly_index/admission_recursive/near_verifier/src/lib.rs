//! Research-only direct succinct STARK verification, no settlement authority.
//! The deployment owner independently initializes the approved image and
//! exact expected journal. Nothing is derived from a receipt's own claims.
use bincode::Options;
use near_sdk::{borsh::{BorshDeserialize,BorshSerialize},env,near_bindgen,PanicOnDefault,json_types::Base64VecU8};
use risc0_zkvm::{Receipt,InnerReceipt,VerifierContext,SuccinctReceiptVerifierParameters};
use risc0_zkp::core::hash::poseidon2::Poseidon2HashSuite;
use shz_stark_fast_hash::{fast_suite,repeated_pairs};
use std::collections::BTreeMap;
use shz_admission_recursive_core::{Journal,JOURNAL_LEN};
const MAX_RECEIPT:usize=1024*1024;
#[near_bindgen]
#[derive(BorshDeserialize,BorshSerialize,PanicOnDefault)]
#[borsh(crate="near_sdk::borsh")]
pub struct Probe {
 image:[u32;8],
 expected:Vec<u8>,
}
#[near_bindgen]
impl Probe {
 #[init]
 pub fn new(image:[u32;8],expected:Base64VecU8)->Self{
  assert_eq!(env::predecessor_account_id(),env::current_account_id(),"self-only research initialization");
  let j=Journal::decode(&expected.0).expect("canonical expected journal");
  assert_eq!(j.ctx.image_id,image);
  assert!(j.height>0&&j.start_op==0&&j.start_reports==0&&j.start_seal==0,"expected aggregate from genesis");
  Self{image,expected:expected.0}
 }
 pub fn verify_receipt(&self,receipt:Base64VecU8)->bool{self.verify_inner(receipt.0,false)}
 pub fn verify_receipt_fast(&self,receipt:Base64VecU8)->bool{self.verify_inner(receipt.0,true)}
 pub fn hash_pairs(&self,n:u32,fast:bool)->[u32;8]{
  assert!(n<=512,"benchmark budget");
  repeated_pairs(n,fast)
 }
 fn verify_inner(&self,b:Vec<u8>,fast:bool)->bool{
  if b.len()<4||b.len()>MAX_RECEIPT||self.expected.len()!=JOURNAL_LEN{return false}
  // bincode fixint enum discriminant: Receipt begins with InnerReceipt.
  // Reject all other receipt kinds before decoding their payloads.
  if b[..4]!=1u32.to_le_bytes(){return false}
  let r:Receipt=match bincode::DefaultOptions::new().with_fixint_encoding()
   .with_limit(MAX_RECEIPT as u64).reject_trailing_bytes().deserialize(&b){
    Ok(r)=>r,Err(_)=>return false
   };
  if !matches!(&r.inner,InnerReceipt::Succinct(s) if s.hashfn=="poseidon2")||r.journal.bytes!=self.expected{return false}
  let params=SuccinctReceiptVerifierParameters::default();
  // Frozen patched parameters, not a proof-selected verification key.
  if params.control_root.to_string()!="e6feef13db7aed4a731c7b0852de1f5c89b137726073f625d05333184d3a551d"{return false}
  let suite=if fast{fast_suite()}else{Poseidon2HashSuite::new_suite()};
  let ctx=VerifierContext::empty()
    .with_suites(BTreeMap::from([("poseidon2".into(),suite)]))
    .with_succinct_verifier_parameters(params);
  r.verify_with_context(&ctx,self.image).is_ok()
 }
 pub fn can_authorize_dlc_settlement(&self)->bool{false}
 pub fn production_ready(&self)->bool{false}
}
