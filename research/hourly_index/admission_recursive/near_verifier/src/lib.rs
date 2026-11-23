//! Research-only direct succinct STARK verification, no settlement authority.
//! The deployment owner independently initializes the approved image and
//! exact expected journal. Nothing is derived from a receipt's own claims.
use bincode::Options;
use near_sdk::{borsh::{BorshDeserialize,BorshSerialize},env,near_bindgen,PanicOnDefault,json_types::Base64VecU8};
use risc0_zkvm::{Receipt,InnerReceipt,VerifierContext};
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
 pub fn verify_receipt(&self,receipt:Base64VecU8)->bool{
  let b=receipt.0;
  if b.len()<4||b.len()>MAX_RECEIPT||self.expected.len()!=JOURNAL_LEN{return false}
  // bincode fixint enum discriminant: Receipt begins with InnerReceipt.
  // Reject all other receipt kinds before decoding their payloads.
  if b[..4]!=1u32.to_le_bytes(){return false}
  let r:Receipt=match bincode::DefaultOptions::new().with_fixint_encoding()
   .with_limit(MAX_RECEIPT as u64).reject_trailing_bytes().deserialize(&b){
    Ok(r)=>r,Err(_)=>return false
   };
  if !matches!(&r.inner,InnerReceipt::Succinct(s) if s.hashfn=="poseidon2")||r.journal.bytes!=self.expected{return false}
  let ctx=VerifierContext::empty()
    .with_suites(VerifierContext::default_hash_suites().into_iter().filter(|(name,_)|name=="poseidon2").collect())
    .with_succinct_verifier_parameters(Default::default());
  r.verify_with_context(&ctx,self.image).is_ok()
 }
 pub fn can_authorize_dlc_settlement(&self)->bool{false}
 pub fn production_ready(&self)->bool{false}
}
