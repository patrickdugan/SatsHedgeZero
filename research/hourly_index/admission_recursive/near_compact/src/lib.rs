//! Research-only, single-owner session for a receiver-pinned STARK receipt.
//! A hash-cache batch is not a proof. Only finish() can set verified=true.
use near_sdk::{borsh::{BorshDeserialize,BorshSerialize},env,near_bindgen,PanicOnDefault,json_types::Base64VecU8,serde_json::{Value,json}};
use shz_admission_recursive_core::{Journal,JOURNAL_LEN};
use shz_stark_hash_compact::*;
fn host_sha(b:&[u8])->[u8;32]{env::sha256(b).try_into().expect("SHA256 length")}
#[near_bindgen]
#[derive(BorshDeserialize,BorshSerialize,PanicOnDefault)]
#[borsh(crate="near_sdk::borsh")]
pub struct Verifier{
    image:[u32;8],expected:Vec<u8>,receipt_hash:[u8;32],
    call_count:u32,cap:u32,initial:[u8;32],current:[u8;32],
    offset:u32,batches:u32,verified:bool,
}
#[near_bindgen]
impl Verifier{
    #[init]
    pub fn new(image:[u32;8],expected:Base64VecU8,receipt_sha256:String,call_count:u32,cap:u32)->Self{
        assert_eq!(env::predecessor_account_id(),env::current_account_id(),"self-only research session");
        assert!((1..=MAX_CALLS as u32).contains(&call_count)&&allowed_cap(cap as usize));
        let j=Journal::decode(&expected.0).expect("canonical expected journal");
        assert_eq!(j.ctx.image_id,image);
        assert!(j.height>0&&j.start_op==0&&j.start_reports==0&&j.start_seal==0&&expected.0.len()==JOURNAL_LEN);
        let receipt_hash:[u8;32]=hex::decode(receipt_sha256).expect("receipt hash").try_into().expect("32-byte receipt hash");
        let initial=initial(host_sha,receipt_hash,image,&expected.0,call_count,cap as usize);
        Self{image,expected:expected.0,receipt_hash,call_count,cap,initial,current:initial,offset:0,batches:0,verified:false}
    }
    pub fn reset(&mut self)->bool{
        self.owner();if self.verified{return false}
        self.current=self.initial;self.offset=0;self.batches=0;true
    }
    fn owner(&self){assert_eq!(env::predecessor_account_id(),env::current_account_id(),"self-only research session")}
    pub fn append_batch(&mut self,offset:u32,frame:Base64VecU8)->bool{
        self.owner();
        if self.verified||offset!=self.offset||self.offset==self.call_count||self.batches as usize>=MAX_BATCHES{return false}
        let Ok(n)=validate_frame(&frame.0,self.cap as usize)else{return false};
        let Some(next)=self.offset.checked_add(n as u32)else{return false};
        if next>self.call_count{return false}
        self.current=extend_commitment(host_sha,self.current,self.offset,&frame.0);
        self.offset=next;self.batches+=1;
        true
    }
    pub fn finish(&mut self,receipt:Base64VecU8,tape:Base64VecU8)->bool{
        self.owner();
        if self.verified||self.offset!=self.call_count||receipt.0.len()>MAX_RECEIPT||tape.0.len()>MAX_TAPE{return false}
        if host_sha(&receipt.0)!=self.receipt_hash{return false}
        let Ok(r)=decode_receipt(&receipt.0,&self.expected)else{return false};
        let Ok(tape)=decode_tape(&tape.0,self.call_count as usize,self.batches as usize,self.cap as usize)else{return false};
        if !replay(&r,self.image,tape,self.cap as usize,self.initial,self.current,host_sha).accepted(){return false}
        self.verified=true;true
    }
    pub fn status(&self)->Value{
        json!({"cap":self.cap,"offset":self.offset,"call_count":self.call_count,"batches":self.batches,"commitment":hex::encode(self.current),"verified":self.verified})
    }
    pub fn can_authorize_dlc_settlement(&self)->bool{false}
    pub fn production_ready(&self)->bool{false}
}
