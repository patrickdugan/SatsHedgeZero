//! ADMIT-12: replay only digest outputs; reconstruct the exact checked frame
//! commitments from the ORIGINAL verifier's actual hash inputs.
//! No cryptographic equations or Fiat-Shamir RNG are removed.
#![forbid(unsafe_code)]
use risc0_core::field::{baby_bear::{BabyBear,BabyBearElem,BabyBearExtElem,P},ExtElem};
use risc0_zkp::core::{digest::Digest,hash::{HashFn,HashSuite,poseidon2::Poseidon2HashSuite}};
use risc0_zkvm::{Receipt,VerifierContext,SuccinctReceiptVerifierParameters};
pub use shz_stark_hash_replay::{Call,Hash32,sha,decode_receipt,trace,extend_commitment,MAX_CALLS,MAX_BATCHES,MAX_RECEIPT,CONTROL_ROOT,PAIR,BASE,EXT};
use std::{collections::BTreeMap,rc::Rc,sync::Mutex};

pub const PROFILES:[usize;3]=[512,2048,3072];
pub const FUSED_PROFILES:[usize;3]=[3072,3456,3584];
const MAX_WORDS:usize=8192;
pub const MAX_TAPE:usize=4+4*MAX_BATCHES+32*MAX_CALLS;
pub fn allowed_cap(cap:usize)->bool{PROFILES.contains(&cap)||FUSED_PROFILES.contains(&cap)}
fn push(b:&mut Vec<u8>,v:u32){b.extend(v.to_le_bytes());}
fn read_u32(b:&[u8],p:&mut usize)->Result<u32,String>{
    let end=p.checked_add(4).ok_or("offset overflow")?;
    let v=u32::from_le_bytes(b.get(*p..end).ok_or("truncated word")?.try_into().unwrap());
    *p=end;Ok(v)
}
fn shape(c:&Call)->bool{
    matches!(c.kind,PAIR|BASE|EXT)&&c.words.len()<=MAX_WORDS
    &&(c.kind!=PAIR||c.words.len()==16)&&(c.kind!=EXT||c.words.len()%4==0)
    &&c.words.iter().chain(&c.output).all(|&x|x<P)
}
fn put(b:&mut Vec<u8>,c:&Call){
    b.push(c.kind);push(b,c.words.len() as u32);
    for &x in c.words.iter().chain(&c.output){push(b,x);}
}
// A call costs at least one permutation, at most 101 bytes per permutation.
fn max_frame(cap:usize)->usize{4+101*cap}
pub fn encode_frame(calls:&[Call],cap:usize)->Result<Vec<u8>,String>{
    if !allowed_cap(cap)||calls.is_empty()||calls.len()>cap||calls.iter().any(|c|!shape(c))
    ||calls.iter().map(Call::permutations).sum::<usize>()>cap{return Err("frame work/shape limit".into())}
    let mut b=Vec::new();push(&mut b,calls.len() as u32);
    for c in calls{put(&mut b,c);}
    if b.len()>max_frame(cap){return Err("frame byte limit".into())}
    Ok(b)
}
pub fn parse_frame(raw:&[u8],cap:usize)->Result<Vec<Call>,String>{
    if !allowed_cap(cap)||raw.len()>max_frame(cap){return Err("frame size/profile".into())}
    let mut p=0;let n=read_u32(raw,&mut p)? as usize;
    if n==0||n>cap{return Err("frame count".into())}
    let mut out=Vec::with_capacity(n);let mut work=0usize;
    for _ in 0..n{
        let kind=*raw.get(p).ok_or("truncated kind")?;p+=1;
        let k=read_u32(raw,&mut p)? as usize;
        if k>MAX_WORDS||raw.len().saturating_sub(p)<4*(k+8){return Err("word limit or truncated call".into())}
        work=work.checked_add(k.div_ceil(16).max(1)).ok_or("work overflow")?;
        if work>cap{return Err("frame permutation limit".into())}
        let mut words=Vec::with_capacity(k);
        for _ in 0..k{words.push(read_u32(raw,&mut p)?);}
        let mut output=[0;8];for x in &mut output{*x=read_u32(raw,&mut p)?;}
        let c=Call{kind,words,output};
        if !shape(&c){return Err("noncanonical call".into())}
        out.push(c);
    }
    if p!=raw.len(){return Err("trailing frame bytes".into())}
    Ok(out)
}
pub fn validate_frame(raw:&[u8],cap:usize)->Result<usize,String>{
    let calls=parse_frame(raw,cap)?;
    if calls.iter().any(|c|!c.valid_hash()){return Err("incorrect hash output".into())}
    Ok(calls.len())
}
pub fn partition(calls:&[Call],cap:usize)->Result<Vec<Vec<u8>>,String>{
    if !allowed_cap(cap)||calls.is_empty()||calls.len()>MAX_CALLS{return Err("call/profile limit".into())}
    let mut frames=Vec::new();let mut begin=0;let mut work=0;
    for(i,c)in calls.iter().enumerate(){
        let w=c.permutations();
        if !shape(c)||w>cap{return Err("oversized call".into())}
        if work+w>cap{frames.push(encode_frame(&calls[begin..i],cap)?);begin=i;work=0;}
        work+=w;
    }
    frames.push(encode_frame(&calls[begin..],cap)?);
    if frames.len()>MAX_BATCHES{return Err("batch limit".into())}
    Ok(frames)
}
/// Distinct initial domain binds the selected, immutable batch-work profile.
pub fn initial(hash:Hash32,receipt:[u8;32],image:[u32;8],journal:&[u8],count:u32,cap:usize)->[u8;32]{
    let old=shz_stark_hash_replay::initial_commitment(hash,receipt,image,journal,count);
    let mut b=b"SHZ/STARK/COMPACT/V1".to_vec();b.extend(old);push(&mut b,cap as u32);hash(&b)
}
#[derive(Clone,Debug)]
pub struct Tape{counts:Vec<usize>,outputs:Vec<[u32;8]>}
/// Wire: frame_count:u32le || frame_count count:u32le || all digest words.
pub fn output_tape(frames:&[Vec<u8>],cap:usize)->Result<Vec<u8>,String>{
    if frames.is_empty()||frames.len()>MAX_BATCHES{return Err("batch count".into())}
    let mut b=Vec::new();push(&mut b,frames.len() as u32);
    let mut outputs=Vec::new();
    for f in frames{
        let calls=parse_frame(f,cap)?;
        push(&mut b,calls.len() as u32);
        outputs.extend(calls.into_iter().map(|c|c.output));
        if outputs.len()>MAX_CALLS{return Err("total calls".into())}
    }
    for d in outputs{for x in d{push(&mut b,x);}}
    Ok(b)
}
pub fn decode_tape(raw:&[u8],count:usize,batches:usize,cap:usize)->Result<Tape,String>{
    if !allowed_cap(cap)||raw.len()>MAX_TAPE||count==0||count>MAX_CALLS||batches==0||batches>MAX_BATCHES{return Err("tape limits".into())}
    let mut p=0;let n=read_u32(raw,&mut p)? as usize;
    if n!=batches||raw.len()!=4+4*n+32*count{return Err("tape framing".into())}
    let mut counts=Vec::with_capacity(n);let mut sum=0usize;
    for _ in 0..n{
        let k=read_u32(raw,&mut p)? as usize;
        if k==0||k>cap{return Err("tape frame count".into())}
        sum=sum.checked_add(k).ok_or("tape count overflow")?;
        if sum>count{return Err("tape count".into())}
        counts.push(k);
    }
    if sum!=count{return Err("tape call total".into())}
    let mut outputs=Vec::with_capacity(count);
    for _ in 0..count{
        let mut d=[0;8];for x in &mut d{*x=read_u32(raw,&mut p)?;if *x>=P{return Err("noncanonical output".into())}}
        outputs.push(d);
    }
    if p!=raw.len(){return Err("trailing tape".into())}
    Ok(Tape{counts,outputs})
}
struct Cursor{
    root:[u8;32],idx:usize,frame_idx:usize,within:usize,
    work:usize,frame:Vec<u8>,bad:bool,
}
struct CompactHash{tape:Tape,cap:usize,hash:Hash32,state:Mutex<Cursor>}
impl CompactHash{
    fn next(&self,kind:u8,words:impl Iterator<Item=u32>)->Box<Digest>{
        let mut s=self.state.lock().unwrap();
        if s.bad{return Box::new(Digest::ZERO)}
        let Some(&output)=self.tape.outputs.get(s.idx)else{s.bad=true;return Box::new(Digest::ZERO)};
        let Some(&count)=self.tape.counts.get(s.frame_idx)else{s.bad=true;return Box::new(Digest::ZERO)};
        let c=Call{kind,words:words.take(MAX_WORDS+1).collect(),output};
        if !shape(&c)||s.work+c.permutations()>self.cap{s.bad=true;return Box::new(Digest::ZERO)}
        if s.within==0{push(&mut s.frame,count as u32);}
        put(&mut s.frame,&c);
        if s.frame.len()>max_frame(self.cap){s.bad=true;return Box::new(Digest::ZERO)}
        s.work+=c.permutations();s.idx+=1;s.within+=1;
        if s.within==count{
            s.root=extend_commitment(self.hash,s.root,(s.idx-count) as u32,&s.frame);
            s.frame.clear();s.within=0;s.work=0;s.frame_idx+=1;
        }
        Box::new(Digest::from(output))
    }
    fn outcome(&self,expected:[u8;32],upstream_verified:bool)->Outcome{
        let s=self.state.lock().unwrap();
        Outcome{upstream_verified,complete:!s.bad&&s.idx==self.tape.outputs.len()&&s.frame_idx==self.tape.counts.len()&&s.within==0&&s.frame.is_empty(),commitment_matches:s.root==expected}
    }
}
impl HashFn<BabyBear> for CompactHash{
    fn hash_pair(&self,a:&Digest,b:&Digest)->Box<Digest>{self.next(PAIR,a.as_words().iter().chain(b.as_words()).copied())}
    fn hash_elem_slice(&self,s:&[BabyBearElem])->Box<Digest>{self.next(BASE,s.iter().map(|e|e.as_u32_montgomery()))}
    fn hash_ext_elem_slice(&self,s:&[BabyBearExtElem])->Box<Digest>{self.next(EXT,s.iter().flat_map(|e|e.subelems().iter().map(|x|x.as_u32_montgomery())))}
    fn is_digest_valid(&self,d:&Digest)->bool{d.as_words().iter().all(|&x|x<P)}
}
#[derive(Clone,Debug)]
pub struct Outcome{pub upstream_verified:bool,pub complete:bool,pub commitment_matches:bool}
impl Outcome{pub fn accepted(&self)->bool{self.upstream_verified&&self.complete&&self.commitment_matches}}
/// PRECONDITION: expected is the contract's terminal commitment from actual
/// validated batch transactions. Never accept a relayer-selected expected root.
/// Original verifier equations and RNG execute unmodified. Its ACTUAL hash
/// inputs are serialized, joined to the tape outputs and committed during replay.
pub fn replay(r:&Receipt,image:[u32;8],tape:Tape,cap:usize,start:[u8;32],expected:[u8;32],hash:Hash32)->Outcome{
    let invalid=Outcome{upstream_verified:false,complete:false,commitment_matches:false};
    if !allowed_cap(cap){return invalid}
    let h=Rc::new(CompactHash{tape,cap,hash,state:Mutex::new(Cursor{root:start,idx:0,frame_idx:0,within:0,work:0,frame:Vec::new(),bad:false})});
    let p=SuccinctReceiptVerifierParameters::default();
    if p.control_root.to_string()!=CONTROL_ROOT{return invalid}
    let old=Poseidon2HashSuite::new_suite();
    let suite=HashSuite{name:old.name,hashfn:h.clone(),rng:old.rng};
    let ctx=VerifierContext::empty().with_suites(BTreeMap::from([("poseidon2".into(),suite)])).with_succinct_verifier_parameters(p);
    let verified=r.verify_with_context(&ctx,image).is_ok();
    h.outcome(expected,verified)
}
#[cfg(test)]
mod tests{
    use super::*;
    fn sample()->Call{let mut c=Call{kind:PAIR,words:(1..=16).collect(),output:[0;8]};c.output=c.computed();c}
    #[test]fn canonical_encoding_and_tape(){
        for cap in PROFILES{
            let c=sample();let f=encode_frame(&[c.clone(),c.clone()],cap).unwrap();
            assert_eq!(validate_frame(&f,cap).unwrap(),2);
            let t=output_tape(&[f],cap).unwrap();
            let v=decode_tape(&t,2,1,cap).unwrap();
            assert_eq!(v.counts,vec![2]);assert_eq!(v.outputs,vec![c.output,c.output]);
            assert!(decode_tape(&t,1,1,cap).is_err());assert!(decode_tape(&t,2,2,cap).is_err());
            let mut bad=t.clone();bad.push(0);assert!(decode_tape(&bad,2,1,cap).is_err());
            let mut bad=t;bad[8..12].copy_from_slice(&P.to_le_bytes());assert!(decode_tape(&bad,2,1,cap).is_err());
        }
    }
    #[test]fn limits_and_canonicality(){
        let c=sample();
        assert!(encode_frame(&[c.clone()],4096).is_err());
        let big=vec![c.clone();513];assert!(encode_frame(&big,512).is_err());
        let f=encode_frame(&big,2048).unwrap();assert!(parse_frame(&f,512).is_err());
        let mut bad=encode_frame(&[c],512).unwrap();bad[9..13].copy_from_slice(&P.to_le_bytes());assert!(parse_frame(&bad,512).is_err());
    }
    #[test]fn actual_inputs_are_committed_and_boundaries_matter(){
        let c=sample();let f=encode_frame(&[c.clone()],512).unwrap();
        let start=[1;32];let expected=extend_commitment(sha,start,0,&f);
        let h=CompactHash{tape:decode_tape(&output_tape(&[f],512).unwrap(),1,1,512).unwrap(),cap:512,hash:sha,state:Mutex::new(Cursor{root:start,idx:0,frame_idx:0,within:0,work:0,frame:Vec::new(),bad:false})};
        assert_eq!(h.next(PAIR,c.words.iter().copied()).as_words(),&c.output);assert!(h.outcome(expected,true).accepted());
        assert!(!h.outcome([2;32],true).accepted());
        h.next(PAIR,c.words.iter().copied());assert!(!h.outcome(expected,true).accepted());
    }
}
