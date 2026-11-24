//! ADMIT-11: bounded, authenticated hash replay for the patched succinct STARK.
//! Only batches of actual Poseidon2 computations can extend the cache commitment.
//! Final replay still executes every upstream STARK verification equation.
//! No acceptance based solely on a transcript, receipt hash or batch count.
#![forbid(unsafe_code)]
use bincode::Options;
use risc0_core::field::{baby_bear::{BabyBear,BabyBearElem,BabyBearExtElem,P},ExtElem};
use risc0_zkp::core::{digest::Digest,hash::{HashFn,HashSuite,poseidon2::Poseidon2HashSuite}};
use risc0_zkvm::{Receipt,InnerReceipt,VerifierContext,SuccinctReceiptVerifierParameters};
use shz_stark_fast_hash::FastHash;
use sha2::{Digest as ShaDigest,Sha256};
use std::{collections::BTreeMap,rc::Rc,sync::{Arc,Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}}};

pub const CONTROL_ROOT:&str="e6feef13db7aed4a731c7b0852de1f5c89b137726073f625d05333184d3a551d";
pub const MAX_RECEIPT:usize=1024*1024;
pub const MAX_TRANSCRIPT:usize=1024*1024;
pub const MAX_FRAME:usize=64*1024;
pub const MAX_BATCH_PERMUTATIONS:usize=512;
pub const MAX_BATCH_CALLS:usize=512;
pub const MAX_CALLS:usize=8192;
pub const MAX_BATCHES:usize=64;
pub const PAIR:u8=0;
pub const BASE:u8=1;
pub const EXT:u8=2;
pub type Hash32=fn(&[u8])->[u8;32];
pub fn sha(b:&[u8])->[u8;32]{Sha256::digest(b).into()}

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Call{pub kind:u8,pub words:Vec<u32>,pub output:[u32;8]}
impl Call{
    pub fn permutations(&self)->usize{self.words.len().div_ceil(16).max(1)}
    fn valid_shape(&self)->bool{
        matches!(self.kind,PAIR|BASE|EXT)
        && (self.kind!=PAIR || self.words.len()==16)
        && (self.kind!=EXT || self.words.len()%4==0)
        && self.words.len()<=MAX_BATCH_PERMUTATIONS*16
        && self.words.iter().chain(&self.output).all(|&x|x<P)
    }
    pub fn computed(&self)->[u32;8]{
        // All three upstream interfaces flatten to the same unpadded sponge.
        // Canonical input/type/length checks are performed BEFORE computing.
        let e=self.words.iter().map(|&w|BabyBearElem::new_raw(w)).collect::<Vec<_>>();
        FastHash.hash_elem_slice(&e).as_words().try_into().unwrap()
    }
    pub fn valid_hash(&self)->bool{self.valid_shape() && self.computed()==self.output}
}
fn push_u32(b:&mut Vec<u8>,n:u32){b.extend(n.to_le_bytes());}
fn u32_at(b:&[u8],p:&mut usize)->Result<u32,String>{
    let end=p.checked_add(4).ok_or("offset overflow")?;
    let out=u32::from_le_bytes(b.get(*p..end).ok_or("truncated u32")?.try_into().unwrap());
    *p=end;Ok(out)
}
fn put_call(b:&mut Vec<u8>,c:&Call){
    b.push(c.kind);push_u32(b,c.words.len() as u32);
    for w in c.words.iter().chain(&c.output){push_u32(b,*w);}
}
pub fn encode_frame(calls:&[Call])->Result<Vec<u8>,String>{
    if calls.is_empty()||calls.len()>MAX_BATCH_CALLS{return Err("batch call cap".into())}
    if calls.iter().any(|c|!c.valid_shape())||calls.iter().map(Call::permutations).sum::<usize>()>MAX_BATCH_PERMUTATIONS{return Err("batch work/shape cap".into())}
    let mut b=Vec::new();push_u32(&mut b,calls.len() as u32);
    for c in calls{put_call(&mut b,c);}
    if b.len()>MAX_FRAME{return Err("frame byte cap".into())}
    Ok(b)
}
pub fn parse_frame(raw:&[u8])->Result<Vec<Call>,String>{
    if raw.len()>MAX_FRAME{return Err("frame byte cap".into())}
    let mut p=0;let n=u32_at(raw,&mut p)? as usize;
    if n==0||n>MAX_BATCH_CALLS{return Err("frame count".into())}
    let mut calls=Vec::with_capacity(n);let mut work=0usize;
    for _ in 0..n{
        let kind=*raw.get(p).ok_or("truncated kind")?;p+=1;
        let len=u32_at(raw,&mut p)? as usize;
        if len>MAX_BATCH_PERMUTATIONS*16{return Err("word cap".into())}
        work=work.checked_add(len.div_ceil(16).max(1)).ok_or("work overflow")?;
        if work>MAX_BATCH_PERMUTATIONS{return Err("frame permutation cap".into())}
        if !matches!(kind,PAIR|BASE|EXT)||(kind==PAIR&&len!=16)||(kind==EXT&&len%4!=0){return Err("wrong interface shape".into())}
        if raw.len().saturating_sub(p)<4*(len+8){return Err("truncated call".into())}
        let mut words=Vec::with_capacity(len);
        for _ in 0..len{words.push(u32_at(raw,&mut p)?);}
        let mut output=[0;8];for x in &mut output{*x=u32_at(raw,&mut p)?;}
        let c=Call{kind,words,output};if !c.valid_shape(){return Err("noncanonical field words".into())}calls.push(c);
    }
    if p!=raw.len(){return Err("trailing frame bytes".into())}
    Ok(calls)
}
pub fn validate_frame(raw:&[u8])->Result<usize,String>{
    let calls=parse_frame(raw)?;
    if calls.iter().any(|c|!c.valid_hash()){return Err("false Poseidon2 computation".into())}
    Ok(calls.len())
}
pub fn initial_commitment(hash:Hash32,receipt:[u8;32],image:[u32;8],journal:&[u8],count:u32)->[u8;32]{
    let mut b=b"SHZ/STARK/CACHE/START/V1".to_vec();
    b.extend(receipt);for w in image{push_u32(&mut b,w);}
    push_u32(&mut b,journal.len() as u32);b.extend(journal);push_u32(&mut b,count);
    hash(&b)
}
pub fn extend_commitment(hash:Hash32,previous:[u8;32],offset:u32,frame:&[u8])->[u8;32]{
    let mut b=b"SHZ/STARK/CACHE/BATCH/V1".to_vec();
    b.extend(previous);push_u32(&mut b,offset);push_u32(&mut b,frame.len() as u32);b.extend(frame);
    hash(&b)
}
pub fn encode_transcript(frames:&[Vec<u8>])->Result<Vec<u8>,String>{
    if frames.is_empty()||frames.len()>MAX_BATCHES{return Err("frame count cap".into())}
    let mut out=Vec::new();
    for f in frames{parse_frame(f)?;push_u32(&mut out,f.len() as u32);out.extend(f);}
    if out.len()>MAX_TRANSCRIPT{return Err("transcript cap".into())}Ok(out)
}
/// Reconstruct commitment from the exact bytes to be consumed by the verifier.
/// This is only a parsing/commitment check; call hashes were verified in the
/// preceding stateful transactions. Do not use this as a standalone validator.
pub fn open_transcript(hash:Hash32,initial:[u8;32],raw:&[u8])->Result<(Vec<Call>,[u8;32],usize),String>{
    if raw.is_empty()||raw.len()>MAX_TRANSCRIPT{return Err("transcript cap".into())}
    let mut p=0;let mut calls=Vec::new();let mut root=initial;let mut frames=0;
    while p<raw.len(){
        let n=u32_at(raw,&mut p)? as usize;
        if n==0||n>MAX_FRAME||frames==MAX_BATCHES{return Err("frame cap".into())}
        let end=p.checked_add(n).ok_or("frame overflow")?;
        let b=raw.get(p..end).ok_or("truncated transcript")?;
        let next=parse_frame(b)?;
        if calls.len()+next.len()>MAX_CALLS{return Err("transcript call cap".into())}
        root=extend_commitment(hash,root,calls.len() as u32,b);
        calls.extend(next);frames+=1;p=end;
    }
    Ok((calls,root,frames))
}
pub fn partition(calls:&[Call])->Result<Vec<Vec<u8>>,String>{
    if calls.is_empty()||calls.len()>MAX_CALLS{return Err("call cap".into())}
    let mut frames=Vec::new();let mut start=0;let mut work=0;
    for(i,c)in calls.iter().enumerate(){
        let w=c.permutations();
        if w>MAX_BATCH_PERMUTATIONS||!c.valid_shape(){return Err("call too large".into())}
        if i-start==MAX_BATCH_CALLS||work+w>MAX_BATCH_PERMUTATIONS{
            frames.push(encode_frame(&calls[start..i])?);start=i;work=0;
        }
        work+=w;
    }
    frames.push(encode_frame(&calls[start..])?);
    encode_transcript(&frames)?;Ok(frames)
}

fn canonical_digest(d:&Digest)->bool{d.as_words().iter().all(|&x|x<P)}
fn verify_context(suite:HashSuite<BabyBear>)->Result<VerifierContext,String>{
    let p=SuccinctReceiptVerifierParameters::default();
    if p.control_root.to_string()!=CONTROL_ROOT{return Err("wrong patched control root".into())}
    Ok(VerifierContext::empty().with_suites(BTreeMap::from([("poseidon2".into(),suite)])).with_succinct_verifier_parameters(p))
}
pub fn decode_receipt(raw:&[u8],expected:&[u8])->Result<Receipt,String>{
    if raw.len()<4||raw.len()>MAX_RECEIPT||raw[..4]!=1u32.to_le_bytes(){return Err("receipt cap/kind".into())}
    let r:Receipt=bincode::DefaultOptions::new().with_fixint_encoding().with_limit(MAX_RECEIPT as u64).reject_trailing_bytes().deserialize(raw).map_err(|e|e.to_string())?;
    if !matches!(&r.inner,InnerReceipt::Succinct(s) if s.hashfn=="poseidon2")||r.journal.bytes!=expected{return Err("receipt type/journal mismatch".into())}
    Ok(r)
}

/// Native trace collector: actual upstream verification, retaining each exact
/// input and output. Trace generation is untrusted by the contract.
struct TraceHash(Arc<Mutex<Vec<Call>>>);
impl TraceHash{
    fn record(&self,kind:u8,words:Vec<u32>,d:Box<Digest>)->Box<Digest>{
        self.0.lock().unwrap().push(Call{kind,words,output:d.as_words().try_into().unwrap()});d
    }
}
impl HashFn<BabyBear> for TraceHash{
    fn hash_pair(&self,a:&Digest,b:&Digest)->Box<Digest>{
        self.record(PAIR,a.as_words().iter().chain(b.as_words()).copied().collect(),Poseidon2HashSuite::new_suite().hashfn.hash_pair(a,b))
    }
    fn hash_elem_slice(&self,s:&[BabyBearElem])->Box<Digest>{
        self.record(BASE,s.iter().map(|e|e.as_u32_montgomery()).collect(),Poseidon2HashSuite::new_suite().hashfn.hash_elem_slice(s))
    }
    fn hash_ext_elem_slice(&self,s:&[BabyBearExtElem])->Box<Digest>{
        self.record(EXT,s.iter().flat_map(|e|e.subelems().iter().map(|w|w.as_u32_montgomery())).collect(),Poseidon2HashSuite::new_suite().hashfn.hash_ext_elem_slice(s))
    }
    fn is_digest_valid(&self,d:&Digest)->bool{canonical_digest(d)}
}
pub fn trace(r:&Receipt,image:[u32;8])->Result<Vec<Call>,String>{
    let calls=Arc::new(Mutex::new(Vec::new()));let original=Poseidon2HashSuite::new_suite();
    let suite=HashSuite{name:original.name,hashfn:Rc::new(TraceHash(calls.clone())),rng:original.rng};
    r.verify_with_context(&verify_context(suite)?,image).map_err(|e|format!("{e:?}"))?;
    let out=std::mem::take(&mut *calls.lock().unwrap());
    if out.len()>MAX_CALLS{return Err("trace call cap".into())}
    Ok(out)
}

struct ReplayHash{
    calls:Vec<Call>,cursor:AtomicUsize,bad:AtomicBool,
}
impl ReplayHash{
    fn next(&self,kind:u8,mut words:impl Iterator<Item=u32>)->Box<Digest>{
        let i=self.cursor.fetch_add(1,Ordering::Relaxed);
        let Some(c)=self.calls.get(i)else{self.bad.store(true,Ordering::Relaxed);return Box::new(Digest::ZERO)};
        if kind!=c.kind{self.bad.store(true,Ordering::Relaxed);}
        for &w in &c.words{
            if words.next()!=Some(w){self.bad.store(true,Ordering::Relaxed);}
        }
        if words.next().is_some(){self.bad.store(true,Ordering::Relaxed);}
        Box::new(Digest::from(c.output))
    }
    fn complete(&self)->bool{
        !self.bad.load(Ordering::Relaxed)&&self.cursor.load(Ordering::Relaxed)==self.calls.len()
    }
}
impl HashFn<BabyBear> for ReplayHash{
    fn hash_pair(&self,a:&Digest,b:&Digest)->Box<Digest>{
        self.next(PAIR,a.as_words().iter().chain(b.as_words()).copied())
    }
    fn hash_elem_slice(&self,s:&[BabyBearElem])->Box<Digest>{
        self.next(BASE,s.iter().map(|e|e.as_u32_montgomery()))
    }
    fn hash_ext_elem_slice(&self,s:&[BabyBearExtElem])->Box<Digest>{
        self.next(EXT,s.iter().flat_map(|e|e.subelems().iter().map(|w|w.as_u32_montgomery())))
    }
    fn is_digest_valid(&self,d:&Digest)->bool{canonical_digest(d)}
}
/// PRECONDITION: calls must come from a commitment whose every batch was
/// cryptographically recomputed, and whose complete opening has been checked.
/// A matching but unvalidated transcript is not a proof.
/// The actual upstream verifier still checks the seal, Merkle authentication,
/// FRI, transcript challenges, circuit equations, claim and journal binding.
/// The original RNG is retained; all hash inputs are compared word for word.
pub fn verify_with_validated_calls(r:&Receipt,image:[u32;8],calls:Vec<Call>)->bool{
    if calls.is_empty()||calls.len()>MAX_CALLS{return false}
    let h=Rc::new(ReplayHash{calls,cursor:AtomicUsize::new(0),bad:AtomicBool::new(false)});
    let original=Poseidon2HashSuite::new_suite();
    let suite=HashSuite{name:original.name,hashfn:h.clone(),rng:original.rng};
    let Ok(ctx)=verify_context(suite)else{return false};
    r.verify_with_context(&ctx,image).is_ok()&&h.complete()
}

#[cfg(test)]
mod tests{
    use super::*;
    fn sample()->Call{let mut c=Call{kind:PAIR,words:(1..=16).collect(),output:[0;8]};c.output=c.computed();c}
    #[test]fn valid_batch_and_exact_reopen(){
        let frames=partition(&[sample(),sample()]).unwrap();
        let start=initial_commitment(sha,[1;32],[2;8],b"journal",2);
        let root=extend_commitment(sha,start,0,&frames[0]);
        assert_eq!(validate_frame(&frames[0]).unwrap(),2);
        let(c,r,n)=open_transcript(sha,start,&encode_transcript(&frames).unwrap()).unwrap();
        assert_eq!(c,vec![sample(),sample()]);assert_eq!(r,root);assert_eq!(n,1);
    }
    #[test]fn bad_hash_canonicality_and_framing(){
        let mut c=sample();c.output[0]=(c.output[0]+1)%P;
        assert!(validate_frame(&encode_frame(&[c]).unwrap()).is_err());
        let mut f=encode_frame(&[sample()]).unwrap();
        f[9..13].copy_from_slice(&P.to_le_bytes());assert!(validate_frame(&f).is_err());
        let mut f=encode_frame(&[sample()]).unwrap();f.push(0);assert!(parse_frame(&f).is_err());
        assert!(parse_frame(&f[..4]).is_err());
    }
    #[test]fn bounded_work_and_nonempty(){
        let c=sample();
        assert!(encode_frame(&[]).is_err());
        assert!(encode_frame(&vec![c.clone();MAX_BATCH_CALLS+1]).is_err());
        let big=Call{kind:BASE,words:vec![0;16*MAX_BATCH_PERMUTATIONS],output:[0;8]};
        assert!(encode_frame(&[big,c]).is_err());
    }
    #[test]fn commitment_binds_order_offset_and_receipt(){
        let a=sample();let mut b=a.clone();b.words[0]=19;b.output=b.computed();
        let f=encode_frame(&[a.clone(),b.clone()]).unwrap();let g=encode_frame(&[b,a]).unwrap();
        let z=initial_commitment(sha,[1;32],[2;8],b"j",2);
        assert_ne!(extend_commitment(sha,z,0,&f),extend_commitment(sha,z,0,&g));
        assert_ne!(extend_commitment(sha,z,0,&f),extend_commitment(sha,z,1,&f));
        assert_ne!(z,initial_commitment(sha,[2;32],[2;8],b"j",2));
    }
    #[test]fn replay_requires_exact_interface_order_and_exhaustion(){
        let c=sample();let h=ReplayHash{calls:vec![c.clone()],cursor:AtomicUsize::new(0),bad:AtomicBool::new(false)};
        assert!(!h.complete());h.next(BASE,c.words.iter().copied());assert!(!h.complete());
        let h=ReplayHash{calls:vec![c.clone()],cursor:AtomicUsize::new(0),bad:AtomicBool::new(false)};
        assert_eq!(h.next(PAIR,c.words.iter().copied()).as_words(),&c.output);assert!(h.complete());h.next(PAIR,c.words.into_iter());assert!(!h.complete());
    }
}
