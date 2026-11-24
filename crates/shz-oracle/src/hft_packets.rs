//! HFT-04 reference: scoped, quorum-certified fast oracle packets.
//! Synthetic source evidence only. Independent signatures, not production FROST.
//! The access entitlement, real clocks, transport, durable signer locks,
//! source adapters and Lightning settlement remain external engineering gates.
use shz_dlc::{Bip340Signature,bip340_sign,bip340_verify,pubkey_x_from_secret,tagged_hash};
use std::collections::{BTreeMap,BTreeSet};

pub type Hash=[u8;32];
pub const CADENCE_US:u64=200_000;
pub const EARLY_US:u64=200_000;
pub const MAX_CLOCK_ERROR_US:u64=5_000;
pub const MAX_SOURCE_AGE_US:u64=1_000_000;
pub const MAX_SOURCE_SKEW_US:u64=500_000;
pub const QUORUM:usize=4;
const ORDER:[u8;32]=[
 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
 0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
];
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Error{Policy,Scope,Bounds,Source,Signature,Quorum,Equivocation,Sequence,Clock,Window,Hold}
type R<T>=Result<T,Error>;
fn n(b:&mut Vec<u8>,v:u64){b.extend(v.to_le_bytes())}

#[derive(Debug,Clone)]
pub struct Policy{
 pub network:Hash,pub market:Hash,pub epoch:u64,pub origin_us:u64,pub members:[Hash;5],
}
impl Policy{
 pub fn id(&self)->R<Hash>{
  if self.network==[0;32]||self.market==[0;32]||self.epoch==0||self.origin_us==0||
     self.members.iter().any(|k|*k==[0;32])||
     self.members.iter().collect::<BTreeSet<_>>().len()!=5{return Err(Error::Policy)}
  let mut b=Vec::new();b.extend(self.network);b.extend(self.market);n(&mut b,self.epoch);n(&mut b,self.origin_us);
  for k in self.members{b.extend(k)}
  for v in [CADENCE_US,EARLY_US,MAX_CLOCK_ERROR_US,MAX_SOURCE_AGE_US,MAX_SOURCE_SKEW_US,QUORUM as u64,50]{n(&mut b,v)}
  Ok(tagged_hash(b"SHZ/HFT/PACKET-POLICY/V1",&b))
 }
 pub fn fast_at(&self,seq:u64)->R<u64>{
  self.origin_us.checked_add(seq.checked_sub(1).ok_or(Error::Sequence)?.checked_mul(CADENCE_US).ok_or(Error::Bounds)?).ok_or(Error::Bounds)
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Source{pub report:Hash,pub published_us:u64,pub price_e8:u64}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Mark{Valid{pyth:Source,chainlink:Source},Hold{reason:u8}}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Packet{pub policy:Hash,pub seq:u64,pub previous:Hash,pub mark:Mark}
impl Packet{
 pub fn digest(&self)->Hash{
  let mut b=Vec::new();b.extend(self.policy);n(&mut b,self.seq);b.extend(self.previous);
  match self.mark{
   Mark::Hold{reason}=>{b.push(0);b.push(reason);}
   Mark::Valid{pyth,chainlink}=>{
    b.push(1);
    for s in [pyth,chainlink]{b.extend(s.report);n(&mut b,s.published_us);n(&mut b,s.price_e8)}
   }
  }
  tagged_hash(b"SHZ/HFT/PACKET/V1",&b)
 }
 fn validate(&self,p:&Policy)->R<()>{
  if self.policy!=p.id()?{return Err(Error::Scope)}
  let t=p.fast_at(self.seq)?;
  if (self.seq==1)!=(self.previous==[0;32]){return Err(Error::Sequence)}
  match self.mark{
   Mark::Hold{reason}=>if !(1..=3).contains(&reason){return Err(Error::Bounds)},
   Mark::Valid{pyth,chainlink}=>{
    if pyth.report==chainlink.report{return Err(Error::Source)}
    for s in [pyth,chainlink]{
     if s.report==[0;32]||s.published_us==0||s.price_e8==0||s.price_e8>10_000_000_000_000_000||
       !t.checked_sub(s.published_us).is_some_and(|a|a<=MAX_SOURCE_AGE_US){return Err(Error::Source)}
    }
    if pyth.published_us.abs_diff(chainlink.published_us)>MAX_SOURCE_SKEW_US||
       pyth.price_e8.abs_diff(chainlink.price_e8)as u128*20_000>50*(pyth.price_e8 as u128+chainlink.price_e8 as u128){return Err(Error::Source)}
   }
  }
  Ok(())
 }
 pub fn price(&self)->Option<u64>{
  match self.mark{Mark::Valid{pyth,chainlink}=>Some(((pyth.price_e8 as u128+chainlink.price_e8 as u128)/2)as u64),Mark::Hold{..}=>None}
 }
}
#[derive(Debug,Clone)]
pub struct Vote{pub member:u8,pub signature:Bip340Signature}
#[derive(Debug,Clone)]
pub struct Certificate{pub packet:Packet,pub votes:Vec<Vote>}
impl Certificate{
 pub fn verify(&self,p:&Policy)->R<Hash>{
  self.packet.validate(p)?;
  if !(QUORUM..=5).contains(&self.votes.len()){return Err(Error::Quorum)}
  let digest=self.packet.digest();let mut seen=BTreeSet::new();
  for v in &self.votes{
   let key=p.members.get(v.member as usize).ok_or(Error::Quorum)?;
   if !seen.insert(v.member){return Err(Error::Quorum)}
   if v.signature.s>=ORDER{return Err(Error::Signature)}
   bip340_verify(key,&digest,&v.signature).map_err(|_|Error::Signature)?;
  }
  Ok(digest)
 }
}
/// One-vote-per-slot test lock. A production signer MUST durably persist and
/// fence the lock before signing, independently verify raw source reports,
/// and implement safe proposal coordination. In-memory restart is unsafe.
pub struct Signer{secret:Hash,member:u8,policy:Hash,locked:BTreeMap<u64,Hash>}
impl Signer{
 pub fn new(p:&Policy,member:u8,secret:Hash)->R<Self>{
  if p.members.get(member as usize)!=Some(&pubkey_x_from_secret(&secret).map_err(|_|Error::Signature)?){return Err(Error::Policy)}
  Ok(Self{secret,member,policy:p.id()?,locked:BTreeMap::new()})
 }
 pub fn vote(&mut self,p:&Policy,packet:&Packet)->R<Vote>{
  if self.policy!=p.id()?{return Err(Error::Scope)}
  packet.validate(p)?;let digest=packet.digest();
  if self.locked.get(&packet.seq).is_some_and(|v|*v!=digest){return Err(Error::Equivocation)}
  self.locked.insert(packet.seq,digest);
  Ok(Vote{member:self.member,signature:bip340_sign(&self.secret,&digest).map_err(|_|Error::Signature)?})
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Tier{Fast,Public}
/// A receiver is provisioned in one tier by an external entitlement policy.
/// This gate neither provides access control nor proves real-world time.
pub struct Receiver{policy:Policy,tier:Tier,seq:u64,last:Hash,packet:Option<Packet>,clock:u64}
impl Receiver{
 pub fn new(policy:Policy,tier:Tier)->R<Self>{policy.id()?;Ok(Self{policy,tier,seq:0,last:[0;32],packet:None,clock:0})}
 fn clock(&mut self,now:u64,error:u64)->R<()>{
  if now<self.clock||error>MAX_CLOCK_ERROR_US||now.checked_sub(error).is_none()||now.checked_add(error).is_none(){return Err(Error::Clock)}
  self.clock=now;Ok(())
 }
 fn check_window(&self,seq:u64,now:u64,error:u64)->R<()>{
  let start=self.policy.fast_at(seq)?.checked_add(if self.tier==Tier::Fast{0}else{EARLY_US}).ok_or(Error::Bounds)?;
  let end=start.checked_add(CADENCE_US).ok_or(Error::Bounds)?;
  // Both ends conservative: do not admit before release, do not keep old
  // packet alive after the next scheduled slot if a new packet is missing.
  if now.checked_sub(error).ok_or(Error::Clock)?<start||now.checked_add(error).ok_or(Error::Clock)? >= end{return Err(Error::Window)}
  Ok(())
 }
 pub fn accept(&mut self,cert:&Certificate,now:u64,error:u64)->R<Hash>{
  self.clock(now,error)?;let digest=cert.verify(&self.policy)?;
  if cert.packet.seq!=self.seq.checked_add(1).ok_or(Error::Sequence)?||cert.packet.previous!=self.last{return Err(Error::Sequence)}
  self.check_window(cert.packet.seq,now,error)?;
  self.seq=cert.packet.seq;self.last=digest;self.packet=Some(cert.packet.clone());Ok(digest)
 }
 pub fn mark(&mut self,now:u64,error:u64)->R<(u64,Hash,u64)>{
  self.clock(now,error)?;let packet=self.packet.as_ref().ok_or(Error::Sequence)?;
  self.check_window(packet.seq,now,error)?;
  let Mark::Valid{pyth,chainlink}=packet.mark else{return Err(Error::Hold)};
  let latest=now.checked_add(error).ok_or(Error::Clock)?;
  if [pyth,chainlink].iter().any(|s|!latest.checked_sub(s.published_us).is_some_and(|a|a<=MAX_SOURCE_AGE_US)){return Err(Error::Source)}
  Ok((packet.seq,self.last,packet.price().ok_or(Error::Hold)?))
 }
}

#[cfg(test)]
mod tests{
 use super::*;
 const START:u64=10_000_000;
 fn fixture()->(Policy,Vec<Signer>){
  let p=Policy{network:[9;32],market:[8;32],epoch:1,origin_us:START,members:std::array::from_fn(|i|pubkey_x_from_secret(&[(i+1)as u8;32]).unwrap())};
  let ss=(0..5).map(|i|Signer::new(&p,i,[(i+1)as u8;32]).unwrap()).collect();(p,ss)
 }
 fn packet(p:&Policy,seq:u64,previous:Hash)->Packet{
  let at=p.fast_at(seq).unwrap();
  Packet{policy:p.id().unwrap(),seq,previous,mark:Mark::Valid{
   pyth:Source{report:[1;32],published_us:at-20_000,price_e8:10_000_000_000_000},
   chainlink:Source{report:[2;32],published_us:at-30_000,price_e8:10_001_000_000_000}}}
 }
 fn certify(p:&Policy,ss:&mut[Signer],packet:Packet)->Certificate{
  let votes=ss.iter_mut().take(4).map(|s|s.vote(p,&packet).unwrap()).collect();Certificate{packet,votes}
 }
 #[test]fn release_gap_and_fail_closed(){
  let(p,mut ss)=fixture();let c=certify(&p,&mut ss,packet(&p,1,[0;32]));
  let mut fast=Receiver::new(p.clone(),Tier::Fast).unwrap();
  let mut public=Receiver::new(p.clone(),Tier::Public).unwrap();
  assert_eq!(fast.accept(&c,START+4_999,5_000),Err(Error::Window));
  let d=fast.accept(&c,START+5_000,5_000).unwrap();
  assert_eq!(fast.mark(START+5_001,5_000).unwrap().1,d);
  assert_eq!(public.accept(&c,START+204_999,5_000),Err(Error::Window));
  assert_eq!(public.accept(&c,START+205_000,5_000).unwrap(),d);
  assert_eq!(public.mark(START+205_000,5_000).unwrap().1,d);
  assert_eq!(fast.mark(START+195_000,5_000),Err(Error::Window));
  let mut q=packet(&p,2,d);q.mark=Mark::Hold{reason:1};
  let c2=certify(&p,&mut ss,q);fast.accept(&c2,START+205_000,5_000).unwrap();
  assert_eq!(fast.mark(START+205_000,5_000),Err(Error::Hold));
  assert_eq!(fast.accept(&c,START+205_001,5_000),Err(Error::Sequence));
  assert_eq!(fast.mark(START+205_000,5_000),Err(Error::Clock));
 }
 #[test]fn quorum_rejects_duplicate_signer_and_equivocation(){
  let(p,mut ss)=fixture();let q=packet(&p,1,[0;32]);let c=certify(&p,&mut ss,q.clone());
  assert!(c.verify(&p).is_ok());
  let mut bad=c.clone();bad.votes.pop();assert_eq!(bad.verify(&p),Err(Error::Quorum));
  let mut bad=c.clone();bad.votes[3]=bad.votes[0].clone();assert_eq!(bad.verify(&p),Err(Error::Quorum));
  let mut alt=q;alt.mark=Mark::Hold{reason:2};
  assert_eq!(ss[0].vote(&p,&alt).unwrap_err(),Error::Equivocation);
  let mut bad=c.clone();bad.packet=alt;assert_eq!(bad.verify(&p),Err(Error::Signature));
  // All two four-of-five sets intersect in at least three nodes,
  // so at most one Byzantine cannot create two conflicting certificates
  // given durable honest locks (durability is not implemented here).
  for a in 0..5{for b in 0..5{
   assert!((0..5).filter(|&i|i!=a&&i!=b).count()>=3);
  }}
 }
 #[test]fn source_and_chain_bounds(){
  let(p,mut ss)=fixture();let mut q=packet(&p,1,[0;32]);
  if let Mark::Valid{ref mut pyth,..}=q.mark{pyth.published_us=START+1;}
  assert_eq!(ss[0].vote(&p,&q).unwrap_err(),Error::Source);
  let mut q=packet(&p,1,[0;32]);if let Mark::Valid{ref mut pyth,..}=q.mark{pyth.price_e8*=2;}
  assert_eq!(ss[0].vote(&p,&q).unwrap_err(),Error::Source);
  let c=certify(&p,&mut ss,packet(&p,2,[77;32]));let mut rx=Receiver::new(p,Tier::Fast).unwrap();
  assert_eq!(rx.accept(&c,START+205_000,5_000),Err(Error::Sequence));
  assert_eq!(rx.accept(&c,START+205_001,5_001),Err(Error::Clock));
 }
 #[test]fn stale_report_dies_even_with_valid_certificate(){
  let(p,mut ss)=fixture();let mut q=packet(&p,1,[0;32]);
  if let Mark::Valid{ref mut pyth,ref mut chainlink}=q.mark{
   pyth.published_us=START-900_000;chainlink.published_us=START-900_000;
  }
  let c=certify(&p,&mut ss,q);let mut rx=Receiver::new(p,Tier::Public).unwrap();
  rx.accept(&c,START+205_000,5_000).unwrap();
  assert_eq!(rx.mark(START+205_000,5_000),Err(Error::Source));
 }
}
