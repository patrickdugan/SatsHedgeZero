//! HFT-01 research router: signed scoped intents, immutable collateral partitions,
//! cached dual-relay marks, delayed eligibility and separately accounted priority fees.
//! One trusted single writer per router; no live LN funding or settlement authority.
use crate::OrderSide;
use shz_dlc::{Bip340Signature,BtcOutPoint,bip340_sign,bip340_verify,pubkey_x_from_secret,tagged_hash};
use shz_margin::{InverseContractSpec,ZeroFeePolicy};
use std::collections::{BTreeMap,BTreeSet};
type Key=[u8;32];
type Outpoint=([u8;32],u32);
type BookKey=(u64,u64);
const ORDER_CAP:usize=200_000;
const MAX_NOTIONAL:u64=1_000_000;
const MAX_PRICE:u64=100_000_000;
pub const MAKER_PPM:u32=20;
pub const TAKER_PPM:u32=200;
pub const ORACLE_SHARE_BPS:u64=7000;
pub const MAX_AGE_US:u64=1_000_000;
pub const MAX_SKEW_US:u64=500_000;
pub const COLLAR_BPS:u128=200;
const SECP_ORDER:[u8;32]=[
 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
 0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
];
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Reject{Scope,Signature,Allocation,Replay,Bounds,Clock,Oracle,Expired,Capacity,NoLiquidity,FeeLimit,UnknownOrder}
type R<T>=Result<T,Reject>;
fn verify(key:&Key,msg:&Key,sig:&Bip340Signature)->R<()>{
 if sig.s>=SECP_ORDER{return Err(Reject::Signature)}
 bip340_verify(key,msg,sig).map_err(|_|Reject::Signature)
}
fn sign(sk:&Key,msg:&Key)->R<Bip340Signature>{bip340_sign(sk,msg).map_err(|_|Reject::Signature)}
pub fn public(sk:&Key)->Key{pubkey_x_from_secret(sk).expect("valid signing key")}
fn op(o:&BtcOutPoint)->Outpoint{(o.txid,o.vout)}
fn u32b(b:&mut Vec<u8>,n:u32){b.extend(n.to_le_bytes())}
fn u64b(b:&mut Vec<u8>,n:u64){b.extend(n.to_le_bytes())}
fn put_op(b:&mut Vec<u8>,o:&BtcOutPoint){b.extend(o.txid);u32b(b,o.vout)}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Scope{pub network:Key,pub epoch:u64,pub policy:Key}
impl Scope{
 fn put(&self,b:&mut Vec<u8>){b.extend(self.network);u64b(b,self.epoch);b.extend(self.policy)}
}
#[derive(Debug,Clone)]
pub struct Policy{pub network:Key,pub epoch:u64,pub relay_keys:[Key;2]}
impl Policy{
 pub fn scope(&self)->Scope{
  let mut b=Vec::new();b.extend(self.relay_keys[0]);b.extend(self.relay_keys[1]);
  for n in [MAKER_PPM as u64,TAKER_PPM as u64,ORACLE_SHARE_BPS,MAX_AGE_US,MAX_SKEW_US,COLLAR_BPS as u64,200_000,300_000,0,100_000]{u64b(&mut b,n)}
  Scope{network:self.network,epoch:self.epoch,policy:tagged_hash(b"SHZ/HFT/POLICY/V1",&b)}
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Share{pub router:u32,pub sats:u64}
#[derive(Debug,Clone)]
pub struct Allocation{
 pub scope:Scope,pub owner:Key,pub channel:BtcOutPoint,pub total_sats:u64,pub shares:Vec<Share>,
 pub owner_sig:Bip340Signature,pub authority_sig:Bip340Signature,
}
impl Allocation{
 fn digest(&self)->R<Key>{
  if self.total_sats==0||self.shares.is_empty()||self.shares.len()>64{return Err(Reject::Allocation)}
  let mut sum=0u64;let mut prev=0;
  let mut b=Vec::new();self.scope.put(&mut b);b.extend(self.owner);put_op(&mut b,&self.channel);
  u64b(&mut b,self.total_sats);u32b(&mut b,self.shares.len()as u32);
  for s in &self.shares{
   if s.router<=prev||s.sats==0{return Err(Reject::Allocation)}
   sum=sum.checked_add(s.sats).ok_or(Reject::Allocation)?;prev=s.router;
   u32b(&mut b,s.router);u64b(&mut b,s.sats);
  }
  if sum>self.total_sats{return Err(Reject::Allocation)}
  Ok(tagged_hash(b"SHZ/HFT/ALLOCATION/V1",&b))
 }
 pub fn signed(scope:Scope,owner_sk:&Key,authority_sk:&Key,channel:BtcOutPoint,total_sats:u64,shares:Vec<Share>)->R<Self>{
  let zero=Bip340Signature{r_x:[0;32],s:[0;32]};
  let mut a=Self{scope,owner:public(owner_sk),channel,total_sats,shares,owner_sig:zero,authority_sig:zero};
  let h=a.digest()?;a.owner_sig=sign(owner_sk,&h)?;a.authority_sig=sign(authority_sk,&h)?;Ok(a)
 }
}
/// Canonical allocation snapshot chosen by the channel-state authority.
/// Duplicate outpoints are forbidden even across owners. Independent processes
/// must use this same registry and one single writer per allocated router.
pub struct Registry{scope:Scope,allocations:Vec<Allocation>}
impl Registry{
 pub fn new(scope:Scope,authority:Key,allocations:Vec<Allocation>)->R<Self>{
  let mut seen=BTreeSet::new();
  for a in &allocations{
   if a.scope!=scope||!seen.insert(op(&a.channel)){return Err(Reject::Allocation)}
   let h=a.digest()?;verify(&a.owner,&h,&a.owner_sig)?;verify(&authority,&h,&a.authority_sig)?;
  }
  Ok(Self{scope,allocations})
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Tier{Free,Priority}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Action{Post,Take,Cancel}
pub fn delay_us(tier:Tier,action:Action)->u64{match(tier,action){
 (Tier::Free,Action::Take)=>300_000,(Tier::Priority,Action::Take)=>100_000,
 (Tier::Free,_)=>200_000,(Tier::Priority,_)=>0}}
pub fn rate_ppm(tier:Tier,action:Action)->u32{match(tier,action){
 (Tier::Priority,Action::Post)=>MAKER_PPM,(Tier::Priority,Action::Take)=>TAKER_PPM,_=>0}}
/// Exact satoshi fee, rounded up. Maker partial fills use cumulative fee differences.
pub fn fee_sats(q:u64,price:u64,ppm:u32)->R<u64>{
 if q>MAX_NOTIONAL||price==0||price>MAX_PRICE||ppm>TAKER_PPM{return Err(Reject::Bounds)}
 u64::try_from((q as u128*100_000_000*ppm as u128).div_ceil(price as u128*1_000_000)).map_err(|_|Reject::Bounds)
}
#[derive(Debug,Clone)]
pub struct Intent{
 pub scope:Scope,pub router:u32,pub channel:BtcOutPoint,pub owner:Key,pub sequence:u64,pub expires_us:u64,
 pub action:Action,pub side:OrderSide,pub tier:Tier,pub quantity:u64,pub limit_usd:u64,pub leverage_bps:u32,
 pub max_fee_ppm:u32,pub max_fee_sats:u64,pub cancel_target:Key,pub signature:Bip340Signature,
}
impl Intent{
 pub fn id(&self)->Key{
  let mut b=Vec::new();self.scope.put(&mut b);u32b(&mut b,self.router);put_op(&mut b,&self.channel);b.extend(self.owner);
  u64b(&mut b,self.sequence);u64b(&mut b,self.expires_us);
  b.push(match self.action{Action::Post=>1,Action::Take=>2,Action::Cancel=>3});
  b.push(match self.side{OrderSide::Long=>1,OrderSide::Short=>2});
  b.push(match self.tier{Tier::Free=>0,Tier::Priority=>1});
  u64b(&mut b,self.quantity);u64b(&mut b,self.limit_usd);u32b(&mut b,self.leverage_bps);
  u32b(&mut b,self.max_fee_ppm);u64b(&mut b,self.max_fee_sats);b.extend(self.cancel_target);
  tagged_hash(b"SHZ/HFT/INTENT/V1",&b)
 }
 pub fn signed(mut self,sk:&Key)->R<Self>{self.owner=public(sk);self.signature=sign(sk,&self.id())?;Ok(self)}
 fn check(&self)->R<()>{
  if self.sequence==0||self.router==0||self.max_fee_ppm>TAKER_PPM{return Err(Reject::Bounds)}
  if self.action==Action::Cancel{
   if self.cancel_target==[0;32]||self.quantity!=0||self.limit_usd!=0||self.leverage_bps!=0||self.max_fee_ppm!=0||self.max_fee_sats!=0{return Err(Reject::Bounds)}
  }else if self.quantity==0||self.quantity>MAX_NOTIONAL||self.limit_usd==0||self.limit_usd>MAX_PRICE||!(1000..=1_000_000).contains(&self.leverage_bps)||self.cancel_target!=[0;32]{return Err(Reject::Bounds)}
  if rate_ppm(self.tier,self.action)>self.max_fee_ppm{return Err(Reject::FeeLimit)}
  verify(&self.owner,&self.id(),&self.signature)
 }
}
#[derive(Debug,Clone)]
pub struct RelayTick{
 pub scope:Scope,pub source:u8,pub sequence:u64,pub publish_us:u64,pub price_e8:u64,pub report_hash:Key,pub signature:Bip340Signature,
}
impl RelayTick{
 pub fn id(&self)->Key{
  let mut b=Vec::new();self.scope.put(&mut b);b.push(self.source);u64b(&mut b,self.sequence);u64b(&mut b,self.publish_us);u64b(&mut b,self.price_e8);b.extend(self.report_hash);
  tagged_hash(b"SHZ/HFT/RELAY/V1",&b)
 }
 pub fn signed(mut self,sk:&Key)->R<Self>{self.signature=sign(sk,&self.id())?;Ok(self)}
}
#[derive(Debug,Clone)]
struct Mark{ticks:[RelayTick;2],price_e8:u64,id:Key}
impl Mark{
 fn fresh(&self,now:u64)->bool{self.ticks.iter().all(|x|now.checked_sub(x.publish_us).is_some_and(|age|age<=MAX_AGE_US))}
 fn allows(&self,p:u64)->bool{let p=p as u128*100_000_000;let m=self.price_e8 as u128;p.abs_diff(m)*10_000<=m*COLLAR_BPS}
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Balance{pub cap:u64,pub free:u64,pub resting:u64,pub pending:u64}
impl Balance{pub fn conserved(&self)->bool{self.free as u128+self.resting as u128+self.pending as u128==self.cap as u128}}
struct Account{owner:Key,balance:Balance,last_seq:u64}
#[derive(Debug,Clone)]
struct Quote{intent:Intent,remaining:u64,hold_per_unit:u64}
#[derive(Debug,Clone)]
pub struct Fill{
 pub maker_id:Key,pub taker_id:Key,pub maker_channel:BtcOutPoint,pub taker_channel:BtcOutPoint,
 pub scope:Scope,pub router:u32,pub execution_us:u64,pub maker_owner:Key,pub taker_owner:Key,
 pub mark_id:Key,pub spec:InverseContractSpec,pub maker_fee_sats:u64,pub taker_fee_sats:u64,
 pub oracle_due_sats:u64,pub router_due_sats:u64,
}
#[derive(Debug,Clone)]
pub enum Outcome{Posted(Key),Cancelled(Key),Filled(Box<Fill>),Rejected(Reject)}
pub struct Router{
 policy:Policy,scope:Scope,id:u32,clock:u64,arrival:u64,activation:u64,accounts:BTreeMap<Outpoint,Account>,
 queue:BTreeMap<(u64,u64),Intent>,bids:BTreeMap<BookKey,Quote>,asks:BTreeMap<BookKey,Quote>,
 locations:BTreeMap<Key,(OrderSide,BookKey)>,expirations:BTreeMap<(u64,Key),()>,
 mark:Option<Mark>,fills:BTreeMap<Key,Fill>,
}
impl Router{
 pub fn new(policy:Policy,registry:&Registry,id:u32)->R<Self>{
  if id==0||policy.scope()!=registry.scope||policy.relay_keys[0]==policy.relay_keys[1]{return Err(Reject::Scope)}
  let mut accounts=BTreeMap::new();
  for a in &registry.allocations{if let Some(s)=a.shares.iter().find(|s|s.router==id){
   accounts.insert(op(&a.channel),Account{owner:a.owner,balance:Balance{cap:s.sats,free:s.sats,resting:0,pending:0},last_seq:0});
  }}
  Ok(Self{scope:policy.scope(),policy,id,clock:0,arrival:0,activation:0,accounts,queue:BTreeMap::new(),bids:BTreeMap::new(),asks:BTreeMap::new(),locations:BTreeMap::new(),expirations:BTreeMap::new(),mark:None,fills:BTreeMap::new()})
 }
 pub fn balance(&self,channel:&BtcOutPoint)->Option<Balance>{self.accounts.get(&op(channel)).map(|a|a.balance)}
 pub fn resting(&self)->usize{self.locations.len()}
 pub fn pending_orders(&self)->usize{self.queue.len()}
 pub fn pending_fill(&self,taker_id:&Key)->Option<&Fill>{self.fills.get(taker_id)}
 pub fn pending_fills(&self)->usize{self.fills.len()}
 fn clock(&mut self,now:u64)->R<()>{if now<self.clock{return Err(Reject::Clock)}self.clock=now;Ok(())}
 pub fn update_mark(&mut self,ticks:[RelayTick;2],now:u64)->R<Key>{
  self.clock(now)?;
  for(i,t)in ticks.iter().enumerate(){
   if t.scope!=self.scope||t.source!=i as u8+1||t.sequence==0||t.publish_us==0||t.price_e8==0||t.price_e8>10_000_000_000_000_000||t.report_hash==[0;32]||!now.checked_sub(t.publish_us).is_some_and(|age|age<=MAX_AGE_US){return Err(Reject::Oracle)}
   verify(&self.policy.relay_keys[i],&t.id(),&t.signature)?;
  }
  if ticks[0].publish_us.abs_diff(ticks[1].publish_us)>MAX_SKEW_US||
     ticks[0].price_e8.abs_diff(ticks[1].price_e8)as u128*20_000>50*(ticks[0].price_e8 as u128+ticks[1].price_e8 as u128){return Err(Reject::Oracle)}
  if let Some(m)=&self.mark{
   for(i,t)in ticks.iter().enumerate(){let p=&m.ticks[i];if t.sequence<p.sequence||t.publish_us<p.publish_us||(t.sequence==p.sequence&&t.id()!=p.id())||(t.sequence>p.sequence&&t.publish_us<=p.publish_us){return Err(Reject::Replay)}}
   if ticks.iter().zip(&m.ticks).all(|(a,b)|a.sequence==b.sequence){return Err(Reject::Replay)}
  }
  let price_e8=((ticks[0].price_e8 as u128+ticks[1].price_e8 as u128)/2)as u64;
  let mut b=Vec::new();b.extend(ticks[0].id());b.extend(ticks[1].id());let id=tagged_hash(b"SHZ/HFT/MARK/V1",&b);
  self.mark=Some(Mark{ticks,price_e8,id});Ok(id)
 }
 /// Clock comes from the local trusted monotonic scheduler, not the order payload.
 pub fn submit(&mut self,intent:Intent,now:u64)->R<u64>{
  self.clock(now)?;
  if intent.scope!=self.scope||intent.router!=self.id{return Err(Reject::Scope)}
  intent.check()?;
  let due=now.checked_add(delay_us(intent.tier,intent.action)).ok_or(Reject::Clock)?;
  if due>=intent.expires_us{return Err(Reject::Expired)}
  if self.queue.len()>=ORDER_CAP{return Err(Reject::Capacity)}
  let a=self.accounts.get_mut(&op(&intent.channel)).ok_or(Reject::Allocation)?;
  if a.owner!=intent.owner{return Err(Reject::Allocation)}
  if intent.sequence<=a.last_seq{return Err(Reject::Replay)}
  self.arrival=self.arrival.checked_add(1).ok_or(Reject::Bounds)?;
  a.last_seq=intent.sequence;
  self.queue.insert((due,self.arrival),intent);Ok(due)
 }
 fn book(&self,side:OrderSide)->&BTreeMap<BookKey,Quote>{match side{OrderSide::Long=>&self.bids,OrderSide::Short=>&self.asks}}
 fn book_mut(&mut self,side:OrderSide)->&mut BTreeMap<BookKey,Quote>{match side{OrderSide::Long=>&mut self.bids,OrderSide::Short=>&mut self.asks}}
 fn remove(&mut self,id:Key)->Option<Quote>{
  let (side,key)=self.locations.remove(&id)?;let q=self.book_mut(side).remove(&key)?;
  self.expirations.remove(&(q.intent.expires_us,id));
  let b=&mut self.accounts.get_mut(&op(&q.intent.channel)).unwrap().balance;
  let hold=q.remaining*q.hold_per_unit;b.resting-=hold;b.free+=hold;Some(q)
 }
 fn expire(&mut self,now:u64){
  while let Some((&(at,id),_))=self.expirations.first_key_value(){if at>now{break}self.remove(id);}
 }
 /// Dispatch one eligible event. Intent authentication is already complete;
 /// quote freshness and margin are evaluated at actual execution time.
 pub fn process_one(&mut self,now:u64)->R<Option<Outcome>>{
  self.clock(now)?;self.expire(now);
  let Some((&key,_))=self.queue.first_key_value()else{return Ok(None)};
  if key.0>now{return Ok(None)}
  let i=self.queue.remove(&key).unwrap();
  let result=if i.expires_us<=now{Err(Reject::Expired)}else if i.action==Action::Cancel{self.cancel(&i)}else{
   match self.mark.as_ref().filter(|m|m.fresh(now)).cloned(){
    None=>Err(Reject::Oracle),Some(m)=>match i.action{Action::Post=>self.post(i,&m),Action::Take=>self.take(&i,&m),Action::Cancel=>unreachable!()}
   }
  };
  Ok(Some(result.unwrap_or_else(Outcome::Rejected)))
 }
 fn cancel(&mut self,i:&Intent)->R<Outcome>{
  let (side,key)=*self.locations.get(&i.cancel_target).ok_or(Reject::UnknownOrder)?;
  let q=&self.book(side)[&key];
  if q.intent.owner!=i.owner||q.intent.channel!=i.channel||q.intent.tier!=i.tier{return Err(Reject::Allocation)}
  self.remove(i.cancel_target).ok_or(Reject::UnknownOrder)?;Ok(Outcome::Cancelled(i.cancel_target))
 }
 fn post(&mut self,i:Intent,m:&Mark)->R<Outcome>{
  if !m.allows(i.limit_usd){return Err(Reject::Oracle)}
  if self.locations.len()>=ORDER_CAP{return Err(Reject::Capacity)}
  let ppm=rate_ppm(i.tier,Action::Post);
  if fee_sats(i.quantity,i.limit_usd,ppm)?>i.max_fee_sats{return Err(Reject::FeeLimit)}
  // Per-dollar ceil is a conservative reserve even for arbitrarily split fills.
  let unit=InverseContractSpec::margin_for_leverage_bps(1,i.limit_usd,i.leverage_bps).map_err(|_|Reject::Bounds)?
     .checked_add(fee_sats(1,i.limit_usd,ppm)?).ok_or(Reject::Bounds)?;
  let hold=unit.checked_mul(i.quantity).ok_or(Reject::Bounds)?;
  let b=&mut self.accounts.get_mut(&op(&i.channel)).unwrap().balance;
  if b.free<hold{return Err(Reject::Capacity)}
  let activation=self.activation.checked_add(1).ok_or(Reject::Bounds)?;
  b.free-=hold;b.resting+=hold;self.activation=activation;
  let id=i.id();let side=i.side;
  let key=(if side==OrderSide::Long{u64::MAX-i.limit_usd}else{i.limit_usd},activation);
  self.locations.insert(id,(side,key));self.expirations.insert((i.expires_us,id),());
  let remaining=i.quantity;self.book_mut(side).insert(key,Quote{intent:i,remaining,hold_per_unit:unit});Ok(Outcome::Posted(id))
 }
 fn take(&mut self,i:&Intent,m:&Mark)->R<Outcome>{
  if self.fills.len()>=ORDER_CAP{return Err(Reject::Capacity)}
  // V1 FOK within one private maker quote; price then actual local arrival.
  let side=if i.side==OrderSide::Long{OrderSide::Short}else{OrderSide::Long};
  let chosen=self.book(side).iter().find(|(_,q)|{
   let p=q.intent.limit_usd;
   q.intent.owner!=i.owner&&q.remaining>=i.quantity&&m.allows(p)&&
    if i.side==OrderSide::Long{p<=i.limit_usd}else{p>=i.limit_usd}
  }).map(|(k,q)|(*k,q.clone())).ok_or(Reject::NoLiquidity)?;
  let (key,q)=chosen;let price=q.intent.limit_usd;let n=i.quantity;
  let (long,short)=if i.side==OrderSide::Long{(i.leverage_bps,q.intent.leverage_bps)}else{(q.intent.leverage_bps,i.leverage_bps)};
  let spec=InverseContractSpec::from_leverages_v0(n,price,long,short).map_err(|_|Reject::Bounds)?;
  debug_assert_eq!(spec.fee_policy,ZeroFeePolicy::ZERO);
  let (tm,mm)=if i.side==OrderSide::Long{(spec.long_margin_sats,spec.short_margin_sats)}else{(spec.short_margin_sats,spec.long_margin_sats)};
  let used=q.intent.quantity-q.remaining;
  let ppm=rate_ppm(q.intent.tier,Action::Post);
  let mf=fee_sats(used+n,price,ppm)?-fee_sats(used,price,ppm)?;
  let tf=fee_sats(n,price,rate_ppm(i.tier,Action::Take))?;
  if tf>i.max_fee_sats||fee_sats(used+n,price,ppm)?>q.intent.max_fee_sats{return Err(Reject::FeeLimit)}
  let maker_debit=mm.checked_add(mf).ok_or(Reject::Bounds)?;
  let taker_debit=tm.checked_add(tf).ok_or(Reject::Bounds)?;
  let released=n*q.hold_per_unit;
  if maker_debit>released||self.accounts[&op(&i.channel)].balance.free<taker_debit{return Err(Reject::Capacity)}
  let total=mf.checked_add(tf).ok_or(Reject::Bounds)?;
  let oracle=(total as u128*ORACLE_SHARE_BPS as u128/10_000)as u64;
  // All fallible arithmetic and checks above; one local atomic mutation below.
  let b=&mut self.accounts.get_mut(&op(&q.intent.channel)).unwrap().balance;
  b.resting-=released;b.pending+=maker_debit;b.free+=released-maker_debit;
  let b=&mut self.accounts.get_mut(&op(&i.channel)).unwrap().balance;
  b.free-=taker_debit;b.pending+=taker_debit;
  let maker_id=q.intent.id();
  if q.remaining==n{
   self.book_mut(side).remove(&key);self.locations.remove(&maker_id);self.expirations.remove(&(q.intent.expires_us,maker_id));
  }else{self.book_mut(side).get_mut(&key).unwrap().remaining-=n;}
  let fill=Fill{maker_id,taker_id:i.id(),maker_channel:q.intent.channel,taker_channel:i.channel.clone(),scope:self.scope,router:self.id,execution_us:self.clock,maker_owner:q.intent.owner,taker_owner:i.owner,mark_id:m.id,spec,maker_fee_sats:mf,taker_fee_sats:tf,oracle_due_sats:oracle,router_due_sats:total-oracle};
  self.fills.insert(fill.taker_id,fill.clone());
  Ok(Outcome::Filled(Box::new(fill)))
 }
}
