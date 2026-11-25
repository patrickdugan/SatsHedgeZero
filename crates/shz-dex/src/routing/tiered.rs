//! HFT-06 tiered admission and matching for one router with its own private book
//! and partitioned collateral (the same `Registry`/`Allocation`/`Balance` semantics
//! as HFT-01).
//!
//! * Three feed tiers (`Standard`, `Intermediate`, `Premium`) with a versioned
//!   `TariffSchedule` and a signed, relay-operator-pinned `Entitlement`.
//! * An `ExecutionPolicy` fixes per-tier feed delay and per-tier order delay. The
//!   arm (`FeedOnly`, `SchedulerOnly`, `Combined`) decides which mechanism is active.
//! * Matching is fill-or-kill against a single maker quote with price-time priority.
//!   A taker is matched against the latest mark visible to its tier. While that mark
//!   is still privileged (before `public_release_us`) only makers that opted in to
//!   the early window can be matched; public-only resting orders are protected.
//! * Stale-quote guard, 200 bps collar, HOLD handling and an operator hold switch
//!   reject takes and posts while cancels always succeed.
//!
//! # Confidentiality
//! The oracle side is only ever an input: `TieredRouter::ingest_mark` accepts a
//! `MarkView` (packet digest, sequence, price or HOLD, timing). The engine owns no
//! callback, channel, trait object or return value that carries book state, resting
//! orders, owners or sizes toward the oracle. Nothing about resting orders is
//! observable by the oracle side through this API.
//!
//! # Cancellation priority
//! Cancels are admitted with zero order delay for every tier and `process_one`
//! drains every due cancel before any due post or take. A slow-tier owner can always
//! pull a quote at least as fast as a fast-tier taker can reach it.
//!
//! # Lead reporting and double counting
//! See `ExecutionPolicy::lead`. Under `Combined` the feed lead and the order lead are
//! configured upper bounds from two mechanisms that act on the same fill; adding them
//! is not a measurement. Benchmarks must report each mechanism separately plus the
//! measured combined advantage, never the sum of configured delays.
use super::*;
use shz_oracle::hft_packets as packets;

pub const DOMAIN_ENTITLEMENT:&[u8]=b"SHZ/HFT06/ENTITLEMENT/V1";
pub const DOMAIN_INTENT:&[u8]=b"SHZ/HFT06/INTENT/V1";
pub const MAX_TIER_PPM:u32=200;
/// Placeholder for the signature field before `signed(..)` is called.
pub const ZERO_SIG:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};

#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Serialize,Deserialize)]
pub enum FeedTier{Standard,Intermediate,Premium}
impl FeedTier{
 pub const ALL:[FeedTier;3]=[FeedTier::Standard,FeedTier::Intermediate,FeedTier::Premium];
 pub fn index(self)->usize{self as usize}
 fn code(self)->u8{self as u8}
}

/// Every reason the tiered engine refuses an intent or an execution.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum TierReject{
 Scope,Signature,Allocation,Replay,Bounds,Clock,Expired,Capacity,NoLiquidity,FeeLimit,UnknownOrder,
 TariffVersion,PolicyMismatch,
 EntitlementMissing,EntitlementExpired,EntitlementClient,EntitlementTier,EntitlementSignature,
 /// Latest visible mark is HOLD, or the operator hold switch is set.
 Hold,
 /// No mark is visible to the tier yet.
 NoMark,
 StaleMark,
 Collar,
 /// The only otherwise-matchable makers were public-only during a privileged mark.
 EarlyWindowProtected,
}
impl From<Reject> for TierReject{
 fn from(r:Reject)->Self{match r{
  Reject::Scope=>Self::Scope,Reject::Signature=>Self::Signature,Reject::Allocation=>Self::Allocation,Reject::Replay=>Self::Replay,
  Reject::Bounds=>Self::Bounds,Reject::Clock=>Self::Clock,Reject::Oracle=>Self::NoMark,Reject::Expired=>Self::Expired,
  Reject::Capacity=>Self::Capacity,Reject::NoLiquidity=>Self::NoLiquidity,Reject::FeeLimit=>Self::FeeLimit,Reject::UnknownOrder=>Self::UnknownOrder}}
}
type T<X>=Result<X,TierReject>;

/// Versioned fee schedule indexed by `FeedTier::index`. Rates are ppm of notional.
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct TariffSchedule{pub version:u32,pub maker_ppm:[u32;3],pub taker_ppm:[u32;3]}
impl TariffSchedule{
 /// Candidate: Standard 0/0, Intermediate maker 0 / taker 50 ppm (0.5 bps),
 /// Premium maker 20 / taker 200 ppm.
 pub fn default_candidate()->Self{Self{version:1,maker_ppm:[0,0,20],taker_ppm:[0,50,200]}}
 pub fn with_intermediate_maker(mut self,ppm:u32)->Self{self.maker_ppm[FeedTier::Intermediate.index()]=ppm;self}
 pub fn validate(&self)->T<()>{
  for i in 0..3{if self.taker_ppm[i]>MAX_TIER_PPM||self.maker_ppm[i]>self.taker_ppm[i]{return Err(TierReject::Bounds)}}
  if self.version==0{return Err(TierReject::Bounds)}
  Ok(())
 }
 pub fn rate_ppm(&self,tier:FeedTier,action:Action)->u32{match action{
  Action::Post=>self.maker_ppm[tier.index()],Action::Take=>self.taker_ppm[tier.index()],Action::Cancel=>0}}
 pub fn id(&self)->Key{
  let mut b=Vec::new();u32b(&mut b,self.version);
  for n in self.maker_ppm.iter().chain(&self.taker_ppm){u32b(&mut b,*n)}
  tagged_hash(b"SHZ/HFT06/TARIFF/V1",&b)
 }
}

#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub enum Arm{FeedOnly,SchedulerOnly,Combined}

/// End-to-end advantage of one tier over another, per mechanism.
/// `effective_us` is the single mechanism's lead for `FeedOnly`/`SchedulerOnly`.
/// For `Combined` it is the sum of the two configured leads and `double_counted`
/// is `true`: that sum is an upper bound, not a measurement.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Lead{pub feed_us:i64,pub order_us:i64,pub effective_us:i64,pub double_counted:bool}

/// Tier indexed delays. Order within each array is `[Standard, Intermediate, Premium]`.
/// The active mechanisms are selected by `arm`; the inactive array is ignored by every
/// accessor (and by `id`), so a `FeedOnly` policy never delays orders.
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct ExecutionPolicy{pub feed_delay_us:[u64;3],pub order_delay_us:[u64;3],pub arm:Arm}
impl ExecutionPolicy{
 /// Default lags: Standard 200 ms, Intermediate 100 ms, Premium 0.
 pub fn defaults(arm:Arm)->Self{
  let lag=[200_000,100_000,0];
  match arm{
   Arm::FeedOnly=>Self{feed_delay_us:lag,order_delay_us:[0;3],arm},
   Arm::SchedulerOnly=>Self{feed_delay_us:[0;3],order_delay_us:lag,arm},
   Arm::Combined=>Self{feed_delay_us:lag,order_delay_us:lag,arm},
  }
 }
 pub fn feed_delay(&self,t:FeedTier)->u64{if self.arm==Arm::SchedulerOnly{0}else{self.feed_delay_us[t.index()]}}
 pub fn order_delay(&self,t:FeedTier)->u64{if self.arm==Arm::FeedOnly{0}else{self.order_delay_us[t.index()]}}
 pub fn validate(&self)->T<()>{
  for a in [&self.feed_delay_us,&self.order_delay_us]{
   if a.iter().any(|d|*d>1_000_000)||a[2]>a[1]||a[1]>a[0]{return Err(TierReject::Bounds)}
  }
  Ok(())
 }
 pub fn id(&self)->Key{
  let mut b=vec![match self.arm{Arm::FeedOnly=>1,Arm::SchedulerOnly=>2,Arm::Combined=>3}];
  for t in FeedTier::ALL{u64b(&mut b,self.feed_delay(t));u64b(&mut b,self.order_delay(t))}
  tagged_hash(b"SHZ/HFT06/EXEC-POLICY/V1",&b)
 }
 /// Advantage of `a` over `b`. Rule: a single active mechanism is reported as is;
 /// under `Combined` the configured leads add (`double_counted=true`) and the result
 /// must be labelled a configured bound, with each mechanism reported separately.
 pub fn lead(&self,a:FeedTier,b:FeedTier)->Lead{
  let feed=self.feed_delay(b) as i64-self.feed_delay(a) as i64;
  let order=self.order_delay(b) as i64-self.order_delay(a) as i64;
  match self.arm{
   Arm::FeedOnly=>Lead{feed_us:feed,order_us:0,effective_us:feed,double_counted:false},
   Arm::SchedulerOnly=>Lead{feed_us:0,order_us:order,effective_us:order,double_counted:false},
   Arm::Combined=>Lead{feed_us:feed,order_us:order,effective_us:feed+order,double_counted:true},
  }
 }
}

#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct RevenuePolicy{pub oracle_share_bps:u64}
impl Default for RevenuePolicy{fn default()->Self{Self{oracle_share_bps:ORACLE_SHARE_BPS}}}
impl RevenuePolicy{
 /// `(oracle, router)`; oracle is floored, router takes the remainder: exact conservation.
 pub fn split(&self,total:u64)->(u64,u64){
  let oracle=(total as u128*self.oracle_share_bps as u128/10_000)as u64;(oracle,total-oracle)
 }
}

/// Feed access grant signed by the pinned relay/feed operator key.
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Entitlement{
 pub client:Key,pub tier:FeedTier,pub tariff_version:u32,pub valid_from_us:u64,pub valid_until_us:u64,
 pub relay_key:Key,pub signature:Bip340Signature,
}
impl Entitlement{
 pub fn digest(&self)->Key{
  let mut b=Vec::new();b.extend(self.client);b.push(self.tier.code());u32b(&mut b,self.tariff_version);
  u64b(&mut b,self.valid_from_us);u64b(&mut b,self.valid_until_us);b.extend(self.relay_key);
  tagged_hash(DOMAIN_ENTITLEMENT,&b)
 }
 pub fn signed(mut self,relay_sk:&Key)->T<Self>{
  self.relay_key=public(relay_sk);self.signature=sign(relay_sk,&self.digest()).map_err(|_|TierReject::EntitlementSignature)?;Ok(self)
 }
 fn verify_with(&self,pinned:&Key)->T<()>{
  if self.relay_key!=*pinned{return Err(TierReject::EntitlementSignature)}
  verify(&self.relay_key,&self.digest(),&self.signature).map_err(|_|TierReject::EntitlementSignature)
 }
}

/// The only oracle-to-router interface. Verification of the quorum certificate
/// happens upstream; the router keeps the packet digest for every fill.
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct MarkView{
 pub packet_digest:Key,pub seq:u64,
 /// `None` is an emergency HOLD.
 pub price_e8:Option<u64>,pub boundary_us:u64,pub public_release_us:u64,
}
impl MarkView{
 pub fn from_packet(p:&packets::Packet,boundary_us:u64,public_release_us:u64)->Self{
  Self{packet_digest:p.digest(),seq:p.seq,price_e8:p.price(),boundary_us,public_release_us}
 }
 fn allows(&self,usd:u64)->bool{
  let Some(m)=self.price_e8 else{return false};
  let p=usd as u128*100_000_000;let m=m as u128;p.abs_diff(m)*10_000<=m*COLLAR_BPS
 }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct IntentV6{
 pub scope:Scope,pub router:u32,pub channel:BtcOutPoint,pub owner:Key,pub sequence:u64,pub expires_us:u64,
 pub action:Action,pub side:OrderSide,pub tier:FeedTier,pub tariff_version:u32,
 /// Zero for `Standard`.
 pub entitlement_digest:Key,pub execution_policy:Key,
 pub quantity:u64,pub limit_usd:u64,pub leverage_bps:u32,pub max_fee_ppm:u32,pub max_fee_sats:u64,
 pub max_mark_age_us:u64,
 /// Makers only: allow matching against a still-privileged mark.
 pub early_window_opt_in:bool,
 pub cancel_target:Key,pub signature:Bip340Signature,
}
impl IntentV6{
 pub fn id(&self)->Key{
  let mut b=Vec::new();self.scope.put(&mut b);u32b(&mut b,self.router);put_op(&mut b,&self.channel);b.extend(self.owner);
  u64b(&mut b,self.sequence);u64b(&mut b,self.expires_us);
  b.push(match self.action{Action::Post=>1,Action::Take=>2,Action::Cancel=>3});
  b.push(match self.side{OrderSide::Long=>1,OrderSide::Short=>2});
  b.push(self.tier.code());u32b(&mut b,self.tariff_version);b.extend(self.entitlement_digest);b.extend(self.execution_policy);
  u64b(&mut b,self.quantity);u64b(&mut b,self.limit_usd);u32b(&mut b,self.leverage_bps);
  u32b(&mut b,self.max_fee_ppm);u64b(&mut b,self.max_fee_sats);u64b(&mut b,self.max_mark_age_us);
  b.push(self.early_window_opt_in as u8);b.extend(self.cancel_target);
  tagged_hash(DOMAIN_INTENT,&b)
 }
 pub fn signed(mut self,sk:&Key)->T<Self>{self.owner=public(sk);self.signature=sign(sk,&self.id()).map_err(|_|TierReject::Signature)?;Ok(self)}
 fn check(&self)->T<()>{
  if self.sequence==0||self.router==0||self.max_fee_ppm>MAX_TIER_PPM{return Err(TierReject::Bounds)}
  if self.action==Action::Cancel{
   if self.cancel_target==[0;32]||self.quantity!=0||self.limit_usd!=0||self.leverage_bps!=0||self.max_fee_ppm!=0||self.max_fee_sats!=0||
      self.max_mark_age_us!=0||self.early_window_opt_in{return Err(TierReject::Bounds)}
  }else if self.quantity==0||self.quantity>MAX_NOTIONAL||self.limit_usd==0||self.limit_usd>MAX_PRICE||
     !(1000..=1_000_000).contains(&self.leverage_bps)||self.cancel_target!=[0;32]||self.max_mark_age_us==0||
     (self.early_window_opt_in&&self.action!=Action::Post){return Err(TierReject::Bounds)}
  if (self.tier==FeedTier::Standard)!=(self.entitlement_digest==[0;32]){return Err(TierReject::EntitlementMissing)}
  verify(&self.owner,&self.id(),&self.signature).map_err(|_|TierReject::Signature)
 }
}

/// Everything a fill binds. `fill` is the standard HFT-01/03 leg; its `mark_id` is
/// `tagged_hash("SHZ/HFT06/FILL-BINDING/V1", packet_digest || tariff_version ||
/// execution_policy || maker_entitlement || taker_entitlement)`.
#[derive(Debug,Clone)]
pub struct TieredFill{
 pub fill:Fill,pub packet_digest:Key,pub mark_seq:u64,pub maker_entitlement:Key,pub taker_entitlement:Key,
 pub tariff_version:u32,pub execution_policy:Key,pub maker_tier:FeedTier,pub taker_tier:FeedTier,
 /// The matched mark was still privileged when the fill executed.
 pub early_window:bool,
}
#[derive(Debug,Clone)]
pub enum TierOutcome{Posted(Key),Cancelled(Key),Filled(Box<TieredFill>),Rejected(TierReject)}

#[derive(Debug,Clone)]
pub struct TieredConfig{
 pub scope:Scope,pub router:u32,pub entitlement_key:Key,pub tariff:TariffSchedule,
 pub execution:ExecutionPolicy,pub revenue:RevenuePolicy,
}
#[derive(Debug,Clone)]
struct Queued{intent:IntentV6,ent_until:u64}
#[derive(Debug,Clone)]
struct Quote{intent:IntentV6,remaining:u64,hold_per_unit:u64}

pub struct TieredRouter{
 cfg:TieredConfig,policy_id:Key,clock:u64,arrival:u64,activation:u64,hold:bool,
 accounts:BTreeMap<Outpoint,Account>,
 cancels:BTreeMap<(u64,u64),Queued>,queue:BTreeMap<(u64,u64),Queued>,
 bids:BTreeMap<BookKey,Quote>,asks:BTreeMap<BookKey,Quote>,
 locations:BTreeMap<Key,(OrderSide,BookKey)>,expirations:BTreeMap<(u64,Key),()>,
 marks:Vec<MarkView>,
 fills:BTreeMap<Key,TieredFill>,fill_log:Vec<Key>,batch_cursor:usize,batch_sequence:u64,last_batch_digest:Key,
}
const MARK_HISTORY:usize=1024;
impl TieredRouter{
 pub fn new(registry:&Registry,cfg:TieredConfig)->T<Self>{
  if cfg.router==0||cfg.scope!=registry.scope||cfg.entitlement_key==[0;32]||cfg.revenue.oracle_share_bps>10_000{return Err(TierReject::Scope)}
  cfg.tariff.validate()?;cfg.execution.validate()?;
  let mut accounts=BTreeMap::new();
  for a in &registry.allocations{if let Some(s)=a.shares.iter().find(|s|s.router==cfg.router){
   accounts.insert(op(&a.channel),Account{owner:a.owner,balance:Balance{cap:s.sats,free:s.sats,resting:0,pending:0,committed:0,paid_fees:0},last_seq:0});
  }}
  let policy_id=cfg.execution.id();
  Ok(Self{cfg,policy_id,clock:0,arrival:0,activation:0,hold:false,accounts,cancels:BTreeMap::new(),queue:BTreeMap::new(),
   bids:BTreeMap::new(),asks:BTreeMap::new(),locations:BTreeMap::new(),expirations:BTreeMap::new(),marks:Vec::new(),
   fills:BTreeMap::new(),fill_log:Vec::new(),batch_cursor:0,batch_sequence:0,last_batch_digest:[0;32]})
 }
 pub fn execution_policy_id(&self)->Key{self.policy_id}
 pub fn tariff(&self)->&TariffSchedule{&self.cfg.tariff}
 pub fn execution(&self)->&ExecutionPolicy{&self.cfg.execution}
 pub fn balance(&self,channel:&BtcOutPoint)->Option<Balance>{self.accounts.get(&op(channel)).map(|a|a.balance)}
 pub fn resting(&self)->usize{self.locations.len()}
 pub fn pending_orders(&self)->usize{self.queue.len()+self.cancels.len()}
 pub fn fill_count(&self)->usize{self.fill_log.len()}
 pub fn fill(&self,taker_id:&Key)->Option<&TieredFill>{self.fills.get(taker_id)}
 /// Operator switch: while set, takes and posts are rejected with `Hold`; cancels succeed.
 pub fn set_emergency_hold(&mut self,on:bool){self.hold=on}
 pub fn emergency_hold(&self)->bool{self.hold}
 fn clock(&mut self,now:u64)->T<()>{if now<self.clock{return Err(TierReject::Clock)}self.clock=now;Ok(())}
 /// Order delay (admission to due time) for a tier and action. Cancels are never delayed.
 pub fn due_delay_us(&self,tier:FeedTier,action:Action)->u64{
  if action==Action::Cancel{0}else{self.cfg.execution.order_delay(tier)}
 }
 /// Sole oracle input. Marks must be strictly increasing in sequence and monotone in time.
 pub fn ingest_mark(&mut self,m:MarkView,now:u64)->T<()>{
  self.clock(now)?;
  if m.packet_digest==[0;32]||m.seq==0||m.boundary_us>now||m.public_release_us<m.boundary_us{return Err(TierReject::Bounds)}
  if m.price_e8.is_some_and(|p|p==0||p>10_000_000_000_000_000){return Err(TierReject::Bounds)}
  if let Some(last)=self.marks.last()
   && (m.seq<=last.seq||m.boundary_us<last.boundary_us){return Err(TierReject::Replay)}
  self.marks.push(m);
  if self.marks.len()>MARK_HISTORY{self.marks.remove(0);}
  Ok(())
 }
 /// Latest mark visible to `tier` at `now`: boundary plus the tier's feed delay.
 /// HOLD marks are visible to every tier at their boundary (fail closed).
 pub fn visible_mark(&self,tier:FeedTier,now:u64)->Option<&MarkView>{
  let d=self.cfg.execution.feed_delay(tier);
  self.marks.iter().rev().find(|m|m.price_e8.is_none()||now>=m.boundary_us.saturating_add(d))
 }
 fn entitlement(&self,i:&IntentV6,e:Option<&Entitlement>,now:u64)->T<u64>{
  if i.tier==FeedTier::Standard{return Ok(u64::MAX)}
  let e=e.ok_or(TierReject::EntitlementMissing)?;
  if e.digest()!=i.entitlement_digest{return Err(TierReject::EntitlementMissing)}
  e.verify_with(&self.cfg.entitlement_key)?;
  if e.client!=i.owner{return Err(TierReject::EntitlementClient)}
  if e.tier!=i.tier{return Err(TierReject::EntitlementTier)}
  if e.tariff_version!=i.tariff_version{return Err(TierReject::TariffVersion)}
  if now<e.valid_from_us||now>=e.valid_until_us{return Err(TierReject::EntitlementExpired)}
  Ok(e.valid_until_us)
 }
 /// Admit an intent; returns the due time. Authentication, replay, tariff, entitlement
 /// and fee-cap checks happen here; mark, collar, margin and liquidity at execution.
 pub fn submit(&mut self,i:IntentV6,e:Option<&Entitlement>,now:u64)->T<u64>{
  self.clock(now)?;
  if i.scope!=self.cfg.scope||i.router!=self.cfg.router{return Err(TierReject::Scope)}
  i.check()?;
  if i.tariff_version!=self.cfg.tariff.version{return Err(TierReject::TariffVersion)}
  if i.execution_policy!=self.policy_id{return Err(TierReject::PolicyMismatch)}
  let ent_until=self.entitlement(&i,e,now)?;
  if self.cfg.tariff.rate_ppm(i.tier,i.action)>i.max_fee_ppm{return Err(TierReject::FeeLimit)}
  let due=now.checked_add(self.due_delay_us(i.tier,i.action)).ok_or(TierReject::Clock)?;
  if due>=i.expires_us{return Err(TierReject::Expired)}
  if self.queue.len()+self.cancels.len()>=ORDER_CAP{return Err(TierReject::Capacity)}
  let a=self.accounts.get_mut(&op(&i.channel)).ok_or(TierReject::Allocation)?;
  if a.owner!=i.owner{return Err(TierReject::Allocation)}
  if i.sequence<=a.last_seq{return Err(TierReject::Replay)}
  self.arrival=self.arrival.checked_add(1).ok_or(TierReject::Bounds)?;
  a.last_seq=i.sequence;
  let q=if i.action==Action::Cancel{&mut self.cancels}else{&mut self.queue};
  q.insert((due,self.arrival),Queued{intent:i,ent_until});Ok(due)
 }
 fn book(&self,s:OrderSide)->&BTreeMap<BookKey,Quote>{match s{OrderSide::Long=>&self.bids,OrderSide::Short=>&self.asks}}
 fn book_mut(&mut self,s:OrderSide)->&mut BTreeMap<BookKey,Quote>{match s{OrderSide::Long=>&mut self.bids,OrderSide::Short=>&mut self.asks}}
 fn remove(&mut self,id:Key)->Option<Quote>{
  let (side,key)=self.locations.remove(&id)?;let q=self.book_mut(side).remove(&key)?;
  self.expirations.remove(&(q.intent.expires_us,id));
  let b=&mut self.accounts.get_mut(&op(&q.intent.channel)).unwrap().balance;
  let hold=q.remaining*q.hold_per_unit;b.resting-=hold;b.free+=hold;Some(q)
 }
 fn expire(&mut self,now:u64){
  while let Some((&(at,id),_))=self.expirations.first_key_value(){if at>now{break}self.remove(id);}
 }
 /// Process one due event: all due cancels first, then the earliest due post or take.
 pub fn process_one(&mut self,now:u64)->T<Option<TierOutcome>>{
  self.clock(now)?;self.expire(now);
  let cancel_due=self.cancels.first_key_value().is_some_and(|(k,_)|k.0<=now);
  let queue=if cancel_due{&mut self.cancels}else{&mut self.queue};
  let Some((&key,_))=queue.first_key_value()else{return Ok(None)};
  if key.0>now{return Ok(None)}
  let Queued{intent:i,ent_until}=queue.remove(&key).unwrap();
  let result=if i.expires_us<=now{Err(TierReject::Expired)}
   else if i.action==Action::Cancel{self.cancel(&i)}
   else if now>=ent_until{Err(TierReject::EntitlementExpired)}
   else if i.action==Action::Post{self.post(i,now)}else{self.take(&i,now)};
  Ok(Some(result.unwrap_or_else(TierOutcome::Rejected)))
 }
 fn cancel(&mut self,i:&IntentV6)->T<TierOutcome>{
  let (side,key)=*self.locations.get(&i.cancel_target).ok_or(TierReject::UnknownOrder)?;
  let q=&self.book(side)[&key];
  if q.intent.owner!=i.owner||q.intent.channel!=i.channel{return Err(TierReject::Allocation)}
  self.remove(i.cancel_target).ok_or(TierReject::UnknownOrder)?;Ok(TierOutcome::Cancelled(i.cancel_target))
 }
 /// Mark usable by `i` at `now`, with the HOLD and staleness rules applied.
 fn usable_mark(&self,tier:FeedTier,max_age:u64,now:u64)->T<(MarkView,u64)>{
  if self.hold{return Err(TierReject::Hold)}
  let m=*self.visible_mark(tier,now).ok_or(TierReject::NoMark)?;
  if m.price_e8.is_none(){return Err(TierReject::Hold)}
  let age=now.saturating_sub(m.boundary_us);
  if age>max_age{return Err(TierReject::StaleMark)}
  Ok((m,age))
 }
 fn post(&mut self,i:IntentV6,now:u64)->T<TierOutcome>{
  let (m,_)=self.usable_mark(i.tier,i.max_mark_age_us,now)?;
  if !m.allows(i.limit_usd){return Err(TierReject::Collar)}
  if self.locations.len()>=ORDER_CAP{return Err(TierReject::Capacity)}
  let ppm=self.cfg.tariff.rate_ppm(i.tier,Action::Post);
  if fee_sats(i.quantity,i.limit_usd,ppm)?>i.max_fee_sats{return Err(TierReject::FeeLimit)}
  let unit=InverseContractSpec::margin_for_leverage_bps(1,i.limit_usd,i.leverage_bps).map_err(|_|TierReject::Bounds)?
   .checked_add(fee_sats(1,i.limit_usd,ppm)?).ok_or(TierReject::Bounds)?;
  let hold=unit.checked_mul(i.quantity).ok_or(TierReject::Bounds)?;
  let b=&mut self.accounts.get_mut(&op(&i.channel)).unwrap().balance;
  if b.free<hold{return Err(TierReject::Capacity)}
  let activation=self.activation.checked_add(1).ok_or(TierReject::Bounds)?;
  b.free-=hold;b.resting+=hold;self.activation=activation;
  let id=i.id();let side=i.side;
  let key=(if side==OrderSide::Long{u64::MAX-i.limit_usd}else{i.limit_usd},activation);
  self.locations.insert(id,(side,key));self.expirations.insert((i.expires_us,id),());
  let remaining=i.quantity;
  self.book_mut(side).insert(key,Quote{intent:i,remaining,hold_per_unit:unit});Ok(TierOutcome::Posted(id))
 }
 fn take(&mut self,i:&IntentV6,now:u64)->T<TierOutcome>{
  if self.fills.len()>=ORDER_CAP{return Err(TierReject::Capacity)}
  let (m,age)=self.usable_mark(i.tier,i.max_mark_age_us,now)?;
  let privileged=now<m.public_release_us;
  let side=if i.side==OrderSide::Long{OrderSide::Short}else{OrderSide::Long};
  let (mut stale,mut protected)=(false,false);
  let mut found=None;
  for (k,q) in self.book(side){
   let p=q.intent.limit_usd;
   if q.intent.owner==i.owner||q.remaining<i.quantity||!m.allows(p){continue}
   if !(if i.side==OrderSide::Long{p<=i.limit_usd}else{p>=i.limit_usd}){continue}
   if age>q.intent.max_mark_age_us{stale=true;continue}
   if privileged&&!q.intent.early_window_opt_in{protected=true;continue}
   found=Some(*k);break;
  }
  let key=found.ok_or(if stale{TierReject::StaleMark}else if protected{TierReject::EarlyWindowProtected}else{TierReject::NoLiquidity})?;
  let q=self.book(side)[&key].clone();let price=q.intent.limit_usd;let n=i.quantity;
  let (long,short)=if i.side==OrderSide::Long{(i.leverage_bps,q.intent.leverage_bps)}else{(q.intent.leverage_bps,i.leverage_bps)};
  let spec=InverseContractSpec::from_leverages_v0(n,price,long,short).map_err(|_|TierReject::Bounds)?;
  debug_assert_eq!(spec.fee_policy,ZeroFeePolicy::ZERO);
  let (tm,mm)=if i.side==OrderSide::Long{(spec.long_margin_sats,spec.short_margin_sats)}else{(spec.short_margin_sats,spec.long_margin_sats)};
  let used=q.intent.quantity-q.remaining;
  let mppm=self.cfg.tariff.rate_ppm(q.intent.tier,Action::Post);
  let tppm=self.cfg.tariff.rate_ppm(i.tier,Action::Take);
  let mf=fee_sats(used+n,price,mppm)?-fee_sats(used,price,mppm)?;
  let tf=fee_sats(n,price,tppm)?;
  if tf>i.max_fee_sats||fee_sats(used+n,price,mppm)?>q.intent.max_fee_sats{return Err(TierReject::FeeLimit)}
  let maker_debit=mm.checked_add(mf).ok_or(TierReject::Bounds)?;
  let taker_debit=tm.checked_add(tf).ok_or(TierReject::Bounds)?;
  let released=n*q.hold_per_unit;
  if maker_debit>released||self.accounts[&op(&i.channel)].balance.free<taker_debit{return Err(TierReject::Capacity)}
  let total=mf.checked_add(tf).ok_or(TierReject::Bounds)?;
  let (oracle,router)=self.cfg.revenue.split(total);
  // Every fallible step is above; the mutation below is atomic.
  let b=&mut self.accounts.get_mut(&op(&q.intent.channel)).unwrap().balance;
  b.resting-=released;b.pending+=maker_debit;b.free+=released-maker_debit;
  let b=&mut self.accounts.get_mut(&op(&i.channel)).unwrap().balance;
  b.free-=taker_debit;b.pending+=taker_debit;
  let maker_id=q.intent.id();
  if q.remaining==n{
   self.book_mut(side).remove(&key);self.locations.remove(&maker_id);self.expirations.remove(&(q.intent.expires_us,maker_id));
  }else{self.book_mut(side).get_mut(&key).unwrap().remaining-=n;}
  let mut bind=Vec::new();bind.extend(m.packet_digest);u32b(&mut bind,self.cfg.tariff.version);bind.extend(self.policy_id);
  bind.extend(q.intent.entitlement_digest);bind.extend(i.entitlement_digest);
  let mark_id=tagged_hash(b"SHZ/HFT06/FILL-BINDING/V1",&bind);
  let fill=Fill{maker_id,taker_id:i.id(),maker_channel:q.intent.channel,taker_channel:i.channel.clone(),scope:self.cfg.scope,
   router:self.cfg.router,execution_us:self.clock,maker_owner:q.intent.owner,taker_owner:i.owner,mark_id,
   maker_side:q.intent.side,spec,maker_fee_sats:mf,taker_fee_sats:tf,oracle_due_sats:oracle,router_due_sats:router};
  let tf=TieredFill{fill,packet_digest:m.packet_digest,mark_seq:m.seq,maker_entitlement:q.intent.entitlement_digest,
   taker_entitlement:i.entitlement_digest,tariff_version:self.cfg.tariff.version,execution_policy:self.policy_id,
   maker_tier:q.intent.tier,taker_tier:i.tier,early_window:privileged};
  self.fill_log.push(tf.fill.taker_id);self.fills.insert(tf.fill.taker_id,tf.clone());
  Ok(TierOutcome::Filled(Box::new(tf)))
 }
 /// Seal at most one elapsed 100 ms window using the shared HFT-03 implementation.
 pub fn seal_batch(&mut self)->T<Option<Batch>>{
  let Some(first)=self.fill_log.get(self.batch_cursor)else{return Ok(None)};
  let start=self.fills[first].fill.execution_us/COALESCE_US*COALESCE_US;
  let end=start.checked_add(COALESCE_US).ok_or(TierReject::Clock)?;
  if self.clock<end{return Ok(None)}
  let seq=self.batch_sequence.checked_add(1).ok_or(TierReject::Bounds)?;
  let mut next=self.batch_cursor;let mut legs=Vec::new();
  while let Some(id)=self.fill_log.get(next){
   let f=&self.fills[id].fill;
   if f.execution_us>=end{break}
   if f.taker_id!=*id{return Err(TierReject::Scope)}
   legs.push(f.clone());next+=1;
  }
  let accounts=&self.accounts;
  let batch=Batch::seal_legs(self.cfg.scope,self.cfg.router,seq,self.last_batch_digest,(start,end),legs,
   &|k:&Outpoint|accounts.get(k).map(|a|(a.owner,a.balance.pending)))?;
  self.batch_cursor=next;self.batch_sequence=seq;self.last_batch_digest=batch.digest();
  Ok(Some(batch))
 }
}

/// Narrow accessors for the durable tiered router (`tiered_durable`). Nothing here
/// bypasses admission or matching; they expose only what an acknowledged HFT-05-style
/// resolution must read and write.
impl TieredRouter{
 pub fn config(&self)->&TieredConfig{&self.cfg}
 /// Retained mark history, oldest first.
 pub fn marks(&self)->&[MarkView]{&self.marks}
 pub fn clock_us(&self)->u64{self.clock}
 pub fn batch_sequence(&self)->u64{self.batch_sequence}
 pub(super) fn account_count(&self)->usize{self.accounts.len()}
 pub(super) fn account_owner(&self,k:&Outpoint)->Option<Key>{self.accounts.get(k).map(|a|a.owner)}
 pub(super) fn account_balance(&self,k:&Outpoint)->Option<Balance>{self.accounts.get(k).map(|a|a.balance)}
 pub(super) fn set_account_balance(&mut self,k:&Outpoint,b:Balance){if let Some(a)=self.accounts.get_mut(k){a.balance=b}}
 /// Pull a resting maker quote (used when a fenced abort cancels a batch's makers).
 pub(super) fn cancel_resting(&mut self,id:Key){self.remove(id);}
}
