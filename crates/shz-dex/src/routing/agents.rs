//! Delegated agent keys (docs/SHZ_AGENT_API.md). An account owner signs an `AgentGrant`
//! naming an agent key; the router then accepts intents signed by that key for that
//! account, and the owner's batch acknowledgement signed by it for a batch whose every leg
//! on the account came from the agent's own intents. The agent never holds the owner's key.
//!
//! The router enforces authorization: grant signature and account, expiry at the router
//! clock, instant revocation (resting and queued agent orders are pulled), instrument
//! classes, cancels limited to the agent's own orders, acknowledgements limited to the
//! agent's own legs, and `may_withdraw == false` (no transfer path accepts an agent key).
//! The numeric limits (`AgentLimits`) are signed into the grant and enforced by the venue
//! at intake, where the mark and the account's order history are.
//!
//! Journaled as `EnableAgents` (once), then `GrantAgent` / `RevokeAgent` and the agent
//! variants of submit, prepare and resolve. A journal without `EnableAgents` replays as
//! before; every agent event is refused until it.
use super::*;

pub const AGENT_GRANT_VERSION:u32=1;
pub const DOMAIN_AGENT_GRANT:&[u8]=b"SHZ/HFT06/AGENT-GRANT/V1";
pub const DOMAIN_AGENT_REVOKE:&[u8]=b"SHZ/HFT06/AGENT-REVOKE/V1";
pub const INSTRUMENT_PERPS:u8=1;
pub const INSTRUMENT_OPTIONS:u8=2;
pub const INSTRUMENT_SPOT:u8=4;
pub const INSTRUMENT_ALL:u8=7;
/// Longest grant lifetime (`expires_us - issued_us`): 30 days.
pub const MAX_GRANT_US:u64=30*86_400_000_000;
/// Unrevoked, unexpired grants per account.
pub const MAX_ACTIVE_GRANTS:usize=4;

/// Venue-enforced limits, signed into the grant. Notionals are whole USD at the venue's
/// mark (perpetual `quantity`; option BTC-series `qty`; stable-series and spot size times
/// the mark). `collar_bps` bounds an order's price against the mark (perpetual and spot
/// limit; option premium is bounded by `max_order_notional_usd` instead).
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct AgentLimits{
 pub max_order_notional_usd:u64,pub max_daily_notional_usd:u64,pub max_open_orders:u32,
 pub max_orders_per_minute:u32,pub collar_bps:u32,
}
impl AgentLimits{
 fn put(&self,b:&mut Vec<u8>){
  u64b(b,self.max_order_notional_usd);u64b(b,self.max_daily_notional_usd);u32b(b,self.max_open_orders);
  u32b(b,self.max_orders_per_minute);u32b(b,self.collar_bps);
 }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct AgentGrant{
 pub version:u32,pub scope:Scope,pub router:u32,pub channel:BtcOutPoint,pub owner:Key,pub agent:Key,
 /// Strictly increasing per account: an old signed grant cannot be replayed.
 pub nonce:u64,pub issued_us:u64,pub expires_us:u64,
 /// `INSTRUMENT_*` bits.
 pub instruments:u8,
 /// Must be false: grants never authorize withdrawals or transfers.
 pub may_withdraw:bool,
 pub limits:AgentLimits,
 pub signature:Bip340Signature,
}
impl AgentGrant{
 pub fn id(&self)->Key{
  let mut b=Vec::new();u32b(&mut b,self.version);self.scope.put(&mut b);u32b(&mut b,self.router);put_op(&mut b,&self.channel);
  b.extend(self.owner);b.extend(self.agent);u64b(&mut b,self.nonce);u64b(&mut b,self.issued_us);u64b(&mut b,self.expires_us);
  b.push(self.instruments);b.push(self.may_withdraw as u8);self.limits.put(&mut b);
  tagged_hash(DOMAIN_AGENT_GRANT,&b)
 }
 /// Sign as the owner (`sk` is the owner's key; sets `owner`).
 pub fn signed(mut self,sk:&Key)->R<Self>{self.owner=public(sk);self.signature=sign(sk,&self.id())?;Ok(self)}
 pub fn allows(&self,instrument:u8)->bool{self.instruments&instrument!=0}
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct AgentRevocation{
 pub version:u32,pub scope:Scope,pub router:u32,pub grant:Key,pub owner:Key,pub issued_us:u64,pub signature:Bip340Signature,
}
impl AgentRevocation{
 pub fn id(&self)->Key{
  let mut b=Vec::new();u32b(&mut b,self.version);self.scope.put(&mut b);u32b(&mut b,self.router);
  b.extend(self.grant);b.extend(self.owner);u64b(&mut b,self.issued_us);
  tagged_hash(DOMAIN_AGENT_REVOKE,&b)
 }
 pub fn signed(mut self,sk:&Key)->R<Self>{self.owner=public(sk);self.signature=sign(sk,&self.id())?;Ok(self)}
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct GrantState{pub grant:AgentGrant,pub admitted_us:u64,pub revoked_us:Option<u64>}
impl GrantState{
 pub fn active_at(&self,now:u64)->bool{self.revoked_us.is_none()&&now<self.grant.expires_us}
}

/// Grants, revocations and which intents each grant's agent signed.
#[derive(Debug,Clone,Default)]
pub struct AgentBook{
 grants:BTreeMap<Key,GrantState>,
 by_channel:BTreeMap<Outpoint,BTreeSet<Key>>,
 last_nonce:BTreeMap<Outpoint,u64>,
 /// Intent id -> (account, grant id) for every intent an agent signed under a live grant.
 intents:BTreeMap<Key,(Outpoint,Key)>,
}
impl AgentBook{
 pub fn grant(&self,id:&Key)->Option<&GrantState>{self.grants.get(id)}
 pub fn grants(&self)->impl Iterator<Item=(&Key,&GrantState)>{self.grants.iter()}
 pub fn grants_of(&self,channel:&BtcOutPoint)->Vec<&GrantState>{
  self.by_channel.get(&op(channel)).map(|s|s.iter().filter_map(|g|self.grants.get(g)).collect()).unwrap_or_default()
 }
 /// The grant that authorized intent `id`, if an agent signed it.
 pub fn signer_of(&self,id:&Key)->Option<Key>{self.intents.get(id).map(|(_,g)|*g)}
 pub(crate) fn admit(&mut self,g:AgentGrant,scope:Scope,router:u32,owner_of:&dyn Fn(&Outpoint)->Option<Key>,now:u64)->R<Key>{
  if g.version!=AGENT_GRANT_VERSION||g.scope!=scope||g.router!=router{return Err(Reject::Scope)}
  let k=op(&g.channel);
  if owner_of(&k)!=Some(g.owner){return Err(Reject::Allocation)}
  if g.agent==[0;32]||g.agent==g.owner||g.may_withdraw||g.instruments==0||g.instruments&!INSTRUMENT_ALL!=0{return Err(Reject::Bounds)}
  let l=&g.limits;
  if l.max_order_notional_usd==0||l.max_daily_notional_usd<l.max_order_notional_usd||l.max_open_orders==0||l.max_orders_per_minute==0||
     l.collar_bps==0||l.collar_bps>10_000{return Err(Reject::Bounds)}
  if g.expires_us<=g.issued_us||g.expires_us-g.issued_us>MAX_GRANT_US{return Err(Reject::Bounds)}
  if g.expires_us<=now{return Err(Reject::Expired)}
  verify(&g.owner,&g.id(),&g.signature)?;
  if g.nonce<=self.last_nonce.get(&k).copied().unwrap_or(0){return Err(Reject::Replay)}
  let live=self.by_channel.get(&k).map_or(0,|s|s.iter().filter(|id|self.grants[*id].active_at(now)).count());
  if live>=MAX_ACTIVE_GRANTS{return Err(Reject::Capacity)}
  let id=g.id();
  if self.grants.contains_key(&id){return Err(Reject::Replay)}
  self.last_nonce.insert(k,g.nonce);
  self.by_channel.entry(k).or_default().insert(id);
  self.grants.insert(id,GrantState{grant:g,admitted_us:now,revoked_us:None});
  Ok(id)
 }
 /// Revoke a grant; returns the intent ids its agent signed (to pull from the books).
 pub(crate) fn revoke(&mut self,r:&AgentRevocation,scope:Scope,router:u32,now:u64)->R<Vec<Key>>{
  if r.version!=AGENT_GRANT_VERSION||r.scope!=scope||r.router!=router{return Err(Reject::Scope)}
  let s=self.grants.get(&r.grant).ok_or(Reject::UnknownOrder)?;
  if s.grant.owner!=r.owner{return Err(Reject::Allocation)}
  if s.revoked_us.is_some(){return Err(Reject::Replay)}
  verify(&r.owner,&r.id(),&r.signature)?;
  self.grants.get_mut(&r.grant).unwrap().revoked_us=Some(now);
  let ids:Vec<Key>=self.intents.iter().filter(|(_,(_,g))|*g==r.grant).map(|(i,_)|*i).collect();
  for i in &ids{self.intents.remove(i);}
  Ok(ids)
 }
 /// The grant, if live at `now`, for `instrument` on the intent's account and owner.
 pub(crate) fn authorize(&self,id:&Key,instrument:u8,channel:&BtcOutPoint,owner:&Key,now:u64)->R<&AgentGrant>{
  let s=self.grants.get(id).ok_or(Reject::UnknownOrder)?;
  if s.revoked_us.is_some(){return Err(Reject::Signature)}
  if now>=s.grant.expires_us{return Err(Reject::Expired)}
  if !s.grant.allows(instrument){return Err(Reject::Scope)}
  if op(&s.grant.channel)!=op(channel)||s.grant.owner!=*owner{return Err(Reject::Allocation)}
  Ok(&s.grant)
 }
 /// A cancel signed by an agent may target only an order its own grant's agent signed.
 pub(crate) fn own_order(&self,grant:&Key,target:&Key)->R<()>{
  let agent=self.grants.get(grant).map(|s|s.grant.agent);
  match self.intents.get(target){
   Some((_,g)) if self.grants.get(g).map(|s|s.grant.agent)==agent=>Ok(()),
   _=>Err(Reject::Allocation),
  }
 }
 pub(crate) fn record(&mut self,intent:Key,channel:&BtcOutPoint,grant:Key){self.intents.insert(intent,(op(channel),grant));}
 /// Whether `grant`'s agent may sign the owner slot of `channel` for a batch whose fills
 /// are `fills`: (channel a, channel b, intent x, intent y) per fill, the two intents in
 /// either order. Each fill side on the channel must be matched by an intent this agent
 /// signed on this account (so a fill against the owner's own order is never delegable),
 /// and the channel must have at least one side.
 pub(crate) fn may_ack(&self,grant:&Key,instrument:u8,channel:&BtcOutPoint,fills:&[(BtcOutPoint,Key,BtcOutPoint,Key)],now:u64)->R<Key>{
  let s=self.grants.get(grant).ok_or(Reject::UnknownOrder)?;
  if !s.active_at(now){return Err(if s.revoked_us.is_some(){Reject::Signature}else{Reject::Expired})}
  if !s.grant.allows(instrument){return Err(Reject::Scope)}
  let k=op(channel);
  if op(&s.grant.channel)!=k{return Err(Reject::Allocation)}
  let mine=|i:&Key|matches!(self.intents.get(i),Some((ch,g)) if *ch==k&&self.grants.get(g).map(|x|x.grant.agent)==Some(s.grant.agent));
  let mut n=0;
  for (ca,x,cb,y) in fills{
   let on=(op(ca)==k) as usize+(op(cb)==k) as usize;
   if on==0{continue}
   n+=on;
   if (mine(x) as usize)+(mine(y) as usize)<on{return Err(Reject::Allocation)}
  }
  if n==0{return Err(Reject::Allocation)}
  Ok(s.grant.agent)
 }
}
