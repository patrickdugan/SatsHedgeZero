//! In-memory, single-writer commitment preparation. No Lightning authority,
//! balance release, payment, or durable recovery. Every exact DLC leg is retained.
use super::*;

pub const COALESCE_US:u64=100_000;

#[derive(Debug,Clone)]
pub struct ChannelObligation{
 pub channel:BtcOutPoint,pub owner:Key,pub margin_sats:u64,pub fee_sats:u64,
}
#[derive(Debug,Clone)]
pub struct ChannelPayout{
 pub channel:BtcOutPoint,pub payout_sats:u64,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct BatchApproval{
 pub channel:BtcOutPoint,pub signature:Bip340Signature,
}

/// All fields private: only a router's append-only fill log creates a batch.
#[derive(Debug,Clone)]
pub struct Batch{
 scope:Scope,router:u32,sequence:u64,window_start:u64,window_end:u64,
 previous:Key,digest:Key,legs:Vec<Fill>,accounts:Vec<ChannelObligation>,
 oracle_due:u128,router_due:u128,
}
impl Batch{
 pub fn scope(&self)->Scope{self.scope}
 pub fn router(&self)->u32{self.router}
 pub fn sequence(&self)->u64{self.sequence}
 pub fn window(&self)->(u64,u64){(self.window_start,self.window_end)}
 pub fn previous(&self)->Key{self.previous}
 pub fn digest(&self)->Key{self.digest}
 pub fn legs(&self)->&[Fill]{&self.legs}
 pub fn accounts(&self)->&[ChannelObligation]{&self.accounts}
 pub fn oracle_due_sats(&self)->u128{self.oracle_due}
 pub fn router_due_sats(&self)->u128{self.router_due}
 /// Exact clipped, independently rounded DLC payouts at one common mark.
 /// Fee obligations remain separate. This is diagnostic arithmetic, not settlement.
 pub fn payouts_at_price(&self,price:u64)->R<Vec<ChannelPayout>>{
  let mut sums:BTreeMap<Outpoint,u64>=BTreeMap::new();
  for f in &self.legs{
   let p=f.spec.payout_at_price(price);
   let (maker,taker)=if f.maker_side==OrderSide::Long{(p.long_sats,p.short_sats)}else{(p.short_sats,p.long_sats)};
   for (channel,v) in [(&f.maker_channel,maker),(&f.taker_channel,taker)]{
    let slot=sums.entry(op(channel)).or_default();
    *slot=slot.checked_add(v).ok_or(Reject::Bounds)?;
   }
  }
  let total:u128=sums.values().map(|&v|v as u128).sum();
  let margin:u128=self.accounts.iter().map(|a|a.margin_sats as u128).sum();
  if total!=margin{return Err(Reject::Bounds)}
  Ok(sums.into_iter().map(|((txid,vout),payout_sats)|ChannelPayout{channel:BtcOutPoint{txid,vout},payout_sats}).collect())
 }
 /// Channel-specific, scope-bound approval of this exact proposed batch.
 pub fn approval_message(&self,channel:&BtcOutPoint)->Option<Key>{
  let account=self.accounts.iter().find(|a|op(&a.channel)==op(channel))?;
  let mut b=Vec::new();b.extend(self.digest);put_op(&mut b,channel);b.extend(account.owner);
  Some(tagged_hash(b"SHZ/HFT/BATCH-APPROVAL/V1",&b))
 }
 /// All participating channel owners must approve exactly once.
 /// Owner signatures do not authorize an LN state transition by themselves.
 pub fn verify_approvals(&self,approvals:&[BatchApproval])->R<()>{
  if approvals.len()!=self.accounts.len(){return Err(Reject::Allocation)}
  let mut seen=BTreeSet::new();
  let owners:BTreeMap<_,_>=self.accounts.iter().map(|a|(op(&a.channel),a.owner)).collect();
  for a in approvals{
   let outpoint=op(&a.channel);
   if !seen.insert(outpoint){return Err(Reject::Replay)}
   let key=owners.get(&outpoint).ok_or(Reject::Allocation)?;
   let mut b=Vec::new();b.extend(self.digest);put_op(&mut b,&a.channel);b.extend(key);
   verify(key,&tagged_hash(b"SHZ/HFT/BATCH-APPROVAL/V1",&b),&a.signature)?;
  }
  Ok(())
 }
}
fn leg_hash(f:&Fill)->Key{
 let mut b=Vec::new();f.scope.put(&mut b);u32b(&mut b,f.router);u64b(&mut b,f.execution_us);
 b.extend(f.maker_id);b.extend(f.taker_id);put_op(&mut b,&f.maker_channel);put_op(&mut b,&f.taker_channel);
 b.extend(f.maker_owner);b.extend(f.taker_owner);b.extend(f.mark_id);
 b.push(if f.maker_side==OrderSide::Long{1}else{2});
 // validate_v0 below fixes collateral=VanillaBtc and fee_policy=ZERO.
 for n in [f.spec.usd_notional,f.spec.entry_price_usd,f.spec.long_margin_sats,f.spec.short_margin_sats,
           f.maker_fee_sats,f.taker_fee_sats,f.oracle_due_sats,f.router_due_sats]{u64b(&mut b,n)}
 tagged_hash(b"SHZ/HFT/BATCH-LEG/V1",&b)
}
impl Router{
 /// Seal at most one nonempty, elapsed 100ms window from the immutable fill log.
 /// Router clock, not a supplied client timestamp, determines readiness. The
 /// clock is monotone and a fill at the end boundary belongs to the next window.
 /// Reservations and fill receipts are retained unchanged.
 pub fn seal_fill_batch(&mut self)->R<Option<Batch>>{
  let Some(first)=self.fill_log.get(self.batch_cursor)else{return Ok(None)};
  let f=&self.fills[first];
  let start=f.execution_us/COALESCE_US*COALESCE_US;
  let end=start.checked_add(COALESCE_US).ok_or(Reject::Clock)?;
  if self.clock<end{return Ok(None)}
  let seq=self.batch_sequence.checked_add(1).ok_or(Reject::Bounds)?;
  let mut next=self.batch_cursor;
  let mut legs=Vec::new();
  let mut sums:BTreeMap<Outpoint,ChannelObligation>=BTreeMap::new();
  let mut oracle=0u128;let mut router_due=0u128;
  while let Some(id)=self.fill_log.get(next){
   let f=&self.fills[id];
   if f.execution_us>=end{break}
   if f.execution_us<start||f.scope!=self.scope||f.router!=self.id||f.taker_id!=*id{return Err(Reject::Scope)}
   f.spec.validate_v0().map_err(|_|Reject::Bounds)?;
   if f.maker_fee_sats as u128+f.taker_fee_sats as u128!=f.oracle_due_sats as u128+f.router_due_sats as u128{return Err(Reject::FeeLimit)}
   let (mm,tm)=if f.maker_side==OrderSide::Long{(f.spec.long_margin_sats,f.spec.short_margin_sats)}else{(f.spec.short_margin_sats,f.spec.long_margin_sats)};
   for (channel,owner,margin,fee) in [(&f.maker_channel,f.maker_owner,mm,f.maker_fee_sats),(&f.taker_channel,f.taker_owner,tm,f.taker_fee_sats)]{
    let account=self.accounts.get(&op(channel)).ok_or(Reject::Allocation)?;
    if account.owner!=owner{return Err(Reject::Allocation)}
    let sum=sums.entry(op(channel)).or_insert_with(||ChannelObligation{channel:channel.clone(),owner,margin_sats:0,fee_sats:0});
    sum.margin_sats=sum.margin_sats.checked_add(margin).ok_or(Reject::Bounds)?;
    sum.fee_sats=sum.fee_sats.checked_add(fee).ok_or(Reject::Bounds)?;
    if sum.margin_sats.checked_add(sum.fee_sats).ok_or(Reject::Bounds)?>account.balance.pending{return Err(Reject::Capacity)}
   }
   oracle+=f.oracle_due_sats as u128;router_due+=f.router_due_sats as u128;
   legs.push(f.clone());next+=1;
  }
  let accounts:Vec<_>=sums.into_values().collect();
  if legs.is_empty()||accounts.iter().map(|a|a.fee_sats as u128).sum::<u128>()!=oracle+router_due{return Err(Reject::Bounds)}
  let mut b=Vec::new();self.scope.put(&mut b);u32b(&mut b,self.id);
  u64b(&mut b,seq);u64b(&mut b,start);u64b(&mut b,end);b.extend(self.last_batch_digest);
  u64b(&mut b,legs.len() as u64);
  for f in &legs{b.extend(leg_hash(f))}
  u64b(&mut b,accounts.len() as u64);
  for a in &accounts{put_op(&mut b,&a.channel);b.extend(a.owner);u64b(&mut b,a.margin_sats);u64b(&mut b,a.fee_sats);}
  b.extend(oracle.to_le_bytes());b.extend(router_due.to_le_bytes());
  let digest=tagged_hash(b"SHZ/HFT/BATCH/V1",&b);
  let batch=Batch{scope:self.scope,router:self.id,sequence:seq,window_start:start,window_end:end,previous:self.last_batch_digest,digest,legs,accounts,oracle_due:oracle,router_due};
  // No external effect; the caller must retain the batch. No abort/release path.
  self.batch_cursor=next;self.batch_sequence=seq;self.last_batch_digest=digest;
  Ok(Some(batch))
 }
}
