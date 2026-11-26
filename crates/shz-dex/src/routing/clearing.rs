//! Multilateral clearing for the venue as central counterparty (V3 acknowledgements).
//!
//! Margin release (`positions`, V2) values each closed lot as its own opening DLC leg:
//! a loss clamps at the lot's margin and a gain at the margin of the lot's *opening*
//! counterparty. Once lots are novated (opened against one account, closed against
//! another) those per-lot clamps stop adding up: a gain can be paid while the loss that
//! funds it is never collected, and a collected loss can fail to reach any winner
//! (docs/SHZ_VENUE_CLEARING.md, findings A1-A5).
//!
//! Clearing replaces the per-lot clamp with one ledger for the whole venue:
//!
//! * every closed slice realizes its exact unclamped PnL (`Settlement::pnl`): entry
//!   value minus closing value for a long, the reverse for a short, where a fill's value
//!   `floor(qty * 1e8 / price)` enters its long and its short leg identically, so the
//!   PnL of a fully closed book sums to exactly zero;
//! * per batch, each account's PnL is netted across all its closes into one amount;
//! * a loss is collected from the margin those closes release, then from the account's
//!   own outstanding claim; the rest is a shortfall (closed past its bankruptcy price);
//! * shortfalls run through the default waterfall: clearing fund, then a pro-rata
//!   haircut on every outstanding winning claim (this batch's gains and every deferred
//!   claim), then a carried deficit that haircuts the next gains;
//! * gains are paid in cash only from what the clearing pool holds (`cash`). The part
//!   it cannot pay yet stays a deferred claim, paid when the account is next in a batch.
//!
//! Invariants, checked by `clear` and by `Summary::identity`:
//! * per batch, the net settlement vector sums to zero with the pool's line:
//!   `sum(row.net) + (cash_after - cash_before) == 0`;
//! * the pool never pays out cash it does not hold (`cash` never goes below zero, or
//!   below its starting value if a legacy deficit made that negative);
//! * `cash - claims - fund + carry == book`, where `book` is the signed entry value of
//!   every open lot. On a flat book this reads `cash == claims + fund - carry`, and since
//!   carry is non-zero only after every claim and the fund are exhausted, carry is zero
//!   and the pool holds every deferred claim plus the unused fund, to the sat.
use super::*;
use super::durable::PositionOf;
use super::positions::{self,Position,Settlement};

/// Deepest layer of the default waterfall a batch reached.
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Default,Serialize,Deserialize)]
pub enum Waterfall{
 /// No losses were realized.
 #[default] None,
 /// Losses were covered by the margin the closes released.
 Margin,
 /// A loser's own outstanding claim covered the rest.
 OwnClaim,
 /// The clearing fund absorbed a shortfall.
 Fund,
 /// Winning claims were haircut pro rata.
 Haircut,
 /// A deficit is carried to haircut later gains.
 Carried,
}
impl Waterfall{fn code(self)->u8{self as u8}}

/// Clearing ledger of the venue, switched on by a journaled `EnableClearing`.
#[derive(Debug,Clone,PartialEq,Eq,Default,Serialize,Deserialize)]
pub struct ClearingState{
 /// Clearing fund the venue committed when clearing was switched on.
 pub fund0:u64,
 /// Sats the clearing pool holds: fund plus collected losses minus paid gains.
 pub cash:i64,
 /// Loss-absorbing fund capacity left.
 pub fund:u64,
 /// Shortfall no fund or claim could absorb yet; it haircuts the next gains.
 pub carry:u64,
 /// Imbalance inherited from margin-release (V2) history when clearing was switched on:
 /// positive means V2 had kept sats that no winner received, negative that it paid
 /// gains no loser funded. Folded into `fund` (or `carry`).
 pub legacy:i64,
 claims:BTreeMap<Outpoint,u64>,
}
impl ClearingState{
 /// Open the ledger. `accounts` is every account's position and balance at the switch:
 /// the pool's cash is the fund plus whatever V2 history left with the venue, and the
 /// fund is set so that the clearing identity holds from the first V3 batch.
 pub(crate) fn open<'a>(fund0:u64,accounts:impl Iterator<Item=(&'a Position,&'a Balance)>)->R<Self>{
  let (mut book,mut realized)=(0i128,0i128);
  for (p,b) in accounts{book+=p.book_value();realized+=b.realized_pnl as i128;}
  let cash=fund0 as i128-realized;
  let capacity=cash-book;
  let (fund,carry)=if capacity>=0{(capacity,0)}else{(0,-capacity)};
  let n=|x:i128|i64::try_from(x).map_err(|_|Reject::Bounds);
  let u=|x:i128|u64::try_from(x).map_err(|_|Reject::Bounds);
  Ok(Self{fund0,cash:n(cash)?,fund:u(fund)?,carry:u(carry)?,legacy:n(capacity-fund0 as i128)?,claims:BTreeMap::new()})
 }
 /// Deferred claim of `channel`: a realized gain the pool has not paid yet.
 pub fn claim(&self,channel:&BtcOutPoint)->u64{self.claims.get(&op(channel)).copied().unwrap_or(0)}
 pub fn claims(&self)->impl Iterator<Item=(BtcOutPoint,u64)>+'_{self.claims.iter().map(|(&(txid,vout),&c)|(BtcOutPoint{txid,vout},c))}
 pub fn claims_total(&self)->u64{self.claims.values().sum()}
 /// Ledger totals against the open book (`book`: sum of every account's `book_value`).
 pub fn summary(&self,book:i128)->Summary{
  let claims=self.claims_total();
  Summary{fund0:self.fund0,cash:self.cash,fund:self.fund,carry:self.carry,claims,legacy:self.legacy,book,
   identity:self.cash as i128-claims as i128-self.fund as i128+self.carry as i128-book}
 }
}

/// Ledger totals with the clearing identity term (`identity` is zero in every state).
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct Summary{
 pub fund0:u64,pub cash:i64,pub fund:u64,pub carry:u64,pub claims:u64,pub legacy:i64,
 /// Signed entry value of every open lot (long `+`, short `-`).
 pub book:i128,
 /// `cash - claims - fund + carry - book`.
 pub identity:i128,
}

/// One account's line of the multilateral net settlement of a batch.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct ClearingRow{
 pub channel:BtcOutPoint,
 /// Exact unclamped PnL of every slice the account closed in the batch, netted.
 pub pnl:i64,
 /// Lot margin the closes released.
 pub released:u64,
 /// Loss collected from the released margin into the pool.
 pub collected:u64,
 /// Loss covered by cancelling part of the account's own deferred claim.
 pub own_claim_used:u64,
 /// Loss neither margin nor claim covered (the account's default).
 pub shortfall:u64,
 /// Haircut on this account's gain and deferred claim.
 pub haircut:u64,
 pub claim_before:u64,pub claim_after:u64,
 /// Cash the pool paid the account: gain and deferred claim.
 pub paid:u64,
 /// Net sats between the account and the pool: `paid - collected`. The channel adapter
 /// moves exactly this amount on the account's lane.
 pub net:i64,
}
impl ClearingRow{
 fn put(&self,b:&mut Vec<u8>){
  put_op(b,&self.channel);b.extend(self.pnl.to_le_bytes());
  for n in [self.released,self.collected,self.own_claim_used,self.shortfall,self.haircut,self.claim_before,self.claim_after,self.paid]{u64b(b,n)}
  b.extend(self.net.to_le_bytes());
 }
}

/// Multilateral clearing result of one committed batch.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct BatchClearing{
 /// One row per batch account, in batch order.
 pub rows:Vec<ClearingRow>,
 /// Haircuts on deferred claims of accounts not in the batch (no cash moves for them).
 pub claim_haircuts:Vec<(BtcOutPoint,u64)>,
 /// Sum of the rows' shortfalls.
 pub shortfall:u64,
 pub fund_absorbed:u64,
 /// Total haircut on gains and claims (absorbs this batch's shortfall and any carry).
 pub haircut:u64,
 pub layer:Waterfall,
 pub cash_before:i64,pub cash_after:i64,
 pub fund_after:u64,pub carry_after:u64,pub claims_after:u64,
}
impl BatchClearing{
 /// The pool's own line: what it received net (`-sum(row.net)`).
 pub fn pool_net(&self)->i64{self.cash_after-self.cash_before}
 /// Digest every lane's V3 acknowledgement signs: the whole net settlement vector.
 pub fn digest(&self)->Key{
  let mut b=Vec::new();u64b(&mut b,self.rows.len()as u64);
  for r in &self.rows{r.put(&mut b)}
  u64b(&mut b,self.claim_haircuts.len()as u64);
  for (c,h) in &self.claim_haircuts{put_op(&mut b,c);u64b(&mut b,*h)}
  for n in [self.shortfall,self.fund_absorbed,self.haircut]{u64b(&mut b,n)}
  b.push(self.layer.code());b.extend(self.cash_before.to_le_bytes());b.extend(self.cash_after.to_le_bytes());
  for n in [self.fund_after,self.carry_after,self.claims_after]{u64b(&mut b,n)}
  tagged_hash(b"SHZ/HFT/CLEARING/V1",&b)
 }
 pub(crate) fn row(&self,channel:&BtcOutPoint)->Option<&ClearingRow>{self.rows.iter().find(|r|op(&r.channel)==op(channel))}
 pub(crate) fn put_row(&self,channel:&BtcOutPoint,b:&mut Vec<u8>)->R<()>{
  self.row(channel).ok_or(Reject::Allocation)?.put(b);b.extend(self.digest());Ok(())
 }
}

/// Fully validated clearing of one batch; applying it cannot fail.
pub(crate) struct ClearPlan{
 pub report:BatchClearing,
 /// Each batch account's new position and the settlement its acknowledgement signs, in
 /// batch order. `Settlement::payout` is the cleared cash credit, not the V2 lot payout.
 pub lanes:Vec<(Position,Settlement)>,
 pub next:ClearingState,
}

/// Split `total` over `amounts` pro rata, floors first, then the remainder one item at a
/// time in order. Requires `total <= sum(amounts)`; every share is at most its amount.
fn prorata(total:u64,amounts:&[u64])->Vec<u64>{
 let sum:u128=amounts.iter().map(|&a|a as u128).sum();
 if sum==0||total==0{return vec![0;amounts.len()]}
 let mut out:Vec<u64>=amounts.iter().map(|&a|(total as u128*a as u128/sum)as u64).collect();
 let mut rest=total-out.iter().sum::<u64>();
 for (o,&a) in out.iter_mut().zip(amounts){let x=rest.min(a-*o);*o+=x;rest-=x;}
 out
}

/// Clear one committed batch against the ledger.
pub(crate) fn clear(state:&ClearingState,batch:&Batch,position_of:PositionOf)->R<ClearPlan>{
 let mut next=state.clone();
 let mut lanes=Vec::new();let mut rows=Vec::new();
 for a in batch.accounts(){
  let key=op(&a.channel);
  let (p,s)=positions::settle(&position_of(&key).ok_or(Reject::Allocation)?,&key,batch.legs())?;
  let claim=next.claim(&a.channel);
  rows.push(ClearingRow{channel:a.channel.clone(),pnl:s.pnl,released:s.released_margin,collected:0,own_claim_used:0,shortfall:0,haircut:0,
   claim_before:claim,claim_after:claim,paid:0,net:0});
  lanes.push((p,s));
 }
 let mut layer=Waterfall::None;
 // 1. Losses: released margin, then the loser's own claim; the rest is a shortfall.
 let mut collected=0u64;let mut shortfall=0u64;
 for r in rows.iter_mut().filter(|r|r.pnl<0){
  let need=r.pnl.unsigned_abs();
  r.collected=need.min(r.released);
  let rest=need-r.collected;
  r.own_claim_used=rest.min(r.claim_before);
  r.shortfall=rest-r.own_claim_used;
  r.claim_after=r.claim_before-r.own_claim_used;
  set_claim(&mut next,&r.channel,r.claim_after);
  collected=collected.checked_add(r.collected).ok_or(Reject::Bounds)?;
  shortfall=shortfall.checked_add(r.shortfall).ok_or(Reject::Bounds)?;
  layer=layer.max(if r.own_claim_used>0{Waterfall::OwnClaim}else{Waterfall::Margin});
 }
 next.cash=next.cash.checked_add(i64::try_from(collected).map_err(|_|Reject::Bounds)?).ok_or(Reject::Bounds)?;
 // 2. Clearing fund.
 let fund_absorbed=shortfall.min(next.fund);
 next.fund-=fund_absorbed;
 if fund_absorbed>0{layer=layer.max(Waterfall::Fund)}
 // 3. Pro-rata haircut on every outstanding winning claim: deferred claims (all
 // accounts, key order), then this batch's gains (batch order). Absorbs the shortfall
 // left after the fund and any carried deficit.
 let owed=(shortfall-fund_absorbed).checked_add(next.carry).ok_or(Reject::Bounds)?;
 let mut gains:Vec<u64>=rows.iter().map(|r|if r.pnl>0{r.pnl as u64}else{0}).collect();
 let mut claim_haircuts=Vec::new();let mut haircut=0;
 if owed>0{
  let keys:Vec<Outpoint>=next.claims.keys().copied().collect();
  let mut amounts:Vec<u64>=keys.iter().map(|k|next.claims[k]).collect();
  amounts.extend(&gains);
  let base=amounts.iter().try_fold(0u64,|s,&a|s.checked_add(a)).ok_or(Reject::Bounds)?;
  haircut=owed.min(base);
  let cut=prorata(haircut,&amounts);
  for (k,&c) in keys.iter().zip(&cut){
   if c==0{continue}
   let left=next.claims[k]-c;
   set_claim_key(&mut next,*k,left);
   let ch=BtcOutPoint{txid:k.0,vout:k.1};
   match rows.iter_mut().find(|r|op(&r.channel)==*k){
    Some(r)=>{r.haircut+=c;r.claim_after=left;},
    None=>claim_haircuts.push((ch,c)),
   }
  }
  for ((g,&c),r) in gains.iter_mut().zip(&cut[keys.len()..]).zip(rows.iter_mut()){*g-=c;r.haircut+=c;}
  next.carry=owed-haircut;
  if haircut>0{layer=layer.max(Waterfall::Haircut)}
  if next.carry>0{layer=layer.max(Waterfall::Carried)}
 }
 // 4. Pay each batch account its gain and deferred claim from the pool's cash, pro rata
 // when the pool cannot pay everyone; the unpaid part is (or stays) a deferred claim.
 let dues:Vec<u64>=rows.iter().zip(&gains).map(|(r,&g)|g.checked_add(r.claim_after).ok_or(Reject::Bounds)).collect::<R<_>>()?;
 let due:u64=dues.iter().try_fold(0u64,|s,&a|s.checked_add(a)).ok_or(Reject::Bounds)?;
 let available=u64::try_from(next.cash.max(0)).unwrap_or(0);
 let paid=if due<=available{dues.clone()}else{prorata(available,&dues)};
 let mut out=0u64;
 for ((r,(&d,&p)),(_,s)) in rows.iter_mut().zip(dues.iter().zip(&paid)).zip(lanes.iter_mut()){
  r.paid=p;r.claim_after=d-p;set_claim(&mut next,&r.channel,r.claim_after);
  r.net=p as i64-r.collected as i64;
  s.payout=s.released_margin-r.collected+p;
  out+=p;
 }
 next.cash-=i64::try_from(out).map_err(|_|Reject::Bounds)?;
 // Invariants: the net vector sums to zero with the pool's line, and the pool never
 // pays cash it does not hold.
 let net:i128=rows.iter().map(|r|r.net as i128).sum();
 if net+(next.cash as i128-state.cash as i128)!=0||next.cash<state.cash.min(0){return Err(Reject::Bounds)}
 let report=BatchClearing{rows,claim_haircuts,shortfall,fund_absorbed,haircut,layer,cash_before:state.cash,cash_after:next.cash,
  fund_after:next.fund,carry_after:next.carry,claims_after:next.claims_total()};
 Ok(ClearPlan{report,lanes,next})
}
fn set_claim(s:&mut ClearingState,c:&BtcOutPoint,v:u64){set_claim_key(s,op(c),v)}
fn set_claim_key(s:&mut ClearingState,k:Outpoint,v:u64){if v==0{s.claims.remove(&k);}else{s.claims.insert(k,v);}}

#[cfg(test)]
mod tests{
 use super::prorata;
 #[test]
 fn prorata_is_exact_and_bounded(){
  for (t,a) in [(7u64,vec![3u64,3,3]),(10,vec![1,2,3,4]),(1,vec![5,0,5]),(9,vec![4,5]),(0,vec![1])]{
   let s=prorata(t,&a);
   assert_eq!(s.iter().sum::<u64>(),t);
   assert!(s.iter().zip(&a).all(|(x,y)|x<=y));
  }
 }
}
