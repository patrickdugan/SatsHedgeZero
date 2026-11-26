//! Margin release on committed batches.
//!
//! Every committed fill opens or closes exposure on each side's account. An account
//! carries one `Position`: FIFO lots, all on one side. When a committed leg is on the
//! opposite side of the open lots, the overlapping quantity closes lots oldest first:
//!
//! * the closed lot's margin leaves `committed`;
//! * the lot is valued exactly as its opening DLC leg would settle at the closing
//!   fill's price (`InverseContractSpec::payout_at_price` with the lot's own margin
//!   and its opening counterparty's margin), and that payout is credited to `free`;
//! * `realized_pnl` moves by payout minus released margin;
//! * the closing leg's own margin for the closed quantity goes straight back to
//!   `free`; only the excess quantity (a flip) opens a new lot.
//!
//! The venue is the central counterparty: a lot closed against a different account
//! than the one it was opened against is netted at the account level. The payout
//! clamp is the DLC rule, so a loss never exceeds the lot's margin and a gain never
//! exceeds the opening counterparty's margin for that quantity. Gains are funded by
//! the margin still committed in the open lots on the other side.
//!
//! A `Settlement` is a pure function of the account's position after the previous
//! resolution and the legs of the batch being resolved. It is computed only when a
//! Commit bundle is resolved and is bound into every lane's acknowledgement message,
//! so the owner, peer and monitor signatures cover the released margin and PnL.
//!
//! The per-lot clamp does not add up across novated lots (docs/SHZ_VENUE_CLEARING.md).
//! With multilateral clearing active (`clearing`), closes settle on `Settlement::pnl`,
//! the exact unclamped PnL against each lot's entry value, and the cash payout comes
//! from the clearing ledger.
use super::*;
use shz_margin::CollateralAsset;
use std::collections::VecDeque;

/// One open slice of exposure: `qty` USD at `price`, backed by `margin` sats of this
/// account and `opp_margin` sats posted by the counterparty of the opening fill.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Lot{pub side:OrderSide,pub qty:u64,pub price:u64,pub margin:u64,pub opp_margin:u64}

/// Open lots of one account, oldest first, all on one side. `values` runs parallel to
/// `lots`: each lot's exact entry value in sats (`value(qty, price)` of the opening leg,
/// split with remainders kept), used by multilateral clearing so that every fill's value
/// enters the long and the short side identically and realized PnL sums to zero exactly.
#[derive(Debug,Clone,Default,PartialEq,Eq)]
pub struct Position{lots:VecDeque<Lot>,values:VecDeque<u64>}
impl Position{
 pub fn lots(&self)->impl Iterator<Item=&Lot>{self.lots.iter()}
 pub fn side(&self)->Option<OrderSide>{self.lots.front().map(|l|l.side)}
 /// Signed USD exposure: positive long, negative short.
 pub fn net_usd(&self)->i64{
  let q:u64=self.lots.iter().map(|l|l.qty).sum();
  if self.side()==Some(OrderSide::Short){-(q as i64)}else{q as i64}
 }
 /// Margin committed behind the open lots.
 pub fn margin(&self)->u64{self.lots.iter().map(|l|l.margin).sum()}
 /// Sats the open lots would pay this account at `price` (exact, per lot).
 pub fn value_at(&self,price:u64)->u64{self.lots.iter().map(|l|lot_payout(l,l.qty,l.margin,l.opp_margin,price)).sum()}
 /// Inverse-average entry price, `qty / sum(qty_i / price_i)`.
 pub fn avg_entry_usd(&self)->Option<f64>{
  let q:u64=self.lots.iter().map(|l|l.qty).sum();
  if q==0{return None}
  let inv:f64=self.lots.iter().map(|l|l.qty as f64/l.price as f64).sum();
  Some(q as f64/inv)
 }
 /// Signed entry value of the open lots, sats: long lots count `+`, short lots `-`.
 /// Summed over every account it is the open book term of the clearing identity.
 pub fn book_value(&self)->i128{
  let v:u128=self.values.iter().map(|&v|v as u128).sum();
  if self.side()==Some(OrderSide::Short){-(v as i128)}else{v as i128}
 }
 /// Exact unclamped PnL of the open lots at `price` under multilateral clearing:
 /// entry value minus value at `price` for a long, the reverse for a short.
 pub fn pnl_at(&self,price:u64)->Option<i128>{
  let q:u64=self.lots.iter().map(|l|l.qty).sum();
  let now=value(q,price).ok()? as i128;
  let b=self.book_value();
  Some(if self.side()==Some(OrderSide::Short){now+b}else{b-now})
 }
}

/// Exact sats value of `usd` at `price`: `floor(usd * 1e8 / price)`.
pub fn value(usd:u64,price:u64)->R<u64>{
 if price==0{return Err(Reject::Bounds)}
 u64::try_from(usd as u128*100_000_000/price as u128).map_err(|_|Reject::Bounds)
}

/// Effect of one committed batch on one account.
#[derive(Debug,Clone,Copy,PartialEq,Eq,Default)]
pub struct Settlement{
 /// Leg margin that opened new lots (pending -> committed).
 pub opened_margin:u64,
 /// Leg margin of quantity that closed existing lots (pending -> free).
 pub closed_leg_margin:u64,
 /// Lot margin released by the closes (leaves committed).
 pub released_margin:u64,
 /// Exact DLC payout of the closed lots at the closing prices (credited to free).
 pub payout:u64,
 /// Quantity closed, USD.
 pub closed_usd:u64,
 pub net_before:i64,pub net_after:i64,
 /// Position margin after the batch; equals `committed` once margin release is active.
 pub margin_after:u64,
 /// Exact unclamped PnL of the closed slices (entry value against closing value). Not
 /// part of the V2 acknowledgement; multilateral clearing settles on it.
 pub pnl:i64,
}
impl Settlement{
 pub fn realized_pnl(&self)->i64{self.payout as i64-self.released_margin as i64}
 pub(crate) fn put(&self,b:&mut Vec<u8>){
  for n in [self.opened_margin,self.closed_leg_margin,self.released_margin,self.payout,self.closed_usd]{u64b(b,n)}
  b.extend(self.net_before.to_le_bytes());b.extend(self.net_after.to_le_bytes());u64b(b,self.margin_after);
 }
}

pub(crate) fn part(total:u64,x:u64,of:u64)->u64{(total as u128*x as u128/of as u128)as u64}

/// Payout to the lot's side for `x` USD of the lot, backed by `m` own and `o`
/// counterparty sats, settled at `price`: the inverse contract spec's clamped payout.
fn lot_payout(l:&Lot,x:u64,m:u64,o:u64,price:u64)->u64{
 let (long,short)=if l.side==OrderSide::Long{(m,o)}else{(o,m)};
 let spec=InverseContractSpec{usd_notional:x,entry_price_usd:l.price,long_margin_sats:long,short_margin_sats:short,
  collateral:CollateralAsset::VanillaBtc,fee_policy:ZeroFeePolicy::ZERO};
 let p=spec.payout_at_price(price);
 if l.side==OrderSide::Long{p.long_sats}else{p.short_sats}
}

/// `(side, qty, price, own margin, counterparty margin)` of every leg `channel` is on, in batch order.
pub(crate) fn account_legs(channel:&Outpoint,legs:&[Fill])->Vec<(OrderSide,u64,u64,u64,u64)>{
 let mut out=Vec::new();
 for f in legs{
  let taker_side=if f.maker_side==OrderSide::Long{OrderSide::Short}else{OrderSide::Long};
  for (c,side) in [(&f.maker_channel,f.maker_side),(&f.taker_channel,taker_side)]{
   if op(c)!=*channel{continue}
   let (own,opp)=if side==OrderSide::Long{(f.spec.long_margin_sats,f.spec.short_margin_sats)}else{(f.spec.short_margin_sats,f.spec.long_margin_sats)};
   out.push((side,f.spec.usd_notional,f.spec.entry_price_usd,own,opp));
  }
 }
 out
}

/// Net `channel`'s legs of a committed batch against its open lots.
pub fn settle(position:&Position,channel:&Outpoint,legs:&[Fill])->R<(Position,Settlement)>{
 let mut p=position.clone();
 let mut s=Settlement{net_before:p.net_usd(),..Settlement::default()};
 for (side,qty,price,margin,opp) in account_legs(channel,legs){
  if qty==0||price==0{return Err(Reject::Bounds)}
  let mut left=qty;
  let leg_value=value(qty,price)?;
  while left>0&&p.side().is_some_and(|ps|ps!=side){
   let lot=p.lots.front_mut().unwrap();let entry=p.values.front_mut().unwrap();
   let x=left.min(lot.qty);
   let (m,o,e)=if x==lot.qty{(lot.margin,lot.opp_margin,*entry)}else{(part(lot.margin,x,lot.qty),part(lot.opp_margin,x,lot.qty),part(*entry,x,lot.qty))};
   let pay=lot_payout(lot,x,m,o,price);
   // Closing value of this slice: telescoping split of the leg value, exact in sum.
   let done=qty-left;
   let exit=part(leg_value,done+x,qty)-part(leg_value,done,qty);
   let pnl=if lot.side==OrderSide::Long{e as i128-exit as i128}else{exit as i128-e as i128};
   s.pnl=i64::try_from(s.pnl as i128+pnl).map_err(|_|Reject::Bounds)?;
   s.released_margin=s.released_margin.checked_add(m).ok_or(Reject::Bounds)?;
   s.payout=s.payout.checked_add(pay).ok_or(Reject::Bounds)?;
   lot.qty-=x;lot.margin-=m;lot.opp_margin-=o;*entry-=e;left-=x;
   if lot.qty==0{p.lots.pop_front();p.values.pop_front();}
  }
  let closed=qty-left;
  let closed_margin=if left==0{margin}else{part(margin,closed,qty)};
  s.closed_usd=s.closed_usd.checked_add(closed).ok_or(Reject::Bounds)?;
  s.closed_leg_margin=s.closed_leg_margin.checked_add(closed_margin).ok_or(Reject::Bounds)?;
  if left>0{
   let opp_open=if closed==0{opp}else{opp-part(opp,closed,qty)};
   s.opened_margin=s.opened_margin.checked_add(margin-closed_margin).ok_or(Reject::Bounds)?;
   p.lots.push_back(Lot{side,qty:left,price,margin:margin-closed_margin,opp_margin:opp_open});
   p.values.push_back(leg_value-part(leg_value,closed,qty));
  }
 }
 s.net_after=p.net_usd();s.margin_after=p.margin();
 Ok((p,s))
}

/// Apply a settlement to a balance whose batch margin already left `pending`
/// (`incoming` = that margin, routed by the settlement to committed or free).
pub(crate) fn apply(mut b:Balance,s:&Settlement,incoming:u64)->R<Balance>{
 if s.opened_margin.checked_add(s.closed_leg_margin)!=Some(incoming){return Err(Reject::Bounds)}
 b.committed=b.committed.checked_add(s.opened_margin).and_then(|c|c.checked_sub(s.released_margin)).ok_or(Reject::Bounds)?;
 b.free=b.free.checked_add(s.closed_leg_margin).and_then(|f|f.checked_add(s.payout)).ok_or(Reject::Bounds)?;
 b.realized_pnl=b.realized_pnl.checked_add(s.realized_pnl()).ok_or(Reject::Bounds)?;
 Ok(b)
}

/// One-time reconciliation when margin release is switched on for a router that has
/// already committed batches without it: replay netting over every committed batch in
/// sequence order, starting from empty positions and the margin those batches committed.
/// Returns the new positions and balances, and every per-batch settlement.
#[allow(clippy::type_complexity)]
pub(crate) fn reconcile<'a>(committed:impl Iterator<Item=(u64,&'a Batch)>,balance_of:&dyn Fn(&Outpoint)->Option<Balance>)
 ->R<(BTreeMap<Outpoint,(Position,Balance)>,Vec<(u64,Vec<(BtcOutPoint,Settlement)>)>)>{
 let mut state:BTreeMap<Outpoint,(Position,Balance)>=BTreeMap::new();
 let mut per_batch=Vec::new();
 for (seq,batch) in committed{
  let mut rows=Vec::new();
  for a in batch.accounts(){
   let key=op(&a.channel);
   let (pos,bal)=match state.entry(key){
    std::collections::btree_map::Entry::Occupied(e)=>e.into_mut(),
    std::collections::btree_map::Entry::Vacant(e)=>e.insert((Position::default(),balance_of(&key).ok_or(Reject::Allocation)?)),
   };
   let (np,s)=settle(pos,&key,batch.legs())?;
   let mut b=*bal;b.committed=b.committed.checked_sub(a.margin_sats).ok_or(Reject::Bounds)?;
   *bal=apply(b,&s,a.margin_sats)?;*pos=np;
   rows.push((a.channel.clone(),s));
  }
  per_batch.push((seq,rows));
 }
 for (pos,b) in state.values(){if !b.conserved()||b.committed<pos.margin(){return Err(Reject::Bounds)}}
 Ok((state,per_batch))
}
