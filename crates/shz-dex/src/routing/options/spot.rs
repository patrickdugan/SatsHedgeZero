//! Spot BTC/stablecoin market on the options desk (docs/SHZ_SPOT.md).
//!
//! * A pair is BTC against one registered stablecoin (`SpotPair{quote, lot_sats, tick}`),
//!   listed once (journaled `ListSpotPair`) after `EnableSpot`. Its id is a tagged hash of
//!   the base, the quote asset, the lot and the tick.
//! * Fully funded: no margin, no leverage, no liquidation. A resting sell locks its BTC, a
//!   resting buy locks its stablecoin, both out of the account's one asset wallet (the
//!   options sub-account balances, `AssetBalance::free`). Locked spot funds are not in
//!   `free`, so option margin, defund and withdraw can never reach them.
//! * Units: size in sats, a multiple of `lot_sats`; price in stablecoin base units per BTC,
//!   a multiple of `tick`. `lot_sats * tick` is a multiple of 10^8, so the stablecoin amount
//!   of every fill (`sats * price / 10^8`) is an exact integer: no rounding, no dust.
//! * Orders are `SpotIntent` (intent version 8, digest tag `SPOT_INTENT_TAG`), signed by the
//!   account owner. Post rests (post-only, refused if it would cross); Take fills
//!   immediately at the makers' prices up to its limit and size, the rest is dropped (IOC);
//!   Cancel pulls a resting order and unlocks what it still holds.
//! * A take is one `OptionBatch` of kind `Spot`: BTC moves seller to buyer and the
//!   stablecoin buyer to seller, with one clearing row per account per asset (net of all
//!   its fills) and each asset's net summing to zero. `EnableSpot` requires the option
//!   acknowledgement round, so every spot batch is staged and commits only when owner, peer
//!   and monitor of every lane sign its V4 message: both legs settle or neither does.
use super::*;

/// Intent version number of spot orders (`IntentV7` is the option intent).
pub const SPOT_INTENT_VERSION:u32=8;
/// Domain tag of `SpotIntent::id`.
pub const SPOT_INTENT_TAG:&[u8]=b"SHZ/HFT06/SPOT-INTENT/V8";
const SATS_PER_BTC:u128=100_000_000;

/// A spot pair: BTC (base, sats) against `quote` (a registered stablecoin).
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct SpotPair{pub quote:SettleAsset,pub lot_sats:u64,pub tick:u64}
impl SpotPair{
 pub fn id(&self)->Key{
  let mut b=Vec::new();SettleAsset::Btc.put(&mut b);self.quote.put(&mut b);u64b(&mut b,self.lot_sats);u64b(&mut b,self.tick);
  tagged_hash(b"SHZ/SPOT/PAIR/V1",&b)
 }
 /// Stablecoin base units of `sats` at `price` (base units per BTC); exact or refused.
 pub fn quote_amount(&self,sats:u64,price:u64)->R<u64>{
  let v=sats as u128*price as u128;
  if !v.is_multiple_of(SATS_PER_BTC){return Err(Reject::Bounds)}
  u(v/SATS_PER_BTC)
 }
 fn valid(&self)->bool{
  self.lot_sats>0&&self.tick>0&&(self.lot_sats as u128*self.tick as u128).is_multiple_of(SATS_PER_BTC)&&matches!(self.quote,SettleAsset::Stable{..})
 }
 fn check(&self,sats:u64,price:u64)->R<()>{
  if sats==0||!sats.is_multiple_of(self.lot_sats)||price==0||!price.is_multiple_of(self.tick){return Err(Reject::Bounds)}
  self.quote_amount(sats,price).map(|_|())
 }
}

/// Signed spot order (intent version 8). `buy`: the account buys BTC with the quote asset.
/// Post and Take: `qty_sats` and the limit `price` (quote base units per BTC). Cancel:
/// `cancel_target` is the id of the account's resting order (`qty_sats`, `price` zero).
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct SpotIntent{
 pub version:u32,pub scope:Scope,pub router:u32,pub channel:BtcOutPoint,pub owner:Key,pub sequence:u64,pub expires_us:u64,
 pub action:Action,pub pair:Key,pub buy:bool,pub qty_sats:u64,pub price:u64,pub cancel_target:Key,pub signature:Bip340Signature,
}
impl SpotIntent{
 pub fn id(&self)->Key{
  let mut b=Vec::new();u32b(&mut b,self.version);self.scope.put(&mut b);u32b(&mut b,self.router);put_op(&mut b,&self.channel);
  b.extend(self.owner);u64b(&mut b,self.sequence);u64b(&mut b,self.expires_us);
  b.push(match self.action{Action::Post=>1,Action::Take=>2,Action::Cancel=>3});
  b.extend(self.pair);b.push(self.buy as u8);u64b(&mut b,self.qty_sats);u64b(&mut b,self.price);b.extend(self.cancel_target);
  tagged_hash(SPOT_INTENT_TAG,&b)
 }
 pub fn signed(mut self,sk:&Key)->R<Self>{self.owner=public(sk);self.signature=sign(sk,&self.id())?;Ok(self)}
}

/// One spot fill: `sats` of BTC from `seller` to `buyer` at the maker's `price`, and
/// `quote_units` of the pair's quote asset from `buyer` to `seller`.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct SpotFill{pub pair:Key,pub seller:BtcOutPoint,pub buyer:BtcOutPoint,pub maker:Key,pub taker:Key,pub taker_buys:bool,pub sats:u64,pub price:u64,pub quote_units:u64}
impl SpotFill{
 pub(super) fn put(&self,b:&mut Vec<u8>){
  b.extend(self.pair);put_op(b,&self.seller);put_op(b,&self.buyer);b.extend(self.maker);b.extend(self.taker);b.push(self.taker_buys as u8);
  for n in [self.sats,self.price,self.quote_units]{u64b(b,n)}
 }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
struct SpotQuote{intent:SpotIntent,remaining:u64,locked:u64}
type BookKey=(u64,u64);

/// Spot pairs, books and resting orders. Balances live in the options desk's accounts.
#[derive(Debug,Clone,Default,PartialEq,Eq)]
pub struct SpotDesk{
 pairs:BTreeMap<Key,SpotPair>,
 books:BTreeMap<(Key,bool),BTreeMap<BookKey,SpotQuote>>,
 locations:BTreeMap<Key,(Key,bool,BookKey)>,
 arrival:u64,
}
impl SpotDesk{
 pub fn pairs(&self)->impl Iterator<Item=(&Key,&SpotPair)>{self.pairs.iter()}
 pub fn pair(&self,id:&Key)->Option<&SpotPair>{self.pairs.get(id)}
 /// Resting orders of one side in priority order: (id, price, remaining sats, owner channel).
 pub fn depth(&self,pair:&Key,buy:bool)->Vec<(Key,u64,u64,BtcOutPoint)>{
  self.books.get(&(*pair,buy)).map(|b|b.values().map(|q|(q.intent.id(),q.intent.price,q.remaining,q.intent.channel.clone())).collect()).unwrap_or_default()
 }
 /// Units of `asset` locked by the account's resting spot orders.
 pub fn locked(&self,k:&Outpoint,asset:&SettleAsset)->u64{
  let mut t=0u64;
  for ((p,buy),b) in &self.books{
   let Some(pair)=self.pairs.get(p) else{continue};
   let a=if *buy{pair.quote}else{SettleAsset::Btc};
   if a!=*asset{continue}
   for q in b.values(){if op(&q.intent.channel)==*k{t=t.saturating_add(q.locked)}}
  }
  t
 }
 fn key(buy:bool,price:u64,arrival:u64)->BookKey{(if buy{u64::MAX-price}else{price},arrival)}
}

impl OptionsDesk{
 /// The spot market, once `EnableSpot` is journaled.
 pub fn spot(&self)->Option<&SpotDesk>{self.spot.as_ref()}
 pub(crate) fn enable_spot(&mut self)->R<()>{
  if self.spot.is_some(){return Err(Reject::Replay)}
  self.spot=Some(SpotDesk::default());Ok(())
 }
 /// List a pair against a registered stablecoin (lot and tick make every fill exact).
 pub(crate) fn list_spot(&mut self,pair:SpotPair)->R<Key>{
  if !pair.valid(){return Err(Reject::Bounds)}
  if !self.pools.contains_key(&pair.quote){return Err(Reject::Scope)}
  let s=self.spot.as_mut().ok_or(Reject::Scope)?;
  let id=pair.id();
  if s.pairs.contains_key(&id){return Err(Reject::Replay)}
  s.pairs.insert(id,pair);Ok(id)
 }
 fn wallet(&mut self,k:Outpoint,a:SettleAsset)->&mut AssetBalance{self.accounts.entry(k).or_default().balances.entry(a).or_default()}
 /// Pull a resting spot order and return what it still locks to free. False if unknown.
 pub(crate) fn spot_pull(&mut self,id:&Key)->bool{
  let Some(s)=self.spot.as_mut() else{return false};
  let Some((p,buy,key))=s.locations.remove(id) else{return false};
  let Some(q)=s.books.get_mut(&(p,buy)).and_then(|b|b.remove(&key)) else{return false};
  let asset=if buy{s.pairs[&p].quote}else{SettleAsset::Btc};
  let w=self.wallet(op(&q.intent.channel),asset);w.free=w.free.saturating_add(q.locked);
  true
 }

 /// Admit and execute one signed spot intent. Post and Cancel apply here; a Take returns
 /// `Filled` with the batch (already applied to this desk: callers stage a clone).
 pub fn submit_spot(&mut self,scope:Scope,router:u32,owner_of:&dyn Fn(&Outpoint)->Option<Key>,clearing:&ClearingState,i:SpotIntent,now:u64)->R<OptionOutcome>{
  if now<self.clock{return Err(Reject::Clock)}
  self.clock=now;
  let k=op(&i.channel);
  if i.version!=SPOT_INTENT_VERSION||i.scope!=scope||i.router!=router{return Err(Reject::Scope)}
  if owner_of(&k)!=Some(i.owner){return Err(Reject::Allocation)}
  verify(&i.owner,&i.id(),&i.signature)?;
  if i.expires_us<=now{return Err(Reject::Expired)}
  if i.sequence<=self.accounts.get(&k).map_or(0,|a|a.last_sequence){return Err(Reject::Replay)}
  let out=match i.action{
   Action::Cancel=>{
    let s=self.spot.as_ref().ok_or(Reject::Scope)?;
    let (p,buy,key)=*s.locations.get(&i.cancel_target).ok_or(Reject::UnknownOrder)?;
    if op(&s.books[&(p,buy)][&key].intent.channel)!=k{return Err(Reject::UnknownOrder)}
    self.spot_pull(&i.cancel_target);
    OptionOutcome::Cancelled(i.cancel_target)
   },
   Action::Post=>self.spot_post(&i)?,
   Action::Take=>self.spot_take(&i,clearing)?,
  };
  self.accounts.entry(k).or_default().last_sequence=i.sequence;
  Ok(out)
 }
 fn spot_post(&mut self,i:&SpotIntent)->R<OptionOutcome>{
  let s=self.spot.as_ref().ok_or(Reject::Scope)?;
  let pair=*s.pairs.get(&i.pair).ok_or(Reject::UnknownOrder)?;
  pair.check(i.qty_sats,i.price)?;
  // Post-only: an order that would cross the best opposite order is refused.
  if let Some(best)=s.books.get(&(i.pair,!i.buy)).and_then(|b|b.values().next()){
   let p=best.intent.price;
   if (i.buy&&i.price>=p)||(!i.buy&&i.price<=p){return Err(Reject::Bounds)}
  }
  let id=i.id();
  if s.locations.contains_key(&id){return Err(Reject::Replay)}
  let (asset,lock)=if i.buy{(pair.quote,pair.quote_amount(i.qty_sats,i.price)?)}else{(SettleAsset::Btc,i.qty_sats)};
  let w=self.wallet(op(&i.channel),asset);
  if w.free<lock{return Err(Reject::Capacity)}
  w.free-=lock;
  let s=self.spot.as_mut().unwrap();
  s.arrival+=1;
  let key=SpotDesk::key(i.buy,i.price,s.arrival);
  s.books.entry((i.pair,i.buy)).or_default().insert(key,SpotQuote{intent:i.clone(),remaining:i.qty_sats,locked:lock});
  s.locations.insert(id,(i.pair,i.buy,key));
  Ok(OptionOutcome::Posted(id))
 }
 /// Immediate-or-cancel take at the makers' prices. Makers' sides come out of their locks;
 /// the taker pays from free and must cover every fill or the intent is refused.
 fn spot_take(&mut self,i:&SpotIntent,clearing:&ClearingState)->R<OptionOutcome>{
  let s=self.spot.as_ref().ok_or(Reject::Scope)?;
  let pair=*s.pairs.get(&i.pair).ok_or(Reject::UnknownOrder)?;
  pair.check(i.qty_sats,i.price)?;
  let taker=op(&i.channel);let tid=i.id();
  let mut work=self.clone();
  let s=work.spot.as_mut().unwrap();
  let book=s.books.entry((i.pair,!i.buy)).or_default();
  let (mut need,mut fills,mut done)=(i.qty_sats,Vec::new(),Vec::new());
  for (key,q) in book.iter_mut(){
   if need==0{break}
   let p=q.intent.price;
   if (i.buy&&p>i.price)||(!i.buy&&p<i.price){break}
   // Self-trade prevention: the taker's own resting orders are skipped.
   if op(&q.intent.channel)==taker{continue}
   let n=need.min(q.remaining);
   let units=pair.quote_amount(n,p)?;
   let (seller,buyer)=if i.buy{(q.intent.channel.clone(),i.channel.clone())}else{(i.channel.clone(),q.intent.channel.clone())};
   q.locked=q.locked.checked_sub(if i.buy{n}else{units}).ok_or(Reject::Bounds)?;
   q.remaining-=n;need-=n;
   fills.push(SpotFill{pair:i.pair,seller,buyer,maker:q.intent.id(),taker:tid,taker_buys:i.buy,sats:n,price:p,quote_units:units});
   if q.remaining==0{done.push((*key,q.intent.id(),q.locked,q.intent.channel.clone()))}
  }
  let s=work.spot.as_mut().unwrap();
  let book=s.books.get_mut(&(i.pair,!i.buy)).unwrap();
  if fills.is_empty(){return Err(Reject::NoLiquidity)}
  let mut refunds=Vec::new();
  for (key,id,left,ch) in done{
   book.remove(&key);s.locations.remove(&id);
   // Exact amounts leave nothing locked; any remainder returns to free all the same.
   if left>0{refunds.push((op(&ch),left))}
  }
  for (k,left) in refunds{let a=if i.buy{SettleAsset::Btc}else{pair.quote};let w=work.wallet(k,a);w.free=w.free.saturating_add(left);}
  // Per (asset, account): received and paid. Makers pay out of their locks (already off
  // free), the taker out of free.
  type Cash=BTreeMap<(SettleAsset,Outpoint),(BtcOutPoint,u64,u64)>;
  let add=|m:&mut Cash,a:SettleAsset,c:&BtcOutPoint,recv:u64,paid:u64|->R<()>{
   let e=m.entry((a,op(c))).or_insert((c.clone(),0,0));
   e.1=e.1.checked_add(recv).ok_or(Reject::Bounds)?;e.2=e.2.checked_add(paid).ok_or(Reject::Bounds)?;Ok(())
  };
  let mut cash=Cash::new();
  for f in &fills{
   add(&mut cash,SettleAsset::Btc,&f.buyer,f.sats,0)?;add(&mut cash,SettleAsset::Btc,&f.seller,0,f.sats)?;
   add(&mut cash,pair.quote,&f.seller,f.quote_units,0)?;add(&mut cash,pair.quote,&f.buyer,0,f.quote_units)?;
  }
  let mut rows:BTreeMap<SettleAsset,Vec<ClearingRow>>=BTreeMap::new();
  for ((asset,k),(ch,recv,paid)) in &cash{
   let w=work.wallet(*k,*asset);
   if *k==taker{
    w.free=w.free.checked_sub(*paid).ok_or(Reject::Capacity)?;
   }
   w.free=w.free.checked_add(*recv).ok_or(Reject::Bounds)?;
   let pool=if *asset==SettleAsset::Btc{clearing}else{&work.pools[asset]};
   rows.entry(*asset).or_default().push(row(pool,ch,s64(*recv)?-s64(*paid)?,*paid,*recv));
  }
  let seq=work.batches.len()as u64+1;
  let (reports,next)=work.settle_all(clearing,rows,&BTreeMap::new())?;
  // Spot moves no pool cash: the BTC ledger is unchanged.
  if next!=*clearing{return Err(Reject::Bounds)}
  let batch=OptionBatch{sequence:seq,kind:OptionBatchKind::Spot{taker:tid},fills:Vec::new(),spot:fills,clearing:reports};
  work.batches.push(batch.clone());
  *self=work;
  Ok(OptionOutcome::Filled(Box::new(batch)))
 }
}
