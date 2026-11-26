//! Options desk: listed option series beside the perpetual book (docs/SHZ_OPTIONS_COMBOS.md).
//!
//! * Instruments: the perpetual (the existing books) and option series. A series is a
//!   kind (call/put), a settlement asset, a strike and the DLC oracle event it expires
//!   on; its id is a tagged hash of those fields. Each series has its own book.
//! * Orders are `IntentV7`, a new intent version signed by the account owner. A Post
//!   rests one leg at a premium per unit; a Take is one leg or an N-leg combo that fills
//!   all-or-none against resting quotes in one option batch, within one net premium limit.
//! * Units. `Asset::Btc` series are inverse options (`qty` = USD notional, premium in
//!   millisats per unit, collateral and payoff in sats). `Asset::Usd` series are linear
//!   options (`qty` = 1e-8 BTC, premium in thousandths of a micro-USD per unit, collateral
//!   and payoff in micro-USD).
//! * Margin is one rule: each account's option collateral per asset is exactly the
//!   portfolio's worst-case loss over the oracle's price domain (`payoff::max_loss`),
//!   recomputed on every fill. Legs offset only within one expiry (one oracle event, one
//!   price): the requirement is the sum over expiries of each expiry's worst case. Premium moves in cash at fill time and is not part of the
//!   margined payoff. Assets never net against each other. Every option portfolio is
//!   therefore `fully_funded` and needs no liquidation.
//! * Cash moves (premium at a fill, payoff at expiry) go through the multilateral
//!   clearing ledger: each option batch has a `BatchClearing` with one row per account,
//!   losers' cash collected into the pool and winners paid from it. Premium nets to zero
//!   exactly; expiry rounds each net winner down and each net loser up and the dust goes to the
//!   clearing fund, so the clearing identity holds.
//! * BTC collateral is moved from the account's perpetual allocation (`fund`/`defund`):
//!   `Balance::cap` and `free` drop by the amount, the options sub-account gains it.
use super::*;
use super::clearing::{BatchClearing,ClearingRow,ClearingState,Waterfall};
use shz_dlc::{OracleAnnouncement,OracleAttestation};
use shz_margin::payoff::{self,Asset,Leg,OptionKind,PriceDomain};
use shz_margin::CollateralAsset;

/// Intent version number of option orders (`IntentV6` is the perpetual intent).
pub const OPTION_INTENT_VERSION:u32=7;
/// Most legs one combo intent may carry.
pub const MAX_LEGS:usize=4;

/// One listed option series.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct Series{pub kind:OptionKind,pub asset:Asset,pub strike_usd:u64,pub event_id:String}
impl Series{
 pub fn id(&self)->Key{
  let mut b=Vec::new();
  b.push(match self.kind{OptionKind::Call=>1,OptionKind::Put=>2});
  b.push(match self.asset{Asset::Btc=>1,Asset::Usd=>2});
  u64b(&mut b,self.strike_usd);u64b(&mut b,self.event_id.len()as u64);b.extend(self.event_id.as_bytes());
  tagged_hash(b"SHZ/OPTIONS/SERIES/V1",&b)
 }
 /// The payoff leg of `net` units (positive long), premium excluded.
 fn leg(&self,net:i64)->Leg{
  let (long,qty)=(net>0,net.unsigned_abs());
  match self.asset{
   Asset::Btc=>Leg::InverseOption{kind:self.kind,long,qty_usd:qty,strike_usd:self.strike_usd,premium_sats:0},
   Asset::Usd=>Leg::LinearOption{kind:self.kind,long,qty_btc_e8:qty,strike_usd:self.strike_usd,premium_usd:0},
  }
 }
}

/// What a book trades: the perpetual or one option series.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub enum Instrument{Perp,Option(Series)}
impl Instrument{
 pub fn id(&self)->Key{match self{Self::Perp=>tagged_hash(b"SHZ/OPTIONS/INSTRUMENT/V1",b"perp"),Self::Option(s)=>s.id()}}
}

/// One leg of an option order: `qty` units of `series`, bought (`long`) or sold.
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct LegOrder{pub series:Key,pub long:bool,pub qty:u64}

/// Signed option order (intent version 7). Post: one leg, `premium_milli` is the
/// premium per unit in thousandths of the asset unit (positive). Take: one or more legs
/// in one asset, `premium_milli` is the most the taker pays net for the whole order in
/// thousandths of the asset unit (negative: the least it must receive). Cancel:
/// `cancel_target` is the id of the account's resting quote.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct IntentV7{
 pub version:u32,pub scope:Scope,pub router:u32,pub channel:BtcOutPoint,pub owner:Key,pub sequence:u64,pub expires_us:u64,
 pub action:Action,pub legs:Vec<LegOrder>,pub premium_milli:i64,pub cancel_target:Key,pub signature:Bip340Signature,
}
impl IntentV7{
 pub fn id(&self)->Key{
  let mut b=Vec::new();u32b(&mut b,self.version);self.scope.put(&mut b);u32b(&mut b,self.router);put_op(&mut b,&self.channel);
  b.extend(self.owner);u64b(&mut b,self.sequence);u64b(&mut b,self.expires_us);
  b.push(match self.action{Action::Post=>1,Action::Take=>2,Action::Cancel=>3});
  u64b(&mut b,self.legs.len()as u64);
  for l in &self.legs{b.extend(l.series);b.push(l.long as u8);u64b(&mut b,l.qty);}
  b.extend(self.premium_milli.to_le_bytes());b.extend(self.cancel_target);
  tagged_hash(b"SHZ/HFT06/INTENT/V7",&b)
 }
 pub fn signed(mut self,sk:&Key)->R<Self>{self.owner=public(sk);self.signature=sign(sk,&self.id())?;Ok(self)}
}

/// Options sub-account of one channel. `*_locked` is always the portfolio's worst-case
/// loss in that asset; `realized_*` is premium and payoff received minus paid.
#[derive(Debug,Clone,Default,PartialEq,Eq,Serialize,Deserialize)]
pub struct OptionAccount{
 pub btc_free:u64,pub btc_locked:u64,pub realized_btc:i64,
 pub usd_free:u64,pub usd_locked:u64,pub realized_usd:i64,
 /// Rail the account's USD collateral sits on (set by its first deposit).
 pub usd_rail:Option<CollateralAsset>,
 /// Net units per series, positive long.
 pub legs:BTreeMap<Key,i64>,
 pub last_sequence:u64,
}
impl OptionAccount{
 fn free(&self,a:Asset)->u64{match a{Asset::Btc=>self.btc_free,Asset::Usd=>self.usd_free}}
 fn locked(&self,a:Asset)->u64{match a{Asset::Btc=>self.btc_locked,Asset::Usd=>self.usd_locked}}
 fn set(&mut self,a:Asset,free:u64,locked:u64,realized:i64){
  match a{Asset::Btc=>{self.btc_free=free;self.btc_locked=locked;self.realized_btc=realized},
   Asset::Usd=>{self.usd_free=free;self.usd_locked=locked;self.realized_usd=realized}}
 }
 fn realized(&self,a:Asset)->i64{match a{Asset::Btc=>self.realized_btc,Asset::Usd=>self.realized_usd}}
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
struct Quote{intent:IntentV7,remaining:u64}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
struct Listed{series:Series,announcement:OracleAnnouncement,settled:Option<u64>}

/// One option fill: `qty` units of `series` between the long and the short account at
/// `premium_milli` per unit; `premium` (asset units) moves from long to short.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct OptionFill{pub series:Key,pub long:BtcOutPoint,pub short:BtcOutPoint,pub maker:Key,pub taker:Key,pub qty:u64,pub premium_milli:u64,pub premium:u64}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub enum OptionBatchKind{
 /// One taker intent (single leg or combo), all of its fills.
 Trade{taker:Key},
 /// Expiry of every `series` of one asset on oracle event `event_id` at the attested
 /// `price_usd` (clamped to the domain).
 Expiry{event_id:String,series:Vec<Key>,price_usd:u64},
}
/// Atomic unit of option settlement: every fill and cash move of one take or expiry.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct OptionBatch{pub sequence:u64,pub kind:OptionBatchKind,pub asset:Asset,pub fills:Vec<OptionFill>,pub clearing:BatchClearing}

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum OptionOutcome{Posted(Key),Cancelled(Key),Filled(Box<OptionBatch>)}

/// Every option book, sub-account and batch. Pure state: callers pass the router's
/// account owners and the clearing ledger.
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct OptionsDesk{
 pub oracle:Key,pub domain:PriceDomain,
 /// `Asset::Usd` series and USD collateral accepted (journaled `EnableUsdCollateral`).
 pub usd:bool,
 /// Combos (more than one leg per Take) accepted (journaled `EnableCombos`).
 pub combos:bool,
 series:BTreeMap<Key,Listed>,
 books:BTreeMap<(Key,bool),BTreeMap<(i64,u64),Quote>>,
 locations:BTreeMap<Key,(Key,bool,(i64,u64))>,
 accounts:BTreeMap<Outpoint,OptionAccount>,
 batches:Vec<OptionBatch>,
 arrival:u64,clock:u64,
}

/// Premium of `qty` units at `milli` per unit, in asset units (floor, same for both sides).
fn premium(qty:u64,milli:u64)->R<u64>{u64::try_from(qty as u128*milli as u128/1000).map_err(|_|Reject::Bounds)}
fn s64(x:u64)->R<i64>{i64::try_from(x).map_err(|_|Reject::Bounds)}

impl OptionsDesk{
 pub fn new(oracle:Key,num_bits:u8)->R<Self>{
  if !(4..=40).contains(&num_bits)||oracle==[0;32]{return Err(Reject::Bounds)}
  Ok(Self{oracle,domain:PriceDomain::from_bits(num_bits),usd:false,combos:false,series:BTreeMap::new(),books:BTreeMap::new(),
   locations:BTreeMap::new(),accounts:BTreeMap::new(),batches:Vec::new(),arrival:0,clock:0})
 }
 pub fn account(&self,k:&Outpoint)->Option<&OptionAccount>{self.accounts.get(k)}
 pub fn batch(&self,sequence:u64)->Option<&OptionBatch>{sequence.checked_sub(1).and_then(|i|self.batches.get(i as usize))}
 pub fn batch_count(&self)->u64{self.batches.len()as u64}
 pub fn series(&self,id:&Key)->Option<(&Series,Option<u64>)>{self.series.get(id).map(|l|(&l.series,l.settled))}
 pub fn series_ids(&self)->impl Iterator<Item=&Key>{self.series.keys()}
 /// Resting quotes of one side of a series book in priority order: (id, premium_milli, remaining).
 pub fn depth(&self,series:&Key,long:bool)->Vec<(Key,i64,u64)>{
  self.books.get(&(*series,long)).map(|b|b.values().map(|q|(q.intent.id(),q.intent.premium_milli,q.remaining)).collect()).unwrap_or_default()
 }
 /// Payoff legs of an account's open option positions.
 pub fn legs(&self,k:&Outpoint)->Vec<Leg>{
  self.accounts.get(k).map(|a|a.legs.iter().filter(|(_,n)|**n!=0).filter_map(|(s,n)|self.series.get(s).map(|l|l.series.leg(*n))).collect()).unwrap_or_default()
 }
 /// The account's legs grouped by expiry (oracle event): legs offset only within a group,
 /// since different events settle at different prices.
 pub fn legs_by_event(&self,k:&Outpoint)->BTreeMap<String,Vec<Leg>>{
  let mut out:BTreeMap<String,Vec<Leg>>=BTreeMap::new();
  if let Some(a)=self.accounts.get(k){
   for (s,&n) in &a.legs{
    if let (true,Some(l))=(n!=0,self.series.get(s)){out.entry(l.series.event_id.clone()).or_default().push(l.series.leg(n));}
   }
  }
  out
 }
 /// Collateral the account's option portfolio needs in `asset`: the sum over expiries of
 /// each expiry's worst-case loss.
 pub fn required(&self,k:&Outpoint,asset:Asset)->u128{
  self.legs_by_event(k).values().map(|g|payoff::max_loss(g,asset,self.domain)).sum()
 }
 /// The account's posted option collateral covers every expiry's worst-case loss in every
 /// asset (`payoff::fully_funded` per expiry, collateral split across expiries).
 pub fn fully_funded(&self,k:&Outpoint)->bool{
  let Some(a)=self.accounts.get(k)else{return true};
  a.btc_locked as u128>=self.required(k,Asset::Btc)&&a.usd_locked as u128>=self.required(k,Asset::Usd)
 }

 /// List a series on an oracle announcement of the desk's oracle and domain.
 pub fn list(&mut self,series:Series,announcement:OracleAnnouncement)->R<Key>{
  let id=series.id();
  if self.series.contains_key(&id)||announcement.oracle_pubkey_x!=self.oracle||announcement.event_id!=series.event_id||
     PriceDomain::from_bits(announcement.num_bits().clamp(1,40))!=self.domain||announcement.num_bits()==0||
     !(self.domain.p_min..=self.domain.p_max).contains(&series.strike_usd){return Err(Reject::Bounds)}
  if series.asset==Asset::Usd&&!self.usd{return Err(Reject::Scope)}
  // Every series of one event settles on one announcement.
  if self.series.values().any(|l|l.series.event_id==series.event_id&&l.announcement!=announcement){return Err(Reject::Bounds)}
  self.series.insert(id,Listed{series,announcement,settled:None});Ok(id)
 }
 /// Move `sats` between the account's perpetual allocation and its options sub-account.
 pub(crate) fn fund(&mut self,k:Outpoint,b:&mut Balance,sats:u64,to_options:bool)->R<()>{
  let a=self.accounts.entry(k).or_default();
  if to_options{
   if b.free<sats{return Err(Reject::Capacity)}
   b.free-=sats;b.cap-=sats;a.btc_free=a.btc_free.checked_add(sats).ok_or(Reject::Bounds)?;
  }else{
   if a.btc_free<sats{return Err(Reject::Capacity)}
   a.btc_free-=sats;b.free=b.free.checked_add(sats).ok_or(Reject::Bounds)?;b.cap=b.cap.checked_add(sats).ok_or(Reject::Bounds)?;
  }
  Ok(())
 }
 /// Credit `micro_usd` of USD collateral on `rail` (TAP or RGB; the on-chain transfer is
 /// simulated) or, with `deposit` false, withdraw it from the free USD balance.
 pub fn usd_transfer(&mut self,k:Outpoint,rail:Option<CollateralAsset>,micro_usd:u64,deposit:bool)->R<()>{
  if !self.usd{return Err(Reject::Scope)}
  let a=self.accounts.entry(k).or_default();
  if deposit{
   let rail=rail.ok_or(Reject::Bounds)?;
   if matches!(rail,CollateralAsset::VanillaBtc){return Err(Reject::Bounds)}
   if a.usd_rail.as_ref().is_some_and(|r|*r!=rail){return Err(Reject::Scope)}
   a.usd_free=a.usd_free.checked_add(micro_usd).ok_or(Reject::Bounds)?;a.usd_rail=Some(rail);
  }else{
   if a.usd_free<micro_usd{return Err(Reject::Capacity)}
   a.usd_free-=micro_usd;
  }
  Ok(())
 }

 /// Admit and execute one signed option intent. `owner_of` is the router's account owner.
 pub fn submit(&mut self,scope:Scope,router:u32,owner_of:&dyn Fn(&Outpoint)->Option<Key>,clearing:&mut ClearingState,i:IntentV7,now:u64)->R<OptionOutcome>{
  if now<self.clock{return Err(Reject::Clock)}
  self.clock=now;
  let k=op(&i.channel);
  if i.version!=OPTION_INTENT_VERSION||i.scope!=scope||i.router!=router{return Err(Reject::Scope)}
  if owner_of(&k)!=Some(i.owner){return Err(Reject::Allocation)}
  verify(&i.owner,&i.id(),&i.signature)?;
  if i.expires_us<=now{return Err(Reject::Expired)}
  if i.sequence<=self.accounts.get(&k).map_or(0,|a|a.last_sequence){return Err(Reject::Replay)}
  let out=match i.action{
   Action::Cancel=>{
    let (s,long,key)=*self.locations.get(&i.cancel_target).ok_or(Reject::UnknownOrder)?;
    if op(&self.books[&(s,long)][&key].intent.channel)!=k{return Err(Reject::UnknownOrder)}
    self.books.get_mut(&(s,long)).unwrap().remove(&key);self.locations.remove(&i.cancel_target);
    OptionOutcome::Cancelled(i.cancel_target)
   },
   Action::Post=>self.post(&i)?,
   Action::Take=>self.take(&i,clearing)?,
  };
  self.accounts.entry(k).or_default().last_sequence=i.sequence;
  Ok(out)
 }
 fn open_series(&self,id:&Key)->R<&Listed>{
  let l=self.series.get(id).ok_or(Reject::UnknownOrder)?;
  if l.settled.is_some(){return Err(Reject::Expired)}
  Ok(l)
 }
 fn post(&mut self,i:&IntentV7)->R<OptionOutcome>{
  let [leg]=i.legs.as_slice()else{return Err(Reject::Bounds)};
  self.open_series(&leg.series)?;
  if leg.qty==0||i.premium_milli<=0{return Err(Reject::Bounds)}
  // Post-only: a quote that would cross the best opposite quote is refused.
  if let Some(best)=self.books.get(&(leg.series,!leg.long)).and_then(|b|b.values().next()){
   let p=best.intent.premium_milli;
   if (leg.long&&i.premium_milli>=p)||(!leg.long&&i.premium_milli<=p){return Err(Reject::Bounds)}
  }
  self.arrival+=1;
  let key=(if leg.long{-i.premium_milli}else{i.premium_milli},self.arrival);
  let id=i.id();
  if self.locations.contains_key(&id){return Err(Reject::Replay)}
  self.books.entry((leg.series,leg.long)).or_default().insert(key,Quote{intent:i.clone(),remaining:leg.qty});
  self.locations.insert(id,(leg.series,leg.long,key));
  Ok(OptionOutcome::Posted(id))
 }
 /// All-or-none take. Makers that cannot fund their side are dropped from the books and
 /// matching restarts without them; the taker failing to fund rejects the whole intent.
 fn take(&mut self,i:&IntentV7,clearing:&mut ClearingState)->R<OptionOutcome>{
  if i.legs.is_empty()||i.legs.len()>MAX_LEGS||(i.legs.len()>1&&!self.combos){return Err(Reject::Bounds)}
  let mut seen=BTreeSet::new();let mut asset=None;
  for l in &i.legs{
   let s=&self.open_series(&l.series)?.series;
   if l.qty==0||!seen.insert(l.series)||asset.is_some_and(|a|a!=s.asset){return Err(Reject::Bounds)}
   asset=Some(s.asset);
  }
  let asset=asset.unwrap();
  let mut base=self.clone();
  loop{
   let mut work=base.clone();
   match work.try_take(i,asset,clearing)?{
    Ok((batch,next))=>{
     work.batches.push(batch.clone());*self=work;*clearing=next;
     return Ok(OptionOutcome::Filled(Box::new(batch)));
    },
    Err(bad)=>{
     // Drop every quote of the unfunded maker and match again.
     let ids:Vec<Key>=base.locations.iter().filter(|(_,(s,l,key))|op(&base.books[&(*s,*l)][key].intent.channel)==bad).map(|(id,_)|*id).collect();
     if ids.is_empty(){return Err(Reject::Capacity)}
     for id in ids{let (s,l,key)=base.locations.remove(&id).unwrap();base.books.get_mut(&(s,l)).unwrap().remove(&key);}
    }
   }
  }
 }
 /// One matching attempt on `self` (a working copy). `Ok(Err(maker))` names a maker
 /// that cannot fund its side.
 #[allow(clippy::type_complexity)]
 fn try_take(&mut self,i:&IntentV7,asset:Asset,clearing:&ClearingState)->R<Result<(OptionBatch,ClearingState),Outpoint>>{
  let taker=op(&i.channel);
  let mut fills=Vec::new();
  for l in &i.legs{
   let mut need=l.qty;
   let book=self.books.entry((l.series,!l.long)).or_default();
   let mut done=Vec::new();
   for (key,q) in book.iter_mut(){
    if need==0{break}
    if op(&q.intent.channel)==taker{continue}
    let n=need.min(q.remaining);
    let milli=u64::try_from(q.intent.premium_milli).map_err(|_|Reject::Bounds)?;
    let (long,short)=if l.long{(i.channel.clone(),q.intent.channel.clone())}else{(q.intent.channel.clone(),i.channel.clone())};
    fills.push(OptionFill{series:l.series,long,short,maker:q.intent.id(),taker:i.id(),qty:n,premium_milli:milli,premium:premium(n,milli)?});
    q.remaining-=n;need-=n;
    if q.remaining==0{done.push((*key,q.intent.id()))}
   }
   if need>0{return Err(Reject::NoLiquidity)}
   for (key,id) in done{book.remove(&key);self.locations.remove(&id);}
  }
  // Taker's net premium against its limit (thousandths of the asset unit).
  let mut net:i128=0;
  for f in &fills{let p=f.premium as i128*1000;if op(&f.long)==taker{net+=p}else{net-=p}}
  if net>i.premium_milli as i128{return Err(Reject::FeeLimit)}
  // Cash per account, then legs and margin.
  let mut cash:BTreeMap<Outpoint,(BtcOutPoint,u64,u64)>=BTreeMap::new();
  for f in &fills{
   cash.entry(op(&f.long)).or_insert((f.long.clone(),0,0)).2+=f.premium;
   cash.entry(op(&f.short)).or_insert((f.short.clone(),0,0)).1+=f.premium;
   let units=s64(f.qty)?;
   *self.accounts.entry(op(&f.long)).or_default().legs.entry(f.series).or_insert(0)+=units;
   *self.accounts.entry(op(&f.short)).or_default().legs.entry(f.series).or_insert(0)-=units;
  }
  let mut rows=Vec::new();
  for (k,(ch,received,paid)) in &cash{
   let a=self.accounts.get_mut(k).unwrap();a.legs.retain(|_,n|*n!=0);
   let req=u64::try_from(self.required(k,asset)).map_err(|_|Reject::Bounds)?;
   let a=&self.accounts[k];
   let avail=a.free(asset) as i128+a.locked(asset) as i128+*received as i128-*paid as i128-req as i128;
   if avail<0{return if *k==taker{Err(Reject::Capacity)}else{Ok(Err(*k))}}
   let realized=a.realized(asset).checked_add(s64(*received)?-s64(*paid)?).ok_or(Reject::Bounds)?;
   self.accounts.get_mut(k).unwrap().set(asset,avail as u64,req,realized);
   rows.push(row(clearing,ch,s64(*received)?-s64(*paid)?,*paid,*received));
  }
  let seq=self.batches.len()as u64+1;
  let (report,next)=settle(clearing,asset,rows,0)?;
  Ok(Ok((OptionBatch{sequence:seq,kind:OptionBatchKind::Trade{taker:i.id()},asset,fills,clearing:report},next)))
 }

 /// Expire, at the oracle's attested price, every open series in the asset of `id` on the
 /// same oracle event as `id`: each account's positions in them pay out as one amount,
 /// shorts from their locked collateral, and the collateral they no longer need is freed.
 pub fn expire(&mut self,id:&Key,attestation:&OracleAttestation,clearing:&mut ClearingState)->R<OptionBatch>{
  let l=self.open_series(id)?;
  attestation.verify_against(&l.announcement).map_err(|_|Reject::Oracle)?;
  let (event,asset,price)=(l.series.event_id.clone(),l.series.asset,attestation.price_usd.clamp(self.domain.p_min,self.domain.p_max));
  let ids:Vec<Key>=self.series.iter().filter(|(_,l)|l.settled.is_none()&&l.series.event_id==event&&l.series.asset==asset).map(|(k,_)|*k).collect();
  // Resting quotes of expired series are cancelled.
  for s in &ids{
   for long in [true,false]{
    if let Some(b)=self.books.remove(&(*s,long)){for q in b.values(){self.locations.remove(&q.intent.id());}}
   }
  }
  let mut rows=Vec::new();let (mut gains,mut losses)=(0u64,0u64);
  let holders:Vec<Outpoint>=self.accounts.iter().filter(|(_,a)|ids.iter().any(|s|a.legs.get(s).is_some_and(|&n|n!=0))).map(|(k,_)|*k).collect();
  let mut moves=Vec::new();
  for k in holders{
   let a=&self.accounts[&k];
   let legs:Vec<Leg>=ids.iter().filter_map(|s|a.legs.get(s).filter(|&&n|n!=0).map(|&n|self.series[s].series.leg(n))).collect();
   let v=payoff::pnl(&legs,asset,price);
   // `pnl` floors: a net winner is paid the floor, a net loser pays the ceiling.
   let (paid,collected)=if v>=0{(u64::try_from(v).map_err(|_|Reject::Bounds)?,0)}else{(0,u64::try_from(-v).map_err(|_|Reject::Bounds)?)};
   gains=gains.checked_add(paid).ok_or(Reject::Bounds)?;losses=losses.checked_add(collected).ok_or(Reject::Bounds)?;
   moves.push((k,paid,collected));
  }
  if gains>losses{return Err(Reject::Bounds)}
  for (k,paid,collected) in moves{
   let a=self.accounts.get_mut(&k).unwrap();for s in &ids{a.legs.remove(s);}
   let req=u64::try_from(self.required(&k,asset)).map_err(|_|Reject::Bounds)?;
   let a=&self.accounts[&k];
   let total=a.free(asset) as i128+a.locked(asset) as i128+paid as i128-collected as i128-req as i128;
   // Locked collateral covers each expiry's worst case on its own, so this cannot go negative.
   if total<0{return Err(Reject::Bounds)}
   let realized=a.realized(asset).checked_add(s64(paid)?-s64(collected)?).ok_or(Reject::Bounds)?;
   self.accounts.get_mut(&k).unwrap().set(asset,total as u64,req,realized);
   let ch=BtcOutPoint{txid:k.0,vout:k.1};
   rows.push(row(clearing,&ch,s64(paid)?-s64(collected)?,collected,paid));
  }
  let seq=self.batches.len()as u64+1;
  let (report,next)=settle(clearing,asset,rows,losses-gains)?;
  let batch=OptionBatch{sequence:seq,kind:OptionBatchKind::Expiry{event_id:event,series:ids.clone(),price_usd:price},asset,fills:Vec::new(),clearing:report};
  for s in &ids{self.series.get_mut(s).unwrap().settled=Some(price);}
  self.batches.push(batch.clone());*clearing=next;
  Ok(batch)
 }
}

fn row(c:&ClearingState,ch:&BtcOutPoint,pnl:i64,collected:u64,paid:u64)->ClearingRow{
 let claim=c.claim(ch);
 ClearingRow{channel:ch.clone(),pnl,released:0,collected,own_claim_used:0,shortfall:0,haircut:0,claim_before:claim,claim_after:claim,paid,net:paid as i64-collected as i64}
}
/// Clearing report of one option batch. BTC batches move the pool's cash (collected in,
/// paid out, `dust` kept as clearing fund); USD batches have their own pool line that
/// always nets to zero apart from dust, which stays with the venue.
fn settle(c:&ClearingState,asset:Asset,rows:Vec<ClearingRow>,dust:u64)->R<(BatchClearing,ClearingState)>{
 let collected:i128=rows.iter().map(|r|r.collected as i128).sum();
 let paid:i128=rows.iter().map(|r|r.paid as i128).sum();
 if collected-paid!=dust as i128{return Err(Reject::Bounds)}
 let mut next=c.clone();
 let (before,after)=match asset{
  Asset::Btc=>{
   next.cash=next.cash.checked_add(s64(dust)?).ok_or(Reject::Bounds)?;next.fund=next.fund.checked_add(dust).ok_or(Reject::Bounds)?;
   (c.cash,next.cash)
  },
  Asset::Usd=>(0,s64(dust)?),
 };
 let layer=if collected>0{Waterfall::Margin}else{Waterfall::None};
 Ok((BatchClearing{rows,claim_haircuts:Vec::new(),shortfall:0,fund_absorbed:0,haircut:0,layer,cash_before:before,cash_after:after,
  fund_after:next.fund,carry_after:next.carry,claims_after:next.claims_total()},next))
}
