//! Options desk: listed option series beside the perpetual book (docs/SHZ_OPTIONS_COMBOS.md).
//!
//! * Assets. `SettleAsset::Btc` is the primary asset; `SettleAsset::Stable{protocol, id,
//!   decimals}` is a registered USD stablecoin (RGB or Taproot Assets), journaled once with
//!   `register_stable`. A second stablecoin is another registration, not code. Inverse
//!   perpetuals stay BTC-only; nothing here touches them.
//! * Instruments: the perpetual (the existing books) and option series. A series is a
//!   kind, a settlement asset, a strike and the DLC oracle event it expires on; its id is a
//!   tagged hash of those fields, and each series has its own book. Calls settle in BTC.
//!   Puts settle in BTC (margined to the bottom of the outcome domain) or in a registered
//!   stablecoin (cash-secured: the writer posts strike x size and its loss is capped).
//! * Orders are `IntentV7`, signed by the account owner. A Post rests one leg at a premium
//!   per unit; a Take is one leg or an N-leg combo that fills all-or-none in one option
//!   batch. Premium is paid in each leg's settlement asset, so a fill never converts one
//!   asset into another at a price; the taker states one net premium limit per asset.
//! * Units. BTC series are inverse options: `qty` USD notional, premium in millisats per
//!   unit, payoff and collateral in sats. Stable series are linear: `qty` in 1e-8 BTC,
//!   premium in thousandths of the stablecoin's base unit per unit, payoff and collateral
//!   in its base units (`10^decimals` per USD).
//! * Margin is one rule, per asset: collateral locked in an asset is exactly the sum over
//!   expiries of the worst-case loss (`payoff::max_loss`) of the legs settling in that asset
//!   on that expiry. Legs offset only within one expiry and one asset; assets never net.
//!   Every option portfolio is therefore `fully_funded` in every asset and needs no
//!   liquidation.
//! * Clearing is per asset inside one batch: each option batch carries one
//!   `BatchClearing` per asset it moves (BTC through the router's clearing ledger, each
//!   stablecoin through its own pool with fund, waterfall, deferred claims and identity).
//!   Premium nets to zero exactly; expiry rounds each net winner down and each net loser up
//!   and the dust goes to that asset's clearing fund, so every pool's identity holds.
//! * BTC collateral is moved from the account's perpetual allocation (`fund`/`defund`):
//!   `Balance::cap` and `free` drop by the amount, the options sub-account gains it.
//!   Stablecoin collateral is credited and debited by the simulated TAP/RGB adapter.
use super::*;
use super::clearing::{BatchClearing,ClearingRow,ClearingState,Waterfall};
use shz_dlc::{OracleAnnouncement,OracleAttestation};
use shz_margin::payoff::{self,Leg,OptionKind,PriceDomain};
use shz_margin::CollateralAsset;

/// Intent version number of option orders (`IntentV6` is the perpetual intent).
pub const OPTION_INTENT_VERSION:u32=7;
/// Most legs one combo intent may carry.
pub const MAX_LEGS:usize=4;

/// Issuance protocol of a registered stablecoin.
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Serialize,Deserialize)]
pub enum StableProtocol{Rgb,Tap}
/// Asset an option leg settles and is margined in.
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Serialize,Deserialize)]
pub enum SettleAsset{
 /// Satoshis.
 Btc,
 /// A USD stablecoin: RGB contract id or Taproot Assets asset id, `decimals` base-unit
 /// digits per USD (6 for USDT).
 Stable{protocol:StableProtocol,id:Key,decimals:u8},
}
impl SettleAsset{
 /// Dimension of the payoff engine this asset is valued in.
 pub fn payoff_asset(&self)->payoff::Asset{match self{Self::Btc=>payoff::Asset::Btc,Self::Stable{..}=>payoff::Asset::Usd}}
 /// Base units per payoff unit (`payoff::Asset::Usd` is micro-USD).
 pub fn scale(&self)->u128{match self{Self::Btc=>1,Self::Stable{decimals,..}=>10u128.pow((*decimals).saturating_sub(6) as u32)}}
 /// The channel-collateral hook this asset maps to in `shz_margin`.
 pub fn collateral(&self)->CollateralAsset{
  match *self{
   Self::Btc=>CollateralAsset::VanillaBtc,
   Self::Stable{protocol:StableProtocol::Tap,id,..}=>CollateralAsset::TaprootAsset{asset_id:id,group_key:None,script_version:0},
   Self::Stable{protocol:StableProtocol::Rgb,id,..}=>CollateralAsset::Rgb{contract_id:id},
  }
 }
 pub(crate) fn put(&self,b:&mut Vec<u8>){
  match self{Self::Btc=>b.push(1),Self::Stable{protocol,id,decimals}=>{b.push(2);b.push(*protocol as u8);b.extend(id);b.push(*decimals)}}
 }
}

/// One listed option series.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct Series{pub kind:OptionKind,pub asset:SettleAsset,pub strike_usd:u64,pub event_id:String}
impl Series{
 pub fn id(&self)->Key{
  let mut b=Vec::new();
  b.push(match self.kind{OptionKind::Call=>1,OptionKind::Put=>2});
  self.asset.put(&mut b);
  u64b(&mut b,self.strike_usd);u64b(&mut b,self.event_id.len()as u64);b.extend(self.event_id.as_bytes());
  tagged_hash(b"SHZ/OPTIONS/SERIES/V2",&b)
 }
 /// The payoff leg of `net` units (positive long), premium excluded, in payoff units.
 fn leg(&self,net:i64)->Leg{
  let (long,qty)=(net>0,net.unsigned_abs());
  match self.asset{
   SettleAsset::Btc=>Leg::InverseOption{kind:self.kind,long,qty_usd:qty,strike_usd:self.strike_usd,premium_sats:0},
   SettleAsset::Stable{..}=>Leg::LinearOption{kind:self.kind,long,qty_btc_e8:qty,strike_usd:self.strike_usd,premium_usd:0},
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
/// Net premium limit of a Take in one asset (thousandths of the asset's base unit).
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct AssetLimit{pub asset:SettleAsset,pub premium_milli:i64}

/// Signed option order (intent version 7). Post: one leg, `premium_milli` is the premium
/// per unit in thousandths of the leg's asset unit (positive). Take: `premium_milli` is the
/// most the taker pays net, in thousandths of a unit, in the asset of the first leg
/// (negative: the least it must receive); every other asset among the legs needs exactly
/// one entry in `other_limits`. Cancel: `cancel_target` is the id of the account's quote.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct IntentV7{
 pub version:u32,pub scope:Scope,pub router:u32,pub channel:BtcOutPoint,pub owner:Key,pub sequence:u64,pub expires_us:u64,
 pub action:Action,pub legs:Vec<LegOrder>,pub premium_milli:i64,
 #[serde(default,skip_serializing_if="Vec::is_empty")]
 pub other_limits:Vec<AssetLimit>,
 pub cancel_target:Key,pub signature:Bip340Signature,
}
impl IntentV7{
 pub fn id(&self)->Key{
  let mut b=Vec::new();u32b(&mut b,self.version);self.scope.put(&mut b);u32b(&mut b,self.router);put_op(&mut b,&self.channel);
  b.extend(self.owner);u64b(&mut b,self.sequence);u64b(&mut b,self.expires_us);
  b.push(match self.action{Action::Post=>1,Action::Take=>2,Action::Cancel=>3});
  u64b(&mut b,self.legs.len()as u64);
  for l in &self.legs{b.extend(l.series);b.push(l.long as u8);u64b(&mut b,l.qty);}
  b.extend(self.premium_milli.to_le_bytes());b.extend(self.cancel_target);
  if !self.other_limits.is_empty(){
   u64b(&mut b,self.other_limits.len()as u64);
   for l in &self.other_limits{l.asset.put(&mut b);b.extend(l.premium_milli.to_le_bytes());}
  }
  tagged_hash(b"SHZ/HFT06/INTENT/V7",&b)
 }
 pub fn signed(mut self,sk:&Key)->R<Self>{self.owner=public(sk);self.signature=sign(sk,&self.id())?;Ok(self)}
}

/// One asset of an options sub-account: `locked` is always the worst-case loss of the
/// legs settling in it; `realized` is premium and payoff received minus paid.
#[derive(Debug,Clone,Copy,Default,PartialEq,Eq,Serialize,Deserialize)]
pub struct AssetBalance{pub free:u64,pub locked:u64,pub realized:i64}
/// Options sub-account of one channel.
#[derive(Debug,Clone,Default,PartialEq,Eq)]
pub struct OptionAccount{
 pub balances:BTreeMap<SettleAsset,AssetBalance>,
 /// Net units per series, positive long.
 pub legs:BTreeMap<Key,i64>,
 pub last_sequence:u64,
}
impl OptionAccount{
 pub fn balance(&self,a:&SettleAsset)->AssetBalance{self.balances.get(a).copied().unwrap_or_default()}
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
struct Quote{intent:IntentV7,remaining:u64}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
struct Listed{series:Series,announcement:OracleAnnouncement,settled:Option<u64>}

/// One option fill: `qty` units of `series` between the long and the short account at
/// `premium_milli` per unit; `premium` (base units of the series' asset) moves long to short.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct OptionFill{pub series:Key,pub asset:SettleAsset,pub long:BtcOutPoint,pub short:BtcOutPoint,pub maker:Key,pub taker:Key,pub qty:u64,pub premium_milli:u64,pub premium:u64}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub enum OptionBatchKind{
 /// One taker intent (single leg or combo), all of its fills.
 Trade{taker:Key},
 /// Expiry of every open `series` on oracle event `event_id`, every asset, at the
 /// attested `price_usd` (clamped to the domain). `price_usd == 0`, outside every domain,
 /// is a void: the oracle declared the event unattestable, no payoff moves, every leg
 /// returns to its pre-trade position (premiums stay paid) and its collateral is freed.
 Expiry{event_id:String,series:Vec<Key>,price_usd:u64},
}
impl OptionBatchKind{
 /// An expiry on the oracle's unattestable notice (`price_usd == 0`).
 pub fn is_void(&self)->bool{matches!(self,Self::Expiry{price_usd:0,..})}
}

/// Domain tag of the oracle's unattestable notice (the FROST members' `UNATTESTABLE_TAG`).
pub const UNATTESTABLE_TAG:&[u8]=b"SHZ/DLC/UNATTESTABLE/V1";
/// Message the oracle signs to declare `event_id` unattestable.
pub fn unattestable_message(event_id:&str)->Key{tagged_hash(UNATTESTABLE_TAG,event_id.as_bytes())}
/// Clearing of one asset inside an option batch.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct AssetClearing{pub asset:SettleAsset,pub report:BatchClearing}
/// Atomic unit of option settlement: every fill and cash move of one take or expiry,
/// with one clearing report per asset it moves (assets in `SettleAsset` order).
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct OptionBatch{pub sequence:u64,pub kind:OptionBatchKind,pub fills:Vec<OptionFill>,pub clearing:Vec<AssetClearing>}
impl OptionBatch{
 pub fn clearing_of(&self,a:&SettleAsset)->Option<&BatchClearing>{self.clearing.iter().find(|c|c.asset==*a).map(|c|&c.report)}
 /// Channels with a clearing row in any asset, in key order.
 pub fn channels(&self)->Vec<BtcOutPoint>{
  let mut m=BTreeMap::new();
  for c in &self.clearing{for r in &c.report.rows{m.insert(op(&r.channel),r.channel.clone());}}
  m.into_values().collect()
 }
 /// Digest of the whole batch: kind, fills and every asset's clearing digest.
 pub fn digest(&self)->Key{
  let mut b=Vec::new();u64b(&mut b,self.sequence);
  match &self.kind{
   OptionBatchKind::Trade{taker}=>{b.push(1);b.extend(taker)},
   OptionBatchKind::Expiry{event_id,series,price_usd}=>{
    b.push(2);u64b(&mut b,event_id.len()as u64);b.extend(event_id.as_bytes());u64b(&mut b,series.len()as u64);
    for s in series{b.extend(s)}
    u64b(&mut b,*price_usd);
   }
  }
  u64b(&mut b,self.fills.len()as u64);
  for f in &self.fills{
   b.extend(f.series);f.asset.put(&mut b);put_op(&mut b,&f.long);put_op(&mut b,&f.short);b.extend(f.maker);b.extend(f.taker);
   for n in [f.qty,f.premium_milli,f.premium]{u64b(&mut b,n)}
  }
  u64b(&mut b,self.clearing.len()as u64);
  for c in &self.clearing{c.asset.put(&mut b);b.extend(c.report.digest());}
  tagged_hash(b"SHZ/OPTIONS/BATCH/V1",&b)
 }
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum OptionOutcome{
 Posted(Key),Cancelled(Key),
 /// The batch committed (option acknowledgements off).
 Filled(Box<OptionBatch>),
 /// The batch is staged until every lane in it acknowledges (`EnableOptionAcks`).
 Staged(Box<OptionBatch>),
}

/// Domain tag of option-batch lane acknowledgements: config, batch digest, sequence,
/// disposition, channel and the lane's clearing row with the clearing digest in every
/// asset the lane moves in (`AssetClearing`).
pub const OPTION_ACK_TAG_V4:&[u8]=b"SHZ/HFT06/CHANNEL-ACK/V4";
/// Owner, peer and monitor signatures of one lane over its V4 acknowledgement message.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct OptionAck{pub channel:BtcOutPoint,pub signatures:[Bip340Signature;3]}
/// Acknowledgements of the staged option batch, one per lane in `OptionBatch::channels`
/// order. A Commit needs all three signatures on every lane; a FencedAbort after the
/// deadline needs peer and monitor only (owner signature all-zero allowed).
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct OptionAckBundle{pub sequence:u64,pub batch:Key,pub disposition:super::durable::Disposition,pub acks:Vec<OptionAck>}
/// V4 acknowledgement message of `channel` for `batch`.
pub fn option_ack_message(config:&Key,batch:&OptionBatch,disposition:super::durable::Disposition,channel:&BtcOutPoint)->R<Key>{
 let mut b=Vec::new();b.extend(config);b.extend(batch.digest());u64b(&mut b,batch.sequence);
 b.push(match disposition{super::durable::Disposition::Commit=>1,super::durable::Disposition::FencedAbort=>2});
 put_op(&mut b,channel);
 let mut any=false;
 for c in &batch.clearing{
  if c.report.row(channel).is_some(){any=true;c.asset.put(&mut b);c.report.put_row(channel,&mut b)?;}
 }
 if !any{return Err(Reject::Allocation)}
 Ok(tagged_hash(OPTION_ACK_TAG_V4,&b))
}

/// Every option book, sub-account, stablecoin pool and batch. Pure state: callers pass
/// the router's account owners and its (BTC) clearing ledger.
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct OptionsDesk{
 pub oracle:Key,pub domain:PriceDomain,
 /// Combos (more than one leg per Take) accepted (journaled `EnableCombos`).
 pub combos:bool,
 /// Registered stablecoins and their clearing pools.
 pools:BTreeMap<SettleAsset,ClearingState>,
 series:BTreeMap<Key,Listed>,
 books:BTreeMap<(Key,bool),BTreeMap<(i64,u64),Quote>>,
 locations:BTreeMap<Key,(Key,bool,(i64,u64))>,
 accounts:BTreeMap<Outpoint,OptionAccount>,
 batches:Vec<OptionBatch>,
 arrival:u64,clock:u64,
}

/// Premium of `qty` units at `milli` per unit, in base units (floor, same for both sides).
fn premium(qty:u64,milli:u64)->R<u64>{u64::try_from(qty as u128*milli as u128/1000).map_err(|_|Reject::Bounds)}
fn s64(x:u64)->R<i64>{i64::try_from(x).map_err(|_|Reject::Bounds)}
fn u(x:u128)->R<u64>{u64::try_from(x).map_err(|_|Reject::Bounds)}

impl OptionsDesk{
 pub fn new(oracle:Key,num_bits:u8)->R<Self>{
  if !(4..=40).contains(&num_bits)||oracle==[0;32]{return Err(Reject::Bounds)}
  Ok(Self{oracle,domain:PriceDomain::from_bits(num_bits),combos:false,pools:BTreeMap::new(),series:BTreeMap::new(),books:BTreeMap::new(),
   locations:BTreeMap::new(),accounts:BTreeMap::new(),batches:Vec::new(),arrival:0,clock:0})
 }
 pub fn account(&self,k:&Outpoint)->Option<&OptionAccount>{self.accounts.get(k)}
 /// Latest `now` the desk has seen.
 pub fn clock(&self)->u64{self.clock}
 pub(crate) fn touch(&mut self,now:u64){self.clock=self.clock.max(now)}
 /// Mark an intent sequence used (an aborted staged take cannot be replayed).
 pub(crate) fn consume(&mut self,k:Outpoint,sequence:u64){let a=self.accounts.entry(k).or_default();a.last_sequence=a.last_sequence.max(sequence)}
 /// Pull resting quotes by id (makers of an aborted batch are not reactivated).
 pub(crate) fn cancel_quotes(&mut self,ids:&[Key]){
  for id in ids{if let Some((s,l,key))=self.locations.remove(id)&&let Some(b)=self.books.get_mut(&(s,l)){b.remove(&key);}}
 }
 pub fn batch(&self,sequence:u64)->Option<&OptionBatch>{sequence.checked_sub(1).and_then(|i|self.batches.get(i as usize))}
 pub fn batch_count(&self)->u64{self.batches.len()as u64}
 pub fn series(&self,id:&Key)->Option<(&Series,Option<u64>)>{self.series.get(id).map(|l|(&l.series,l.settled))}
 pub fn series_ids(&self)->impl Iterator<Item=&Key>{self.series.keys()}
 /// Registered stablecoins and their clearing pools.
 pub fn stable_pools(&self)->impl Iterator<Item=(&SettleAsset,&ClearingState)>{self.pools.iter()}
 pub fn registered(&self,a:&SettleAsset)->bool{*a==SettleAsset::Btc||self.pools.contains_key(a)}
 /// Resting quotes of one side of a series book in priority order: (id, premium_milli, remaining).
 pub fn depth(&self,series:&Key,long:bool)->Vec<(Key,i64,u64)>{
  self.books.get(&(*series,long)).map(|b|b.values().map(|q|(q.intent.id(),q.intent.premium_milli,q.remaining)).collect()).unwrap_or_default()
 }
 /// Payoff legs of an account's open option positions (payoff units).
 pub fn legs(&self,k:&Outpoint)->Vec<Leg>{self.groups(k).into_values().flatten().collect()}
 /// The account's legs grouped by (expiry, settlement asset): legs offset only within a
 /// group, since different events settle at different prices and assets never net.
 pub fn groups(&self,k:&Outpoint)->BTreeMap<(String,SettleAsset),Vec<Leg>>{
  let mut out:BTreeMap<(String,SettleAsset),Vec<Leg>>=BTreeMap::new();
  if let Some(a)=self.accounts.get(k){
   for (s,&n) in &a.legs{
    if let (true,Some(l))=(n!=0,self.series.get(s)){out.entry((l.series.event_id.clone(),l.series.asset)).or_default().push(l.series.leg(n));}
   }
  }
  out
 }
 /// Collateral the account's options need in `asset` (base units): the sum over expiries
 /// of each expiry's worst-case loss in that asset.
 pub fn required(&self,k:&Outpoint,asset:&SettleAsset)->u128{
  self.groups(k).iter().filter(|((_,a),_)|a==asset).map(|((_,a),g)|payoff::max_loss(g,a.payoff_asset(),self.domain)*a.scale()).sum()
 }
 /// Posted collateral covers every expiry's worst-case loss in every asset the account
 /// settles in (`payoff::fully_funded` per asset and expiry): exempt from liquidation.
 pub fn fully_funded(&self,k:&Outpoint)->bool{
  let Some(a)=self.accounts.get(k)else{return true};
  let assets:BTreeSet<SettleAsset>=self.groups(k).keys().map(|(_,a)|*a).collect();
  assets.iter().all(|x|a.balance(x).locked as u128>=self.required(k,x))
 }

 /// Register a stablecoin (once): opens its clearing pool with no fund.
 pub fn register_stable(&mut self,asset:SettleAsset)->R<()>{
  let SettleAsset::Stable{id,decimals,..}=asset else{return Err(Reject::Bounds)};
  if !(6..=18).contains(&decimals)||id==[0;32]{return Err(Reject::Bounds)}
  if self.pools.contains_key(&asset){return Err(Reject::Replay)}
  self.pools.insert(asset,ClearingState::open(0,std::iter::empty())?);Ok(())
 }
 /// List a series on an oracle announcement of the desk's oracle and domain. Calls settle
 /// in BTC; puts in BTC or a registered stablecoin.
 pub fn list(&mut self,series:Series,announcement:OracleAnnouncement)->R<Key>{
  let id=series.id();
  if self.series.contains_key(&id)||announcement.oracle_pubkey_x!=self.oracle||announcement.event_id!=series.event_id||
     announcement.num_bits()==0||PriceDomain::from_bits(announcement.num_bits().clamp(1,40))!=self.domain||
     !(self.domain.p_min..=self.domain.p_max).contains(&series.strike_usd){return Err(Reject::Bounds)}
  if series.asset!=SettleAsset::Btc&&series.kind!=OptionKind::Put{return Err(Reject::Bounds)}
  if !self.registered(&series.asset){return Err(Reject::Scope)}
  // Every series of one event settles on one announcement.
  if self.series.values().any(|l|l.series.event_id==series.event_id&&l.announcement!=announcement){return Err(Reject::Bounds)}
  self.series.insert(id,Listed{series,announcement,settled:None});Ok(id)
 }
 /// Move `sats` between the account's perpetual allocation and its options sub-account.
 pub(crate) fn fund(&mut self,k:Outpoint,b:&mut Balance,sats:u64,to_options:bool)->R<()>{
  let a=self.accounts.entry(k).or_default().balances.entry(SettleAsset::Btc).or_default();
  if to_options{
   if b.free<sats{return Err(Reject::Capacity)}
   b.free-=sats;b.cap-=sats;a.free=a.free.checked_add(sats).ok_or(Reject::Bounds)?;
  }else{
   if a.free<sats{return Err(Reject::Capacity)}
   a.free-=sats;b.free=b.free.checked_add(sats).ok_or(Reject::Bounds)?;b.cap=b.cap.checked_add(sats).ok_or(Reject::Bounds)?;
  }
  Ok(())
 }
 /// Credit (`deposit`) or debit `units` of a registered stablecoin. The TAP/RGB transfer
 /// itself is the simulated adapter's; this records its effect on the sub-account.
 pub fn stable_transfer(&mut self,k:Outpoint,asset:SettleAsset,units:u64,deposit:bool)->R<()>{
  if asset==SettleAsset::Btc||!self.pools.contains_key(&asset){return Err(Reject::Scope)}
  let a=self.accounts.entry(k).or_default().balances.entry(asset).or_default();
  if deposit{a.free=a.free.checked_add(units).ok_or(Reject::Bounds)?}
  else{if a.free<units{return Err(Reject::Capacity)}a.free-=units}
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
  if leg.qty==0||i.premium_milli<=0||!i.other_limits.is_empty(){return Err(Reject::Bounds)}
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
  let mut seen=BTreeSet::new();let mut assets=BTreeSet::new();
  for l in &i.legs{
   let s=&self.open_series(&l.series)?.series;
   if l.qty==0||!seen.insert(l.series){return Err(Reject::Bounds)}
   assets.insert(s.asset);
  }
  // One limit per asset among the legs: the first leg's in `premium_milli`, the others in
  // `other_limits`, each exactly once.
  let first=self.series[&i.legs[0].series].series.asset;
  let mut limits=BTreeMap::from([(first,i.premium_milli)]);
  for l in &i.other_limits{if limits.insert(l.asset,l.premium_milli).is_some(){return Err(Reject::Bounds)}}
  if limits.keys().copied().collect::<BTreeSet<_>>()!=assets{return Err(Reject::Bounds)}
  let mut base=self.clone();
  loop{
   let mut work=base.clone();
   match work.try_take(i,&limits,clearing)?{
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
 fn try_take(&mut self,i:&IntentV7,limits:&BTreeMap<SettleAsset,i64>,clearing:&ClearingState)->R<Result<(OptionBatch,ClearingState),Outpoint>>{
  let taker=op(&i.channel);
  let mut fills=Vec::new();
  for l in &i.legs{
   let asset=self.series[&l.series].series.asset;
   let mut need=l.qty;
   let book=self.books.entry((l.series,!l.long)).or_default();
   let mut done=Vec::new();
   for (key,q) in book.iter_mut(){
    if need==0{break}
    if op(&q.intent.channel)==taker{continue}
    let n=need.min(q.remaining);
    let milli=u64::try_from(q.intent.premium_milli).map_err(|_|Reject::Bounds)?;
    let (long,short)=if l.long{(i.channel.clone(),q.intent.channel.clone())}else{(q.intent.channel.clone(),i.channel.clone())};
    fills.push(OptionFill{series:l.series,asset,long,short,maker:q.intent.id(),taker:i.id(),qty:n,premium_milli:milli,premium:premium(n,milli)?});
    q.remaining-=n;need-=n;
    if q.remaining==0{done.push((*key,q.intent.id()))}
   }
   if need>0{return Err(Reject::NoLiquidity)}
   for (key,id) in done{book.remove(&key);self.locations.remove(&id);}
  }
  // Taker's net premium per asset against its limits (thousandths of a unit).
  for (asset,&limit) in limits{
   let mut net:i128=0;
   for f in fills.iter().filter(|f|f.asset==*asset){let p=f.premium as i128*1000;if op(&f.long)==taker{net+=p}else{net-=p}}
   if net>limit as i128{return Err(Reject::FeeLimit)}
  }
  // Cash per (account, asset), then legs and margin.
  let mut cash:BTreeMap<(SettleAsset,Outpoint),(BtcOutPoint,u64,u64)>=BTreeMap::new();
  for f in &fills{
   cash.entry((f.asset,op(&f.long))).or_insert((f.long.clone(),0,0)).2+=f.premium;
   cash.entry((f.asset,op(&f.short))).or_insert((f.short.clone(),0,0)).1+=f.premium;
   let units=s64(f.qty)?;
   *self.accounts.entry(op(&f.long)).or_default().legs.entry(f.series).or_insert(0)+=units;
   *self.accounts.entry(op(&f.short)).or_default().legs.entry(f.series).or_insert(0)-=units;
  }
  let mut rows:BTreeMap<SettleAsset,Vec<ClearingRow>>=BTreeMap::new();
  for ((asset,k),(ch,received,paid)) in &cash{
   self.accounts.get_mut(k).unwrap().legs.retain(|_,n|*n!=0);
   let req=u(self.required(k,asset))?;
   let b=self.accounts[k].balance(asset);
   let avail=b.free as i128+b.locked as i128+*received as i128-*paid as i128-req as i128;
   if avail<0{return if *k==taker{Err(Reject::Capacity)}else{Ok(Err(*k))}}
   let realized=b.realized.checked_add(s64(*received)?-s64(*paid)?).ok_or(Reject::Bounds)?;
   self.accounts.get_mut(k).unwrap().balances.insert(*asset,AssetBalance{free:avail as u64,locked:req,realized});
   let pool=if *asset==SettleAsset::Btc{clearing}else{&self.pools[asset]};
   rows.entry(*asset).or_default().push(row(pool,ch,s64(*received)?-s64(*paid)?,*paid,*received));
  }
  let seq=self.batches.len()as u64+1;
  let (reports,next)=self.settle_all(clearing,rows,&BTreeMap::new())?;
  Ok(Ok((OptionBatch{sequence:seq,kind:OptionBatchKind::Trade{taker:i.id()},fills,clearing:reports},next)))
 }
 /// Clear every asset's rows: BTC against `clearing`, stablecoins against their pools
 /// (updated in place on this working copy). Returns the reports and the next BTC ledger.
 fn settle_all(&mut self,clearing:&ClearingState,rows:BTreeMap<SettleAsset,Vec<ClearingRow>>,dust:&BTreeMap<SettleAsset,u64>)->R<(Vec<AssetClearing>,ClearingState)>{
  let mut next_btc=clearing.clone();let mut reports=Vec::new();
  for (asset,rows) in rows{
   let d=dust.get(&asset).copied().unwrap_or(0);
   let pool=if asset==SettleAsset::Btc{clearing}else{&self.pools[&asset]};
   let (report,next)=settle(pool,rows,d)?;
   if asset==SettleAsset::Btc{next_btc=next}else{self.pools.insert(asset,next);}
   reports.push(AssetClearing{asset,report});
  }
  Ok((reports,next_btc))
 }

 /// Expire, at the oracle's attested price, every open series on the oracle event of
 /// `id`, in every asset: each account's positions pay out as one amount per asset,
 /// losers from their locked collateral, and the collateral no longer needed is freed.
 pub fn expire(&mut self,id:&Key,attestation:&OracleAttestation,clearing:&mut ClearingState)->R<OptionBatch>{
  let l=self.open_series(id)?;
  attestation.verify_against(&l.announcement).map_err(|_|Reject::Oracle)?;
  let (event,price)=(l.series.event_id.clone(),attestation.price_usd.clamp(self.domain.p_min,self.domain.p_max));
  self.settle_event(event,Some(price),clearing)
 }
 /// Void every open series on `event_id` on the oracle's signed unattestable notice: a
 /// BIP340 signature by the desk's oracle key over `unattestable_message(event_id)` whose
 /// nonce is none of the event's digit nonces. Every leg on the event is removed with no
 /// payoff (premiums stay paid) and the collateral it held is freed. A voided series reads
 /// `settled == Some(0)` afterwards (0 is outside every price domain).
 pub fn void(&mut self,event_id:&str,notice:&Bip340Signature,clearing:&mut ClearingState)->R<OptionBatch>{
  let l=self.series.values().find(|l|l.settled.is_none()&&l.series.event_id==event_id).ok_or(Reject::UnknownOrder)?;
  if l.announcement.digit_nonces_x.contains(&notice.r_x){return Err(Reject::Oracle)}
  verify(&self.oracle,&unattestable_message(event_id),notice).map_err(|_|Reject::Oracle)?;
  self.settle_event(event_id.to_string(),None,clearing)
 }
 /// Settle every open series on `event`: at `price`, or void when `None`.
 fn settle_event(&mut self,event:String,price:Option<u64>,clearing:&mut ClearingState)->R<OptionBatch>{
  let mut work=self.clone();
  let ids:Vec<Key>=work.series.iter().filter(|(_,l)|l.settled.is_none()&&l.series.event_id==event).map(|(k,_)|*k).collect();
  // Resting quotes of expired series are cancelled.
  for s in &ids{
   for long in [true,false]{
    if let Some(b)=work.books.remove(&(*s,long)){for q in b.values(){work.locations.remove(&q.intent.id());}}
   }
  }
  let holders:Vec<Outpoint>=work.accounts.iter().filter(|(_,a)|ids.iter().any(|s|a.legs.get(s).is_some_and(|&n|n!=0))).map(|(k,_)|*k).collect();
  let mut moves=Vec::new();let mut totals:BTreeMap<SettleAsset,(u64,u64)>=BTreeMap::new();
  for k in &holders{
   let groups=work.groups(k);
   for ((ev,asset),legs) in groups{
    if ev!=event{continue}
    // `pnl` floors: a net winner is paid the floor, a net loser pays the ceiling.
    let v=price.map_or(0,|p|payoff::pnl(&legs,asset.payoff_asset(),p)*asset.scale() as i128);
    let (paid,collected)=if v>=0{(u(v as u128)?,0)}else{(0,u((-v) as u128)?)};
    let t=totals.entry(asset).or_default();
    t.0=t.0.checked_add(paid).ok_or(Reject::Bounds)?;t.1=t.1.checked_add(collected).ok_or(Reject::Bounds)?;
    moves.push((*k,asset,paid,collected));
   }
  }
  for k in &holders{let a=work.accounts.get_mut(k).unwrap();for s in &ids{a.legs.remove(s);}}
  let mut rows:BTreeMap<SettleAsset,Vec<ClearingRow>>=BTreeMap::new();
  for (k,asset,paid,collected) in moves{
   let req=u(work.required(&k,&asset))?;
   let b=work.accounts[&k].balance(&asset);
   let total=b.free as i128+b.locked as i128+paid as i128-collected as i128-req as i128;
   // Locked collateral covers each expiry's worst case on its own, so this cannot go negative.
   if total<0{return Err(Reject::Bounds)}
   let realized=b.realized.checked_add(s64(paid)?-s64(collected)?).ok_or(Reject::Bounds)?;
   work.accounts.get_mut(&k).unwrap().balances.insert(asset,AssetBalance{free:total as u64,locked:req,realized});
   let ch=BtcOutPoint{txid:k.0,vout:k.1};
   let pool=if asset==SettleAsset::Btc{&*clearing}else{&work.pools[&asset]};
   rows.entry(asset).or_default().push(row(pool,&ch,s64(paid)?-s64(collected)?,collected,paid));
  }
  let mut dust=BTreeMap::new();
  for (asset,(g,c)) in totals{if g>c{return Err(Reject::Bounds)}dust.insert(asset,c-g);}
  let seq=work.batches.len()as u64+1;
  let (reports,next)=work.settle_all(clearing,rows,&dust)?;
  let kind=OptionBatchKind::Expiry{event_id:event,series:ids.clone(),price_usd:price.unwrap_or(0)};
  let batch=OptionBatch{sequence:seq,kind,fills:Vec::new(),clearing:reports};
  for s in &ids{work.series.get_mut(s).unwrap().settled=Some(price.unwrap_or(0));}
  work.batches.push(batch.clone());*self=work;*clearing=next;
  Ok(batch)
 }
}

fn row(c:&ClearingState,ch:&BtcOutPoint,pnl:i64,collected:u64,paid:u64)->ClearingRow{
 let claim=c.claim(ch);
 ClearingRow{channel:ch.clone(),pnl,released:0,collected,own_claim_used:0,shortfall:0,haircut:0,claim_before:claim,claim_after:claim,paid,net:paid as i64-collected as i64}
}
/// Clearing report of one asset of an option batch against that asset's pool: losers'
/// cash collected in, winners paid out, `dust` kept as clearing fund (cash and fund both
/// rise, so `cash - claims - fund + carry == book` still holds).
fn settle(c:&ClearingState,rows:Vec<ClearingRow>,dust:u64)->R<(BatchClearing,ClearingState)>{
 let collected:i128=rows.iter().map(|r|r.collected as i128).sum();
 let paid:i128=rows.iter().map(|r|r.paid as i128).sum();
 if collected-paid!=dust as i128{return Err(Reject::Bounds)}
 let mut next=c.clone();
 next.cash=next.cash.checked_add(s64(dust)?).ok_or(Reject::Bounds)?;next.fund=next.fund.checked_add(dust).ok_or(Reject::Bounds)?;
 let layer=if collected>0{Waterfall::Margin}else{Waterfall::None};
 Ok((BatchClearing{rows,claim_haircuts:Vec::new(),shortfall:0,fund_absorbed:0,haircut:0,layer,cash_before:c.cash,cash_after:next.cash,
  fund_after:next.fund,carry_after:next.carry,claims_after:next.claims_total()},next))
}
