//! Spot BTC/USDT market on the options desk (docs/SHZ_SPOT.md): fully funded orders out of
//! the shared asset wallet, IOC takes staged as spot batches, per-asset clearing rows,
//! commit or fenced abort through the V4 lane acknowledgement round, journal replay.
//! Synthetic funds and a deterministic test oracle only.
use shz_dex::routing::*;
use shz_dex::routing::durable::{Disposition,FeeRecipients,Head,Lane};
use shz_dex::routing::options::*;
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dlc::BtcOutPoint;
use shz_oracle::frost::FrostConfederation;
use std::{cell::Cell,fs,path::{Path,PathBuf},sync::atomic::{AtomicU64,Ordering}};

type Key=[u8;32];
const AUTH:[u8;32]=[77;32];
const CAP:u64=100_000_000;
const N:u8=4;
const T0:u64=1_000_000;
fn sk(n:u8)->Key{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn op(n:u8)->([u8;32],u32){([n;32],0)}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[pk(50),pk(51)]}}
fn registry()->Registry{
 let p=policy();
 let plans=(1..=N).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),CAP,vec![Share{router:1,sats:CAP}]).unwrap()).collect();
 Registry::new(p.scope(),public(&AUTH),plans).unwrap()
}
fn cfg()->TieredConfig{
 TieredConfig{scope:policy().scope(),router:1,entitlement_key:pk(60),tariff:TariffSchedule::default_candidate(),
  execution:ExecutionPolicy::defaults(Arm::FeedOnly),revenue:RevenuePolicy::default()}
}
fn lanes()->Vec<Lane>{
 (1..=N).map(|n|Lane{channel:channel(n),peer:pk(70+n),monitor:pk(90+n),initial:Head{revision:0,commitment:10,state:[110+n;32]}}).collect()
}
fn recipients()->FeeRecipients{FeeRecipients{oracle:pk(110),router:pk(111)}}
const BTC:SettleAsset=SettleAsset::Btc;
const USDT:SettleAsset=SettleAsset::Stable{protocol:StableProtocol::Rgb,id:[0x52;32],decimals:6};
/// 1000-sat lots and a 0.1 USDT tick: every fill's USDT amount is an exact integer.
const PAIR:SpotPair=SpotPair{quote:USDT,lot_sats:1_000,tick:100_000};
/// USDT base units per BTC.
const fn usd(p:u64)->u64{p*1_000_000}
const ZSIG:shz_dlc::Bip340Signature=shz_dlc::Bip340Signature{r_x:[0;32],s:[0;32]};

static COUNTER:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp{
 fn new()->Self{
  let p=std::env::temp_dir().join(format!("shz-spot-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
 fn path(&self)->PathBuf{self.0.join("router.wal")}
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

struct Spot{d:DurableTieredRouter,pair:Key,seq:Cell<u64>,now:Cell<u64>,
 /// Units of each asset that entered the asset wallets (fund + deposit), for conservation.
 total:Cell<(u64,u64)>}
/// Options with acknowledgements, USDT registered, spot on with the BTC/USDT pair.
fn open_desk(path:&Path)->DurableTieredRouter{
 let mut d=DurableTieredRouter::create(path,&registry(),cfg(),lanes(),recipients()).unwrap();
 assert!(d.enable_margin_release().unwrap());assert!(d.enable_clearing(1_000_000).unwrap());
 let oracle=FrostConfederation::keygen_deterministic(2,3,&[0x51;32]).unwrap();
 assert!(d.enable_options(oracle.group_pubkey_x,20).unwrap());
 d.register_stable(USDT).unwrap();
 d
}
impl Spot{
 fn new(path:&Path)->Self{
  let mut d=open_desk(path);
  // Spot needs the acknowledgement round: refused before it is on.
  rejected(d.enable_spot(),TierReject::Scope);
  assert!(d.enable_option_acks().unwrap());
  rejected(d.list_spot_pair(PAIR),TierReject::Scope);
  assert!(d.enable_spot().unwrap());assert!(!d.enable_spot().unwrap());
  let pair=d.list_spot_pair(PAIR).unwrap();
  assert_eq!(pair,PAIR.id());
  rejected(d.list_spot_pair(PAIR),TierReject::Replay);
  // A lot and tick whose product is not a multiple of 10^8, and a BTC quote, are refused.
  rejected(d.list_spot_pair(SpotPair{quote:USDT,lot_sats:1_000,tick:1}),TierReject::Bounds);
  rejected(d.list_spot_pair(SpotPair{quote:BTC,lot_sats:1_000,tick:100_000}),TierReject::Bounds);
  Self{d,pair,seq:Cell::new(0),now:Cell::new(T0),total:Cell::new((0,0))}
 }
 fn fund(&mut self,n:u8,sats:u64,usdt:u64){
  if sats>0{self.d.fund_options(channel(n),sats).unwrap()}
  if usdt>0{self.d.deposit_stable(channel(n),USDT,usdt).unwrap()}
  let (a,b)=self.total.get();self.total.set((a+sats,b+usdt));
 }
 fn intent(&self,n:u8,action:Action,buy:bool,qty_sats:u64,price:u64,cancel_target:Key)->SpotIntent{
  let c=cfg();self.seq.set(self.seq.get()+1);
  SpotIntent{version:SPOT_INTENT_VERSION,scope:c.scope,router:1,channel:channel(n),owner:[0;32],sequence:self.seq.get(),
   expires_us:self.now.get()+5_000_000,action,pair:self.pair,buy,qty_sats,price,cancel_target,signature:ZSIG}.signed(&sk(n)).unwrap()
 }
 fn send(&mut self,i:SpotIntent)->Result<OptionOutcome,TieredDurableError>{self.now.set(self.now.get()+1);let now=self.now.get();self.d.submit_spot(i,now)}
 fn post(&mut self,n:u8,buy:bool,qty:u64,price:u64)->Key{
  match self.send(self.intent(n,Action::Post,buy,qty,price,[0;32])).unwrap(){OptionOutcome::Posted(id)=>id,x=>panic!("{x:?}")}
 }
 fn take(&mut self,n:u8,buy:bool,qty:u64,price:u64)->OptionBatch{
  match self.send(self.intent(n,Action::Take,buy,qty,price,[0;32])).unwrap(){OptionOutcome::Staged(b)=>*b,x=>panic!("{x:?}")}
 }
 fn cancel(&mut self,n:u8,id:Key)->Result<OptionOutcome,TieredDurableError>{self.send(self.intent(n,Action::Cancel,false,0,0,id))}
 fn desk(&self)->&OptionsDesk{self.d.options().unwrap().unwrap()}
 fn bal(&self,n:u8,a:SettleAsset)->AssetBalance{self.desk().account(&op(n)).map(|x|x.balance(&a)).unwrap_or_default()}
 fn locked(&self,n:u8,a:SettleAsset)->u64{self.desk().spot().unwrap().locked(&op(n),&a)}
 /// (free BTC, spot-locked BTC, free USDT, spot-locked USDT)
 fn wallet(&self,n:u8)->(u64,u64,u64,u64){(self.bal(n,BTC).free,self.locked(n,BTC),self.bal(n,USDT).free,self.locked(n,USDT))}
 /// Every V4 lane acknowledgement of the staged batch: owner (unless `owner` is false),
 /// peer and monitor.
 fn acks(&self,disposition:Disposition,owner:bool)->OptionAckBundle{
  let b=self.d.pending_option().unwrap().unwrap().clone();
  let acks=b.channels().into_iter().map(|c|{
   let n=c.txid[0];let h=self.d.option_ack_message(disposition,&c).unwrap();
   let o=if owner{shz_dlc::bip340_sign(&sk(n),&h).unwrap()}else{ZSIG};
   OptionAck{channel:c,signatures:[o,shz_dlc::bip340_sign(&sk(70+n),&h).unwrap(),shz_dlc::bip340_sign(&sk(90+n),&h).unwrap()]}
  }).collect();
  OptionAckBundle{sequence:b.sequence,batch:b.digest(),disposition,acks}
 }
 fn commit(&mut self){let a=self.acks(Disposition::Commit,true);assert!(self.d.resolve_option(a,self.now.get()).unwrap());}
 /// Per asset: every unit that entered the wallets is in some free or spot-locked balance
 /// (spot never creates or destroys an asset), option collateral is untouched, the clearing
 /// identity holds in every pool, and the perpetual balances are conserved.
 fn check(&self){
  let (mut btc,mut usdt)=(0u64,0u64);
  for n in 1..=N{
   let (a,b,c,d)=self.wallet(n);btc+=a+b;usdt+=c+d;
   assert_eq!((self.bal(n,BTC).locked,self.bal(n,USDT).locked),(0,0));
   assert_eq!((self.bal(n,BTC).realized,self.bal(n,USDT).realized),(0,0),"spot is an exchange, not PnL");
   assert!(self.d.balance(&channel(n)).unwrap().unwrap().conserved());
  }
  assert_eq!((btc,usdt),self.total.get());
  assert_eq!(self.d.clearing_summary().unwrap().unwrap().identity,0);
  for (_,pool) in self.desk().stable_pools(){assert_eq!(pool.summary(0).identity,0);}
 }
}
fn rejected(r:Result<impl std::fmt::Debug,TieredDurableError>,want:TierReject){
 match r{Err(TieredDurableError::Rejected(x)) if x==want=>{},x=>panic!("want {want:?}, got {x:?}")}
}
/// Each asset's rows in a batch: one per account, nets summing to zero, the pool unchanged.
type Rows=Vec<(u8,i64)>;
fn per_asset(b:&OptionBatch)->(Rows,Rows){
 assert!(matches!(b.kind,OptionBatchKind::Spot{..}));
 assert!(b.fills.is_empty());
 assert_eq!(b.clearing.iter().map(|c|c.asset).collect::<Vec<_>>(),vec![BTC,USDT]);
 let rows=|a:&SettleAsset|{
  let r=b.clearing_of(a).unwrap();
  assert_eq!(r.rows.iter().map(|x|x.net).sum::<i64>(),0,"{a:?} nets to zero");
  assert_eq!((r.cash_before,r.pool_net(),r.shortfall,r.haircut),(r.cash_after,0,0,0));
  let mut v:Rows=r.rows.iter().map(|x|(x.channel.txid[0],x.net)).collect();
  let mut seen=v.iter().map(|x|x.0).collect::<Vec<_>>();seen.dedup();assert_eq!(seen.len(),v.len(),"one row per account");
  v.sort();v
 };
 (rows(&BTC),rows(&USDT))
}

/// S1. A maker's resting sell fills in parts: each take is one staged spot batch that moves
/// nothing until every lane acknowledges, then BTC moves seller to buyer and USDT buyer to
/// seller, one net clearing row per account per asset. A take walks two price levels and
/// is netted per account; the unfilled remainder of an IOC take is dropped.
#[test]
fn s1_partial_fills_move_both_legs_per_asset(){
 let t=Temp::new();let mut v=Spot::new(&t.path());
 v.fund(1,2_000_000,0);v.fund(2,0,2_000_000_000);v.fund(3,0,1_000_000_000);v.fund(4,500_000,0);
 let ask=v.post(1,false,1_000_000,usd(90_000));
 let ask2=v.post(4,false,500_000,usd(90_100));
 assert_eq!(v.wallet(1),(1_000_000,1_000_000,0,0));
 // Buyer 2 takes 0.004 BTC: staged, nothing moves.
 let before=(v.wallet(1),v.wallet(2));
 let b=v.take(2,true,400_000,usd(90_050));
 assert_eq!((v.wallet(1),v.wallet(2)),before,"a staged spot batch moves nothing");
 assert_eq!(b.spot.len(),1);
 assert_eq!((b.spot[0].sats,b.spot[0].price,b.spot[0].quote_units,b.spot[0].maker),(400_000,usd(90_000),360_000_000,ask));
 assert_eq!(per_asset(&b),(vec![(1,-400_000),(2,400_000)],vec![(1,360_000_000),(2,-360_000_000)]));
 assert_eq!(b.channels(),vec![channel(1),channel(2)]);
 // Everything else on the desk waits for the round.
 rejected(v.send(v.intent(3,Action::Post,true,1_000,usd(80_000),[0;32])),TierReject::Hold);
 v.commit();
 assert_eq!(v.wallet(1),(1_000_000,600_000,360_000_000,0));
 assert_eq!(v.wallet(2),(400_000,0,1_640_000_000,0));
 assert_eq!(v.desk().spot().unwrap().depth(&v.pair,false).iter().map(|q|(q.0,q.2)).collect::<Vec<_>>(),vec![(ask,600_000),(ask2,500_000)]);
 v.check();
 // Buyer 3 sweeps the rest of level 1 and part of level 2, asking for more than rests.
 let b=v.take(3,true,1_000_000,usd(90_100));
 assert_eq!(b.spot.iter().map(|f|(f.maker,f.sats,f.quote_units)).collect::<Vec<_>>(),vec![(ask,600_000,540_000_000),(ask2,400_000,360_400_000)]);
 assert_eq!(per_asset(&b),(vec![(1,-600_000),(3,1_000_000),(4,-400_000)],vec![(1,540_000_000),(3,-900_400_000),(4,360_400_000)]));
 v.commit();
 assert_eq!(v.wallet(3),(1_000_000,0,99_600_000,0));
 assert_eq!(v.wallet(1),(1_000_000,0,900_000_000,0));
 assert_eq!(v.wallet(4),(0,100_000,360_400_000,0));
 // Seller-side take: 1 buys back from 4's resting bid? 4 has a resting ask only; 2 posts a
 // bid and 1 sells into it with an IOC larger than the bid.
 let bid=v.post(2,true,300_000,usd(89_000));
 assert_eq!(v.wallet(2),(400_000,0,1_640_000_000-267_000_000,267_000_000));
 let b=v.take(1,false,500_000,usd(88_000));
 assert_eq!(b.spot.iter().map(|f|(f.maker,f.sats,f.price,f.taker_buys)).collect::<Vec<_>>(),vec![(bid,300_000,usd(89_000),false)]);
 v.commit();
 assert_eq!(v.wallet(2),(700_000,0,1_373_000_000,0));
 assert_eq!(v.wallet(1),(700_000,0,1_167_000_000,0));
 assert_eq!(v.d.options().unwrap().unwrap().batch_count(),3);
 v.check();
}

/// S2. Cancel returns exactly what the order still locks; only the owner can cancel; a
/// partially filled order unlocks its remainder.
#[test]
fn s2_cancel_unlocks_the_remainder(){
 let t=Temp::new();let mut v=Spot::new(&t.path());
 v.fund(1,0,1_000_000_000);v.fund(2,1_000_000,0);
 let bid=v.post(1,true,1_000_000,usd(89_000));
 assert_eq!(v.wallet(1),(0,0,110_000_000,890_000_000));
 rejected(v.cancel(2,bid),TierReject::UnknownOrder);
 let b=v.take(2,false,250_000,usd(89_000));assert_eq!(b.spot[0].quote_units,222_500_000);
 v.commit();
 assert_eq!(v.wallet(1),(250_000,0,110_000_000,667_500_000));
 assert!(matches!(v.cancel(1,bid).unwrap(),OptionOutcome::Cancelled(x) if x==bid));
 assert_eq!(v.wallet(1),(250_000,0,777_500_000,0));
 rejected(v.cancel(1,bid),TierReject::UnknownOrder);
 assert!(v.desk().spot().unwrap().depth(&v.pair,true).is_empty());
 // Freed USDT can leave through the adapter; locked USDT cannot.
 let ask=v.post(2,false,750_000,usd(95_000));
 rejected(v.d.defund_options(channel(2),1),TierReject::Capacity);
 assert!(matches!(v.cancel(2,ask).unwrap(),OptionOutcome::Cancelled(_)));
 v.d.defund_options(channel(2),750_000).unwrap();v.total.set((v.total.get().0-750_000,v.total.get().1));
 v.check();
}

/// S3. Fully funded or refused: a post without the asset it locks, a take that cannot pay
/// every fill, off-lot sizes and off-tick prices, a crossing post, an empty book, a spot
/// order before `EnableSpot` (version or pair unknown) and a replayed sequence.
#[test]
fn s3_insufficient_funds_and_bad_orders_refused(){
 let t=Temp::new();let mut v=Spot::new(&t.path());
 v.fund(1,1_000_000,0);v.fund(2,0,100_000_000);
 rejected(v.send(v.intent(2,Action::Post,true,1_000_000,usd(90_000),[0;32])),TierReject::Capacity);
 rejected(v.send(v.intent(1,Action::Post,false,1_001_000,usd(90_000),[0;32])),TierReject::Capacity);
 rejected(v.send(v.intent(1,Action::Post,false,1_500,usd(90_000),[0;32])),TierReject::Bounds);
 rejected(v.send(v.intent(1,Action::Post,false,1_000,usd(90_000)+1,[0;32])),TierReject::Bounds);
 rejected(v.send(v.intent(2,Action::Take,true,1_000,usd(90_000),[0;32])),TierReject::NoLiquidity);
 let ask=v.post(1,false,1_000_000,usd(90_000));
 rejected(v.send(v.intent(2,Action::Post,true,1_000,usd(90_000),[0;32])),TierReject::Bounds);
 // 0.01 BTC at 90,000 needs 900 USDT; 2 holds 100.
 rejected(v.send(v.intent(2,Action::Take,true,1_000_000,usd(90_000),[0;32])),TierReject::Capacity);
 // A limit below the best ask fills nothing.
 rejected(v.send(v.intent(2,Action::Take,true,1_000,usd(89_900),[0;32])),TierReject::NoLiquidity);
 // The maker's own order is never taken by itself.
 v.fund(1,0,1_000_000_000);
 rejected(v.send(v.intent(1,Action::Take,true,1_000,usd(90_000),[0;32])),TierReject::NoLiquidity);
 let mut i=v.intent(2,Action::Take,true,1_000,usd(90_000),[0;32]);
 i.version=7;let i=i.signed(&sk(2)).unwrap();rejected(v.send(i),TierReject::Scope);
 let mut i=v.intent(2,Action::Take,true,1_000,usd(90_000),[0;32]);
 i.pair=[9;32];let i=i.signed(&sk(2)).unwrap();rejected(v.send(i),TierReject::UnknownOrder);
 let mut i=v.intent(2,Action::Take,true,1_000,usd(90_000),[0;32]);
 i.channel=channel(3);rejected(v.send(i),TierReject::Allocation);
 // A rejected or refused intent leaves the books and wallets as they were.
 assert_eq!(v.wallet(1),(0,1_000_000,1_000_000_000,0));assert_eq!(v.wallet(2),(0,0,100_000_000,0));
 let ok=v.intent(2,Action::Take,true,100_000,usd(90_000),[0;32]);let replay=ok.clone();
 assert!(matches!(v.send(ok).unwrap(),OptionOutcome::Staged(_)));v.commit();
 rejected(v.send(replay),TierReject::Replay);
 assert_eq!(v.desk().spot().unwrap().depth(&v.pair,false)[0].0,ask);
 v.check();
 // No spot before EnableSpot on a journal without it.
 let t2=Temp::new();let mut d=open_desk(&t2.path());assert!(d.enable_option_acks().unwrap());
 let i=v.intent(1,Action::Post,false,1_000,usd(90_000),[0;32]);
 rejected(d.submit_spot(i,T0+100),TierReject::Scope);
 assert!(!d.spot_active().unwrap());
}

/// S4. Atomicity: a spot batch whose taker never signs is fence-aborted by peer and monitor
/// after the deadline. Neither leg moved; the maker's order is pulled and its lock returned
/// to free; the taker's sequence stays used. A commit without an owner signature is refused
/// even with ownerless expiry on (that covers expiry batches only).
#[test]
fn s4_unsigned_spot_batch_aborts_and_unlocks_both_sides(){
 let t=Temp::new();let mut v=Spot::new(&t.path());
 assert!(v.d.enable_ownerless_expiry().unwrap());
 v.fund(1,1_000_000,0);v.fund(2,0,1_000_000_000);v.fund(3,0,500_000_000);
 let ask=v.post(1,false,1_000_000,usd(90_000));
 let bid=v.post(3,true,500_000,usd(88_000));
 let before=(v.wallet(1),v.wallet(2),v.wallet(3));
 let mut i=v.intent(2,Action::Take,true,600_000,usd(90_000),[0;32]);
 i.expires_us+=60_000_000;let i=i.signed(&sk(2)).unwrap();let replay=i.clone();
 let b=match v.send(i).unwrap(){OptionOutcome::Staged(b)=>*b,x=>panic!("{x:?}")};
 assert_eq!(b.spot[0].maker,ask);
 rejected(v.d.resolve_option(v.acks(Disposition::Commit,false),v.now.get()),TierReject::Signature);
 rejected(v.d.resolve_option(v.acks(Disposition::FencedAbort,false),v.now.get()),TierReject::Clock);
 let late=v.d.pending_option_since().unwrap().unwrap()+ABORT_AFTER_US;
 assert!(v.d.resolve_option(v.acks(Disposition::FencedAbort,false),late).unwrap());
 v.now.set(late);
 assert!(v.d.pending_option().unwrap().is_none());
 assert_eq!(v.d.options().unwrap().unwrap().batch_count(),0,"an aborted batch is not recorded");
 // Taker: untouched. Maker: order pulled, 0.01 BTC back in free. Bystander bid: still rests.
 assert_eq!(v.wallet(2),before.1);
 assert_eq!(v.wallet(1),(1_000_000,0,0,0));
 assert_eq!(v.wallet(3),before.2);
 assert!(v.desk().spot().unwrap().depth(&v.pair,false).is_empty());
 assert_eq!(v.desk().spot().unwrap().depth(&v.pair,true)[0].0,bid);
 rejected(v.send(replay),TierReject::Replay);
 rejected(v.cancel(1,ask),TierReject::UnknownOrder);
 v.check();
 // The desk trades again after the abort.
 v.post(1,false,1_000_000,usd(90_000));
 v.take(2,true,1_000_000,usd(90_000));v.commit();
 assert_eq!(v.wallet(2),(1_000_000,0,100_000_000,0));
 v.check();
}

/// S5. Spot lives behind journaled events: a reopen replays posts, cancels, commits, an
/// abort and a staged batch to the identical desk; journals without `EnableSpot` (every
/// options journal so far) replay exactly as before, and option batch digests are unchanged
/// by the new `spot` field.
#[test]
fn s5_journal_replay(){
 let t=Temp::new();
 let (desk,pending,since,tip)={
  let mut v=Spot::new(&t.path());
  v.fund(1,2_000_000,0);v.fund(2,0,3_000_000_000);v.fund(3,0,1_000_000_000);
  let a=v.post(1,false,1_000_000,usd(90_000));v.post(1,false,500_000,usd(90_500));
  let c=v.post(3,true,200_000,usd(88_000));
  v.take(2,true,300_000,usd(90_000));v.commit();
  v.cancel(3,c).unwrap();
  v.take(2,true,200_000,usd(90_000));
  let late=v.d.pending_option_since().unwrap().unwrap()+ABORT_AFTER_US;
  assert!(v.d.resolve_option(v.acks(Disposition::FencedAbort,false),late).unwrap());v.now.set(late);
  rejected(v.cancel(1,a),TierReject::UnknownOrder);
  v.take(2,true,100_000,usd(90_500));
  v.check();
  (v.desk().clone(),v.d.pending_option().unwrap().cloned(),v.d.pending_option_since().unwrap(),v.d.tip().unwrap())
 };
 let d=DurableTieredRouter::open(&t.path(),&registry(),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 assert!(d.spot_active().unwrap());
 assert_eq!(d.options().unwrap().unwrap(),&desk);
 assert_eq!(d.pending_option().unwrap().cloned(),pending);
 assert_eq!(d.pending_option_since().unwrap(),since);
 assert!(pending.is_some());
 // An option batch serializes without a `spot` key (the venue's stored batches read back).
 let ob=OptionBatch{sequence:1,kind:OptionBatchKind::Trade{taker:[1;32]},fills:vec![],clearing:vec![],spot:vec![]};
 let j=serde_json::to_value(&ob).unwrap();assert!(j.get("spot").is_none());
 assert_eq!(serde_json::from_value::<OptionBatch>(j).unwrap(),ob);
}

/// S6. The intent digest: version, pair, side, size, price and cancel target are all bound,
/// and the tag is distinct from the option intent's.
#[test]
fn s6_spot_intent_digest_binds_every_field(){
 let t=Temp::new();let v=Spot::new(&t.path());
 let i=v.intent(1,Action::Post,true,1_000,usd(90_000),[0;32]);
 assert!(shz_dlc::bip340_verify(&pk(1),&i.id(),&i.signature).is_ok());
 let mut seen=vec![i.id()];
 let fs:[fn(&mut SpotIntent);7]=[|x:&mut SpotIntent|x.buy=false,|x:&mut SpotIntent|x.qty_sats+=1,|x:&mut SpotIntent|x.price+=1,|x:&mut SpotIntent|x.pair[0]^=1,
           |x:&mut SpotIntent|x.cancel_target[0]=1,|x:&mut SpotIntent|x.version=9,|x:&mut SpotIntent|x.action=Action::Take];
 for f in fs{
  let mut j=i.clone();f(&mut j);assert!(!seen.contains(&j.id()));seen.push(j.id());
 }
 assert_ne!(SPOT_INTENT_TAG,b"SHZ/HFT06/INTENT/V7");
}
