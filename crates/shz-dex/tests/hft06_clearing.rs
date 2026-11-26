//! Multilateral clearing of the central-counterparty netting. The `a*` tests replay the
//! audit findings of docs/SHZ_VENUE_CLEARING.md: each runs one fill sequence under margin
//! release alone (V2, asserting the defect with its exact numbers) and under multilateral
//! clearing (V3, asserting the fix). The `c*` tests cover the clearing ledger itself.
//! Synthetic funds only.
use shz_dex::{OrderSide,routing::*};
use shz_dex::routing::clearing::{BatchClearing,ClearingRow,Waterfall};
use shz_dex::routing::durable::{AckBundle,ChannelAck,Disposition,FeeRecipients,Head,Lane};
use shz_dex::routing::positions::Settlement;
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dlc::{Bip340Signature,BtcOutPoint,bip340_sign,tagged_hash};
use shz_margin::InverseContractSpec;
use std::{cell::Cell,fs,path::{Path,PathBuf},sync::atomic::{AtomicU64,Ordering}};

type Key=[u8;32];
const T0:u64=1_000_000;
const AUTH:[u8;32]=[77;32];
const CAP:u64=100_000_000;
const N:u8=4;
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
const X1:u32=10_000;const X100:u32=1_000_000;
const V2:Option<u64>=None;
fn sk(n:u8)->Key{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[pk(50),pk(51)]}}
fn registry(cap:u64)->Registry{
 let p=policy();
 let plans=(1..=N).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),cap,vec![Share{router:1,sats:cap}]).unwrap()).collect();
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

static COUNTER:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp{
 fn new()->Self{
  let p=std::env::temp_dir().join(format!("shz-clearing-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
 fn path(&self)->PathBuf{self.0.join("router.wal")}
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

struct Venue{d:DurableTieredRouter,round:u64,seq:Cell<u64>}
impl Venue{
 /// Margin release always; `fund` switches multilateral clearing on with that fund.
 fn new(path:&Path,fund:Option<u64>)->Self{Self::with_cap(path,fund,CAP)}
 fn with_cap(path:&Path,fund:Option<u64>,cap:u64)->Self{
  let mut d=DurableTieredRouter::create(path,&registry(cap),cfg(),lanes(),recipients()).unwrap();
  assert!(d.enable_margin_release().unwrap());
  if let Some(f)=fund{assert!(d.enable_clearing(f).unwrap());assert!(!d.enable_clearing(f).unwrap());}
  Self{d,round:0,seq:Cell::new(0)}
 }
 #[allow(clippy::too_many_arguments)]
 fn intent(&self,n:u8,action:Action,side:OrderSide,q:u64,price:u64,lev:u32,now:u64)->IntentV6{
  let c=cfg();self.seq.set(self.seq.get()+1);
  IntentV6{scope:c.scope,router:1,channel:channel(n),owner:[0;32],sequence:self.seq.get(),expires_us:now+5_000_000,action,side,tier:FeedTier::Standard,
   tariff_version:c.tariff.version,entitlement_digest:[0;32],execution_policy:c.execution.id(),
   quantity:q,limit_usd:price,leverage_bps:lev,max_fee_ppm:c.tariff.rate_ppm(FeedTier::Standard,action),max_fee_sats:100_000,
   max_mark_age_us:1_000_000,early_window_opt_in:false,cancel_target:[0;32],signature:ZERO_SIG}.signed(&sk(n)).unwrap()
 }
 /// Post and take without sealing; returns the take's outcome.
 fn attempt(&mut self,maker:u8,taker:u8,taker_side:OrderSide,q:u64,price:u64,lev:(u32,u32))->TierOutcome{
  self.round+=1;
  let t=T0+self.round*1_000_000;let now=t+200_000;
  self.d.ingest_mark(MarkView{packet_digest:tagged_hash(b"test/mark",&self.round.to_le_bytes()),seq:self.round,price_e8:Some(price*100_000_000),boundary_us:t,public_release_us:t},t).unwrap();
  let maker_side=if taker_side==OrderSide::Long{OrderSide::Short}else{OrderSide::Long};
  self.d.submit(self.intent(maker,Action::Post,maker_side,q,price,lev.0,now),None,now).unwrap();
  assert!(matches!(self.d.process_one(now).unwrap().unwrap(),TierOutcome::Posted(_)));
  self.d.submit(self.intent(taker,Action::Take,taker_side,q,price,lev.1,now),None,now).unwrap();
  self.d.process_one(now).unwrap().unwrap()
 }
 fn seal(&mut self,maker:u8,taker:u8,taker_side:OrderSide,q:u64,price:u64,lev:(u32,u32))->Batch{
  let out=self.attempt(maker,taker,taker_side,q,price,lev);
  assert!(matches!(out,TierOutcome::Filled(_)),"{out:?}");
  self.d.process_one(T0+self.round*1_000_000+500_000).unwrap();
  let b=self.d.seal_batch().unwrap().expect("window elapsed");
  self.d.prepare(b.sequence(),approvals(&b)).unwrap();
  b
 }
 /// `maker` rests a quote, `taker` takes `q` USD on `taker_side` at `price`; the window is
 /// sealed, approved, acknowledged by every lane and committed. Checks the invariants.
 fn trade(&mut self,maker:u8,taker:u8,taker_side:OrderSide,q:u64,price:u64,lev:(u32,u32)){
  let b=self.seal(maker,taker,taker_side,q,price,lev);
  let before:Vec<i64>=(1..=N).map(|n|self.bal(n).realized_pnl).collect();
  assert!(self.d.resolve(ack(&self.d,&b)).unwrap());
  if let Some(c)=self.d.clearing(b.sequence()).unwrap(){
   // The net settlement vector sums to zero with the pool's line, and each row is
   // exactly the account's realized cash movement.
   assert_eq!(c.rows.iter().map(|r|r.net).sum::<i64>()+c.pool_net(),0,"{c:?}");
   for r in &c.rows{let n=r.channel.txid[0];assert_eq!(self.bal(n).realized_pnl-before[n as usize-1],r.net,"{c:?}");}
  }
  self.check();
 }
 fn bal(&self,n:u8)->Balance{self.d.balance(&channel(n)).unwrap().unwrap()}
 fn net(&self,n:u8)->i64{self.d.position(&channel(n)).unwrap().unwrap().net_usd()}
 fn total_realized(&self)->i64{(1..=N).map(|n|self.bal(n).realized_pnl).sum()}
 fn flat(&self)->bool{(1..=N).all(|n|self.net(n)==0)}
 fn claim(&self,n:u8)->u64{self.d.clearing_state().unwrap().unwrap().claim(&channel(n))}
 fn last(&self)->&BatchClearing{self.d.clearing(self.d.next_resolution().unwrap()-1).unwrap().unwrap()}
 fn check(&self){
  for n in 1..=N{
   let b=self.bal(n);let p=self.d.position(&channel(n)).unwrap().unwrap();
   assert!(b.conserved(),"{n}: {b:?}");assert_eq!(b.committed,p.margin());assert_eq!(b.pending,0);
  }
  if let Some(s)=self.d.clearing_summary().unwrap(){
   assert_eq!(s.identity,0,"{s:?}");
   assert!(s.cash>=0,"pool paid cash it did not hold: {s:?}");
   // Every sat an account realized came out of (or went into) the pool.
   assert_eq!(self.total_realized() as i128+s.cash as i128,s.fund0 as i128,"{s:?}");
   if self.flat(){assert_eq!((s.carry,s.cash as i128),(0,(s.claims+s.fund) as i128),"flat book: pool holds every claim plus the fund: {s:?}");}
  }
 }
 /// Close every open position at `price` by trading longs against shorts.
 fn flatten(&mut self,price:u64){
  while let (Some(l),Some(s))=((1..=N).find(|&n|self.net(n)>0),(1..=N).find(|&n|self.net(n)<0)){
   let q=self.net(l).min(-self.net(s)) as u64;
   self.trade(s,l,OrderSide::Short,q,price,(X1,X1));
  }
  assert!(self.flat());
 }
}
fn approvals(b:&Batch)->Vec<BatchApproval>{
 b.accounts().iter().map(|a|{
  let n=a.channel.txid[0];let h=b.approval_message(&a.channel).unwrap();
  BatchApproval{channel:a.channel.clone(),signature:bip340_sign(&sk(n),&h).unwrap()}
 }).collect()
}
fn lane_ack(d:&DurableTieredRouter,b:&Batch,a:&ChannelObligation)->ChannelAck{
 let n=a.channel.txid[0];
 let previous=d.head(&a.channel).unwrap().unwrap();let mut next=previous;next.revision+=1;next.commitment+=1;
 next.state=tagged_hash(b"test/state",&[&[n][..],&b.sequence().to_le_bytes()].concat());
 ChannelAck{channel:a.channel.clone(),previous,next,evidence:tagged_hash(b"test/evidence",&[&[n][..],&b.sequence().to_le_bytes()].concat()),fee_evidence:[0;32],signatures:[ZERO;3]}
}
fn sign_all(n:u8,h:&Key,c:&mut ChannelAck){
 c.signatures=[bip340_sign(&sk(n),h).unwrap(),bip340_sign(&sk(70+n),h).unwrap(),bip340_sign(&sk(90+n),h).unwrap()];
}
fn ack(d:&DurableTieredRouter,b:&Batch)->AckBundle{
 let mut channels=Vec::new();
 for a in b.accounts(){
  let mut c=lane_ack(d,b,a);
  let h=d.ack_message(b.sequence(),Disposition::Commit,&c).unwrap();sign_all(a.channel.txid[0],&h,&mut c);channels.push(c);
 }
 AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:Disposition::Commit,channels}
}
fn margin(q:u64,price:u64,lev:u32)->u64{InverseContractSpec::margin_for_leverage_bps(q,price,lev).unwrap()}
fn value(q:u64,price:u64)->i64{(q as u128*100_000_000/price as u128) as i64}

/// A1. A thin long (1, 100x) is closed past its bankruptcy price against 3; the lot's loss
/// clamps at its margin. The price recovers and the original counterparty 2 (short) closes
/// against 3 at the entry price. V2 pays 3's gain in full while 2 pays nothing: the
/// accounts end with more sats than were deposited.
fn a1(v:&mut Venue){
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X100));   // 1 long 100x vs 2 short 1x
 v.trade(3,1,OrderSide::Short,1000,98_000,(X1,X1));     // 1 sells to 3 past bankruptcy
 v.trade(3,2,OrderSide::Long,1000,100_000,(X1,X1));     // 2 buys back from 3 at entry
 assert!(v.flat());
}
#[test]
fn a1_recovery_after_a_clamped_close_pays_an_unfunded_gain(){
 let thin=margin(1000,100_000,X100) as i64;
 let loss=value(1000,98_000)-value(1000,100_000); // 20,408: 1's unclamped loss
 let t=Temp::new();let mut v=Venue::new(&t.path(),V2);a1(&mut v);
 assert_eq!((v.bal(1).realized_pnl,v.bal(2).realized_pnl,v.bal(3).realized_pnl),(-thin,0,loss));
 assert_eq!(v.total_realized(),loss-thin); // V2: insolvent by 10,408 sats
 // V3, no fund: 1's shortfall is carried and haircuts 3's gain to what 1 paid.
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(0));
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X100));
 v.trade(3,1,OrderSide::Short,1000,98_000,(X1,X1));
 let c=v.last();
 assert_eq!((c.shortfall,c.fund_absorbed,c.carry_after,c.layer),((loss-thin) as u64,0,(loss-thin) as u64,Waterfall::Carried));
 v.trade(3,2,OrderSide::Long,1000,100_000,(X1,X1));
 let c=v.last();
 assert_eq!((c.haircut,c.carry_after,c.layer),((loss-thin) as u64,0,Waterfall::Haircut));
 assert_eq!((v.bal(1).realized_pnl,v.bal(2).realized_pnl,v.bal(3).realized_pnl),(-thin,0,thin));
 assert_eq!(v.total_realized(),0);
 // V3 with a fund: the fund absorbs the shortfall and 3 is paid in full.
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(50_000));a1(&mut v);
 assert_eq!(v.bal(3).realized_pnl,loss);
 let s=v.d.clearing_summary().unwrap().unwrap();
 assert_eq!((s.fund,s.cash,s.claims),(50_000-(loss-thin) as u64,50_000-(loss-thin),0));
}

/// A2. A thin short (2, 100x) is closed past its bankruptcy price; the long it faced (1)
/// keeps a lot whose V2 gain is capped at 2's margin. The price keeps rising and 1 closes
/// against 3, whose loss is collected in full but only 2's old margin reaches 1.
fn a2(v:&mut Venue){
 v.trade(1,2,OrderSide::Short,1000,100_000,(X1,X100));  // 2 short 100x vs 1 long 1x
 v.trade(3,2,OrderSide::Long,1000,102_000,(X1,X1));     // 2 buys from 3 past bankruptcy
 v.trade(3,1,OrderSide::Short,1000,104_000,(X1,X1));    // 1 sells to 3 (3 closes its short)
 assert!(v.flat());
}
#[test]
fn a2_a_gain_capped_at_a_stale_counterparty_margin_strands_sats(){
 let thin=margin(1000,100_000,X100) as i64;
 let c_loss=value(1000,102_000)-value(1000,104_000); // 18,854 collected from 3
 let t=Temp::new();let mut v=Venue::new(&t.path(),V2);a2(&mut v);
 assert_eq!((v.bal(1).realized_pnl,v.bal(3).realized_pnl),(thin,-c_loss));
 assert_eq!(v.total_realized(),-c_loss); // V2: 18,854 sats reach no winner
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(0));a2(&mut v);
 // V3: 1 receives every collected loss: 2's margin plus 3's loss.
 assert_eq!((v.bal(1).realized_pnl,v.bal(2).realized_pnl,v.bal(3).realized_pnl),(thin+c_loss,-thin,-c_loss));
 assert_eq!(v.total_realized(),0);
}

/// A3. After a novated close, the new lot's `opp_margin` names collateral that is no
/// longer committed anywhere: the closing leg's margin went back to the closer's free
/// balance. V3 settles on exact entry values instead, and the pool's books show the
/// claim against the open book.
#[test]
fn a3_a_novated_lot_is_backed_by_released_margin(){
 for fund in [V2,Some(0)]{
  let t=Temp::new();let mut v=Venue::new(&t.path(),fund);
  v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
  v.trade(3,1,OrderSide::Short,1000,101_000,(X1,X100));  // 1 closes against 3 with a 100x leg
  let lots:Vec<_>=(1..=N).flat_map(|n|v.d.position(&channel(n)).unwrap().unwrap().lots().copied().collect::<Vec<_>>()).collect();
  let backing:u64=lots.iter().filter(|l|l.side==OrderSide::Long).map(|l|l.opp_margin).sum();
  let short_committed:u64=(1..=N).filter(|&n|v.net(n)<0).map(|n|v.bal(n).committed).sum();
  assert_eq!((backing,short_committed),(margin(1000,101_000,X100),margin(1000,100_000,X1)));
  if fund.is_some(){
   // 1's gain is a deferred claim (the pool holds nothing yet), and the open book's
   // signed entry value is exactly what the pool owes against it.
   let s=v.d.clearing_summary().unwrap().unwrap();
   let gain=(value(1000,100_000)-value(1000,101_000)) as u64;
   assert_eq!((v.claim(1),s.claims,s.cash,s.book),(gain,gain,0,-(gain as i128)));
  }
 }
}

struct Rng(u64);
impl Rng{
 fn next(&mut self)->u64{self.0^=self.0<<13;self.0^=self.0>>7;self.0^=self.0<<17;self.0}
 fn below(&mut self,n:u64)->u64{self.next()%n}
}
/// One seeded random sequence: price walk with jumps, mixed leverage, partial closes and
/// flips (`clamps`), or 1x legs and small moves only. Returns the running sum of realized PnL.
fn random_sequence(v:&mut Venue,seed:u64,steps:usize,clamps:bool)->Vec<i64>{
 let mut r=Rng(seed);let mut price=100_000u64;let mut totals=Vec::new();
 const LEV:[u32;5]=[X1,20_000,100_000,500_000,X100];
 for _ in 0..steps{
  price=if !clamps{price+r.below(41)-20}else{match r.below(10){0=>price*(1000+r.below(60))/1000,1=>price*(1000-r.below(60))/1000,_=>price+r.below(400)-200}}.clamp(50_000,200_000);
  let maker=1+r.below(N as u64) as u8;let mut taker=1+r.below(N as u64) as u8;if taker==maker{taker=1+taker%N}
  let side=if r.below(2)==0{OrderSide::Long}else{OrderSide::Short};
  let q=1+r.below(1500);
  let lev=if clamps{(LEV[r.below(5) as usize],LEV[r.below(5) as usize])}else{(X1,X1)};
  v.trade(maker,taker,side,q,price,lev);
  totals.push(v.total_realized());
 }
 v.flatten(price);totals.push(v.total_realized());
 totals
}

/// A4. Without any clamp (1x legs, small price moves), V2's per-slice rounding (half-even
/// payouts, floored margin splits on partial closes) leaves a residue once the book is
/// flat. V3's exact entry values leave none.
#[test]
fn a4_rounding_drift_without_clamps(){
 let run=|fund:Option<u64>|->Vec<i64>{(1..=4u64).map(|seed|{
  let t=Temp::new();let mut v=Venue::new(&t.path(),fund);
  *random_sequence(&mut v,seed.wrapping_mul(0xD1B5_4A32_D192_ED03),40,false).last().unwrap()
 }).collect()};
 assert_eq!(run(V2),vec![1,0,-2,-3]);
 // V3, no fund and no shortfall: on a flat book every gain has been paid from the
 // matching collected loss, to the sat.
 assert_eq!(run(Some(0)),vec![0;4]);
}

/// A5. Seeded random sequences with clamps: V2 breaks conservation in every one of them.
/// Under V3 every batch's invariants hold (checked in `Venue::trade`), the pool never goes
/// negative, and on the flat book the pool holds exactly the deferred claims plus the
/// unused fund.
#[test]
fn a5_random_sequences(){
 let seeds=|i:u64|i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
 let mut v2=Vec::new();
 for i in 1..=6u64{
  let t=Temp::new();let mut v=Venue::new(&t.path(),V2);
  let totals=random_sequence(&mut v,seeds(i),40,true);
  v2.push((*totals.iter().max().unwrap(),*totals.last().unwrap()));
 }
 assert_eq!(v2,vec![(120028,120028),(38797,13595),(14705,-35585),(130002,130002),(13736,-7592),(198804,-7672)]);
 let mut layers=std::collections::BTreeMap::new();let mut deferred=0;
 for fund in [0,30_000,10_000_000]{
  for i in 1..=6u64{
   let t=Temp::new();let mut v=Venue::new(&t.path(),Some(fund));
   let totals=random_sequence(&mut v,seeds(i),40,true);
   for q in 1..v.d.next_resolution().unwrap(){
    let c=v.d.clearing(q).unwrap().unwrap();
    *layers.entry((fund,c.layer)).or_insert(0)+=1;
    deferred+=c.rows.iter().filter(|r|r.claim_after>r.claim_before).count();
   }
   assert!(totals.iter().all(|&x|x<=fund as i64),"accounts never hold more than deposits plus the fund");
   let s=v.d.clearing_summary().unwrap().unwrap();
   assert_eq!(s.carry,0);assert_eq!(s.cash as u64,s.claims+s.fund);
   assert_eq!(*totals.last().unwrap()+s.claims as i64,(fund-s.fund) as i64,"winners are owed exactly what losers paid plus the fund used");
  }
 }
 // The sequences reach every layer of the waterfall and defer claims.
 println!("A5 V3 layers {layers:?}, deferred rows {deferred}");
 for l in [Waterfall::Haircut,Waterfall::Carried]{assert!(layers.contains_key(&(0,l)),"{l:?}");}
 assert!(layers.contains_key(&(30_000,Waterfall::Fund))&&layers.contains_key(&(10_000_000,Waterfall::Fund)));
 assert!(deferred>0);
}

/// C1. A gain realized before its loser closes is a deferred claim when the pool is empty,
/// and is paid the next time the account is in a batch after the loss is collected. With
/// a fund the pool pays it at once.
#[test]
fn c1_deferred_claims_are_paid_once_funded(){
 let gain=(value(1000,100_000)-value(1000,101_000)) as u64;
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(0));
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 v.trade(3,1,OrderSide::Short,1000,101_000,(X1,X1));    // 1 closes at a gain vs 3
 let r=v.last().rows.iter().find(|r|r.channel==channel(1)).unwrap().clone();
 assert_eq!((r.pnl,r.paid,r.claim_after,r.net),(gain as i64,0,gain,0));
 assert_eq!(v.bal(1).realized_pnl,0);
 v.trade(3,2,OrderSide::Long,1000,101_000,(X1,X1));     // 2 closes vs 3: loss collected
 assert_eq!((v.claim(1),v.d.clearing_summary().unwrap().unwrap().cash),(gain,gain as i64));
 v.trade(4,1,OrderSide::Long,1,101_000,(X1,X1));        // 1 is in a batch again: paid
 assert_eq!((v.claim(1),v.bal(1).realized_pnl),(0,gain as i64));
 // With a fund the gain is paid when it is realized.
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(1_000_000));
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 v.trade(3,1,OrderSide::Short,1000,101_000,(X1,X1));
 assert_eq!((v.claim(1),v.bal(1).realized_pnl),(0,gain as i64));
}

/// C2. A shortfall in a batch account 1 is not part of haircuts 1's deferred claim; the
/// haircut is reported for 1 and the rest is carried to the next gains.
#[test]
fn c2_shortfalls_haircut_deferred_claims_of_other_accounts(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(0));
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 v.trade(3,1,OrderSide::Short,1000,101_000,(X1,X1));    // 1: deferred claim
 let claim=v.claim(1);
 v.trade(2,4,OrderSide::Long,1000,101_000,(X1,X100));   // 4 long 100x vs 2
 v.trade(3,4,OrderSide::Short,1000,99_000,(X1,X1));     // 4 sold past bankruptcy
 let loss=(value(1000,99_000)-value(1000,101_000)) as u64;let thin=margin(1000,101_000,X100);
 let c=v.last().clone();
 assert_eq!(c.shortfall,loss-thin);
 assert_eq!(c.claim_haircuts,vec![(channel(1),claim)]);
 assert_eq!((c.haircut,c.carry_after,c.layer),(claim,loss-thin-claim,Waterfall::Carried));
 assert_eq!(v.claim(1),0);
 v.flatten(100_000);
}

/// C3. V3 acknowledgements bind the lane's settlement, its clearing row and the digest of
/// the whole net settlement vector; a V2 acknowledgement does not resolve.
#[test]
fn c3_acknowledgements_bind_the_clearing(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(5_000));
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 let b=v.seal(3,1,OrderSide::Short,400,100_900,(X1,X1));
 let cfg_hash=v.d.config_hash();
 let mut stale=Vec::new();
 for a in b.accounts(){
  let mut c=lane_ack(&v.d,&b,a);
  let h=message(TIERED_ACK_TAG_V2,&cfg_hash,&b,&c,None);sign_all(a.channel.txid[0],&h,&mut c);stale.push(c);
 }
 assert!(v.d.resolve(AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:Disposition::Commit,channels:stale}).is_err());
 let bundle=ack(&v.d,&b);
 assert!(v.d.resolve(bundle.clone()).unwrap());
 let c=v.d.clearing(b.sequence()).unwrap().unwrap().clone();
 let rows=v.d.settlements(b.sequence()).unwrap();
 assert_eq!(c.digest(),digest(&c));
 for (a,(ch,s)) in bundle.channels.iter().zip(rows){
  assert_eq!(a.channel,*ch);
  let h=message(TIERED_ACK_TAG_V3,&cfg_hash,&b,a,Some((s,c.rows.iter().find(|r|r.channel==a.channel).unwrap(),&c)));
  shz_dlc::bip340_verify(&pk(a.channel.txid[0]),&h,&a.signatures[0]).unwrap();
 }
 v.check();
}

/// Independent reconstruction of the acknowledgement digest.
fn message(tag:&[u8],config:&Key,b:&Batch,a:&ChannelAck,s:Option<(&Settlement,&ClearingRow,&BatchClearing)>)->Key{
 let put=|v:&mut Vec<u8>,n:u64|v.extend(n.to_le_bytes());
 let head=|v:&mut Vec<u8>,h:&Head|{v.extend(h.revision.to_le_bytes());v.extend(h.commitment.to_le_bytes());v.extend(h.state)};
 let o=b.accounts().iter().find(|o|o.channel==a.channel).unwrap();
 let mut v=Vec::new();v.extend(config);v.extend(b.digest());put(&mut v,b.sequence());v.push(1);
 v.extend(a.channel.txid);v.extend(a.channel.vout.to_le_bytes());v.extend(o.owner);put(&mut v,o.margin_sats);put(&mut v,o.fee_sats);
 head(&mut v,&a.previous);head(&mut v,&a.next);v.extend(a.evidence);v.extend(a.fee_evidence);
 v.extend(recipients().oracle);v.extend(recipients().router);
 v.extend(b.oracle_due_sats().to_le_bytes());v.extend(b.router_due_sats().to_le_bytes());
 if let Some((s,r,c))=s{
  v.push(1);
  for n in [s.opened_margin,s.closed_leg_margin,s.released_margin,s.payout,s.closed_usd]{put(&mut v,n)}
  v.extend(s.net_before.to_le_bytes());v.extend(s.net_after.to_le_bytes());put(&mut v,s.margin_after);
  v.push(2);row(&mut v,r);v.extend(digest(c));
 }
 tagged_hash(tag,&v)
}
fn row(v:&mut Vec<u8>,r:&ClearingRow){
 v.extend(r.channel.txid);v.extend(r.channel.vout.to_le_bytes());v.extend(r.pnl.to_le_bytes());
 for n in [r.released,r.collected,r.own_claim_used,r.shortfall,r.haircut,r.claim_before,r.claim_after,r.paid]{v.extend(n.to_le_bytes())}
 v.extend(r.net.to_le_bytes());
}
fn digest(c:&BatchClearing)->Key{
 let mut v=Vec::new();v.extend((c.rows.len() as u64).to_le_bytes());
 for r in &c.rows{row(&mut v,r)}
 v.extend((c.claim_haircuts.len() as u64).to_le_bytes());
 for (ch,h) in &c.claim_haircuts{v.extend(ch.txid);v.extend(ch.vout.to_le_bytes());v.extend(h.to_le_bytes())}
 for n in [c.shortfall,c.fund_absorbed,c.haircut]{v.extend(n.to_le_bytes())}
 v.push(c.layer as u8);v.extend(c.cash_before.to_le_bytes());v.extend(c.cash_after.to_le_bytes());
 for n in [c.fund_after,c.carry_after,c.claims_after]{v.extend(n.to_le_bytes())}
 tagged_hash(b"SHZ/HFT/CLEARING/V1",&v)
}

/// C4. Switching clearing on in a live journal: the V2 history (here the stranded sats of
/// A2) is folded into the ledger as `legacy`, the clearing identity holds from the first
/// V3 batch, and reopening the journal replays every V2 and V3 batch to the same state.
#[test]
fn c4_enabling_on_a_live_journal_folds_v2_history_and_replays(){
 let t=Temp::new();let path=t.path();
 let mut v=Venue::new(&path,V2);
 a2(&mut v);
 v.trade(2,1,OrderSide::Long,700,103_000,(X1,X1));
 let stranded=-v.total_realized();
 // A batch prepared under V2 commits under V3.
 let open=v.seal(4,3,OrderSide::Long,200,103_500,(X1,X1));
 assert!(v.d.enable_clearing(1_000).unwrap());
 let s=v.d.clearing_summary().unwrap().unwrap();
 assert_eq!((s.cash,s.legacy,s.identity),(1_000+stranded,stranded,0));
 assert!(v.d.resolve(ack(&v.d,&open)).unwrap());
 assert!(v.d.clearing(open.sequence()).unwrap().is_some());
 v.check();
 v.trade(1,3,OrderSide::Short,500,101_000,(X1,X1));
 v.flatten(102_000);
 let snap=|d:&DurableTieredRouter|{
  let mut x:Vec<String>=(1..=N).map(|n|format!("{:?}|{:?}|{:?}",d.balance(&channel(n)).unwrap(),d.position(&channel(n)).unwrap(),d.head(&channel(n)).unwrap())).collect();
  x.push(format!("{:?}",d.clearing_state().unwrap()));
  for q in 1..d.next_resolution().unwrap(){x.push(format!("{:?}|{:?}",d.settlements(q).unwrap(),d.clearing(q).unwrap()));}
  x
 };
 let before=snap(&v.d);let tip=v.d.tip().unwrap();
 drop(v);
 let d=DurableTieredRouter::open(&path,&registry(CAP),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 assert!(d.clearing_active().unwrap());
 assert_eq!(snap(&d),before);
}

/// C5. Clearing needs margin release; fenced aborts move nothing through the ledger.
#[test]
fn c5_clearing_requires_release_and_ignores_aborts(){
 let t=Temp::new();
 let mut d=DurableTieredRouter::create(&t.path(),&registry(CAP),cfg(),lanes(),recipients()).unwrap();
 assert!(d.enable_clearing(0).is_err());
 let t=Temp::new();let mut v=Venue::new(&t.path(),Some(0));
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 let b=v.seal(3,1,OrderSide::Short,1000,101_000,(X1,X1));
 let mut channels=Vec::new();
 for a in b.accounts(){
  let mut c=lane_ack(&v.d,&b,a);c.next.commitment-=1;c.next.state=c.previous.state;
  let h=v.d.ack_message(b.sequence(),Disposition::FencedAbort,&c).unwrap();sign_all(a.channel.txid[0],&h,&mut c);channels.push(c);
 }
 let before=v.d.clearing_state().unwrap().cloned();
 assert!(v.d.resolve(AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:Disposition::FencedAbort,channels}).unwrap());
 assert!(v.d.clearing(b.sequence()).unwrap().is_none());
 assert_eq!(v.d.clearing_state().unwrap().cloned(),before);
 v.check();
}

/// P1. Liquidation close with no free margin: a 1x long that committed its whole balance
/// takes an equal short. The closing leg borrows its margin from the lot it closes, the
/// batch commits, the account is flat and receives the lot's payout. Without clearing the
/// same take is refused for capacity (V2 behavior, unchanged for old journals).
#[test]
fn p1_a_reducing_leg_needs_no_free_margin(){
 let m=margin(1000,100_000,X1);
 let t=Temp::new();let mut v=Venue::with_cap(&t.path(),V2,m);
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 assert_eq!(v.bal(1).free,0);
 assert!(matches!(v.attempt(3,1,OrderSide::Short,1000,101_000,(X1,X1)),TierOutcome::Rejected(TierReject::Capacity)));
 let t=Temp::new();let mut v=Venue::with_cap(&t.path(),Some(10_000_000),m);
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 assert_eq!((v.bal(1).free,v.bal(1).committed),(0,m));
 let b=v.seal(3,1,OrderSide::Short,1000,101_000,(X1,X1));
 // Between match and commit the leg's margin is lent out of committed.
 let leg=margin(1000,101_000,X1);
 assert_eq!((v.bal(1).free,v.bal(1).committed,v.bal(1).pending),(0,m-leg,leg));
 assert!(v.d.resolve(ack(&v.d,&b)).unwrap());v.check();
 let gain=value(1000,100_000)-value(1000,101_000);
 assert_eq!((v.net(1),v.bal(1).committed,v.bal(1).realized_pnl,v.bal(1).free as i64),(0,0,gain,m as i64+gain));
 // A loser with no free margin closes too: two lots (100x and 1x) closed in one take at
 // a price below the 100x lot's bankruptcy; the 1x lot's released margin covers both.
 let thin=margin(1000,100_000,X100);
 let t=Temp::new();let mut v=Venue::with_cap(&t.path(),Some(0),m+thin);
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X100));
 v.trade(3,1,OrderSide::Long,1000,100_000,(20_000,X1));
 assert_eq!(v.bal(1).free,0);
 v.trade(4,1,OrderSide::Short,2000,98_000,(30_000,X100));
 let loss=2*(value(1000,98_000)-value(1000,100_000));
 assert_eq!((v.net(1),v.bal(1).committed,v.bal(1).realized_pnl,v.bal(1).free as i64),(0,0,-loss,(m+thin) as i64-loss));
 assert_eq!(v.last().shortfall,0);
}

/// P2. A flip needs fresh margin only for the excess over the lots it closes.
#[test]
fn p2_a_flip_needs_margin_for_the_excess_only(){
 let excess=margin(500,100_000,X1);
 for (cap,ok) in [(margin(1000,100_000,X1)+excess,true),(margin(1000,100_000,X1)+excess-1,false)]{
  let t=Temp::new();let mut v=Venue::with_cap(&t.path(),Some(0),cap);
  v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
  assert_eq!(v.bal(1).free,cap-margin(1000,100_000,X1));
  if ok{
   v.trade(3,1,OrderSide::Short,1500,100_000,(20_000,X1));
   assert_eq!((v.net(1),v.bal(1).committed,v.bal(1).free),(-500,excess,cap-excess));
  }else{
   assert!(matches!(v.attempt(3,1,OrderSide::Short,1500,100_000,(20_000,X1)),TierOutcome::Rejected(TierReject::Capacity)));
  }
 }
}

/// P3. A fenced abort of a closing leg returns its loan to committed; the lot is intact.
/// Unresolved legs count against the lots, so a second close of the same lots in a later
/// window before the first resolves borrows nothing.
#[test]
fn p3_aborted_or_repeated_closes_do_not_double_borrow(){
 let m=margin(1000,100_000,X1);
 let t=Temp::new();let mut v=Venue::with_cap(&t.path(),Some(10_000_000),2*m);
 v.trade(2,1,OrderSide::Long,1000,100_000,(X1,X1));
 let b=v.seal(3,1,OrderSide::Short,1000,100_500,(X1,X1));
 let leg=margin(1000,100_500,X1);
 assert_eq!((v.bal(1).free,v.bal(1).committed),(m,m-leg));
 // Second close of the same lots while the first is unresolved: paid from free.
 assert!(matches!(v.attempt(4,1,OrderSide::Short,1000,100_400,(X1,X1)),TierOutcome::Filled(_)));
 assert_eq!((v.bal(1).free,v.bal(1).committed),(m-margin(1000,100_400,X1),m-leg));
 let mut channels=Vec::new();
 for a in b.accounts(){
  let mut c=lane_ack(&v.d,&b,a);c.next.commitment-=1;c.next.state=c.previous.state;
  let h=v.d.ack_message(b.sequence(),Disposition::FencedAbort,&c).unwrap();sign_all(a.channel.txid[0],&h,&mut c);channels.push(c);
 }
 assert!(v.d.resolve(AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:Disposition::FencedAbort,channels}).unwrap());
 assert_eq!((v.net(1),v.bal(1).committed),(1000,m));
 // The second close commits normally and flattens the account.
 v.d.process_one(T0+v.round*1_000_000+500_000).unwrap();
 let b2=v.d.seal_batch().unwrap().unwrap();v.d.prepare(b2.sequence(),approvals(&b2)).unwrap();
 assert!(v.d.resolve(ack(&v.d,&b2)).unwrap());
 assert_eq!((v.net(1),v.bal(1).committed),(0,0));
 v.check();
}
