//! Margin release on the durable tiered router: positions net in committed batches,
//! the offset quantity's margin leaves `committed`, and PnL is realized exactly as the
//! inverse contract spec pays the closed lots. Synthetic funds only.
use shz_dex::{OrderSide,routing::*};
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
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
fn sk(n:u8)->Key{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[pk(50),pk(51)]}}
fn registry(cap:u64)->Registry{
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),cap,vec![Share{router:1,sats:cap}]).unwrap()).collect();
 Registry::new(p.scope(),public(&AUTH),plans).unwrap()
}
fn cfg()->TieredConfig{
 TieredConfig{scope:policy().scope(),router:1,entitlement_key:pk(60),tariff:TariffSchedule::default_candidate(),
  execution:ExecutionPolicy::defaults(Arm::FeedOnly),revenue:RevenuePolicy::default()}
}
fn lanes()->Vec<Lane>{
 (1..=4u8).map(|n|Lane{channel:channel(n),peer:pk(70+n),monitor:pk(90+n),initial:Head{revision:0,commitment:10,state:[110+n;32]}}).collect()
}
fn recipients()->FeeRecipients{FeeRecipients{oracle:pk(110),router:pk(111)}}

static COUNTER:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp{
 fn new()->Self{
  let p=std::env::temp_dir().join(format!("shz-margin-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
 fn path(&self)->PathBuf{self.0.join("router.wal")}
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

struct Venue{d:DurableTieredRouter,round:u64,seq:Cell<u64>,cap:u64}
impl Venue{
 fn new(path:&Path,cap:u64,release:bool)->Self{
  let mut d=DurableTieredRouter::create(path,&registry(cap),cfg(),lanes(),recipients()).unwrap();
  if release{assert!(d.enable_margin_release().unwrap());assert!(!d.enable_margin_release().unwrap());}
  Self{d,round:0,seq:Cell::new(0),cap}
 }
 #[allow(clippy::too_many_arguments)]
 fn intent(&self,n:u8,action:Action,side:OrderSide,tier:FeedTier,q:u64,price:u64,lev:u32,now:u64)->IntentV6{
  let c=cfg();self.seq.set(self.seq.get()+1);
  IntentV6{scope:c.scope,router:1,channel:channel(n),owner:[0;32],sequence:self.seq.get(),expires_us:now+5_000_000,action,side,tier,
   tariff_version:c.tariff.version,entitlement_digest:if tier==FeedTier::Standard{[0;32]}else{grant(n,tier).digest()},execution_policy:c.execution.id(),
   quantity:q,limit_usd:price,leverage_bps:lev,max_fee_ppm:c.tariff.rate_ppm(tier,action),max_fee_sats:100_000,
   max_mark_age_us:1_000_000,early_window_opt_in:false,cancel_target:[0;32],signature:ZERO_SIG}.signed(&sk(n)).unwrap()
 }
 /// `maker` rests a quote, `taker` takes `q` USD on `taker_side` at `price`, all in one
 /// 100 ms window that is sealed afterwards. Returns the sealed batch.
 #[allow(clippy::too_many_arguments)]
 fn trade(&mut self,maker:u8,taker:u8,taker_side:OrderSide,q:u64,price:u64,lev:(u32,u32),tier:FeedTier)->Batch{
  self.round+=1;
  let t=T0+self.round*1_000_000;let now=t+200_000;
  self.d.ingest_mark(MarkView{packet_digest:[self.round as u8;32],seq:self.round,price_e8:Some(price*100_000_000),boundary_us:t,public_release_us:t},t).unwrap();
  let maker_side=if taker_side==OrderSide::Long{OrderSide::Short}else{OrderSide::Long};
  let ent=|n:u8|(tier!=FeedTier::Standard).then(||grant(n,tier));
  self.d.submit(self.intent(maker,Action::Post,maker_side,tier,q,price,lev.0,now),ent(maker),now).unwrap();
  assert!(matches!(self.d.process_one(now).unwrap().unwrap(),TierOutcome::Posted(_)));
  self.d.submit(self.intent(taker,Action::Take,taker_side,tier,q,price,lev.1,now),ent(taker),now).unwrap();
  let out=self.d.process_one(now).unwrap().unwrap();
  assert!(matches!(out,TierOutcome::Filled(_)),"{out:?}");
  self.d.process_one(t+500_000).unwrap();
  self.d.seal_batch().unwrap().expect("window elapsed")
 }
 /// Approve, acknowledge (owner, peer, monitor) and commit. Returns each lane's signed digest.
 fn commit(&mut self,b:&Batch)->Vec<Key>{
  self.d.prepare(b.sequence(),approvals(b)).unwrap();
  let (bundle,digests)=ack(&self.d,b,Disposition::Commit);
  assert!(self.d.resolve(bundle).unwrap());
  digests
 }
 fn trade_commit(&mut self,maker:u8,taker:u8,taker_side:OrderSide,q:u64,price:u64)->Batch{
  let b=self.trade(maker,taker,taker_side,q,price,(10_000,10_000),FeedTier::Standard);self.commit(&b);b
 }
 fn bal(&self,n:u8)->Balance{self.d.balance(&channel(n)).unwrap().unwrap()}
 fn net(&self,n:u8)->i64{self.d.position(&channel(n)).unwrap().unwrap().net_usd()}
 /// Release invariant: committed is exactly the margin behind the open lots, every
 /// balance conserves cap + realized PnL, and nothing is left pending.
 fn check(&self){
  for n in 1..=4{
   let b=self.bal(n);let p=self.d.position(&channel(n)).unwrap().unwrap();
   assert!(b.conserved(),"{n}: {b:?}");assert_eq!(b.cap,self.cap);
   assert_eq!(b.committed,p.margin(),"{n}: {b:?} {p:?}");assert_eq!(b.pending,0);
  }
 }
}
fn grant(n:u8,tier:FeedTier)->Entitlement{
 Entitlement{client:pk(n),tier,tariff_version:1,valid_from_us:0,valid_until_us:u64::MAX/2,relay_key:[0;32],signature:ZERO_SIG}.signed(&sk(60)).unwrap()
}
fn approvals(b:&Batch)->Vec<BatchApproval>{
 b.accounts().iter().map(|a|{
  let n=a.channel.txid[0];let h=b.approval_message(&a.channel).unwrap();
  BatchApproval{channel:a.channel.clone(),signature:bip340_sign(&sk(n),&h).unwrap()}
 }).collect()
}
fn lane_ack(d:&DurableTieredRouter,b:&Batch,a:&ChannelObligation,disp:Disposition)->ChannelAck{
 let n=a.channel.txid[0];
 let previous=d.head(&a.channel).unwrap().unwrap();let mut next=previous;next.revision+=1;
 if disp==Disposition::Commit{next.commitment+=1;next.state=tagged_hash(b"test/state",&[&[n][..],&b.sequence().to_le_bytes()].concat());}
 let mut fee=[0;32];
 if disp==Disposition::Commit&&a.fee_sats>0{fee[0]=n;fee[1..9].copy_from_slice(&b.sequence().to_le_bytes());fee[31]=180;}
 ChannelAck{channel:a.channel.clone(),previous,next,evidence:tagged_hash(b"test/evidence",&[&[n][..],&b.sequence().to_le_bytes()].concat()),fee_evidence:fee,signatures:[ZERO;3]}
}
fn sign_all(n:u8,h:&Key,a:&mut ChannelAck){
 a.signatures=[bip340_sign(&sk(n),h).unwrap(),bip340_sign(&sk(70+n),h).unwrap(),bip340_sign(&sk(90+n),h).unwrap()];
}
fn ack(d:&DurableTieredRouter,b:&Batch,disp:Disposition)->(AckBundle,Vec<Key>){
 let (mut channels,mut digests)=(Vec::new(),Vec::new());
 for a in b.accounts(){
  let mut c=lane_ack(d,b,a,disp);
  let h=d.ack_message(b.sequence(),disp,&c).unwrap();sign_all(a.channel.txid[0],&h,&mut c);channels.push(c);digests.push(h);
 }
 (AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:disp,channels},digests)
}
/// Exact payout of `q` USD of a lot opened at `entry` with margins `(own, opp)`, closed at `exit`.
fn payout(long:bool,q:u64,entry:u64,own:u64,opp:u64,exit:u64)->u64{
 let (l,s)=if long{(own,opp)}else{(opp,own)};
 let spec=InverseContractSpec{usd_notional:q,entry_price_usd:entry,long_margin_sats:l,short_margin_sats:s,
  collateral:shz_margin::CollateralAsset::VanillaBtc,fee_policy:shz_margin::ZeroFeePolicy::ZERO};
 let p=spec.payout_at_price(exit);if long{p.long_sats}else{p.short_sats}
}
fn margin(q:u64,price:u64,lev:u32)->u64{InverseContractSpec::margin_for_leverage_bps(q,price,lev).unwrap()}

#[test]
fn open_commits_the_leg_margin_as_a_lot(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000);
 let m=margin(1000,100_000,10_000);
 assert_eq!((v.net(1),v.net(2)),(1000,-1000));
 for n in [1,2]{let b=v.bal(n);assert_eq!(b.committed,m);assert_eq!(b.realized_pnl,0);assert_eq!(b.free,CAP-m);}
 let s=v.d.settlements(1).unwrap();
 assert_eq!(s.len(),2);
 for (_,x) in s{assert_eq!((x.opened_margin,x.closed_leg_margin,x.released_margin,x.payout,x.closed_usd),(m,0,0,0,0));}
 // Adding on the same side opens a second lot.
 v.trade_commit(2,1,OrderSide::Long,500,101_000);
 assert_eq!((v.net(1),v.net(2)),(1500,-1500));
 assert_eq!(v.bal(1).committed,m+margin(500,101_000,10_000));
 assert_eq!(v.d.position(&channel(1)).unwrap().unwrap().lots().count(),2);
 v.check();
}

#[test]
fn full_offset_releases_all_margin_and_realizes_spec_pnl(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000);
 v.trade_commit(2,1,OrderSide::Short,1000,101_000);
 let m=margin(1000,100_000,10_000);
 let gain=payout(true,1000,100_000,m,m,101_000) as i64-m as i64;
 assert_eq!(gain,9901); // 1000e8 * 1000 / (100000 * 101000), rounded half-even
 let (a,b)=(v.bal(1),v.bal(2));
 assert_eq!((v.net(1),v.net(2)),(0,0));
 assert_eq!((a.committed,b.committed),(0,0));
 assert_eq!((a.realized_pnl,b.realized_pnl),(gain,-gain));
 assert_eq!((a.free as i64,b.free as i64),(CAP as i64+gain,CAP as i64-gain));
 let s:Vec<Settlement>=v.d.settlements(2).unwrap().iter().map(|x|x.1).collect();
 for x in &s{assert_eq!((x.opened_margin,x.released_margin,x.closed_usd,x.net_after,x.margin_after),(0,m,1000,0,0));}
 assert_eq!(s.iter().map(|x|x.realized_pnl()).sum::<i64>(),0);
 v.check();
}

#[test]
fn partial_offset_releases_the_offset_share(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000);
 v.trade_commit(2,1,OrderSide::Short,400,99_000);
 let m=margin(1000,100_000,10_000);let part=m*400/1000;
 let loss=payout(true,400,100_000,part,part,99_000) as i64-part as i64;
 assert!(loss<0);
 let a=v.bal(1);
 assert_eq!(v.net(1),600);assert_eq!(v.net(2),-600);
 assert_eq!(a.committed,m-part);assert_eq!(a.realized_pnl,loss);assert_eq!(v.bal(2).realized_pnl,-loss);
 let lot=*v.d.position(&channel(1)).unwrap().unwrap().lots().next().unwrap();
 assert_eq!((lot.qty,lot.price,lot.margin,lot.opp_margin),(600,100_000,m-part,m-part));
 // Close the rest at a third price; the lot is now fully released.
 v.trade_commit(2,1,OrderSide::Short,600,100_500);
 let rest=payout(true,600,100_000,m-part,m-part,100_500) as i64-(m-part) as i64;
 assert_eq!(v.bal(1).realized_pnl,loss+rest);assert_eq!(v.bal(1).committed,0);assert_eq!(v.net(1),0);
 v.check();
}

#[test]
fn flip_closes_then_opens_the_excess(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000);
 v.trade_commit(2,1,OrderSide::Short,1500,100_000);
 let m1=margin(1000,100_000,10_000);let m2=margin(1500,100_000,10_000);
 let closed=m2*1000/1500;
 assert_eq!((v.net(1),v.net(2)),(-500,500));
 let a=v.bal(1);
 assert_eq!(a.realized_pnl,0); // closed at the entry price
 assert_eq!(a.committed,m2-closed);
 let x=v.d.settlements(2).unwrap().iter().find(|x|x.0==channel(1)).unwrap().1;
 assert_eq!((x.released_margin,x.payout,x.closed_leg_margin,x.opened_margin,x.closed_usd),(m1,m1,closed,m2-closed,1000));
 assert_eq!((x.net_before,x.net_after),(1000,-500));
 let lot=*v.d.position(&channel(1)).unwrap().unwrap().lots().next().unwrap();
 assert_eq!((lot.side,lot.qty,lot.margin),(OrderSide::Short,500,m2-closed));
 v.check();
}

#[test]
fn offset_against_a_different_counterparty_nets_at_the_account(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000); // 1 long vs 2
 v.trade_commit(3,1,OrderSide::Short,1000,101_000); // 1 short vs 3
 let m=margin(1000,100_000,10_000);
 let gain=payout(true,1000,100_000,m,m,101_000) as i64-m as i64;
 assert_eq!(v.net(1),0);assert_eq!(v.bal(1).committed,0);assert_eq!(v.bal(1).realized_pnl,gain);
 // 2 is still short at 100,000 and 3 long at 101,000: their open lots back 1's gain.
 assert_eq!((v.net(2),v.net(3)),(-1000,1000));
 assert_eq!(v.bal(2).committed,m);assert_eq!(v.bal(3).committed,margin(1000,101_000,10_000));
 // When they close against each other at any price, the system nets to zero.
 v.trade_commit(3,2,OrderSide::Long,1000,100_700);
 let total:i64=(1..=4).map(|n|v.bal(n).realized_pnl).sum();
 assert!(total.abs()<=2,"rounding only: {total}");
 for n in 1..=3{assert_eq!(v.net(n),0);assert_eq!(v.bal(n).committed,0);}
 v.check();
}

#[test]
fn losses_clamp_at_the_lot_margin_and_gains_at_the_counterparty_margin(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 // 1 goes long 1000 at 100x against 2 at 1x; the next fill is 1.5% lower.
 let b=v.trade(2,1,OrderSide::Long,1000,100_000,(10_000,1_000_000),FeedTier::Standard);v.commit(&b);
 let b=v.trade(2,1,OrderSide::Short,1000,98_500,(10_000,1_000_000),FeedTier::Standard);v.commit(&b);
 let thin=margin(1000,100_000,1_000_000);let thick=margin(1000,100_000,10_000);
 assert_eq!(v.bal(1).realized_pnl,-(thin as i64)); // payout 0: loss is the whole lot margin
 assert_eq!(v.bal(2).realized_pnl,thin as i64);   // and no more than that
 assert!(thick>thin);
 v.check();
}

#[test]
fn fees_and_release_conserve_together(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 for (i,side) in [OrderSide::Long,OrderSide::Short,OrderSide::Short,OrderSide::Long].into_iter().enumerate(){
  let b=v.trade(2,1,side,700+100*i as u64,100_000+300*i as u64,(20_000,20_000),FeedTier::Premium);
  assert!(b.accounts().iter().all(|a|a.fee_sats>0));v.commit(&b);v.check();
 }
 assert_eq!(v.net(1),700-800-900+1000);
 let (a,b)=(v.bal(1),v.bal(2));
 assert!(a.paid_fees>0&&b.paid_fees>0);
 assert_eq!(a.realized_pnl+b.realized_pnl,0);
}

#[test]
fn alternating_fills_on_one_pair_never_run_out_of_capacity(){
 // docs/SHZ_VENUE_LATENCY.md finding 4: 48 alternating 5 USD fills at 2x left two flat
 // accounts with 196,949 of 200,000 sats committed. With release they stay bounded.
 let t=Temp::new();let mut v=Venue::new(&t.path(),200_000,true);
 let leg=margin(5,120_000,20_000);
 for i in 0..120u64{
  let side=if i%2==0{OrderSide::Long}else{OrderSide::Short};
  let b=v.trade(2,1,side,5,120_000+(i%7)*10,(20_000,20_000),FeedTier::Standard);v.commit(&b);
  for n in [1,2]{assert!(v.bal(n).committed<=leg+1,"{i}: {:?}",v.bal(n));}
 }
 assert_eq!((v.net(1),v.net(2)),(0,0));
 for n in [1,2]{let b=v.bal(n);assert_eq!(b.committed,0);assert!(b.free as i64>=190_000);}
 v.check();
}

#[test]
fn acknowledgements_bind_the_settlement(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000);
 let b=v.trade(2,1,OrderSide::Short,400,100_900,(10_000,10_000),FeedTier::Standard);
 v.d.prepare(b.sequence(),approvals(&b)).unwrap();
 // A V1 acknowledgement (no settlement) signed by every party does not resolve.
 let cfg_hash=v.d.config_hash();
 let mut stale=Vec::new();
 for a in b.accounts(){
  let mut c=lane_ack(&v.d,&b,a,Disposition::Commit);
  let h=v1_message(TIERED_ACK_TAG,&cfg_hash,&b,&c,None);sign_all(a.channel.txid[0],&h,&mut c);stale.push(c);
 }
 assert!(v.d.resolve(AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:Disposition::Commit,channels:stale}).is_err());
 let (bundle,digests)=ack(&v.d,&b,Disposition::Commit);
 assert!(v.d.resolve(bundle.clone()).unwrap());
 // Every signed digest is the V2 message over the recorded settlement, rebuilt independently.
 let rows=v.d.settlements(b.sequence()).unwrap();
 for ((c,h),(ch,s)) in bundle.channels.iter().zip(&digests).zip(rows){
  assert_eq!(c.channel,*ch);
  assert_eq!(*h,v1_message(TIERED_ACK_TAG_V2,&cfg_hash,&b,c,Some(s)));
 }
 v.check();
}

/// Independent reconstruction of the acknowledgement digest (V1 layout, plus the
/// settlement suffix for V2).
fn v1_message(tag:&[u8],config:&Key,b:&Batch,a:&ChannelAck,s:Option<&Settlement>)->Key{
 let put=|v:&mut Vec<u8>,n:u64|v.extend(n.to_le_bytes());
 let head=|v:&mut Vec<u8>,h:&Head|{v.extend(h.revision.to_le_bytes());v.extend(h.commitment.to_le_bytes());v.extend(h.state)};
 let o=b.accounts().iter().find(|o|o.channel==a.channel).unwrap();
 let mut v=Vec::new();v.extend(config);v.extend(b.digest());put(&mut v,b.sequence());v.push(1);
 v.extend(a.channel.txid);v.extend(a.channel.vout.to_le_bytes());v.extend(o.owner);put(&mut v,o.margin_sats);put(&mut v,o.fee_sats);
 head(&mut v,&a.previous);head(&mut v,&a.next);v.extend(a.evidence);v.extend(a.fee_evidence);
 v.extend(recipients().oracle);v.extend(recipients().router);
 v.extend(b.oracle_due_sats().to_le_bytes());v.extend(b.router_due_sats().to_le_bytes());
 if let Some(s)=s{
  v.push(1);
  for n in [s.opened_margin,s.closed_leg_margin,s.released_margin,s.payout,s.closed_usd]{put(&mut v,n)}
  v.extend(s.net_before.to_le_bytes());v.extend(s.net_after.to_le_bytes());put(&mut v,s.margin_after);
 }
 tagged_hash(tag,&v)
}

#[test]
fn enabling_on_a_live_journal_reconciles_committed_batches_and_replays(){
 let t=Temp::new();let path=t.path();
 let mut v=Venue::new(&path,CAP,false);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000);
 v.trade_commit(2,1,OrderSide::Short,1000,101_000);
 v.trade_commit(3,1,OrderSide::Long,300,100_500);
 // A sealed, prepared but unresolved batch spans the switch.
 let open=v.trade(4,3,OrderSide::Long,200,100_200,(10_000,10_000),FeedTier::Standard);
 v.d.prepare(open.sequence(),approvals(&open)).unwrap();
 // Without release, nothing ever leaves committed.
 let m=margin(1000,100_000,10_000);
 assert_eq!(v.bal(1).committed,m+margin(1000,101_000,10_000)+margin(300,100_500,10_000));
 assert!(!v.d.margin_release_active().unwrap());
 assert!(v.d.settlements(1).unwrap().is_empty());
 assert!(v.d.enable_margin_release().unwrap());
 let gain=payout(true,1000,100_000,m,m,101_000) as i64-m as i64;
 assert_eq!(v.bal(1).committed,margin(300,100_500,10_000));assert_eq!(v.bal(1).realized_pnl,gain);
 assert_eq!(v.bal(2).committed,0);assert_eq!(v.bal(2).realized_pnl,-gain);
 assert_eq!((v.net(1),v.net(2),v.net(3)),(300,0,-300));
 assert_eq!(v.d.settlements(2).unwrap().len(),2);
 // The batch prepared before the switch commits under V2 acknowledgements.
 v.commit(&open);
 assert_eq!((v.net(3),v.net(4)),(-100,-200));
 v.check();
 let snap=|d:&DurableTieredRouter|(1..=4).map(|n|format!("{:?}|{:?}|{:?}",d.balance(&channel(n)).unwrap(),d.position(&channel(n)).unwrap(),d.head(&channel(n)).unwrap())).collect::<Vec<_>>();
 let before=snap(&v.d);let tip=v.d.tip().unwrap();
 drop(v);
 let d=DurableTieredRouter::open(&path,&registry(CAP),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 assert!(d.margin_release_active().unwrap());
 assert_eq!(snap(&d),before);
 assert_eq!(d.settlements(4).unwrap().len(),2);
}

#[test]
fn fenced_abort_leaves_positions_unchanged(){
 let t=Temp::new();let mut v=Venue::new(&t.path(),CAP,true);
 v.trade_commit(2,1,OrderSide::Long,1000,100_000);
 let b=v.trade(2,1,OrderSide::Short,1000,100_800,(10_000,10_000),FeedTier::Standard);
 v.d.prepare(b.sequence(),approvals(&b)).unwrap();
 let (bundle,_)=ack(&v.d,&b,Disposition::FencedAbort);
 assert!(v.d.resolve(bundle).unwrap());
 assert_eq!((v.net(1),v.net(2)),(1000,-1000));
 assert_eq!(v.bal(1).committed,margin(1000,100_000,10_000));assert_eq!(v.bal(1).realized_pnl,0);
 assert!(v.d.settlements(b.sequence()).unwrap().is_empty());
 v.check();
}
