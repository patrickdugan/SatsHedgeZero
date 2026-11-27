//! Options desk on the durable tiered router (docs/SHZ_OPTIONS_COMBOS.md): listed series,
//! `IntentV7` orders, worst-case-loss margin, premium and expiry through the clearing
//! ledger, journal replay. Synthetic funds and a deterministic test oracle only.
use shz_dex::routing::*;
use shz_dex::routing::durable::{Disposition,FeeRecipients,Head,Lane};
use shz_dex::routing::options::*;
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dlc::{BtcOutPoint,OracleAttestation};
use shz_margin::payoff::{self,Asset,Leg,OptionKind,PriceDomain};
use shz_oracle::frost::{FrostConfederation,FrostEventNonceState};
use std::{cell::Cell,fs,path::{Path,PathBuf},sync::atomic::{AtomicU64,Ordering}};

type Key=[u8;32];
const AUTH:[u8;32]=[77;32];
const CAP:u64=100_000_000;
const N:u8=4;
const BITS:u8=20;
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
fn domain()->PriceDomain{PriceDomain::from_bits(BITS)}
const BTC:SettleAsset=SettleAsset::Btc;
/// RGB USDT (6 decimals) and a second stablecoin on Taproot Assets with 8 decimals.
const USDT:SettleAsset=SettleAsset::Stable{protocol:StableProtocol::Rgb,id:[0x52;32],decimals:6};
const TUSD:SettleAsset=SettleAsset::Stable{protocol:StableProtocol::Tap,id:[0x7a;32],decimals:8};
/// 0.01 BTC in 1e-8 BTC units, the size of a linear option leg in these tests.
const CENT:u64=1_000_000;

static COUNTER:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp{
 fn new()->Self{
  let p=std::env::temp_dir().join(format!("shz-options-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
 fn path(&self)->PathBuf{self.0.join("router.wal")}
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

struct Desk{d:DurableTieredRouter,oracle:FrostConfederation,events:Vec<FrostEventNonceState>,seq:Cell<u64>,now:Cell<u64>}
impl Desk{
 fn new(path:&Path)->Self{
  let mut d=DurableTieredRouter::create(path,&registry(),cfg(),lanes(),recipients()).unwrap();
  assert!(d.enable_margin_release().unwrap());assert!(d.enable_clearing(1_000_000).unwrap());
  let oracle=FrostConfederation::keygen_deterministic(2,3,&[0x51;32]).unwrap();
  assert!(d.enable_options(oracle.group_pubkey_x,BITS).unwrap());assert!(!d.enable_options(oracle.group_pubkey_x,BITS).unwrap());
  Self{d,oracle,events:Vec::new(),seq:Cell::new(0),now:Cell::new(T0)}
 }
 /// List a series on the shared expiry (oracle event 0); returns its id.
 fn list(&mut self,kind:OptionKind,asset:SettleAsset,strike:u64)->Key{self.list_on(0,kind,asset,strike)}
 /// List a series on oracle event `ev` (announced on first use).
 fn list_on(&mut self,ev:u8,kind:OptionKind,asset:SettleAsset,strike:u64)->Key{
  let event=format!("BTCUSD-{ev}");
  if !self.events.iter().any(|e|e.announcement.event_id==event){
   self.events.push(self.oracle.announce_event(&event,1_800_000_000,BITS,&[ev;32]).unwrap());
  }
  let ann=self.events.iter().find(|e|e.announcement.event_id==event).unwrap().announcement.clone();
  self.d.list_series(Series{kind,asset,strike_usd:strike,event_id:event},ann).unwrap()
 }
 fn attest(&self,series:&Key,price:u64)->OracleAttestation{
  let (s,_)=self.d.options().unwrap().unwrap().series(series).unwrap();
  let ns=self.events.iter().find(|e|e.announcement.event_id==s.event_id).unwrap();
  self.oracle.threshold_attest_price(ns,&[1,2],1_800_000_000,price).unwrap()
 }
 fn intent(&self,n:u8,action:Action,legs:Vec<LegOrder>,premium_milli:i64)->IntentV7{
  let c=cfg();self.seq.set(self.seq.get()+1);
  IntentV7{version:OPTION_INTENT_VERSION,scope:c.scope,router:1,channel:channel(n),owner:[0;32],sequence:self.seq.get(),
   expires_us:self.now.get()+5_000_000,action,legs,premium_milli,other_limits:vec![],cancel_target:[0;32],
   signature:shz_dlc::Bip340Signature{r_x:[0;32],s:[0;32]}}.signed(&sk(n)).unwrap()
 }
 fn send(&mut self,i:IntentV7)->Result<OptionOutcome,TieredDurableError>{self.now.set(self.now.get()+1);let now=self.now.get();self.d.submit_option(i,now)}
 fn post(&mut self,n:u8,series:Key,long:bool,qty:u64,milli:i64)->Key{
  match self.send(self.intent(n,Action::Post,vec![LegOrder{series,long,qty}],milli)).unwrap(){OptionOutcome::Posted(id)=>id,x=>panic!("{x:?}")}
 }
 fn take(&mut self,n:u8,legs:Vec<LegOrder>,limit:i64)->Result<OptionBatch,TieredDurableError>{
  match self.send(self.intent(n,Action::Take,legs,limit))?{OptionOutcome::Filled(b)=>Ok(*b),x=>panic!("{x:?}")}
 }
 fn acct(&self,n:u8)->OptionAccount{self.d.options().unwrap().unwrap().account(&op(n)).cloned().unwrap_or_default()}
 fn btc(&self,n:u8)->AssetBalance{self.acct(n).balance(&BTC)}
 fn stable(&self,n:u8,a:SettleAsset)->AssetBalance{self.acct(n).balance(&a)}
 fn legs(&self,n:u8)->Vec<Leg>{self.d.options().unwrap().unwrap().legs(&op(n))}
 /// Invariants after every step, per asset: locked collateral is exactly the sum over
 /// expiries of the worst-case loss, every perpetual balance is conserved, each pool's
 /// clearing identity holds, and every unit realized came out of (or went into) its pool.
 fn check(&self){
  let desk=self.d.options().unwrap().unwrap();
  let mut assets=vec![BTC];assets.extend(desk.stable_pools().map(|(a,_)|*a));
  let mut realized:Vec<i128>=vec![0;assets.len()];
  for n in 1..=N{
   let a=self.acct(n);
   let groups=desk.groups(&op(n));
   for (i,x) in assets.iter().enumerate(){
    let want:u128=groups.iter().filter(|((_,g),_)|g==x).map(|(_,l)|payoff::max_loss(l,x.payoff_asset(),domain())*x.scale()).sum();
    assert_eq!(a.balance(x).locked as u128,want,"{n} {x:?}");
    realized[i]+=a.balance(x).realized as i128;
   }
   assert!(desk.fully_funded(&op(n)));
   let b=self.d.balance(&channel(n)).unwrap().unwrap();assert!(b.conserved());
   realized[0]+=b.realized_pnl as i128;
  }
  let s=self.d.clearing_summary().unwrap().unwrap();
  assert_eq!(s.identity,0,"{s:?}");
  assert_eq!(realized[0]+s.cash as i128,s.fund0 as i128,"{s:?}");
  for (i,(_,pool)) in desk.stable_pools().enumerate(){
   let p=pool.summary(0);assert_eq!(p.identity,0,"{p:?}");
   assert_eq!(realized[i+1]+p.cash as i128,p.fund0 as i128,"{p:?}");
  }
 }
}
fn rejected(r:Result<impl std::fmt::Debug,TieredDurableError>,want:TierReject){
 match r{Err(TieredDurableError::Rejected(x)) if x==want=>{},x=>panic!("want {want:?}, got {x:?}")}
}
fn leg(series:Key,long:bool,qty:u64)->LegOrder{LegOrder{series,long,qty}}
/// Sats an inverse call of `q` USD at strike `k` pays at `p` (floor).
fn call_pays(q:u64,k:u64,p:u64)->i128{payoff::pnl(&[Leg::InverseOption{kind:OptionKind::Call,long:true,qty_usd:q,strike_usd:k,premium_sats:0}],Asset::Btc,p)}

/// B1. A call trades at a premium, the writer locks the call's worst-case loss, and the
/// series expires in the money at the attested price through the clearing ledger.
#[test]
fn b1_call_premium_margin_and_expiry(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let call=v.list(OptionKind::Call,BTC,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 let b=v.d.balance(&channel(1)).unwrap().unwrap();
 assert_eq!((b.cap,b.free,v.btc(1).free),(CAP-5_000_000,CAP-5_000_000,5_000_000));
 // 2 writes 1,000 USD of the call at 40 sats per USD; 1 buys it.
 v.post(2,call,false,1000,40_000);
 let batch=v.take(1,vec![leg(call,true,1000)],40_000_000).unwrap();
 assert_eq!(batch.fills.len(),1);assert_eq!(batch.fills[0].premium,40_000);
 let worst=payoff::max_loss(&[Leg::InverseOption{kind:OptionKind::Call,long:false,qty_usd:1000,strike_usd:100_000,premium_sats:0}],Asset::Btc,domain());
 // Q*1e8*(1/K - 1/p_max), the call at the top of the 20-bit domain.
 assert_eq!(worst as i128,-payoff::pnl(&[Leg::InverseOption{kind:OptionKind::Call,long:false,qty_usd:1000,strike_usd:100_000,premium_sats:0}],Asset::Btc,domain().p_max));
 assert_eq!(worst,904_633);
 let (a1,a2)=(v.btc(1),v.btc(2));
 assert_eq!((a1.free,a1.locked,a1.realized),(5_000_000-40_000,0,-40_000));
 assert_eq!((a2.free,a2.locked as u128,a2.realized),(5_000_000+40_000-worst as u64,worst,40_000));
 let c=batch.clearing_of(&BTC).unwrap();
 assert_eq!(c.rows.iter().map(|r|r.net).sum::<i64>()+c.pool_net(),0);assert_eq!(c.pool_net(),0);
 v.check();
 // Expiry at 110,000: the long gets the floor of its payoff, the short pays the ceiling.
 let pays=call_pays(1000,100_000,110_000) as u64;
 let e=v.d.expire_series(call,v.attest(&call,110_000)).unwrap();
 assert!(matches!(e.kind,OptionBatchKind::Expiry{price_usd:110_000,..}));
 let dust=e.clearing_of(&BTC).unwrap().pool_net();assert!((0..=1).contains(&dust),"{dust}");
 let (a1,a2)=(v.btc(1),v.btc(2));
 assert_eq!((a1.free,a1.locked),(5_000_000-40_000+pays,0));
 assert_eq!((a2.free,a2.locked),(5_000_000+40_000-pays-dust as u64,0));
 assert!(v.legs(1).is_empty()&&v.legs(2).is_empty());
 v.check();
 // Collateral goes back to the perpetual allocation.
 v.d.defund_options(channel(1),a1.free).unwrap();
 let b=v.d.balance(&channel(1)).unwrap().unwrap();
 assert_eq!((b.cap,v.btc(1).free),(CAP-5_000_000+a1.free,0));
 // An expired series no longer trades or expires again.
 rejected(v.d.expire_series(call,v.attest(&call,110_000)),TierReject::Expired);
 rejected(v.send(v.intent(2,Action::Post,vec![leg(call,false,1)],1000)),TierReject::Expired);
 v.check();
}

/// B1. Out of the money: nothing is paid, the writer keeps the premium, collateral frees.
#[test]
fn b1_expiry_out_of_the_money_frees_collateral(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let call=v.list(OptionKind::Call,BTC,100_000);
 for n in [1,2,3]{v.d.fund_options(channel(n),3_000_000).unwrap();}
 // Two writers at different premiums; the taker sweeps the best first.
 v.post(2,call,false,500,30_000);v.post(3,call,false,1000,35_000);
 let b=v.take(1,vec![leg(call,true,800)],1_000_000_000).unwrap();
 assert_eq!(b.fills.iter().map(|f|(f.qty,f.premium)).collect::<Vec<_>>(),vec![(500,15_000),(300,10_500)]);
 assert_eq!(v.d.options().unwrap().unwrap().depth(&call,false)[0].2,700);
 v.check();
 let e=v.d.expire_series(call,v.attest(&call,99_000)).unwrap();
 assert!(e.clearing_of(&BTC).unwrap().rows.iter().all(|r|r.net==0));
 assert_eq!((v.btc(2).free,v.btc(3).free,v.btc(1).free),(3_015_000,3_010_500,3_000_000-25_500));
 assert!(v.d.options().unwrap().unwrap().depth(&call,false).is_empty());
 v.check();
}

/// B1. Admission: version, signature, replay, crossing posts, premium limit, capacity,
/// unfunded makers dropped, combos refused until enabled, attestation checked.
#[test]
fn b1_rejections(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let call=v.list(OptionKind::Call,BTC,100_000);
 let other=v.list_on(1,OptionKind::Call,BTC,105_000);
 v.d.fund_options(channel(2),2_000_000).unwrap();
 // No collateral for the buyer's premium.
 v.post(2,call,false,1000,40_000);
 rejected(v.take(1,vec![leg(call,true,1000)],40_000_000),TierReject::Capacity);
 v.d.fund_options(channel(1),1_000_000).unwrap();
 // Premium limit.
 rejected(v.take(1,vec![leg(call,true,1000)],39_999_999),TierReject::FeeLimit);
 // A post that would cross the best ask is refused.
 rejected(v.send(v.intent(1,Action::Post,vec![leg(call,true,10)],40_000)),TierReject::Bounds);
 // Replayed sequence, wrong version, bad signature, wrong owner.
 let i=v.intent(1,Action::Post,vec![leg(call,true,10)],1_000);
 v.send(i.clone()).unwrap();rejected(v.send(i),TierReject::Replay);
 let mut i=v.intent(1,Action::Post,vec![leg(call,true,10)],1_000);i.version=6;
 rejected(v.send(i.signed(&sk(1)).unwrap()),TierReject::Scope);
 let mut i=v.intent(1,Action::Post,vec![leg(call,true,10)],1_000);i.premium_milli=2_000;
 rejected(v.send(i),TierReject::Signature);
 rejected(v.send(v.intent(1,Action::Post,vec![leg(call,true,10)],1_000).signed(&sk(3)).unwrap()),TierReject::Allocation);
 // Combos are refused until `enable_combos`.
 v.post(2,other,false,100,10_000);
 rejected(v.take(1,vec![leg(call,true,10),leg(other,true,10)],1_000_000_000),TierReject::Bounds);
 // A maker who cannot fund its side is dropped and the taker fills against the next.
 v.post(3,other,false,100,9_000);
 let b=v.take(1,vec![leg(other,true,100)],1_000_000_000).unwrap();
 assert_eq!(b.fills.len(),1);assert_eq!(b.fills[0].short,channel(2));
 assert_eq!(v.d.options().unwrap().unwrap().depth(&other,false).len(),0);
 // Cancel: only the owner's own quote.
 let q=v.post(2,call,false,10,50_000);
 let mut c=v.intent(1,Action::Cancel,vec![],0);c.cancel_target=q;
 rejected(v.send(c.signed(&sk(1)).unwrap()),TierReject::UnknownOrder);
 let mut c=v.intent(2,Action::Cancel,vec![],0);c.cancel_target=q;
 assert!(matches!(v.send(c.signed(&sk(2)).unwrap()).unwrap(),OptionOutcome::Cancelled(x) if x==q));
 // An attestation for another event does not expire the series.
 rejected(v.d.expire_series(call,v.attest(&other,110_000)),TierReject::NoMark);
 v.check();
}

/// B1. The journal replays the options desk to the same state.
#[test]
fn b1_journal_replays(){
 let t=Temp::new();let path=t.path();
 let mut v=Desk::new(&path);
 let call=v.list(OptionKind::Call,BTC,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 v.post(2,call,false,1000,40_000);
 v.take(1,vec![leg(call,true,600)],1_000_000_000).unwrap();
 rejected(v.take(3,vec![leg(call,true,1)],1_000_000_000),TierReject::Capacity);
 let before=format!("{:?}|{:?}",v.d.options().unwrap(),v.d.clearing_state().unwrap());
 let tip=v.d.tip().unwrap();drop(v);
 let d=DurableTieredRouter::open(&path,&registry(),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 assert_eq!(format!("{:?}|{:?}",d.options().unwrap(),d.clearing_state().unwrap()),before);
}

fn short_call(q:u64,k:u64)->Leg{Leg::InverseOption{kind:OptionKind::Call,long:false,qty_usd:q,strike_usd:k,premium_sats:0}}
/// Combos desk: series listed, makers funded and quoting every leg.
fn combo_desk(path:&Path)->(Desk,Key,Key,Key,Key){
 let mut v=Desk::new(path);
 let deep=v.list(OptionKind::Call,BTC,50_000);
 let c100=v.list(OptionKind::Call,BTC,100_000);
 let c110=v.list(OptionKind::Call,BTC,110_000);
 let p90=v.list(OptionKind::Put,BTC,90_000);
 for n in [1,2]{v.d.fund_options(channel(n),40_000_000).unwrap();}
 // An inverse put's worst case is at the bottom of the domain: a 1 USD put struck at 90k
 // locks 1e8*(1/1 - 1/90k) sats, almost a whole bitcoin (why puts are USD-settled in C).
 v.d.fund_options(channel(3),CAP).unwrap();
 // Maker 2 quotes both sides of every call, maker 3 sells the put.
 for s in [deep,c100,c110]{v.post(2,s,false,5_000,60_000);v.post(2,s,true,5_000,20_000);}
 v.post(3,p90,false,5_000,10_000);
 assert!(v.d.enable_combos().unwrap());assert!(!v.d.enable_combos().unwrap());
 (v,deep,c100,c110,p90)
}

/// B2. Call spread: one signed two-leg intent fills both legs in one batch, and the
/// writer's margin is the spread's worst case, not the naked short call's.
#[test]
fn b2_call_spread_margined_on_the_combined_payoff(){
 let t=Temp::new();let (mut v,_,c100,c110,_)=combo_desk(&t.path());
 // Bear call spread: sell the 100k call, buy the 110k call. Net credit: receives 20, pays 60
 // sats per USD, so the taker pays 40 per USD net, at most 40,000 milli * 1,000 USD.
 let b=v.take(1,vec![leg(c100,false,1000),leg(c110,true,1000)],40_000_000).unwrap();
 assert_eq!(b.fills.len(),2);assert!(matches!(b.kind,OptionBatchKind::Trade{..}));
 assert_eq!(b.sequence,v.d.options().unwrap().unwrap().batch_count());
 let spread=payoff::max_loss(&[short_call(1000,100_000),Leg::InverseOption{kind:OptionKind::Call,long:true,qty_usd:1000,strike_usd:110_000,premium_sats:0}],Asset::Btc,domain());
 let naked=payoff::max_loss(&[short_call(1000,100_000)],Asset::Btc,domain());
 // Q*1e8*(1/100k - 1/110k) = 90,909.09 sats, rounded up.
 assert_eq!((spread,naked),(90_910,904_633));
 assert_eq!(v.btc(1).locked as u128,spread);
 assert_eq!(v.btc(1).free,40_000_000-40_000-90_910);
 v.check();
 // Both legs share one expiry: at 120k the spread pays its full width in one amount.
 assert_eq!(-payoff::pnl(&v.legs(1),Asset::Btc,120_000),90_910);
 let e=v.d.expire_series(c100,v.attest(&c100,120_000)).unwrap();
 assert!(matches!(&e.kind,OptionBatchKind::Expiry{series,..} if series.len()==4));
 let a=v.btc(1);
 assert_eq!((a.locked,a.free,a.realized),(0,40_000_000-40_000-90_910,-40_000-90_910));
 assert!(v.legs(1).is_empty());
 v.check();
}

/// B2. Covered call with a deep in-the-money call as the cover: selling the 110k call
/// against a long 50k call needs no collateral beyond the net premium.
#[test]
fn b2_covered_call(){
 let t=Temp::new();let (mut v,deep,_,c110,_)=combo_desk(&t.path());
 v.take(1,vec![leg(deep,true,2000),leg(c110,false,2000)],80_000_000).unwrap();
 assert_eq!(v.btc(1).locked,0);
 assert_eq!(v.btc(1).free,40_000_000-(120_000-40_000));
 // The 50k call covers up to 4,400 USD of 110k calls (2000/50k = 4400/110k as P grows);
 // selling 3,000 more (5,000 in all) locks the uncovered worst case.
 v.take(1,vec![leg(c110,false,3000)],-60_000_000).unwrap();
 assert_eq!(v.btc(1).locked as u128,payoff::max_loss(&v.legs(1),Asset::Btc,domain()));
 assert!(v.btc(1).locked>0);
 v.check();
}

/// B2. Collar: long cover, long put, short call in one three-leg intent (1 USD each: the
/// put writer must lock almost a bitcoin per USD); the combined payoff cannot lose, so
/// only the net premium is paid.
#[test]
fn b2_collar(){
 let t=Temp::new();let (mut v,deep,_,c110,p90)=combo_desk(&t.path());
 let b=v.take(1,vec![leg(deep,true,1),leg(p90,true,1),leg(c110,false,1)],60_000).unwrap();
 assert_eq!(b.fills.len(),3);
 // Pays 60 + 10, receives 20 sats per USD.
 assert_eq!((v.btc(1).locked,v.btc(1).free),(0,40_000_000-50));
 assert_eq!(v.btc(3).locked,99_998_889);
 let c=b.clearing_of(&BTC).unwrap();assert_eq!(c.rows.iter().map(|r|r.net).sum::<i64>(),0);
 v.check();
}

/// B2. All-or-none: a combo with one unfillable leg, or over its net premium limit,
/// changes nothing; duplicate series and more than `MAX_LEGS` legs are refused.
#[test]
fn b2_all_or_none(){
 let t=Temp::new();let (mut v,deep,c100,c110,p90)=combo_desk(&t.path());
 let snap=|v:&Desk|{
  let d=v.d.options().unwrap().unwrap();
  format!("{:?}|{:?}",(1..=N).map(|n|v.btc(n)).collect::<Vec<_>>(),[deep,c100,c110,p90].iter().map(|s|(d.depth(s,true),d.depth(s,false))).collect::<Vec<_>>())
 };
 let before=snap(&v);
 rejected(v.take(1,vec![leg(c100,true,1000),leg(c110,false,6000)],1_000_000_000),TierReject::NoLiquidity);
 rejected(v.take(1,vec![leg(c100,true,1000),leg(c110,false,1000)],39_999_999),TierReject::FeeLimit);
 rejected(v.take(1,vec![leg(c100,true,1),leg(c100,true,1)],1_000_000_000),TierReject::Bounds);
 rejected(v.take(1,vec![leg(c100,true,1),leg(c110,true,1),leg(deep,true,1),leg(p90,true,1),leg(c100,false,1)],1_000_000_000),TierReject::Bounds);
 assert_eq!(snap(&v),before);
 v.check();
}

/// C. The BTC-only alternative to a USD put: a put spread. Each side's worst case is the
/// spread's (`Q*1e8*(1/80k - 1/90k)` for the seller, nothing for the buyer), not the naked
/// put's almost-a-bitcoin per USD, so it trades with ordinary BTC collateral.
#[test]
fn c5_btc_put_spread(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let p80=v.list(OptionKind::Put,BTC,80_000);
 let p90=v.list(OptionKind::Put,BTC,90_000);
 for n in [1,2]{v.d.fund_options(channel(n),2_000_000).unwrap();}
 assert!(v.d.enable_combos().unwrap());
 // 2 quotes the spread's two legs: bids the 90k put, offers the 80k put.
 v.post(2,p90,true,1000,60_000);v.post(2,p80,false,1000,20_000);
 // 1 sells the spread: sells the 90k put, buys the 80k put, for a 40 sats/USD credit.
 v.take(1,vec![leg(p90,false,1000),leg(p80,true,1000)],-40_000_000).unwrap();
 assert_eq!(v.btc(1).locked,138_889);
 assert_eq!(v.btc(2).locked,0);
 assert_eq!(v.btc(1).free,2_000_000+40_000-138_889);
 let naked=payoff::max_loss(&[Leg::InverseOption{kind:OptionKind::Put,long:false,qty_usd:1000,strike_usd:90_000,premium_sats:0}],Asset::Btc,domain());
 assert!(naked>99_000_000_000,"{naked}");
 v.check();
 // Both legs expire together at 85k: the 90k put pays, the 80k put does not.
 v.d.expire_series(p80,v.attest(&p80,85_000)).unwrap();
 let owed=payoff::pnl(&[Leg::InverseOption{kind:OptionKind::Put,long:true,qty_usd:1000,strike_usd:90_000,premium_sats:0}],Asset::Btc,85_000);
 assert_eq!(owed,65_359);
 assert_eq!((v.btc(1).locked,v.btc(1).free),(0,2_000_000+40_000-65_360));
 v.check();
}

/// Legs on different expiries do not offset: a long call on one event cannot cover a
/// short call on another, so expiring the first never leaves the second underfunded.
#[test]
fn c4_legs_offset_only_within_one_expiry(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 assert!(v.d.enable_combos().unwrap());
 let near=v.list_on(0,OptionKind::Call,BTC,100_000);
 let far=v.list_on(1,OptionKind::Call,BTC,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 v.post(2,near,false,1000,40_000);v.post(2,far,true,1000,30_000);
 v.take(1,vec![leg(near,true,1000),leg(far,false,1000)],10_000_000).unwrap();
 assert_eq!(v.btc(1).locked as u128,payoff::max_loss(&[short_call(1000,100_000)],Asset::Btc,domain()));
 v.check();
 v.d.expire_series(near,v.attest(&near,120_000)).unwrap();
 v.check();
 v.d.expire_series(far,v.attest(&far,90_000)).unwrap();
 assert_eq!((v.btc(1).locked,v.btc(2).locked),(0,0));
 v.check();
}

fn stable_desk(path:&Path)->Desk{
 let mut v=Desk::new(path);
 rejected(v.d.deposit_stable(channel(1),USDT,1),TierReject::Scope);
 v.d.register_stable(USDT).unwrap();rejected(v.d.register_stable(USDT),TierReject::Replay);
 v.d.register_stable(TUSD).unwrap();
 rejected(v.d.register_stable(SettleAsset::Stable{protocol:StableProtocol::Rgb,id:[1;32],decimals:2}),TierReject::Bounds);
 v
}

/// C. A USDT cash-secured put: the writer posts strike x size in USDT and is capped there;
/// premium is paid in USDT; expiry pays the put in USDT through the USDT pool. BTC
/// collateral and the BTC pool are untouched.
#[test]
fn c1_usdt_cash_secured_put(){
 let t=Temp::new();let mut v=stable_desk(&t.path());
 let put=v.list(OptionKind::Put,USDT,90_000);
 v.d.deposit_stable(channel(2),USDT,2_000_000_000).unwrap();   // $2,000
 v.d.deposit_stable(channel(1),USDT,100_000_000).unwrap();     // $100
 // 0.01 BTC put at $90k; premium $25 = 25e6 base units over 1e6 units = 25,000 milli.
 v.post(2,put,false,CENT,25_000);
 let b=v.take(1,vec![leg(put,true,CENT)],25_000_000_000).unwrap();
 assert_eq!((b.fills[0].asset,b.fills[0].premium),(USDT,25_000_000));
 assert!(b.clearing_of(&BTC).is_none());
 // Cash-secured: Q*(K - p_min) = 0.01 * 89,999 USD.
 assert_eq!(v.stable(2,USDT).locked,899_990_000);
 assert_eq!((v.stable(2,USDT).free,v.stable(1,USDT).free),(2_000_000_000+25_000_000-899_990_000,75_000_000));
 assert_eq!((v.btc(1).locked,v.btc(2).locked),(0,0));
 let cash=v.d.clearing_state().unwrap().unwrap().cash;
 v.check();
 // Expiry at $80k pays 0.01 * 10,000 = $100.
 let e=v.d.expire_series(put,v.attest(&put,80_000)).unwrap();
 let rows:Vec<_>=e.clearing_of(&USDT).unwrap().rows.iter().map(|r|(r.channel.txid[0],r.net)).collect();
 assert_eq!(rows,vec![(1,100_000_000),(2,-100_000_000)]);
 assert_eq!((v.stable(1,USDT).free,v.stable(2,USDT).free,v.stable(2,USDT).locked),(175_000_000,1_925_000_000,0));
 assert_eq!(v.d.clearing_state().unwrap().unwrap().cash,cash);
 v.d.withdraw_stable(channel(2),USDT,1_925_000_000).unwrap();
 rejected(v.d.withdraw_stable(channel(2),USDT,1),TierReject::Capacity);
 v.check();
}

/// C. Per asset, no netting: BTC collateral does not secure a USDT put, one stablecoin does
/// not secure another's, calls cannot settle in a stablecoin, and an 8-decimal stablecoin
/// is margined in its own base units.
#[test]
fn c2_assets_do_not_net(){
 let t=Temp::new();let mut v=stable_desk(&t.path());
 let put=v.list(OptionKind::Put,USDT,90_000);
 let tput=v.list(OptionKind::Put,TUSD,90_000);
 let ann=v.events[0].announcement.clone();
 rejected(v.d.list_series(Series{kind:OptionKind::Call,asset:USDT,strike_usd:100_000,event_id:"BTCUSD-0".into()},ann.clone()),TierReject::Bounds);
 let other=SettleAsset::Stable{protocol:StableProtocol::Tap,id:[9;32],decimals:6};
 rejected(v.d.list_series(Series{kind:OptionKind::Put,asset:other,strike_usd:100_000,event_id:"BTCUSD-0".into()},ann),TierReject::Scope);
 v.d.fund_options(channel(2),CAP).unwrap();
 v.d.deposit_stable(channel(2),TUSD,1_000_000_000_000).unwrap();
 v.d.deposit_stable(channel(1),USDT,100_000_000).unwrap();
 v.post(2,put,false,CENT,25_000);
 // Writer 2 holds a bitcoin and $10,000 of the other stablecoin, no USDT: dropped as unfunded.
 rejected(v.take(1,vec![leg(put,true,CENT)],25_000_000_000),TierReject::NoLiquidity);
 // The 8-decimal asset: the same put locks 100x the base units.
 v.d.deposit_stable(channel(1),TUSD,10_000_000_000).unwrap();
 v.post(2,tput,false,CENT,2_500_000);
 v.take(1,vec![leg(tput,true,CENT)],2_500_000_000_000).unwrap();
 assert_eq!(v.stable(2,TUSD).locked,89_999_000_000);
 assert_eq!(v.btc(2).locked,0);
 v.check();
}

/// C. Collar across assets in one batch: buy the USDT put (writer cash-secured in USDT),
/// sell the BTC call (covered by BTC collateral). One signed intent, one batch, one
/// clearing report per asset, each netting to zero on its own.
#[test]
fn c3_collar_clears_in_two_assets(){
 let t=Temp::new();let mut v=stable_desk(&t.path());
 assert!(v.d.enable_combos().unwrap());
 let put=v.list(OptionKind::Put,USDT,90_000);
 let call=v.list(OptionKind::Call,BTC,110_000);
 v.d.deposit_stable(channel(2),USDT,1_000_000_000).unwrap();
 v.d.deposit_stable(channel(1),USDT,30_000_000).unwrap();
 for n in [1,3]{v.d.fund_options(channel(n),2_000_000).unwrap();}
 v.post(2,put,false,CENT,25_000);v.post(3,call,true,1000,20_000);
 // Limits: pay at most $25 in USDT (first leg's asset), receive at least 20,000 sats.
 let mut i=v.intent(1,Action::Take,vec![leg(put,true,CENT),leg(call,false,1000)],25_000_000_000);
 i.other_limits=vec![AssetLimit{asset:BTC,premium_milli:-20_000_000}];
 let b=match v.send(i.signed(&sk(1)).unwrap()).unwrap(){OptionOutcome::Filled(b)=>*b,x=>panic!("{x:?}")};
 assert_eq!(b.clearing.iter().map(|c|c.asset).collect::<Vec<_>>(),vec![BTC,USDT]);
 for c in &b.clearing{assert_eq!(c.report.rows.iter().map(|r|r.net).sum::<i64>(),0);}
 // Collector 1: short call locked in BTC, the long put needs nothing; writer 2 in USDT.
 let naked=payoff::max_loss(&[short_call(1000,110_000)],Asset::Btc,domain());
 assert_eq!((v.btc(1).locked as u128,v.stable(1,USDT).locked),(naked,0));
 assert_eq!((v.btc(1).free,v.stable(1,USDT).free),(2_000_000+20_000-naked as u64,5_000_000));
 assert_eq!(v.stable(2,USDT).locked,899_990_000);
 assert!(v.d.options().unwrap().unwrap().fully_funded(&op(1)));
 // A missing per-asset limit, or a limit for an asset no leg settles in, is refused.
 rejected(v.take(1,vec![leg(put,true,1),leg(call,false,1)],1_000_000),TierReject::Bounds);
 v.check();
 // One expiry settles both assets in one batch.
 let e=v.d.expire_series(put,v.attest(&put,120_000)).unwrap();
 assert_eq!(e.clearing.len(),2);
 assert_eq!(e.clearing_of(&USDT).unwrap().rows.iter().map(|r|r.net).sum::<i64>(),0);
 v.check();
}

const ZSIG:shz_dlc::Bip340Signature=shz_dlc::Bip340Signature{r_x:[0;32],s:[0;32]};
/// Every lane of the staged batch signs its V4 message: owner (unless `owner` is false),
/// peer and monitor.
fn acks(v:&Desk,disposition:Disposition,owner:bool)->OptionAckBundle{
 let b=v.d.pending_option().unwrap().unwrap().clone();
 let acks=b.channels().into_iter().map(|c|{
  let n=c.txid[0];let h=v.d.option_ack_message(disposition,&c).unwrap();
  let o=if owner{shz_dlc::bip340_sign(&sk(n),&h).unwrap()}else{ZSIG};
  OptionAck{channel:c,signatures:[o,shz_dlc::bip340_sign(&sk(70+n),&h).unwrap(),shz_dlc::bip340_sign(&sk(90+n),&h).unwrap()]}
 }).collect();
 OptionAckBundle{sequence:b.sequence,batch:b.digest(),disposition,acks}
}
fn staged(v:&mut Desk,n:u8,legs:Vec<LegOrder>,limit:i64)->OptionBatch{
 match v.send(v.intent(n,Action::Take,legs,limit)).unwrap(){OptionOutcome::Staged(b)=>*b,x=>panic!("{x:?}")}
}

/// C3. With option acknowledgements on, a trade batch and an expiry batch are staged and
/// move nothing until owner, peer and monitor of every lane sign the lane's V4 message
/// (its per-asset clearing rows and the batch's clearing digests).
#[test]
fn d1_option_batches_commit_only_on_lane_acks(){
 let t=Temp::new();let mut v=stable_desk(&t.path());
 assert!(v.d.enable_combos().unwrap());
 let put=v.list(OptionKind::Put,USDT,90_000);let call=v.list(OptionKind::Call,BTC,110_000);
 v.d.deposit_stable(channel(2),USDT,1_000_000_000).unwrap();v.d.deposit_stable(channel(1),USDT,30_000_000).unwrap();
 for n in [1,3]{v.d.fund_options(channel(n),2_000_000).unwrap();}
 v.post(2,put,false,CENT,25_000);v.post(3,call,true,1000,20_000);
 assert!(v.d.enable_option_acks().unwrap());assert!(!v.d.enable_option_acks().unwrap());
 let before=(v.btc(1),v.stable(1,USDT),v.stable(2,USDT),v.btc(3));
 let mut i=v.intent(1,Action::Take,vec![leg(put,true,CENT),leg(call,false,1000)],25_000_000_000);
 i.other_limits=vec![AssetLimit{asset:BTC,premium_milli:-20_000_000}];
 let b=match v.send(i.signed(&sk(1)).unwrap()).unwrap(){OptionOutcome::Staged(b)=>*b,x=>panic!("{x:?}")};
 assert_eq!(b.channels(),vec![channel(1),channel(2),channel(3)]);
 assert_eq!((v.btc(1),v.stable(1,USDT),v.stable(2,USDT),v.btc(3)),before,"a staged batch moves nothing");
 // Every other option event waits.
 rejected(v.send(v.intent(2,Action::Post,vec![leg(put,false,1)],30_000)),TierReject::Hold);
 rejected(v.d.fund_options(channel(4),1),TierReject::Hold);
 rejected(v.d.expire_series(put,v.attest(&put,80_000)),TierReject::Hold);
 // Bad bundles: a lane missing, an owner signature over another lane's message, an
 // abort before the deadline, a commit without the owner.
 let mut bad=acks(&v,Disposition::Commit,true);bad.acks.pop();
 rejected(v.d.resolve_option(bad,v.now.get()),TierReject::Allocation);
 let mut bad=acks(&v,Disposition::Commit,true);bad.acks[0].signatures[0]=bad.acks[1].signatures[0];
 rejected(v.d.resolve_option(bad,v.now.get()),TierReject::Signature);
 rejected(v.d.resolve_option(acks(&v,Disposition::FencedAbort,false),v.now.get()),TierReject::Clock);
 rejected(v.d.resolve_option(acks(&v,Disposition::Commit,false),v.now.get()),TierReject::Signature);
 assert!(v.d.resolve_option(acks(&v,Disposition::Commit,true),v.now.get()).unwrap());
 assert!(v.d.pending_option().unwrap().is_none());
 assert_eq!(v.stable(2,USDT).locked,899_990_000);
 assert_eq!(v.stable(1,USDT).free,5_000_000);
 v.check();
 // The expiry batch is staged and acknowledged the same way.
 let e=v.d.expire_series(put,v.attest(&put,80_000)).unwrap();
 assert_eq!(v.d.pending_option().unwrap(),Some(&e));
 assert_eq!(v.stable(2,USDT).locked,899_990_000);
 assert!(v.d.resolve_option(acks(&v,Disposition::Commit,true),v.now.get()).unwrap());
 assert_eq!((v.stable(2,USDT).locked,v.stable(1,USDT).free),(0,105_000_000));
 v.check();
}

/// C3. A staged batch whose owner never signs is fence-aborted by peer and monitor once
/// `ABORT_AFTER_US` has passed: nothing moves, the maker's quote is pulled, the taker's
/// intent cannot be replayed; the journal replays to the same state.
#[test]
fn d2_staged_batch_aborts_after_the_deadline_and_replays(){
 let t=Temp::new();let path=t.path();
 let mut v=Desk::new(&path);
 let call=v.list(OptionKind::Call,BTC,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 v.post(2,call,false,1000,40_000);
 assert!(v.d.enable_option_acks().unwrap());
 // An intent that outlives the abort deadline.
 let mut i=v.intent(1,Action::Take,vec![leg(call,true,1000)],40_000_000);i.expires_us+=60_000_000;
 let i=i.signed(&sk(1)).unwrap();
 assert!(matches!(v.send(i.clone()).unwrap(),OptionOutcome::Staged(_)));
 let since=v.d.pending_option_since().unwrap().unwrap();
 rejected(v.d.resolve_option(acks(&v,Disposition::FencedAbort,false),since+ABORT_AFTER_US-1),TierReject::Clock);
 assert!(v.d.resolve_option(acks(&v,Disposition::FencedAbort,false),since+ABORT_AFTER_US).unwrap());
 assert_eq!((v.btc(1).free,v.btc(2).free,v.btc(2).locked),(5_000_000,5_000_000,0));
 assert!(v.d.options().unwrap().unwrap().depth(&call,false).is_empty());
 v.now.set(since+ABORT_AFTER_US);
 rejected(v.send(i),TierReject::Replay);
 // A second trade stages and commits.
 v.post(2,call,false,500,41_000);
 staged(&mut v,1,vec![leg(call,true,500)],1_000_000_000);
 assert!(v.d.resolve_option(acks(&v,Disposition::Commit,true),v.now.get()).unwrap());
 v.check();
 let snap=|d:&DurableTieredRouter|format!("{:?}|{:?}|{:?}",d.options().unwrap(),d.clearing_state().unwrap(),d.pending_option().unwrap());
 let before=snap(&v.d);let tip=v.d.tip().unwrap();drop(v);
 let d=DurableTieredRouter::open(&path,&registry(),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 assert_eq!(snap(&d),before);
}

/// C3. Recovery: a batch staged when the writer stops is still staged after the journal
/// reopens and resolves there; an exact retry of the resolving bundle is idempotent, a
/// conflicting one is refused.
#[test]
fn d3_staged_batch_survives_restart_and_retries_are_idempotent(){
 let t=Temp::new();let path=t.path();
 let mut v=Desk::new(&path);
 let call=v.list(OptionKind::Call,BTC,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 v.post(2,call,false,1000,40_000);
 assert!(v.d.enable_option_acks().unwrap());
 let b=staged(&mut v,1,vec![leg(call,true,1000)],40_000_000);
 let bundle=acks(&v,Disposition::Commit,true);
 let abort=acks(&v,Disposition::FencedAbort,false);
 let tip=v.d.tip().unwrap();
 let Desk{d,oracle,events,seq,now}=v;drop(d);
 let d=DurableTieredRouter::open(&path,&registry(),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 let mut v=Desk{d,oracle,events,seq,now};
 assert_eq!(v.d.pending_option().unwrap(),Some(&b));
 assert_eq!(v.btc(1).free,5_000_000);
 assert!(v.d.resolve_option(bundle.clone(),v.now.get()).unwrap());
 assert!(!v.d.resolve_option(bundle,v.now.get()).unwrap(),"exact retry is idempotent");
 rejected(v.d.resolve_option(abort,v.now.get()+ABORT_AFTER_US),TierReject::UnknownOrder);
 assert_eq!(v.btc(1).free,5_000_000-40_000);
 v.check();
}

/// A desk whose options oracle is the single key `sk(55)` (the unattestable notice is a
/// plain BIP340 signature by the oracle key), with a hand-built announcement for `event`.
fn plain_oracle_desk(path:&Path,event:&str)->(Desk,shz_dlc::OracleAnnouncement){
 let mut d=DurableTieredRouter::create(path,&registry(),cfg(),lanes(),recipients()).unwrap();
 assert!(d.enable_margin_release().unwrap());assert!(d.enable_clearing(1_000_000).unwrap());
 assert!(d.enable_options(pk(55),BITS).unwrap());
 let ann=shz_dlc::OracleAnnouncement{event_id:event.into(),maturity_unix:1_800_000_000,oracle_pubkey_x:pk(55),
  digit_nonces_x:(0..BITS).map(|j|pk(120+j)).collect()};
 let oracle=FrostConfederation::keygen_deterministic(2,3,&[0x51;32]).unwrap();
 (Desk{d,oracle,events:Vec::new(),seq:Cell::new(0),now:Cell::new(T0)},ann)
}

/// Gap 1. An event the oracle declares unattestable voids its series: legs return to their
/// pre-trade positions with no payoff, premiums stay paid, collateral is freed.
#[test]
fn e1_unattestable_notice_voids_the_event(){
 let t=Temp::new();let (mut v,ann)=plain_oracle_desk(&t.path(),"BTCUSD-U");
 let call=v.d.list_series(Series{kind:OptionKind::Call,asset:BTC,strike_usd:100_000,event_id:"BTCUSD-U".into()},ann.clone()).unwrap();
 let put=v.d.list_series(Series{kind:OptionKind::Put,asset:BTC,strike_usd:90_000,event_id:"BTCUSD-U".into()},ann).unwrap();
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 v.post(2,call,false,1000,40_000);v.post(1,put,true,1,5_000);
 v.take(1,vec![leg(call,true,1000)],40_000_000).unwrap();
 assert!(v.btc(2).locked>0);
 let msg=unattestable_message("BTCUSD-U");
 // Wrong key, wrong event: refused.
 rejected(v.d.void_event("BTCUSD-U".into(),shz_dlc::bip340_sign(&sk(56),&msg).unwrap()),TierReject::NoMark);
 rejected(v.d.void_event("BTCUSD-U".into(),shz_dlc::bip340_sign(&sk(55),&unattestable_message("BTCUSD-X")).unwrap()),TierReject::NoMark);
 rejected(v.d.void_event("BTCUSD-X".into(),shz_dlc::bip340_sign(&sk(55),&unattestable_message("BTCUSD-X")).unwrap()),TierReject::UnknownOrder);
 let b=v.d.void_event("BTCUSD-U".into(),shz_dlc::bip340_sign(&sk(55),&msg).unwrap()).unwrap();
 assert!(b.kind.is_void());assert!(matches!(&b.kind,OptionBatchKind::Expiry{series,price_usd:0,..} if series.len()==2));
 assert!(b.clearing_of(&BTC).unwrap().rows.iter().all(|r|r.net==0));
 assert_eq!((v.btc(1).free,v.btc(1).locked,v.btc(2).free,v.btc(2).locked),(5_000_000-40_000,0,5_000_000+40_000,0));
 assert!(v.legs(1).is_empty()&&v.legs(2).is_empty());
 let desk=v.d.options().unwrap().unwrap();
 assert_eq!(desk.series(&call).unwrap().1,Some(0));
 assert!(desk.depth(&put,true).is_empty(),"resting quotes on a void event are cancelled");
 rejected(v.d.void_event("BTCUSD-U".into(),shz_dlc::bip340_sign(&sk(55),&msg).unwrap()),TierReject::UnknownOrder);
 v.check();
}

/// Lane acks with the owner signature of `offline` left all-zero.
fn acks_without(v:&Desk,offline:&[u8])->OptionAckBundle{
 let mut b=acks(v,Disposition::Commit,true);
 for a in &mut b.acks{if offline.contains(&a.channel.txid[0]){a.signatures[0]=ZSIG;}}
 b
}

/// Gap 2. With `EnableOwnerlessExpiry`, an expiry batch commits on peer and monitor alone
/// when a holder is offline; before it, and for trade batches always, owners must sign.
#[test]
fn e2_offline_holder_cannot_hold_an_expiry(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let near=v.list_on(0,OptionKind::Call,BTC,100_000);
 let far=v.list_on(1,OptionKind::Call,BTC,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 v.post(2,near,false,1000,40_000);v.post(2,far,false,1000,40_000);
 assert!(v.d.enable_option_acks().unwrap());
 staged(&mut v,1,vec![leg(near,true,1000)],40_000_000);
 assert!(v.d.resolve_option(acks(&v,Disposition::Commit,true),v.now.get()).unwrap());
 staged(&mut v,1,vec![leg(far,true,1000)],40_000_000);
 assert!(v.d.resolve_option(acks(&v,Disposition::Commit,true),v.now.get()).unwrap());
 // Before the switch: an expiry with holder 1 offline is refused.
 v.d.expire_series(near,v.attest(&near,110_000)).unwrap();
 rejected(v.d.resolve_option(acks_without(&v,&[1]),v.now.get()),TierReject::Signature);
 assert!(v.d.resolve_option(acks(&v,Disposition::Commit,true),v.now.get()).unwrap());
 assert!(v.d.enable_ownerless_expiry().unwrap());assert!(!v.d.enable_ownerless_expiry().unwrap());
 // A trade batch still needs every owner.
 v.post(2,far,false,10,40_000);
 staged(&mut v,1,vec![leg(far,true,10)],1_000_000_000);
 rejected(v.d.resolve_option(acks_without(&v,&[1]),v.now.get()),TierReject::Signature);
 rejected(v.d.resolve_option(acks_without(&v,&[2]),v.now.get()),TierReject::Signature);
 assert!(v.d.resolve_option(acks(&v,Disposition::Commit,true),v.now.get()).unwrap());
 // The far expiry commits with both holders offline; peer and monitor still must sign.
 v.d.expire_series(far,v.attest(&far,120_000)).unwrap();
 let mut bad=acks_without(&v,&[1,2]);bad.acks[0].signatures[1]=ZSIG;
 rejected(v.d.resolve_option(bad,v.now.get()),TierReject::Signature);
 assert!(v.d.resolve_option(acks_without(&v,&[1,2]),v.now.get()).unwrap());
 assert_eq!((v.btc(1).locked,v.btc(2).locked),(0,0));
 assert!(v.legs(1).is_empty());
 v.check();
}
