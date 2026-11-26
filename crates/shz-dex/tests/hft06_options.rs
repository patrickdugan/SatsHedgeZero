//! Options desk on the durable tiered router (docs/SHZ_OPTIONS_COMBOS.md): listed series,
//! `IntentV7` orders, worst-case-loss margin, premium and expiry through the clearing
//! ledger, journal replay. Synthetic funds and a deterministic test oracle only.
use shz_dex::routing::*;
use shz_dex::routing::durable::{FeeRecipients,Head,Lane};
use shz_dex::routing::options::*;
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dlc::{BtcOutPoint,OracleAttestation};
use shz_margin::payoff::{self,Asset,Leg,OptionKind,PriceDomain};
use shz_margin::CollateralAsset;
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
 fn list(&mut self,kind:OptionKind,asset:Asset,strike:u64)->Key{self.list_on(0,kind,asset,strike)}
 /// List a series on oracle event `ev` (announced on first use).
 fn list_on(&mut self,ev:u8,kind:OptionKind,asset:Asset,strike:u64)->Key{
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
   expires_us:self.now.get()+5_000_000,action,legs,premium_milli,cancel_target:[0;32],
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
 fn legs(&self,n:u8)->Vec<Leg>{self.d.options().unwrap().unwrap().legs(&op(n))}
 /// Invariants after every step: locked collateral is exactly the worst-case loss per
 /// asset, every perpetual balance is conserved, the clearing identity holds, and every
 /// sat realized anywhere came out of (or went into) the pool.
 fn check(&self){
  let desk=self.d.options().unwrap().unwrap();
  let mut realized=0i128;
  for n in 1..=N{
   let a=self.acct(n);
   // Legs offset only within one expiry.
   let groups=desk.legs_by_event(&op(n));
   for (asset,locked) in [(Asset::Btc,a.btc_locked),(Asset::Usd,a.usd_locked)]{
    assert_eq!(locked as u128,groups.values().map(|g|payoff::max_loss(g,asset,domain())).sum::<u128>(),"{n}");
   }
   assert!(desk.fully_funded(&op(n)));
   let b=self.d.balance(&channel(n)).unwrap().unwrap();assert!(b.conserved());
   realized+=b.realized_pnl as i128+a.realized_btc as i128;
  }
  let s=self.d.clearing_summary().unwrap().unwrap();
  assert_eq!(s.identity,0,"{s:?}");
  assert_eq!(realized+s.cash as i128,s.fund0 as i128,"{s:?}");
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
 let call=v.list(OptionKind::Call,Asset::Btc,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 let b=v.d.balance(&channel(1)).unwrap().unwrap();
 assert_eq!((b.cap,b.free,v.acct(1).btc_free),(CAP-5_000_000,CAP-5_000_000,5_000_000));
 // 2 writes 1,000 USD of the call at 40 sats per USD; 1 buys it.
 v.post(2,call,false,1000,40_000);
 let batch=v.take(1,vec![leg(call,true,1000)],40_000_000).unwrap();
 assert_eq!(batch.fills.len(),1);assert_eq!(batch.fills[0].premium,40_000);
 let worst=payoff::max_loss(&[Leg::InverseOption{kind:OptionKind::Call,long:false,qty_usd:1000,strike_usd:100_000,premium_sats:0}],Asset::Btc,domain());
 // Q*1e8*(1/K - 1/p_max), the call at the top of the 20-bit domain.
 assert_eq!(worst as i128,-payoff::pnl(&[Leg::InverseOption{kind:OptionKind::Call,long:false,qty_usd:1000,strike_usd:100_000,premium_sats:0}],Asset::Btc,domain().p_max));
 assert_eq!(worst,904_633);
 let (a1,a2)=(v.acct(1),v.acct(2));
 assert_eq!((a1.btc_free,a1.btc_locked,a1.realized_btc),(5_000_000-40_000,0,-40_000));
 assert_eq!((a2.btc_free,a2.btc_locked as u128,a2.realized_btc),(5_000_000+40_000-worst as u64,worst,40_000));
 let c=&batch.clearing;
 assert_eq!(c.rows.iter().map(|r|r.net).sum::<i64>()+c.pool_net(),0);assert_eq!(c.pool_net(),0);
 v.check();
 // Expiry at 110,000: the long gets the floor of its payoff, the short pays the ceiling.
 let pays=call_pays(1000,100_000,110_000) as u64;
 let e=v.d.expire_series(call,v.attest(&call,110_000)).unwrap();
 assert!(matches!(e.kind,OptionBatchKind::Expiry{price_usd:110_000,..}));
 let dust=e.clearing.pool_net();assert!((0..=1).contains(&dust),"{dust}");
 let (a1,a2)=(v.acct(1),v.acct(2));
 assert_eq!((a1.btc_free,a1.btc_locked),(5_000_000-40_000+pays,0));
 assert_eq!((a2.btc_free,a2.btc_locked),(5_000_000+40_000-pays-dust as u64,0));
 assert!(v.legs(1).is_empty()&&v.legs(2).is_empty());
 v.check();
 // Collateral goes back to the perpetual allocation.
 v.d.defund_options(channel(1),a1.btc_free).unwrap();
 let b=v.d.balance(&channel(1)).unwrap().unwrap();
 assert_eq!((b.cap,v.acct(1).btc_free),(CAP-5_000_000+a1.btc_free,0));
 // An expired series no longer trades or expires again.
 rejected(v.d.expire_series(call,v.attest(&call,110_000)),TierReject::Expired);
 rejected(v.send(v.intent(2,Action::Post,vec![leg(call,false,1)],1000)),TierReject::Expired);
 v.check();
}

/// B1. Out of the money: nothing is paid, the writer keeps the premium, collateral frees.
#[test]
fn b1_expiry_out_of_the_money_frees_collateral(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let call=v.list(OptionKind::Call,Asset::Btc,100_000);
 for n in [1,2,3]{v.d.fund_options(channel(n),3_000_000).unwrap();}
 // Two writers at different premiums; the taker sweeps the best first.
 v.post(2,call,false,500,30_000);v.post(3,call,false,1000,35_000);
 let b=v.take(1,vec![leg(call,true,800)],1_000_000_000).unwrap();
 assert_eq!(b.fills.iter().map(|f|(f.qty,f.premium)).collect::<Vec<_>>(),vec![(500,15_000),(300,10_500)]);
 assert_eq!(v.d.options().unwrap().unwrap().depth(&call,false)[0].2,700);
 v.check();
 let e=v.d.expire_series(call,v.attest(&call,99_000)).unwrap();
 assert!(e.clearing.rows.iter().all(|r|r.net==0));
 assert_eq!((v.acct(2).btc_free,v.acct(3).btc_free,v.acct(1).btc_free),(3_015_000,3_010_500,3_000_000-25_500));
 assert!(v.d.options().unwrap().unwrap().depth(&call,false).is_empty());
 v.check();
}

/// B1. Admission: version, signature, replay, crossing posts, premium limit, capacity,
/// unfunded makers dropped, combos refused until enabled, attestation checked.
#[test]
fn b1_rejections(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let call=v.list(OptionKind::Call,Asset::Btc,100_000);
 let other=v.list_on(1,OptionKind::Call,Asset::Btc,105_000);
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
 let call=v.list(OptionKind::Call,Asset::Btc,100_000);
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
 let deep=v.list(OptionKind::Call,Asset::Btc,50_000);
 let c100=v.list(OptionKind::Call,Asset::Btc,100_000);
 let c110=v.list(OptionKind::Call,Asset::Btc,110_000);
 let p90=v.list(OptionKind::Put,Asset::Btc,90_000);
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
 assert_eq!(v.acct(1).btc_locked as u128,spread);
 assert_eq!(v.acct(1).btc_free,40_000_000-40_000-90_910);
 v.check();
 // Both legs share one expiry: at 120k the spread pays its full width in one amount.
 assert_eq!(-payoff::pnl(&v.legs(1),Asset::Btc,120_000),90_910);
 let e=v.d.expire_series(c100,v.attest(&c100,120_000)).unwrap();
 assert!(matches!(&e.kind,OptionBatchKind::Expiry{series,..} if series.len()==4));
 let a=v.acct(1);
 assert_eq!((a.btc_locked,a.btc_free,a.realized_btc),(0,40_000_000-40_000-90_910,-40_000-90_910));
 assert!(v.legs(1).is_empty());
 v.check();
}

/// B2. Covered call with a deep in-the-money call as the cover: selling the 110k call
/// against a long 50k call needs no collateral beyond the net premium.
#[test]
fn b2_covered_call(){
 let t=Temp::new();let (mut v,deep,_,c110,_)=combo_desk(&t.path());
 v.take(1,vec![leg(deep,true,2000),leg(c110,false,2000)],80_000_000).unwrap();
 assert_eq!(v.acct(1).btc_locked,0);
 assert_eq!(v.acct(1).btc_free,40_000_000-(120_000-40_000));
 // The 50k call covers up to 4,400 USD of 110k calls (2000/50k = 4400/110k as P grows);
 // selling 3,000 more (5,000 in all) locks the uncovered worst case.
 v.take(1,vec![leg(c110,false,3000)],-60_000_000).unwrap();
 assert_eq!(v.acct(1).btc_locked as u128,payoff::max_loss(&v.legs(1),Asset::Btc,domain()));
 assert!(v.acct(1).btc_locked>0);
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
 assert_eq!((v.acct(1).btc_locked,v.acct(1).btc_free),(0,40_000_000-50));
 assert_eq!(v.acct(3).btc_locked,99_998_889);
 let c=&b.clearing;assert_eq!(c.rows.iter().map(|r|r.net).sum::<i64>(),0);
 v.check();
}

/// B2. All-or-none: a combo with one unfillable leg, or over its net premium limit,
/// changes nothing; duplicate series and more than `MAX_LEGS` legs are refused.
#[test]
fn b2_all_or_none(){
 let t=Temp::new();let (mut v,deep,c100,c110,p90)=combo_desk(&t.path());
 let snap=|v:&Desk|{
  let d=v.d.options().unwrap().unwrap();
  format!("{:?}|{:?}",(1..=N).map(|n|v.acct(n)).collect::<Vec<_>>(),[deep,c100,c110,p90].iter().map(|s|(d.depth(s,true),d.depth(s,false))).collect::<Vec<_>>())
 };
 let before=snap(&v);
 rejected(v.take(1,vec![leg(c100,true,1000),leg(c110,false,6000)],1_000_000_000),TierReject::NoLiquidity);
 rejected(v.take(1,vec![leg(c100,true,1000),leg(c110,false,1000)],39_999_999),TierReject::FeeLimit);
 rejected(v.take(1,vec![leg(c100,true,1),leg(c100,true,1)],1_000_000_000),TierReject::Bounds);
 rejected(v.take(1,vec![leg(c100,true,1),leg(c110,true,1),leg(deep,true,1),leg(p90,true,1),leg(c100,false,1)],1_000_000_000),TierReject::Bounds);
 assert_eq!(snap(&v),before);
 v.check();
}

const TAP:CollateralAsset=CollateralAsset::TaprootAsset{asset_id:[0x7a;32],group_key:None,script_version:0};
const RGB:CollateralAsset=CollateralAsset::Rgb{contract_id:[0x52;32]};
/// 0.01 BTC in 1e-8 BTC units, the size of a linear option leg in these tests.
const CENT:u64=1_000_000;
fn usd_desk(path:&Path)->Desk{
 let mut v=Desk::new(path);
 rejected(v.d.deposit_usd(channel(1),TAP,1),TierReject::Scope);
 assert!(v.d.enable_usd_collateral().unwrap());assert!(!v.d.enable_usd_collateral().unwrap());
 v
}

/// C. A USD cash-secured put: the writer locks strike times size in USD (micro-USD) on its
/// RGB rail, the buyer pays USD premium, and expiry pays the put in USD through its own
/// clearing line; BTC collateral and the BTC pool are untouched.
#[test]
fn c1_usd_cash_secured_put(){
 let t=Temp::new();let mut v=usd_desk(&t.path());
 let put=v.list(OptionKind::Put,Asset::Usd,90_000);
 v.d.deposit_usd(channel(2),RGB,2_000_000_000).unwrap();   // $2,000 on RGB
 v.d.deposit_usd(channel(1),TAP,100_000_000).unwrap();     // $100 on Taproot Assets
 // Writer 2: 0.01 BTC put at $90k; premium $25 = 25e6 micro-USD over 1e6 units = 25,000 milli.
 v.post(2,put,false,CENT,25_000);
 let b=v.take(1,vec![leg(put,true,CENT)],25_000_000_000).unwrap();
 assert_eq!((b.asset,b.fills[0].premium),(Asset::Usd,25_000_000));
 // Cash-secured: Q*(K - p_min) = 0.01 * 89,999 USD.
 assert_eq!(v.acct(2).usd_locked,899_990_000);
 assert_eq!((v.acct(2).usd_free,v.acct(1).usd_free),(2_000_000_000+25_000_000-899_990_000,75_000_000));
 assert_eq!((v.acct(1).btc_locked,v.acct(2).btc_locked),(0,0));
 let cash=v.d.clearing_state().unwrap().unwrap().cash;
 v.check();
 // Expiry at $80k pays 0.01 * 10,000 = $100.
 let e=v.d.expire_series(put,v.attest(&put,80_000)).unwrap();
 assert_eq!(e.clearing.rows.iter().map(|r|(r.channel.txid[0],r.net)).collect::<Vec<_>>(),vec![(1,100_000_000),(2,-100_000_000)]);
 assert_eq!((v.acct(1).usd_free,v.acct(2).usd_free,v.acct(2).usd_locked),(175_000_000,1_925_000_000,0));
 assert_eq!(v.d.clearing_state().unwrap().unwrap().cash,cash);
 v.d.withdraw_usd(channel(2),1_925_000_000).unwrap();
 rejected(v.d.withdraw_usd(channel(2),1),TierReject::Capacity);
 v.check();
}

/// C. Per-asset margin, no cross-asset netting: BTC collateral cannot secure a USD put,
/// a combo cannot mix assets, and an account keeps one USD rail.
#[test]
fn c2_assets_do_not_net(){
 let t=Temp::new();let mut v=usd_desk(&t.path());
 let put=v.list(OptionKind::Put,Asset::Usd,90_000);
 let call=v.list(OptionKind::Call,Asset::Btc,100_000);
 v.d.fund_options(channel(2),CAP).unwrap();
 v.d.deposit_usd(channel(1),TAP,100_000_000).unwrap();
 v.post(2,put,false,CENT,25_000);
 // Writer 2 holds a whole bitcoin of option collateral and no USD: the put is unsecured.
 rejected(v.take(1,vec![leg(put,true,CENT)],25_000_000_000),TierReject::NoLiquidity);
 assert!(v.d.enable_combos().unwrap());
 v.post(3,call,false,10,1_000);v.post(2,put,false,CENT,25_000);
 rejected(v.take(1,vec![leg(put,true,CENT),leg(call,true,10)],1_000_000_000_000),TierReject::Bounds);
 // Rails: one per account; vanilla BTC is not a USD rail.
 rejected(v.d.deposit_usd(channel(1),RGB,1),TierReject::Scope);
 rejected(v.d.deposit_usd(channel(3),CollateralAsset::VanillaBtc,1),TierReject::Bounds);
 assert!(v.d.options().unwrap().unwrap().fully_funded(&([1;32],0)));
 v.check();
}

/// C. The BTC-only alternative to a USD put: a put spread. Each side's worst case is the
/// spread's (`Q*1e8*(1/80k - 1/90k)` for the seller, nothing for the buyer), not the naked
/// put's almost-a-bitcoin per USD, so it trades with ordinary BTC collateral.
#[test]
fn c3_btc_put_spread(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 let p80=v.list(OptionKind::Put,Asset::Btc,80_000);
 let p90=v.list(OptionKind::Put,Asset::Btc,90_000);
 for n in [1,2]{v.d.fund_options(channel(n),2_000_000).unwrap();}
 assert!(v.d.enable_combos().unwrap());
 // 2 quotes the spread's two legs: bids the 90k put, offers the 80k put.
 v.post(2,p90,true,1000,60_000);v.post(2,p80,false,1000,20_000);
 // 1 sells the spread: sells the 90k put, buys the 80k put, for a 40 sats/USD credit.
 v.take(1,vec![leg(p90,false,1000),leg(p80,true,1000)],-40_000_000).unwrap();
 assert_eq!(v.acct(1).btc_locked,138_889);
 assert_eq!(v.acct(2).btc_locked,0);
 assert_eq!(v.acct(1).btc_free,2_000_000+40_000-138_889);
 let naked=payoff::max_loss(&[Leg::InverseOption{kind:OptionKind::Put,long:false,qty_usd:1000,strike_usd:90_000,premium_sats:0}],Asset::Btc,domain());
 assert!(naked>99_000_000_000,"{naked}");
 v.check();
 // Both legs expire together at 85k: the 90k put pays, the 80k put does not.
 v.d.expire_series(p80,v.attest(&p80,85_000)).unwrap();
 let owed=payoff::pnl(&[Leg::InverseOption{kind:OptionKind::Put,long:true,qty_usd:1000,strike_usd:90_000,premium_sats:0}],Asset::Btc,85_000);
 assert_eq!(owed,65_359);
 assert_eq!((v.acct(1).btc_locked,v.acct(1).btc_free),(0,2_000_000+40_000-65_360));
 v.check();
}

/// Legs on different expiries do not offset: a long call on one event cannot cover a
/// short call on another, so expiring the first never leaves the second underfunded.
#[test]
fn c4_legs_offset_only_within_one_expiry(){
 let t=Temp::new();let mut v=Desk::new(&t.path());
 assert!(v.d.enable_combos().unwrap());
 let near=v.list_on(0,OptionKind::Call,Asset::Btc,100_000);
 let far=v.list_on(1,OptionKind::Call,Asset::Btc,100_000);
 for n in [1,2]{v.d.fund_options(channel(n),5_000_000).unwrap();}
 v.post(2,near,false,1000,40_000);v.post(2,far,true,1000,30_000);
 v.take(1,vec![leg(near,true,1000),leg(far,false,1000)],10_000_000).unwrap();
 assert_eq!(v.acct(1).btc_locked as u128,payoff::max_loss(&[short_call(1000,100_000)],Asset::Btc,domain()));
 v.check();
 v.d.expire_series(near,v.attest(&near,120_000)).unwrap();
 v.check();
 v.d.expire_series(far,v.attest(&far,90_000)).unwrap();
 assert_eq!((v.acct(1).btc_locked,v.acct(2).btc_locked),(0,0));
 v.check();
}
