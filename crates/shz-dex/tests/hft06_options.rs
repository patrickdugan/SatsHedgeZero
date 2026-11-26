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
 /// List a series on a fresh oracle event; returns its id.
 fn list(&mut self,kind:OptionKind,asset:Asset,strike:u64)->Key{
  let event=format!("BTCUSD-{}",self.events.len());
  let ns=self.oracle.announce_event(&event,1_800_000_000,BITS,&[self.events.len() as u8;32]).unwrap();
  let id=self.d.list_series(Series{kind,asset,strike_usd:strike,event_id:event},ns.announcement.clone()).unwrap();
  self.events.push(ns);id
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
   assert_eq!(a.btc_locked as u128,payoff::max_loss(&self.legs(n),Asset::Btc,domain()),"{n}");
   assert_eq!(a.usd_locked as u128,payoff::max_loss(&self.legs(n),Asset::Usd,domain()),"{n}");
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
 let other=v.list(OptionKind::Call,Asset::Btc,105_000);
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
