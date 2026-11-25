//! Live venue registration: accounts join a running tiered router after creation.
use shz_dex::{OrderSide,routing::*};
use shz_dex::routing::durable::{FeeRecipients,Head,Lane};
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dlc::{Bip340Signature,BtcOutPoint};
use std::{fs,path::PathBuf,sync::atomic::{AtomicU64,Ordering}};

type Key=[u8;32];
const T0:u64=1_000_000;
const AUTH:[u8;32]=[77;32];
const RELAY:u8=60;
const PRICE:u64=10_000_000_000_000;
const CAP:u64=100_000_000;
const ZERO_SIG:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
fn sk(n:u8)->Key{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[pk(50),pk(51)]}}
fn registry()->Registry{
 let p=policy();
 let plans=(1..=2).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),CAP*2,vec![Share{router:1,sats:CAP},Share{router:2,sats:CAP}]).unwrap()).collect();
 Registry::new(p.scope(),public(&AUTH),plans).unwrap()
}
fn cfg()->TieredConfig{
 TieredConfig{scope:policy().scope(),router:1,entitlement_key:pk(RELAY),tariff:TariffSchedule::default_candidate(),
  execution:ExecutionPolicy::defaults(Arm::FeedOnly),revenue:RevenuePolicy::default()}
}
fn lane(n:u8)->Lane{Lane{channel:channel(n),peer:pk(70+n),monitor:pk(90+n),initial:Head{revision:0,commitment:10,state:[110+n;32]}}}
fn recipients()->FeeRecipients{FeeRecipients{oracle:pk(110),router:pk(111)}}
fn alloc(n:u8)->Allocation{
 Allocation::signed(policy().scope(),&sk(n),&AUTH,channel(n),CAP*2,vec![Share{router:1,sats:CAP}]).unwrap()
}
static COUNTER:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp{
 fn new()->Self{
  let p=std::env::temp_dir().join(format!("shz-venuereg-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn create(t:&Temp)->DurableTieredRouter{
 DurableTieredRouter::create(&t.0.join("j"),&registry(),cfg(),vec![lane(1),lane(2)],recipients()).unwrap()
}
fn open(t:&Temp)->DurableTieredRouter{
 DurableTieredRouter::open(&t.0.join("j"),&registry(),cfg(),vec![lane(1),lane(2)],recipients(),None).unwrap()
}
fn mark(seq:u64,t:u64)->MarkView{MarkView{packet_digest:[seq as u8+100;32],seq,price_e8:Some(PRICE),boundary_us:t,public_release_us:t}}
fn intent(n:u8,seq:u64,action:Action,side:OrderSide,q:u64)->IntentV6{
 let c=cfg();
 IntentV6{scope:c.scope,router:1,channel:channel(n),owner:[0;32],sequence:seq,expires_us:T0+10_000_000,action,side,tier:FeedTier::Standard,
  tariff_version:c.tariff.version,entitlement_digest:[0;32],execution_policy:c.execution.id(),
  quantity:q,limit_usd:100_000,leverage_bps:10_000,max_fee_ppm:c.tariff.rate_ppm(FeedTier::Standard,action),max_fee_sats:100_000,
  max_mark_age_us:1_000_000,early_window_opt_in:false,cancel_target:[0;32],signature:ZERO_SIG}.signed(&sk(n)).unwrap()
}
fn trade(d:&mut DurableTieredRouter,maker:u8,taker:u8){
 let t=T0;let now=t+200_000;
 d.ingest_mark(mark(1,t),t).unwrap();
 d.submit(intent(maker,1,Action::Post,OrderSide::Short,1000),None,now).unwrap();
 assert!(matches!(d.process_one(now).unwrap().unwrap(),TierOutcome::Posted(_)));
 d.submit(intent(taker,1,Action::Take,OrderSide::Long,1000),None,now).unwrap();
 assert!(matches!(d.process_one(now).unwrap().unwrap(),TierOutcome::Filled(_)));
}
fn rejected<X:std::fmt::Debug>(r:Result<X,TieredDurableError>)->TierReject{
 match r{Err(TieredDurableError::Rejected(e))=>e,o=>panic!("expected rejection, got {o:?}")}
}

#[test]
fn register_then_trade_with_new_account(){
 let t=Temp::new();let mut d=create(&t);
 d.register(alloc(3),lane(3)).unwrap();
 assert_eq!(d.balance(&channel(3)).unwrap().unwrap().cap,CAP);
 assert!(d.head(&channel(3)).unwrap().is_some());
 trade(&mut d,3,1);
 assert!(d.router().unwrap().fill_count()==1);
}
#[test]
fn restart_replays_registered_account(){
 let t=Temp::new();let mut d=create(&t);let cfg_hash=d.config_hash();
 d.register(alloc(3),lane(3)).unwrap();
 trade(&mut d,3,1);
 let bal=d.balance(&channel(3)).unwrap().unwrap();let tip=d.tip().unwrap();
 drop(d);
 let d=open(&t);
 assert_eq!(d.config_hash(),cfg_hash);
 assert_eq!(d.tip().unwrap(),tip);
 assert_eq!(d.balance(&channel(3)).unwrap().unwrap(),bal);
 assert_eq!(d.router().unwrap().fill_count(),1);
 assert!(d.head(&channel(3)).unwrap().is_some());
}
#[test]
fn journal_without_register_events_opens_unchanged(){
 let t=Temp::new();let mut d=create(&t);
 trade(&mut d,1,2);
 let (tip,bal)=(d.tip().unwrap(),d.balance(&channel(1)).unwrap().unwrap());
 drop(d);
 let d=open(&t);
 assert_eq!(d.tip().unwrap(),tip);
 assert_eq!(d.balance(&channel(1)).unwrap().unwrap(),bal);
}
#[test]
fn duplicate_outpoint_rejected(){
 let t=Temp::new();let mut d=create(&t);
 d.register(alloc(3),lane(3)).unwrap();
 assert_eq!(rejected(d.register(alloc(3),lane(3))),TierReject::Allocation);
 assert_eq!(rejected(d.register(alloc(1),lane(1))),TierReject::Allocation);
}
#[test]
fn wrong_authority_signature_rejected(){
 let t=Temp::new();let mut d=create(&t);
 let bad=Allocation::signed(policy().scope(),&sk(3),&sk(88),channel(3),CAP*2,vec![Share{router:1,sats:CAP}]).unwrap();
 assert_eq!(rejected(d.register(bad,lane(3))),TierReject::Signature);
 assert!(d.balance(&channel(3)).unwrap().is_none());
}
#[test]
fn wrong_scope_rejected(){
 let t=Temp::new();let mut d=create(&t);
 let mut s=policy().scope();s.epoch+=1;
 let bad=Allocation::signed(s,&sk(3),&AUTH,channel(3),CAP*2,vec![Share{router:1,sats:CAP}]).unwrap();
 assert_eq!(rejected(d.register(bad,lane(3))),TierReject::Scope);
}
#[test]
fn missing_owner_signature_rejected(){
 let t=Temp::new();let mut d=create(&t);
 let a=alloc(3);
 let bad=Allocation::from_parts(a.scope,a.owner,a.channel,a.total_sats,a.shares.clone(),ZERO_SIG,a.authority_sig);
 assert_eq!(rejected(d.register(bad,lane(3))),TierReject::Signature);
 assert!(d.balance(&channel(3)).unwrap().is_none());
}
#[test]
fn no_share_for_this_router_rejected(){
 let t=Temp::new();let mut d=create(&t);
 let a=Allocation::signed(policy().scope(),&sk(3),&AUTH,channel(3),CAP*2,vec![Share{router:2,sats:CAP}]).unwrap();
 assert_eq!(rejected(d.register(a,lane(3))),TierReject::Allocation);
}
#[test]
fn lane_with_peer_equal_owner_rejected(){
 let t=Temp::new();let mut d=create(&t);
 let mut l=lane(3);l.peer=pk(3);
 assert_eq!(rejected(d.register(alloc(3),l)),TierReject::Allocation);
 assert!(d.balance(&channel(3)).unwrap().is_none());
 let mut l=lane(3);l.initial.revision=1;
 assert_eq!(rejected(d.register(alloc(3),l)),TierReject::Allocation);
 // rejected registrations replay as rejected
 let tip=d.tip().unwrap();drop(d);
 let d=open(&t);
 assert_eq!(d.tip().unwrap(),tip);
 assert!(d.balance(&channel(3)).unwrap().is_none());
}
#[test]
fn router_register_direct(){
 let mut r=TieredRouter::new(&registry(),cfg()).unwrap();
 assert!(r.balance(&channel(3)).is_none());
 r.register(alloc(3),&public(&AUTH)).unwrap();
 assert_eq!(r.balance(&channel(3)).unwrap().free,CAP);
 assert_eq!(r.register(alloc(4),&public(&sk(88))),Err(TierReject::Signature));
 let a=alloc(4);assert!(a.digest().is_ok());
}
