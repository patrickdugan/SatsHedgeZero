use shz_dex::{OrderSide,routing::*};
use shz_dex::routing::tiered::*;
use shz_dlc::{BtcOutPoint,tagged_hash};

const T0:u64=1_000_000;
const AUTH:[u8;32]=[77;32];
const RELAY:u8=60;
const PRICE:u64=10_000_000_000_000;
fn sk(n:u8)->[u8;32]{[n;32]}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[public(&sk(50)),public(&sk(51))]}}
fn setup(arm:Arm,tariff:TariffSchedule)->(Policy,TieredRouter){
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),200_000_000,vec![Share{router:1,sats:100_000_000},Share{router:2,sats:100_000_000}]).unwrap()).collect();
 let g=Registry::new(p.scope(),public(&AUTH),plans).unwrap();
 let cfg=TieredConfig{scope:p.scope(),router:1,entitlement_key:public(&sk(RELAY)),tariff,execution:ExecutionPolicy::defaults(arm),revenue:RevenuePolicy::default()};
 (p,TieredRouter::new(&g,cfg).unwrap())
}
fn mark(seq:u64,boundary:u64,release:u64,price:Option<u64>)->MarkView{
 MarkView{packet_digest:[seq as u8+100;32],seq,price_e8:price,boundary_us:boundary,public_release_us:release}
}
fn grant(n:u8,tier:FeedTier)->Entitlement{
 Entitlement{client:public(&sk(n)),tier,tariff_version:1,valid_from_us:0,valid_until_us:T0+50_000_000,relay_key:[0;32],signature:ZERO_SIG}.signed(&sk(RELAY)).unwrap()
}
#[allow(clippy::too_many_arguments)]
fn build(t:&TieredRouter,p:&Policy,n:u8,seq:u64,action:Action,side:OrderSide,tier:FeedTier,q:u64,opt_in:bool,ent:Option<&Entitlement>)->IntentV6{
 let tariff=*t.tariff();
 IntentV6{scope:p.scope(),router:1,channel:channel(n),owner:[0;32],sequence:seq,expires_us:T0+10_000_000,action,side,tier,
  tariff_version:tariff.version,entitlement_digest:ent.map(|e|e.digest()).unwrap_or([0;32]),execution_policy:t.execution_policy_id(),
  quantity:q,limit_usd:100_000,leverage_bps:10_000,max_fee_ppm:tariff.rate_ppm(tier,action),max_fee_sats:100_000,
  max_mark_age_us:1_000_000,early_window_opt_in:opt_in,cancel_target:[0;32],signature:ZERO_SIG}
}
#[allow(clippy::too_many_arguments)]
fn premium(t:&TieredRouter,p:&Policy,n:u8,seq:u64,action:Action,side:OrderSide,q:u64,opt_in:bool)->(IntentV6,Entitlement){
 let e=grant(n,FeedTier::Premium);
 (build(t,p,n,seq,action,side,FeedTier::Premium,q,opt_in,Some(&e)).signed(&sk(n)).unwrap(),e)
}
fn cancel_of(t:&TieredRouter,p:&Policy,n:u8,seq:u64,tier:FeedTier,target:Key,ent:Option<&Entitlement>)->IntentV6{
 let mut i=build(t,p,n,seq,Action::Cancel,OrderSide::Short,tier,0,false,ent);
 i.limit_usd=0;i.leverage_bps=0;i.max_fee_sats=0;i.max_fee_ppm=0;i.max_mark_age_us=0;i.cancel_target=target;i.signed(&sk(n)).unwrap()
}
type Key=[u8;32];
fn run(t:&mut TieredRouter,now:u64)->TierOutcome{t.process_one(now).unwrap().unwrap()}
fn post(t:&mut TieredRouter,i:IntentV6,e:&Entitlement,now:u64)->Key{
 t.submit(i,Some(e),now).unwrap();
 match run(t,now){TierOutcome::Posted(id)=>id,o=>panic!("expected post, got {o:?}")}
}

#[test]fn tariff_defaults_and_intermediate_maker_configurable(){
 let d=TariffSchedule::default_candidate();
 assert_eq!((d.maker_ppm,d.taker_ppm),([0,0,20],[0,50,200]));d.validate().unwrap();
 assert_eq!(d.rate_ppm(FeedTier::Intermediate,Action::Take),50);assert_eq!(d.rate_ppm(FeedTier::Premium,Action::Cancel),0);
 let c=d.with_intermediate_maker(10);c.validate().unwrap();assert_ne!(c.id(),d.id());assert_eq!(c.maker_ppm[1],10);
 assert_eq!(d.with_intermediate_maker(51).validate(),Err(TierReject::Bounds));
 let mut over=d;over.taker_ppm[2]=201;assert_eq!(over.validate(),Err(TierReject::Bounds));
 let mut changed=d;changed.version=2;assert_ne!(changed.id(),d.id());
}

#[test]fn admission_rejections_scope_signature_replay_tariff_policy_expiry(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let (ok,e)=premium(&t,&p,1,1,Action::Post,OrderSide::Short,100,false);
 let mut wrong=ok.clone();wrong.router=2;assert_eq!(t.submit(wrong.signed(&sk(1)).unwrap(),Some(&e),T0),Err(TierReject::Scope));
 let mut tampered=ok.clone();tampered.max_fee_sats+=1;assert_eq!(t.submit(tampered,Some(&e),T0),Err(TierReject::Signature));
 let mut v=ok.clone();v.tariff_version=9;assert_eq!(t.submit(v.signed(&sk(1)).unwrap(),Some(&e),T0),Err(TierReject::TariffVersion));
 let mut pol=ok.clone();pol.execution_policy=[5;32];assert_eq!(t.submit(pol.signed(&sk(1)).unwrap(),Some(&e),T0),Err(TierReject::PolicyMismatch));
 let mut exp=ok.clone();exp.expires_us=T0;assert_eq!(t.submit(exp.signed(&sk(1)).unwrap(),Some(&e),T0),Err(TierReject::Expired));
 let mut late=ok.clone();late.expires_us=T0+100_000;late=late.signed(&sk(1)).unwrap();
 let (s,se)=(build(&t,&p,2,1,Action::Post,OrderSide::Short,FeedTier::Standard,10,false,None),None::<&Entitlement>);
 let mut s=s;s.expires_us=T0+100_000;let s=s.signed(&sk(2)).unwrap();
 // Standard order delay is 0 under FeedOnly, so the same expiry is acceptable.
 assert!(t.submit(s,se,T0).is_ok());assert!(t.submit(late,Some(&e),T0).is_ok());
 assert_eq!(t.submit(ok.clone(),Some(&e),T0),Err(TierReject::Replay));
 // Non-owner channel owner mismatch.
 let mut thief=build(&t,&p,3,1,Action::Post,OrderSide::Short,FeedTier::Standard,10,false,None);thief.channel=channel(4);
 assert_eq!(t.submit(thief.signed(&sk(3)).unwrap(),None,T0),Err(TierReject::Allocation));
}

#[test]fn expiry_before_due_time_uses_tier_order_delay(){
 let (p,mut t)=setup(Arm::SchedulerOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let mut s=build(&t,&p,1,1,Action::Post,OrderSide::Short,FeedTier::Standard,10,false,None);s.expires_us=T0+200_000;
 assert_eq!(t.submit(s.signed(&sk(1)).unwrap(),None,T0),Err(TierReject::Expired));
 let mut s=build(&t,&p,1,1,Action::Post,OrderSide::Short,FeedTier::Standard,10,false,None);s.expires_us=T0+200_001;
 assert_eq!(t.submit(s.signed(&sk(1)).unwrap(),None,T0),Ok(T0+200_000));
}

#[test]fn fee_cap_below_tariff_is_rejected(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let e=grant(2,FeedTier::Premium);
 let mut i=build(&t,&p,2,1,Action::Take,OrderSide::Long,FeedTier::Premium,10,false,Some(&e));i.max_fee_ppm=199;
 assert_eq!(t.submit(i.signed(&sk(2)).unwrap(),Some(&e),T0),Err(TierReject::FeeLimit));
 let e=grant(3,FeedTier::Intermediate);
 let mut i=build(&t,&p,3,1,Action::Take,OrderSide::Long,FeedTier::Intermediate,10,false,Some(&e));i.max_fee_ppm=49;
 assert_eq!(t.submit(i.signed(&sk(3)).unwrap(),Some(&e),T0),Err(TierReject::FeeLimit));
 let mut i=build(&t,&p,3,2,Action::Take,OrderSide::Long,FeedTier::Intermediate,10,false,Some(&e));i.max_fee_ppm=50;
 assert!(t.submit(i.signed(&sk(3)).unwrap(),Some(&e),T0).is_ok());
}

#[test]fn entitlement_enforcement(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let good=grant(1,FeedTier::Premium);
 let mk=|t:&TieredRouter,seq,e:&Entitlement|build(t,&p,1,seq,Action::Post,OrderSide::Short,FeedTier::Premium,10,false,Some(e)).signed(&sk(1)).unwrap();
 // missing
 assert_eq!(t.submit(mk(&t,1,&good),None,T0),Err(TierReject::EntitlementMissing));
 // standard may not carry an entitlement digest, premium may not carry none
 let no_digest=build(&t,&p,1,1,Action::Post,OrderSide::Short,FeedTier::Premium,10,false,None).signed(&sk(1)).unwrap();
 assert_eq!(t.submit(no_digest,Some(&good),T0),Err(TierReject::EntitlementMissing));
 // expired and not yet valid
 let mut old=Entitlement{valid_until_us:T0,..good.clone()};old=old.signed(&sk(RELAY)).unwrap();
 assert_eq!(t.submit(mk(&t,1,&old),Some(&old),T0),Err(TierReject::EntitlementExpired));
 let mut future=Entitlement{valid_from_us:T0+1,..good.clone()};future=future.signed(&sk(RELAY)).unwrap();
 assert_eq!(t.submit(mk(&t,1,&future),Some(&future),T0),Err(TierReject::EntitlementExpired));
 // wrong tier
 let wrong_tier=grant(1,FeedTier::Intermediate);
 assert_eq!(t.submit(mk(&t,1,&wrong_tier),Some(&wrong_tier),T0),Err(TierReject::EntitlementTier));
 // wrong client
 let other=grant(2,FeedTier::Premium);
 assert_eq!(t.submit(mk(&t,1,&other),Some(&other),T0),Err(TierReject::EntitlementClient));
 // forged: signed by a different key, and tampered after signing
 let forged=Entitlement{client:public(&sk(1)),tier:FeedTier::Premium,tariff_version:1,valid_from_us:0,valid_until_us:T0+9_000_000,relay_key:[0;32],signature:ZERO_SIG}.signed(&sk(61)).unwrap();
 assert_eq!(t.submit(mk(&t,1,&forged),Some(&forged),T0),Err(TierReject::EntitlementSignature));
 let mut tampered=good.clone();tampered.valid_until_us+=1;
 assert_eq!(t.submit(mk(&t,1,&tampered),Some(&tampered),T0),Err(TierReject::EntitlementSignature));
 // entitlement tariff version must match
 let mut v2=good.clone();v2.tariff_version=2;v2=v2.signed(&sk(RELAY)).unwrap();
 assert_eq!(t.submit(mk(&t,1,&v2),Some(&v2),T0),Err(TierReject::TariffVersion));
 // none of the rejections consumed the sequence number
 assert!(t.submit(mk(&t,1,&good),Some(&good),T0).is_ok());
 // an entitlement that lapses while queued rejects at execution
 let short=Entitlement{valid_until_us:T0+500,..grant(2,FeedTier::Premium)}.signed(&sk(RELAY)).unwrap();
 t.submit(build(&t,&p,2,1,Action::Post,OrderSide::Short,FeedTier::Premium,10,false,Some(&short)).signed(&sk(2)).unwrap(),Some(&short),T0).unwrap();
 assert!(matches!(run(&mut t,T0+600),TierOutcome::Posted(_))); // the earlier valid order
 assert!(matches!(run(&mut t,T0+600),TierOutcome::Rejected(TierReject::EntitlementExpired)));
}

#[test]fn public_only_maker_is_protected_and_opted_in_maker_is_matchable_in_early_window(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 // Privileged until T0+200_000 (the Standard tier's feed delay).
 t.ingest_mark(mark(1,T0,T0+200_000,Some(PRICE)),T0).unwrap();
 let (m1,e1)=premium(&t,&p,1,1,Action::Post,OrderSide::Short,100,false);post(&mut t,m1,&e1,T0);
 let (tk,et)=premium(&t,&p,2,1,Action::Take,OrderSide::Long,100,false);
 t.submit(tk,Some(&et),T0+1).unwrap();
 assert!(matches!(run(&mut t,T0+1),TierOutcome::Rejected(TierReject::EarlyWindowProtected)));
 assert_eq!(t.resting(),1);assert_eq!(t.fill_count(),0);
 // An opted-in maker is matchable while the mark is still privileged.
 let (m2,e2)=premium(&t,&p,3,1,Action::Post,OrderSide::Short,100,true);post(&mut t,m2,&e2,T0+2);
 let (tk,et)=premium(&t,&p,2,2,Action::Take,OrderSide::Long,100,false);
 t.submit(tk,Some(&et),T0+3).unwrap();
 let TierOutcome::Filled(f)=run(&mut t,T0+3)else{panic!("early-window fill")};
 assert!(f.early_window);assert_eq!(f.fill.maker_channel,channel(3));
 // After public release the protected quote becomes matchable.
 let (tk,et)=premium(&t,&p,2,3,Action::Take,OrderSide::Long,100,false);
 t.submit(tk,Some(&et),T0+200_000).unwrap();
 let TierOutcome::Filled(f)=run(&mut t,T0+200_000)else{panic!("public fill")};
 assert!(!f.early_window);assert_eq!(f.fill.maker_channel,channel(1));
}

#[test]fn feed_delay_gates_which_mark_each_tier_trades_on(){
 let (_p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0+200_000,Some(PRICE)),T0).unwrap();
 t.ingest_mark(mark(2,T0+500_000,T0+700_000,Some(PRICE+1)),T0+500_000).unwrap();
 let at=T0+550_000;
 assert_eq!(t.visible_mark(FeedTier::Premium,at).unwrap().seq,2);
 assert_eq!(t.visible_mark(FeedTier::Intermediate,at).unwrap().seq,1);
 assert_eq!(t.visible_mark(FeedTier::Standard,at).unwrap().seq,1);
 assert_eq!(t.visible_mark(FeedTier::Intermediate,T0+600_000).unwrap().seq,2);
 assert_eq!(t.visible_mark(FeedTier::Standard,T0+699_999).unwrap().seq,1);
 assert_eq!(t.visible_mark(FeedTier::Standard,T0+700_000).unwrap().seq,2);
 assert!(t.visible_mark(FeedTier::Standard,T0+199_999).is_none());
 // non-monotone marks are rejected
 assert_eq!(t.ingest_mark(mark(2,T0+500_000,T0+700_000,Some(PRICE)),T0+600_000),Err(TierReject::Replay));
 assert_eq!(t.ingest_mark(mark(3,T0+400_000,T0+700_000,Some(PRICE)),T0+600_000),Err(TierReject::Replay));
 assert_eq!(t.ingest_mark(mark(3,T0+900_000,T0+700_000,Some(PRICE)),T0+950_000),Err(TierReject::Bounds));
}

#[test]fn stale_quote_guard_and_collar(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 // maker tolerates only 50 ms of mark age
 let e1=grant(1,FeedTier::Premium);
 let mut m=build(&t,&p,1,1,Action::Post,OrderSide::Short,FeedTier::Premium,100,false,Some(&e1));m.max_mark_age_us=50_000;
 post(&mut t,m.signed(&sk(1)).unwrap(),&e1,T0);
 let (tk,et)=premium(&t,&p,2,1,Action::Take,OrderSide::Long,100,false);
 t.submit(tk,Some(&et),T0+60_000).unwrap();
 assert!(matches!(run(&mut t,T0+60_000),TierOutcome::Rejected(TierReject::StaleMark)));
 // taker's own bound
 let e2=grant(2,FeedTier::Premium);
 let mut tk=build(&t,&p,2,2,Action::Take,OrderSide::Long,FeedTier::Premium,100,false,Some(&e2));tk.max_mark_age_us=10_000;
 t.submit(tk.signed(&sk(2)).unwrap(),Some(&e2),T0+60_000).unwrap();
 assert!(matches!(run(&mut t,T0+60_000),TierOutcome::Rejected(TierReject::StaleMark)));
 // posting against an old mark is also refused
 let e3=grant(3,FeedTier::Premium);
 let mut old=build(&t,&p,3,1,Action::Post,OrderSide::Short,FeedTier::Premium,10,false,Some(&e3));old.max_mark_age_us=1_000;
 t.submit(old.signed(&sk(3)).unwrap(),Some(&e3),T0+60_000).unwrap();
 assert!(matches!(run(&mut t,T0+60_000),TierOutcome::Rejected(TierReject::StaleMark)));
 // collar: 200 bps inclusive
 let e4=grant(4,FeedTier::Premium);
 for (seq,price,ok) in [(1u64,102_000u64,true),(2,102_001,false),(3,98_000,true),(4,97_999,false)]{
  let mut i=build(&t,&p,4,seq,Action::Post,OrderSide::Short,FeedTier::Premium,1,false,Some(&e4));i.limit_usd=price;
  t.submit(i.signed(&sk(4)).unwrap(),Some(&e4),T0+61_000).unwrap();
  let o=run(&mut t,T0+61_000);
  assert_eq!(matches!(o,TierOutcome::Posted(_)),ok,"price {price}: {o:?}");
  if !ok{assert!(matches!(o,TierOutcome::Rejected(TierReject::Collar)))}
 }
}

#[test]fn emergency_hold_rejects_takes_and_posts_but_cancels_succeed(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 // no mark: nothing trades
 let (m,e)=premium(&t,&p,1,1,Action::Post,OrderSide::Short,100,true);
 t.submit(m,Some(&e),T0).unwrap();
 assert!(matches!(run(&mut t,T0),TierOutcome::Rejected(TierReject::NoMark)));
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let (m,e)=premium(&t,&p,1,2,Action::Post,OrderSide::Short,100,true);let id=m.id();post(&mut t,m,&e,T0+1);
 let (m2,e2)=premium(&t,&p,3,1,Action::Post,OrderSide::Short,100,true);let id2=m2.id();post(&mut t,m2,&e2,T0+1);
 // HOLD packet at the next boundary
 t.ingest_mark(mark(2,T0+200_000,T0+200_000,None),T0+200_000).unwrap();
 let (tk,et)=premium(&t,&p,2,1,Action::Take,OrderSide::Long,100,false);t.submit(tk,Some(&et),T0+200_001).unwrap();
 assert!(matches!(run(&mut t,T0+200_001),TierOutcome::Rejected(TierReject::Hold)));
 let (pm,pe)=premium(&t,&p,4,1,Action::Post,OrderSide::Short,100,true);t.submit(pm,Some(&pe),T0+200_002).unwrap();
 assert!(matches!(run(&mut t,T0+200_002),TierOutcome::Rejected(TierReject::Hold)));
 // Standard tier sees HOLD immediately as well (fail closed)
 assert!(t.visible_mark(FeedTier::Standard,T0+200_000).unwrap().price_e8.is_none());
 // cancels still succeed
 t.submit(cancel_of(&t,&p,1,3,FeedTier::Premium,id,Some(&e)),Some(&e),T0+200_003).unwrap();
 assert!(matches!(run(&mut t,T0+200_003),TierOutcome::Cancelled(x) if x==id));
 // operator switch overrides a healthy mark
 t.ingest_mark(mark(3,T0+400_000,T0+400_000,Some(PRICE)),T0+400_000).unwrap();
 t.set_emergency_hold(true);assert!(t.emergency_hold());
 let (tk,et)=premium(&t,&p,2,2,Action::Take,OrderSide::Long,100,false);t.submit(tk,Some(&et),T0+400_001).unwrap();
 assert!(matches!(run(&mut t,T0+400_001),TierOutcome::Rejected(TierReject::Hold)));
 t.submit(cancel_of(&t,&p,3,2,FeedTier::Premium,id2,Some(&e2)),Some(&e2),T0+400_002).unwrap();
 assert!(matches!(run(&mut t,T0+400_002),TierOutcome::Cancelled(_)));
 assert_eq!(t.resting(),0);
 for n in 1..=4{let b=t.balance(&channel(n)).unwrap();assert!(b.conserved());assert_eq!(b.resting,0);assert_eq!(b.free,b.cap);}
 t.set_emergency_hold(false);
}

#[test]fn cancel_has_priority_and_zero_delay_for_every_tier(){
 let (p,mut t)=setup(Arm::SchedulerOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 // Standard maker posts with the 200 ms order delay.
 let e1=grant(1,FeedTier::Intermediate);
 let m=build(&t,&p,1,1,Action::Post,OrderSide::Short,FeedTier::Intermediate,100,false,Some(&e1)).signed(&sk(1)).unwrap();
 let id=m.id();
 assert_eq!(t.submit(m,Some(&e1),T0).unwrap(),T0+100_000);
 assert!(t.process_one(T0+99_999).unwrap().is_none());
 assert!(matches!(run(&mut t,T0+100_000),TierOutcome::Posted(x) if x==id));
 // Premium take is due immediately; the slower owner's cancel, submitted later at the
 // same instant, is still executed first.
 let (tk,et)=premium(&t,&p,2,1,Action::Take,OrderSide::Long,100,false);
 let now=T0+100_001;
 assert_eq!(t.submit(tk,Some(&et),now).unwrap(),now);
 let c=cancel_of(&t,&p,1,2,FeedTier::Intermediate,id,Some(&e1));
 assert_eq!(t.submit(c,Some(&e1),now).unwrap(),now);
 assert!(matches!(run(&mut t,now),TierOutcome::Cancelled(x) if x==id));
 assert!(matches!(run(&mut t,now),TierOutcome::Rejected(TierReject::NoLiquidity)));
 // A standard-tier order is delayed, its cancel is not.
 let s=build(&t,&p,3,1,Action::Post,OrderSide::Short,FeedTier::Standard,10,false,None).signed(&sk(3)).unwrap();
 let sid=s.id();assert_eq!(t.submit(s,None,now).unwrap(),now+200_000);
 let c=cancel_of(&t,&p,3,2,FeedTier::Standard,sid,None);assert_eq!(t.submit(c,None,now).unwrap(),now);
 // cancel of an order that is not yet resting is an unknown-order reject
 assert!(matches!(run(&mut t,now),TierOutcome::Rejected(TierReject::UnknownOrder)));
}

#[test]fn every_fill_binds_packet_entitlements_tariff_policy_and_conserves_fees(){
 let (p,mut t)=setup(Arm::Combined,TariffSchedule::default_candidate());
 let m=mark(7,T0,T0,Some(PRICE));t.ingest_mark(m,T0).unwrap();
 let (mk,me)=premium(&t,&p,1,1,Action::Post,OrderSide::Short,1000,false);post(&mut t,mk,&me,T0);
 let te=grant(2,FeedTier::Intermediate);
 let tk=build(&t,&p,2,1,Action::Take,OrderSide::Long,FeedTier::Intermediate,1000,false,Some(&te)).signed(&sk(2)).unwrap();
 let taker_id=tk.id();
 // Intermediate order delay under Combined is 100 ms; feed delay 100 ms.
 assert_eq!(t.submit(tk,Some(&te),T0).unwrap(),T0+100_000);
 let TierOutcome::Filled(f)=run(&mut t,T0+100_000)else{panic!("fill")};
 assert_eq!(f.packet_digest,m.packet_digest);assert_eq!(f.mark_seq,7);
 assert_eq!(f.maker_entitlement,me.digest());assert_eq!(f.taker_entitlement,te.digest());
 assert_eq!(f.tariff_version,1);assert_eq!(f.execution_policy,t.execution_policy_id());
 assert_eq!((f.maker_tier,f.taker_tier),(FeedTier::Premium,FeedTier::Intermediate));
 let mut bind=Vec::new();bind.extend(m.packet_digest);bind.extend(1u32.to_le_bytes());bind.extend(t.execution_policy_id());
 bind.extend(me.digest());bind.extend(te.digest());
 assert_eq!(f.fill.mark_id,tagged_hash(b"SHZ/HFT06/FILL-BINDING/V1",&bind));
 assert_eq!((f.fill.maker_fee_sats,f.fill.taker_fee_sats),(20,50));
 assert_eq!((f.fill.oracle_due_sats,f.fill.router_due_sats),(49,21));
 assert_eq!(f.fill.maker_fee_sats+f.fill.taker_fee_sats,f.fill.oracle_due_sats+f.fill.router_due_sats);
 assert_eq!(f.fill.spec.fee_policy,shz_margin::ZeroFeePolicy::ZERO);
 assert_eq!(t.fill(&taker_id).unwrap().fill.taker_id,taker_id);
 for n in [1,2]{assert!(t.balance(&channel(n)).unwrap().conserved())}
 // A different tariff/policy changes the binding, so fills cannot be replayed across them.
 let (_p2,t2)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 assert_ne!(t2.execution_policy_id(),t.execution_policy_id());
}

#[test]fn maker_partial_fills_use_cumulative_rounding_and_revenue_split_conserves(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let (mk,me)=premium(&t,&p,1,1,Action::Post,OrderSide::Short,4,false);post(&mut t,mk,&me,T0);
 let (mut maker_fees,mut taker_fees)=(0,0);
 for k in 0..2u8{
  let (tk,te)=premium(&t,&p,2+k,1,Action::Take,OrderSide::Long,1,false);
  t.submit(tk,Some(&te),T0+1).unwrap();
  let TierOutcome::Filled(f)=run(&mut t,T0+1)else{panic!()};
  assert_eq!(f.fill.maker_fee_sats+f.fill.taker_fee_sats,f.fill.oracle_due_sats+f.fill.router_due_sats);
  maker_fees+=f.fill.maker_fee_sats;taker_fees+=f.fill.taker_fee_sats;
 }
 assert_eq!(maker_fees,fee_sats(2,100_000,20).unwrap());assert_eq!(taker_fees,2*fee_sats(1,100_000,200).unwrap());
 let r=RevenuePolicy::default();
 for total in [0u64,1,2,3,9,10,11,999,12_345,u32::MAX as u64]{let (o,rt)=r.split(total);assert_eq!(o+rt,total);assert_eq!(o,(total as u128*7000/10_000)as u64)}
 assert_eq!(RevenuePolicy{oracle_share_bps:0}.split(77),(0,77));assert_eq!(RevenuePolicy{oracle_share_bps:10_000}.split(77),(77,0));
}

#[test]fn lead_reporting_has_no_double_counting(){
 let feed=ExecutionPolicy::defaults(Arm::FeedOnly);
 let sched=ExecutionPolicy::defaults(Arm::SchedulerOnly);
 let both=ExecutionPolicy::defaults(Arm::Combined);
 for e in [feed,sched,both]{e.validate().unwrap()}
 let (a,b)=(FeedTier::Premium,FeedTier::Standard);
 let l=feed.lead(a,b);assert_eq!((l.feed_us,l.order_us,l.effective_us,l.double_counted),(200_000,0,200_000,false));
 let l=sched.lead(a,b);assert_eq!((l.feed_us,l.order_us,l.effective_us,l.double_counted),(0,200_000,200_000,false));
 // Combined: the two configured mechanisms are reported separately and flagged. The
 // 400 ms sum is a configured bound, not a measured advantage.
 let l=both.lead(a,b);assert_eq!((l.feed_us,l.order_us,l.effective_us,l.double_counted),(200_000,200_000,400_000,true));
 // An inactive mechanism's configured delay is ignored entirely.
 let mut odd=feed;odd.order_delay_us=[500_000,300_000,0];
 assert_eq!(odd.lead(a,b),feed.lead(a,b));assert_eq!(odd.id(),feed.id());
 assert_ne!(feed.id(),sched.id());assert_ne!(sched.id(),both.id());
 // Reverse direction is negative, same tier is zero.
 assert_eq!(feed.lead(b,a).effective_us,-200_000);assert_eq!(both.lead(a,a).effective_us,0);
 assert_eq!((feed.order_delay(b),sched.feed_delay(b),both.feed_delay(b),both.order_delay(b)),(0,0,200_000,200_000));
 // Invalid orderings are refused.
 let bad=ExecutionPolicy{feed_delay_us:[0,100_000,200_000],order_delay_us:[0;3],arm:Arm::FeedOnly};
 assert_eq!(bad.validate(),Err(TierReject::Bounds));
}

#[test]fn combined_arm_delays_orders_and_feed_independently(){
 let (p,mut t)=setup(Arm::Combined,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let s=build(&t,&p,1,1,Action::Post,OrderSide::Short,FeedTier::Standard,10,false,None).signed(&sk(1)).unwrap();
 assert_eq!(t.submit(s,None,T0).unwrap(),T0+200_000);
 // Due at T0+200_000, mark visible to Standard from T0+200_000: posts at exactly that instant.
 assert!(matches!(run(&mut t,T0+200_000),TierOutcome::Posted(_)));
 assert_eq!(t.due_delay_us(FeedTier::Premium,Action::Take),0);assert_eq!(t.due_delay_us(FeedTier::Standard,Action::Cancel),0);
}

#[test]
fn tiered_batches_reuse_the_hft03_sealer(){
 let (p,mut t)=setup(Arm::FeedOnly,TariffSchedule::default_candidate());
 t.ingest_mark(mark(1,T0,T0,Some(PRICE)),T0).unwrap();
 let (mk,me)=premium(&t,&p,1,1,Action::Post,OrderSide::Short,1000,false);post(&mut t,mk,&me,T0);
 let (tk,te)=premium(&t,&p,2,1,Action::Take,OrderSide::Long,1000,false);t.submit(tk,Some(&te),T0+5).unwrap();
 assert!(matches!(run(&mut t,T0+5),TierOutcome::Filled(_)));
 assert!(t.seal_batch().unwrap().is_none());
 t.process_one(T0+100_000).unwrap();
 let b=t.seal_batch().unwrap().unwrap();
 assert_eq!((b.sequence(),b.legs().len()),(1,1));
 assert_eq!(b.oracle_due_sats()+b.router_due_sats(),220);assert_eq!((b.oracle_due_sats(),b.router_due_sats()),(154,66));
 assert!(t.seal_batch().unwrap().is_none());
 // second batch chains to the first
 let (mk,me)=premium(&t,&p,1,2,Action::Post,OrderSide::Short,1000,false);post(&mut t,mk,&me,T0+200_000);
 let (tk,te)=premium(&t,&p,2,2,Action::Take,OrderSide::Long,1000,false);t.submit(tk,Some(&te),T0+200_001).unwrap();
 assert!(matches!(run(&mut t,T0+200_001),TierOutcome::Filled(_)));
 t.process_one(T0+300_000).unwrap();
 let b2=t.seal_batch().unwrap().unwrap();
 assert_eq!((b2.sequence(),b2.previous()),(2,b.digest()));
 let payouts=b2.payouts_at_price(100_000).unwrap();assert_eq!(payouts.len(),2);
}
