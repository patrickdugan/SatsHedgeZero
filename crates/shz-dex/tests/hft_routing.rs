use shz_dex::{OrderSide,routing::*};
use shz_dlc::{Bip340Signature,BtcOutPoint};
const NOW:u64=1_000_000;
const AUTH:[u8;32]=[77;32];
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
fn sk(n:u8)->[u8;32]{[n;32]}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[public(&sk(50)),public(&sk(51))]}}
fn setup(cap:u64)->(Policy,Registry){
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),cap*2,vec![Share{router:1,sats:cap},Share{router:2,sats:cap}]).unwrap()).collect();
 let r=Registry::new(p.scope(),public(&AUTH),plans).unwrap();(p,r)
}
fn marks(p:&Policy,seq:u64,t:u64,prices:[u64;2])->[RelayTick;2]{
 std::array::from_fn(|i|RelayTick{scope:p.scope(),source:i as u8+1,sequence:seq,publish_us:t,price_e8:prices[i],report_hash:[i as u8+1;32],signature:ZERO}.signed(&sk(50+i as u8)).unwrap())
}
fn good_marks(p:&Policy)->[RelayTick;2]{marks(p,1,NOW,[10_000_000_000_000;2])}
fn order(p:&Policy,n:u8,seq:u64,action:Action,side:OrderSide,tier:Tier,q:u64)->Intent{
 Intent{scope:p.scope(),router:1,channel:channel(n),owner:[0;32],sequence:seq,expires_us:NOW+10_000_000,action,side,tier,quantity:q,limit_usd:100_000,leverage_bps:10_000,max_fee_ppm:rate_ppm(tier,action),max_fee_sats:100_000,cancel_target:[0;32],signature:ZERO}.signed(&sk(n)).unwrap()
}
fn ready(r:&mut Router,t:u64)->Outcome{r.process_one(t).unwrap().unwrap()}
#[test]fn priority_and_explicit_fee_split_preserve_dlc_zero_fee(){
 let(p,g)=setup(10_000_000);let mut r=Router::new(p.clone(),&g,1).unwrap();r.update_mark(good_marks(&p),NOW).unwrap();
 let maker=order(&p,1,1,Action::Post,OrderSide::Short,Tier::Priority,1000);r.submit(maker,NOW).unwrap();assert!(matches!(ready(&mut r,NOW),Outcome::Posted(_)));
 let f=order(&p,2,1,Action::Take,OrderSide::Long,Tier::Free,1000);let fast=order(&p,3,1,Action::Take,OrderSide::Long,Tier::Priority,1000);
 assert_eq!(r.submit(f,NOW).unwrap(),NOW+300_000);assert_eq!(r.submit(fast,NOW).unwrap(),NOW+100_000);
 assert!(r.process_one(NOW+99_999).unwrap().is_none());
 let Outcome::Filled(fill)=ready(&mut r,NOW+100_000)else{panic!("priority fill")};
 assert_eq!(fill.maker_fee_sats,20);assert_eq!(fill.taker_fee_sats,200);assert_eq!(fill.oracle_due_sats,154);assert_eq!(fill.router_due_sats,66);
 assert_eq!(fill.spec.fee_policy,shz_margin::ZeroFeePolicy::ZERO);
 assert!(matches!(ready(&mut r,NOW+300_000),Outcome::Rejected(Reject::NoLiquidity)));
 assert!(r.balance(&channel(1)).unwrap().conserved());assert!(r.balance(&channel(3)).unwrap().conserved());
 assert_eq!(r.balance(&channel(2)).unwrap().pending,0);
}
#[test]fn allocation_partition_scope_and_replay(){
 let(p,g)=setup(1_000_000);
 let mut a=Router::new(p.clone(),&g,1).unwrap();let b=Router::new(p.clone(),&g,2).unwrap();
 assert_eq!(a.balance(&channel(1)).unwrap().cap+b.balance(&channel(1)).unwrap().cap,2_000_000);
 let i=order(&p,1,1,Action::Post,OrderSide::Short,Tier::Free,100);
 a.submit(i.clone(),NOW).unwrap();assert_eq!(a.submit(i.clone(),NOW),Err(Reject::Replay));
 let mut changed=i;changed.max_fee_sats+=1;assert_eq!(a.submit(changed,NOW),Err(Reject::Signature));
 let mut b=b;assert_eq!(b.submit(order(&p,1,2,Action::Post,OrderSide::Short,Tier::Free,100),NOW),Err(Reject::Scope));
 let p1=Allocation::signed(p.scope(),&sk(1),&AUTH,channel(1),100,vec![Share{router:1,sats:100}]).unwrap();
 assert!(Registry::new(p.scope(),public(&AUTH),vec![p1.clone(),p1]).is_err());
 assert!(Allocation::signed(p.scope(),&sk(1),&AUTH,channel(1),100,vec![Share{router:1,sats:60},Share{router:2,sats:60}]).is_err());
}
#[test]fn stale_and_equivocating_marks_fail_closed(){
 let(p,g)=setup(1_000_000);let mut r=Router::new(p.clone(),&g,1).unwrap();
 let t=good_marks(&p);r.update_mark(t.clone(),NOW).unwrap();assert_eq!(r.update_mark(t,NOW),Err(Reject::Replay));
 let bad=marks(&p,2,NOW+1,[10_000_000_000_000,11_000_000_000_000]);assert_eq!(r.update_mark(bad,NOW+1),Err(Reject::Oracle));
 let changed=marks(&p,1,NOW,[10_000_000_000_001,10_000_000_000_000]);assert_eq!(r.update_mark(changed,NOW+1),Err(Reject::Replay));
 let i=order(&p,1,1,Action::Post,OrderSide::Short,Tier::Priority,100);r.submit(i,NOW+MAX_AGE_US+1).unwrap();
 assert!(matches!(ready(&mut r,NOW+MAX_AGE_US+1),Outcome::Rejected(Reject::Oracle)));
 assert_eq!(r.balance(&channel(1)).unwrap().free,1_000_000);
}
#[test]fn partial_fee_rounding_cancel_and_insufficient_funds(){
 let(p,g)=setup(10_000);let mut r=Router::new(p.clone(),&g,1).unwrap();r.update_mark(good_marks(&p),NOW).unwrap();
 let maker=order(&p,1,1,Action::Post,OrderSide::Short,Tier::Priority,4);let id=maker.id();r.submit(maker,NOW).unwrap();assert!(matches!(ready(&mut r,NOW),Outcome::Posted(_)));
 for n in 2..=3{r.submit(order(&p,n,1,Action::Take,OrderSide::Long,Tier::Free,1),NOW).unwrap();}
 let Outcome::Filled(a)=ready(&mut r,NOW+300_000)else{panic!()};let Outcome::Filled(b)=ready(&mut r,NOW+300_000)else{panic!()};
 assert_eq!(a.maker_fee_sats+b.maker_fee_sats,fee_sats(2,100_000,20).unwrap());assert_eq!(a.taker_fee_sats+b.taker_fee_sats,0);
 let mut cancel=order(&p,1,2,Action::Cancel,OrderSide::Short,Tier::Priority,0);
 cancel.limit_usd=0;cancel.leverage_bps=0;cancel.max_fee_sats=0;cancel.cancel_target=id;
 let cancel=cancel.signed(&sk(1)).unwrap();r.submit(cancel,NOW+300_000).unwrap();assert!(matches!(ready(&mut r,NOW+300_000),Outcome::Cancelled(_)));
 let balance=r.balance(&channel(1)).unwrap();assert_eq!(balance.resting,0);assert!(balance.conserved());assert_eq!(balance.pending,2001);
 r.submit(order(&p,4,1,Action::Post,OrderSide::Short,Tier::Priority,1000),NOW+300_000).unwrap();
 assert!(matches!(ready(&mut r,NOW+300_000),Outcome::Rejected(Reject::Capacity)));assert_eq!(r.balance(&channel(4)).unwrap().free,10_000);
}
#[test]fn free_maker_and_taker_no_fee_and_fok(){
 let(p,g)=setup(10_000_000);let mut r=Router::new(p.clone(),&g,1).unwrap();r.update_mark(good_marks(&p),NOW).unwrap();
 r.submit(order(&p,1,1,Action::Post,OrderSide::Short,Tier::Free,100),NOW).unwrap();
 assert!(r.process_one(NOW+199_999).unwrap().is_none());assert!(matches!(ready(&mut r,NOW+200_000),Outcome::Posted(_)));
 r.submit(order(&p,2,1,Action::Take,OrderSide::Long,Tier::Free,101),NOW+200_000).unwrap();
 r.submit(order(&p,3,1,Action::Take,OrderSide::Long,Tier::Free,100),NOW+200_000).unwrap();
 assert!(matches!(ready(&mut r,NOW+500_000),Outcome::Rejected(Reject::NoLiquidity)));
 let Outcome::Filled(f)=ready(&mut r,NOW+500_000)else{panic!()};assert_eq!(f.maker_fee_sats+f.taker_fee_sats,0);
}
