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

#[test]fn price_time_is_activation_order_and_pending_receipts_are_retained(){
 let(p,g)=setup(10_000_000);let mut r=Router::new(p.clone(),&g,1).unwrap();r.update_mark(good_marks(&p),NOW).unwrap();
 let free=order(&p,1,1,Action::Post,OrderSide::Short,Tier::Free,100);
 let fast=order(&p,2,1,Action::Post,OrderSide::Short,Tier::Priority,100);let fast_id=fast.id();
 r.submit(free,NOW).unwrap();r.submit(fast,NOW+1).unwrap();
 assert!(matches!(ready(&mut r,NOW+1),Outcome::Posted(_)));
 assert!(matches!(ready(&mut r,NOW+200_000),Outcome::Posted(_)));
 let taker=order(&p,3,1,Action::Take,OrderSide::Long,Tier::Priority,100);let id=taker.id();
 r.submit(taker,NOW+200_000).unwrap();
 let Outcome::Filled(f)=ready(&mut r,NOW+300_000)else{panic!()};
 assert_eq!(f.maker_id,fast_id);assert_eq!(r.pending_fills(),1);assert_eq!(r.pending_fill(&id).unwrap().maker_id,fast_id);
}
#[test]fn cross_router_budget_and_expiry_release_only_resting(){
 let(p,g)=setup(200_000);let mut r=Router::new(p.clone(),&g,1).unwrap();let mut r2=Router::new(p.clone(),&g,2).unwrap();
 r.update_mark(good_marks(&p),NOW).unwrap();r2.update_mark(good_marks(&p),NOW).unwrap();
 let mut maker=order(&p,1,1,Action::Post,OrderSide::Short,Tier::Priority,100);
 maker.expires_us=NOW+500_000;maker=maker.signed(&sk(1)).unwrap();
 let mut second=maker.clone();second.router=2;second=second.signed(&sk(1)).unwrap();
 r.submit(maker,NOW).unwrap();r2.submit(second,NOW).unwrap();
 assert!(matches!(ready(&mut r,NOW),Outcome::Posted(_)));assert!(matches!(ready(&mut r2,NOW),Outcome::Posted(_)));
 r.submit(order(&p,2,1,Action::Take,OrderSide::Long,Tier::Priority,50),NOW).unwrap();assert!(matches!(ready(&mut r,NOW+100_000),Outcome::Filled(_)));
 assert!(r.process_one(NOW+500_000).unwrap().is_none());assert!(r2.process_one(NOW+500_000).unwrap().is_none());
 let a=r.balance(&channel(1)).unwrap();let b=r2.balance(&channel(1)).unwrap();
 assert_eq!(a.resting+b.resting,0);assert!(a.pending>0);assert_eq!(b.pending,0);assert!(a.conserved()&&b.conserved());assert_eq!(a.cap+b.cap,400_000);
}

#[test]fn hft02_engines_preserve_ordered_outcomes_and_balances(){
 let(p,g)=setup(100_000_000);
 let mut engines=[Engine::Scan,Engine::Indexed,Engine::Joint,Engine::Both].map(|e|Router::new_with_engine(p.clone(),&g,1,e).unwrap());
 let mut intents=Vec::new();
 // Exact size boundary, self-match, partial fills crossing a size bucket,
 // price-time ties, collar boundaries, and resting quote cancellation.
 for (k,(owner,qty,price,side)) in [(1,7,98000,OrderSide::Short),(2,8,98000,OrderSide::Short),(3,17,98000,OrderSide::Short),(1,64,102000,OrderSide::Long),(4,32,101999,OrderSide::Long)].into_iter().enumerate(){
  let mut i=order(&p,owner,k as u64+1,Action::Post,side,Tier::Priority,qty);
  i.limit_usd=price;intents.push(i.signed(&sk(owner)).unwrap());
 }
 let cancel_id=intents[3].id();
 for (k,(owner,qty,price,side)) in [(2,8,98000,OrderSide::Long),(4,9,98000,OrderSide::Long),(1,1,98000,OrderSide::Long),(3,20,102000,OrderSide::Short),(4,5,101999,OrderSide::Short),(1,256,100000,OrderSide::Long)].into_iter().enumerate(){
  let mut i=order(&p,owner,20+k as u64,Action::Take,side,Tier::Priority,qty);
  i.limit_usd=price;intents.push(i.signed(&sk(owner)).unwrap());
 }
 let mut i=order(&p,1,99,Action::Cancel,OrderSide::Long,Tier::Priority,0);
 i.limit_usd=0;i.leverage_bps=0;i.max_fee_sats=0;i.cancel_target=cancel_id;
 let cancel=i.signed(&sk(1)).unwrap();
 let mut traces=Vec::new();
 for r in &mut engines{
  r.update_mark(good_marks(&p),NOW).unwrap();
  for (j,i) in intents.iter().enumerate(){r.submit(i.clone(),NOW+j as u64).unwrap();}
  let mut trace=Vec::new();
  while let Some(o)=r.process_one(NOW+300_000).unwrap(){trace.push(format!("{o:?}"));}
  r.submit(cancel.clone(),NOW+300_001).unwrap();trace.push(format!("{:?}",ready(r,NOW+300_001)));
  // Same authenticated replay/tamper decisions in both verifier variants.
  let mut bad=order(&p,4,100,Action::Post,OrderSide::Short,Tier::Priority,3);bad.signature.s=[255;32];
  assert_eq!(r.submit(bad,NOW+300_002),Err(Reject::Signature));
  assert!(r.process_one(NOW+10_000_001).unwrap().is_none());
  assert_eq!(r.resting(),0);
  for n in 1..=4{let b=r.balance(&channel(n)).unwrap();assert!(b.conserved());trace.push(format!("{b:?}"));}
  traces.push(trace);
 }
 assert!(traces[0].iter().any(|e|e.starts_with("Filled")));
 assert!(traces.iter().all(|t|t==&traces[0]));
}

#[test]fn hft02_joint_verifier_matches_reference_on_mutations(){
 use shz_dlc::{bip340_verify,bip340_verify_joint};
 for n in 1..=12u8{
  let(p,_)=setup(1_000_000);
  let i=order(&p,(n%4)+1,n as u64,Action::Post,OrderSide::Short,Tier::Priority,100);
  let h=i.id();assert!(bip340_verify_joint(&i.owner,&h,&i.signature).is_ok());
  let mut bad_h=h;bad_h[0]^=1;
  let mut bad_sig=i.signature;bad_sig.r_x[0]^=1;
  for (msg,sig) in [(bad_h,i.signature),(h,bad_sig)]{
   assert!(bip340_verify(&i.owner,&msg,&sig).is_err());
   assert!(bip340_verify_joint(&i.owner,&msg,&sig).is_err());
  }
 }
}

#[test]fn hft03_exact_window_commitments_and_owner_approvals(){
 use shz_dlc::bip340_sign;
 let(p,g)=setup(100_000_000);
 let mut r=Router::new_with_engine(p.clone(),&g,1,Engine::Both).unwrap();
 r.update_mark(good_marks(&p),NOW).unwrap();
 // Same maker, two entries, differing leverage and fee. Split first across windows.
 let mut a=order(&p,1,1,Action::Post,OrderSide::Short,Tier::Priority,100);
 a.limit_usd=99_000;a.leverage_bps=100_000;
 let a=a.signed(&sk(1)).unwrap();
 let mut b=order(&p,1,2,Action::Post,OrderSide::Short,Tier::Priority,100);
 b.limit_usd=101_000;b.leverage_bps=20_000;
 let b=b.signed(&sk(1)).unwrap();
 r.submit(a,NOW).unwrap();r.submit(b,NOW).unwrap();
 assert!(matches!(ready(&mut r,NOW),Outcome::Posted(_)));
 assert!(matches!(ready(&mut r,NOW),Outcome::Posted(_)));
 r.submit(order(&p,2,1,Action::Take,OrderSide::Long,Tier::Priority,60),NOW).unwrap();
 let Outcome::Filled(first)=ready(&mut r,NOW+100_000)else{panic!()};
 assert!(r.seal_fill_batch().unwrap().is_none());
 let mut i=order(&p,2,2,Action::Take,OrderSide::Long,Tier::Priority,80);
 i.limit_usd=101_000;
 r.submit(i.signed(&sk(2)).unwrap(),NOW+100_000).unwrap();
 let Outcome::Filled(second)=ready(&mut r,NOW+200_000)else{panic!()};
 let before=r.balance(&channel(1)).unwrap();
 let a=r.seal_fill_batch().unwrap().unwrap();
 assert_eq!(a.sequence(),1);assert_eq!(a.window(),(NOW+100_000,NOW+200_000));assert_eq!(a.previous(),[0;32]);
 assert_eq!(a.legs().len(),1);assert_eq!(a.legs()[0].taker_id,first.taker_id);
 assert!(r.seal_fill_batch().unwrap().is_none());
 assert_eq!(r.balance(&channel(1)).unwrap(),before);
 assert_eq!(r.pending_fills(),2);
 let approvals:Vec<_>=(1..=2).map(|n|{
  let ch=channel(n);let h=a.approval_message(&ch).unwrap();
  BatchApproval{channel:ch,signature:bip340_sign(&sk(n),&h).unwrap()}
 }).collect();
 assert!(a.verify_approvals(&approvals).is_ok());
 assert!(a.verify_approvals(&approvals[..1]).is_err());
 assert!(a.verify_approvals(&[approvals[0].clone(),approvals[0].clone()]).is_err());
 assert!(a.approval_message(&channel(3)).is_none());
 assert!(r.process_one(NOW+300_000).unwrap().is_none());
 let b=r.seal_fill_batch().unwrap().unwrap();
 assert_eq!(b.sequence(),2);assert_eq!(b.previous(),a.digest());
 assert_eq!(b.legs()[0].taker_id,second.taker_id);
 assert!(b.verify_approvals(&approvals).is_err());
 assert!(r.seal_fill_batch().unwrap().is_none());
 for px in [0,50_000,99_000,100_000,101_000,150_000]{
  for batch in [&a,&b]{
   let p=batch.legs()[0].spec.payout_at_price(px);
   let actual=batch.payouts_at_price(px).unwrap();
   assert_eq!(actual[0].payout_sats,p.short_sats);
   assert_eq!(actual[1].payout_sats,p.long_sats);
   assert_eq!(actual.iter().map(|x|x.payout_sats as u128).sum::<u128>(),batch.accounts().iter().map(|x|x.margin_sats as u128).sum::<u128>());
   assert_eq!(batch.accounts().iter().map(|x|x.fee_sats as u128).sum::<u128>(),batch.oracle_due_sats()+batch.router_due_sats());
  }
 }
 for n in 1..=2{
  let total:u64=[&a,&b].iter().flat_map(|batch|batch.accounts()).filter(|x|x.channel.txid==[n;32]).map(|x|x.margin_sats+x.fee_sats).sum();
  assert_eq!(r.balance(&channel(n)).unwrap().pending,total);
 }
}
#[test]fn hft03_multileg_payouts_use_each_leg_and_never_merge_at_arithmetic_vwap(){
 let(p,g)=setup(100_000_000);
 let mut r=Router::new_with_engine(p.clone(),&g,1,Engine::Both).unwrap();
 r.update_mark(good_marks(&p),NOW).unwrap();
 for (seq,price,lev) in [(1,98_000,100_000),(2,102_000,10_000)]{
  let mut i=order(&p,1,seq,Action::Post,OrderSide::Long,Tier::Priority,1000);
  i.limit_usd=price;i.leverage_bps=lev;
  r.submit(i.signed(&sk(1)).unwrap(),NOW).unwrap();
 }
 for _ in 0..2{assert!(matches!(ready(&mut r,NOW),Outcome::Posted(_)))}
 for seq in 1..=2{
  let mut i=order(&p,2,seq,Action::Take,OrderSide::Short,Tier::Priority,1000);
  i.limit_usd=98_000;
  r.submit(i.signed(&sk(2)).unwrap(),NOW).unwrap();
 }
 for _ in 0..2{assert!(matches!(ready(&mut r,NOW+100_000),Outcome::Filled(_)))}
 assert!(r.process_one(NOW+200_000).unwrap().is_none());
 let b=r.seal_fill_batch().unwrap().unwrap();
 assert_eq!(b.legs().len(),2);assert_eq!(b.accounts().len(),2);
 let mut found_difference=false;
 let merged=shz_margin::InverseContractSpec{usd_notional:2000,entry_price_usd:100_000,
  long_margin_sats:b.legs().iter().map(|f|f.spec.long_margin_sats).sum(),
  short_margin_sats:b.legs().iter().map(|f|f.spec.short_margin_sats).sum(),
  collateral:b.legs()[0].spec.collateral.clone(),fee_policy:shz_margin::ZeroFeePolicy::ZERO};
 for px in [0,50_000,90_000,98_000,100_000,102_000,110_000,200_000]{
  let actual=b.payouts_at_price(px).unwrap();
  let exact:u64=b.legs().iter().map(|f|f.spec.payout_at_price(px).long_sats).sum();
  assert_eq!(actual[0].payout_sats,exact);
  found_difference|=exact!=merged.payout_at_price(px).long_sats;
 }
 assert!(found_difference);
 assert!(r.seal_fill_batch().unwrap().is_none());
}
