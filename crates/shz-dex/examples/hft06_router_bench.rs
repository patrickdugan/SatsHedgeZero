//! Deterministic synthetic benchmark of the HFT-06 tiered router and Lightning fee ledger.
//! Usage: hft06_router_bench [--orders N] [--fee-batches K] [--out PATH]
//!
//! Intents are pre-built and pre-signed outside timing. Virtual clock times only gate
//! eligibility; they are not network latency. Configured feed/order delays are reported
//! as configuration, never as a measured advantage. The fee ledger is fed by HFT-05
//! `DurableRouter` batches because `observe_resolution` authenticates against it.
use shz_dex::{OrderSide,routing::*};
use shz_dex::routing::durable::*;
use shz_dex::routing::ln_fees::*;
use shz_dex::routing::tiered::*;
use shz_dlc::{Bip340Signature,BtcOutPoint,bip340_sign};
use serde_json::{json,Value};
use std::{collections::BTreeMap,fs,path::PathBuf,time::Instant};

type Key=[u8;32];
const T0:u64=1_000_000;
const STEP:u64=250_000;
const AUTH:[u8;32]=[77;32];
const RELAY:u8=60;
const PRICE:u64=10_000_000_000_000;
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
fn sk(n:u8)->[u8;32]{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[public(&sk(50)),public(&sk(51))]}}

// ---------- stats ----------
#[derive(Default,Clone)]
struct Samples(Vec<u64>);
impl Samples{
 fn push(&mut self,ns:u64){self.0.push(ns)}
 fn q(sorted:&[u64],p:f64)->f64{
  if sorted.is_empty(){return 0.0}
  let rank=((p*sorted.len()as f64).ceil()as usize).clamp(1,sorted.len());sorted[rank-1]as f64/1000.0
 }
 fn json(&self)->Value{
  let mut s=self.0.clone();s.sort_unstable();
  let n=s.len();let mean=if n==0{0.0}else{s.iter().map(|x|*x as u128).sum::<u128>()as f64/n as f64/1000.0};
  json!({"count":n,"p50_us":Self::q(&s,0.50),"p95_us":Self::q(&s,0.95),"p99_us":Self::q(&s,0.99),
   "max_us":s.last().copied().unwrap_or(0)as f64/1000.0,"mean_us":mean})
 }
}
fn ns(t:Instant)->u64{t.elapsed().as_nanos()as u64}

// ---------- tiered stream ----------
fn setup(arm:Arm)->(Policy,TieredRouter){
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),20_000_000_000,vec![Share{router:1,sats:10_000_000_000},Share{router:2,sats:10_000_000_000}]).unwrap()).collect();
 let g=Registry::new(p.scope(),public(&AUTH),plans).unwrap();
 let cfg=TieredConfig{scope:p.scope(),router:1,entitlement_key:public(&sk(RELAY)),tariff:TariffSchedule::default_candidate(),
  execution:ExecutionPolicy::defaults(arm),revenue:RevenuePolicy::default()};
 (p,TieredRouter::new(&g,cfg).unwrap())
}
fn grant(n:u8,tier:FeedTier,until:u64)->Entitlement{
 Entitlement{client:public(&sk(n)),tier,tariff_version:1,valid_from_us:0,valid_until_us:until,relay_key:[0;32],signature:ZERO_SIG}.signed(&sk(RELAY)).unwrap()
}
#[allow(clippy::too_many_arguments)]
fn build(t:&TieredRouter,p:&Policy,n:u8,seq:u64,action:Action,side:OrderSide,tier:FeedTier,q:u64,price:u64,opt_in:bool,exp:u64,ent:Option<&Entitlement>)->IntentV6{
 let tariff=*t.tariff();
 IntentV6{scope:p.scope(),router:1,channel:channel(n),owner:[0;32],sequence:seq,expires_us:exp,action,side,tier,
  tariff_version:tariff.version,entitlement_digest:ent.map(|e|e.digest()).unwrap_or([0;32]),execution_policy:t.execution_policy_id(),
  quantity:q,limit_usd:price,leverage_bps:10_000,max_fee_ppm:tariff.rate_ppm(tier,action),max_fee_sats:100_000,
  max_mark_age_us:1_000_000,early_window_opt_in:opt_in,cancel_target:[0;32],signature:ZERO_SIG}
}
fn mark(seq:u64,boundary:u64,release:u64)->MarkView{
 let mut d=[0u8;32];d[..8].copy_from_slice(&seq.to_le_bytes());d[31]=1;
 MarkView{packet_digest:d,seq,price_e8:Some(PRICE),boundary_us:boundary,public_release_us:release}
}
struct Item{intent:IntentV6,ent:Option<usize>}
struct Round{t:u64,mark:MarkView,items:Vec<Item>}
const TIER_OF:[FeedTier;5]=[FeedTier::Standard,FeedTier::Premium,FeedTier::Standard,FeedTier::Intermediate,FeedTier::Premium];

// channel 1 maker (Premium), 2 Standard taker, 3 Intermediate taker, 4 Premium taker.
// ents[n] is the entitlement of channel n (ents[2] is unused: Standard carries none).
fn build_stream(t:&TieredRouter,p:&Policy,orders:usize,ents:&[Entitlement;5])->Vec<Round>{
 let mut seq=[0u64;5];
 let mut rounds=Vec::new();let mut count=0usize;let mut r=0u64;
 while count<orders{
  let now=T0+r*STEP;let exp=now+5_000_000;
  let mut items:Vec<Item>=Vec::new();
  seq[1]+=1;
  let post=build(t,p,1,seq[1],Action::Post,OrderSide::Short,FeedTier::Premium,10,100_000,true,exp,Some(&ents[1])).signed(&sk(1)).unwrap();
  let replay_src=post.clone();
  items.push(Item{intent:post,ent:Some(1)});
  let n=(2+r%3)as u8;let tier=TIER_OF[n as usize];
  seq[n as usize]+=1;
  let e=if tier==FeedTier::Standard{None}else{Some(n as usize)};
  let take=build(t,p,n,seq[n as usize],Action::Take,OrderSide::Long,tier,10,100_000,false,exp,e.map(|k|&ents[k])).signed(&sk(n)).unwrap();
  items.push(Item{intent:take,ent:e});
  if r%17==3{ // second take against an empty book: NoLiquidity at execution
   seq[4]+=1;
   items.push(Item{intent:build(t,p,4,seq[4],Action::Take,OrderSide::Long,FeedTier::Premium,10,100_000,false,exp,Some(&ents[4])).signed(&sk(4)).unwrap(),ent:Some(4)});
  }
  if r%23==5{ // tampered after signing: Signature at admission
   let mut bad=build(t,p,1,seq[1]+1,Action::Post,OrderSide::Short,FeedTier::Premium,10,100_000,true,exp,Some(&ents[1])).signed(&sk(1)).unwrap();
   bad.max_fee_sats+=1;items.push(Item{intent:bad,ent:Some(1)});
  }
  if r%29==7{ // replay of this round's post: Replay at admission
   items.push(Item{intent:replay_src,ent:Some(1)});
  }
  if r%31==11{ // outside the 200 bps collar: Collar at execution
   seq[3]+=1;
   items.push(Item{intent:build(t,p,3,seq[3],Action::Post,OrderSide::Short,FeedTier::Intermediate,10,110_000,false,exp,Some(&ents[3])).signed(&sk(3)).unwrap(),ent:Some(3)});
  }
  if r%37==13{ // Intermediate intent whose entitlement is not presented: EntitlementMissing at admission
   items.push(Item{intent:build(t,p,3,seq[3]+1,Action::Take,OrderSide::Long,FeedTier::Intermediate,10,100_000,false,exp,Some(&ents[3])).signed(&sk(3)).unwrap(),ent:None});
  }
  count+=items.len();
  rounds.push(Round{t:now,mark:mark(r+1,now,now+200_000),items});r+=1;
 }
 let mut over=count-orders;
 while over>0{
  let last=rounds.last_mut().unwrap();
  if last.items.len()<=over{over-=last.items.len();rounds.pop();}else{let l=last.items.len();last.items.truncate(l-over);over=0;}
 }
 rounds
}

#[derive(Default)]
struct ArmResult{
 admit:Samples,admit_reject:Samples,process_all:Samples,matching:Samples,seal:Samples,
 submitted:u64,admitted:u64,submit_rejects:BTreeMap<String,u64>,exec_rejects:BTreeMap<String,u64>,
 posted:u64,cancelled:u64,fills:u64,fills_by_taker_tier:BTreeMap<String,u64>,
 batches:u64,batch_legs:u64,fees:u128,dues:u128,batch_dues:u128,wall_ns:u64,balances_conserved:bool,
}
fn run_arm(arm:Arm,orders:usize)->(ArmResult,ExecutionPolicy){
 let (p,mut t)=setup(arm);
 let until=T0+(orders as u64+10)*STEP+100_000_000;
 let ents:[Entitlement;5]=[grant(1,FeedTier::Premium,until),grant(1,FeedTier::Premium,until),grant(1,FeedTier::Premium,until),
  grant(3,FeedTier::Intermediate,until),grant(4,FeedTier::Premium,until)];
 let stream=build_stream(&t,&p,orders,&ents);
 let mut r=ArmResult::default();
 let wall=Instant::now();
 for round in stream{
  t.ingest_mark(round.mark,round.t).unwrap();
  for it in &round.items{
   let e=it.ent.map(|k|&ents[k]);
   let c=it.intent.clone();
   let s=Instant::now();let res=t.submit(c,e,round.t);let d=ns(s);
   r.submitted+=1;
   match res{Ok(_)=>{r.admitted+=1;r.admit.push(d)},Err(x)=>{r.admit_reject.push(d);*r.submit_rejects.entry(format!("{x:?}")).or_default()+=1}}
  }
  for off in [0u64,100_000,200_000]{
   loop{
    let s=Instant::now();let o=t.process_one(round.t+off).unwrap();let d=ns(s);
    let Some(o)=o else{break};
    r.process_all.push(d);
    match o{
     TierOutcome::Posted(_)=>r.posted+=1,
     TierOutcome::Cancelled(_)=>r.cancelled+=1,
     TierOutcome::Filled(f)=>{
      r.matching.push(d);r.fills+=1;
      *r.fills_by_taker_tier.entry(format!("{:?}",f.taker_tier)).or_default()+=1;
      r.fees+=u128::from(f.fill.maker_fee_sats)+u128::from(f.fill.taker_fee_sats);
      r.dues+=u128::from(f.fill.oracle_due_sats)+u128::from(f.fill.router_due_sats);
     },
     TierOutcome::Rejected(x)=>*r.exec_rejects.entry(format!("{x:?}")).or_default()+=1,
    }
   }
  }
  loop{
   let s=Instant::now();let b=t.seal_batch().unwrap();let d=ns(s);
   let Some(b)=b else{break};
   r.seal.push(d);r.batches+=1;r.batch_legs+=b.legs().len()as u64;r.batch_dues+=b.oracle_due_sats()+b.router_due_sats();
  }
 }
 r.wall_ns=ns(wall);
 r.balances_conserved=(1..=4).all(|n|t.balance(&channel(n)).unwrap().conserved());
 (r,*t.execution())
}
fn lead_json(e:&ExecutionPolicy)->Value{
 let one=|a:FeedTier,b:FeedTier|{let l=e.lead(a,b);json!({"feed_lead_us":l.feed_us,"order_lead_us":l.order_us,"effective_us_configured":l.effective_us,"double_counted":l.double_counted})};
 json!({"premium_over_standard":one(FeedTier::Premium,FeedTier::Standard),"premium_over_intermediate":one(FeedTier::Premium,FeedTier::Intermediate),
  "note":"configured bounds from the policy; under Combined the effective sum double counts and is not a measurement; no measured advantage is computed"})
}
fn arm_json(name:&str,r:&ArmResult,e:&ExecutionPolicy)->Value{
 let secs=r.wall_ns as f64/1e9;
 json!({"arm":name,"orders":r.submitted,"admitted":r.admitted,"fills":r.fills,"posted":r.posted,"cancelled":r.cancelled,
  "rejects_at_admission":r.submit_rejects,"rejects_at_execution":r.exec_rejects,"fills_by_taker_tier":r.fills_by_taker_tier,
  "batches":r.batches,"batch_legs":r.batch_legs,
  "fee_conservation":{"sum_maker_taker_fees":r.fees.to_string(),"sum_oracle_router_due_fills":r.dues.to_string(),"sum_batch_due":r.batch_dues.to_string(),
   "conserved":r.fees==r.dues&&r.dues==r.batch_dues},
  "balances_conserved":r.balances_conserved,
  "throughput":{"orders_per_s":r.submitted as f64/secs,"fills_per_s":r.fills as f64/secs,"loop_wall_s":secs,"basis":"whole timed loop incl. mark ingest and instrumentation"},
  "stages":{"router_admission_admitted":r.admit.json(),"router_admission_rejected":r.admit_reject.json(),
   "process_one_all_outcomes":r.process_all.json(),"matching_fills":r.matching.json(),"seal_batch":r.seal.json()},
  "lead":lead_json(e)})
}

// ---------- fee ledger ----------
fn lanes()->Vec<Lane>{(1..=4u8).map(|n|Lane{channel:channel(n),peer:pk(70+n),monitor:pk(90+n),initial:Head{revision:0,commitment:10,state:[110+n;32]}}).collect()}
fn recipients()->FeeRecipients{FeeRecipients{oracle:pk(110),router:pk(111)}}
fn marks(p:&Policy,seq:u64,t:u64)->[RelayTick;2]{
 std::array::from_fn(|i|RelayTick{scope:p.scope(),source:i as u8+1,sequence:seq,publish_us:t,price_e8:PRICE,report_hash:[i as u8+1;32],signature:ZERO}.signed(&sk(50+i as u8)).unwrap())
}
fn order(p:&Policy,n:u8,seq:u64,action:Action,side:OrderSide,q:u64)->Intent{
 Intent{scope:p.scope(),router:1,channel:channel(n),owner:[0;32],sequence:seq,expires_us:T0+u64::MAX/4,action,side,tier:Tier::Priority,quantity:q,limit_usd:100_000,leverage_bps:10_000,
  max_fee_ppm:rate_ppm(Tier::Priority,action),max_fee_sats:100_000,cancel_target:[0;32],signature:ZERO}.signed(&sk(n)).unwrap()
}
fn approvals(b:&Batch)->Vec<BatchApproval>{
 b.accounts().iter().map(|a|{let n=a.channel.txid[0];let h=b.approval_message(&a.channel).unwrap();
  BatchApproval{channel:a.channel.clone(),signature:bip340_sign(&sk(n),&h).unwrap()}}).collect()
}
fn ack(d:&DurableRouter,b:&Batch,disp:Disposition)->AckBundle{
 let mut channels=Vec::new();
 for a in b.accounts(){
  let n=a.channel.txid[0];
  let previous=d.head(&a.channel).unwrap().unwrap();let mut next=previous;next.revision+=1;
  let tag=(b.sequence()%100)as u8;
  if disp==Disposition::Commit{next.commitment+=1;next.state=[130+n+tag;32];}
  let mut c=ChannelAck{channel:a.channel.clone(),previous,next,evidence:[150+n+tag;32],
   fee_evidence:if disp==Disposition::Commit&&a.fee_sats>0{let mut v=[0;32];v[0]=n;v[1..9].copy_from_slice(&b.sequence().to_le_bytes());v[31]=180;v}else{[0;32]},signatures:[ZERO;3]};
  let h=d.ack_message(b.sequence(),disp,&c).unwrap();
  c.signatures=[bip340_sign(&sk(n),&h).unwrap(),bip340_sign(&sk(70+n),&h).unwrap(),bip340_sign(&sk(90+n),&h).unwrap()];
  channels.push(c);
 }
 AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:disp,channels}
}
const OPS:[(u8,u32);3]=[(120,3),(121,1),(122,1)];
fn rpolicy()->RecipientPolicy{RecipientPolicy{version:1,oracle_operators:OPS.iter().map(|(n,w)|(pk(*n),*w)).collect(),upkeep:(pk(123),1000),router:pk(124)}}
fn group()->GroupCommit{GroupCommit{max_obligations:1_000_000,max_delay_us:1_000_000}}
fn receipt(recipient:u8,msat:u64,id:u64,refs:Vec<BatchRef>)->FeeReceipt{
 let mut pre=[0u8;32];pre[..8].copy_from_slice(&id.to_le_bytes());pre[31]=0xA5;
 FeeReceipt{recipient:pk(recipient),amount_msat:msat,payment_hash:MockAdapter::payment_hash(&pre),preimage:pre,batch_refs:refs,signature:ZERO}.signed(&sk(recipient)).unwrap()
}
struct FeeFx{d:DurableRouter,batches:Vec<Batch>,acks:Vec<AckBundle>,receipts:Vec<FeeReceipt>,dir:PathBuf}
fn fee_fixture(k:u64)->FeeFx{
 let dir=std::env::temp_dir().join(format!("shz-hft06-bench-{}",std::process::id()));
 let _=fs::remove_dir_all(&dir);fs::create_dir_all(&dir).unwrap();
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),20_000_000_000,vec![Share{router:1,sats:10_000_000_000},Share{router:2,sats:10_000_000_000}]).unwrap()).collect();
 let g=Registry::new(p.scope(),public(&AUTH),plans).unwrap();
 let mut d=DurableRouter::create(&dir.join("router.wal"),p.clone(),&g,1,Engine::Both,lanes(),recipients()).unwrap();
 let (mut batches,mut acks)=(Vec::new(),Vec::new());
 for i in 1..=k{
  let at=T0+(i-1)*200_000;
  d.update_mark(marks(&p,i,at),at).unwrap();
  d.submit(order(&p,1,i,Action::Post,OrderSide::Short,1000),at).unwrap();
  let o=d.process_one(at).unwrap().unwrap();assert!(matches!(o,Outcome::Posted(_)),"batch {i}: {o:?}");
  d.submit(order(&p,2,i,Action::Take,OrderSide::Long,1000),at).unwrap();
  let o=d.process_one(at+100_000).unwrap().unwrap();assert!(matches!(o,Outcome::Filled(_)),"batch {i} take: {o:?}");
  d.process_one(at+200_000).unwrap();
  let b=d.seal_fill_batch().unwrap().unwrap();
  d.prepare(i,approvals(&b)).unwrap();
  let disp=if i%10==0{Disposition::FencedAbort}else{Disposition::Commit};
  let a=ack(&d,&b,disp);assert!(d.resolve(a.clone()).unwrap());
  batches.push(b);acks.push(a);
 }
 let pol=rpolicy();let mut receipts=Vec::new();let mut id=1u64;
 for (b,a) in batches.iter().zip(&acks){
  if a.disposition!=Disposition::Commit{continue}
  let s=pol.split(u64::try_from(b.oracle_due_sats()).unwrap(),u64::try_from(b.router_due_sats()).unwrap());
  let sh=s.shares();
  for n in 120u8..=124{if let Some(v)=sh.get(&pk(n)){if *v>0{receipts.push(receipt(n,v*1000,id,vec![(1,b.sequence())]));id+=1;}}}
 }
 FeeFx{d,batches,acks,receipts,dir}
}
fn run_fee(fx:&FeeFx,ledger:&mut FeeLedger,wal:Option<&PathBuf>)->Value{
 let (mut accrue,mut commit,mut reverse,mut rcpt,mut per_batch)=(Samples::default(),Samples::default(),Samples::default(),Samples::default(),Samples::default());
 let mut batch_total:Vec<u64>=vec![0;fx.batches.len()];
 for (i,(b,a)) in fx.batches.iter().zip(&fx.acks).enumerate(){
  let s=Instant::now();ledger.observe_batch(b).unwrap();let d=ns(s);accrue.push(d);batch_total[i]+=d;
  let s=Instant::now();ledger.observe_resolution(&fx.d,a,2_000_000+i as u64).unwrap();let d=ns(s);
  if a.disposition==Disposition::Commit{commit.push(d)}else{reverse.push(d)}
  batch_total[i]+=d;
 }
 let ad=MockAdapter::new();
 let mut by_seq:BTreeMap<u64,u64>=BTreeMap::new();
 for r in &fx.receipts{
  let s=Instant::now();let ok=ledger.receive_receipt(&ad,r).unwrap();let d=ns(s);assert!(ok);rcpt.push(d);
  *by_seq.entry(r.batch_refs[0].1).or_default()+=d;
 }
 for (i,b) in fx.batches.iter().enumerate(){per_batch.push(batch_total[i]+by_seq.get(&b.sequence()).copied().unwrap_or(0))}
 let totals=ledger.all_totals();
 let sum=|f:fn(&RecipientTotals)->u64|totals.values().map(|t|u128::from(f(t))).sum::<u128>();
 let (cor,cro)=ledger.committed_by_role();
 let (fo,fr)=fx.d.fee_totals().unwrap();
 let committed=sum(|t|t.committed);
 let rec=ledger.reconcile(&fx.d).unwrap();
 let mut v=json!({
  "stages":{"fee_accrue_observe_batch":accrue.json(),"fee_commit_observe_resolution_commit":commit.json(),
   "fee_reverse_observe_resolution_abort":reverse.json(),"fee_receive_receipt":rcpt.json(),"fee_path_per_batch_total":per_batch.json()},
  "fee_conservation":{"sum_recipient_committed_splits":committed.to_string(),"sum_committed_fees_oracle_plus_router":(cor+cro).to_string(),
   "durable_router_fee_totals":(fo+fr).to_string(),"conserved":committed==cor+cro&&committed==fo+fr&&rec.clean(),"reconcile_clean":rec.clean(),
   "collected":sum(|t|t.collected).to_string(),"outstanding":sum(|t|t.outstanding).to_string(),"reversed":sum(|t|t.reversed).to_string()},
  "batches":fx.batches.len(),"receipts":fx.receipts.len()});
 if let Some(p)=wal{
  let len=fs::metadata(p).unwrap().len();
  v["wal_bytes_total"]=json!(len);v["wal_bytes_per_batch"]=json!(len as f64/fx.batches.len()as f64);
 }
 v
}

fn main(){
 let a:Vec<String>=std::env::args().collect();
 let mut orders=20_000usize;let mut fee_batches=200u64;let mut out:Option<String>=None;
 let mut i=1;
 while i<a.len(){
  match a[i].as_str(){
   "--orders"=>{orders=a[i+1].parse().unwrap();i+=2},
   "--fee-batches"=>{fee_batches=a[i+1].parse().unwrap();i+=2},
   "--out"=>{out=Some(a[i+1].clone());i+=2},
   o=>panic!("unknown arg {o}"),
  }
 }
 let arms=[("FeedOnly",Arm::FeedOnly),("SchedulerOnly",Arm::SchedulerOnly),("Combined",Arm::Combined)];
 let mut arm_values=Vec::new();let mut primary=Value::Null;
 for (name,arm) in arms{
  let (r,e)=run_arm(arm,orders);
  let j=arm_json(name,&r,&e);
  eprintln!("{name}: orders={} fills={} admit p50={:.1}us p99={:.1}us",r.submitted,r.fills,
   j["stages"]["router_admission_admitted"]["p50_us"].as_f64().unwrap(),j["stages"]["router_admission_admitted"]["p99_us"].as_f64().unwrap());
  if name=="FeedOnly"{primary=j.clone()}
  arm_values.push(j);
 }
 let fx=fee_fixture(fee_batches);
 let mut mem=FeeLedger::in_memory(1,rpolicy(),group()).unwrap();
 let fee_mem=run_fee(&fx,&mut mem,None);
 let wal=fx.dir.join("fees.wal");
 let mut dur=FeeLedger::create(&wal,1,rpolicy(),group()).unwrap();
 let fee_dur=run_fee(&fx,&mut dur,Some(&wal));
 drop(dur);let _=fs::remove_dir_all(&fx.dir);
 let receipt=json!({
  "schema":"shz-hft06-router-bench/v1","synthetic":true,"production_ready":false,
  "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"family":std::env::consts::FAMILY,"profile":if cfg!(debug_assertions){"debug"}else{"release"}},
  "params":{"orders":orders,"fee_batches":fee_batches,"round_step_us":STEP,"primary_arm":"FeedOnly"},
  "stages":primary["stages"].clone(),"throughput":primary["throughput"].clone(),
  "fee_conservation":primary["fee_conservation"].clone(),
  "wal_bytes_per_batch":fee_dur["wal_bytes_per_batch"].clone(),
  "fee_ledger":{"durable_wal":fee_dur,"in_memory":fee_mem,
   "fed_by":"HFT-05 DurableRouter batches (observe_resolution authenticates against it), not TieredRouter batches"},
  "arms":arm_values,
  "not_measured":["network or Lightning transport latency (MockAdapter only)","real LN payment proofs","multi-router or multi-process contention","measured combined lead advantage (configured bounds only)","WAL cost of the matching path (TieredRouter is in-memory)","memory or peak RSS"],
  "notes":["virtual clock gates eligibility; delays are configuration, not measured latency","intents pre-built and pre-signed outside timing","extra intents inject reject reasons deterministically"]
 });
 let s=serde_json::to_string_pretty(&receipt).unwrap();
 if let Some(p)=out{
  if let Some(par)=std::path::Path::new(&p).parent(){if !par.as_os_str().is_empty(){fs::create_dir_all(par).unwrap()}}
  fs::write(&p,&s).unwrap();eprintln!("wrote {p}");
 }else{println!("{s}")}
}
