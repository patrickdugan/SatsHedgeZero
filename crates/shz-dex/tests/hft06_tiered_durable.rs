//! Gate G-LN-2: durable tiered router (journal + signed channel acknowledgements) and
//! the HFT-06 fee ledger consuming its authenticated resolutions. Synthetic funds only.
use shz_dex::{OrderSide,routing::*};
use shz_dex::routing::durable::{AckBundle,ChannelAck,Disposition,DurableRouter,FeeRecipients,Head,Lane,Phase};
use shz_dex::routing::ln_fees::*;
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dlc::{Bip340Signature,BtcOutPoint,bip340_sign,tagged_hash};
use std::{fs,io::Write,path::{Path,PathBuf},sync::atomic::{AtomicU64,Ordering}};

type Key=[u8;32];
const T0:u64=1_000_000;
const AUTH:[u8;32]=[77;32];
const RELAY:u8=60;
const PRICE:u64=10_000_000_000_000;
const CAP:u64=100_000_000;
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
fn sk(n:u8)->Key{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[pk(50),pk(51)]}}
fn registry(cap:u64)->Registry{
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),cap*2,vec![Share{router:1,sats:cap},Share{router:2,sats:cap}]).unwrap()).collect();
 Registry::new(p.scope(),public(&AUTH),plans).unwrap()
}
fn cfg()->TieredConfig{
 TieredConfig{scope:policy().scope(),router:1,entitlement_key:pk(RELAY),tariff:TariffSchedule::default_candidate(),
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
  let p=std::env::temp_dir().join(format!("shz-hft06td-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
 fn path(&self,n:&str)->PathBuf{self.0.join(n)}
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

fn create(path:&Path)->DurableTieredRouter{DurableTieredRouter::create(path,&registry(CAP),cfg(),lanes(),recipients()).unwrap()}
fn reopen(path:&Path,min:Option<shz_dex::routing::durable::JournalTip>)->Result<DurableTieredRouter,TieredDurableError>{
 DurableTieredRouter::open(path,&registry(CAP),cfg(),lanes(),recipients(),min)
}
fn open(path:&Path)->DurableTieredRouter{reopen(path,None).unwrap()}
fn failure(r:Result<DurableTieredRouter,TieredDurableError>)->TieredDurableError{match r{Err(e)=>e,Ok(_)=>panic!("expected open to fail")}}

fn mark(seq:u64,t:u64)->MarkView{MarkView{packet_digest:[seq as u8+100;32],seq,price_e8:Some(PRICE),boundary_us:t,public_release_us:t}}
fn grant(n:u8,tier:FeedTier)->Entitlement{
 Entitlement{client:pk(n),tier,tariff_version:1,valid_from_us:0,valid_until_us:T0+50_000_000,relay_key:[0;32],signature:ZERO_SIG}.signed(&sk(RELAY)).unwrap()
}
fn intent(n:u8,seq:u64,action:Action,side:OrderSide,tier:FeedTier,q:u64,ent:Option<&Entitlement>)->IntentV6{
 let c=cfg();
 IntentV6{scope:c.scope,router:1,channel:channel(n),owner:[0;32],sequence:seq,expires_us:T0+10_000_000,action,side,tier,
  tariff_version:c.tariff.version,entitlement_digest:ent.map(|e|e.digest()).unwrap_or([0;32]),execution_policy:c.execution.id(),
  quantity:q,limit_usd:100_000,leverage_bps:10_000,max_fee_ppm:c.tariff.rate_ppm(tier,action),max_fee_sats:100_000,
  max_mark_age_us:1_000_000,early_window_opt_in:false,cancel_target:[0;32],signature:ZERO_SIG}.signed(&sk(n)).unwrap()
}
fn round_time(r:u64)->u64{T0+r*1_000_000}
/// One fill in its own 100 ms window: maker posts a short quote, taker lifts it.
fn fill_round(d:&mut DurableTieredRouter,r:u64,tier:FeedTier,maker:u8,taker:u8,q:u64){
 let t=round_time(r);let now=t+200_000;let seq=r+1;
 d.ingest_mark(mark(r+1,t),t).unwrap();
 let ent=|n:u8|if tier==FeedTier::Standard{None}else{Some(grant(n,tier))};
 let (me,te)=(ent(maker),ent(taker));
 d.submit(intent(maker,seq,Action::Post,OrderSide::Short,tier,q,me.as_ref()),me.clone(),now).unwrap();
 assert!(matches!(d.process_one(now).unwrap().unwrap(),TierOutcome::Posted(_)));
 d.submit(intent(taker,seq,Action::Take,OrderSide::Long,tier,q,te.as_ref()),te.clone(),now).unwrap();
 assert!(matches!(d.process_one(now).unwrap().unwrap(),TierOutcome::Filled(_)));
}
fn seal_round(d:&mut DurableTieredRouter,r:u64)->Batch{
 d.process_one(round_time(r)+500_000).unwrap();
 d.seal_batch().unwrap().expect("window elapsed")
}
/// Rounds: 0 premium, 1 intermediate, 2 standard, 3 premium. Rounds 1 uses channels 3/4 only.
fn round(d:&mut DurableTieredRouter,r:u64)->Batch{
 match r{
  0=>fill_round(d,0,FeedTier::Premium,1,2,1000),
  1=>fill_round(d,1,FeedTier::Intermediate,3,4,1000),
  2=>fill_round(d,2,FeedTier::Standard,1,2,500),
  3=>fill_round(d,3,FeedTier::Premium,1,2,1000),
  _=>unreachable!(),
 }
 seal_round(d,r)
}
fn approvals(b:&Batch)->Vec<BatchApproval>{
 b.accounts().iter().map(|a|{
  let n=a.channel.txid[0];let h=b.approval_message(&a.channel).unwrap();
  BatchApproval{channel:a.channel.clone(),signature:bip340_sign(&sk(n),&h).unwrap()}
 }).collect()
}
fn sign_all(n:u8,h:&Key,a:&mut ChannelAck){
 a.signatures=[bip340_sign(&sk(n),h).unwrap(),bip340_sign(&sk(70+n),h).unwrap(),bip340_sign(&sk(90+n),h).unwrap()];
}
fn ack(d:&DurableTieredRouter,b:&Batch,disp:Disposition)->AckBundle{
 let mut channels=Vec::new();
 for a in b.accounts(){
  let n=a.channel.txid[0];
  let previous=d.head(&a.channel).unwrap().unwrap();let mut next=previous;next.revision+=1;
  if disp==Disposition::Commit{next.commitment+=1;next.state=[130+n+b.sequence()as u8;32];}
  let mut c=ChannelAck{channel:a.channel.clone(),previous,next,evidence:[150+n+b.sequence()as u8;32],
   fee_evidence:if disp==Disposition::Commit&&a.fee_sats>0{let mut v=[0;32];v[0]=n;v[1..9].copy_from_slice(&b.sequence().to_le_bytes());v[31]=180;v}else{[0;32]},signatures:[ZERO;3]};
  let h=d.ack_message(b.sequence(),disp,&c).unwrap();sign_all(n,&h,&mut c);channels.push(c);
 }
 AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:disp,channels}
}
fn put64(b:&mut Vec<u8>,n:u64){b.extend(n.to_le_bytes())}
fn put_head(b:&mut Vec<u8>,h:&Head){put64(b,h.revision);put64(b,h.commitment);b.extend(h.state)}
/// Independent reconstruction of the acknowledgement digest with a caller-chosen domain tag.
fn message(tag:&[u8],config:&Key,seq:u64,b:&Batch,disp:Disposition,a:&ChannelAck)->Key{
 let o=b.accounts().iter().find(|o|o.channel.txid==a.channel.txid&&o.channel.vout==a.channel.vout).unwrap();
 let mut v=Vec::new();v.extend(config);v.extend(b.digest());put64(&mut v,seq);
 v.push(match disp{Disposition::Commit=>1,Disposition::FencedAbort=>2});
 v.extend(a.channel.txid);v.extend(a.channel.vout.to_le_bytes());v.extend(o.owner);put64(&mut v,o.margin_sats);put64(&mut v,o.fee_sats);
 put_head(&mut v,&a.previous);put_head(&mut v,&a.next);v.extend(a.evidence);v.extend(a.fee_evidence);
 v.extend(recipients().oracle);v.extend(recipients().router);
 v.extend(b.oracle_due_sats().to_le_bytes());v.extend(b.router_due_sats().to_le_bytes());
 tagged_hash(tag,&v)
}
/// Four batches: 1 premium commit, 2 intermediate fenced abort, 3 standard commit, 4 premium commit.
fn drive_all(d:&mut DurableTieredRouter)->(Vec<Batch>,Vec<AckBundle>){
 let (mut bs,mut acks)=(Vec::new(),Vec::new());
 for r in 0..4{bs.push(round(d,r));}
 for b in &bs{
  d.prepare(b.sequence(),approvals(b)).unwrap();
  let disp=if b.sequence()==2{Disposition::FencedAbort}else{Disposition::Commit};
  let a=ack(d,b,disp);assert!(d.resolve(a.clone()).unwrap());acks.push(a);
 }
 (bs,acks)
}
fn snapshot(d:&DurableTieredRouter)->String{
 let r=d.router().unwrap();let mut s=String::new();
 for n in 1..=4{s+=&format!("{:?}|{:?}\n",d.balance(&channel(n)).unwrap(),d.head(&channel(n)).unwrap());}
 s+=&format!("{}|{}|{}|{}|{:?}|{}\n",r.fill_count(),r.resting(),r.pending_orders(),r.clock_us(),r.marks(),r.batch_sequence());
 let mut seq=1;
 while let Some((b,phase))=d.batch(seq).unwrap(){
  s+=&format!("{seq}|{:?}|{:?}|{:?}\n",b.digest(),phase,d.acknowledgement(seq).unwrap());
  for leg in b.legs(){s+=&format!("{:?}\n",r.fill(&leg.taker_id));}
  seq+=1;
 }
 s+=&format!("{:?}|{}|{:?}\n",d.fee_totals().unwrap(),d.next_resolution().unwrap(),d.tip().unwrap());s
}

#[test]fn replay_after_restart_reproduces_book_marks_fills_balances_batches_and_phases(){
 let t=Temp::new();let p=t.path("tiered.wal");
 let mut d=create(&p);
 let (bs,_)=drive_all(&mut d);
 // leave an unfilled resting premium quote and an operator hold in the journal
 d.ingest_mark(mark(5,round_time(4)),round_time(4)).unwrap();
 let e=grant(1,FeedTier::Premium);
 d.submit(intent(1,9,Action::Post,OrderSide::Short,FeedTier::Premium,100,Some(&e)),Some(e),round_time(4)+200_000).unwrap();
 assert!(matches!(d.process_one(round_time(4)+200_000).unwrap().unwrap(),TierOutcome::Posted(_)));
 d.set_emergency_hold(true).unwrap();
 let before=snapshot(&d);let tip=d.tip().unwrap();
 assert_eq!(d.router().unwrap().resting(),1);assert!(d.router().unwrap().emergency_hold());
 assert_eq!(bs.len(),4);assert!(d.router().unwrap().fill_count()==4);
 drop(d);
 let d=reopen(&p,Some(tip)).unwrap();
 assert_eq!(snapshot(&d),before);
 assert!(d.router().unwrap().emergency_hold());
 assert_eq!(d.batch(2).unwrap().unwrap().1,Phase::Aborted);assert_eq!(d.batch(3).unwrap().unwrap().1,Phase::Committed);
}

#[test]fn restart_between_every_stage_reaches_the_same_journal_tip_as_a_straight_run(){
 let t=Temp::new();
 let straight=t.path("a.wal");let mut d=create(&straight);drive_all(&mut d);let want=snapshot(&d);drop(d);
 let p=t.path("b.wal");let mut d=create(&p);
 let (mut bs,mut acks)=(Vec::new(),Vec::new());
 for r in 0..4{bs.push(round(&mut d,r));drop(d);d=open(&p);}
 for b in &bs{
  d.prepare(b.sequence(),approvals(b)).unwrap();drop(d);d=open(&p);
  let disp=if b.sequence()==2{Disposition::FencedAbort}else{Disposition::Commit};
  let a=ack(&d,b,disp);assert!(d.resolve(a.clone()).unwrap());acks.push(a);drop(d);d=open(&p);
 }
 assert_eq!(snapshot(&d),want);
}

#[test]fn rejected_calls_are_journaled_and_replay_their_clock_effect(){
 let t=Temp::new();let p=t.path("r.wal");let mut d=create(&p);
 d.ingest_mark(mark(1,T0),T0).unwrap();
 let tip=d.tip().unwrap();
 // replayed sequence number at a later time: rejected, but the clock moved and a frame exists
 let e=grant(1,FeedTier::Premium);
 d.submit(intent(1,1,Action::Post,OrderSide::Short,FeedTier::Premium,10,Some(&e)),Some(e.clone()),T0+10).unwrap();
 let rej=d.submit(intent(1,1,Action::Post,OrderSide::Short,FeedTier::Premium,10,Some(&e)),Some(e),T0+500);
 assert!(matches!(rej,Err(TieredDurableError::Rejected(TierReject::Replay))));
 assert_eq!(d.tip().unwrap().records,tip.records+2);
 assert!(d.router().unwrap().visible_mark(FeedTier::Premium,T0).is_some());
 let clock=d.router().unwrap().clock_us();assert_eq!(clock,T0+500);
 let snap=snapshot(&d);drop(d);
 let d=open(&p);assert_eq!(snapshot(&d),snap);assert_eq!(d.router().unwrap().clock_us(),clock);
}

#[test]fn crash_between_append_and_apply_replays_the_persisted_command(){
 let t=Temp::new();let p=t.path("c.wal");let mut d=create(&p);
 d.ingest_mark(mark(1,T0),T0).unwrap();
 let now=T0+200_000;
 let (me,te)=(grant(1,FeedTier::Premium),grant(2,FeedTier::Premium));
 d.submit(intent(1,1,Action::Post,OrderSide::Short,FeedTier::Premium,1000,Some(&me)),Some(me),now).unwrap();
 assert!(matches!(d.process_one(now).unwrap().unwrap(),TierOutcome::Posted(_)));
 d.submit(intent(2,1,Action::Take,OrderSide::Long,FeedTier::Premium,1000,Some(&te)),Some(te),now).unwrap();
 // the fill is journaled but the process dies before it is applied or acknowledged
 d.append_process_without_apply(now).unwrap();
 assert!(matches!(d.tip(),Err(TieredDurableError::Poisoned)));
 assert!(matches!(d.process_one(now),Err(TieredDurableError::Poisoned)));
 drop(d);
 let d=open(&p);
 let r=d.router().unwrap();
 assert_eq!(r.fill_count(),1);assert_eq!(r.pending_orders(),0);
 assert!(d.balance(&channel(2)).unwrap().unwrap().pending>0);
}

#[test]fn exclusive_writer_lock_and_foreign_files_are_refused(){
 let t=Temp::new();let p=t.path("l.wal");let d=create(&p);
 assert!(matches!(failure(reopen(&p,None)),TieredDurableError::Locked));
 assert!(DurableTieredRouter::create(&p,&registry(CAP),cfg(),lanes(),recipients()).is_err());
 drop(d);
 // an HFT-05 journal is not a tiered journal
 let h5=t.path("h5.wal");
 let dr=DurableRouter::create(&h5,policy(),&registry(CAP),1,Engine::Both,lanes(),recipients()).unwrap();drop(dr);
 assert!(matches!(failure(reopen(&h5,None)),TieredDurableError::Corrupt));
}

#[test]fn torn_and_corrupt_tails_fail_closed(){
 let t=Temp::new();let p=t.path("t.wal");let mut d=create(&p);
 drive_all(&mut d);drop(d);
 let good=fs::read(&p).unwrap();
 // torn final frame (one byte short)
 fs::write(&p,&good[..good.len()-1]).unwrap();
 assert!(matches!(failure(reopen(&p,None)),TieredDurableError::Corrupt));
 // partial length prefix of a next frame
 fs::write(&p,&good).unwrap();
 fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(&[9,0]).unwrap();
 assert!(matches!(failure(reopen(&p,None)),TieredDurableError::Corrupt));
 // flipped byte in the middle of the chain
 let mut bad=good.clone();let at=bad.len()/2;bad[at]^=0x01;
 fs::write(&p,&bad).unwrap();
 assert!(matches!(failure(reopen(&p,None)),TieredDurableError::Corrupt));
 // wrong magic
 let mut bad=good.clone();bad[7]=b'5';fs::write(&p,&bad).unwrap();
 assert!(matches!(failure(reopen(&p,None)),TieredDurableError::Corrupt));
 // untouched copy still opens
 fs::write(&p,&good).unwrap();let d=open(&p);assert!(d.fee_totals().unwrap().0 > 0);
}

#[test]fn configuration_substitution_fails_closed(){
 let t=Temp::new();let p=t.path("cfg.wal");let d=create(&p);let h=d.config_hash();drop(d);
 let open_with=|c:TieredConfig,reg:Registry,l:Vec<Lane>,r:FeeRecipients|DurableTieredRouter::open(&p,&reg,c,l,r,None);
 let ok=open_with(cfg(),registry(CAP),lanes(),recipients()).unwrap();assert_eq!(ok.config_hash(),h);drop(ok);
 let cfg_err=|r:Result<DurableTieredRouter,TieredDurableError>|assert!(matches!(failure(r),TieredDurableError::Config));
 cfg_err(open_with(TieredConfig{tariff:TariffSchedule::default_candidate().with_intermediate_maker(10),..cfg()},registry(CAP),lanes(),recipients()));
 cfg_err(open_with(TieredConfig{execution:ExecutionPolicy::defaults(Arm::Combined),..cfg()},registry(CAP),lanes(),recipients()));
 cfg_err(open_with(TieredConfig{revenue:RevenuePolicy{oracle_share_bps:5000},..cfg()},registry(CAP),lanes(),recipients()));
 cfg_err(open_with(TieredConfig{entitlement_key:pk(61),..cfg()},registry(CAP),lanes(),recipients()));
 cfg_err(open_with(TieredConfig{router:2,..cfg()},registry(CAP),lanes(),recipients()));
 cfg_err(open_with(cfg(),registry(CAP-1),lanes(),recipients()));
 cfg_err(open_with(cfg(),registry(CAP),lanes(),FeeRecipients{oracle:pk(111),router:pk(110)}));
 let mut l=lanes();l[0].monitor=pk(99);
 cfg_err(open_with(cfg(),registry(CAP),l,recipients()));
 let mut l=lanes();l[2].initial.commitment=11;
 cfg_err(open_with(cfg(),registry(CAP),l,recipients()));
}

#[test]fn valid_prefix_rollback_is_detected_with_a_pinned_tip(){
 let t=Temp::new();let p=t.path("rb.wal");let mut d=create(&p);
 let b1=round(&mut d,0);d.prepare(1,approvals(&b1)).unwrap();
 let (tip_a,len_a)=(d.tip().unwrap(),fs::metadata(&p).unwrap().len());
 let a=ack(&d,&b1,Disposition::Commit);assert!(d.resolve(a).unwrap());
 let tip_b=d.tip().unwrap();drop(d);
 // storage silently rolled back to a valid earlier prefix
 fs::OpenOptions::new().write(true).open(&p).unwrap().set_len(len_a).unwrap();
 assert!(matches!(failure(reopen(&p,Some(tip_b))),TieredDurableError::Rollback));
 let d=reopen(&p,Some(tip_a)).unwrap();
 assert_eq!(d.batch(1).unwrap().unwrap().1,Phase::Prepared);drop(d);
 // without an independent pin the rollback is not detectable
 assert!(reopen(&p,None).is_ok());
}

#[test]fn acknowledgement_state_machine_enforces_order_idempotence_and_no_timeout_release(){
 let t=Temp::new();let p=t.path("sm.wal");let mut d=create(&p);
 let b1=round(&mut d,0);let b2=round(&mut d,1);
 // cannot resolve or prepare out of order or before prepare
 let a1=ack(&d,&b1,Disposition::Commit);
 assert!(matches!(d.resolve(a1.clone()),Err(TieredDurableError::Rejected(TierReject::Replay))));
 assert!(matches!(d.prepare(2,approvals(&b2)),Err(TieredDurableError::Rejected(TierReject::Replay))));
 // missing or wrong approvals do not prepare
 let mut partial=approvals(&b1);partial.pop();
 assert!(d.prepare(1,partial).is_err());assert_eq!(d.batch(1).unwrap().unwrap().1,Phase::Sealed);
 // time alone never releases collateral
 let pending=d.balance(&channel(2)).unwrap().unwrap().pending;assert!(pending>0);
 d.process_one(T0+3_600_000_000).unwrap();
 assert_eq!(d.balance(&channel(2)).unwrap().unwrap().pending,pending);assert_eq!(d.batch(1).unwrap().unwrap().1,Phase::Sealed);
 d.prepare(1,approvals(&b1)).unwrap();d.prepare(1,approvals(&b1)).unwrap();
 // wrong signature, wrong heads, missing channel
 let mut bad=a1.clone();bad.channels[0].signatures[2]=bad.channels[1].signatures[2];
 assert!(matches!(d.resolve(bad),Err(TieredDurableError::Rejected(TierReject::Signature))));
 let mut bad=a1.clone();bad.channels.pop();assert!(d.resolve(bad).is_err());
 let mut bad=a1.clone();bad.channels[0].previous.revision=5;assert!(d.resolve(bad).is_err());
 assert!(d.resolve(a1.clone()).unwrap());
 // exact retry is idempotent, a conflicting replay is rejected
 assert!(!d.resolve(a1.clone()).unwrap());
 let mut other=a1.clone();other.disposition=Disposition::FencedAbort;
 assert!(matches!(d.resolve(other),Err(TieredDurableError::Rejected(TierReject::Replay))));
 let tip=d.tip().unwrap();drop(d);
 let mut d=reopen(&p,Some(tip)).unwrap();
 assert!(!d.resolve(a1).unwrap());
 // fenced abort frees collateral and leaves the commitment head unchanged
 d.prepare(2,approvals(&b2)).unwrap();
 let head=d.head(&channel(3)).unwrap().unwrap();
 let a2=ack(&d,&b2,Disposition::FencedAbort);assert!(d.resolve(a2).unwrap());
 let bal=d.balance(&channel(3)).unwrap().unwrap();
 assert_eq!((bal.pending,bal.committed,bal.paid_fees),(0,0,0));assert_eq!(bal.free,CAP);
 let after=d.head(&channel(3)).unwrap().unwrap();
 assert_eq!((after.revision,after.commitment,after.state),(head.revision+1,head.commitment,head.state));
}

#[test]fn hft05_acknowledgements_and_domain_tags_cannot_cross_into_the_tiered_router(){
 // An HFT-05 router with the same registry, lanes and recipients produces a valid bundle.
 let t=Temp::new();
 let mut h5=DurableRouter::create(&t.path("h5.wal"),policy(),&registry(CAP),1,Engine::Both,lanes(),recipients()).unwrap();
 let ticks:[RelayTick;2]=std::array::from_fn(|i|RelayTick{scope:policy().scope(),source:i as u8+1,sequence:1,publish_us:T0,price_e8:PRICE,report_hash:[i as u8+1;32],signature:ZERO}.signed(&sk(50+i as u8)).unwrap());
 h5.update_mark(ticks,T0).unwrap();
 let o=|n:u8,a:Action,s:OrderSide|Intent{scope:policy().scope(),router:1,channel:channel(n),owner:[0;32],sequence:1,expires_us:T0+10_000_000,action:a,side:s,tier:Tier::Priority,
  quantity:1000,limit_usd:100_000,leverage_bps:10_000,max_fee_ppm:shz_dex::routing::rate_ppm(Tier::Priority,a),max_fee_sats:100_000,cancel_target:[0;32],signature:ZERO}.signed(&sk(n)).unwrap();
 h5.submit(o(1,Action::Post,OrderSide::Short),T0).unwrap();h5.process_one(T0).unwrap();
 h5.submit(o(2,Action::Take,OrderSide::Long),T0).unwrap();h5.process_one(T0+100_000).unwrap();
 h5.process_one(T0+200_000).unwrap();
 let hb=h5.seal_fill_batch().unwrap().unwrap();
 h5.prepare(1,approvals(&hb)).unwrap();
 let mut hc=Vec::new();
 for a in hb.accounts(){
  let n=a.channel.txid[0];let previous=h5.head(&a.channel).unwrap().unwrap();let mut next=previous;next.revision+=1;next.commitment+=1;next.state=[200+n;32];
  let mut c=ChannelAck{channel:a.channel.clone(),previous,next,evidence:[151+n;32],
   fee_evidence:if a.fee_sats>0{let mut v=[0;32];v[0]=n;v[31]=181;v}else{[0;32]},signatures:[ZERO;3]};
  let h=h5.ack_message(1,Disposition::Commit,&c).unwrap();sign_all(n,&h,&mut c);hc.push(c);
 }
 let h5_bundle=AckBundle{sequence:1,batch:hb.digest(),disposition:Disposition::Commit,channels:hc};
 assert!(h5.resolve(h5_bundle.clone()).unwrap());

 let mut d=create(&t.path("t.wal"));
 let b1=round(&mut d,0);d.prepare(1,approvals(&b1)).unwrap();
 let before=snapshot(&d);
 // the HFT-05 bundle is bound to another router's batch
 assert!(matches!(d.resolve(h5_bundle),Err(TieredDurableError::Rejected(TierReject::Replay))));
 // a bundle over the tiered batch signed under the HFT-05 domain tag verifies nowhere
 let mut forged=ack(&d,&b1,Disposition::Commit);
 for c in forged.channels.iter_mut(){
  let n=c.channel.txid[0];
  let h=message(b"SHZ/HFT/CHANNEL-ACK/V1",&d.config_hash(),1,&b1,Disposition::Commit,c);sign_all(n,&h,c);
 }
 assert!(matches!(d.resolve(forged),Err(TieredDurableError::Rejected(TierReject::Signature))));
 // the tiered tag reproduces the router's own digest exactly
 let good=ack(&d,&b1,Disposition::Commit);
 for c in &good.channels{assert_eq!(message(TIERED_ACK_TAG,&d.config_hash(),1,&b1,Disposition::Commit,c),d.ack_message(1,Disposition::Commit,c).unwrap());}
 assert_ne!(TIERED_ACK_TAG,&b"SHZ/HFT/CHANNEL-ACK/V1"[..]);
 // rejected calls left balances, heads and phases unchanged (only journal records advanced)
 let after=snapshot(&d);
 let strip=|s:&str|s.lines().filter(|l|!l.contains("JournalTip")).collect::<Vec<_>>().join("\n");
 assert_eq!(strip(&before),strip(&after));
 assert!(d.resolve(good).unwrap());
}

const OPS:[(u8,u32);3]=[(120,3),(121,1),(122,1)];
fn rpolicy()->RecipientPolicy{
 RecipientPolicy{version:1,oracle_operators:OPS.iter().map(|(n,w)|(pk(*n),*w)).collect(),upkeep:(pk(123),1000),router:pk(124)}
}
fn group()->GroupCommit{GroupCommit{max_obligations:1000,max_delay_us:1_000_000}}
fn receipt(recipient:u8,msat:u64,preimage:u8,refs:Vec<BatchRef>)->FeeReceipt{
 let pre=[preimage;32];
 FeeReceipt{recipient:pk(recipient),amount_msat:msat,payment_hash:MockAdapter::payment_hash(&pre),preimage:pre,batch_refs:refs,signature:ZERO}.signed(&sk(recipient)).unwrap()
}
fn all_keys()->Vec<Key>{vec![pk(120),pk(121),pk(122),pk(123),pk(124)]}
fn sum(l:&FeeLedger)->RecipientTotals{
 let mut t=RecipientTotals::default();
 for k in all_keys(){let x=l.totals(&k);t.accrued+=x.accrued;t.reversed+=x.reversed;t.committed+=x.committed;t.collected+=x.collected;t.outstanding+=x.outstanding}
 t
}

#[test]fn tiered_economic_loop_premium_intermediate_standard_commit_abort_collect_reconcile(){
 let t=Temp::new();let mut d=create(&t.path("t.wal"));
 let (bs,acks)=drive_all(&mut d);
 let due=|b:&Batch|(b.oracle_due_sats()+b.router_due_sats())as u64;
 // tier pricing actually shows up in the batch dues
 assert_eq!((bs[0].oracle_due_sats(),bs[0].router_due_sats()),(154,66));
 assert!(due(&bs[1])>0&&due(&bs[1])<due(&bs[0]),"intermediate taker pays 50 ppm, no maker fee");
 assert_eq!(due(&bs[2]),0,"standard fills are free");
 assert_eq!(due(&bs[3]),220);
 let committed_oracle=bs[0].oracle_due_sats()+bs[2].oracle_due_sats()+bs[3].oracle_due_sats();
 let committed_router=bs[0].router_due_sats()+bs[2].router_due_sats()+bs[3].router_due_sats();
 assert_eq!(d.fee_totals().unwrap(),(committed_oracle,committed_router));
 // channel balances: aborted lanes paid nothing, committed lanes paid fees, conservation holds
 for n in [3u8,4]{let b=d.balance(&channel(n)).unwrap().unwrap();assert_eq!((b.pending,b.committed,b.paid_fees),(0,0,0));assert!(b.conserved());}
 for n in [1u8,2]{let b=d.balance(&channel(n)).unwrap().unwrap();assert!(b.paid_fees>0&&b.committed>0&&b.pending==0&&b.conserved());}

 let mut l=FeeLedger::create(&t.path("fees.wal"),1,rpolicy(),group()).unwrap();
 for b in &bs{assert!(l.observe_batch(b).unwrap());}
 let mut forged=acks[0].clone();forged.channels[0].fee_evidence=[9;32];
 assert!(matches!(l.observe_resolution(&d,&forged,T0),Err(LedgerError::BadResolution)));
 for (i,a) in acks.iter().enumerate(){assert!(l.observe_resolution(&d,a,T0+i as u64).unwrap());assert!(!l.observe_resolution(&d,a,T0+i as u64).unwrap());}
 assert_eq!((l.batch_state(1),l.batch_state(2),l.batch_state(3),l.batch_state(4)),
  (Some(BatchState::Committed),Some(BatchState::Reversed),Some(BatchState::Committed),Some(BatchState::Committed)));
 let mut flipped=acks[0].clone();flipped.disposition=Disposition::FencedAbort;
 assert!(l.observe_resolution(&d,&flipped,T0).is_err());
 let s=sum(&l);
 let accrued:u64=bs.iter().map(due).sum();
 assert_eq!(s.accrued,accrued);assert_eq!(s.reversed,due(&bs[1]));
 assert_eq!(s.committed,(committed_oracle+committed_router)as u64);
 assert_eq!((s.collected,s.outstanding,s.unresolved()),(0,s.committed,0));
 assert_eq!(l.committed_by_role(),(committed_oracle,committed_router));
 let r=l.reconcile(&d).unwrap();assert!(r.clean(),"{:?}",r.mismatches);
 assert_eq!((r.ledger_oracle,r.ledger_router,r.router_oracle,r.router_router),(committed_oracle,committed_router,committed_oracle,committed_router));

 // Collection: router recipient in full, one oracle operator partially, with MockAdapter receipts.
 let ad=MockAdapter::new();
 let router_total=l.totals(&pk(124)).committed;assert_eq!(router_total,committed_router as u64);
 assert!(l.receive_receipt(&ad,&receipt(124,router_total*1000,1,vec![(1,1),(1,3),(1,4)])).unwrap());
 assert_eq!(l.totals(&pk(124)),RecipientTotals{accrued:router_total+bs[1].router_due_sats()as u64,reversed:bs[1].router_due_sats()as u64,committed:router_total,collected:router_total,outstanding:0});
 let op0=l.totals(&pk(120)).committed;let half=op0/2;
 assert!(l.receive_receipt(&ad,&receipt(120,half*1000,2,vec![(1,1),(1,4)])).unwrap());
 assert_eq!(l.totals(&pk(120)).collected,half);assert_eq!(l.totals(&pk(120)).outstanding,op0-half);
 // a receipt for the aborted batch is refused
 assert!(matches!(l.receive_receipt(&ad,&receipt(121,1000,3,vec![(1,2)])),Err(LedgerError::BadReceipt)));
 let s=sum(&l);assert_eq!(s.collected,router_total+half);assert_eq!(s.outstanding,s.committed-s.collected);
 let r=l.reconcile(&d).unwrap();assert!(r.clean(),"{:?}",r.mismatches);

 // Everything survives a restart of both journals.
 let totals=l.all_totals();drop(l);let tip=d.tip().unwrap();drop(d);
 let d=reopen(&t.path("t.wal"),Some(tip)).unwrap();
 let l=FeeLedger::open(&t.path("fees.wal"),1,rpolicy(),group()).unwrap();
 assert_eq!(l.all_totals(),totals);
 let r=l.reconcile(&d).unwrap();assert!(r.clean(),"{:?}",r.mismatches);
 // the HFT-05 reconciliation path is unchanged: a tiered ledger does not match an empty HFT-05 router
 let h5=DurableRouter::create(&t.path("h5.wal"),policy(),&registry(CAP),1,Engine::Both,lanes(),recipients()).unwrap();
 assert!(!l.reconcile(&h5).unwrap().clean());
}

/// Fenced-abort bundle signed by peer and monitor only (owner signature all-zero).
fn abort_without_owner(d:&DurableTieredRouter,b:&Batch)->AckBundle{
 let mut a=ack(d,b,Disposition::FencedAbort);
 for c in &mut a.channels{c.signatures[0]=ZERO;}
 a
}
fn window_end(b:&Batch)->u64{b.window().1}

#[test]fn deadline_abort_releases_a_batch_whose_owner_never_signs(){
 let t=Temp::new();let p=t.path("dl.wal");let mut d=create(&p);
 let b1=round(&mut d,0);let b2=round(&mut d,1);
 // owner 2 never approves batch 1: it stays sealed and holds batch 2
 let a=abort_without_owner(&d,&b1);
 // an owner-less abort is not a resolution, and not before the deadline
 assert!(d.resolve(a.clone()).is_err());
 d.process_one(window_end(&b1)+ABORT_AFTER_US-1).unwrap();
 assert!(matches!(d.expire(a.clone()),Err(TieredDurableError::Rejected(TierReject::Clock))));
 assert_eq!(d.batch(1).unwrap().unwrap().1,Phase::Sealed);
 d.process_one(window_end(&b1)+ABORT_AFTER_US).unwrap();
 let head=d.head(&channel(1)).unwrap().unwrap();
 assert!(d.expire(a.clone()).unwrap());
 assert!(!d.expire(a).unwrap(),"exact retry is idempotent");
 assert_eq!(d.batch(1).unwrap().unwrap().1,Phase::Aborted);
 for n in [1,2]{
  let bal=d.balance(&channel(n)).unwrap().unwrap();
  assert_eq!((bal.pending,bal.committed,bal.paid_fees),(0,0,0));assert!(bal.conserved());
 }
 let after=d.head(&channel(1)).unwrap().unwrap();
 assert_eq!((after.revision,after.commitment,after.state),(head.revision+1,head.commitment,head.state));
 // the queue moves: batch 2 prepares and commits normally
 d.prepare(2,approvals(&b2)).unwrap();
 assert!(d.resolve(ack(&d,&b2,Disposition::Commit)).unwrap());
 assert_eq!(d.next_resolution().unwrap(),3);
 // replay reaches the same state
 let before=snapshot(&d);let tip=d.tip().unwrap();drop(d);
 let d=reopen(&p,Some(tip)).unwrap();assert_eq!(snapshot(&d),before);
}

#[test]fn deadline_abort_needs_peer_and_monitor_and_cannot_commit(){
 let t=Temp::new();let p=t.path("dl2.wal");let mut d=create(&p);
 let b1=round(&mut d,0);let _b2=round(&mut d,1);
 d.process_one(window_end(&b1)+ABORT_AFTER_US).unwrap();
 // a commit can never go through the deadline path, signed or not
 assert!(d.expire(ack(&d,&b1,Disposition::Commit)).is_err());
 let mut c=ack(&d,&b1,Disposition::Commit);for x in &mut c.channels{x.signatures[0]=ZERO;}
 assert!(d.expire(c).is_err());
 // peer and monitor signatures are still required
 let mut a=abort_without_owner(&d,&b1);a.channels[0].signatures[1]=ZERO;
 assert!(matches!(d.expire(a),Err(TieredDurableError::Rejected(TierReject::Signature))));
 let mut a=abort_without_owner(&d,&b1);a.channels[1].signatures[2]=a.channels[0].signatures[2];
 assert!(matches!(d.expire(a),Err(TieredDurableError::Rejected(TierReject::Signature))));
 // a present owner signature must verify
 let mut a=abort_without_owner(&d,&b1);a.channels[0].signatures[0]=a.channels[0].signatures[1];
 assert!(matches!(d.expire(a),Err(TieredDurableError::Rejected(TierReject::Signature))));
 // only the head batch, and the abort must move no channel state
 let b2=_b2;d.process_one(window_end(&b2)+ABORT_AFTER_US).unwrap();
 assert!(d.expire(abort_without_owner(&d,&b2)).is_err());
 let mut a=abort_without_owner(&d,&b1);a.channels[0].next.commitment+=1;
 assert!(d.expire(a).is_err());
 assert_eq!(d.batch(1).unwrap().unwrap().1,Phase::Sealed);
 assert!(d.expire(abort_without_owner(&d,&b1)).unwrap());
}
