//! Delegated agent keys on the durable tiered router (docs/SHZ_AGENT_API.md): owner-signed
//! grants, agent-signed perpetual and spot intents, delegated batch acknowledgements limited
//! to the agent's own legs, expiry at the router clock, instant revocation, replay of the
//! journal. Synthetic funds and a deterministic test oracle only.
use shz_dex::{OrderSide,routing::*};
use shz_dex::routing::agents::*;
use shz_dex::routing::durable::{AckBundle,ChannelAck,Disposition,FeeRecipients,Head,Lane};
use shz_dex::routing::options::*;
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dlc::{Bip340Signature,BtcOutPoint,bip340_sign,tagged_hash};
use shz_oracle::frost::FrostConfederation;
use std::{cell::Cell,fs,path::{Path,PathBuf},sync::atomic::{AtomicU64,Ordering}};

type Key=[u8;32];
const T0:u64=1_000_000;
const AUTH:[u8;32]=[77;32];
const CAP:u64=100_000_000;
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
/// Agent keys: account n's agent is sk(200+n).
fn sk(n:u8)->Key{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn agent_sk(n:u8)->Key{sk(200+n)}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn op(n:u8)->([u8;32],u32){([n;32],0)}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[pk(50),pk(51)]}}
fn registry()->Registry{
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),CAP,vec![Share{router:1,sats:CAP}]).unwrap()).collect();
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
fn rejected(r:Result<impl std::fmt::Debug,TieredDurableError>,want:TierReject){
 match r{Err(TieredDurableError::Rejected(x)) if x==want=>{},x=>panic!("want {want:?}, got {x:?}")}
}
const LIMITS:AgentLimits=AgentLimits{max_order_notional_usd:5_000,max_daily_notional_usd:50_000,max_open_orders:10,max_orders_per_minute:60,collar_bps:300};
fn grant(n:u8,nonce:u64,expires_us:u64,instruments:u8)->AgentGrant{
 AgentGrant{version:AGENT_GRANT_VERSION,scope:policy().scope(),router:1,channel:channel(n),owner:[0;32],agent:public(&agent_sk(n)),
  nonce,issued_us:0,expires_us,instruments,may_withdraw:false,limits:LIMITS,signature:ZERO}.signed(&sk(n)).unwrap()
}
fn revocation(n:u8,grant:Key,issued_us:u64)->AgentRevocation{
 AgentRevocation{version:AGENT_GRANT_VERSION,scope:policy().scope(),router:1,grant,owner:[0;32],issued_us,signature:ZERO}.signed(&sk(n)).unwrap()
}

static COUNTER:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp{
 fn new()->Self{
  let p=std::env::temp_dir().join(format!("shz-agents-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
 fn path(&self)->PathBuf{self.0.join("router.wal")}
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

// ------------------------------------------------------------------ perpetuals ----
struct Perp{d:DurableTieredRouter,round:u64,seq:Cell<u64>,t:u64}
impl Perp{
 fn new(path:&Path)->Self{
  let mut d=DurableTieredRouter::create(path,&registry(),cfg(),lanes(),recipients()).unwrap();
  assert!(d.enable_margin_release().unwrap());
  Self{d,round:0,seq:Cell::new(0),t:T0}
 }
 /// An intent on account `n`, signed by the owner (`agent == false`) or by n's agent key.
 #[allow(clippy::too_many_arguments)]
 fn intent(&self,n:u8,agent:bool,action:Action,side:OrderSide,q:u64,price:u64,cancel:Key)->IntentV6{
  let c=cfg();self.seq.set(self.seq.get()+1);
  let mut i=IntentV6{scope:c.scope,router:1,channel:channel(n),owner:pk(n),sequence:self.seq.get(),expires_us:self.t+60_000_000,action,side,
   tier:FeedTier::Standard,tariff_version:c.tariff.version,entitlement_digest:[0;32],execution_policy:c.execution.id(),
   quantity:q,limit_usd:price,leverage_bps:if action==Action::Cancel{0}else{10_000},max_fee_ppm:if action==Action::Cancel{0}else{c.tariff.rate_ppm(FeedTier::Standard,action)},
   max_fee_sats:if action==Action::Cancel{0}else{100_000},max_mark_age_us:if action==Action::Cancel{0}else{1_000_000},early_window_opt_in:false,cancel_target:cancel,signature:ZERO_SIG};
  if action==Action::Cancel{i.side=OrderSide::Long;}
  let s=if agent{agent_sk(n)}else{sk(n)};
  i.signature=bip340_sign(&s,&i.id()).unwrap();i
 }
 /// Next 1 s round: a fresh mark at `price` and the round's clock `t + 200 ms`.
 fn round(&mut self,price:u64)->u64{
  self.round+=1;self.t=T0+self.round*1_000_000;let t=self.t;
  self.d.ingest_mark(MarkView{packet_digest:[self.round as u8;32],seq:self.round,price_e8:Some(price*100_000_000),boundary_us:t,public_release_us:t},t).unwrap();
  t+200_000
 }
 fn send(&mut self,i:IntentV6,grant:Option<Key>,now:u64)->Result<u64,TieredDurableError>{
  match grant{Some(g)=>self.d.submit_agent(i,None,now,g),None=>self.d.submit(i,None,now)}
 }
 fn process(&mut self,now:u64)->TierOutcome{self.d.process_one(now).unwrap().unwrap()}
 fn seal(&mut self)->Batch{self.d.process_one(self.t+500_000).unwrap();self.d.seal_batch().unwrap().expect("window elapsed")}
 fn bal(&self,n:u8)->Balance{self.d.balance(&channel(n)).unwrap().unwrap()}
}
fn approvals(b:&Batch,agent_on:&[u8])->Vec<BatchApproval>{
 b.accounts().iter().map(|a|{
  let n=a.channel.txid[0];let h=b.approval_message(&a.channel).unwrap();
  let s=if agent_on.contains(&n){agent_sk(n)}else{sk(n)};
  BatchApproval{channel:a.channel.clone(),signature:bip340_sign(&s,&h).unwrap()}
 }).collect()
}
fn acks(d:&DurableTieredRouter,b:&Batch,agent_on:&[u8])->AckBundle{
 let mut channels=Vec::new();
 for a in b.accounts(){
  let n=a.channel.txid[0];
  let previous=d.head(&a.channel).unwrap().unwrap();let mut next=previous;next.revision+=1;next.commitment+=1;
  next.state=tagged_hash(b"test/state",&[&[n][..],&b.sequence().to_le_bytes()].concat());
  let mut fee=[0;32];
  if a.fee_sats>0{fee[0]=n;fee[1..9].copy_from_slice(&b.sequence().to_le_bytes());fee[31]=180;}
  let mut c=ChannelAck{channel:a.channel.clone(),previous,next,evidence:tagged_hash(b"test/evidence",&[&[n][..],&b.sequence().to_le_bytes()].concat()),fee_evidence:fee,signatures:[ZERO;3]};
  let h=d.ack_message(b.sequence(),Disposition::Commit,&c).unwrap();
  let o=if agent_on.contains(&n){agent_sk(n)}else{sk(n)};
  c.signatures=[bip340_sign(&o,&h).unwrap(),bip340_sign(&sk(70+n),&h).unwrap(),bip340_sign(&sk(90+n),&h).unwrap()];
  channels.push(c);
 }
 AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:Disposition::Commit,channels}
}

/// G1. Off by default: every agent event is refused until `EnableAgents`, and a journal
/// that never enabled agents reopens to the same tip (nothing new is written).
#[test]
fn g1_off_by_default_and_old_journal_replays_unchanged(){
 let t=Temp::new();
 let tip={
  let mut v=Perp::new(&t.path());
  rejected(v.d.grant_agent(grant(1,1,u64::MAX/2,INSTRUMENT_ALL),T0),TierReject::Scope);
  let now=v.round(100_000);
  rejected(v.d.submit_agent(v.intent(1,true,Action::Post,OrderSide::Long,100,99_000,[0;32]),None,now,[1;32]),TierReject::Scope);
  assert!(v.d.agents().unwrap().is_none());
  v.d.tip().unwrap()
 };
 let bytes=fs::read(t.path()).unwrap();
 let d=DurableTieredRouter::open(&t.path(),&registry(),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 assert_eq!(d.tip().unwrap(),tip);assert!(d.agents().unwrap().is_none());
 drop(d);
 assert_eq!(fs::read(t.path()).unwrap(),bytes,"reopening writes nothing");
}

/// G2. Grant admission: owner signature, account owner, agent != owner, may_withdraw is
/// refused, instrument bits, limit sanity, lifetime cap, expiry, nonce replay, active cap.
#[test]
fn g2_grant_admission_rules(){
 let t=Temp::new();let mut v=Perp::new(&t.path());
 assert!(v.d.enable_agents().unwrap());assert!(!v.d.enable_agents().unwrap());
 let ok=grant(1,1,T0+86_400_000_000,INSTRUMENT_ALL);
 // Signed by someone other than the owner.
 let mut forged=ok.clone();forged.signature=bip340_sign(&sk(2),&forged.id()).unwrap();
 rejected(v.d.grant_agent(forged,T0),TierReject::Signature);
 // A grant naming account 1 signed by owner 2 (owner field 2).
 let mut other=ok.clone();other.owner=pk(2);other.signature=bip340_sign(&sk(2),&other.id()).unwrap();
 rejected(v.d.grant_agent(other,T0),TierReject::Allocation);
 let resign=|mut g:AgentGrant|{g.signature=bip340_sign(&sk(1),&g.id()).unwrap();g};
 let mut g=ok.clone();g.agent=pk(1);rejected(v.d.grant_agent(resign(g),T0),TierReject::Bounds);
 let mut g=ok.clone();g.may_withdraw=true;rejected(v.d.grant_agent(resign(g),T0),TierReject::Bounds);
 let mut g=ok.clone();g.instruments=0;rejected(v.d.grant_agent(resign(g),T0),TierReject::Bounds);
 let mut g=ok.clone();g.instruments=8;rejected(v.d.grant_agent(resign(g),T0),TierReject::Bounds);
 let mut g=ok.clone();g.limits.max_daily_notional_usd=1;rejected(v.d.grant_agent(resign(g),T0),TierReject::Bounds);
 let mut g=ok.clone();g.limits.collar_bps=0;rejected(v.d.grant_agent(resign(g),T0),TierReject::Bounds);
 let mut g=ok.clone();g.expires_us=MAX_GRANT_US+1;rejected(v.d.grant_agent(resign(g),T0),TierReject::Bounds);
 rejected(v.d.grant_agent(grant(1,1,T0,INSTRUMENT_ALL),T0),TierReject::Expired);
 let mut g=ok.clone();g.scope.epoch+=1;rejected(v.d.grant_agent(resign(g),T0),TierReject::Scope);
 let id=v.d.grant_agent(ok.clone(),T0).unwrap();
 assert_eq!(id,ok.id());
 rejected(v.d.grant_agent(ok.clone(),T0),TierReject::Replay);
 rejected(v.d.grant_agent(grant(1,1,T0+2_000_000,INSTRUMENT_PERPS),T0),TierReject::Replay);
 for nonce in 2..=MAX_ACTIVE_GRANTS as u64{v.d.grant_agent(grant(1,nonce,T0+86_400_000_000,INSTRUMENT_PERPS),T0).unwrap();}
 rejected(v.d.grant_agent(grant(1,99,T0+86_400_000_000,INSTRUMENT_PERPS),T0),TierReject::Capacity);
 // Revoking one frees a slot; the revocation must be the owner's and happens once.
 let bad=AgentRevocation{owner:pk(2),..revocation(2,id,T0)};
 rejected(v.d.revoke_agent(bad,T0),TierReject::Allocation);
 v.d.revoke_agent(revocation(1,id,T0),T0).unwrap();
 rejected(v.d.revoke_agent(revocation(1,id,T0),T0),TierReject::Replay);
 v.d.grant_agent(grant(1,100,T0+86_400_000_000,INSTRUMENT_PERPS),T0).unwrap();
 assert_eq!(v.d.agents().unwrap().unwrap().grants_of(&channel(1)).len(),MAX_ACTIVE_GRANTS+1);
}

/// G3. Perpetuals: the agent posts and takes for the owner's account under its grant; its
/// key is not the owner's (a plain submit with its signature fails); the trade commits on
/// approvals and channel acknowledgements the agent signs for its own legs; a batch with
/// an owner-signed leg on the account needs the owner; cancels reach only the agent's own
/// orders; instruments outside the grant are refused.
#[test]
fn g3_perps_agent_trades_and_acks_its_own_legs(){
 let t=Temp::new();let mut v=Perp::new(&t.path());
 v.d.enable_agents().unwrap();
 let g1=v.d.grant_agent(grant(1,1,T0+3_600_000_000,INSTRUMENT_PERPS),T0).unwrap();
 let g2=v.d.grant_agent(grant(2,1,T0+3_600_000_000,INSTRUMENT_SPOT),T0).unwrap();
 let now=v.round(100_000);
 // Agent signature on the plain (owner) path: refused.
 rejected(v.send(v.intent(1,true,Action::Post,OrderSide::Short,1_000,100_000,[0;32]),None,now),TierReject::Signature);
 // Owner signature on the agent path: refused too (the agent path checks the agent key).
 rejected(v.send(v.intent(1,false,Action::Post,OrderSide::Short,1_000,100_000,[0;32]),Some(g1),now),TierReject::Signature);
 // Account 2's grant has spot only.
 rejected(v.send(v.intent(2,true,Action::Post,OrderSide::Short,1_000,100_000,[0;32]),Some(g2),now),TierReject::Scope);
 // Grant 1 used for account 2's intent.
 rejected(v.send(v.intent(2,true,Action::Post,OrderSide::Short,1_000,100_000,[0;32]),Some(g1),now),TierReject::Allocation);
 // Agent of 1 rests an ask; account 3 (owner) takes it.
 let ask=v.intent(1,true,Action::Post,OrderSide::Short,1_000,100_000,[0;32]);let ask_id=ask.id();
 v.send(ask,Some(g1),now).unwrap();
 assert!(matches!(v.process(now),TierOutcome::Posted(_)));
 assert_eq!(v.d.agents().unwrap().unwrap().signer_of(&ask_id),Some(g1));
 v.send(v.intent(3,false,Action::Take,OrderSide::Long,1_000,100_000,[0;32]),None,now).unwrap();
 assert!(matches!(v.process(now),TierOutcome::Filled(_)));
 let b=v.seal();
 assert!(v.d.agent_may_ack(b.sequence(),&channel(1),&g1).unwrap());
 assert!(!v.d.agent_may_ack(b.sequence(),&channel(3),&g1).unwrap());
 // Delegating channel 3's slot to grant 1: refused; the plain prepare with agent
 // signatures: refused; the delegated prepare for channel 1: accepted.
 rejected(v.d.prepare_delegated(b.sequence(),approvals(&b,&[1]),vec![(channel(3),g1)]),TierReject::Allocation);
 rejected(v.d.prepare(b.sequence(),approvals(&b,&[1])),TierReject::Signature);
 rejected(v.d.prepare_delegated(b.sequence(),approvals(&b,&[1]),vec![]),TierReject::Bounds);
 v.d.prepare_delegated(b.sequence(),approvals(&b,&[1]),vec![(channel(1),g1)]).unwrap();
 rejected(v.d.resolve(acks(&v.d,&b,&[1])),TierReject::Signature);
 assert!(v.d.resolve_delegated(acks(&v.d,&b,&[1]),vec![(channel(1),g1)]).unwrap());
 assert_eq!(v.d.position(&channel(1)).unwrap().unwrap().net_usd(),-1_000);
 assert!(v.bal(1).conserved());
 // The owner of 1 trades by hand; the agent of 1 then takes against account 4 in the same
 // window: the batch has an owner-signed leg on channel 1, so the agent cannot ack it.
 let now=v.round(100_000);
 v.send(v.intent(4,false,Action::Post,OrderSide::Short,500,100_000,[0;32]),None,now).unwrap();v.process(now);
 v.send(v.intent(1,false,Action::Take,OrderSide::Long,200,100_000,[0;32]),None,now).unwrap();v.process(now);
 v.send(v.intent(1,true,Action::Take,OrderSide::Long,300,100_000,[0;32]),Some(g1),now).unwrap();v.process(now);
 let b=v.seal();
 assert!(!v.d.agent_may_ack(b.sequence(),&channel(1),&g1).unwrap());
 rejected(v.d.prepare_delegated(b.sequence(),approvals(&b,&[1]),vec![(channel(1),g1)]),TierReject::Allocation);
 v.d.prepare(b.sequence(),approvals(&b,&[])).unwrap();
 assert!(v.d.resolve(acks(&v.d,&b,&[])).unwrap());
 // Cancels: the agent may not cancel the owner's order; it may cancel its own; the owner
 // may cancel the agent's.
 let now=v.round(100_000);
 let own=v.intent(1,false,Action::Post,OrderSide::Long,100,99_000,[0;32]);let own_id=own.id();
 v.send(own,None,now).unwrap();v.process(now);
 rejected(v.send(v.intent(1,true,Action::Cancel,OrderSide::Long,0,0,own_id),Some(g1),now),TierReject::Allocation);
 let a=v.intent(1,true,Action::Post,OrderSide::Long,100,99_000,[0;32]);let a_id=a.id();
 v.send(a,Some(g1),now).unwrap();v.process(now);
 v.send(v.intent(1,true,Action::Cancel,OrderSide::Long,0,0,a_id),Some(g1),now).unwrap();
 assert!(matches!(v.process(now),TierOutcome::Cancelled(x) if x==a_id));
 let a=v.intent(1,true,Action::Post,OrderSide::Long,100,99_000,[0;32]);let a_id=a.id();
 v.send(a,Some(g1),now).unwrap();v.process(now);
 v.send(v.intent(1,false,Action::Cancel,OrderSide::Long,0,0,a_id),None,now).unwrap();
 assert!(matches!(v.process(now),TierOutcome::Cancelled(x) if x==a_id));
 // Sequence numbers are the account's: an agent intent replaying an old sequence fails.
 let mut old=v.intent(1,true,Action::Post,OrderSide::Long,100,99_000,[0;32]);old.sequence=1;
 old.signature=bip340_sign(&agent_sk(1),&old.id()).unwrap();
 rejected(v.send(old,Some(g1),now),TierReject::Replay);
}

/// G4. Revocation is instant: the agent's resting quote and its queued intent are pulled in
/// the revoke event (the hold returns to free), later agent intents and acks fail, and the
/// owner keeps trading. Expiry at the router clock does the same for new intents.
#[test]
fn g4_revocation_and_expiry(){
 let t=Temp::new();let mut v=Perp::new(&t.path());
 v.d.enable_agents().unwrap();
 let g1=v.d.grant_agent(grant(1,1,T0+3_600_000_000,INSTRUMENT_PERPS),T0).unwrap();
 let now=v.round(100_000);
 let free=v.bal(1).free;
 let q=v.intent(1,true,Action::Post,OrderSide::Long,1_000,99_000,[0;32]);let qid=q.id();
 v.send(q,Some(g1),now).unwrap();v.process(now);
 assert!(v.bal(1).free<free);
 // A second agent intent admitted but not yet processed (queued).
 let q2=v.intent(1,true,Action::Post,OrderSide::Long,500,98_000,[0;32]);let q2id=q2.id();
 v.send(q2,Some(g1),now).unwrap();
 let (pulled,dropped)=v.d.revoke_agent(revocation(1,g1,now),now).unwrap();
 assert!(pulled.contains(&qid)&&pulled.contains(&q2id));
 assert_eq!(dropped,vec![q2id]);
 assert_eq!(v.bal(1).free,free,"the resting hold returned to free");
 assert_eq!(v.d.router().unwrap().resting(),0);
 assert!(v.d.process_one(now).unwrap().is_none(),"nothing left queued");
 rejected(v.send(v.intent(1,true,Action::Post,OrderSide::Long,100,99_000,[0;32]),Some(g1),now),TierReject::Signature);
 v.send(v.intent(1,false,Action::Post,OrderSide::Long,100,99_000,[0;32]),None,now).unwrap();
 assert!(matches!(v.process(now),TierOutcome::Posted(_)));
 // Expiry: a grant that ends at T0 + 5 s.
 let g2=v.d.grant_agent(grant(1,2,T0+5_000_000,INSTRUMENT_PERPS),now).unwrap();
 v.send(v.intent(1,true,Action::Post,OrderSide::Long,100,98_000,[0;32]),Some(g2),now).unwrap();v.process(now);
 for _ in 0..4{v.round(100_000);}
 let now=v.round(100_000);
 assert!(now>=T0+5_000_000);
 rejected(v.send(v.intent(1,true,Action::Post,OrderSide::Long,100,98_000,[0;32]),Some(g2),now),TierReject::Expired);
}

/// G5. The journal replays agent state exactly: grants, revocations, intent signers,
/// balances and the books after reopen.
#[test]
fn g5_journal_replay(){
 let t=Temp::new();
 let (tip,g1,g2,bal,resting)={
  let mut v=Perp::new(&t.path());
  v.d.enable_agents().unwrap();
  let g1=v.d.grant_agent(grant(1,1,T0+3_600_000_000,INSTRUMENT_PERPS),T0).unwrap();
  let g2=v.d.grant_agent(grant(2,1,T0+3_600_000_000,INSTRUMENT_PERPS),T0).unwrap();
  let now=v.round(100_000);
  v.send(v.intent(1,true,Action::Post,OrderSide::Short,1_000,100_000,[0;32]),Some(g1),now).unwrap();v.process(now);
  v.send(v.intent(2,true,Action::Take,OrderSide::Long,400,100_000,[0;32]),Some(g2),now).unwrap();v.process(now);
  let b=v.seal();
  v.d.prepare_delegated(b.sequence(),approvals(&b,&[1,2]),vec![(channel(1),g1),(channel(2),g2)]).unwrap();
  assert!(v.d.resolve_delegated(acks(&v.d,&b,&[1,2]),vec![(channel(2),g2),(channel(1),g1)]).unwrap());
  let now=v.round(100_000);
  v.d.revoke_agent(revocation(2,g2,now),now).unwrap();
  (v.d.tip().unwrap(),g1,g2,(v.bal(1),v.bal(2)),v.d.router().unwrap().resting())
 };
 let d=DurableTieredRouter::open(&t.path(),&registry(),cfg(),lanes(),recipients(),Some(tip)).unwrap();
 let book=d.agents().unwrap().unwrap();
 assert!(book.grant(&g1).unwrap().revoked_us.is_none());
 assert!(book.grant(&g2).unwrap().revoked_us.is_some());
 assert_eq!((d.balance(&channel(1)).unwrap().unwrap(),d.balance(&channel(2)).unwrap().unwrap()),bal);
 assert_eq!(d.router().unwrap().resting(),resting);
 assert_eq!(d.position(&channel(2)).unwrap().unwrap().net_usd(),400);
}

// ------------------------------------------------------------------------ spot ----
const USDT:SettleAsset=SettleAsset::Stable{protocol:StableProtocol::Rgb,id:[0x52;32],decimals:6};
const PAIR:SpotPair=SpotPair{quote:USDT,lot_sats:1_000,tick:100_000};
const fn usd(p:u64)->u64{p*1_000_000}
struct Spot{d:DurableTieredRouter,pair:Key,seq:Cell<u64>,now:Cell<u64>}
impl Spot{
 fn new(path:&Path)->Self{
  let mut d=DurableTieredRouter::create(path,&registry(),cfg(),lanes(),recipients()).unwrap();
  d.enable_margin_release().unwrap();d.enable_clearing(1_000_000).unwrap();
  let oracle=FrostConfederation::keygen_deterministic(2,3,&[0x51;32]).unwrap();
  d.enable_options(oracle.group_pubkey_x,20).unwrap();d.register_stable(USDT).unwrap();
  d.enable_option_acks().unwrap();d.enable_spot().unwrap();
  let pair=d.list_spot_pair(PAIR).unwrap();
  d.enable_agents().unwrap();
  Self{d,pair,seq:Cell::new(0),now:Cell::new(T0)}
 }
 #[allow(clippy::too_many_arguments)]
 fn intent(&self,n:u8,agent:bool,action:Action,buy:bool,qty_sats:u64,price:u64,cancel_target:Key)->SpotIntent{
  let c=cfg();self.seq.set(self.seq.get()+1);
  let mut i=SpotIntent{version:SPOT_INTENT_VERSION,scope:c.scope,router:1,channel:channel(n),owner:pk(n),sequence:self.seq.get(),
   expires_us:self.now.get()+5_000_000,action,pair:self.pair,buy,qty_sats,price,cancel_target,signature:ZERO};
  i.signature=bip340_sign(&if agent{agent_sk(n)}else{sk(n)},&i.id()).unwrap();i
 }
 fn tick(&self)->u64{self.now.set(self.now.get()+1);self.now.get()}
 fn send(&mut self,i:SpotIntent,grant:Option<Key>)->Result<OptionOutcome,TieredDurableError>{
  let now=self.tick();
  match grant{Some(g)=>self.d.submit_spot_agent(i,now,g),None=>self.d.submit_spot(i,now)}
 }
 fn acks(&self,agent_on:&[u8])->OptionAckBundle{
  let b=self.d.pending_option().unwrap().unwrap().clone();
  let acks=b.channels().into_iter().map(|c|{
   let n=c.txid[0];let h=self.d.option_ack_message(Disposition::Commit,&c).unwrap();
   let o=if agent_on.contains(&n){agent_sk(n)}else{sk(n)};
   OptionAck{channel:c,signatures:[bip340_sign(&o,&h).unwrap(),bip340_sign(&sk(70+n),&h).unwrap(),bip340_sign(&sk(90+n),&h).unwrap()]}
  }).collect();
  OptionAckBundle{sequence:b.sequence,batch:b.digest(),disposition:Disposition::Commit,acks}
 }
 fn wallet(&self,n:u8)->(u64,u64,u64,u64){
  let d=self.d.options().unwrap().unwrap();let s=d.spot().unwrap();
  let bal=|a:&SettleAsset|d.account(&op(n)).map(|x|x.balance(a)).unwrap_or_default();
  (bal(&SettleAsset::Btc).free,s.locked(&op(n),&SettleAsset::Btc),bal(&USDT).free,s.locked(&op(n),&USDT))
 }
}

/// G6. Spot: the agent's take is staged and committed on the agent's own owner-slot ack;
/// the agent cannot ack for the maker; revoking pulls the agent's resting order and
/// unlocks its funds; an options-only grant cannot trade spot.
#[test]
fn g6_spot_agent_take_ack_and_revoke(){
 let t=Temp::new();let mut v=Spot::new(&t.path());
 v.d.fund_options(channel(1),2_000_000).unwrap();
 v.d.deposit_stable(channel(2),USDT,2_000_000_000).unwrap();
 let g2=v.d.grant_agent(grant(2,1,T0+3_600_000_000,INSTRUMENT_SPOT),T0).unwrap();
 let g1=v.d.grant_agent(grant(1,1,T0+3_600_000_000,INSTRUMENT_OPTIONS),T0).unwrap();
 rejected(v.send(v.intent(1,true,Action::Post,false,1_000_000,usd(90_000),[0;32]),Some(g1)),TierReject::Scope);
 let ask=v.send(v.intent(1,false,Action::Post,false,1_000_000,usd(90_000),[0;32]),None).unwrap();
 assert!(matches!(ask,OptionOutcome::Posted(_)));
 match v.send(v.intent(2,true,Action::Take,true,400_000,usd(90_050),[0;32]),Some(g2)).unwrap(){OptionOutcome::Staged(_)=>{},x=>panic!("{x:?}")}
 let now=v.tick();
 assert!(v.d.agent_may_ack_option(&channel(2),&g2,now).unwrap());
 assert!(!v.d.agent_may_ack_option(&channel(1),&g2,now).unwrap());
 rejected(v.d.resolve_option(v.acks(&[2]),now),TierReject::Signature);
 rejected(v.d.resolve_option_delegated(v.acks(&[1,2]),now,vec![(channel(1),g2),(channel(2),g2)]),TierReject::Allocation);
 assert!(v.d.resolve_option_delegated(v.acks(&[2]),now,vec![(channel(2),g2)]).unwrap());
 assert_eq!(v.wallet(2),(400_000,0,2_000_000_000-360_000_000,0));
 // The agent rests a bid (locks USDT); revoking pulls it and unlocks.
 let bid=v.intent(2,true,Action::Post,true,100_000,usd(89_000),[0;32]);let bid_id=bid.id();
 assert!(matches!(v.send(bid,Some(g2)).unwrap(),OptionOutcome::Posted(x) if x==bid_id));
 assert_eq!(v.wallet(2).3,89_000_000);
 let now=v.tick();
 let (pulled,_)=v.d.revoke_agent(revocation(2,g2,now),now).unwrap();
 assert!(pulled.contains(&bid_id));
 assert_eq!(v.wallet(2),(400_000,0,2_000_000_000-360_000_000,0));
 rejected(v.send(v.intent(2,true,Action::Post,true,100_000,usd(89_000),[0;32]),Some(g2)),TierReject::Signature);
}
