//! HFT-06 durable tiered router: the HFT-05 journal framing and signed channel-state
//! acknowledgement gate applied to `TieredRouter`. A signed monitor attestation is a
//! trust assumption, NOT an LDK/BOLT proof. One journal and writer per immutable
//! router configuration (scope, router id, tariff, execution policy, revenue policy,
//! entitlement key, allocation registry, lanes, fee recipients).
use super::*;
use super::durable::{AckBundle,ChannelAck,Disposition,FeeRecipients,Head,JournalTip,Lane,LaneState,Phase,
 ZERO_TIP,MAX_FRAME,ack_message,plan_resolution,put_head,read_frame,write_frame,exact};
use super::tiered::*;
use std::{fs::{File,OpenOptions},io::{self,Write},path::Path};
use thiserror::Error;

const MAGIC:&[u8;8]=b"SHZWAL06";
/// Distinct from the HFT-05 tag, and the config hash differs as well: an HFT-05
/// acknowledgement can never verify against a tiered router.
pub const TIERED_ACK_TAG:&[u8]=b"SHZ/HFT06/CHANNEL-ACK/V1";
/// Deadline abort: once the router clock is this far past a batch window's end, the
/// batch at the head of the resolution queue may be fenced and aborted with the peer
/// and monitor signatures alone (owner signature all-zero). Batches resolve strictly in
/// order, so without this one owner who never signs holds every later batch. Abort
/// leaves channel commitments unchanged and returns each debit to free; the trust
/// added is that peer and monitor can cancel, not move, a batch after the deadline.
pub const ABORT_AFTER_US:u64=10_000_000;

#[derive(Debug,Error)]
pub enum TieredDurableError{
 #[error("journal I/O: {0}")] Io(#[from] io::Error),
 #[error("journal writer already held or cannot be locked")] Locked,
 #[error("invalid journal, checksum, format or torn frame")] Corrupt,
 #[error("journal configuration mismatch")] Config,
 #[error("journal does not contain the independently pinned tip")] Rollback,
 #[error("writer poisoned after failed persistence; reopen and reconcile")] Poisoned,
 #[error("router rejected operation: {0:?}")] Rejected(TierReject),
}
impl From<TierReject> for TieredDurableError{fn from(r:TierReject)->Self{Self::Rejected(r)}}
impl From<super::durable::DurableError> for TieredDurableError{
 fn from(e:super::durable::DurableError)->Self{
  use super::durable::DurableError as E;
  match e{E::Io(e)=>Self::Io(e),E::Locked=>Self::Locked,E::Corrupt=>Self::Corrupt,E::Config=>Self::Config,
   E::Rollback=>Self::Rollback,E::Poisoned=>Self::Poisoned,E::Rejected(_)=>Self::Corrupt}
 }
}
type D<T>=Result<T,TieredDurableError>;

fn lane_ok(l:&Lane,owner:&Key)->bool{
 l.peer!=[0;32]&&l.monitor!=[0;32]&&l.peer!=l.monitor&&l.peer!=*owner&&l.monitor!=*owner&&
 l.initial.state!=[0;32]&&l.initial.revision==0
}
/// Serializable mirror of `Lane` for the journal.
#[derive(Debug,Serialize,Deserialize)]
struct LaneRec{channel:BtcOutPoint,peer:Key,monitor:Key,initial:Head}
struct Entry{batch:Batch,phase:Phase,ack:Option<AckBundle>}
struct State{
 router:TieredRouter,lanes:BTreeMap<Outpoint,LaneState>,recipients:FeeRecipients,config:Key,
 batches:BTreeMap<u64,Entry>,next_resolution:u64,oracle_paid:u128,router_paid:u128,fee_receipts:BTreeSet<Key>,
}
impl State{
 fn new(registry:&Registry,cfg:TieredConfig,lanes:Vec<Lane>,recipients:FeeRecipients)->D<Self>{
  let router=TieredRouter::new(registry,cfg)?;
  if recipients.oracle==[0;32]||recipients.router==[0;32]||recipients.oracle==recipients.router{return Err(TieredDurableError::Config)}
  let mut map=BTreeMap::new();
  for l in lanes{
   let owner=router.account_owner(&op(&l.channel)).ok_or(TieredDurableError::Config)?;
   if !lane_ok(&l,&owner)||
      map.insert(op(&l.channel),LaneState{peer:l.peer,monitor:l.monitor,head:l.initial}).is_some(){return Err(TieredDurableError::Config)}
  }
  if map.len()!=router.account_count(){return Err(TieredDurableError::Config)}
  let c=router.config();
  let mut b=Vec::new();c.scope.put(&mut b);u32b(&mut b,c.router);
  b.extend(c.tariff.id());b.extend(router.execution_policy_id());u64b(&mut b,c.revenue.oracle_share_bps);
  b.extend(c.entitlement_key);b.extend(recipients.oracle);b.extend(recipients.router);
  let mut allocations:Vec<_>=registry.allocations.iter().collect();
  allocations.sort_by_key(|a|op(&a.channel));u64b(&mut b,allocations.len()as u64);
  for a in allocations{b.extend(a.digest().map_err(|_|TieredDurableError::Config)?);b.extend(a.owner_sig.to_bytes());b.extend(a.authority_sig.to_bytes());}
  u64b(&mut b,map.len()as u64);
  for (&(txid,vout),l) in &map{b.extend(txid);u32b(&mut b,vout);b.extend(l.peer);b.extend(l.monitor);put_head(&mut b,&l.head);}
  let config=tagged_hash(b"SHZ/HFT06/WAL-CONFIG/V1",&b);
  Ok(Self{router,lanes:map,recipients,config,batches:BTreeMap::new(),next_resolution:1,oracle_paid:0,router_paid:0,fee_receipts:BTreeSet::new()})
 }
 fn message(&self,sequence:u64,disposition:Disposition,ack:&ChannelAck)->R<Key>{
  let batch=&self.batches.get(&sequence).ok_or(Reject::UnknownOrder)?.batch;
  ack_message(TIERED_ACK_TAG,&self.config,&self.recipients,sequence,batch,disposition,ack)
 }
 fn prepare(&mut self,sequence:u64,approvals:&[BatchApproval])->R<()>{
  if sequence!=self.next_resolution{return Err(Reject::Replay)}
  let entry=self.batches.get_mut(&sequence).ok_or(Reject::UnknownOrder)?;
  if !matches!(entry.phase,Phase::Sealed|Phase::Prepared){return Err(Reject::Replay)}
  entry.batch.verify_approvals(approvals)?;
  entry.phase=Phase::Prepared;Ok(())
 }
 fn resolve(&mut self,bundle:AckBundle,deadline:bool)->R<bool>{
  let entry=self.batches.get(&bundle.sequence).ok_or(Reject::UnknownOrder)?;
  // An exact byte-equivalent signed bundle is idempotent after recovery.
  if let Some(old)=&entry.ack{return if old==&bundle{Ok(false)}else{Err(Reject::Replay)}}
  if bundle.sequence!=self.next_resolution||bundle.batch!=entry.batch.digest(){return Err(Reject::Replay)}
  if deadline{
   if bundle.disposition!=Disposition::FencedAbort||!matches!(entry.phase,Phase::Sealed|Phase::Prepared){return Err(Reject::Replay)}
   if self.router.clock_us()<entry.batch.window().1.saturating_add(ABORT_AFTER_US){return Err(Reject::Clock)}
  }else if entry.phase!=Phase::Prepared{return Err(Reject::Replay)}
  let next_sequence=self.next_resolution.checked_add(1).ok_or(Reject::Bounds)?;
  let plan=plan_resolution(TIERED_ACK_TAG,&self.config,&self.recipients,&self.lanes,
   &|k:&Outpoint|self.router.account_balance(k),&self.fee_receipts,(self.oracle_paid,self.router_paid),&entry.batch,&bundle,deadline)?;
  // No fallible checks past this point. All account updates atomic in memory.
  for (key,balance,head) in plan.changes{self.router.set_account_balance(&key,balance);self.lanes.get_mut(&key).unwrap().head=head;}
  for id in plan.cancel{self.router.cancel_resting(id);}
  self.oracle_paid=plan.oracle;self.router_paid=plan.router;self.next_resolution=next_sequence;self.fee_receipts.extend(plan.receipts);
  let entry=self.batches.get_mut(&bundle.sequence).unwrap();
  entry.phase=match bundle.disposition{Disposition::Commit=>Phase::Committed,Disposition::FencedAbort=>Phase::Aborted};
  entry.ack=Some(bundle);Ok(true)
 }
 fn register(&mut self,allocation:Allocation,rec:LaneRec)->Result<(),TierReject>{
  let lane=Lane{channel:rec.channel,peer:rec.peer,monitor:rec.monitor,initial:rec.initial};
  let k=op(&allocation.channel);
  if lane.channel!=allocation.channel||self.lanes.contains_key(&k)||!lane_ok(&lane,&allocation.owner){return Err(TierReject::Allocation)}
  let authority=self.router.authority();
  self.router.register(allocation,&authority)?;
  self.lanes.insert(k,LaneState{peer:lane.peer,monitor:lane.monitor,head:lane.initial});
  Ok(())
 }
 fn apply(&mut self,event:Event)->Result<Reply,TierReject>{
  match event{
   Event::Mark{mark,now}=>{self.router.ingest_mark(mark,now)?;Ok(Reply::Unit)},
   Event::Submit{intent,entitlement,now}=>Ok(Reply::Due(self.router.submit(intent,entitlement.as_ref(),now)?)),
   Event::Process{now}=>Ok(Reply::Outcome(self.router.process_one(now)?)),
   Event::Register{allocation,lane}=>{self.register(allocation,lane)?;Ok(Reply::Unit)},
   Event::Hold{on}=>{self.router.set_emergency_hold(on);Ok(Reply::Unit)},
   Event::Seal=>{
    let batch=self.router.seal_batch()?;
    if let Some(ref b)=batch{
     assert!(self.batches.insert(b.sequence(),Entry{batch:b.clone(),phase:Phase::Sealed,ack:None}).is_none());
    }
    Ok(Reply::Batch(batch))
   },
   Event::Prepare{sequence,approvals}=>{self.prepare(sequence,&approvals)?;Ok(Reply::Unit)},
   Event::Resolve{bundle}=>Ok(Reply::Resolved(self.resolve(bundle,false)?)),
   Event::Expire{bundle}=>Ok(Reply::Resolved(self.resolve(bundle,true)?)),
  }
 }
}

#[allow(clippy::large_enum_variant)] // journal record, serialized once per command
#[derive(Debug,Serialize,Deserialize)]
enum Event{
 Mark{mark:MarkView,now:u64},
 Submit{intent:IntentV6,entitlement:Option<Entitlement>,now:u64},
 Process{now:u64},
 Hold{on:bool},
 Register{allocation:Allocation,lane:LaneRec},
 Seal,
 Prepare{sequence:u64,approvals:Vec<BatchApproval>},
 Resolve{bundle:AckBundle},
 /// Deadline abort of the head batch (see `ABORT_AFTER_US`).
 Expire{bundle:AckBundle},
}
#[allow(clippy::large_enum_variant)]
enum Reply{Due(u64),Outcome(Option<TierOutcome>),Batch(Option<Batch>),Unit,Resolved(bool)}

/// Full event-sourced tiered router, including rejected calls that may advance time.
/// No mutable `TieredRouter` escapes. The file is held exclusively for the writer
/// lifetime. The command is durable before in-memory application or reply; on I/O
/// failure the writer is poisoned. A fully persisted but unacknowledged command replays.
pub struct DurableTieredRouter{file:File,tip:JournalTip,state:State,poisoned:bool}
impl DurableTieredRouter{
 pub fn create(path:&Path,registry:&Registry,cfg:TieredConfig,lanes:Vec<Lane>,recipients:FeeRecipients)->D<Self>{
  let state=State::new(registry,cfg,lanes,recipients)?;
  let mut file=OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
  file.try_lock().map_err(|_|TieredDurableError::Locked)?;
  file.write_all(MAGIC)?;
  let tip=write_frame(&mut file,ZERO_TIP,&state.config)?;
  #[cfg(unix)]
  {let parent=path.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(Path::new("."));File::open(parent)?.sync_all()?;}
  Ok(Self{file,tip,state,poisoned:false})
 }
 /// A caller-supplied independently stored minimum tip detects valid-prefix
 /// rollback. Without it, recovery assumes storage has not been rolled back.
 pub fn open(path:&Path,registry:&Registry,cfg:TieredConfig,lanes:Vec<Lane>,recipients:FeeRecipients,minimum:Option<JournalTip>)->D<Self>{
  let mut state=State::new(registry,cfg,lanes,recipients)?;
  let mut file=OpenOptions::new().read(true).write(true).open(path)?;
  file.try_lock().map_err(|_|TieredDurableError::Locked)?;
  let mut magic=[0;8];exact(&mut file,&mut magic)?;
  if &magic!=MAGIC{return Err(TieredDurableError::Corrupt)}
  let (mut tip,genesis)=read_frame(&mut file,ZERO_TIP)?.ok_or(TieredDurableError::Corrupt)?;
  if genesis.as_slice()!=state.config.as_slice(){return Err(TieredDurableError::Config)}
  let mut found=minimum.is_none()||minimum==Some(tip);
  while let Some((next,payload))=read_frame(&mut file,tip)?{
   if payload.len()>MAX_FRAME{return Err(TieredDurableError::Corrupt)}
   let event:Event=serde_json::from_slice(&payload).map_err(|_|TieredDurableError::Corrupt)?;
   // Rejected calls were journaled too (clock may have advanced).
   let _=state.apply(event);
   tip=next;found|=minimum==Some(tip);
  }
  if !found{return Err(TieredDurableError::Rollback)}
  Ok(Self{file,tip,state,poisoned:false})
 }
 fn ready(&self)->D<()>{if self.poisoned{Err(TieredDurableError::Poisoned)}else{Ok(())}}
 fn append(&mut self,event:&Event)->D<()>{
  self.ready()?;
  let data=serde_json::to_vec(event).map_err(|_|TieredDurableError::Corrupt)?;
  match write_frame(&mut self.file,self.tip,&data){
   Ok(tip)=>{self.tip=tip;Ok(())},
   Err(e)=>{self.poisoned=true;Err(e.into())}
  }
 }
 fn record(&mut self,event:Event)->D<Reply>{
  self.append(&event)?;
  Ok(self.state.apply(event)?)
 }
 pub fn tip(&self)->D<JournalTip>{self.ready()?;Ok(self.tip)}
 /// Read-only view of the in-memory tiered router.
 pub fn router(&self)->D<&TieredRouter>{self.ready()?;Ok(&self.state.router)}
 pub fn balance(&self,channel:&BtcOutPoint)->D<Option<Balance>>{self.ready()?;Ok(self.state.router.balance(channel))}
 pub fn head(&self,channel:&BtcOutPoint)->D<Option<Head>>{self.ready()?;Ok(self.state.lanes.get(&op(channel)).map(|l|l.head))}
 pub fn batch(&self,sequence:u64)->D<Option<(&Batch,Phase)>>{self.ready()?;Ok(self.state.batches.get(&sequence).map(|e|(&e.batch,e.phase)))}
 pub fn next_resolution(&self)->D<u64>{self.ready()?;Ok(self.state.next_resolution)}
 pub fn acknowledgement(&self,sequence:u64)->D<Option<&AckBundle>>{self.ready()?;Ok(self.state.batches.get(&sequence).and_then(|e|e.ack.as_ref()))}
 pub fn fee_totals(&self)->D<(u128,u128)>{self.ready()?;Ok((self.state.oracle_paid,self.state.router_paid))}
 pub fn config_hash(&self)->Key{self.state.config}
 pub fn ack_message(&self,sequence:u64,disposition:Disposition,ack:&ChannelAck)->D<Key>{self.ready()?;Ok(self.state.message(sequence,disposition,ack).map_err(TierReject::from)?)}
 pub fn ingest_mark(&mut self,mark:MarkView,now:u64)->D<()>{self.record(Event::Mark{mark,now}).map(|_|())}
 pub fn submit(&mut self,intent:IntentV6,entitlement:Option<Entitlement>,now:u64)->D<u64>{
  match self.record(Event::Submit{intent,entitlement,now})?{Reply::Due(x)=>Ok(x),_=>unreachable!()}
 }
 pub fn process_one(&mut self,now:u64)->D<Option<TierOutcome>>{match self.record(Event::Process{now})?{Reply::Outcome(x)=>Ok(x),_=>unreachable!()}}
 /// Add an account and its lane to a live venue. Journaled and fsynced before it is applied.
 pub fn register(&mut self,allocation:Allocation,lane:Lane)->D<()>{
  let lane=LaneRec{channel:lane.channel,peer:lane.peer,monitor:lane.monitor,initial:lane.initial};
  self.record(Event::Register{allocation,lane}).map(|_|())
 }
 pub fn set_emergency_hold(&mut self,on:bool)->D<()>{self.record(Event::Hold{on}).map(|_|())}
 pub fn seal_batch(&mut self)->D<Option<Batch>>{match self.record(Event::Seal)?{Reply::Batch(x)=>Ok(x),_=>unreachable!()}}
 pub fn prepare(&mut self,sequence:u64,approvals:Vec<BatchApproval>)->D<()>{self.record(Event::Prepare{sequence,approvals}).map(|_|())}
 pub fn resolve(&mut self,bundle:AckBundle)->D<bool>{match self.record(Event::Resolve{bundle})?{Reply::Resolved(x)=>Ok(x),_=>unreachable!()}}
 /// Fence and abort the head batch once the router clock is `ABORT_AFTER_US` past its
 /// window end. Each lane's ack needs peer and monitor signatures; the owner's may be
 /// all-zero (a present owner signature must still verify).
 pub fn expire(&mut self,bundle:AckBundle)->D<bool>{match self.record(Event::Expire{bundle})?{Reply::Resolved(x)=>Ok(x),_=>unreachable!()}}
 /// Crash-testing hook: journal and fsync a process step without applying it, as if the
 /// process died between the append and the in-memory update. The writer is poisoned
 /// afterwards (memory is stale); reopen replays the step.
 #[doc(hidden)]
 pub fn append_process_without_apply(&mut self,now:u64)->D<()>{self.append(&Event::Process{now})?;self.poisoned=true;Ok(())}
}
