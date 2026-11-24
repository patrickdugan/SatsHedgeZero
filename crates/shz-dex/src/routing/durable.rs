//! HFT-05 reference crash recovery and signed channel-state acknowledgement gate.
//! A signed monitor attestation is a trust assumption, NOT an LDK/BOLT proof.
//! One journal and writer per immutable router allocation generation.
use super::*;
use std::{fs::{File,OpenOptions},io::{self,Read,Write},path::Path};
use thiserror::Error;

const MAX_FRAME:usize=16*1024*1024;
const MAGIC:&[u8;8]=b"SHZWAL05";

#[derive(Debug,Error)]
pub enum DurableError{
 #[error("journal I/O: {0}")] Io(#[from] io::Error),
 #[error("journal writer already held or cannot be locked")] Locked,
 #[error("invalid journal, checksum, format or torn frame")] Corrupt,
 #[error("journal configuration mismatch")] Config,
 #[error("journal does not contain the independently pinned tip")] Rollback,
 #[error("writer poisoned after failed persistence; reopen and reconcile")] Poisoned,
 #[error("router rejected operation: {0:?}")] Rejected(Reject),
}
impl From<Reject> for DurableError{fn from(r:Reject)->Self{Self::Rejected(r)}}
type D<T>=Result<T,DurableError>;

#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct JournalTip{pub records:u64,pub digest:Key}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct Head{
 /// Monotone logical allocation-lane revision, not a Bitcoin height.
 pub revision:u64,
 /// Commitment counter supplied by the external channel adapter.
 pub commitment:u64,pub state:Key,
}
#[derive(Debug,Clone)]
pub struct Lane{
 pub channel:BtcOutPoint,pub peer:Key,pub monitor:Key,pub initial:Head,
}
#[derive(Debug,Clone,Copy)]
pub struct FeeRecipients{pub oracle:Key,pub router:Key}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub enum Disposition{Commit,FencedAbort}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct ChannelAck{
 pub channel:BtcOutPoint,pub previous:Head,pub next:Head,
 /// Digest of the independently verified commitment/monitor persistence
 /// transcript, or irreversible cancellation/fencing evidence for abort.
 pub evidence:Key,
 /// Unique digest of an externally verified exact fee debit/recipient credit
 /// receipt for this lane and batch. Zero for fee-free commits and aborts.
 pub fee_evidence:Key,
 /// Ordered: channel owner, pinned counterparty, pinned commitment monitor.
 pub signatures:[Bip340Signature;3],
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct AckBundle{
 pub sequence:u64,pub batch:Key,pub disposition:Disposition,pub channels:Vec<ChannelAck>,
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Phase{Sealed,Prepared,Committed,Aborted}
struct Entry{batch:Batch,phase:Phase,ack:Option<AckBundle>}
struct LaneState{peer:Key,monitor:Key,head:Head}
struct State{
 router:Router,lanes:BTreeMap<Outpoint,LaneState>,recipients:FeeRecipients,config:Key,
 batches:BTreeMap<u64,Entry>,next_resolution:u64,oracle_paid:u128,router_paid:u128,fee_receipts:BTreeSet<Key>,
}
impl State{
 fn new(policy:Policy,registry:&Registry,id:u32,engine:Engine,lanes:Vec<Lane>,recipients:FeeRecipients)->D<Self>{
  let router=Router::new_with_engine(policy,registry,id,engine)?;
  if recipients.oracle==[0;32]||recipients.router==[0;32]||recipients.oracle==recipients.router{return Err(DurableError::Config)}
  let mut map=BTreeMap::new();
  for l in lanes{
   let owner=router.accounts.get(&op(&l.channel)).ok_or(DurableError::Config)?.owner;
   if l.peer==[0;32]||l.monitor==[0;32]||l.peer==l.monitor||l.peer==owner||l.monitor==owner||
      l.initial.state==[0;32]||l.initial.revision!=0||
      map.insert(op(&l.channel),LaneState{peer:l.peer,monitor:l.monitor,head:l.initial}).is_some(){return Err(DurableError::Config)}
  }
  if map.len()!=router.accounts.len(){return Err(DurableError::Config)}
  // Canonical configuration binds the *entire* verified allocation snapshot,
  // not merely its local caps. Authority/owner signatures are included.
  let mut b=Vec::new();router.scope.put(&mut b);u32b(&mut b,id);
  b.push(match engine{Engine::Scan=>0,Engine::Indexed=>1,Engine::Joint=>2,Engine::Both=>3});
  b.extend(recipients.oracle);b.extend(recipients.router);
  let mut allocations:Vec<_>=registry.allocations.iter().collect();
  allocations.sort_by_key(|a|op(&a.channel));u64b(&mut b,allocations.len()as u64);
  for a in allocations{b.extend(a.digest()?);b.extend(a.owner_sig.to_bytes());b.extend(a.authority_sig.to_bytes());}
  u64b(&mut b,map.len()as u64);
  for (&(txid,vout),l) in &map{b.extend(txid);u32b(&mut b,vout);b.extend(l.peer);b.extend(l.monitor);put_head(&mut b,&l.head);}
  let config=tagged_hash(b"SHZ/HFT/WAL-CONFIG/V1",&b);
  Ok(Self{router,lanes:map,recipients,config,batches:BTreeMap::new(),next_resolution:1,oracle_paid:0,router_paid:0,fee_receipts:BTreeSet::new()})
 }
 fn message(&self,sequence:u64,disposition:Disposition,ack:&ChannelAck)->R<Key>{
  let batch=&self.batches.get(&sequence).ok_or(Reject::UnknownOrder)?.batch;
  let a=batch.accounts().iter().find(|a|op(&a.channel)==op(&ack.channel)).ok_or(Reject::Allocation)?;
  let mut b=Vec::new();b.extend(self.config);b.extend(batch.digest());u64b(&mut b,sequence);
  b.push(match disposition{Disposition::Commit=>1,Disposition::FencedAbort=>2});
  put_op(&mut b,&ack.channel);b.extend(a.owner);u64b(&mut b,a.margin_sats);u64b(&mut b,a.fee_sats);
  put_head(&mut b,&ack.previous);put_head(&mut b,&ack.next);b.extend(ack.evidence);b.extend(ack.fee_evidence);
  b.extend(self.recipients.oracle);b.extend(self.recipients.router);
  b.extend(batch.oracle_due_sats().to_le_bytes());b.extend(batch.router_due_sats().to_le_bytes());
  Ok(tagged_hash(b"SHZ/HFT/CHANNEL-ACK/V1",&b))
 }
 fn prepare(&mut self,sequence:u64,approvals:&[BatchApproval])->R<()>{
  if sequence!=self.next_resolution{return Err(Reject::Replay)}
  let entry=self.batches.get_mut(&sequence).ok_or(Reject::UnknownOrder)?;
  if !matches!(entry.phase,Phase::Sealed|Phase::Prepared){return Err(Reject::Replay)}
  entry.batch.verify_approvals(approvals)?;
  entry.phase=Phase::Prepared;Ok(())
 }
 fn resolve(&mut self,bundle:AckBundle)->R<bool>{
  let entry=self.batches.get(&bundle.sequence).ok_or(Reject::UnknownOrder)?;
  // An exact byte-equivalent signed bundle is idempotent after recovery.
  if let Some(old)=&entry.ack{return if old==&bundle{Ok(false)}else{Err(Reject::Replay)}}
  if bundle.sequence!=self.next_resolution||entry.phase!=Phase::Prepared||bundle.batch!=entry.batch.digest(){return Err(Reject::Replay)}
  let batch=&entry.batch;
  if bundle.channels.len()!=batch.accounts().len(){return Err(Reject::Allocation)}
  let next_sequence=self.next_resolution.checked_add(1).ok_or(Reject::Bounds)?;
  let mut changes=Vec::new();let mut new_receipts=BTreeSet::new();
  // Canonical order must be the exact batch account order; no omission,
  // duplicate, cross-router substitution or partial application.
  for (a,ack) in batch.accounts().iter().zip(&bundle.channels){
   if op(&a.channel)!=op(&ack.channel){return Err(Reject::Allocation)}
   let key=op(&a.channel);
   let lane=self.lanes.get(&key).ok_or(Reject::Allocation)?;
   if ack.previous!=lane.head||ack.next.revision!=lane.head.revision.checked_add(1).ok_or(Reject::Bounds)?||
      ack.evidence==[0;32]||ack.next.state==[0;32]{return Err(Reject::Replay)}
   match bundle.disposition{
    Disposition::Commit=>{
     if ack.next.commitment!=lane.head.commitment.checked_add(1).ok_or(Reject::Bounds)?||ack.next.state==lane.head.state{return Err(Reject::Replay)}
    },
    Disposition::FencedAbort=>{
     // The monitor must attest an irreversible cancellation on every lane.
     // Physical commitment state stays unchanged, logical revision advances.
     if ack.next.commitment!=lane.head.commitment||ack.next.state!=lane.head.state{return Err(Reject::Replay)}
    }
   }
   if bundle.disposition==Disposition::Commit&&a.fee_sats>0{
    if ack.fee_evidence==[0;32]||self.fee_receipts.contains(&ack.fee_evidence)||!new_receipts.insert(ack.fee_evidence){return Err(Reject::FeeLimit)}
   }else if ack.fee_evidence!=[0;32]{return Err(Reject::FeeLimit)}
   let h=self.message(bundle.sequence,bundle.disposition,ack)?;
   for (k,sig) in [a.owner,lane.peer,lane.monitor].iter().zip(&ack.signatures){verify(k,&h,sig)?;}
   let mut balance=self.router.accounts.get(&key).ok_or(Reject::Allocation)?.balance;
   let debit=a.margin_sats.checked_add(a.fee_sats).ok_or(Reject::Bounds)?;
   balance.pending=balance.pending.checked_sub(debit).ok_or(Reject::Capacity)?;
   match bundle.disposition{
    Disposition::Commit=>{
     balance.committed=balance.committed.checked_add(a.margin_sats).ok_or(Reject::Bounds)?;
     balance.paid_fees=balance.paid_fees.checked_add(a.fee_sats).ok_or(Reject::Bounds)?;
    },
    Disposition::FencedAbort=>{balance.free=balance.free.checked_add(debit).ok_or(Reject::Bounds)?;}
   }
   if !balance.conserved(){return Err(Reject::Bounds)}
   changes.push((key,balance,ack.next));
  }
  let (oracle,router)=match bundle.disposition{
   Disposition::Commit=>(self.oracle_paid.checked_add(batch.oracle_due_sats()).ok_or(Reject::Bounds)?,self.router_paid.checked_add(batch.router_due_sats()).ok_or(Reject::Bounds)?),
   Disposition::FencedAbort=>(self.oracle_paid,self.router_paid)
  };
  // Do not reactivate aborted maker quantities. Cancel any surviving
  // residual quote, retaining already-created later fill obligations.
  let cancel:Vec<_>=if bundle.disposition==Disposition::FencedAbort{batch.legs().iter().map(|f|f.maker_id).collect()}else{Vec::new()};
  // No fallible checks past this point. All account updates atomic in memory.
  for (key,balance,head) in changes{self.router.accounts.get_mut(&key).unwrap().balance=balance;self.lanes.get_mut(&key).unwrap().head=head;}
  for id in cancel{self.router.remove(id);}
  self.oracle_paid=oracle;self.router_paid=router;self.next_resolution=next_sequence;self.fee_receipts.extend(new_receipts);
  let entry=self.batches.get_mut(&bundle.sequence).unwrap();
  entry.phase=match bundle.disposition{Disposition::Commit=>Phase::Committed,Disposition::FencedAbort=>Phase::Aborted};
  entry.ack=Some(bundle);Ok(true)
 }
 fn apply(&mut self,event:Event)->R<Reply>{
  match event{
   Event::Mark{ticks,now}=>Ok(Reply::Mark(self.router.update_mark(ticks,now)?)),
   Event::Submit{intent,now}=>Ok(Reply::Due(self.router.submit(intent,now)?)),
   Event::Process{now}=>Ok(Reply::Outcome(self.router.process_one(now)?)),
   Event::Seal=>{
    let batch=self.router.seal_fill_batch()?;
    if let Some(ref b)=batch{
     assert!(self.batches.insert(b.sequence(),Entry{batch:b.clone(),phase:Phase::Sealed,ack:None}).is_none());
    }
    Ok(Reply::Batch(batch))
   },
   Event::Prepare{sequence,approvals}=>{self.prepare(sequence,&approvals)?;Ok(Reply::Unit)},
   Event::Resolve{bundle}=>Ok(Reply::Resolved(self.resolve(bundle)?)),
  }
 }
}
fn put_head(b:&mut Vec<u8>,h:&Head){u64b(b,h.revision);u64b(b,h.commitment);b.extend(h.state);}

#[derive(Debug,Serialize,Deserialize)]
enum Event{
 Mark{ticks:[RelayTick;2],now:u64},
 Submit{intent:Intent,now:u64},
 Process{now:u64},
 Seal,
 Prepare{sequence:u64,approvals:Vec<BatchApproval>},
 Resolve{bundle:AckBundle},
}
enum Reply{Mark(Key),Due(u64),Outcome(Option<Outcome>),Batch(Option<Batch>),Unit,Resolved(bool)}

fn frame_hash(previous:JournalTip,payload:&[u8])->D<JournalTip>{
 let records=previous.records.checked_add(1).ok_or(DurableError::Corrupt)?;
 let mut b=Vec::with_capacity(44+payload.len());b.extend(previous.digest);u64b(&mut b,records);u32b(&mut b,payload.len()as u32);b.extend(payload);
 Ok(JournalTip{records,digest:tagged_hash(b"SHZ/HFT/WAL-FRAME/V1",&b)})
}
fn write_frame(file:&mut File,previous:JournalTip,payload:&[u8])->D<JournalTip>{
 if payload.is_empty()||payload.len()>MAX_FRAME{return Err(DurableError::Corrupt)}
 let tip=frame_hash(previous,payload)?;
 file.write_all(&(payload.len()as u32).to_le_bytes())?;file.write_all(payload)?;file.write_all(&tip.digest)?;
 file.sync_all()?;Ok(tip)
}
fn exact(file:&mut File,buf:&mut[u8])->D<()>{
 file.read_exact(buf).map_err(|e|if e.kind()==io::ErrorKind::UnexpectedEof{DurableError::Corrupt}else{DurableError::Io(e)})
}
fn read_frame(file:&mut File,previous:JournalTip)->D<Option<(JournalTip,Vec<u8>)>>{
 let mut length=[0u8;4];
 // Clean EOF only before any frame byte. Torn tails require reconciliation.
 match file.read(&mut length[..1])?{0=>return Ok(None),1=>{},_=>unreachable!()}
 exact(file,&mut length[1..])?;
 let len=u32::from_le_bytes(length)as usize;
 if len==0||len>MAX_FRAME{return Err(DurableError::Corrupt)}
 let mut p=vec![0;len];exact(file,&mut p)?;
 let mut hash=[0;32];exact(file,&mut hash)?;
 let tip=frame_hash(previous,&p)?;
 if hash!=tip.digest{return Err(DurableError::Corrupt)}
 Ok(Some((tip,p)))
}
const ZERO_TIP:JournalTip=JournalTip{records:0,digest:[0;32]};

/// Full event-sourced router, including rejected calls that may advance time.
/// No mutable Router escapes. File is held exclusively for the writer lifetime.
/// The command is durable before in-memory application or reply; on I/O failure
/// the writer is poisoned. A fully persisted but unacknowledged command replays.
pub struct DurableRouter{file:File,tip:JournalTip,state:State,poisoned:bool}
impl DurableRouter{
 pub fn create(path:&Path,policy:Policy,registry:&Registry,id:u32,engine:Engine,lanes:Vec<Lane>,recipients:FeeRecipients)->D<Self>{
  let state=State::new(policy,registry,id,engine,lanes,recipients)?;
  let mut file=OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
  file.try_lock().map_err(|_|DurableError::Locked)?;
  file.write_all(MAGIC)?;
  let tip=write_frame(&mut file,ZERO_TIP,&state.config)?;
  // Persist the newly-created directory entry on the supported Unix host.
  #[cfg(unix)]
  {let parent=path.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(Path::new("."));File::open(parent)?.sync_all()?;}
  Ok(Self{file,tip,state,poisoned:false})
 }
 /// A caller-supplied independently stored minimum tip detects valid-prefix
 /// rollback. Without it, recovery assumes storage has not been rolled back.
 pub fn open(path:&Path,policy:Policy,registry:&Registry,id:u32,engine:Engine,lanes:Vec<Lane>,recipients:FeeRecipients,minimum:Option<JournalTip>)->D<Self>{
  let mut state=State::new(policy,registry,id,engine,lanes,recipients)?;
  let mut file=OpenOptions::new().read(true).write(true).open(path)?;
  file.try_lock().map_err(|_|DurableError::Locked)?;
  let mut magic=[0;8];exact(&mut file,&mut magic)?;
  if &magic!=MAGIC{return Err(DurableError::Corrupt)}
  let (mut tip,genesis)=read_frame(&mut file,ZERO_TIP)?.ok_or(DurableError::Corrupt)?;
  if genesis.as_slice()!=state.config.as_slice(){return Err(DurableError::Config)}
  let mut found=minimum.is_none()||minimum==Some(tip);
  while let Some((next,payload))=read_frame(&mut file,tip)?{
   let event:Event=serde_json::from_slice(&payload).map_err(|_|DurableError::Corrupt)?;
   // Rejected calls were journaled too (clock may have advanced).
   let _=state.apply(event);
   tip=next;found|=minimum==Some(tip);
  }
  if !found{return Err(DurableError::Rollback)}
  Ok(Self{file,tip,state,poisoned:false})
 }
 fn ready(&self)->D<()>{if self.poisoned{Err(DurableError::Poisoned)}else{Ok(())}}
 fn record(&mut self,event:Event)->D<Reply>{
  self.ready()?;
  let data=serde_json::to_vec(&event).map_err(|_|DurableError::Corrupt)?;
  match write_frame(&mut self.file,self.tip,&data){
   Ok(tip)=>self.tip=tip,
   Err(e)=>{self.poisoned=true;return Err(e)}
  }
  Ok(self.state.apply(event)?)
 }
 pub fn tip(&self)->D<JournalTip>{self.ready()?;Ok(self.tip)}
 pub fn balance(&self,channel:&BtcOutPoint)->D<Option<Balance>>{self.ready()?;Ok(self.state.router.balance(channel))}
 pub fn head(&self,channel:&BtcOutPoint)->D<Option<Head>>{self.ready()?;Ok(self.state.lanes.get(&op(channel)).map(|l|l.head))}
 pub fn batch(&self,sequence:u64)->D<Option<(&Batch,Phase)>>{self.ready()?;Ok(self.state.batches.get(&sequence).map(|e|(&e.batch,e.phase)))}
 pub fn next_resolution(&self)->D<u64>{self.ready()?;Ok(self.state.next_resolution)}
 pub fn acknowledgement(&self,sequence:u64)->D<Option<&AckBundle>>{self.ready()?;Ok(self.state.batches.get(&sequence).and_then(|e|e.ack.as_ref()))}
 pub fn fee_totals(&self)->D<(u128,u128)>{self.ready()?;Ok((self.state.oracle_paid,self.state.router_paid))}
 pub fn pending_orders(&self)->D<usize>{self.ready()?;Ok(self.state.router.pending_orders())}
 pub fn resting(&self)->D<usize>{self.ready()?;Ok(self.state.router.resting())}
 pub fn clock(&self)->D<u64>{self.ready()?;Ok(self.state.router.clock)}
 pub fn ack_message(&self,sequence:u64,disposition:Disposition,ack:&ChannelAck)->D<Key>{self.ready()?;Ok(self.state.message(sequence,disposition,ack)?)}
 pub fn update_mark(&mut self,ticks:[RelayTick;2],now:u64)->D<Key>{match self.record(Event::Mark{ticks,now})?{Reply::Mark(x)=>Ok(x),_=>unreachable!()}}
 pub fn submit(&mut self,intent:Intent,now:u64)->D<u64>{match self.record(Event::Submit{intent,now})?{Reply::Due(x)=>Ok(x),_=>unreachable!()}}
 pub fn process_one(&mut self,now:u64)->D<Option<Outcome>>{match self.record(Event::Process{now})?{Reply::Outcome(x)=>Ok(x),_=>unreachable!()}}
 pub fn seal_fill_batch(&mut self)->D<Option<Batch>>{match self.record(Event::Seal)?{Reply::Batch(x)=>Ok(x),_=>unreachable!()}}
 pub fn prepare(&mut self,sequence:u64,approvals:Vec<BatchApproval>)->D<()>{match self.record(Event::Prepare{sequence,approvals})?{Reply::Unit=>Ok(()),_=>unreachable!()}}
 pub fn resolve(&mut self,bundle:AckBundle)->D<bool>{match self.record(Event::Resolve{bundle})?{Reply::Resolved(x)=>Ok(x),_=>unreachable!()}}
}
