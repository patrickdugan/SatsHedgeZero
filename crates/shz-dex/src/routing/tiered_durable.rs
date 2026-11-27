//! HFT-06 durable tiered router: the HFT-05 journal framing and signed channel-state
//! acknowledgement gate applied to `TieredRouter`. A signed monitor attestation is a
//! trust assumption, NOT an LDK/BOLT proof. One journal and writer per immutable
//! router configuration (scope, router id, tariff, execution policy, revenue policy,
//! entitlement key, allocation registry, lanes, fee recipients).
use super::*;
use super::durable::{AckBundle,ChannelAck,Disposition,FeeRecipients,Head,JournalTip,Lane,LaneState,Phase,PositionOf,
 ZERO_TIP,MAX_FRAME,ack_message,lane_settlement,plan_resolution,put_head,read_frame,write_frame,exact};
use super::positions::{self,Position,Settlement};
use super::clearing::{self,BatchClearing,ClearPlan,ClearingState};
use super::tiered::*;
use super::options::{OptionBatchKind,IntentV7,OptionAckBundle,OptionBatch,OptionOutcome,OptionsDesk,Series,SettleAsset,option_ack_message};
use shz_dlc::{OracleAnnouncement,OracleAttestation};
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
/// Acknowledgements once margin release is active: they also bind the lane's `Settlement`
/// (released margin, payout of closed lots, position before and after).
pub const TIERED_ACK_TAG_V2:&[u8]=b"SHZ/HFT06/CHANNEL-ACK/V2";
/// Acknowledgements once multilateral clearing is active: the V2 settlement (with the
/// cleared cash payout) plus the lane's clearing row and the digest of the batch's whole
/// net settlement vector (`clearing::BatchClearing::digest`).
pub const TIERED_ACK_TAG_V3:&[u8]=b"SHZ/HFT06/CHANNEL-ACK/V3";

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
struct Entry{batch:Batch,phase:Phase,ack:Option<AckBundle>,settlements:Vec<(BtcOutPoint,Settlement)>,clearing:Option<BatchClearing>}
struct State{
 router:TieredRouter,lanes:BTreeMap<Outpoint,LaneState>,recipients:FeeRecipients,config:Key,
 batches:BTreeMap<u64,Entry>,next_resolution:u64,oracle_paid:u128,router_paid:u128,fee_receipts:BTreeSet<Key>,
 /// Margin release (`positions`) switched on by a journaled `EnableMarginRelease`.
 netting:bool,
 /// Multilateral clearing (`clearing`) switched on by a journaled `EnableClearing`.
 clearing:Option<ClearingState>,
 /// Options desk (`options`) switched on by a journaled `EnableOptions`.
 options:Option<OptionsDesk>,
 /// Option batches wait for lane acknowledgements (journaled `EnableOptionAcks`).
 option_acks:bool,
 /// The one option batch staged for acknowledgement, if any.
 pending_option:Option<PendingOption>,
 /// The bundle that resolved the last option batch (an exact retry is idempotent).
 last_option_resolution:Option<OptionAckBundle>,
 /// Expiry and void batches commit on peer and monitor signatures, owner optional
 /// (journaled `EnableOwnerlessExpiry`); trade batches always need every owner.
 ownerless_expiry:bool,
}
/// A staged option batch: the desk as it is after the batch, the BTC pool's dust (its only
/// effect on the shared BTC ledger, applied as a delta so perpetual resolutions in between
/// are kept), when it was staged, and what an abort must still do.
struct PendingOption{batch:OptionBatch,desk:OptionsDesk,btc_dust:i64,staged_us:u64,taker:Option<(Outpoint,u64)>,makers:Vec<Key>}
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
  Ok(Self{router,lanes:map,recipients,config,batches:BTreeMap::new(),next_resolution:1,oracle_paid:0,router_paid:0,fee_receipts:BTreeSet::new(),netting:false,clearing:None,options:None,option_acks:false,pending_option:None,last_option_resolution:None,ownerless_expiry:false})
 }
 fn tag(&self)->&'static [u8]{if self.clearing.is_some(){TIERED_ACK_TAG_V3}else if self.netting{TIERED_ACK_TAG_V2}else{TIERED_ACK_TAG}}
 fn plan_clearing(&self,batch:&Batch,disposition:Disposition)->R<Option<ClearPlan>>{
  match (&self.clearing,disposition){
   (Some(c),Disposition::Commit)=>Ok(Some(clearing::clear(c,batch,&|k:&Outpoint|self.router.account_position(k))?)),
   _=>Ok(None),
  }
 }
 fn message(&self,sequence:u64,disposition:Disposition,ack:&ChannelAck)->R<Key>{
  let batch=&self.batches.get(&sequence).ok_or(Reject::UnknownOrder)?.batch;
  if let Some(plan)=self.plan_clearing(batch,disposition)?{
   let i=batch.accounts().iter().position(|a|op(&a.channel)==op(&ack.channel)).ok_or(Reject::Allocation)?;
   return ack_message(self.tag(),&self.config,&self.recipients,sequence,batch,disposition,ack,Some(&plan.lanes[i].1),Some(&plan.report));
  }
  let settled=if self.netting&&disposition==Disposition::Commit{
   Some(lane_settlement(batch,&ack.channel,&|k:&Outpoint|self.router.account_position(k))?.1)
  }else{None};
  ack_message(self.tag(),&self.config,&self.recipients,sequence,batch,disposition,ack,settled.as_ref(),None)
 }
 fn enable_clearing(&mut self,fund:u64)->R<()>{
  if !self.netting||self.clearing.is_some(){return Err(Reject::Replay)}
  self.clearing=Some(ClearingState::open(fund,self.router.account_books().map(|(_,p,b)|(p,b)))?);
  // Clearing switches closing loans on as well: the deployed venue journal (clearing
  // enabled 2026-11-26 12:50Z, running bf4d556 since 12:56Z) depends on it.
  self.router.set_close_from_lots(true);Ok(())
 }
 /// The options desk for a mutation: refused (`Hold`) while an option batch is staged,
 /// since the staged desk replaces the current one when it commits.
 fn desk(&mut self)->Result<&mut OptionsDesk,TierReject>{
  if self.pending_option.is_some(){return Err(TierReject::Hold)}
  self.options.as_mut().ok_or(TierReject::Scope)
 }
 fn stage(&mut self,b:&OptionBatch,desk:OptionsDesk,now:u64,taker:Option<(Outpoint,u64)>){
  let btc_dust=b.clearing_of(&SettleAsset::Btc).map_or(0,|c|c.pool_net());
  let makers=b.fills.iter().map(|f|f.maker).collect();
  self.pending_option=Some(PendingOption{batch:b.clone(),desk,btc_dust,staged_us:now,taker,makers});
 }
 /// Commit or fence-abort the staged option batch against every lane's V4 acknowledgement.
 fn resolve_option(&mut self,bundle:OptionAckBundle,now:u64)->R<bool>{
  let staged=self.pending_option.as_ref().filter(|p|bundle.sequence==p.batch.sequence&&bundle.batch==p.batch.digest());
  // An exact byte-equivalent retry of the last resolution is idempotent after recovery.
  if staged.is_none()&&self.last_option_resolution.as_ref()==Some(&bundle){return Ok(false)}
  let p=self.pending_option.as_ref().ok_or(Reject::UnknownOrder)?;
  if bundle.sequence!=p.batch.sequence||bundle.batch!=p.batch.digest(){return Err(Reject::Replay)}
  let abort=bundle.disposition==Disposition::FencedAbort;
  // An expiry or void batch is a deterministic function of the oracle's signature, so
  // once enabled an offline holder's owner signature is optional for it; never for a trade.
  let owner_optional=abort||(self.ownerless_expiry&&!matches!(p.batch.kind,OptionBatchKind::Trade{..}));
  if abort&&now<p.staged_us.saturating_add(ABORT_AFTER_US){return Err(Reject::Clock)}
  let channels=p.batch.channels();
  if bundle.acks.len()!=channels.len(){return Err(Reject::Allocation)}
  for (c,a) in channels.iter().zip(&bundle.acks){
   if op(c)!=op(&a.channel){return Err(Reject::Allocation)}
   let lane=self.lanes.get(&op(c)).ok_or(Reject::Allocation)?;
   let owner=self.router.account_owner(&op(c)).ok_or(Reject::Allocation)?;
   let h=option_ack_message(&self.config,&p.batch,bundle.disposition,c)?;
   for (i,(k,sig)) in [owner,lane.peer,lane.monitor].iter().zip(&a.signatures).enumerate(){
    if i==0&&owner_optional&&sig.r_x==[0;32]&&sig.s==[0;32]{continue}
    verify(k,&h,sig)?;
   }
  }
  // No fallible checks past this point.
  let p=self.pending_option.take().unwrap();
  let desk=self.options.as_mut().unwrap();
  if abort{
   if let Some((k,seq))=p.taker{desk.consume(k,seq)}
   desk.cancel_quotes(&p.makers);desk.touch(now);
  }else{
   let mut next=p.desk;next.touch(now);*desk=next;
   if let Some(c)=self.clearing.as_mut(){c.cash+=p.btc_dust;c.fund+=p.btc_dust as u64;}
  }
  self.last_option_resolution=Some(bundle);
  Ok(true)
 }
 fn enable_closing_loans(&mut self)->R<()>{
  if !self.netting||self.router.close_from_lots(){return Err(Reject::Replay)}
  self.router.set_close_from_lots(true);Ok(())
 }
 fn enable_netting(&mut self)->R<()>{
  if self.netting{return Err(Reject::Replay)}
  let committed=self.batches.iter().filter(|(_,e)|e.phase==Phase::Committed).map(|(s,e)|(*s,&e.batch));
  let (state,per_batch)=positions::reconcile(committed,&|k:&Outpoint|self.router.account_balance(k))?;
  for (k,(p,b)) in state{self.router.set_account_balance(&k,b);self.router.set_account_position(&k,p);}
  for (seq,rows) in per_batch{self.batches.get_mut(&seq).unwrap().settlements=rows;}
  self.netting=true;Ok(())
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
  let router=&self.router;
  let position_of=|k:&Outpoint|router.account_position(k);
  let cleared=self.plan_clearing(&entry.batch,bundle.disposition)?;
  let plan=plan_resolution(self.tag(),&self.config,&self.recipients,&self.lanes,
   &|k:&Outpoint|router.account_balance(k),self.netting.then_some(&position_of as PositionOf),cleared.as_ref(),&router.batch_loans(&entry.batch),&router.other_loans(&entry.batch),
   &self.fee_receipts,(self.oracle_paid,self.router_paid),&entry.batch,&bundle,deadline)?;
  // No fallible checks past this point. All account updates atomic in memory.
  for (key,balance,head) in plan.changes{self.router.set_account_balance(&key,balance);self.lanes.get_mut(&key).unwrap().head=head;}
  let mut settlements=Vec::new();
  for (key,position,channel,s) in plan.positions{self.router.set_account_position(&key,position);settlements.push((channel,s));}
  for id in plan.cancel{self.router.cancel_resting(id);}
  self.router.release_unresolved(&entry.batch);
  self.oracle_paid=plan.oracle;self.router_paid=plan.router;self.next_resolution=next_sequence;self.fee_receipts.extend(plan.receipts);
  let entry=self.batches.get_mut(&bundle.sequence).unwrap();
  entry.phase=match bundle.disposition{Disposition::Commit=>Phase::Committed,Disposition::FencedAbort=>Phase::Aborted};
  entry.ack=Some(bundle);entry.settlements=settlements;
  if let Some(c)=cleared{entry.clearing=Some(c.report);self.clearing=Some(c.next);}
  Ok(true)
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
     assert!(self.batches.insert(b.sequence(),Entry{batch:b.clone(),phase:Phase::Sealed,ack:None,settlements:Vec::new(),clearing:None}).is_none());
    }
    Ok(Reply::Batch(batch))
   },
   Event::Prepare{sequence,approvals}=>{self.prepare(sequence,&approvals)?;Ok(Reply::Unit)},
   Event::Resolve{bundle}=>Ok(Reply::Resolved(self.resolve(bundle,false)?)),
   Event::Expire{bundle}=>Ok(Reply::Resolved(self.resolve(bundle,true)?)),
   Event::EnableMarginRelease=>{self.enable_netting()?;Ok(Reply::Unit)},
   Event::EnableClearing{fund_sats}=>{self.enable_clearing(fund_sats)?;Ok(Reply::Unit)},
   Event::EnableClosingLoans=>{self.enable_closing_loans()?;Ok(Reply::Unit)},
   Event::EnableOptions{oracle_key,num_bits}=>{
    if self.clearing.is_none()||self.options.is_some(){return Err(TierReject::Replay)}
    self.options=Some(OptionsDesk::new(oracle_key,num_bits)?);Ok(Reply::Unit)
   },
   Event::EnableOptionAcks=>{self.desk()?;if self.option_acks{return Err(TierReject::Replay)}self.option_acks=true;Ok(Reply::Unit)},
   Event::ResolveOption{bundle,now}=>Ok(Reply::Resolved(self.resolve_option(bundle,now)?)),
   Event::RegisterStable{asset}=>{self.desk()?.register_stable(asset)?;Ok(Reply::Unit)},
   Event::StableTransfer{channel,asset,units,deposit}=>{
    let k=op(&channel);if self.router.account_owner(&k).is_none(){return Err(TierReject::Allocation)}
    self.desk()?.stable_transfer(k,asset,units,deposit)?;Ok(Reply::Unit)
   },
   Event::EnableCombos=>{let d=self.desk()?;if d.combos{return Err(TierReject::Replay)}d.combos=true;Ok(Reply::Unit)},
   Event::ListSeries{series,announcement}=>Ok(Reply::Key(self.desk()?.list(series,announcement)?)),
   Event::FundOptions{channel,sats,to_options}=>{
    let k=op(&channel);
    let mut b=self.router.account_balance(&k).ok_or(TierReject::Allocation)?;
    self.desk()?.fund(k,&mut b,sats,to_options)?;
    self.router.set_account_balance(&k,b);Ok(Reply::Unit)
   },
   Event::SubmitOption{intent,now}=>{
    let mut desk=self.desk()?.clone();let mut clearing=self.clearing.clone().ok_or(TierReject::Scope)?;
    let c=self.router.config();let router=&self.router;
    let taker=(op(&intent.channel),intent.sequence);
    match desk.submit(c.scope,c.router,&|k:&Outpoint|router.account_owner(k),&mut clearing,intent,now)?{
     OptionOutcome::Filled(b) if self.option_acks=>{self.stage(&b,desk,now,Some(taker));Ok(Reply::Option(OptionOutcome::Staged(b)))},
     out=>{self.options=Some(desk);self.clearing=Some(clearing);Ok(Reply::Option(out))},
    }
   },
   Event::EnableOwnerlessExpiry=>{self.desk()?;if self.ownerless_expiry{return Err(TierReject::Replay)}self.ownerless_expiry=true;Ok(Reply::Unit)},
   Event::VoidUnattestable{event_id,notice}=>{
    let mut desk=self.desk()?.clone();let mut clearing=self.clearing.clone().ok_or(TierReject::Scope)?;
    let b=desk.void(&event_id,&notice,&mut clearing)?;
    if self.option_acks{let now=desk.clock();self.stage(&b,desk,now,None);}
    else{self.options=Some(desk);self.clearing=Some(clearing);}
    Ok(Reply::OptionBatch(Box::new(b)))
   },
   Event::ExpireSeries{series,attestation}=>{
    let mut desk=self.desk()?.clone();let mut clearing=self.clearing.clone().ok_or(TierReject::Scope)?;
    let b=desk.expire(&series,&attestation,&mut clearing)?;
    if self.option_acks{let now=desk.clock();self.stage(&b,desk,now,None);}
    else{self.options=Some(desk);self.clearing=Some(clearing);}
    Ok(Reply::OptionBatch(Box::new(b)))
   },
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
 EnableMarginRelease,
 /// Switch on multilateral clearing with this clearing fund (V3 acknowledgements).
 EnableClearing{fund_sats:u64},
 /// Closing taker legs borrow their margin from the lots they close (`closing_loan`),
 /// for a journal with margin release but no clearing (`EnableClearing` turns them on too).
 EnableClosingLoans,
 /// Switch on the options desk (clearing must be active): series settle on `oracle_key`
 /// announcements of `num_bits` digits.
 EnableOptions{oracle_key:Key,num_bits:u8},
 ListSeries{series:Series,announcement:OracleAnnouncement},
 /// Option trade and expiry batches wait for the lane acknowledgement round (V4).
 EnableOptionAcks,
 /// Lane acknowledgements committing or fence-aborting the staged option batch.
 ResolveOption{bundle:OptionAckBundle,now:u64},
 /// Register a stablecoin settlement asset (opens its clearing pool).
 RegisterStable{asset:SettleAsset},
 /// Credit (`deposit`) or debit `units` of a registered stablecoin (simulated TAP/RGB adapter).
 StableTransfer{channel:BtcOutPoint,asset:SettleAsset,units:u64,deposit:bool},
 /// Accept Take intents of up to `options::MAX_LEGS` legs (all-or-none, one batch).
 EnableCombos,
 /// Move sats between the perpetual allocation and the options sub-account.
 FundOptions{channel:BtcOutPoint,sats:u64,to_options:bool},
 SubmitOption{intent:IntentV7,now:u64},
 ExpireSeries{series:Key,attestation:OracleAttestation},
 /// Void every open series on `event_id` on the oracle's signed unattestable notice.
 VoidUnattestable{event_id:String,notice:Bip340Signature},
 /// Expiry and void batches commit on peer and monitor signatures, owner optional.
 EnableOwnerlessExpiry,
}
#[allow(clippy::large_enum_variant)]
enum Reply{Due(u64),Outcome(Option<TierOutcome>),Batch(Option<Batch>),Unit,Resolved(bool),Key(Key),Option(OptionOutcome),OptionBatch(Box<OptionBatch>)}

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
 /// Switch on margin release (journaled once). Positions are rebuilt from every batch
 /// already committed and their offset margin is released; later Commit acks use
 /// `TIERED_ACK_TAG_V2` and bind each lane's settlement. Returns `false` if already on.
 pub fn enable_margin_release(&mut self)->D<bool>{
  self.ready()?;if self.state.netting{return Ok(false)}
  self.record(Event::EnableMarginRelease)?;Ok(true)
 }
 pub fn margin_release_active(&self)->D<bool>{self.ready()?;Ok(self.state.netting)}
 /// Switch on multilateral clearing (journaled once; margin release must be active)
 /// with a clearing fund of `fund_sats`, the venue's own sats that absorb shortfalls
 /// before winning claims are haircut. The ledger opens from the current positions and
 /// balances, so an existing journal carries over. Later Commit acks use
 /// `TIERED_ACK_TAG_V3`. Returns `false` if already on.
 pub fn enable_clearing(&mut self,fund_sats:u64)->D<bool>{
  self.ready()?;if self.state.clearing.is_some(){return Ok(false)}
  self.record(Event::EnableClearing{fund_sats})?;Ok(true)
 }
 pub fn clearing_active(&self)->D<bool>{self.ready()?;Ok(self.state.clearing.is_some())}
 /// Switch on closing loans without clearing (journaled once; margin release must be
 /// active): a taker leg that reduces the account's position borrows its leg margin from
 /// the lots it closes, so only a flip excess and the taker fee need free margin.
 /// `enable_clearing` switches them on as well. Returns `false` if already on.
 pub fn enable_closing_loans(&mut self)->D<bool>{
  self.ready()?;if self.state.router.close_from_lots(){return Ok(false)}
  self.record(Event::EnableClosingLoans)?;Ok(true)
 }
 /// Switch on the options desk (journaled once; clearing must be active). Series list on
 /// announcements by `oracle_key` with `num_bits` digits, the margin domain.
 pub fn enable_options(&mut self,oracle_key:Key,num_bits:u8)->D<bool>{
  self.ready()?;if self.state.options.is_some(){return Ok(false)}
  self.record(Event::EnableOptions{oracle_key,num_bits})?;Ok(true)
 }
 pub fn options(&self)->D<Option<&OptionsDesk>>{self.ready()?;Ok(self.state.options.as_ref())}
 /// Accept combo takes (journaled once; options must be on): one signed `IntentV7` with
 /// up to `options::MAX_LEGS` legs in one asset fills all-or-none in one option batch,
 /// margined on the account's whole option payoff. Returns `false` if already on.
 pub fn enable_combos(&mut self)->D<bool>{
  self.ready()?;if self.state.options.as_ref().is_some_and(|d|d.combos){return Ok(false)}
  self.record(Event::EnableCombos)?;Ok(true)
 }
 /// Switch on the option acknowledgement round (journaled `EnableOptionAcks`, once;
 /// options must be on). Every option trade or expiry batch is then staged and commits
 /// only when the owner, peer and monitor of every lane with a clearing row sign that
 /// lane's V4 message (`option_ack_message`); one batch is staged at a time and other
 /// option events return `Hold` meanwhile. Returns `false` if already on.
 pub fn enable_option_acks(&mut self)->D<bool>{
  self.ready()?;if self.state.option_acks{return Ok(false)}
  self.record(Event::EnableOptionAcks)?;Ok(true)
 }
 pub fn option_acks_active(&self)->D<bool>{self.ready()?;Ok(self.state.option_acks)}
 /// The staged option batch awaiting acknowledgement.
 pub fn pending_option(&self)->D<Option<&OptionBatch>>{self.ready()?;Ok(self.state.pending_option.as_ref().map(|p|&p.batch))}
 /// When the staged batch was staged (desk clock); a FencedAbort is allowed `ABORT_AFTER_US` later.
 pub fn pending_option_since(&self)->D<Option<u64>>{self.ready()?;Ok(self.state.pending_option.as_ref().map(|p|p.staged_us))}
 /// V4 message `channel` signs for the staged option batch.
 pub fn option_ack_message(&self,disposition:Disposition,channel:&BtcOutPoint)->D<Key>{
  self.ready()?;
  let p=self.state.pending_option.as_ref().ok_or(TierReject::UnknownOrder)?;
  Ok(option_ack_message(&self.state.config,&p.batch,disposition,channel).map_err(TierReject::from)?)
 }
 /// Commit (all three signatures per lane) or, `ABORT_AFTER_US` after staging, fence-abort
 /// (peer and monitor) the staged option batch. An abort keeps the taker's sequence used
 /// and pulls the makers' quotes.
 pub fn resolve_option(&mut self,bundle:OptionAckBundle,now:u64)->D<bool>{
  match self.record(Event::ResolveOption{bundle,now})?{Reply::Resolved(x)=>Ok(x),_=>unreachable!()}
 }
 /// Register a stablecoin settlement asset (journaled `RegisterStable`, once per asset;
 /// options must be on): `SettleAsset::Stable{protocol, id, decimals}` with decimals in
 /// 6..=18. Opens the asset's clearing pool; puts may then list in it.
 pub fn register_stable(&mut self,asset:SettleAsset)->D<()>{self.record(Event::RegisterStable{asset}).map(|_|())}
 /// Credit `units` of a registered stablecoin. The TAP/RGB transfer is the simulated
 /// adapter's: nothing here verifies a Taproot Assets proof or an RGB consignment.
 pub fn deposit_stable(&mut self,channel:BtcOutPoint,asset:SettleAsset,units:u64)->D<()>{
  self.record(Event::StableTransfer{channel,asset,units,deposit:true}).map(|_|())
 }
 /// Debit `units` of free stablecoin collateral (a withdrawal through the adapter).
 pub fn withdraw_stable(&mut self,channel:BtcOutPoint,asset:SettleAsset,units:u64)->D<()>{
  self.record(Event::StableTransfer{channel,asset,units,deposit:false}).map(|_|())
 }
 /// List an option series; returns its id (`Series::id`).
 pub fn list_series(&mut self,series:Series,announcement:OracleAnnouncement)->D<Key>{
  match self.record(Event::ListSeries{series,announcement})?{Reply::Key(k)=>Ok(k),_=>unreachable!()}
 }
 /// Move `sats` from the channel's perpetual allocation into its options sub-account.
 pub fn fund_options(&mut self,channel:BtcOutPoint,sats:u64)->D<()>{self.record(Event::FundOptions{channel,sats,to_options:true}).map(|_|())}
 /// Move `sats` of free option collateral back to the perpetual allocation.
 pub fn defund_options(&mut self,channel:BtcOutPoint,sats:u64)->D<()>{self.record(Event::FundOptions{channel,sats,to_options:false}).map(|_|())}
 pub fn submit_option(&mut self,intent:IntentV7,now:u64)->D<OptionOutcome>{
  match self.record(Event::SubmitOption{intent,now})?{Reply::Option(x)=>Ok(x),_=>unreachable!()}
 }
 /// Expire a series at the oracle's attestation (one option batch through clearing).
 /// Void every open series on `event_id` on the oracle's unattestable notice (BIP340 by
 /// the options oracle key over `options::unattestable_message(event_id)`): legs return to
 /// their pre-trade positions with no payoff, premiums stay paid, collateral is freed. One
 /// option batch (`OptionBatchKind::Expiry` with `price_usd == 0`, `is_void()`), staged for acks like an expiry when acks are on.
 pub fn void_event(&mut self,event_id:String,notice:Bip340Signature)->D<OptionBatch>{
  match self.record(Event::VoidUnattestable{event_id,notice})?{Reply::OptionBatch(x)=>Ok(*x),_=>unreachable!()}
 }
 /// Let expiry and void batches commit on peer and monitor signatures with the owner
 /// signature optional (journaled `EnableOwnerlessExpiry`, once). Trade batches keep
 /// needing every owner. Returns `false` if already on.
 pub fn enable_ownerless_expiry(&mut self)->D<bool>{
  self.ready()?;if self.state.ownerless_expiry{return Ok(false)}
  self.record(Event::EnableOwnerlessExpiry)?;Ok(true)
 }
 pub fn ownerless_expiry_active(&self)->D<bool>{self.ready()?;Ok(self.state.ownerless_expiry)}
 pub fn expire_series(&mut self,series:Key,attestation:OracleAttestation)->D<OptionBatch>{
  match self.record(Event::ExpireSeries{series,attestation})?{Reply::OptionBatch(x)=>Ok(*x),_=>unreachable!()}
 }
 pub fn closing_loans_active(&self)->D<bool>{self.ready()?;Ok(self.state.router.close_from_lots())}
 /// The clearing ledger: pool cash, fund, carried deficit, deferred claims.
 pub fn clearing_state(&self)->D<Option<&ClearingState>>{self.ready()?;Ok(self.state.clearing.as_ref())}
 /// Ledger totals and the clearing identity (`identity == 0`) against the open book.
 pub fn clearing_summary(&self)->D<Option<clearing::Summary>>{
  self.ready()?;
  let book=self.state.router.account_books().map(|(_,p,_)|p.book_value()).sum();
  Ok(self.state.clearing.as_ref().map(|c|c.summary(book)))
 }
 /// Multilateral net settlement of batch `sequence` (committed with clearing active):
 /// one row per account, shortfall, waterfall layer and pool totals.
 pub fn clearing(&self,sequence:u64)->D<Option<&BatchClearing>>{self.ready()?;Ok(self.state.batches.get(&sequence).and_then(|e|e.clearing.as_ref()))}
 /// Net settlement a Commit of batch `sequence` would apply: the prepared batch at the head
 /// of the resolution queue, with clearing active. A channel adapter moves each row's `net`
 /// on its lane before the lanes sign the V3 acknowledgement, which binds the same rows.
 /// `None` for any other batch.
 pub fn planned_clearing(&self,sequence:u64)->D<Option<BatchClearing>>{
  self.ready()?;
  let Some(e)=self.state.batches.get(&sequence) else{return Ok(None)};
  if sequence!=self.state.next_resolution||e.phase!=Phase::Prepared{return Ok(None)}
  Ok(self.state.plan_clearing(&e.batch,Disposition::Commit).map_err(TierReject::from)?.map(|p|p.report))
 }
 pub fn position(&self,channel:&BtcOutPoint)->D<Option<Position>>{self.ready()?;Ok(self.state.router.account_position(&op(channel)))}
 /// Per-lane settlements applied when batch `sequence` committed, including those rebuilt
 /// when margin release was switched on. Empty without margin release.
 pub fn settlements(&self,sequence:u64)->D<&[(BtcOutPoint,Settlement)]>{
  self.ready()?;Ok(self.state.batches.get(&sequence).map(|e|e.settlements.as_slice()).unwrap_or(&[]))
 }
 /// Crash-testing hook: journal and fsync a process step without applying it, as if the
 /// process died between the append and the in-memory update. The writer is poisoned
 /// afterwards (memory is stale); reopen replays the step.
 #[doc(hidden)]
 pub fn append_process_without_apply(&mut self,now:u64)->D<()>{self.append(&Event::Process{now})?;self.poisoned=true;Ok(())}
}
