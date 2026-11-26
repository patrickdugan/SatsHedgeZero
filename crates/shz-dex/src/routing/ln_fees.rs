//! HFT-06 recipient-specific Lightning fee obligation ledger.
//!
//! The ledger is fed by sealed HFT-03 `Batch`es (accrual) and by authenticated
//! HFT-05 resolutions read back from the `DurableRouter` (commit or reversal).
//! Collection is recorded only when a `LightningAdapter` verifies a `FeeReceipt`.
//!
//! Four quantities are tracked per recipient and never conflated:
//! `accrued` (every sealed obligation), `committed` (after an authenticated Commit),
//! `collected` (verified receipts) and `outstanding = committed - collected`.
//! Accrued-only obligations are not revenue, and reversed batches are never instructed.
//!
//! The ledger has no handle to channel balances: nothing here can release matched
//! collateral, and the passage of time alone never changes state except for the
//! optional emission of `SettlementInstruction`s for already-committed obligations.
//! DLC settlement carries no fee field; `DLC_SETTLEMENT_FEE_SATS` is zero and every
//! observed leg must carry the zero DLC fee policy.
use super::*;
use super::durable::{AckBundle,Disposition,DurableError,DurableRouter,Phase};
use super::tiered_durable::{DurableTieredRouter,TieredDurableError};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::{self,Read,Write},path::Path};
use thiserror::Error;

pub const DLC_SETTLEMENT_FEE_SATS:u64=0;
const MAGIC:&[u8;8]=b"SHZFEE06";
const MAX_FRAME:usize=1<<20;
/// `(router id, batch sequence)`.
pub type BatchRef=(u32,u64);

#[derive(Debug,Error)]
pub enum LedgerError{
 #[error("ledger I/O: {0}")] Io(#[from] io::Error),
 #[error("ledger file locked")] Locked,
 #[error("corrupt or torn ledger journal")] Corrupt,
 #[error("journal configuration mismatch")] Config,
 #[error("writer poisoned after failed persistence; reopen")] Poisoned,
 #[error("invalid recipient policy or group commit bounds")] Policy,
 #[error("unknown batch")] UnknownBatch,
 #[error("batch conflicts with recorded obligation")] BatchMismatch,
 #[error("resolution is not the one recorded by the durable router")] BadResolution,
 #[error("invalid state transition")] InvalidTransition,
 #[error("receipt conflicts with a previous receipt for the same payment hash")] ConflictingReceipt,
 #[error("receipt malformed or references uncommitted batches")] BadReceipt,
 #[error("receipt exceeds the recipient's outstanding amount")] Overpayment,
 #[error("amount overflow")] Overflow,
 #[error("adapter: {0}")] Adapter(#[from] AdapterError),
 #[error("durable router: {0}")] Router(String),
}
impl From<DurableError> for LedgerError{fn from(e:DurableError)->Self{Self::Router(e.to_string())}}
type L<X>=Result<X,LedgerError>;

/// Read-only view of a router that authenticates batch resolutions. Implemented by the
/// HFT-05 `DurableRouter` and the HFT-06 `DurableTieredRouter`; the ledger trusts only
/// what this view reports from the router's own journal.
pub trait ResolutionSource{
 type Error:std::fmt::Display;
 fn batch(&self,sequence:u64)->Result<Option<(&Batch,Phase)>,Self::Error>;
 fn acknowledgement(&self,sequence:u64)->Result<Option<&AckBundle>,Self::Error>;
 fn fee_totals(&self)->Result<(u128,u128),Self::Error>;
 fn next_resolution(&self)->Result<u64,Self::Error>;
}
impl ResolutionSource for DurableRouter{
 type Error=DurableError;
 fn batch(&self,s:u64)->Result<Option<(&Batch,Phase)>,DurableError>{DurableRouter::batch(self,s)}
 fn acknowledgement(&self,s:u64)->Result<Option<&AckBundle>,DurableError>{DurableRouter::acknowledgement(self,s)}
 fn fee_totals(&self)->Result<(u128,u128),DurableError>{DurableRouter::fee_totals(self)}
 fn next_resolution(&self)->Result<u64,DurableError>{DurableRouter::next_resolution(self)}
}
impl ResolutionSource for DurableTieredRouter{
 type Error=TieredDurableError;
 fn batch(&self,s:u64)->Result<Option<(&Batch,Phase)>,TieredDurableError>{DurableTieredRouter::batch(self,s)}
 fn acknowledgement(&self,s:u64)->Result<Option<&AckBundle>,TieredDurableError>{DurableTieredRouter::acknowledgement(self,s)}
 fn fee_totals(&self)->Result<(u128,u128),TieredDurableError>{DurableTieredRouter::fee_totals(self)}
 fn next_resolution(&self)->Result<u64,TieredDurableError>{DurableTieredRouter::next_resolution(self)}
}
fn src<X,E:std::fmt::Display>(r:Result<X,E>)->L<X>{r.map_err(|e|LedgerError::Router(e.to_string()))}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct RecipientPolicy{
 pub version:u32,
 /// `(payout key, weight)`; weights must be positive, keys unique.
 pub oracle_operators:Vec<(Key,u32)>,
 /// `(upkeep payout key, basis points of the oracle share)`.
 pub upkeep:(Key,u64),
 pub router:Key,
}
/// Deterministic split of one batch's dues.
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Split{pub upkeep:(Key,u64),pub operators:Vec<(Key,u64)>,pub router:(Key,u64)}
impl Split{
 /// Per-recipient totals (a key playing several roles is summed).
 pub fn shares(&self)->BTreeMap<Key,u64>{
  let mut m=BTreeMap::new();
  for (k,v) in std::iter::once(&self.upkeep).chain(&self.operators).chain(std::iter::once(&self.router)){
   if *v>0{*m.entry(*k).or_insert(0u64)+=*v;}
  }
  m
 }
}
impl RecipientPolicy{
 pub fn validate(&self)->L<()>{
  let keys:BTreeSet<_>=self.oracle_operators.iter().map(|o|o.0).collect();
  if self.oracle_operators.is_empty()||keys.len()!=self.oracle_operators.len()||
     self.oracle_operators.iter().any(|o|o.1==0||o.0==[0;32])||self.upkeep.0==[0;32]||self.router==[0;32]||
     self.upkeep.1>10_000||self.version==0{return Err(LedgerError::Policy)}
  Ok(())
 }
 pub fn id(&self)->Key{
  let mut b=Vec::new();u32b(&mut b,self.version);u64b(&mut b,self.oracle_operators.len()as u64);
  for (k,w) in &self.oracle_operators{b.extend(k);u32b(&mut b,*w)}
  b.extend(self.upkeep.0);u64b(&mut b,self.upkeep.1);b.extend(self.router);
  tagged_hash(b"SHZ/HFT06/RECIPIENT-POLICY/V1",&b)
 }
 /// Upkeep takes `floor(oracle*bps/10000)`. The remainder is divided by weight with
 /// largest-remainder rounding, ties broken by ascending key. Sum equals the inputs.
 pub fn split(&self,oracle_due:u64,router_due:u64)->Split{
  let upkeep=(oracle_due as u128*self.upkeep.1 as u128/10_000)as u64;
  let rem=oracle_due-upkeep;
  let total_w:u128=self.oracle_operators.iter().map(|o|o.1 as u128).sum();
  let mut ops:Vec<(Key,u64,u128)>=self.oracle_operators.iter().map(|(k,w)|{
   let num=rem as u128*(*w as u128);(*k,(num/total_w)as u64,num%total_w)}).collect();
  let leftover=rem-ops.iter().map(|o|o.1).sum::<u64>();
  let mut order:Vec<usize>=(0..ops.len()).collect();
  order.sort_by(|&a,&b|ops[b].2.cmp(&ops[a].2).then(ops[a].0.cmp(&ops[b].0)));
  for &i in order.iter().take(leftover as usize){ops[i].1+=1}
  Split{upkeep:(self.upkeep.0,upkeep),operators:ops.into_iter().map(|o|(o.0,o.1)).collect(),router:(self.router,router_due)}
 }
}

#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct GroupCommit{pub max_obligations:usize,pub max_delay_us:u64}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct SettlementInstruction{pub recipient:Key,pub amount_sats:u64,pub batch_refs:Vec<BatchRef>}

/// Payment evidence for fees. `signature` is a synthetic recipient attestation used
/// by `MockAdapter`; a production adapter verifies real LN payment proofs instead.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct FeeReceipt{
 pub recipient:Key,pub amount_msat:u64,pub payment_hash:Key,pub preimage:Key,pub batch_refs:Vec<BatchRef>,
 pub signature:Bip340Signature,
}
impl FeeReceipt{
 pub fn digest(&self)->Key{
  let mut b=Vec::new();b.extend(self.recipient);u64b(&mut b,self.amount_msat);b.extend(self.payment_hash);b.extend(self.preimage);
  u64b(&mut b,self.batch_refs.len()as u64);for (r,s) in &self.batch_refs{u32b(&mut b,*r);u64b(&mut b,*s)}
  tagged_hash(b"SHZ/HFT06/FEE-RECEIPT/V1",&b)
 }
 pub fn signed(mut self,sk:&Key)->L<Self>{
  self.signature=bip340_sign(sk,&self.digest()).map_err(|_|LedgerError::BadReceipt)?;Ok(self)
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct VerifiedReceipt{pub recipient:Key,pub amount_msat:u64,pub payment_hash:Key}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Error)]
pub enum AdapterError{
 #[error("peer disconnected")] Disconnected,
 #[error("unknown channel or payment")] Unknown,
 #[error("invalid proof")] Invalid,
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum ChannelStatus{Open{commitment:u64},Closed}
/// Boundary to real Lightning. Everything behind it (LDK commitment updates, real
/// payment proof verification) is an external gate; the ledger trusts only a
/// `VerifiedReceipt` returned here.
pub trait LightningAdapter{
 fn verify_fee_receipt(&self,r:&FeeReceipt)->Result<VerifiedReceipt,AdapterError>;
 fn commitment_status(&self,channel:&BtcOutPoint)->Result<ChannelStatus,AdapterError>;
}
/// Synthetic adapter: `sha256(preimage)==payment_hash` and a BIP340 signature by the
/// recipient over the receipt digest.
#[derive(Debug,Clone)]
pub struct MockAdapter{connected:bool,channels:BTreeMap<Outpoint,ChannelStatus>}
impl MockAdapter{
 pub fn new()->Self{Self{connected:true,channels:BTreeMap::new()}}
 pub fn set_connected(&mut self,on:bool){self.connected=on}
 pub fn set_channel(&mut self,c:&BtcOutPoint,s:ChannelStatus){self.channels.insert(op(c),s);}
 pub fn payment_hash(preimage:&Key)->Key{Sha256::digest(preimage).into()}
}

impl Default for MockAdapter {
    fn default() -> Self {
        Self::new()
    }
}
impl LightningAdapter for MockAdapter{
 fn verify_fee_receipt(&self,r:&FeeReceipt)->Result<VerifiedReceipt,AdapterError>{
  if !self.connected{return Err(AdapterError::Disconnected)}
  if Self::payment_hash(&r.preimage)!=r.payment_hash{return Err(AdapterError::Invalid)}
  if r.signature.s>=SECP_ORDER||bip340_verify(&r.recipient,&r.digest(),&r.signature).is_err(){return Err(AdapterError::Invalid)}
  Ok(VerifiedReceipt{recipient:r.recipient,amount_msat:r.amount_msat,payment_hash:r.payment_hash})
 }
 fn commitment_status(&self,c:&BtcOutPoint)->Result<ChannelStatus,AdapterError>{
  if !self.connected{return Err(AdapterError::Disconnected)}
  self.channels.get(&op(c)).copied().ok_or(AdapterError::Unknown)
 }
}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum BatchState{Accrued,Committed,Reversed}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Default)]
pub struct RecipientTotals{pub accrued:u64,pub reversed:u64,pub committed:u64,pub collected:u64,pub outstanding:u64}
impl RecipientTotals{
 /// Accrued obligations whose resolution has not been observed.
 pub fn unresolved(&self)->u64{self.accrued-self.committed-self.reversed}
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub enum LedgerEvent{
 Accrue{sequence:u64,digest:Key,oracle_due:u64,router_due:u64},
 Commit{sequence:u64,digest:Key,fee_evidence:Vec<(BtcOutPoint,Key)>,at_us:u64},
 Reverse{sequence:u64,digest:Key},
 Collect{receipt:FeeReceipt},
 Instruct{at_us:u64,sequences:Vec<u64>},
}
#[derive(Debug,Clone,PartialEq,Eq)]
enum St{Accrued,Committed{at_us:u64,fee_evidence:Vec<(BtcOutPoint,Key)>},Reversed}
#[derive(Debug,Clone)]
struct Rec{digest:Key,oracle:u64,router:u64,shares:BTreeMap<Key,u64>,state:St,instructed:bool,collected:BTreeMap<Key,u64>}
impl Rec{
 fn outstanding(&self,k:&Key)->u64{self.shares.get(k).copied().unwrap_or(0)-self.collected.get(k).copied().unwrap_or(0)}
}

struct State{
 router_id:u32,policy:RecipientPolicy,group:GroupCommit,
 batches:BTreeMap<u64,Rec>,receipts:BTreeMap<Key,FeeReceipt>,emissions:Vec<(u64,Vec<SettlementInstruction>)>,
}
impl State{
 fn pending_instruction(&self)->Vec<u64>{
  self.batches.iter().filter(|(_,r)|matches!(r.state,St::Committed{..})&&!r.instructed).map(|(s,_)|*s).collect()
 }
 fn instructions(&self,seqs:&[u64])->Vec<SettlementInstruction>{
  let mut by:BTreeMap<Key,(u64,Vec<BatchRef>)>=BTreeMap::new();
  for s in seqs{
   let r=&self.batches[s];
   for k in r.shares.keys(){
    let o=r.outstanding(k);
    if o>0{let e=by.entry(*k).or_default();e.0+=o;e.1.push((self.router_id,*s));}
   }
  }
  by.into_iter().map(|(recipient,(amount_sats,batch_refs))|SettlementInstruction{recipient,amount_sats,batch_refs}).collect()
 }
 /// Validates fully, then mutates unless `dry`. `Ok(false)` is an idempotent no-op.
 fn apply(&mut self,e:&LedgerEvent,dry:bool)->L<bool>{
  match e{
   LedgerEvent::Accrue{sequence,digest,oracle_due,router_due}=>{
    if let Some(r)=self.batches.get(sequence){
     return if r.digest==*digest&&r.oracle==*oracle_due&&r.router==*router_due{Ok(false)}else{Err(LedgerError::BatchMismatch)}
    }
    if *sequence==0{return Err(LedgerError::BatchMismatch)}
    if dry{return Ok(true)}
    let shares=self.policy.split(*oracle_due,*router_due).shares();
    self.batches.insert(*sequence,Rec{digest:*digest,oracle:*oracle_due,router:*router_due,shares,state:St::Accrued,instructed:false,collected:BTreeMap::new()});
    Ok(true)
   },
   LedgerEvent::Commit{sequence,digest,fee_evidence,at_us}=>{
    let r=self.batches.get_mut(sequence).ok_or(LedgerError::UnknownBatch)?;
    if r.digest!=*digest{return Err(LedgerError::BatchMismatch)}
    match &r.state{
     St::Committed{fee_evidence:old,..}=>return if old==fee_evidence{Ok(false)}else{Err(LedgerError::InvalidTransition)},
     St::Reversed=>return Err(LedgerError::InvalidTransition),
     St::Accrued=>{}
    }
    if dry{return Ok(true)}
    r.state=St::Committed{at_us:*at_us,fee_evidence:fee_evidence.clone()};Ok(true)
   },
   LedgerEvent::Reverse{sequence,digest}=>{
    let r=self.batches.get_mut(sequence).ok_or(LedgerError::UnknownBatch)?;
    if r.digest!=*digest{return Err(LedgerError::BatchMismatch)}
    match r.state{
     St::Reversed=>return Ok(false),
     St::Committed{..}=>return Err(LedgerError::InvalidTransition),
     St::Accrued=>{}
    }
    if dry{return Ok(true)}
    r.state=St::Reversed;Ok(true)
   },
   LedgerEvent::Collect{receipt}=>{
    if let Some(old)=self.receipts.get(&receipt.payment_hash){
     return if old==receipt{Ok(false)}else{Err(LedgerError::ConflictingReceipt)}
    }
    if receipt.batch_refs.is_empty()||receipt.amount_msat==0||receipt.amount_msat%1000!=0{return Err(LedgerError::BadReceipt)}
    let mut left=receipt.amount_msat/1000;
    let mut plan=Vec::new();let mut seen=BTreeSet::new();
    for (router,seq) in &receipt.batch_refs{
     if *router!=self.router_id||!seen.insert(*seq){return Err(LedgerError::BadReceipt)}
     let r=self.batches.get(seq).ok_or(LedgerError::UnknownBatch)?;
     if !matches!(r.state,St::Committed{..}){return Err(LedgerError::BadReceipt)}
     let take=left.min(r.outstanding(&receipt.recipient));
     if take>0{plan.push((*seq,take));left-=take;}
    }
    if left>0{return Err(LedgerError::Overpayment)}
    if dry{return Ok(true)}
    for (seq,take) in plan{*self.batches.get_mut(&seq).unwrap().collected.entry(receipt.recipient).or_insert(0)+=take;}
    self.receipts.insert(receipt.payment_hash,receipt.clone());Ok(true)
   },
   LedgerEvent::Instruct{at_us,sequences}=>{
    for s in sequences{
     let r=self.batches.get(s).ok_or(LedgerError::UnknownBatch)?;
     if !matches!(r.state,St::Committed{..})||r.instructed{return Err(LedgerError::InvalidTransition)}
    }
    if dry{return Ok(true)}
    let ins=self.instructions(sequences);
    for s in sequences{self.batches.get_mut(s).unwrap().instructed=true}
    self.emissions.push((*at_us,ins));Ok(true)
   },
  }
 }
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum Mismatch{
 OracleTotal{ledger:u128,router:u128},
 RouterTotal{ledger:u128,router:u128},
 Phase{sequence:u64,ledger:BatchState,router:Option<Phase>},
 MissingInLedger{sequence:u64},
 BatchDigest{sequence:u64},
 FeeEvidence{sequence:u64},
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct ReconcileReport{
 pub ledger_oracle:u128,pub ledger_router:u128,pub router_oracle:u128,pub router_router:u128,pub mismatches:Vec<Mismatch>,
}
impl ReconcileReport{pub fn clean(&self)->bool{self.mismatches.is_empty()}}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
struct Tip{records:u64,digest:Key}
fn frame_hash(prev:Tip,payload:&[u8])->Tip{
 let records=prev.records+1;
 let mut b=Vec::with_capacity(44+payload.len());b.extend(prev.digest);u64b(&mut b,records);u32b(&mut b,payload.len()as u32);b.extend(payload);
 Tip{records,digest:tagged_hash(b"SHZ/HFT06/FEE-WAL/V1",&b)}
}
fn frame_bytes(prev:Tip,payload:&[u8])->(Tip,Vec<u8>){
 let tip=frame_hash(prev,payload);
 let mut v=Vec::new();v.extend((payload.len()as u32).to_le_bytes());v.extend(payload);v.extend(tip.digest);(tip,v)
}
fn exact(f:&mut File,buf:&mut[u8])->L<()>{
 f.read_exact(buf).map_err(|e|if e.kind()==io::ErrorKind::UnexpectedEof{LedgerError::Corrupt}else{LedgerError::Io(e)})
}
fn read_frame(f:&mut File,prev:Tip)->L<Option<(Tip,Vec<u8>)>>{
 let mut len=[0u8;4];
 if f.read(&mut len[..1])? == 0 { return Ok(None) }
 exact(f,&mut len[1..])?;
 let n=u32::from_le_bytes(len)as usize;
 if n==0||n>MAX_FRAME{return Err(LedgerError::Corrupt)}
 let mut p=vec![0;n];exact(f,&mut p)?;
 let mut h=[0;32];exact(f,&mut h)?;
 let tip=frame_hash(prev,&p);
 if tip.digest!=h{return Err(LedgerError::Corrupt)}
 Ok(Some((tip,p)))
}
const ZERO_TIP:Tip=Tip{records:0,digest:[0;32]};

/// Append-only, hash-chained, fsynced ledger. A torn or altered tail fails closed.
/// The event is durable before it is applied; a persisted but unapplied event is
/// applied on reopen.
pub struct FeeLedger{state:State,file:Option<File>,tip:Tip,poisoned:bool}
impl FeeLedger{
 fn build(router_id:u32,policy:RecipientPolicy,group:GroupCommit)->L<(State,Key)>{
  policy.validate()?;
  if router_id==0||group.max_obligations==0{return Err(LedgerError::Policy)}
  let mut b=Vec::new();u32b(&mut b,router_id);b.extend(policy.id());u64b(&mut b,group.max_obligations as u64);u64b(&mut b,group.max_delay_us);
  let config=tagged_hash(b"SHZ/HFT06/FEE-CONFIG/V1",&b);
  Ok((State{router_id,policy,group,batches:BTreeMap::new(),receipts:BTreeMap::new(),emissions:Vec::new()},config))
 }
 pub fn in_memory(router_id:u32,policy:RecipientPolicy,group:GroupCommit)->L<Self>{
  Ok(Self{state:Self::build(router_id,policy,group)?.0,file:None,tip:ZERO_TIP,poisoned:false})
 }
 pub fn create(path:&Path,router_id:u32,policy:RecipientPolicy,group:GroupCommit)->L<Self>{
  let (state,config)=Self::build(router_id,policy,group)?;
  let mut file=OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
  file.try_lock().map_err(|_|LedgerError::Locked)?;
  file.write_all(MAGIC)?;
  let (tip,bytes)=frame_bytes(ZERO_TIP,&config);file.write_all(&bytes)?;file.sync_all()?;
  Ok(Self{state,file:Some(file),tip,poisoned:false})
 }
 pub fn open(path:&Path,router_id:u32,policy:RecipientPolicy,group:GroupCommit)->L<Self>{
  let (mut state,config)=Self::build(router_id,policy,group)?;
  let mut file=OpenOptions::new().read(true).write(true).open(path)?;
  file.try_lock().map_err(|_|LedgerError::Locked)?;
  let mut magic=[0;8];exact(&mut file,&mut magic)?;
  if &magic!=MAGIC{return Err(LedgerError::Corrupt)}
  let (mut tip,genesis)=read_frame(&mut file,ZERO_TIP)?.ok_or(LedgerError::Corrupt)?;
  if genesis.as_slice()!=config.as_slice(){return Err(LedgerError::Config)}
  while let Some((next,payload))=read_frame(&mut file,tip)?{
   let e:LedgerEvent=serde_json::from_slice(&payload).map_err(|_|LedgerError::Corrupt)?;
   state.apply(&e,false).map_err(|_|LedgerError::Corrupt)?;
   tip=next;
  }
  Ok(Self{state,file:Some(file),tip,poisoned:false})
 }
 fn persist(&mut self,e:&LedgerEvent)->L<()>{
  if self.poisoned{return Err(LedgerError::Poisoned)}
  let Some(file)=self.file.as_mut()else{return Ok(())};
  let data=serde_json::to_vec(e).map_err(|_|LedgerError::Corrupt)?;
  let (tip,bytes)=frame_bytes(self.tip,&data);
  if let Err(err)=file.write_all(&bytes).and_then(|_|file.sync_all()){self.poisoned=true;return Err(err.into())}
  self.tip=tip;Ok(())
 }
 /// Validate, fsync, then apply. Idempotent duplicates are no-ops and are not journaled.
 pub fn record(&mut self,e:LedgerEvent)->L<bool>{
  if self.poisoned{return Err(LedgerError::Poisoned)}
  if !self.state.apply(&e,true)?{return Ok(false)}
  self.persist(&e)?;
  self.state.apply(&e,false)
 }
 /// Crash-testing hook: journal and fsync an event without applying it, as if the
 /// process died between the append and the in-memory update. Reopen replays it.
 #[doc(hidden)]
 pub fn append_without_apply(&mut self,e:&LedgerEvent)->L<()>{self.state.apply(e,true)?;self.persist(e)}
 pub fn router_id(&self)->u32{self.state.router_id}
 pub fn policy(&self)->&RecipientPolicy{&self.state.policy}

 /// Record a sealed batch as accrued. Rejects non-zero DLC fee policy on any leg.
 pub fn observe_batch(&mut self,b:&Batch)->L<bool>{
  if b.router()!=self.state.router_id{return Err(LedgerError::BatchMismatch)}
  if b.legs().iter().any(|f|f.spec.fee_policy!=ZeroFeePolicy::ZERO){return Err(LedgerError::BatchMismatch)}
  let oracle_due=u64::try_from(b.oracle_due_sats()).map_err(|_|LedgerError::Overflow)?;
  let router_due=u64::try_from(b.router_due_sats()).map_err(|_|LedgerError::Overflow)?;
  oracle_due.checked_add(router_due).ok_or(LedgerError::Overflow)?;
  self.record(LedgerEvent::Accrue{sequence:b.sequence(),digest:b.digest(),oracle_due,router_due})
 }
 /// Apply an authenticated HFT-05 resolution. `bundle` must equal the bundle the
 /// durable router recorded for that sequence and the router phase must agree.
 pub fn observe_resolution<S:ResolutionSource>(&mut self,router:&S,bundle:&AckBundle,now_us:u64)->L<bool>{
  let recorded=src(router.acknowledgement(bundle.sequence))?.ok_or(LedgerError::BadResolution)?;
  if recorded!=bundle{return Err(LedgerError::BadResolution)}
  let (batch,phase)=src(router.batch(bundle.sequence))?.ok_or(LedgerError::UnknownBatch)?;
  if batch.digest()!=bundle.batch{return Err(LedgerError::BadResolution)}
  self.observe_batch(batch)?;
  match (bundle.disposition,phase){
   (Disposition::Commit,Phase::Committed)=>{
    let fee_evidence=bundle.channels.iter().filter(|c|c.fee_evidence!=[0;32]).map(|c|(c.channel.clone(),c.fee_evidence)).collect();
    self.record(LedgerEvent::Commit{sequence:bundle.sequence,digest:bundle.batch,fee_evidence,at_us:now_us})
   },
   (Disposition::FencedAbort,Phase::Aborted)=>self.record(LedgerEvent::Reverse{sequence:bundle.sequence,digest:bundle.batch}),
   _=>Err(LedgerError::BadResolution),
  }
 }
 /// Verify with the adapter and collect. Duplicate identical receipts are no-ops
 /// (even while disconnected), conflicting duplicates and overpayments are rejected,
 /// and a disconnected adapter leaves every obligation outstanding.
 pub fn receive_receipt(&mut self,adapter:&dyn LightningAdapter,r:&FeeReceipt)->L<bool>{
  if let Some(old)=self.state.receipts.get(&r.payment_hash){
   return if old==r{Ok(false)}else{Err(LedgerError::ConflictingReceipt)}
  }
  let v=adapter.verify_fee_receipt(r)?;
  if v.recipient!=r.recipient||v.amount_msat!=r.amount_msat||v.payment_hash!=r.payment_hash{return Err(AdapterError::Invalid.into())}
  self.record(LedgerEvent::Collect{receipt:r.clone()})
 }
 /// Emit instructions for committed-but-uninstructed obligations when either bound
 /// is reached: obligation count (batch x recipient) or age of the oldest commit.
 /// Accrued-only and reversed batches are never included. Returns the emission.
 pub fn poll(&mut self,now_us:u64)->L<Vec<SettlementInstruction>>{
  let pending=self.state.pending_instruction();
  if pending.is_empty(){return Ok(Vec::new())}
  let count:usize=pending.iter().map(|s|self.state.batches[s].shares.len()).sum();
  let oldest=pending.iter().filter_map(|s|match &self.state.batches[s].state{St::Committed{at_us,..}=>Some(*at_us),_=>None}).min().unwrap();
  if count<self.state.group.max_obligations&&now_us.saturating_sub(oldest)<self.state.group.max_delay_us{return Ok(Vec::new())}
  self.record(LedgerEvent::Instruct{at_us:now_us,sequences:pending})?;
  Ok(self.state.emissions.last().unwrap().1.clone())
 }
 /// Emission `index` as originally produced (also after a reopen).
 pub fn emission(&self,index:usize)->Option<&[SettlementInstruction]>{self.state.emissions.get(index).map(|e|e.1.as_slice())}
 pub fn emissions(&self)->usize{self.state.emissions.len()}
 pub fn batch_state(&self,sequence:u64)->Option<BatchState>{
  self.state.batches.get(&sequence).map(|r|match r.state{St::Accrued=>BatchState::Accrued,St::Committed{..}=>BatchState::Committed,St::Reversed=>BatchState::Reversed})
 }
 pub fn totals(&self,recipient:&Key)->RecipientTotals{self.all_totals().remove(recipient).unwrap_or_default()}
 pub fn all_totals(&self)->BTreeMap<Key,RecipientTotals>{
  let mut m:BTreeMap<Key,RecipientTotals>=BTreeMap::new();
  for r in self.state.batches.values(){
   for (k,v) in &r.shares{
    let t=m.entry(*k).or_default();t.accrued+=v;
    match r.state{
     St::Reversed=>t.reversed+=v,
     St::Committed{..}=>{t.committed+=v;t.collected+=r.collected.get(k).copied().unwrap_or(0);}
     St::Accrued=>{}
    }
   }
  }
  for t in m.values_mut(){t.outstanding=t.committed-t.collected}
  m
 }
 /// Committed totals by role `(oracle, router)`.
 pub fn committed_by_role(&self)->(u128,u128){
  self.state.batches.values().filter(|r|matches!(r.state,St::Committed{..}))
   .fold((0,0),|a,r|(a.0+r.oracle as u128,a.1+r.router as u128))
 }
 /// Channel commitment status for a batch's channels. Read-only; never changes state.
 pub fn check_channels(&self,adapter:&dyn LightningAdapter,batch:&Batch)->Vec<(BtcOutPoint,Result<ChannelStatus,AdapterError>)>{
  batch.accounts().iter().map(|a|(a.channel.clone(),adapter.commitment_status(&a.channel))).collect()
 }
 /// Compare against the durable router: committed totals per role, batch phases,
 /// digests, and the fee evidence of every committed channel.
 pub fn reconcile<S:ResolutionSource>(&self,router:&S)->L<ReconcileReport>{
  let (lo,lr)=self.committed_by_role();
  let (ro,rr)=src(router.fee_totals())?;
  let mut mm=Vec::new();
  if lo!=ro{mm.push(Mismatch::OracleTotal{ledger:lo,router:ro})}
  if lr!=rr{mm.push(Mismatch::RouterTotal{ledger:lr,router:rr})}
  for (seq,rec) in &self.state.batches{
   let got=src(router.batch(*seq))?;
   let state=match rec.state{St::Accrued=>BatchState::Accrued,St::Committed{..}=>BatchState::Committed,St::Reversed=>BatchState::Reversed};
   let Some((b,phase))=got else{mm.push(Mismatch::Phase{sequence:*seq,ledger:state,router:None});continue};
   if b.digest()!=rec.digest{mm.push(Mismatch::BatchDigest{sequence:*seq})}
   let ok=matches!((&rec.state,phase),(St::Accrued,Phase::Sealed|Phase::Prepared)|(St::Committed{..},Phase::Committed)|(St::Reversed,Phase::Aborted));
   if !ok{mm.push(Mismatch::Phase{sequence:*seq,ledger:state,router:Some(phase)})}
   if let St::Committed{fee_evidence,..}=&rec.state{
    let expect:Vec<_>=src(router.acknowledgement(*seq))?.map(|a|a.channels.iter().filter(|c|c.fee_evidence!=[0;32]).map(|c|(c.channel.clone(),c.fee_evidence)).collect()).unwrap_or_default();
    if *fee_evidence!=expect{mm.push(Mismatch::FeeEvidence{sequence:*seq})}
   }
  }
  for seq in 1..src(router.next_resolution())?{
   if !self.state.batches.contains_key(&seq){mm.push(Mismatch::MissingInLedger{sequence:seq})}
  }
  Ok(ReconcileReport{ledger_oracle:lo,ledger_router:lr,router_oracle:ro,router_router:rr,mismatches:mm})
 }
}
