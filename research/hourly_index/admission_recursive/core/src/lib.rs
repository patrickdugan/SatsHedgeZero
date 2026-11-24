//! ADMIT-07: exact state commitments and balanced recursive composition.
//! Successful structural history proofs do not authenticate provider reports or seals.
#![forbid(unsafe_code)]
pub mod state;
use serde::{Deserialize, Serialize};
pub use state::*;
pub const MAX_HEIGHT:u8=6;
pub const MAX_SEGMENT_FOLDS:u64=8192;
pub const MAX_SEGMENT_REPORTS:usize=4096;
pub const MAGIC:&[u8;8]=b"SHZAGG01";
pub const JOURNAL_LEN:usize=8+32+32+1+1+32+32+1+8*6+32*2; // 251 bytes
pub const RELATION:&str="shz/ordered-admission-stark-composition/v1/depth18";

// The outer verifier pins image_id to the approved guest. Every child must carry
// the identical context; the guest verifies child receipts under this same ID.
// Height strictly decreases at each recursion edge, avoiding self-reference.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {pub genesis:[u8;32],pub policy:[u8;32],pub source:u8,pub snapshot_pin:[u8;32],pub image_id:[u32;8]}
impl Context {
 pub fn from_claim(c:&Claim,image_id:[u32;8])->Result<Self,String>{
  c.validate()?;let(genesis,source)=c.header.context()?;
  let out=Self{genesis,policy:policy_digest(),source,snapshot_pin:parse_digest(&c.pin)?,image_id};out.validate()?;Ok(out)
 }
 pub fn validate(&self)->Result<(),String>{
  if self.policy!=policy_digest()||!matches!(self.source,1|2)||self.image_id==[0;8]{return Err("invalid policy, source or image".into())}Ok(())
 }
 fn encode(&self,b:&mut Vec<u8>){b.extend(self.genesis);b.extend(self.policy);b.extend([self.source,DEPTH as u8]);b.extend(self.snapshot_pin);for w in self.image_id{b.extend(w.to_le_bytes());}}
}

/// Canonical fixed-width commitment to EVERY frontier coordinate, not merely
/// its root. Idle and pending forms both have unique encodings; segment cuts are idle.
pub fn state_digest(c:&Context,s:&State)->Result<[u8;32],String>{
 c.validate()?;s.validate()?;
 let mut b=b"SHZ/ADMIT/STATE/V1".to_vec();c.encode(&mut b);
 for v in [s.operations,s.leaf_count,s.last_time,s.sealed_through]{b.extend(v.to_le_bytes());}
 b.extend([u8::from(s.pending),s.level]);b.extend(s.carry.min.to_le_bytes());b.extend(s.carry.digest);
 for f in &s.frontier{b.push(u8::from(f.occupied));b.extend(f.min.to_le_bytes());b.extend(f.digest);}
 Ok(hash(&b))
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Journal {pub ctx:Context,pub height:u8,pub start_op:u64,pub end_op:u64,pub start_reports:u64,pub end_reports:u64,pub start_seal:u64,pub end_seal:u64,pub start:[u8;32],pub end:[u8;32]}
impl Journal {
 pub fn validate(&self)->Result<(),String>{
  self.ctx.validate()?;
  if self.height>MAX_HEIGHT||self.end_op>MAX_STEPS as u64||self.start_op>=self.end_op||self.end_op-self.start_op<(1u64<<self.height)||self.start_reports>self.end_reports||self.end_reports>=CAP||self.start_seal>self.end_seal||self.end_seal==u64::MAX{return Err("invalid journal range".into())}
  Ok(())
 }
 pub fn from_states(ctx:Context,height:u8,a:&State,b:&State)->Result<Self,String>{
  a.validate()?;b.validate()?;if a.pending||b.pending{return Err("pending boundary".into())}
  let out=Self{start:state_digest(&ctx,a)?,end:state_digest(&ctx,b)?,ctx,height,start_op:a.operations,end_op:b.operations,start_reports:a.leaf_count-1,end_reports:b.leaf_count-1,start_seal:a.sealed_through,end_seal:b.sealed_through};out.validate()?;Ok(out)
 }
 pub fn encode(&self)->Result<Vec<u8>,String>{
  self.validate()?;let mut b=MAGIC.to_vec();self.ctx.encode(&mut b);b.push(self.height);
  for v in [self.start_op,self.end_op,self.start_reports,self.end_reports,self.start_seal,self.end_seal]{b.extend(v.to_le_bytes());}
  b.extend(self.start);b.extend(self.end);debug_assert_eq!(b.len(),JOURNAL_LEN);Ok(b)
 }
 pub fn decode(raw:&[u8])->Result<Self,String>{
  if raw.len()!=JOURNAL_LEN||&raw[..8]!=MAGIC{return Err("journal framing".into())}
  let mut pos=8;
  fn take<const N:usize>(b:&[u8],p:&mut usize)->[u8;N]{let r=b[*p..*p+N].try_into().unwrap();*p+=N;r}
  let genesis=take::<32>(raw,&mut pos);let policy=take::<32>(raw,&mut pos);
  let [source,depth]=take::<2>(raw,&mut pos);if depth!=DEPTH as u8{return Err("journal depth".into())}
  let snapshot_pin=take::<32>(raw,&mut pos);let mut image_id=[0;8];for w in &mut image_id{*w=u32::from_le_bytes(take::<4>(raw,&mut pos));}
  let [height]=take::<1>(raw,&mut pos);
  let [start_op,end_op,start_reports,end_reports,start_seal,end_seal]=std::array::from_fn(|_|u64::from_le_bytes(take::<8>(raw,&mut pos)));
  let start=take::<32>(raw,&mut pos);let end=take::<32>(raw,&mut pos);
  let j=Self{ctx:Context{genesis,policy,source,snapshot_pin,image_id},height,start_op,end_op,start_reports,end_reports,start_seal,end_seal,start,end};j.validate()?;Ok(j)
 }
}
/// The guest calls this only after receiving the actual child-journal bytes.
/// Caller MUST cryptographically verify both child receipts under ctx.image_id.
/// This function alone is a relation checker, not proof verification.
pub fn join(left:&Journal,right:&Journal)->Result<Journal,String>{
 left.validate()?;right.validate()?;
 if left.ctx!=right.ctx||left.height!=right.height||left.height>=MAX_HEIGHT||left.end_op!=right.start_op||left.end_reports!=right.start_reports||left.end_seal!=right.start_seal||left.end!=right.start{return Err("disconnected or unequal-height child proofs".into())}
 let out=Journal{ctx:left.ctx.clone(),height:left.height+1,start_op:left.start_op,end_op:right.end_op,start_reports:left.start_reports,end_reports:right.end_reports,start_seal:left.start_seal,end_seal:right.end_seal,start:left.start,end:right.end};out.validate()?;Ok(out)
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafInput {pub ctx:Context,pub before:State,pub records:Vec<Record>,pub seal:Option<u64>}
#[derive(Clone,Debug,Serialize,Deserialize)]
pub enum Input {Leaf(LeafInput),Join{left:Vec<u8>,right:Vec<u8>}}

/// Prove actual normalized reports and required merges in the guest, rather
/// than replaying a native verifier receipt. This is a second proof backend for
/// the original structural relation; it does not wrap Nova proof bytes.
pub fn execute_leaf(w:&LeafInput)->Result<(State,Journal),String>{
 w.ctx.validate()?;w.before.validate()?;
 if w.before.pending||w.records.len()>MAX_SEGMENT_REPORTS{return Err("leaf cut or report budget".into())}
 let mut cur=w.before.clone();
 for r in &w.records {
  cur=advance(&cur,&Action{op:Op::Append,record:r.clone(),watermark:0})?;
  while cur.pending{cur=advance(&cur,&Action{op:Op::Carry,record:Record::default(),watermark:0})?;}
  if cur.operations-w.before.operations>MAX_SEGMENT_FOLDS{return Err("leaf fold budget".into())}
 }
 if let Some(seal)=w.seal{cur=advance(&cur,&Action::seal(seal))?;}
 if cur.operations-w.before.operations>MAX_SEGMENT_FOLDS{return Err("leaf fold budget".into())}
 let j=Journal::from_states(w.ctx.clone(),0,&w.before,&cur)?;Ok((cur,j))
}
/// Receiver-owned expected endpoint, image and balanced segment count. It is
/// independent of the root proof and every prover-provided intermediate state.
pub fn expected_root(c:&Claim,image_id:[u32;8],segments:usize)->Result<Journal,String>{
 if segments==0||segments>1usize<<MAX_HEIGHT||!segments.is_power_of_two(){return Err("balanced segment count".into())}
 Journal::from_states(Context::from_claim(c,image_id)?,segments.trailing_zeros() as u8,&State::initial(),&c.final_state)
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Segment{pub index:usize,pub folds:usize,pub before:State,pub after:State}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan{pub schema:String,pub relation:String,pub snapshot_pin:String,pub segments:Vec<Segment>}
pub const BASE_US:u64=1_792_800_000_000_000;
pub const PERIOD_US:u64=200_000;
pub fn synthetic_record(source:u8,i:u64)->Result<Record,String>{
 if i==0||i>=CAP||!matches!(source,1|2){return Err("synthetic ordinal".into())}
 let mut preimage=b"SHZ/ADMIT/SCALE/V1".to_vec();preimage.push(source);preimage.extend(i.to_le_bytes());
 Ok(Record{price_e8:10_000_000_000_000+(i%10_001)*10_000+u64::from(source-1)*20_000_000_000,publish_us:BASE_US+i*PERIOD_US,report_hash:hash(&preimage)})
}
/// Test-only harness: use frozen independent JS ADMIT-06 plans, reproduce each
/// exact transition and reject mismatched states before spending proving time.
pub fn benchmark_inputs(plan:&Plan,c:&Claim,image_id:[u32;8])->Result<Vec<LeafInput>,String>{
 let expected=expected_root(c,image_id,plan.segments.len())?;let ctx=expected.ctx;
 if plan.schema!="shz/admission-segment-plan/v1"||plan.relation!="shz/ordered-admission-frontier-nova/v4-packed-state/depth18"||plan.snapshot_pin!=c.pin{return Err("plan context".into())}
 let mut prior=State::initial();let mut leaves=vec![];
 for(i,s)in plan.segments.iter().enumerate(){
  if s.index!=i||s.before!=prior{return Err("plan boundary".into())}
  s.before.validate()?;s.after.validate()?;
  let last=i+1==plan.segments.len();
  if s.before.pending||s.after.pending||s.before.sealed_through!=0||s.after.sealed_through!=(if last{c.header.sealed_through}else{0})||s.after.leaf_count<s.before.leaf_count{return Err("plan cut or seal".into())}
  let n=s.after.leaf_count-s.before.leaf_count;
  if n>MAX_SEGMENT_REPORTS as u64||s.folds==0||s.folds as u64>MAX_SEGMENT_FOLDS{return Err("benchmark segment budget".into())}
  let records=(s.before.leaf_count..s.after.leaf_count).map(|i|synthetic_record(ctx.source,i)).collect::<Result<Vec<_>,_>>()?;
  let input=LeafInput{ctx:ctx.clone(),before:s.before.clone(),records,seal:if last{Some(c.header.sealed_through)}else{None}};
  let(end,j)=execute_leaf(&input)?;
  if end!=s.after||j.end_op-j.start_op!=s.folds as u64{return Err("plan replay mismatch".into())}
  prior=end;leaves.push(input);
 }
 if prior!=c.final_state{return Err("plan terminal".into())}Ok(leaves)
}
