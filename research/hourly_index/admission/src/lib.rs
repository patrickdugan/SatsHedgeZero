//! INDEX-ADMIT-02: shared SHA-256 opcode gadget for the binary-carry log.
//! Structural admission and monotone sealing only. Source authentication,
//! independently authorized watermarks and provider completeness are external.
#![forbid(unsafe_code)]
use ff::Field;
use nova_snark::frontend::gadgets::{boolean::{AllocatedBit,Boolean},num::AllocatedNum,sha256::{sha256,sha256_compression_function},uint32::UInt32};
use nova_snark::frontend::{ConstraintSystem,LinearCombination,SynthesisError};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::{Engine,circuit::StepCircuit};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
pub type F=<PallasEngine as Engine>::Scalar;
pub const DEPTH:usize=4;
pub const CAP:u64=1<<DEPTH;
pub const MAX_STEPS:usize=128;
pub const ARITY:usize=9+4*(DEPTH+1)+3;
const CONTEXT:usize=ARITY-3;
pub const RELATION:&str="shz/ordered-admission-frontier-nova/v2-shared-sha/depth4";
const MAX_PRICE:u64=10_000_000_000_000_000;
const LEAF:&[u8]=b"SHZ/LOG/LEAF/V2";
const EMPTY:&[u8]=b"SHZ/LOG/EMPTY/V2";
const NODE:&[u8]=b"SHZ/LOG/NODE/V2";
const SNAPSHOT:&[u8]=b"SHZ/LOG/SNAPSHOT/V2";
const POLICY:&[u8]=b"SHZ/DUAL-ORACLE-50BPS-5MIN/HOLD-NECESSITY/V2";
pub fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn f_le(bytes:&[u8])->F{bytes.iter().rev().fold(F::ZERO,|a,b|a*F::from(256)+F::from(*b as u64))}
fn limbs(h:&[u8;32])->[F;2]{[f_le(&h[..16]),f_le(&h[16..])]}
fn hex32(s:&str)->Result<[u8;32],String>{if s.len()!=64||!s.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()){return Err("noncanonical digest".into())}hex::decode(s).map_err(|_|"bad hex")?.try_into().map_err(|_|"digest length".into())}
mod decimal {
 use serde::{Deserialize,Deserializer,Serializer};
 pub fn serialize<S:Serializer>(v:&u64,s:S)->Result<S::Ok,S::Error>{s.serialize_str(&v.to_string())}
 pub fn deserialize<'de,D:Deserializer<'de>>(d:D)->Result<u64,D::Error>{let s=String::deserialize(d)?;let n=s.parse::<u64>().map_err(serde::de::Error::custom)?;if n.to_string()!=s{return Err(serde::de::Error::custom("noncanonical decimal"))}Ok(n)}
}
mod digest32 {
 use serde::{Deserialize,Deserializer,Serializer};
 pub fn serialize<S:Serializer>(v:&[u8;32],s:S)->Result<S::Ok,S::Error>{s.serialize_str(&hex::encode(v))}
 pub fn deserialize<'de,D:Deserializer<'de>>(d:D)->Result<[u8;32],D::Error>{super::hex32(&String::deserialize(d)?).map_err(serde::de::Error::custom)}
}
#[derive(Clone,Debug,Default,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Summary{#[serde(with="decimal")]pub min:u64,#[serde(with="digest32")]pub digest:[u8;32]}
impl Summary{fn bytes(&self)->Vec<u8>{let mut b=self.min.to_le_bytes().to_vec();b.extend(self.digest);b}}
#[derive(Clone,Debug,Default,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Slot{pub occupied:bool,#[serde(with="decimal")]pub min:u64,#[serde(with="digest32")]pub digest:[u8;32]}
impl Slot{fn summary(&self)->Summary{Summary{min:self.min,digest:self.digest}}fn occupied(s:&Summary)->Self{Self{occupied:true,min:s.min,digest:s.digest}}}
#[derive(Clone,Debug,Default,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Record{#[serde(with="decimal")]pub price_e8:u64,#[serde(with="decimal")]pub publish_us:u64,#[serde(with="digest32")]pub report_hash:[u8;32]}
impl Record{fn valid(&self)->bool{self.price_e8>0&&self.price_e8<=MAX_PRICE&&self.publish_us>0&&self.publish_us<u64::MAX&&self.report_hash!=[0;32]}}
fn leaf(r:&Record,present:bool)->Summary{let mut b=LEAF.to_vec();b.push(u8::from(present));b.extend(r.price_e8.to_le_bytes());b.extend(r.publish_us.to_le_bytes());b.extend(r.report_hash);Summary{min:r.publish_us,digest:hash(&b)}}
fn node(l:&Summary,r:&Summary)->Summary{let mut b=NODE.to_vec();b.extend(l.bytes());b.extend(r.bytes());Summary{min:l.min.min(r.min),digest:hash(&b)}}
fn defaults()->Vec<Summary>{let mut v=vec![Summary{min:u64::MAX,digest:hash(EMPTY)}];for i in 0..DEPTH{v.push(node(&v[i],&v[i]))}v}
#[derive(Clone,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct State{
 #[serde(with="decimal")]pub operations:u64,#[serde(with="decimal")]pub leaf_count:u64,
 #[serde(with="decimal")]pub last_time:u64,#[serde(with="decimal")]pub sealed_through:u64,
 pub pending:bool,pub level:u8,pub carry:Summary,pub frontier:Vec<Slot>,
}
impl State{
 pub fn initial()->Self{let mut f=vec![Slot::default();DEPTH+1];f[0]=Slot::occupied(&leaf(&Record::default(),false));Self{operations:0,leaf_count:1,last_time:0,sealed_through:0,pending:false,level:0,carry:Summary::default(),frontier:f}}
 pub fn validate(&self)->Result<(),String>{
  if !(1..=CAP).contains(&self.leaf_count)||self.operations>MAX_STEPS as u64||self.last_time==u64::MAX||self.sealed_through==u64::MAX||usize::from(self.level)>DEPTH||self.frontier.len()!=DEPTH+1||((self.leaf_count==1)!=(self.last_time==0)){return Err("state bounds".into())}
  if !self.pending&&(self.level!=0||self.carry!=Summary::default()){return Err("idle carry".into())}
  let mut mass=if self.pending{1u64<<self.level}else{0};
  for(i,s)in self.frontier.iter().enumerate(){if s.occupied{if self.pending&&i<usize::from(self.level){return Err("lower carry slot occupied".into())}mass+=1u64<<i;}else if s.summary()!=Summary::default(){return Err("empty slot".into())}}
  if mass!=self.leaf_count{return Err("frontier mass".into())}Ok(())
 }
 pub fn fields(&self,genesis:[u8;32],source:u8)->Vec<F>{let mut z=vec![F::from(self.operations),F::from(self.leaf_count),F::from(self.last_time),F::from(self.sealed_through),F::from(u64::from(self.pending)),F::from(u64::from(self.level)),F::from(self.carry.min)];z.extend(limbs(&self.carry.digest));for s in &self.frontier{z.extend([F::from(u64::from(s.occupied)),F::from(s.min)]);z.extend(limbs(&s.digest))}z.extend(limbs(&genesis));z.push(F::from(u64::from(source)));z}
 pub fn root(&self)->Result<Summary,String>{self.validate()?;if self.pending{return Err("pending carry cannot seal".into())}if self.frontier[DEPTH].occupied{return Ok(self.frontier[DEPTH].summary())}let d=defaults();let mut r=d[0].clone();for(i,empty)in d.iter().enumerate().take(DEPTH){r=if self.frontier[i].occupied{node(&self.frontier[i].summary(),&r)}else{node(&r,empty)}}Ok(r)}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(rename_all="lowercase")]
pub enum Op{Append,Carry,Seal}
#[derive(Clone,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Action{pub op:Op,pub record:Record,#[serde(with="decimal")]pub watermark:u64}
impl Action{pub fn seal(watermark:u64)->Self{Self{op:Op::Seal,record:Record::default(),watermark}}}
pub fn advance(b:&State,w:&Action)->Result<State,String>{b.validate()?;if (w.op==Op::Carry)!=b.pending{return Err("carry required".into())}let mut a=b.clone();a.operations+=1;match w.op{
 Op::Append=>{if !w.record.valid()||w.watermark!=0||b.leaf_count>=CAP||w.record.publish_us<=b.last_time||w.record.publish_us<=b.sealed_through{return Err("invalid append".into())}a.leaf_count+=1;a.last_time=w.record.publish_us;a.pending=true;a.level=0;a.carry=leaf(&w.record,true);},
 Op::Carry=>{if w.record!=Record::default()||w.watermark!=0{return Err("carry dummy fields".into())}let i=usize::from(b.level);let s=&b.frontier[i];if s.occupied{if i==DEPTH||s.min>=b.carry.min{return Err("invalid merge".into())}a.carry=node(&s.summary(),&b.carry);a.frontier[i]=Slot::default();a.level+=1;}else{a.frontier[i]=Slot::occupied(&b.carry);a.carry=Summary::default();a.pending=false;a.level=0;}},
 Op::Seal=>{if w.record!=Record::default()||w.watermark<=b.sealed_through||w.watermark==u64::MAX{return Err("invalid seal".into())}a.sealed_through=w.watermark;}
 }a.validate()?;Ok(a)}
#[derive(Clone,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Header{pub genesis:String,pub policy_hash:String,pub source:String,pub depth:usize,#[serde(with="decimal")]pub count:u64,#[serde(with="decimal")]pub last_time:u64,#[serde(with="decimal")]pub sealed_through:u64,pub root:Summary}
impl Header{pub fn context(&self)->Result<([u8;32],u8),String>{if self.depth!=DEPTH||hex32(&self.policy_hash)?!=hash(POLICY){return Err("policy or depth".into())}let source=match self.source.as_str(){"pyth"=>1,"chainlink"=>2,_=>return Err("source".into())};Ok((hex32(&self.genesis)?,source))}pub fn pin(&self)->Result<String,String>{let(g,s)=self.context()?;if self.count>=CAP||((self.count==0)!=(self.last_time==0))||self.last_time==u64::MAX||self.sealed_through==u64::MAX||self.root.min!=0{return Err("invalid snapshot header".into())}let mut b=SNAPSHOT.to_vec();b.extend(g);b.extend(hash(POLICY));b.extend([s,DEPTH as u8]);b.extend(self.count.to_le_bytes());b.extend(self.last_time.to_le_bytes());b.extend(self.sealed_through.to_le_bytes());b.extend(self.root.bytes());Ok(hex::encode(hash(&b)))}}
#[derive(Clone,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Claim{pub header:Header,pub pin:String,pub steps:usize,pub final_state:State}
impl Claim{pub fn states(&self)->Result<(Vec<F>,Vec<F>),String>{let(g,s)=self.header.context()?;let f=&self.final_state;f.validate()?;if self.steps==0||self.steps>MAX_STEPS||f.operations!=self.steps as u64||f.pending||f.sealed_through==0||self.header.count.checked_add(1)!=Some(f.leaf_count)||self.header.last_time!=f.last_time||self.header.sealed_through!=f.sealed_through||self.header.root!=f.root()?||self.pin!=self.header.pin()?{return Err("final frontier and independently retained snapshot differ".into())}Ok((State::initial().fields(g,s),f.fields(g,s)))}}
#[derive(Clone,Debug)]
pub struct AdmissionStep{pub before:State,pub after:State,pub action:Action,pub genesis:[u8;32],pub source:u8}
impl AdmissionStep{pub fn blank()->Self{let before=State::initial();let action=Action::seal(1);let after=advance(&before,&action).unwrap();Self{before,after,action,genesis:[0;32],source:1}}}
pub fn trace(actions:&[Action],claim:&Claim)->Result<Vec<AdmissionStep>,String>{claim.states()?;if actions.len()!=claim.steps{return Err("action count".into())}let(g,s)=claim.header.context()?;let mut before=State::initial();let mut steps=Vec::new();for action in actions{let after=advance(&before,action)?;steps.push(AdmissionStep{before:before.clone(),after:after.clone(),action:action.clone(),genesis:g,source:s});before=after;}if before!=claim.final_state{return Err("terminal frontier mismatch".into())}Ok(steps)}

// Fixed-width bit/inequality helpers shared with the MAX-01 relation.
fn constant_bits(bytes:&[u8])->Vec<Boolean>{bytes.iter().flat_map(|v|(0..8).rev().map(move|j|Boolean::constant((v>>j)&1!=0))).collect()}
fn bits<CS:ConstraintSystem<F>>(mut cs:CS,bytes:&[u8])->Result<Vec<Boolean>,SynthesisError>{
    let mut out=Vec::with_capacity(bytes.len()*8);
    for(i,b) in bytes.iter().enumerate(){for j in (0..8).rev(){out.push(Boolean::from(AllocatedBit::alloc(cs.namespace(||format!("byte {i} bit {j}")),Some((b>>j)&1!=0))?));}} Ok(out)
}
// SHA input bits are MSB-first within a byte; integers are little-endian by byte.
fn le_lc<CS:ConstraintSystem<F>>(b:&[Boolean])->LinearCombination<F>{
    assert_eq!(b.len()%8,0);let mut out=LinearCombination::zero();let mut weight=F::ONE;
    for byte in b.chunks_exact(8){for x in byte.iter().rev(){out=out+&x.lc(CS::one(),weight);weight=weight.double();}}out
}
fn bit_sum<CS:ConstraintSystem<F>>(b:&[Boolean])->LinearCombination<F>{b.iter().fold(LinearCombination::zero(),|lc,x|lc+&x.lc(CS::one(),F::ONE))}
fn bind<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,b:&[Boolean],n:&AllocatedNum<F>){
    cs.enforce(||label.to_owned(),|_|le_lc::<CS>(b),|lc|lc+CS::one(),|lc|lc+n.get_variable());
}
fn eq<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,l:LinearCombination<F>,r:LinearCombination<F>){
    cs.enforce(||label.to_owned(),|_|l,|lc|lc+CS::one(),|_|r);
}
fn zero_if<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,gate:&Boolean,v:LinearCombination<F>){
    cs.enforce(||label.to_owned(),|_|gate.lc(CS::one(),F::ONE),|_|v,|lc|lc);
}
// Prove gate*expression equals a nonnegative integer of width w. All expressions
// use bounded 64-bit byte values and small constants, far below the field modulus.
fn slack<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,gate:&Boolean,expr:LinearCombination<F>,value:i128,width:usize)->Result<(),SynthesisError>{
    let mut ns=cs.namespace(||label.to_owned());
    let witness=if gate.get_value()==Some(true) && value>=0 {value as u128}else{0};
    let mut rhs=LinearCombination::zero();let mut w=F::ONE;
    for i in 0..width{let bit=Boolean::from(AllocatedBit::alloc(ns.namespace(||format!("slack bit {i}")),Some((witness>>i)&1!=0))?);rhs=rhs+&bit.lc(CS::one(),w);w=w.double();}
    ns.enforce(||"bounded gated difference",|_|gate.lc(CS::one(),F::ONE),|_|expr,|_|rhs);Ok(())
}
fn pick<CS:ConstraintSystem<F>>(mut cs:CS,selector:&Boolean,a:&[Boolean],b:&[Boolean])->Result<Vec<Boolean>,SynthesisError>{
    // selector=0 returns a, selector=1 returns b. This constrains each selected bit.
    a.iter().zip(b).enumerate().map(|(i,(x,y))|{
        let v=if selector.get_value()==Some(true){y.get_value()}else{x.get_value()};
        let mut ns=cs.namespace(||format!("select {i}"));
        let o=Boolean::from(AllocatedBit::alloc(ns.namespace(||"result"),v)?);
        ns.enforce(||"conditional select",|_|selector.lc(CS::one(),F::ONE),|_|y.lc(CS::one(),F::ONE)-&x.lc(CS::one(),F::ONE),|_|o.lc(CS::one(),F::ONE)-&x.lc(CS::one(),F::ONE));Ok(o)
    }).collect()
}
fn one<CS:ConstraintSystem<F>>()->LinearCombination<F>{LinearCombination::zero()+CS::one()}
fn val<CS:ConstraintSystem<F>>(x:&AllocatedNum<F>)->LinearCombination<F>{LinearCombination::zero()+x.get_variable()}
fn bool_eq<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,b:&Boolean,n:&AllocatedNum<F>){eq(cs,label,b.lc(CS::one(),F::ONE),val::<CS>(n))}
fn bit<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,v:bool)->Result<Boolean,SynthesisError>{Ok(Boolean::from(AllocatedBit::alloc(cs.namespace(||label.to_owned()),Some(v))?))}
fn and<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,a:&Boolean,b:&Boolean)->Result<Boolean,SynthesisError>{let mut ns=cs.namespace(||label.to_owned());let o=bit(&mut ns,"result",a.get_value()==Some(true)&&b.get_value()==Some(true))?;ns.enforce(||"and",|_|a.lc(CS::one(),F::ONE),|_|b.lc(CS::one(),F::ONE),|_|o.lc(CS::one(),F::ONE));Ok(o)}
fn bound_bits<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,bytes:&[u8],n:&AllocatedNum<F>)->Result<Vec<Boolean>,SynthesisError>{let mut ns=cs.namespace(||label.to_owned());let b=bits(ns.namespace(||"bits"),bytes)?;bind(&mut ns,"bind state field",&b,n);Ok(b)}
fn bound_digest<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,h:&[u8;32],z:&[AllocatedNum<F>])->Result<Vec<Boolean>,SynthesisError>{let mut ns=cs.namespace(||label.to_owned());let b=bits(ns.namespace(||"bits"),h)?;bind(&mut ns,"low",&b[..128],&z[0]);bind(&mut ns,"high",&b[128..],&z[1]);Ok(b)}
fn gated_eq<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,g:&Boolean,a:LinearCombination<F>,b:LinearCombination<F>){zero_if(cs,label,g,a-&b)}
struct SummaryBits{min:Vec<Boolean>,digest:Vec<Boolean>}
fn gate_summary<CS:ConstraintSystem<F>>(cs:&mut CS,label:&str,g:&Boolean,s:&SummaryBits,z:&[AllocatedNum<F>]){let mut ns=cs.namespace(||label.to_owned());for(i,b)in [s.min.as_slice(),&s.digest[..128],&s.digest[128..]].into_iter().enumerate(){gated_eq(&mut ns,&format!("component {i}"),g,le_lc::<CS>(b),val::<CS>(&z[i]));}}
// Both V2 messages occupy exactly two SHA-256 blocks after canonical padding.
// Lengths and IV are protocol constants, never prover-selected witnesses.
fn pad_two_blocks(input:&[Boolean],expected_bytes:usize)->Vec<Boolean>{
    assert_eq!(input.len(),expected_bytes*8);
    assert!(matches!(expected_bytes,64|95));
    let mut out=input.to_vec();
    out.push(Boolean::constant(true));
    out.resize(960,Boolean::constant(false));
    out.extend(constant_bits(&((expected_bytes as u64)*8).to_be_bytes()));
    assert_eq!(out.len(),1024);
    out
}
fn shared_two_block_sha256<CS:ConstraintSystem<F>>(mut cs:CS,append:&Boolean,leaf:&[Boolean],node:&[Boolean])->Result<Vec<Boolean>,SynthesisError>{
    let leaf=pad_two_blocks(leaf,64);
    let node=pad_two_blocks(node,95);
    // The append opcode is constrained one-hot in the surrounding transition.
    // 0 selects NODE; 1 selects LEAF. Select *including* the padding and length.
    // Constant/constant positions can be simplified without witness-dependent shape.
    let mut padded=Vec::with_capacity(1024);
    for(i,(n,l))in node.iter().zip(&leaf).enumerate(){
        match(n,l){
            (Boolean::Constant(n),Boolean::Constant(l))=>{
                padded.push(if n==l{Boolean::constant(*n)}else if *l{append.clone()}else{append.not()});
            },
            _=>padded.extend(pick(cs.namespace(||format!("padded bit {i}")),append,std::slice::from_ref(n),std::slice::from_ref(l))?),
        }
    }
    const IV:[u32;8]=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let mut state=IV.iter().map(|x|UInt32::constant(*x)).collect::<Vec<_>>();
    for(i,block)in padded.chunks_exact(512).enumerate(){
        state=sha256_compression_function(cs.namespace(||format!("shared sha256 block {i}")),block,&state)?;
    }
    Ok(state.into_iter().flat_map(|x|x.into_bits_be()).collect())
}

impl StepCircuit<F> for AdmissionStep{
 fn arity(&self)->usize{ARITY}
 fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
    self.synthesize_hash_variant::<CS,true>(cs,z)
 }
}
impl AdmissionStep{
 // Compile-time switch only. The production StepCircuit implementation always
 // uses the shared gadget. The legacy arm is retained for matched R1CS tests.
 #[doc(hidden)]
 pub fn synthesize_hash_variant<CS:ConstraintSystem<F>,const SHARED:bool>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
  assert_eq!(z.len(),ARITY);assert_eq!(self.before.frontier.len(),DEPTH+1);assert_eq!(self.after.frontier.len(),DEPTH+1);
  let b=&self.before;let w=&self.action;let always=Boolean::constant(true);
  let a=bit(cs,"append opcode",w.op==Op::Append)?;let m=bit(cs,"carry opcode",w.op==Op::Carry)?;let s=bit(cs,"seal opcode",w.op==Op::Seal)?;
  eq(cs,"exactly one operation",a.lc(CS::one(),F::ONE)+&m.lc(CS::one(),F::ONE)+&s.lc(CS::one(),F::ONE),one::<CS>());
  let before_pending=bit(cs,"pending",b.pending)?;bool_eq(cs,"bind pending",&before_pending,&z[4]);eq(cs,"carry mandatory iff pending",m.lc(CS::one(),F::ONE),before_pending.lc(CS::one(),F::ONE));
  let op_count=bound_bits(cs,"operation ordinal",&b.operations.to_le_bytes(),&z[0])?;
  slack(cs,"operation ceiling",&always,LinearCombination::zero()+(F::from((MAX_STEPS-1) as u64),CS::one())-&le_lc::<CS>(&op_count),(MAX_STEPS-1) as i128-i128::from(b.operations),7)?;
  let n=bound_bits(cs,"leaf count",&b.leaf_count.to_le_bytes(),&z[1])?;
  slack(cs,"sentinel present",&always,le_lc::<CS>(&n)-&one::<CS>(),i128::from(b.leaf_count)-1,DEPTH+1)?;
  slack(cs,"tree capacity",&always,LinearCombination::zero()+(F::from(CAP),CS::one())-&le_lc::<CS>(&n),i128::from(CAP)-i128::from(b.leaf_count),DEPTH+1)?;
  slack(cs,"append capacity",&a,LinearCombination::zero()+(F::from(CAP-1),CS::one())-&le_lc::<CS>(&n),i128::from(CAP-1)-i128::from(b.leaf_count),DEPTH+1)?;
  let tail=bound_bits(cs,"tail time",&b.last_time.to_le_bytes(),&z[2])?;let seal=bound_bits(cs,"old watermark",&b.sealed_through.to_le_bytes(),&z[3])?;
  for(label,bb,v)in [("tail reserve",&tail,b.last_time),("watermark reserve",&seal,b.sealed_through)]{slack(cs,label,&always,LinearCombination::zero()+(F::from(u64::MAX-1),CS::one())-&le_lc::<CS>(bb),i128::from(u64::MAX-1)-i128::from(v),64)?;}
  let level=bound_bits(cs,"carry level",&[b.level],&z[5])?;
  let carry=SummaryBits{min:bound_bits(cs,"carry min",&b.carry.min.to_le_bytes(),&z[6])?,digest:bound_digest(cs,"carry digest",&b.carry.digest,&z[7..9])?};
  for(j,v)in [&z[5],&z[6],&z[7],&z[8]].into_iter().enumerate(){zero_if(cs,&format!("idle carry field {j}"),&m.not(),val::<CS>(v));}
  let mut sels=Vec::new();let mut merges=Vec::new();let mut places=Vec::new();let mut occupied=Vec::new();
  let mut mass=LinearCombination::zero();let mut sel_sum=LinearCombination::zero();let mut level_sum=LinearCombination::zero();let mut merge_sum=LinearCombination::zero();let mut next_level=LinearCombination::zero();
  let mut chosen=SummaryBits{min:vec![Boolean::constant(false);64],digest:vec![Boolean::constant(false);256]};
  for i in 0..=DEPTH{
   let mut ns=cs.namespace(||format!("frontier {i}"));let off=9+4*i;let slot=&b.frontier[i];
   let occ=bit(&mut ns,"occupied",slot.occupied)?;bool_eq(&mut ns,"bind occupied",&occ,&z[off]);
   let sb=SummaryBits{min:bound_bits(&mut ns,"min",&slot.min.to_le_bytes(),&z[off+1])?,digest:bound_digest(&mut ns,"digest",&slot.digest,&z[off+2..off+4])?};
   for k in 1..4{zero_if(&mut ns,&format!("empty component {k}"),&occ.not(),val::<CS>(&z[off+k]));}
   let sel=bit(&mut ns,"select level",b.pending&&usize::from(b.level)==i)?;
   let merge=and(&mut ns,"selected occupied",&sel,&occ)?;let place=and(&mut ns,"selected empty",&sel,&occ.not())?;
   if i==DEPTH{eq(&mut ns,"no carry beyond capacity",merge.lc(CS::one(),F::ONE),LinearCombination::zero());}
   mass=mass+&occ.lc(CS::one(),F::from(1u64<<i))+&sel.lc(CS::one(),F::from(1u64<<i));
   sel_sum=sel_sum+&sel.lc(CS::one(),F::ONE);level_sum=level_sum+&sel.lc(CS::one(),F::from(i as u64));
   merge_sum=merge_sum+&merge.lc(CS::one(),F::ONE);next_level=next_level+&merge.lc(CS::one(),F::from((i+1) as u64));
   chosen.min=pick(ns.namespace(||"select min"),&sel,&chosen.min,&sb.min)?;chosen.digest=pick(ns.namespace(||"select digest"),&sel,&chosen.digest,&sb.digest)?;
   sels.push(sel);merges.push(merge);places.push(place);occupied.push(occ);
  }
  eq(cs,"carry selects exactly one level",sel_sum,m.lc(CS::one(),F::ONE));eq(cs,"selected level is carried level",level_sum,le_lc::<CS>(&level));eq(cs,"frontier plus carry mass",mass,le_lc::<CS>(&n));
  for i in 0..=DEPTH{for j in 0..i{zero_if(cs,&format!("lower slot {j} empty during level {i}"),&sels[i],occupied[j].lc(CS::one(),F::ONE));}}
  let merge=bit(cs,"merge selected",b.pending&&b.frontier.get(usize::from(b.level)).is_some_and(|s|s.occupied))?;eq(cs,"merge boolean bound",merge.lc(CS::one(),F::ONE),merge_sum);
  let place=bit(cs,"placement selected",b.pending&&!b.frontier.get(usize::from(b.level)).is_some_and(|s|s.occupied))?;eq(cs,"carry either merges or places",merge.lc(CS::one(),F::ONE)+&place.lc(CS::one(),F::ONE),m.lc(CS::one(),F::ONE));
  let chosen_value=b.frontier.get(usize::from(b.level)).map(|s|s.min).unwrap_or(0);slack(cs,"ordered disjoint merge",&merge,le_lc::<CS>(&carry.min)-&le_lc::<CS>(&chosen.min)-&one::<CS>(),i128::from(b.carry.min)-i128::from(chosen_value)-1,64)?;
  let price=bits(cs.namespace(||"append price"),&w.record.price_e8.to_le_bytes())?;let time=bits(cs.namespace(||"append time"),&w.record.publish_us.to_le_bytes())?;let report=bits(cs.namespace(||"append report"),&w.record.report_hash)?;let watermark=bits(cs.namespace(||"new watermark"),&w.watermark.to_le_bytes())?;
  let p=i128::from(w.record.price_e8);let t=i128::from(w.record.publish_us);
  slack(cs,"positive price",&a,le_lc::<CS>(&price)-&one::<CS>(),p-1,54)?;
  slack(cs,"price cap",&a,LinearCombination::zero()+(F::from(MAX_PRICE),CS::one())-&le_lc::<CS>(&price),i128::from(MAX_PRICE)-p,54)?;
  slack(cs,"report nonzero",&a,bit_sum::<CS>(&report)-&one::<CS>(),i128::from(w.record.report_hash.iter().map(|x|x.count_ones()).sum::<u32>())-1,8)?;
  slack(cs,"strictly after tail",&a,le_lc::<CS>(&time)-&le_lc::<CS>(&tail)-&one::<CS>(),t-i128::from(b.last_time)-1,64)?;
  slack(cs,"strictly after sealed time",&a,le_lc::<CS>(&time)-&le_lc::<CS>(&seal)-&one::<CS>(),t-i128::from(b.sealed_through)-1,64)?;
  slack(cs,"reserve infinite timestamp",&a,LinearCombination::zero()+(F::from(u64::MAX-1),CS::one())-&le_lc::<CS>(&time),i128::from(u64::MAX-1)-t,64)?;
  zero_if(cs,"nonappend price zero",&a.not(),le_lc::<CS>(&price));zero_if(cs,"nonappend time zero",&a.not(),le_lc::<CS>(&time));zero_if(cs,"nonappend digest zero",&a.not(),bit_sum::<CS>(&report));
  slack(cs,"strict watermark advance",&s,le_lc::<CS>(&watermark)-&le_lc::<CS>(&seal)-&one::<CS>(),i128::from(w.watermark)-i128::from(b.sealed_through)-1,64)?;
  slack(cs,"reserve infinite watermark",&s,LinearCombination::zero()+(F::from(u64::MAX-1),CS::one())-&le_lc::<CS>(&watermark),i128::from(u64::MAX-1)-i128::from(w.watermark),64)?;
  zero_if(cs,"nonseal watermark zero",&s.not(),le_lc::<CS>(&watermark));
   let mut leaf_data=constant_bits(LEAF);leaf_data.extend(constant_bits(&[1]));leaf_data.extend(price);leaf_data.extend(time.iter().cloned());leaf_data.extend(report);
   let mut merge_data=constant_bits(NODE);merge_data.extend(chosen.min.iter().cloned());merge_data.extend(chosen.digest);merge_data.extend(carry.min.iter().cloned());merge_data.extend(carry.digest.iter().cloned());
   // Placement and seal still execute the fixed-shape hash, but neither can
   // install its result. The unchanged transition gates enforce those cases.
   let (leaf_hash,merge_hash)=if SHARED{
       let digest=shared_two_block_sha256(cs.namespace(||"shared opcode sha256"),&a,&leaf_data,&merge_data)?;
       (digest.clone(),digest)
   }else{
       (sha256(cs.namespace(||"append leaf sha256"),&leaf_data)?,sha256(cs.namespace(||"carry merge sha256"),&merge_data)?)
   };
  let values=self.after.fields(self.genesis,self.source);let mut out=Vec::with_capacity(ARITY);for(i,v)in values.iter().take(CONTEXT).enumerate(){out.push(AllocatedNum::alloc_infallible(cs.namespace(||format!("next field {i}")),||*v));}out.extend_from_slice(&z[CONTEXT..]);
  eq(cs,"literal operation increment",val::<CS>(&z[0])+CS::one(),val::<CS>(&out[0]));eq(cs,"only append increases leaf count",val::<CS>(&z[1])+&a.lc(CS::one(),F::ONE),val::<CS>(&out[1]));
  gated_eq(cs,"append sets tail",&a,le_lc::<CS>(&time),val::<CS>(&out[2]));gated_eq(cs,"other ops preserve tail",&a.not(),val::<CS>(&z[2]),val::<CS>(&out[2]));
  gated_eq(cs,"seal sets watermark",&s,le_lc::<CS>(&watermark),val::<CS>(&out[3]));gated_eq(cs,"other ops preserve watermark",&s.not(),val::<CS>(&z[3]),val::<CS>(&out[3]));
  eq(cs,"next pending",a.lc(CS::one(),F::ONE)+&merge.lc(CS::one(),F::ONE),val::<CS>(&out[4]));eq(cs,"next carry level",next_level,val::<CS>(&out[5]));
  gate_summary(cs,"append creates carry",&a,&SummaryBits{min:time,digest:leaf_hash},&out[6..9]);gate_summary(cs,"merge creates parent carry",&merge,&SummaryBits{min:chosen.min,digest:merge_hash},&out[6..9]);
  for i in 6..9{zero_if(cs,&format!("placement clears carry {i}"),&place,val::<CS>(&out[i]));zero_if(cs,&format!("seal clears carry {i}"),&s,val::<CS>(&out[i]));}
  for i in 0..=DEPTH{let off=9+4*i;let mut ns=cs.namespace(||format!("update slot {i}"));for j in 0..4{gated_eq(&mut ns,&format!("unselected component {j}"),&sels[i].not(),val::<CS>(&z[off+j]),val::<CS>(&out[off+j]));zero_if(&mut ns,&format!("merged component {j}"),&merges[i],val::<CS>(&out[off+j]));}gated_eq(&mut ns,"placed slot occupied",&places[i],one::<CS>(),val::<CS>(&out[off]));gate_summary(&mut ns,"placed carry summary",&places[i],&carry,&out[off+1..off+4]);}
  Ok(out)
 }
}

#[cfg(test)]
mod shared_hash_tests{
 use super::*;
 use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
 #[test]
 fn shared_opcode_hash_matches_native_sha256_at_both_lengths(){
  let mut shape=None;
  for seed in [0u8,1,0xff,0xa5]{
   let leaf=(0..64).map(|i|seed.wrapping_add(i as u8)).collect::<Vec<_>>();
   let node=(0..95).map(|i|seed.wrapping_mul(3).wrapping_add(i as u8)).collect::<Vec<_>>();
   for choose_leaf in [false,true]{
    let mut cs=TestConstraintSystem::<F>::new();
    let a=bit(&mut cs,"opcode",choose_leaf).unwrap();
    let l=bits(cs.namespace(||"leaf"),&leaf).unwrap();let n=bits(cs.namespace(||"node"),&node).unwrap();
    let d=shared_two_block_sha256(cs.namespace(||"shared"),&a,&l,&n).unwrap();
    let expected=hash(if choose_leaf{&leaf}else{&node});
    for(i,(x,y))in d.iter().zip(constant_bits(&expected)).enumerate(){eq(&mut cs,&format!("digest bit {i}"),x.lc(TestConstraintSystem::<F>::one(),F::ONE),y.lc(TestConstraintSystem::<F>::one(),F::ONE));}
    assert!(cs.is_satisfied());
    if let Some(count)=shape{assert_eq!(count,cs.num_constraints());}else{shape=Some(cs.num_constraints());}
   }
  }
 }
}
