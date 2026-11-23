//! INDEX-MAX-01: transparent Nova selection of maximal admitted reports.
//! The public snapshot pins must be authenticated by an independently checked
//! ordered append/seal registry. No provider completeness or source signatures.
#![forbid(unsafe_code)]
use ff::Field;
use nova_snark::frontend::gadgets::{boolean::{AllocatedBit, Boolean}, num::AllocatedNum, sha256::sha256};
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::{Engine, circuit::StepCircuit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub type F = <PallasEngine as Engine>::Scalar;
pub const RELATION: &str = "shz/hourly-maximality-min-tree-nova/v1/depth4";
pub const DEPTH: usize = 4; // Fixed research circuit. Larger depths require new VK/policy profile.
pub const ARITY: usize = 26; // count,start,genesis2,policy2,source pins4,evidence queue16
const MAX_PRICE: i128=10_000_000_000_000_000;
const HOUR_US: i128=3_600_000_000;
const LEAF: &[u8]=b"SHZ/LOG/LEAF/V2";
const NODE: &[u8]=b"SHZ/LOG/NODE/V2";
const SNAPSHOT: &[u8]=b"SHZ/LOG/SNAPSHOT/V2";
const EVIDENCE: &[u8]=b"SHZ/HOUR/EVIDENCE/V1";
const EVIDENCE_NODE: &[u8]=b"SHZ/EVIDENCE/NODE/V1";
const EVIDENCE_ROOT: &[u8]=b"SHZ/8H/EVIDENCE/V1";
const POLICY_NAME: &[u8]=b"SHZ/DUAL-ORACLE-50BPS-5MIN/HOLD-NECESSITY/V2";
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Pins {pub pyth:String,pub chainlink:String}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {pub genesis:String,pub policy_hash:String,pub start_hour:String,pub pins:Pins,pub evidence_root:String,pub evidence_leaves:Vec<String>}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateJson {pub present:bool,pub price_e8:String,pub publish_us:String,pub report_hash:String}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryJson {pub min:String,pub digest:String}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {pub genesis:String,pub policy_hash:String,pub source:String,pub depth:usize,pub count:String,pub last_time:String,pub sealed_through:String,pub root:SummaryJson}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {pub header:Header,pub index:String,pub candidate:CandidateJson,pub siblings:Vec<SummaryJson>}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HourOpening {pub hour_id:String,pub pyth:Opening,pub chainlink:Opening}
#[derive(Clone,Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {pub genesis:String,pub start_hour:String,pub openings:Vec<HourOpening>}
#[derive(Clone,Debug)]
pub struct Candidate {pub present:bool,pub price:u64,pub time:u64,pub digest:[u8;32]}
impl Candidate {fn parse(j:&CandidateJson)->Result<Self,String>{Ok(Self{present:j.present,price:dec(&j.price_e8)?,time:dec(&j.publish_us)?,digest:hex32(&j.report_hash)?})}fn bytes(&self)->Vec<u8>{let mut v=vec![u8::from(self.present)];v.extend(self.price.to_le_bytes());v.extend(self.time.to_le_bytes());v.extend(self.digest);v}}
#[derive(Clone,Debug)]
pub struct Summary {pub min:u64,pub digest:[u8;32]}
#[derive(Clone,Debug)]
pub struct SourceWitness {pub index:u64,pub count:u64,pub last_time:u64,pub seal:u64,pub candidate:Candidate,pub siblings:Vec<Summary>}
#[derive(Clone,Debug)]
pub struct HourStep {pub position:u8,pub start:u64,pub genesis:[u8;32],pub policy:[u8;32],pub hour:u64,pub sources:[SourceWitness;2]}
fn hash(bytes: &[u8]) -> [u8;32] { Sha256::digest(bytes).into() }
fn f_le(bytes: &[u8]) -> F { bytes.iter().rev().fold(F::ZERO, |acc, b| acc*F::from(256)+F::from(*b as u64)) }
fn dec(s: &str) -> Result<u64,String> {
    let v = s.parse::<u64>().map_err(|_| "invalid u64")?;
    if v.to_string()!=s {return Err("noncanonical u64".into())} Ok(v)
}
fn hex32(s: &str) -> Result<[u8;32],String> {
    if s.len()!=64 || !s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {return Err("noncanonical digest".into())}
    hex::decode(s).map_err(|_| "digest hex")?.try_into().map_err(|_| "digest length".into())
}
pub fn evidence_root(genesis:[u8;32],policy:[u8;32],start:u64,leaves:&[[u8;32]])->Result<[u8;32],String>{
    if leaves.len()!=8{return Err("eight evidence leaves required".into())}
    let mut layer=leaves.to_vec();while layer.len()>1{layer=layer.chunks_exact(2).map(|p|{let mut b=EVIDENCE_NODE.to_vec();b.extend(p[0]);b.extend(p[1]);hash(&b)}).collect();}
    let mut b=EVIDENCE_ROOT.to_vec();b.extend(genesis);b.extend(policy);b.extend(start.to_le_bytes());b.extend(layer[0]);Ok(hash(&b))
}

impl Claim {pub fn state(&self,count:u64)->Result<Vec<F>,String>{
 let start=dec(&self.start_hour)?;if start%8!=0||start>999_999_992||!(count==0||count==8){return Err("invalid checkpoint count/alignment".into())}
 let genesis=hex32(&self.genesis)?;let policy=hex32(&self.policy_hash)?;if policy!=hash(POLICY_NAME){return Err("policy version".into())}
 let mut z=vec![F::from(count),F::from(start)];for h in [genesis,policy,hex32(&self.pins.pyth)?,hex32(&self.pins.chainlink)?]{z.push(f_le(&h[..16]));z.push(f_le(&h[16..]));}
 let leaves=self.evidence_leaves.iter().map(|h|hex32(h)).collect::<Result<Vec<_>,_>>()?;if evidence_root(genesis,policy,start,&leaves)?!=hex32(&self.evidence_root)?{return Err("wrong evidence root".into())}
 if count==0{for h in leaves{z.push(f_le(&h[..16]));z.push(f_le(&h[16..]));}}else{z.extend([F::ZERO;16]);}Ok(z)
}}
impl SourceWitness {fn parse(w:&Opening,source:&str,g:&str)->Result<Self,String>{
 if w.header.depth!=DEPTH||w.header.source!=source||w.header.genesis!=g||hex32(&w.header.policy_hash)?!=hash(POLICY_NAME)||w.siblings.len()!=DEPTH{return Err("source context or depth".into())}
 Ok(Self{index:dec(&w.index)?,count:dec(&w.header.count)?,last_time:dec(&w.header.last_time)?,seal:dec(&w.header.sealed_through)?,candidate:Candidate::parse(&w.candidate)?,siblings:w.siblings.iter().map(|s|Ok(Summary{min:dec(&s.min)?,digest:hex32(&s.digest)?})).collect::<Result<Vec<_>,String>>()?})
}}
impl HourStep {pub fn evidence_digest(&self)->[u8;32]{let mut b=EVIDENCE.to_vec();b.extend(self.genesis);b.extend(self.policy);b.extend(self.hour.to_le_bytes());for w in &self.sources{b.extend(w.candidate.bytes())}hash(&b)}}
impl Fixture {pub fn steps(&self)->Result<Vec<HourStep>,String>{if self.openings.len()!=8{return Err("exactly eight hours".into())}let start=dec(&self.start_hour)?;let genesis=hex32(&self.genesis)?;self.openings.iter().enumerate().map(|(i,w)|Ok(HourStep{position:i as u8,start,genesis,policy:hash(POLICY_NAME),hour:dec(&w.hour_id)?,sources:[SourceWitness::parse(&w.pyth,"pyth",&self.genesis)?,SourceWitness::parse(&w.chainlink,"chainlink",&self.genesis)?]})).collect()}}
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
fn scaled<CS:ConstraintSystem<F>>(b:&[Boolean],coefficient:i64)->LinearCombination<F>{
    let mut out=LinearCombination::zero();let mut w=F::from(coefficient.unsigned_abs());if coefficient<0{w=-w;}
    for byte in b.chunks_exact(8){for x in byte.iter().rev(){out=out+&x.lc(CS::one(),w);w=w.double();}}out
}
struct CandidateBits {present:Boolean, price:Vec<Boolean>, time:Vec<Boolean>, digest:Vec<Boolean>}
impl CandidateBits {
    fn append(&self,v:&mut Vec<Boolean>){v.extend((0..7).map(|_|Boolean::constant(false)));v.push(self.present.clone());v.extend(self.price.iter().cloned());v.extend(self.time.iter().cloned());v.extend(self.digest.iter().cloned());}
}

// Check latest predecessor relative to an independently pinned append/seal snapshot.
// Candidate allocations feed BOTH the leaf hash and the POLICY-01 evidence digest.
fn selection<CS:ConstraintSystem<F>>(cs:&mut CS,w:&SourceWitness,source:u8,genesis:&[Boolean],policy:&[Boolean],hour:&[Boolean],hour_value:u64,pins:&[AllocatedNum<F>])->Result<CandidateBits,SynthesisError>{
 let always=Boolean::constant(true);
 let idx=bits(cs.namespace(||"index"),&w.index.to_le_bytes())?;
 let count=bits(cs.namespace(||"count"),&w.count.to_le_bytes())?;
 let last=bits(cs.namespace(||"last"),&w.last_time.to_le_bytes())?;
 let seal=bits(cs.namespace(||"seal"),&w.seal.to_le_bytes())?;
 let cap=(1u64<<DEPTH)-1;
 slack(cs,"count capacity",&always,LinearCombination::zero()+(F::from(cap),CS::one())-&le_lc::<CS>(&count),i128::from(cap)-i128::from(w.count),DEPTH)?;
 slack(cs,"index within admitted prefix",&always,le_lc::<CS>(&count)-&le_lc::<CS>(&idx),i128::from(w.count)-i128::from(w.index),DEPTH)?;
 let cutoff_value=(i128::from(hour_value)+1)*HOUR_US;
 let cutoff=scaled::<CS>(hour,HOUR_US as i64)+(F::from(HOUR_US as u64),CS::one());
 slack(cs,"cutoff sealed",&always,le_lc::<CS>(&seal)-&cutoff,i128::from(w.seal)-cutoff_value,64)?;
 let c=&w.candidate;
 let present=Boolean::from(AllocatedBit::alloc(cs.namespace(||"present"),Some(c.present))?);
 let price=bits(cs.namespace(||"price"),&c.price.to_le_bytes())?;
 let time=bits(cs.namespace(||"time"),&c.time.to_le_bytes())?;
 let digest=bits(cs.namespace(||"report digest"),&c.digest)?;
 let absent=present.not();
 for (label,b) in [("absent index zero",&idx),("absent price zero",&price),("absent time zero",&time)]{zero_if(cs,label,&absent,le_lc::<CS>(b));}
 zero_if(cs,"absent digest zero",&absent,bit_sum::<CS>(&digest));
 slack(cs,"present index nonzero",&present,le_lc::<CS>(&idx)-&one::<CS>(),i128::from(w.index)-1,DEPTH)?;
 slack(cs,"present price positive",&present,le_lc::<CS>(&price)-&one::<CS>(),i128::from(c.price)-1,54)?;
 slack(cs,"present price bounded",&present,LinearCombination::zero()+(F::from(MAX_PRICE as u64),CS::one())-&le_lc::<CS>(&price),MAX_PRICE-i128::from(c.price),54)?;
 slack(cs,"present timestamp positive",&present,le_lc::<CS>(&time)-&one::<CS>(),i128::from(c.time)-1,64)?;
 slack(cs,"present digest nonzero",&present,bit_sum::<CS>(&digest)-&one::<CS>(),i128::from(c.digest.iter().map(|b|b.count_ones()).sum::<u32>())-1,8)?;
 slack(cs,"candidate at or before cutoff",&always,cutoff.clone()-&le_lc::<CS>(&time),cutoff_value-i128::from(c.time),64)?;
 slack(cs,"candidate at or before tail",&always,le_lc::<CS>(&last)-&le_lc::<CS>(&time),i128::from(w.last_time)-i128::from(c.time),64)?;
 let candidate=CandidateBits{present,price,time:time.clone(),digest};
 let mut data=constant_bits(LEAF);candidate.append(&mut data);
 let mut current_hash=sha256(cs.namespace(||"leaf hash"),&data)?;let mut current_min=time;let mut min_value=c.time;
 assert_eq!(w.siblings.len(),DEPTH);
 for i in 0..DEPTH {let mut ns=cs.namespace(||format!("level {i}"));let s=&w.siblings[i];let sb=bits(ns.namespace(||"sibling minimum"),&s.min.to_le_bytes())?;let sh=bits(ns.namespace(||"sibling digest"),&s.digest)?;let selector=&idx[(i/8)*8+7-(i%8)];
   // On a left branch the sibling is an entire later subtree. Its certified
   // minimum MUST exceed the cutoff. This also rules out a stale predecessor
   // or a false absence sentinel when an admitted eligible report exists.
   slack(&mut ns,"later subtree strictly after cutoff",&selector.not(),le_lc::<CS>(&sb)-&cutoff-&one::<CS>(),i128::from(s.min)-cutoff_value-1,64)?;
   let lm=pick(ns.namespace(||"left min"),selector,&current_min,&sb)?;let rm=pick(ns.namespace(||"right min"),selector,&sb,&current_min)?;
   let lh=pick(ns.namespace(||"left hash"),selector,&current_hash,&sh)?;let rh=pick(ns.namespace(||"right hash"),selector,&sh,&current_hash)?;
   let (lv,rv)=if (w.index>>i)&1==0{(min_value,s.min)}else{(s.min,min_value)};
   slack(&mut ns,"ordered child minima",&always,le_lc::<CS>(&rm)-&le_lc::<CS>(&lm),i128::from(rv)-i128::from(lv),64)?;
   let mut n=constant_bits(NODE);n.extend(lm.iter().cloned());n.extend(lh);n.extend(rm);n.extend(rh);
   current_hash=sha256(ns.namespace(||"node hash"),&n)?;current_min=lm;min_value=lv;
 }
 eq(cs,"sentinel root minimum zero",le_lc::<CS>(&current_min),LinearCombination::zero());
 let mut h=constant_bits(SNAPSHOT);h.extend_from_slice(genesis);h.extend_from_slice(policy);h.extend(constant_bits(&[source,DEPTH as u8]));h.extend(count);h.extend(last);h.extend(seal);h.extend(current_min);h.extend(current_hash);
 let hd=sha256(cs.namespace(||"snapshot hash"),&h)?;bind(cs,"snapshot low",&hd[..128],&pins[0]);bind(cs,"snapshot high",&hd[128..],&pins[1]);Ok(candidate)
}
impl StepCircuit<F> for HourStep {
 fn arity(&self)->usize{ARITY}
 fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
  assert_eq!(z.len(),ARITY);let pos=bits(cs.namespace(||"position"),&[self.position])?;bind(cs,"count",&pos,&z[0]);eq(cs,"position three bits",bit_sum::<CS>(&pos[..5]),LinearCombination::zero());
  let start=bits(cs.namespace(||"start"),&self.start.to_le_bytes())?;bind(cs,"public start",&start,&z[1]);eq(cs,"eight hour alignment",bit_sum::<CS>(&start[5..8]),LinearCombination::zero());slack(cs,"start bound",&Boolean::constant(true),LinearCombination::zero()+(F::from(999_999_992),CS::one())-&le_lc::<CS>(&start),999_999_992-i128::from(self.start),30)?;
  let genesis=bits(cs.namespace(||"genesis"),&self.genesis)?;let policy=constant_bits(&hash(POLICY_NAME));
  for(i,b)in [genesis.as_slice(),policy.as_slice()].into_iter().enumerate(){bind(cs,&format!("header {i} low"),&b[..128],&z[2+2*i]);bind(cs,&format!("header {i} high"),&b[128..],&z[3+2*i]);}
  let hour=bits(cs.namespace(||"hour"),&self.hour.to_le_bytes())?;eq(cs,"hour ordinal",le_lc::<CS>(&hour),le_lc::<CS>(&start)+&le_lc::<CS>(&pos));
  let p=selection(&mut cs.namespace(||"pyth selection"),&self.sources[0],1,&genesis,&policy,&hour,self.hour,&z[6..8])?;
  let c=selection(&mut cs.namespace(||"chainlink selection"),&self.sources[1],2,&genesis,&policy,&hour,self.hour,&z[8..10])?;
  let mut e=constant_bits(EVIDENCE);e.extend(genesis);e.extend(policy);e.extend(hour);p.append(&mut e);c.append(&mut e);let d=sha256(cs.namespace(||"policy evidence"),&e)?;bind(cs,"evidence low",&d[..128],&z[10]);bind(cs,"evidence high",&d[128..],&z[11]);
  let count=AllocatedNum::alloc_infallible(cs.namespace(||"next count"),||F::from(u64::from(self.position)+1));eq(cs,"literal count increment",LinearCombination::zero()+z[0].get_variable()+CS::one(),LinearCombination::zero()+count.get_variable());let mut out=vec![count];out.extend_from_slice(&z[1..10]);out.extend_from_slice(&z[12..26]);for i in 0..2{let v=AllocatedNum::alloc_infallible(cs.namespace(||format!("zero {i}")),||F::ZERO);eq(cs,&format!("literal zero {i}"),LinearCombination::zero()+v.get_variable(),LinearCombination::zero());out.push(v)}Ok(out)
 }
}
