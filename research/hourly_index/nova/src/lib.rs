//! SHZ-INDEX-02: eight private hourly record openings, one public checkpoint.
//! The report hashes are committed claims, NOT authenticated source reports.
//! This relation is a native Nova candidate, not a NEAR Nova verifier.
#![forbid(unsafe_code)]
use ff::Field;
use nova_snark::frontend::gadgets::{boolean::{AllocatedBit, Boolean}, num::AllocatedNum, sha256::sha256};
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::{Engine, circuit::StepCircuit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type F = <PallasEngine as Engine>::Scalar;
pub const RELATION: &str = "shz/hourly-index-checkpoint-nova/v1";
pub const ARITY: usize = 8; // count, start, genesis[2], policy[2], checkpoint[2]
const LEAF: &[u8] = b"SHZ/HOUR/LEAF/V1";
const NODE: &[u8] = b"SHZ/HOUR/NODE/V1";
const ROOT: &[u8] = b"SHZ/8H/ROOT/V1";
const MAX_PRICE: i128 = 10_000_000_000_000_000;
const HOUR_US: i128 = 3_600_000_000;
const MAX_AGE: i128 = 300_000_000;
const MAX_SKEW: i128 = 60_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub genesis: String,
    pub policy_hash: String,
    pub start_hour: String,
    pub checkpoint_root: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub genesis: String, pub policy_hash: String, pub hour_id: String,
    pub status: u8, pub hold_reason: u8,
    pub pyth_price_e8: String, pub chainlink_price_e8: String, pub index_price_e8: String,
    pub pyth_publish_us: String, pub chainlink_publish_us: String,
    pub pyth_report_hash: String, pub chainlink_report_hash: String,
}
#[derive(Clone, Debug)]
pub struct HourStep {
    pub position: u8, pub start: u64, pub genesis: [u8;32], pub policy: [u8;32],
    pub hour: u64, pub status: u8, pub reason: u8,
    pub p: u64, pub c: u64, pub index: u64, pub pt: u64, pub ct: u64,
    pub p_hash: [u8;32], pub c_hash: [u8;32], pub siblings: [[u8;32];3],
}
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
impl Claim {
    pub fn state(&self,count:u64) -> Result<Vec<F>,String> {
        let start=dec(&self.start_hour)?;
        if start%8!=0 || start>999_999_992 || (count!=0 && count!=8) {return Err("invalid public checkpoint range".into())}
        let mut out=vec![F::from(count),F::from(start)];
        for h in [&self.genesis,&self.policy_hash,&self.checkpoint_root] {
            let b=hex32(h)?; out.push(f_le(&b[..16]));out.push(f_le(&b[16..]));
        }
        Ok(out)
    }
}
impl HourStep {
    pub fn from_record(r:&Record,start:u64,position:u8,siblings:&[String])->Result<Self,String>{
        if siblings.len()!=3{return Err("expected three siblings".into())}
        Ok(Self{position,start,genesis:hex32(&r.genesis)?,policy:hex32(&r.policy_hash)?,hour:dec(&r.hour_id)?,status:r.status,reason:r.hold_reason,p:dec(&r.pyth_price_e8)?,c:dec(&r.chainlink_price_e8)?,index:dec(&r.index_price_e8)?,pt:dec(&r.pyth_publish_us)?,ct:dec(&r.chainlink_publish_us)?,p_hash:hex32(&r.pyth_report_hash)?,c_hash:hex32(&r.chainlink_report_hash)?,siblings:[hex32(&siblings[0])?,hex32(&siblings[1])?,hex32(&siblings[2])?]})
    }
    pub fn leaf_bytes(&self)->Vec<u8>{
        let mut b=LEAF.to_vec(); b.extend(self.genesis);b.extend(self.policy);b.extend(self.hour.to_le_bytes());b.extend([self.status,self.reason]);
        for v in [self.p,self.c,self.index,self.pt,self.ct]{b.extend(v.to_le_bytes())}b.extend(self.p_hash);b.extend(self.c_hash);b
    }
    pub fn native_root(&self)->[u8;32]{
        let mut d=hash(&self.leaf_bytes());
        for (i,s) in self.siblings.iter().enumerate(){let mut b=NODE.to_vec();if (self.position>>i)&1==0 {b.extend(d);b.extend(s)}else{b.extend(s);b.extend(d)}d=hash(&b);}
        let mut b=ROOT.to_vec();b.extend(self.genesis);b.extend(self.policy);b.extend(self.start.to_le_bytes());b.extend(d);hash(&b)
    }
}
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
impl StepCircuit<F> for HourStep {
    fn arity(&self)->usize{ARITY}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
        assert_eq!(z.len(),ARITY);
        let pos=bits(cs.namespace(||"position"),&[self.position])?;
        bind(cs,"position equals fold count",&pos,&z[0]);
        eq(cs,"position fits three bits",bit_sum::<CS>(&pos[..5]),LinearCombination::zero());
        let start=bits(cs.namespace(||"start"),&self.start.to_le_bytes())?;
        bind(cs,"start is public",&start,&z[1]);
        eq(cs,"eight hour alignment",bit_sum::<CS>(&start[5..8]),LinearCombination::zero());
        slack(cs,"bounded start",&Boolean::constant(true),LinearCombination::zero()+(F::from(999_999_992),CS::one())-&le_lc::<CS>(&start),999_999_992-i128::from(self.start),30)?;
        let genesis=bits(cs.namespace(||"genesis"),&self.genesis)?;let policy=bits(cs.namespace(||"policy"),&self.policy)?;
        for (i,b) in [genesis.as_slice(),policy.as_slice()].into_iter().enumerate(){bind(cs,&format!("public header {i} low"),&b[..128],&z[2+i*2]);bind(cs,&format!("public header {i} high"),&b[128..],&z[3+i*2]);}
        let hour=bits(cs.namespace(||"hour"),&self.hour.to_le_bytes())?;
        eq(cs,"consecutive UTC hour",le_lc::<CS>(&hour),le_lc::<CS>(&start)+&le_lc::<CS>(&pos));
        let status=bits(cs.namespace(||"status"),&[self.status])?;let reason=bits(cs.namespace(||"reason"),&[self.reason])?;
        let valid=Boolean::from(AllocatedBit::alloc(cs.namespace(||"valid status flag"),Some(self.status==1))?);let hold=valid.not();
        eq(cs,"exact status encoding",le_lc::<CS>(&status)+&valid.lc(CS::one(),F::ONE),LinearCombination::zero()+(F::from(2),CS::one()));
        zero_if(cs,"valid reason zero",&valid,le_lc::<CS>(&reason));
        eq(cs,"reason fits two bits",bit_sum::<CS>(&reason[..6]),LinearCombination::zero());
        slack(cs,"hold reason nonzero",&hold,le_lc::<CS>(&reason)-&one::<CS>(),i128::from(self.reason)-1,2)?;
        let p=bits(cs.namespace(||"pyth"),&self.p.to_le_bytes())?;let c=bits(cs.namespace(||"chainlink"),&self.c.to_le_bytes())?;let index=bits(cs.namespace(||"index"),&self.index.to_le_bytes())?;
        let pt=bits(cs.namespace(||"pyth time"),&self.pt.to_le_bytes())?;let ct=bits(cs.namespace(||"chainlink time"),&self.ct.to_le_bytes())?;
        let ph=bits(cs.namespace(||"pyth report"),&self.p_hash)?;let ch=bits(cs.namespace(||"chainlink report"),&self.c_hash)?;
        for (i,(b,v)) in [(&p,self.p),(&c,self.c),(&index,self.index)].into_iter().enumerate(){
            slack(cs,&format!("positive price {i}"),&valid,le_lc::<CS>(b)-&one::<CS>(),i128::from(v)-1,54)?;
            slack(cs,&format!("bounded price {i}"),&valid,LinearCombination::zero()+(F::from(MAX_PRICE as u64),CS::one())-&le_lc::<CS>(b),MAX_PRICE-i128::from(v),54)?;
        }
        for(i,b) in [&p,&c,&index,&pt,&ct].into_iter().enumerate(){zero_if(cs,&format!("hold value {i}"),&hold,le_lc::<CS>(b));}
        for(i,(b,h)) in [(&ph,&self.p_hash),(&ch,&self.c_hash)].into_iter().enumerate(){
            zero_if(cs,&format!("hold digest {i}"),&hold,bit_sum::<CS>(b));
            slack(cs,&format!("nonzero report {i}"),&valid,bit_sum::<CS>(b)-&one::<CS>(),i128::from(h.iter().map(|v|v.count_ones()).sum::<u32>())-1,8)?;
        }
        let pv=i128::from(self.p);let cv=i128::from(self.c);let iv=i128::from(self.index);
        slack(cs,"midpoint floor",&Boolean::constant(true),le_lc::<CS>(&p)+&le_lc::<CS>(&c)+&scaled::<CS>(&index,-2),pv+cv-2*iv,1)?;
        slack(cs,"spread p-c",&valid,scaled::<CS>(&p,-19_950)+&scaled::<CS>(&c,20_050),50*(pv+cv)-20_000*(pv-cv),80)?;
        slack(cs,"spread c-p",&valid,scaled::<CS>(&c,-19_950)+&scaled::<CS>(&p,20_050),50*(pv+cv)-20_000*(cv-pv),80)?;
        let cutoff=(i128::from(self.hour)+1)*HOUR_US;
        for(i,(t,v)) in [(&pt,self.pt),(&ct,self.ct)].into_iter().enumerate(){
            let d=scaled::<CS>(&hour,HOUR_US as i64)+(F::from(HOUR_US as u64),CS::one())-&le_lc::<CS>(t);
            slack(cs,&format!("nonfuture source {i}"),&valid,d,cutoff-i128::from(v),64)?;
            slack(cs,&format!("fresh source {i}"),&valid,le_lc::<CS>(t)+&scaled::<CS>(&hour,-(HOUR_US as i64))+( -F::from((HOUR_US-MAX_AGE) as u64),CS::one()),i128::from(v)+MAX_AGE-cutoff,64)?;
        }
        for(i,(a,b,va,vb)) in [(&pt,&ct,self.pt,self.ct),(&ct,&pt,self.ct,self.pt)].into_iter().enumerate(){
            slack(cs,&format!("source skew {i}"),&valid,le_lc::<CS>(a)-&le_lc::<CS>(b)+(F::from(MAX_SKEW as u64),CS::one()),i128::from(va)-i128::from(vb)+MAX_SKEW,64)?;
        }
        let mut leaf=constant_bits(LEAF);for b in [&genesis,&policy,&hour,&status,&reason,&p,&c,&index,&pt,&ct,&ph,&ch]{leaf.extend(b.iter().cloned());}
        let mut digest=sha256(cs.namespace(||"exact leaf sha256"),&leaf)?;
        for i in 0..3 {let s=bits(cs.namespace(||format!("sibling {i}")),&self.siblings[i])?;let selector=&pos[7-i];let l=pick(cs.namespace(||format!("left {i}")),selector,&digest,&s)?;let r=pick(cs.namespace(||format!("right {i}")),selector,&s,&digest)?;let mut data=constant_bits(NODE);data.extend(l);data.extend(r);digest=sha256(cs.namespace(||format!("node sha256 {i}")),&data)?;}
        let mut root=constant_bits(ROOT);root.extend(genesis);root.extend(policy);root.extend(start);root.extend(digest);
        let root=sha256(cs.namespace(||"exact checkpoint sha256"),&root)?;
        bind(cs,"checkpoint low",&root[..128],&z[6]);bind(cs,"checkpoint high",&root[128..],&z[7]);
        let count=AllocatedNum::alloc_infallible(cs.namespace(||"next count"),||F::from(u64::from(self.position)+1));
        eq(cs,"literal next count",LinearCombination::zero()+z[0].get_variable()+CS::one(),LinearCombination::zero()+count.get_variable());
        let mut out=vec![count];out.extend_from_slice(&z[1..]);Ok(out)
    }
}

#[derive(Deserialize)]
pub struct Fixture {pub records:Vec<Record>,pub checkpoint:Checkpoint}
#[derive(Deserialize)]
pub struct Checkpoint {pub genesis:String,pub policy_hash:String,pub start_hour:String,pub checkpoint_root:String,pub inclusion:Vec<Inclusion>}
#[derive(Deserialize)]
pub struct Inclusion {pub hour_id:String,pub siblings:Vec<String>}
impl Fixture {
    pub fn claim(&self)->Claim {Claim{genesis:self.checkpoint.genesis.clone(),policy_hash:self.checkpoint.policy_hash.clone(),start_hour:self.checkpoint.start_hour.clone(),checkpoint_root:self.checkpoint.checkpoint_root.clone()}}
    pub fn steps(&self)->Result<Vec<HourStep>,String>{
        if self.records.len()!=8||self.checkpoint.inclusion.len()!=8{return Err("exactly eight hourly openings required".into())}
        let start=dec(&self.checkpoint.start_hour)?;
        self.records.iter().zip(&self.checkpoint.inclusion).enumerate().map(|(i,(r,p))|{
            if p.hour_id!=r.hour_id{return Err("path hour differs".into())}HourStep::from_record(r,start,i as u8,&p.siblings)
        }).collect()
    }
}
