//! Native depth-18 state machine extracted from ADMIT-05's admission_fused crate.
//! Same MAX-01 byte commitments. This module has no elliptic-curve or Nova dependency.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const DEPTH: usize=18;
pub const CAP:u64=1<<DEPTH;
pub const MAX_STEPS:usize=1<<20;
const MAX_PRICE:u64=10_000_000_000_000_000;
const LEAF:&[u8]=b"SHZ/LOG/LEAF/V2";
const EMPTY:&[u8]=b"SHZ/LOG/EMPTY/V2";
const NODE:&[u8]=b"SHZ/LOG/NODE/V2";
const SNAPSHOT:&[u8]=b"SHZ/LOG/SNAPSHOT/V2";
const POLICY:&[u8]=b"SHZ/DUAL-ORACLE-50BPS-5MIN/HOLD-NECESSITY/V2";
pub fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
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
  if self.pending&&!self.frontier[usize::from(self.level)].occupied{return Err("pending carry must face an occupied slot".into())}
  let mut mass=if self.pending{1u64<<self.level}else{0};
  for(i,s)in self.frontier.iter().enumerate(){if s.occupied{if self.pending&&i<usize::from(self.level){return Err("lower carry slot occupied".into())}mass+=1u64<<i;}else if s.summary()!=Summary::default(){return Err("empty slot".into())}}
  if mass!=self.leaf_count{return Err("frontier mass".into())}Ok(())
 }
 pub fn root(&self)->Result<Summary,String>{self.validate()?;if self.pending{return Err("pending carry cannot seal".into())}if self.frontier[DEPTH].occupied{return Ok(self.frontier[DEPTH].summary())}let d=defaults();let mut r=d[0].clone();for(i,empty)in d.iter().enumerate().take(DEPTH){r=if self.frontier[i].occupied{node(&self.frontier[i].summary(),&r)}else{node(&r,empty)}}Ok(r)}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(rename_all="lowercase")]
pub enum Op{Append,Carry,Seal}
#[derive(Clone,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Action{pub op:Op,pub record:Record,#[serde(with="decimal")]pub watermark:u64}
impl Action{pub fn seal(watermark:u64)->Self{Self{op:Op::Seal,record:Record::default(),watermark}}}
// The target slot is determined by the operation. Install immediately if empty;
// a pending carry is allowed only when a further merge is actually required.
fn install_or_carry(a:&mut State,level:usize,digest:Summary){
 if a.frontier[level].occupied{a.pending=true;a.level=level as u8;a.carry=digest;}
 else{a.frontier[level]=Slot::occupied(&digest);a.pending=false;a.level=0;a.carry=Summary::default();}
}
pub fn advance(b:&State,w:&Action)->Result<State,String>{
 b.validate()?;
 if (w.op==Op::Carry)!=b.pending{return Err("carry required".into())}
 let mut a=b.clone();a.operations+=1;
 match w.op{
 Op::Append=>{
  if !w.record.valid()||w.watermark!=0||b.leaf_count>=CAP||w.record.publish_us<=b.last_time||w.record.publish_us<=b.sealed_through{return Err("invalid append".into())}
  a.leaf_count+=1;a.last_time=w.record.publish_us;
  install_or_carry(&mut a,0,leaf(&w.record,true));
 },
 Op::Carry=>{
  if w.record!=Record::default()||w.watermark!=0{return Err("carry dummy fields".into())}
  let i=usize::from(b.level);let old=&b.frontier[i];
  if !old.occupied||i==DEPTH||old.min>=b.carry.min{return Err("invalid merge".into())}
  let parent=node(&old.summary(),&b.carry);
  a.frontier[i]=Slot::default();install_or_carry(&mut a,i+1,parent);
 },
 Op::Seal=>{
  if w.record!=Record::default()||w.watermark<=b.sealed_through||w.watermark==u64::MAX{return Err("invalid seal".into())}
  a.sealed_through=w.watermark;
 }
 }a.validate()?;Ok(a)
}
#[derive(Clone,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Header{pub genesis:String,pub policy_hash:String,pub source:String,pub depth:usize,#[serde(with="decimal")]pub count:u64,#[serde(with="decimal")]pub last_time:u64,#[serde(with="decimal")]pub sealed_through:u64,pub root:Summary}
impl Header{pub fn context(&self)->Result<([u8;32],u8),String>{if self.depth!=DEPTH||hex32(&self.policy_hash)?!=hash(POLICY){return Err("policy or depth".into())}let source=match self.source.as_str(){"pyth"=>1,"chainlink"=>2,_=>return Err("source".into())};Ok((hex32(&self.genesis)?,source))}pub fn pin(&self)->Result<String,String>{let(g,s)=self.context()?;if self.count>=CAP||((self.count==0)!=(self.last_time==0))||self.last_time==u64::MAX||self.sealed_through==u64::MAX||self.root.min!=0{return Err("invalid snapshot header".into())}let mut b=SNAPSHOT.to_vec();b.extend(g);b.extend(hash(POLICY));b.extend([s,DEPTH as u8]);b.extend(self.count.to_le_bytes());b.extend(self.last_time.to_le_bytes());b.extend(self.sealed_through.to_le_bytes());b.extend(self.root.bytes());Ok(hex::encode(hash(&b)))}}
#[derive(Clone,Debug,PartialEq,Eq,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Claim{pub header:Header,pub pin:String,pub steps:usize,pub final_state:State}
impl Claim {
 pub fn validate(&self)->Result<(),String>{
  self.header.context()?; let f=&self.final_state; f.validate()?;
  if self.steps==0||self.steps>MAX_STEPS||f.operations!=self.steps as u64||f.pending||f.sealed_through==0||self.header.count.checked_add(1)!=Some(f.leaf_count)||self.header.last_time!=f.last_time||self.header.sealed_through!=f.sealed_through||self.header.root!=f.root()?||self.pin!=self.header.pin()?{return Err("final frontier and independently retained snapshot differ".into())}Ok(())
 }
}
pub fn policy_digest()->[u8;32]{hash(POLICY)}
pub fn parse_digest(s:&str)->Result<[u8;32],String>{hex32(s)}
