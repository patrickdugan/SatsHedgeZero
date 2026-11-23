//! Native research prover/verifier. Verification is off-chain only.
use bincode::Options;
use ff::PrimeField;
use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use shz_hourly_index_nova::{Claim,Fixture,HourStep,RELATION};
use std::{env,fs,io::{self,Read,Write},path::Path,time::Instant,panic::{catch_unwind,AssertUnwindSafe}};

type Pp=PublicParams<PallasEngine,VestaEngine,HourStep>;
type Rs=RecursiveSNARK<PallasEngine,VestaEngine,HourStep>;
type S1=RelaxedR1CSSNARK<PallasEngine,EvaluationEngine<PallasEngine>>;
type S2=RelaxedR1CSSNARK<VestaEngine,EvaluationEngine<VestaEngine>>;
type Cs=CompressedSNARK<PallasEngine,VestaEngine,HourStep,S1,S2>;
type Vk=VerifierKey<PallasEngine,VestaEngine,HourStep,S1,S2>;
const STEPS:usize=8;
const LIMIT:u64=4*1024*1024;
#[derive(Serialize,Deserialize,PartialEq,Eq,Debug)]
#[serde(deny_unknown_fields)]
struct Manifest {relation:String,nova_version:String,claim:Claim,steps:usize,verifier_key_sha256:String,proof_sha256:String}
fn read(path:&Path,limit:u64)->Result<Vec<u8>,String>{
 let mut f=fs::File::open(path).map_err(|e|e.to_string())?;let mut b=Vec::new();(&mut f).take(limit+1).read_to_end(&mut b).map_err(|e|e.to_string())?;
 if b.len() as u64>limit{return Err("input exceeds byte limit".into())}Ok(b)
}
fn write(path:&Path,b:&[u8])->Result<(),String>{fs::OpenOptions::new().create_new(true).write(true).open(path).and_then(|mut f|f.write_all(b)).map_err(|e|e.to_string())}
fn read_json<T:serde::de::DeserializeOwned>(p:&Path)->Result<T,String>{serde_json::from_slice(&read(p,LIMIT)?).map_err(|e|e.to_string())}
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn setup(step:&HourStep)->Result<Pp,String>{Pp::setup(step,&*S1::ck_floor(),&*S2::ck_floor()).map_err(|e|format!("setup: {e:?}"))}
struct HashWriter {h:Sha256,n:u64}
impl Write for HashWriter {fn write(&mut self,b:&[u8])->io::Result<usize>{self.n=self.n.checked_add(b.len() as u64).ok_or_else(||io::Error::other("VK length"))?;if self.n>2*1024*1024*1024{return Err(io::Error::other("VK size cap"))}self.h.update(b);Ok(b.len())}fn flush(&mut self)->io::Result<()>{Ok(())}}
fn key_id(vk:&Vk)->Result<(String,u64),String>{let mut w=HashWriter{h:Sha256::new(),n:0};bincode::DefaultOptions::new().with_fixint_encoding().serialize_into(&mut w,vk).map_err(|e|e.to_string())?;Ok((hex::encode(w.h.finalize()),w.n))}
fn flags()->serde_json::Value{serde_json::json!({"source_authentication":false,"hold_necessity_proven":false,"near_nova_verified":false,"bitcoin_anchor_finality_verified":false,"can_authorize_oracle_epoch":false,"can_authorize_dlc_settlement":false,"production_ready":false})}
fn checked_output(proof:&Cs,vk:&Vk,claim:&Claim)->Result<(),String>{
 let init=claim.state(0)?;let expected=claim.state(8)?;
 let out=catch_unwind(AssertUnwindSafe(||proof.verify(vk,STEPS,&init))).map_err(|_|"malformed proof verifier panic")?.map_err(|e|format!("compressed verify: {e:?}"))?;
 if out!=expected{return Err("verified terminal state differs from receiver's checkpoint".into())}Ok(())
}
fn main_run()->Result<(),String>{
 let args:Vec<String>=env::args().collect();
 if args.len()!=5{return Err("usage: shz-hourly-index-nova prove WITNESS.json EXPECTED.json NEW_BUNDLE_DIR | verify SHAPE_FIXTURE.json EXPECTED.json BUNDLE_DIR".into())}
 let mode=args[1].as_str();let claim:Claim=read_json(Path::new(&args[3]))?;let init=claim.state(0)?;let expected=claim.state(8)?;
 let dir=Path::new(&args[4]);
 // For verification the fixture supplies only circuit shape. The same code uses a
 // fixed witness-independent shape for all records, including HOLD. It is public test data.
 let fixture:Fixture=read_json(Path::new(&args[2]))?;let steps=fixture.steps()?;
 let start=Instant::now();let pp=setup(&steps[0])?;let setup_sec=start.elapsed().as_secs_f64();
 let constraints=pp.num_constraints();let digest=hex::encode(pp.digest().to_repr().as_ref());
 if mode=="prove"{
  if fixture.claim()!=claim{return Err("witness checkpoint differs from independently supplied claim".into())}
  let t=Instant::now();let mut rs=Rs::new(&pp,&steps[0],&init).map_err(|e|format!("recursive init: {e:?}"))?;
  for(i,step) in steps.iter().enumerate(){rs.prove_step(&pp,step).map_err(|e|format!("fold {i}: {e:?}"))?;}
  let recursive_sec=t.elapsed().as_secs_f64();let out=rs.verify(&pp,STEPS,&init).map_err(|e|format!("recursive verify: {e:?}"))?;
  if out!=expected{return Err("recursive final state mismatch".into())}
  let t=Instant::now();let(pk,vk)=Cs::setup(&pp).map_err(|e|format!("compression setup: {e:?}"))?;let proof=Cs::prove(&pp,&pk,&rs).map_err(|e|format!("compression: {e:?}"))?;let compression_sec=t.elapsed().as_secs_f64();
  let t=Instant::now();checked_output(&proof,&vk,&claim)?;let verify_sec=t.elapsed().as_secs_f64();
  let bytes=bincode::DefaultOptions::new().with_fixint_encoding().with_limit(LIMIT).serialize(&proof).map_err(|e|e.to_string())?;
  let (key,key_bytes)=key_id(&vk)?;
  let manifest=Manifest{relation:RELATION.into(),nova_version:"0.76.0".into(),claim,steps:STEPS,verifier_key_sha256:key.clone(),proof_sha256:sha(&bytes)};
  fs::create_dir(dir).map_err(|e|e.to_string())?;write(&dir.join("proof.bin"),&bytes)?;write(&dir.join("manifest.json"),&serde_json::to_vec_pretty(&manifest).map_err(|e|e.to_string())?)?;
  let report=serde_json::json!({"relation":RELATION,"steps":STEPS,"recursive_verified":true,"compressed_verified":true,"constraint_counts":[constraints.0,constraints.1],"public_params_digest":digest,"verifier_key_sha256":key,"verifier_key_bytes":key_bytes,"proof_bytes":bytes.len(),"proof_sha256":sha(&bytes),"setup_seconds":setup_sec,"fold_seconds":recursive_sec,"compression_seconds":compression_sec,"verify_seconds":verify_sec,"flags":flags()});
  write(&dir.join("report.json"),&serde_json::to_vec_pretty(&report).map_err(|e|e.to_string())?)?;println!("{report}");
 }else if mode=="verify"{
  let m:Manifest=read_json(&dir.join("manifest.json"))?;
  if m.relation!=RELATION||m.nova_version!="0.76.0"||m.steps!=STEPS||m.claim!=claim{return Err("manifest does not match receiver claim".into())}
  let bytes=read(&dir.join("proof.bin"),LIMIT)?;if sha(&bytes)!=m.proof_sha256{return Err("proof digest mismatch".into())}
  let(_,vk)=Cs::setup(&pp).map_err(|e|format!("verification key setup: {e:?}"))?;let(key,key_bytes)=key_id(&vk)?;if key!=m.verifier_key_sha256{return Err("wrong locally reconstructed verifier identity".into())}
  let proof:Cs=catch_unwind(AssertUnwindSafe(||bincode::DefaultOptions::new().with_fixint_encoding().with_limit(LIMIT).reject_trailing_bytes().deserialize(&bytes))).map_err(|_|"proof decode panic")?.map_err(|e|e.to_string())?;
  checked_output(&proof,&vk,&claim)?;
  // Real proof, wrong receiver state: verifies a cryptographic rejection, not a metadata-only gate.
  let mut wrong=claim.clone();let mut root=hex::decode(&wrong.checkpoint_root).map_err(|e|e.to_string())?;root[0]^=1;wrong.checkpoint_root=hex::encode(root);
  if checked_output(&proof,&vk,&wrong).is_ok(){return Err("proof accepted altered receiver root".into())}
  if proof.verify(&vk,STEPS-1,&init).is_ok(){return Err("proof accepted wrong fold count".into())}
  println!("{}",serde_json::json!({"relation":RELATION,"independent_compressed_verified":true,"wrong_root_rejected":true,"wrong_step_count_rejected":true,"proof_sha256":sha(&bytes),"verifier_key_sha256":key,"verifier_key_bytes":key_bytes,"flags":flags()}));
 }else{return Err("unknown command".into())}Ok(())
}
fn main(){if let Err(e)=main_run(){eprintln!("{e}");std::process::exit(1);}}
