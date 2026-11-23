//! Persist and independently verify the exact transparent admission relation.
use bincode::Options;
use ff::PrimeField;
use nova_snark::nova::{CompressedSNARK,PublicParams,RecursiveSNARK,VerifierKey};
use nova_snark::provider::{ipa_pc::EvaluationEngine,PallasEngine,VestaEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use shz_hourly_index_admission_segments::{AdmissionStep,Claim,F,RELATION,ARITY,Plan,Segment,validate_plan,walk_segment};
use std::{env,fs,io::{self,Read,Write},path::Path,time::Instant,panic::{catch_unwind,AssertUnwindSafe}};
type Pp=PublicParams<PallasEngine,VestaEngine,AdmissionStep>;
type Rs=RecursiveSNARK<PallasEngine,VestaEngine,AdmissionStep>;
type S1=RelaxedR1CSSNARK<PallasEngine,EvaluationEngine<PallasEngine>>;
type S2=RelaxedR1CSSNARK<VestaEngine,EvaluationEngine<VestaEngine>>;
type Cs=CompressedSNARK<PallasEngine,VestaEngine,AdmissionStep,S1,S2>;
type Vk=VerifierKey<PallasEngine,VestaEngine,AdmissionStep,S1,S2>;
const LIMIT:u64=4*1024*1024;
#[derive(Serialize,Deserialize,PartialEq,Eq,Debug)]#[serde(deny_unknown_fields)]
struct Manifest{schema:String,relation:String,nova_version:String,snapshot_pin:String,segment:Segment,verifier_key_sha256:String,proof_sha256:String}
fn read(path:&Path,limit:u64)->Result<Vec<u8>,String>{let mut f=fs::File::open(path).map_err(|e|e.to_string())?;let mut b=Vec::new();(&mut f).take(limit+1).read_to_end(&mut b).map_err(|e|e.to_string())?;if b.len() as u64>limit{return Err("input exceeds byte limit".into())}Ok(b)}
fn write(path:&Path,b:&[u8])->Result<(),String>{fs::OpenOptions::new().create_new(true).write(true).open(path).and_then(|mut f|f.write_all(b)).map_err(|e|e.to_string())}
fn read_json<T:serde::de::DeserializeOwned>(p:&Path)->Result<T,String>{serde_json::from_slice(&read(p,LIMIT)?).map_err(|e|e.to_string())}
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn setup()->Result<Pp,String>{Pp::setup(&AdmissionStep::blank(),&*S1::ck_floor(),&*S2::ck_floor()).map_err(|e|format!("setup: {e:?}"))}
struct HashWriter{h:Sha256,n:u64}
impl Write for HashWriter{fn write(&mut self,b:&[u8])->io::Result<usize>{self.n=self.n.checked_add(b.len() as u64).ok_or_else(||io::Error::other("VK length"))?;if self.n>4*1024*1024*1024{return Err(io::Error::other("VK cap"))}self.h.update(b);Ok(b.len())}fn flush(&mut self)->io::Result<()>{Ok(())}}
fn key_id(vk:&Vk)->Result<(String,u64),String>{let mut w=HashWriter{h:Sha256::new(),n:0};bincode::DefaultOptions::new().with_fixint_encoding().serialize_into(&mut w,vk).map_err(|e|e.to_string())?;Ok((hex::encode(w.h.finalize()),w.n))}
fn verify_crypto(p:&Cs,v:&Vk,steps:usize,init:&[F],expected:&[F])->Result<(),String>{let out=catch_unwind(AssertUnwindSafe(||p.verify(v,steps,init))).map_err(|_|"malformed proof verifier panic")?.map_err(|e|format!("compressed verify: {e:?}"))?;if out!=expected{return Err("wrong terminal frontier".into())}Ok(())}
fn decode(b:&[u8])->Result<Cs,String>{catch_unwind(AssertUnwindSafe(||bincode::DefaultOptions::new().with_fixint_encoding().with_limit(LIMIT).reject_trailing_bytes().deserialize(b))).map_err(|_|"proof decode panic")?.map_err(|e|e.to_string())}
const BUNDLE_SCHEMA:&str="shz/admission-segment-proof/v1";
fn flags()->serde_json::Value{serde_json::json!({"source_authentication":false,"provider_completeness_proven":false,"watermark_authority_proven":false,"near_nova_verified":false,"bitcoin_anchor_finality_verified":false,"can_authorize_dlc_settlement":false,"production_ready":false,"recursive_aggregate_verified":false})}
fn prove(plan:Plan,claim:Claim,index:usize,dir:&Path)->Result<(),String>{
 validate_plan(&plan,&claim)?;
 let seg=plan.segments.get(index).ok_or("segment index")?;
 let cap=match env::var("SHZ_SEGMENT_MAX_FOLDS"){Ok(v)=>v.parse::<usize>().map_err(|_|"invalid fold budget")?,Err(_)=>256};
 if seg.folds>cap{return Err("segment exceeds explicit prover budget".into())}
 let (init,final_z)=seg.states(&claim)?;let t=Instant::now();let pp=setup()?;let setup_sec=t.elapsed().as_secs_f64();let constraints=pp.num_constraints();let digest=hex::encode(pp.digest().to_repr().as_ref());
 let t=Instant::now();let mut recursive:Option<Rs>=None;let mut steps=0usize;
 walk_segment(seg,&claim,|step|{
  if recursive.is_none(){recursive=Some(Rs::new(&pp,step,&init).map_err(|e|format!("init: {e:?}"))?);}
  recursive.as_mut().unwrap().prove_step(&pp,step).map_err(|e|format!("fold {steps}: {e:?}"))?;steps+=1;Ok(())
 })?;
 let r=recursive.ok_or("empty segment")?;if steps!=seg.folds{return Err("segment fold mismatch".into())}
 let fold_seconds=t.elapsed().as_secs_f64();if r.verify(&pp,steps,&init).map_err(|e|format!("recursive verify: {e:?}"))?!=final_z{return Err("wrong recursive terminal state".into())}
 let t=Instant::now();let(pk,vk)=Cs::setup(&pp).map_err(|e|format!("compression setup: {e:?}"))?;let proof=Cs::prove(&pp,&pk,&r).map_err(|e|format!("compression: {e:?}"))?;let compression_seconds=t.elapsed().as_secs_f64();let t=Instant::now();verify_crypto(&proof,&vk,steps,&init,&final_z)?;let verify_seconds=t.elapsed().as_secs_f64();
 let b=bincode::DefaultOptions::new().with_fixint_encoding().with_limit(LIMIT).serialize(&proof).map_err(|e|e.to_string())?;let(key,key_bytes)=key_id(&vk)?;
 let m=Manifest{schema:BUNDLE_SCHEMA.into(),relation:RELATION.into(),nova_version:"0.76.0".into(),snapshot_pin:claim.pin.clone(),segment:seg.clone(),verifier_key_sha256:key.clone(),proof_sha256:sha(&b)};
 fs::create_dir(dir).map_err(|e|e.to_string())?;write(&dir.join("proof.bin"),&b)?;write(&dir.join("manifest.json"),&serde_json::to_vec_pretty(&m).map_err(|e|e.to_string())?)?;
 let report=serde_json::json!({"schema":BUNDLE_SCHEMA,"relation":RELATION,"index":index,"steps":steps,"start_operation":seg.before.operations,"end_operation":seg.after.operations,"reports":seg.after.leaf_count-seg.before.leaf_count,"snapshot_pin":claim.pin,"state_arity":ARITY,"recursive_verified":true,"compressed_segment_verified":true,"whole_history_verified":false,"constraints":[constraints.0,constraints.1],"public_params_digest":digest,"verifier_key_sha256":key,"verifier_key_bytes":key_bytes,"proof_bytes":b.len(),"proof_sha256":sha(&b),"setup_seconds":setup_sec,"fold_seconds":fold_seconds,"compression_seconds":compression_seconds,"verify_seconds":verify_seconds,"flags":flags()});
 write(&dir.join("report.json"),&serde_json::to_vec_pretty(&report).map_err(|e|e.to_string())?)?;println!("{report}");Ok(())
}
fn verify(plan:Plan,claim:Claim,dir:&Path)->Result<(),String>{
 validate_plan(&plan,&claim)?;
 // Reconstruct one approved verification key for the whole chain. Do not accept
 // a verifier key, initial state, or final snapshot pin from a proof bundle.
 let t=Instant::now();let pp=setup()?;let(_,vk)=Cs::setup(&pp).map_err(|e|format!("verification setup: {e:?}"))?;let(key,key_bytes)=key_id(&vk)?;let setup_seconds=t.elapsed().as_secs_f64();
 let t=Instant::now();let mut previous=shz_hourly_index_admission_packed_nova::claim_states(&claim)?.0;let mut digests=Vec::new();let mut total_bytes=0usize;let mut total_folds=0usize;
 let mut wrong_start_rejected=false;let mut wrong_end_rejected=false;let mut wrong_count_rejected=false;let mut substitution_rejected=false;let mut trailing_rejected=false;
 for seg in &plan.segments{
  let path=dir.join(format!("segment-{}",seg.index));let m:Manifest=read_json(&path.join("manifest.json"))?;
  if m.schema!=BUNDLE_SCHEMA||m.relation!=RELATION||m.nova_version!="0.76.0"||m.snapshot_pin!=claim.pin||m.segment!=*seg||m.verifier_key_sha256!=key{return Err(format!("segment {} manifest/context/key mismatch",seg.index))}
  let b=read(&path.join("proof.bin"),LIMIT)?;if sha(&b)!=m.proof_sha256{return Err("proof digest mismatch".into())}
  let p=decode(&b)?;let(init,end)=seg.states(&claim)?;if init!=previous{return Err("verified-chain boundary mismatch".into())}
  verify_crypto(&p,&vk,seg.folds,&init,&end)?;previous=end.clone();total_bytes+=b.len();total_folds+=seg.folds;digests.push(serde_json::json!({"index":seg.index,"proof_sha256":m.proof_sha256,"folds":seg.folds,"proof_bytes":b.len()}));
  if seg.index==0{
   // Real cryptographic negative controls: bypass manifest checks and reuse the
   // decoded proof against changed receiver inputs, outputs and segment count.
   let mut bad=init.clone();bad[0]+=F::from(1);wrong_start_rejected=verify_crypto(&p,&vk,seg.folds,&bad,&end).is_err();
   let mut bad=end.clone();bad[1]+=F::from(1);wrong_end_rejected=verify_crypto(&p,&vk,seg.folds,&init,&bad).is_err();
   wrong_count_rejected=verify_crypto(&p,&vk,seg.folds+1,&init,&end).is_err();
   let mut trailing=b.clone();trailing.push(0);trailing_rejected=decode(&trailing).is_err();
   if let Some(other)=plan.segments.get(1){let(a,b)=other.states(&claim)?;substitution_rejected=verify_crypto(&p,&vk,other.folds,&a,&b).is_err();}
  }
 }
 let expected=shz_hourly_index_admission_packed_nova::claim_states(&claim)?.1;
 if previous!=expected||total_folds!=claim.steps||!wrong_start_rejected||!wrong_end_rejected||!wrong_count_rejected||!trailing_rejected||(plan.segments.len()>1&&!substitution_rejected){return Err("chain terminal or cryptographic negative control failed".into())}
 println!("{}",serde_json::json!({"schema":"shz/admission-proof-chain-verification/v1","relation":RELATION,"snapshot_pin":claim.pin,"source":claim.header.source,"reports":claim.header.count,"segments":plan.segments.len(),"folds":total_folds,"state_arity":ARITY,"proof_chain_verified":true,"structural_append_seal_history_proven":true,"single_succinct_proof":false,"recursive_aggregate_verified":false,"wrong_start_rejected":wrong_start_rejected,"wrong_end_rejected":wrong_end_rejected,"wrong_count_rejected":wrong_count_rejected,"wrong_segment_rejected":if plan.segments.len()>1{Some(substitution_rejected)}else{None},"trailing_rejected":trailing_rejected,"key_setup_seconds":setup_seconds,"chain_verification_seconds":t.elapsed().as_secs_f64(),"total_proof_bytes":total_bytes,"verifier_key_sha256":key,"verifier_key_bytes":key_bytes,"proofs":digests,"flags":flags()}));Ok(())
}
fn run()->Result<(),String>{
 let a:Vec<_>=env::args().collect();match a.get(1).map(String::as_str){
  Some("prove") if a.len()==6=>prove(read_json(Path::new(&a[2]))?,read_json(Path::new(&a[3]))?,a[4].parse().map_err(|_|"bad segment index")?,Path::new(&a[5])),
  Some("verify") if a.len()==5=>verify(read_json(Path::new(&a[2]))?,read_json(Path::new(&a[3]))?,Path::new(&a[4])),
  Some("trace") if a.len()==4=>{let p:Plan=read_json(Path::new(&a[2]))?;let c:Claim=read_json(Path::new(&a[3]))?;validate_plan(&p,&c)?;for s in &p.segments{walk_segment(s,&c,|_|Ok(()))?;}println!("{}",serde_json::json!({"native_segments_verified":true,"segments":p.segments.len(),"folds":c.steps,"snapshot_pin":c.pin,"proof_chain_verified":false}));Ok(())},
  _=>Err("usage: shz-hourly-index-admission-segments prove PLAN EXPECTED INDEX NEW_DIR | verify PLAN EXPECTED BUNDLE_DIR | trace PLAN EXPECTED".into())}
}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1)}}
