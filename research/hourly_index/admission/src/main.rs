//! Persist and independently verify the exact transparent admission relation.
use bincode::Options;
use ff::PrimeField;
use nova_snark::nova::{CompressedSNARK,PublicParams,RecursiveSNARK,VerifierKey};
use nova_snark::provider::{ipa_pc::EvaluationEngine,PallasEngine,VestaEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use shz_hourly_index_admission_nova::{AdmissionStep,Action,Claim,F,RELATION,ARITY,trace};
use std::{env,fs,io::{self,Read,Write},path::Path,time::Instant,panic::{catch_unwind,AssertUnwindSafe}};
type Pp=PublicParams<PallasEngine,VestaEngine,AdmissionStep>;
type Rs=RecursiveSNARK<PallasEngine,VestaEngine,AdmissionStep>;
type S1=RelaxedR1CSSNARK<PallasEngine,EvaluationEngine<PallasEngine>>;
type S2=RelaxedR1CSSNARK<VestaEngine,EvaluationEngine<VestaEngine>>;
type Cs=CompressedSNARK<PallasEngine,VestaEngine,AdmissionStep,S1,S2>;
type Vk=VerifierKey<PallasEngine,VestaEngine,AdmissionStep,S1,S2>;
const LIMIT:u64=4*1024*1024;
#[derive(Serialize,Deserialize,PartialEq,Eq,Debug)]#[serde(deny_unknown_fields)]
struct Manifest{relation:String,nova_version:String,claim:Claim,verifier_key_sha256:String,proof_sha256:String}
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
fn flags()->serde_json::Value{serde_json::json!({"structural_append_seal_history_proven":true,"source_authentication":false,"provider_completeness_proven":false,"duplicate_digest_global_nullifier_proven":false,"watermark_authority_proven":false,"near_nova_verified":false,"bitcoin_anchor_finality_verified":false,"can_authorize_oracle_epoch":false,"can_authorize_dlc_settlement":false,"production_ready":false})}
fn prove(actions:Vec<Action>,claim:Claim,dir:&Path)->Result<(),String>{let(init,final_z)=claim.states()?;let steps=trace(&actions,&claim)?;let t=Instant::now();let pp=setup()?;let setup_sec=t.elapsed().as_secs_f64();let constraints=pp.num_constraints();let pp_digest=hex::encode(pp.digest().to_repr().as_ref());
 let t=Instant::now();let mut r=Rs::new(&pp,&steps[0],&init).map_err(|e|format!("recursive init: {e:?}"))?;for(i,s)in steps.iter().enumerate(){r.prove_step(&pp,s).map_err(|e|format!("microstep {i}: {e:?}"))?;}let fold_seconds=t.elapsed().as_secs_f64();let v=r.verify(&pp,steps.len(),&init).map_err(|e|format!("recursive verification: {e:?}"))?;if v!=final_z{return Err("wrong recursive output".into())}
 let t=Instant::now();let(pk,vk)=Cs::setup(&pp).map_err(|e|format!("compress setup: {e:?}"))?;let p=Cs::prove(&pp,&pk,&r).map_err(|e|format!("compression: {e:?}"))?;let compression_seconds=t.elapsed().as_secs_f64();let t=Instant::now();verify_crypto(&p,&vk,steps.len(),&init,&final_z)?;let verify_seconds=t.elapsed().as_secs_f64();let b=bincode::DefaultOptions::new().with_fixint_encoding().with_limit(LIMIT).serialize(&p).map_err(|e|e.to_string())?;let(key,key_bytes)=key_id(&vk)?;let m=Manifest{relation:RELATION.into(),nova_version:"0.76.0".into(),claim:claim.clone(),verifier_key_sha256:key.clone(),proof_sha256:sha(&b)};
 fs::create_dir(dir).map_err(|e|e.to_string())?;write(&dir.join("proof.bin"),&b)?;write(&dir.join("manifest.json"),&serde_json::to_vec_pretty(&m).map_err(|e|e.to_string())?)?;let report=serde_json::json!({"relation":RELATION,"source":claim.header.source,"snapshot_pin":claim.pin,"steps":claim.steps,"reports":claim.header.count,"state_arity":ARITY,"recursive_verified":true,"compressed_verified":true,"constraints":[constraints.0,constraints.1],"public_params_digest":pp_digest,"verifier_key_sha256":key,"verifier_key_bytes":key_bytes,"proof_bytes":b.len(),"proof_sha256":sha(&b),"setup_seconds":setup_sec,"fold_seconds":fold_seconds,"compression_seconds":compression_seconds,"verify_seconds":verify_seconds,"flags":flags()});write(&dir.join("report.json"),&serde_json::to_vec_pretty(&report).map_err(|e|e.to_string())?)?;println!("{report}");Ok(())}
fn verify(claim:Claim,dir:&Path)->Result<(),String>{let(init,final_z)=claim.states()?;let m:Manifest=read_json(&dir.join("manifest.json"))?;if m.relation!=RELATION||m.nova_version!="0.76.0"||m.claim!=claim{return Err("wrong independent claim or relation".into())}let b=read(&dir.join("proof.bin"),LIMIT)?;if sha(&b)!=m.proof_sha256{return Err("proof digest mismatch".into())}
 let pp=setup()?;let(_,vk)=Cs::setup(&pp).map_err(|e|format!("verification setup: {e:?}"))?;let(key,key_bytes)=key_id(&vk)?;if key!=m.verifier_key_sha256{return Err("wrong reconstructed verifier identity".into())}let p=decode(&b)?;verify_crypto(&p,&vk,claim.steps,&init,&final_z)?;
 let mut wrong=init.clone();wrong[ARITY-1]=if claim.header.source=="pyth"{F::from(2)}else{F::from(1)};if verify_crypto(&p,&vk,claim.steps,&wrong,&final_z).is_ok(){return Err("accepted wrong source context".into())}let mut wrong=init.clone();wrong[11]+=F::from(1);if verify_crypto(&p,&vk,claim.steps,&wrong,&final_z).is_ok(){return Err("accepted forged sentinel genesis".into())}let mut wrong=final_z.clone();wrong[3]+=F::from(1);if verify_crypto(&p,&vk,claim.steps,&init,&wrong).is_ok(){return Err("accepted altered seal".into())}if verify_crypto(&p,&vk,claim.steps-1,&init,&final_z).is_ok(){return Err("accepted wrong step count".into())}let mut trailing=b.clone();trailing.push(0);if decode(&trailing).is_ok(){return Err("accepted trailing proof bytes".into())}
 println!("{}",serde_json::json!({"relation":RELATION,"source":claim.header.source,"snapshot_pin":claim.pin,"independent_compressed_verified":true,"wrong_source_rejected":true,"wrong_sentinel_rejected":true,"wrong_seal_rejected":true,"wrong_step_count_rejected":true,"trailing_proof_rejected":true,"proof_sha256":sha(&b),"verifier_key_sha256":key,"verifier_key_bytes":key_bytes,"flags":flags()}));Ok(())}
fn run()->Result<(),String>{let a:Vec<_>=env::args().collect();match a.get(1).map(String::as_str){Some("prove") if a.len()==5=>prove(read_json(Path::new(&a[2]))?,read_json(Path::new(&a[3]))?,Path::new(&a[4])),Some("verify") if a.len()==4=>verify(read_json(Path::new(&a[2]))?,Path::new(&a[3])),_=>Err("usage: shz-hourly-index-admission-nova prove OPS.json EXPECTED.json NEW_DIR | verify EXPECTED.json BUNDLE_DIR".into())}}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1)}}
