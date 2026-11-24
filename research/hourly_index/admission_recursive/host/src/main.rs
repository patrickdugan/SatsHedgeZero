//! Bounded CPU proof ladder. No network prover, fake receipts, Groth16 or KZG.
mod profile;
use bincode::Options;
use risc0_zkvm::{default_prover,ExecutorEnv,InnerReceipt,ProverOpts,Receipt};
use shz_admission_recursive_core::{benchmark_inputs,execute_leaf,expected_root,join,Claim,Input,Journal,Plan,RELATION};
use shz_admission_recursive_methods::{ADMIT_AGGREGATE_ELF,ADMIT_AGGREGATE_ID};
use std::{error::Error,fs,path::Path,time::Instant};
type R<T>=Result<T,Box<dyn Error>>;
const CAP:usize=4*1024*1024;
const CYCLE_CAP:u64=8*1024*1024;
fn read(path:&Path)->R<Vec<u8>>{use std::io::Read;let mut b=Vec::new();fs::File::open(path)?.take((CAP+1)as u64).read_to_end(&mut b)?;if b.len()>CAP{return Err("input cap".into())}Ok(b)}
fn codec()->impl Options{bincode::DefaultOptions::new().with_fixint_encoding().with_limit(CAP as u64).reject_trailing_bytes()}
fn verified(r:&Receipt,expected:&Journal)->R<()> {
 if !matches!(&r.inner,InnerReceipt::Succinct(s) if s.hashfn=="poseidon2"){return Err("real transparent succinct receipt required".into())}
 let ctx=risc0_zkvm::VerifierContext::empty()
  .with_suites(risc0_zkvm::VerifierContext::default_hash_suites().into_iter().filter(|(name,_)|name=="poseidon2").collect())
  .with_succinct_verifier_parameters(Default::default());
 r.verify_with_context(&ctx,ADMIT_AGGREGATE_ID)?;
 if expected.ctx.image_id!=ADMIT_AGGREGATE_ID||r.journal.bytes!=expected.encode()?||Journal::decode(&r.journal.bytes)?!=*expected{return Err("unexpected journal or image".into())}Ok(())
}
fn prove(input:&Input,assumptions:&[Receipt],expected:&Journal)->R<(Receipt,serde_json::Value)>{
 let mut b=ExecutorEnv::builder();b.session_limit(Some(CYCLE_CAP)).segment_limit_po2(18);b.write(input)?;
 for a in assumptions{b.add_assumption(a.clone());}
 let env=b.build()?;let start=Instant::now();
 let result=default_prover().prove_with_opts(env,ADMIT_AGGREGATE_ELF,&ProverOpts::succinct())?;
 let elapsed=start.elapsed().as_secs_f64();let r=result.receipt;
 let t=Instant::now();verified(&r,expected)?;let verify=t.elapsed().as_secs_f64();
 let bytes=codec().serialize(&r)?;if bytes.len()>CAP{return Err("receipt cap".into())}
 let m=serde_json::json!({"height":expected.height,"folds":expected.end_op-expected.start_op,"reports":expected.end_reports-expected.start_reports,"total_cycles":result.stats.total_cycles,"user_cycles":result.stats.user_cycles,"vm_segments":result.stats.segments,"prove_seconds":elapsed,"verify_seconds":verify,"receipt_bytes":bytes.len(),"seal_bytes":r.seal_size(),"succinct_verified":true});
 println!("{m}");Ok((r,m))
}
fn independent(c:&Claim,segments:usize,path:&Path)->R<serde_json::Value>{
 let expected=expected_root(c,ADMIT_AGGREGATE_ID,segments)?;
 let bytes=read(path)?;let r:Receipt=codec().deserialize(&bytes)?;
 let t=Instant::now();verified(&r,&expected)?;let verify_seconds=t.elapsed().as_secs_f64();
 // Real root proof against independent changed statements and image.
 let mut wrong=expected.clone();wrong.end[0]^=1;
 if verified(&r,&wrong).is_ok(){return Err("wrong endpoint accepted".into())}
 let mut wrong=expected.clone();wrong.ctx.image_id[0]^=1;
 if verified(&r,&wrong).is_ok()||r.verify(wrong.ctx.image_id).is_ok(){return Err("wrong image accepted".into())}
 let mut wrong=expected.clone();wrong.ctx.snapshot_pin[0]^=1;
 if verified(&r,&wrong).is_ok(){return Err("wrong snapshot accepted".into())}
 let mut wrong=expected.clone();wrong.start[0]^=1;
 if verified(&r,&wrong).is_ok(){return Err("wrong genesis accepted".into())}
 let mut wrong=expected.clone();wrong.end_op+=1;
 if verified(&r,&wrong).is_ok(){return Err("wrong fold count accepted".into())}
 let mut bad=bytes.clone();bad.push(0);if codec().deserialize::<Receipt>(&bad).is_ok(){return Err("trailing bytes accepted".into())}
 let mut changed=r.clone();changed.journal.bytes[0]^=1;
 if changed.verify(ADMIT_AGGREGATE_ID).is_ok(){return Err("mutated journal verified".into())}
 Ok(serde_json::json!({"relation":RELATION,"snapshot_pin":c.pin,"segments":segments,"height":expected.height,"folds":c.steps,"image_id_words":ADMIT_AGGREGATE_ID,"root_receipt_bytes":bytes.len(),"verify_seconds":verify_seconds,"independent_succinct_verified":true,"wrong_endpoint_rejected":true,"wrong_image_rejected":true,"wrong_snapshot_rejected":true,"wrong_genesis_rejected":true,"wrong_fold_count_rejected":true,"trailing_rejected":true,"tampered_journal_rejected":true,"nova_wrapped":false,"source_authentication":false,"watermark_authority":false,"provider_completeness":false,"near_verified":false,"production_ready":false}))
}
fn run()->R<()> {
 // Refuse remote/default service selection and explicit developer mode.
 if !matches!(std::env::var("RISC0_PROVER").as_deref(),Ok("local")){return Err("set RISC0_PROVER=local explicitly".into())}
 let a:Vec<_>=std::env::args().collect();
 match a.get(1).map(String::as_str){
 Some("prove") if a.len()==5=>{
  let c:Claim=serde_json::from_slice(&read(Path::new(&a[2]))?)?;let p:Plan=serde_json::from_slice(&read(Path::new(&a[3]))?)?;
  if c.header.count>128||p.segments.len()>4{return Err("registered proof budget: <=128 reports and <=4 leaves".into())}
  let input=benchmark_inputs(&p,&c,ADMIT_AGGREGATE_ID)?;let n=input.len();if n<2{return Err("at least two leaves required".into())}
  let out=Path::new(&a[4]);fs::create_dir(out)?;
  let expected=expected_root(&c,ADMIT_AGGREGATE_ID,n)?;
  let mut layer:Vec<(Receipt,Journal)>=vec![];let mut metrics=vec![];let mut negative=None;
  for w in input{let (_,j)=execute_leaf(&w)?;let (r,m)=prove(&Input::Leaf(w),&[],&j)?;metrics.push(m);layer.push((r,j));}
  while layer.len()>1{
   let mut next=vec![];for pair in layer.chunks_exact(2){let(l,lj)=&pair[0];let(r,rj)=&pair[1];let j=join(lj,rj)?;
    let w=Input::Join{left:lj.encode()?,right:rj.encode()?};
    let (receipt,m)=prove(&w,&[l.clone(),r.clone()],&j)?;
    if negative.is_none(){
     // Real left receipt substituted for right. Journal input and all parent
     // interval constraints remain correct. A valid unconditional result is forbidden.
     let rejection=match prove(&w,&[l.clone(),l.clone()],&j){Ok(_)=>return Err("substituted child proved a valid parent".into()),Err(e)=>e.to_string()};
     let mut forged=l.clone();forged.journal.bytes=r.journal.bytes.clone();
     if forged.verify(ADMIT_AGGREGATE_ID).is_ok(){return Err("genuine child proof accepted substituted journal".into())}
     negative=Some(serde_json::json!({"actual_child_substitution_rejected":true,"substituted_child_journal_rejected":true,"rejection":rejection}));
    }
    metrics.push(m);next.push((receipt,j));
   }layer=next;
  }
  let (root,j)=layer.pop().ok_or("empty tree")?;if j!=expected{return Err("unexpected aggregate endpoint".into())}verified(&root,&expected)?;
  let bytes=codec().serialize(&root)?;fs::write(out.join("root.bin"),bytes)?;fs::write(out.join("journal.bin"),root.journal.bytes.as_slice())?;
  fs::write(out.join("metrics.json"),serde_json::to_vec_pretty(&metrics)?)?;
  fs::write(out.join("negative.json"),serde_json::to_vec_pretty(&negative.ok_or("missing child substitution control")?)?)?;
  let v=independent(&c,n,&out.join("root.bin"))?;fs::write(out.join("verification.json"),serde_json::to_vec_pretty(&v)?)?;println!("{v}");
 },
 Some("expected") if a.len()==4=>{
  let c:Claim=serde_json::from_slice(&read(Path::new(&a[2]))?)?;
  let n=a[3].parse::<usize>()?;
  let j=expected_root(&c,ADMIT_AGGREGATE_ID,n)?;
  println!("{}",serde_json::json!({"image_id_words":ADMIT_AGGREGATE_ID,"journal_hex":hex::encode(j.encode()?),"snapshot_pin":c.pin,"sdk":"3.1.0"}));
 },
 Some("profile") if a.len()==6=>{
  let c:Claim=serde_json::from_slice(&read(Path::new(&a[2]))?)?;
  let n=a[3].parse::<usize>()?;
  let expected=expected_root(&c,ADMIT_AGGREGATE_ID,n)?;
  let bytes=read(Path::new(&a[4]))?;
  let r:Receipt=codec().deserialize(&bytes)?;
  verified(&r,&expected)?;
  let mut bad=r.clone();
  match &mut bad.inner{InnerReceipt::Succinct(s) if !s.seal.is_empty()=>{let k=s.seal.len()-1;s.seal[k]^=1;},_=>return Err("missing seal".into())}
  let rejected=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||verified(&bad,&expected))).map_or(true,|v|v.is_err());
  if !rejected{return Err("tampered seal unexpectedly verified".into())}
  fs::write(&a[5],codec().serialize(&bad)?)?;
  let mut report=profile::profile(&r,ADMIT_AGGREGATE_ID)?;
  report["tampered_seal_rejected"]=serde_json::json!(true);
  report["receipt_bytes"]=serde_json::json!(bytes.len());
  println!("{report}");
 },
 Some("verify") if a.len()==5=>{let c:Claim=serde_json::from_slice(&read(Path::new(&a[2]))?)?;let n=a[3].parse::<usize>()?;if n<2{return Err("aggregate needs two leaves".into())}println!("{}",independent(&c,n,Path::new(&a[4]))?);},
 _=>return Err("usage: host prove EXPECTED.json PLAN.json NEW_DIR | verify EXPECTED.json SEGMENTS ROOT.bin | expected EXPECTED.json SEGMENTS | profile EXPECTED.json SEGMENTS ROOT.bin MUTATED.bin".into())
 }
 Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1)}}
