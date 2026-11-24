//! Count actual verifier-facing hash and Fiat-Shamir calls without altering
//! the upstream algorithms. This is a measurement shim, not a new verifier.
use risc0_core::field::baby_bear::{BabyBear,BabyBearElem,BabyBearExtElem};
use risc0_zkp::core::{digest::Digest,hash::{HashFn,HashSuite,Rng,RngFactory,poseidon2::Poseidon2HashSuite}};
use risc0_zkvm::{InnerReceipt,Receipt,VerifierContext,SuccinctReceiptVerifierParameters};
use std::{collections::BTreeMap,rc::Rc,sync::{Arc,atomic::{AtomicU64,Ordering}},time::Instant};

#[derive(Default)]
struct Counts {
 pairs:AtomicU64, elem_calls:AtomicU64, ext_calls:AtomicU64,
 elems:AtomicU64, ext_elems:AtomicU64, digest_checks:AtomicU64,
 hash_permutations:AtomicU64, rng_instances:AtomicU64, rng_mix:AtomicU64,
 rng_bits:AtomicU64, rng_elem:AtomicU64, rng_ext:AtomicU64,
}
fn inc(v:&AtomicU64,n:u64){v.fetch_add(n,Ordering::Relaxed);}
fn get(v:&AtomicU64)->u64{v.load(Ordering::Relaxed)}
fn permutations(n:usize)->u64{n.div_ceil(16).max(1) as u64}
struct CountingHash(Arc<Counts>);
impl HashFn<BabyBear> for CountingHash {
 fn hash_pair(&self,a:&Digest,b:&Digest)->Box<Digest>{
  inc(&self.0.pairs,1);inc(&self.0.hash_permutations,1);
  Poseidon2HashSuite::new_suite().hashfn.hash_pair(a,b)
 }
 fn hash_elem_slice(&self,s:&[BabyBearElem])->Box<Digest>{
  inc(&self.0.elem_calls,1);inc(&self.0.elems,s.len() as u64);
  inc(&self.0.hash_permutations,permutations(s.len()));
  Poseidon2HashSuite::new_suite().hashfn.hash_elem_slice(s)
 }
 fn hash_ext_elem_slice(&self,s:&[BabyBearExtElem])->Box<Digest>{
  inc(&self.0.ext_calls,1);inc(&self.0.ext_elems,s.len() as u64);
  inc(&self.0.hash_permutations,permutations(4*s.len()));
  Poseidon2HashSuite::new_suite().hashfn.hash_ext_elem_slice(s)
 }
 fn is_digest_valid(&self,d:&Digest)->bool{
  inc(&self.0.digest_checks,1);Poseidon2HashSuite::new_suite().hashfn.is_digest_valid(d)
 }
}
struct CountingRng{inner:Box<dyn Rng<BabyBear>>,c:Arc<Counts>}
impl Rng<BabyBear> for CountingRng{
 fn mix(&mut self,d:&Digest){inc(&self.c.rng_mix,1);self.inner.mix(d)}
 fn random_bits(&mut self,n:usize)->u32{inc(&self.c.rng_bits,1);self.inner.random_bits(n)}
 fn random_elem(&mut self)->BabyBearElem{inc(&self.c.rng_elem,1);self.inner.random_elem()}
 fn random_ext_elem(&mut self)->BabyBearExtElem{inc(&self.c.rng_ext,1);self.inner.random_ext_elem()}
}
struct CountingFactory{inner:Rc<dyn RngFactory<BabyBear>>,c:Arc<Counts>}
impl RngFactory<BabyBear> for CountingFactory{
 fn new_rng(&self)->Box<dyn Rng<BabyBear>>{
  inc(&self.c.rng_instances,1);
  Box::new(CountingRng{inner:self.inner.new_rng(),c:self.c.clone()})
 }
}
pub fn profile(r:&Receipt,image:[u32;8])->Result<serde_json::Value,Box<dyn std::error::Error>>{
 let s=match &r.inner{InnerReceipt::Succinct(s) if s.hashfn=="poseidon2"=>s,_=>return Err("poseidon2 succinct receipt required".into())};
 let counts=Arc::new(Counts::default());
 let original=Poseidon2HashSuite::new_suite();
 let suite=HashSuite{name:original.name,hashfn:Rc::new(CountingHash(counts.clone())),
  rng:Rc::new(CountingFactory{inner:original.rng,c:counts.clone()})};
 let params=SuccinctReceiptVerifierParameters::default();
 let root=params.control_root.to_string();
 let ctx=VerifierContext::empty().with_suites(BTreeMap::from([("poseidon2".into(),suite)]))
   .with_succinct_verifier_parameters(params);
 let t=Instant::now();r.verify_with_context(&ctx,image)?;
 let c=&*counts;
 if get(&c.pairs)==0||get(&c.rng_mix)==0{return Err("missing measured verifier work".into())}
 Ok(serde_json::json!({
   "sdk":"3.1.0","hashfn":s.hashfn,"control_id":s.control_id.to_string(),
   "control_root":root,"verifier_parameters":s.verifier_parameters.to_string(),
   "seal_words":s.seal.len(),"seal_bytes":r.seal_size(),
   "hash_pair_calls":get(&c.pairs),"hash_elem_calls":get(&c.elem_calls),
   "hash_ext_elem_calls":get(&c.ext_calls),"hashed_base_elements":get(&c.elems),
   "hashed_extension_elements":get(&c.ext_elems),"digest_validity_calls":get(&c.digest_checks),
   "poseidon_permutations_in_hash_calls":get(&c.hash_permutations),
   "rng_instances":get(&c.rng_instances),"rng_mix_calls":get(&c.rng_mix),
   "rng_bits_calls":get(&c.rng_bits),"rng_elem_calls":get(&c.rng_elem),"rng_ext_calls":get(&c.rng_ext),
   "instrumented_verify_seconds":t.elapsed().as_secs_f64(),
   "actual_succinct_verified":true,"sha256_and_field_operation_counts_complete":false,
   "near_verified":false,"production_ready":false
 }))
}
