//! Exact upstream Poseidon2 permutation with reduced arithmetic overhead.
//! RISC Zero 3.1.0 / risc0-zkp 3.0.6, BabyBear Montgomery representation.
//! No change to proof parameters, hash function, transcript RNG or encoding.
//! See upstream Apache-2.0 implementation in risc0/zkp/src/core/hash/poseidon2.
#![forbid(unsafe_code)]
use risc0_core::field::{
    baby_bear::{BabyBear,BabyBearElem,BabyBearExtElem,P},
    ExtElem,
};
use risc0_zkp::core::{
    digest::Digest,
    hash::{HashFn,HashSuite,poseidon2::{Poseidon2HashSuite,CELLS,ROUND_CONSTANTS,M_INT_DIAG_HZN,ROUNDS_HALF_FULL,ROUNDS_PARTIAL}},
};
use std::rc::Rc;
const WIDTH:usize=24;
const RATE:usize=16;
const FULL:usize=8;
const PARTIAL:usize=21;
const TOTAL:usize=FULL+PARTIAL;
const _:()=assert!(CELLS==WIDTH && ROUNDS_HALF_FULL==4 && ROUNDS_PARTIAL==PARTIAL);
const _:()=assert!(P==2013265921);
const fn constants()->[u32;WIDTH*TOTAL] {
    let mut out=[0;WIDTH*TOTAL];
    let mut i=0;
    while i<out.len(){out[i]=ROUND_CONSTANTS[i].as_u32_montgomery();i+=1;}
    out
}
const fn diagonal()->[u32;WIDTH]{
    let mut out=[0;WIDTH];let mut i=0;
    while i<WIDTH{out[i]=M_INT_DIAG_HZN[i].as_u32_montgomery();i+=1;}
    out
}
const RC:[u32;WIDTH*TOTAL]=constants();
const DIAG:[u32;WIDTH]=diagonal();
#[inline(always)]
fn reduce(x:u64)->u32{(x%P as u64)as u32}
#[inline(always)]
fn add(a:u32,b:u32)->u32{let t=a+b;if t>=P{t-P}else{t}}
#[inline(always)]
fn mul(a:u32,b:u32)->u32{
    let t=a as u64*b as u64;
    let red=0u32.wrapping_sub(t as u32).wrapping_mul(0x88000001);
    // t < P^2, red*P < 2^32*P, sum < 2^64. Both operands reduced.
    let u=((t+red as u64*P as u64)>>32)as u32;
    if u>=P{u-P}else{u}
}
#[inline(always)]
fn sbox(a:u32)->u32{let a2=mul(a,a);let a4=mul(a2,a2);mul(mul(a4,a2),a)}
/// Same 4x4 circulant blocks as upstream. All intermediates are
/// nonnegative raw Montgomery integers. Each output < 112*P < 2^38
/// before its single modular reduction. No conversion to ordinary residues.
#[inline]
fn external(x:&mut [u32;WIDTH]){
    let mut y=[0u64;WIDTH];
    let mut sums=[0u64;4];
    for i in (0..WIDTH).step_by(4){
        let a=x[i] as u64;let b=x[i+1] as u64;let c=x[i+2] as u64;let d=x[i+3] as u64;
        let t0=a+b;let t1=c+d;
        let t2=2*b+t1;let t3=2*d+t0;
        let t4=4*t1+t3;let t5=4*t0+t2;
        let v=[t3+t5,t5,t2+t4,t4];
        for j in 0..4{y[i+j]=v[j];sums[j]+=v[j];}
    }
    for i in 0..WIDTH{x[i]=reduce(y[i]+sums[i%4]);}
}
#[inline]
fn internal(x:&mut [u32;WIDTH]){
    // sum < 24*P < 2^36; one reduction for the entire sum.
    let sum=reduce(x.iter().map(|&v|v as u64).sum());
    for i in 0..WIDTH{x[i]=add(sum,mul(DIAG[i],x[i]));}
}
#[inline]
fn full(x:&mut [u32;WIDTH],round:usize){
    for i in 0..WIDTH{x[i]=sbox(add(x[i],RC[round*WIDTH+i]));}
    external(x)
}
/// Private helper: all cells are reduced Montgomery residues by construction.
fn mix(x:&mut [u32;WIDTH]){
    external(x);
    for r in 0..4{full(x,r);}
    for r in 4..4+PARTIAL{
        x[0]=sbox(add(x[0],RC[r*WIDTH]));
        internal(x);
    }
    for r in 4+PARTIAL..TOTAL{full(x,r);}
}
fn hash_words(words:impl Iterator<Item=u32>)->Box<Digest>{
    let mut x=[0u32;WIDTH];let mut used=0;let mut any=false;
    for word in words{
        assert!(word<P,"noncanonical BabyBear word");
        x[used]=word;used+=1;any=true;
        if used==RATE{mix(&mut x);used=0;}
    }
    // Upstream overwrite-mode sponge; pad only a final partial block
    // or the empty input. Never add an extra block for a full final block.
    if used!=0||!any{x[used..RATE].fill(0);mix(&mut x);}
    Box::new(Digest::from(<[u32;8]>::try_from(&x[..8]).unwrap()))
}
pub struct FastHash;
impl HashFn<BabyBear> for FastHash{
    fn hash_pair(&self,a:&Digest,b:&Digest)->Box<Digest>{
        hash_words(a.as_words().iter().chain(b.as_words()).copied())
    }
    fn hash_elem_slice(&self,s:&[BabyBearElem])->Box<Digest>{
        hash_words(s.iter().map(|x|x.as_u32_montgomery()))
    }
    fn hash_ext_elem_slice(&self,s:&[BabyBearExtElem])->Box<Digest>{
        hash_words(s.iter().flat_map(|x|x.subelems().iter().map(|x|x.as_u32_montgomery())))
    }
    fn is_digest_valid(&self,d:&Digest)->bool{d.as_words().iter().all(|&x|x<P)}
}
/// Keep the upstream Fiat-Shamir RNG exactly unchanged.
pub fn fast_suite()->HashSuite<BabyBear>{
    let s=Poseidon2HashSuite::new_suite();
    HashSuite{name:s.name,hashfn:Rc::new(FastHash),rng:s.rng}
}
pub fn repeated_pairs(n:u32,fast:bool)->[u32;8]{
    let suite=if fast{fast_suite()}else{Poseidon2HashSuite::new_suite()};
    let mut a=Digest::from([1,2,3,4,5,6,7,8]);
    let b=Digest::from([P-1,P-2,P-3,P-4,P-5,P-6,P-7,P-8]);
    for _ in 0..n{a=*suite.hashfn.hash_pair(&a,&b);}
    a.as_words().try_into().unwrap()
}
#[cfg(test)]
mod tests{
    use super::*;
    use risc0_zkp::core::hash::poseidon2::poseidon2_mix;
    fn random(s:&mut u32)->u32{*s=s.wrapping_mul(1664525).wrapping_add(1013904223);*s%P}
    #[test]
    fn exact_permutation_4096_states(){
        let mut seed=0x96372abdu32;
        for i in 0..4096{
            let mut x=std::array::from_fn(|j|match i{0=>0,1=>P-1,2=>j as u32,_=>random(&mut seed)});
            let mut y=x.map(BabyBearElem::new_raw);
            mix(&mut x);poseidon2_mix(&mut y);
            assert_eq!(x,y.map(|e|e.as_u32_montgomery()),"permutation mismatch {i}");
        }
    }
    #[test]
    fn exact_all_hash_interfaces_and_padding(){
        let slow=Poseidon2HashSuite::new_suite();let fast=fast_suite();
        let mut seed=987654321;
        for n in [0,1,7,8,15,16,17,24,31,32,33,63,64,65,659,2636]{
            let data=(0..n).map(|_|BabyBearElem::new_raw(random(&mut seed))).collect::<Vec<_>>();
            assert_eq!(slow.hashfn.hash_elem_slice(&data),fast.hashfn.hash_elem_slice(&data),"base length {n}");
            let ext=(0..n).map(|_|BabyBearExtElem::from_subelems((0..4).map(|_|BabyBearElem::new_raw(random(&mut seed))))).collect::<Vec<_>>();
            assert_eq!(slow.hashfn.hash_ext_elem_slice(&ext),fast.hashfn.hash_ext_elem_slice(&ext),"ext length {n}");
        }
        for _ in 0..1024{
            let a=Digest::from(std::array::from_fn(|_|random(&mut seed)));
            let b=Digest::from(std::array::from_fn(|_|random(&mut seed)));
            assert_eq!(slow.hashfn.hash_pair(&a,&b),fast.hashfn.hash_pair(&a,&b));
        }
        for v in [0,P-1,P,P+1,u32::MAX]{let d=Digest::from([v;8]);assert_eq!(slow.hashfn.is_digest_valid(&d),fast.hashfn.is_digest_valid(&d));}
    }
    #[test]
    fn repeated_pair_bench_parity(){for n in [0,1,32,128,512,5661]{assert_eq!(repeated_pairs(n,false),repeated_pairs(n,true));}}
}
