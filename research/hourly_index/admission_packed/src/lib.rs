//! INDEX-ADMIT-04: injective packing of the existing eager-placement relation.
//! No SHA, tree, policy, or external authentication semantics change.
#![forbid(unsafe_code)]
use ff::Field;
use nova_snark::frontend::{gadgets::num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;
use shz_hourly_index_admission_fused_nova as parent;
pub use parent::{F, Claim, Action, State, Op, DEPTH, CAP, MAX_STEPS};
pub const LEGACY_ARITY:usize=parent::ARITY;
pub const ARITY:usize=1+2+2*(DEPTH+1)+3;
pub const HEADER_BITS:usize=201+(DEPTH+1);
#[cfg(not(feature="depth18"))]
pub const RELATION:&str="shz/ordered-admission-frontier-nova/v4-packed-state/depth4";
#[cfg(feature="depth18")]
pub const RELATION:&str="shz/ordered-admission-frontier-nova/v4-packed-state/depth18";
pub const SENTINEL_PACKED_INDEX:usize=3;

pub fn pow2(bits:usize)->F{(0..bits).fold(F::ONE,|a,_|a.double())}

// Each group maps to one field. The tuples are (old index, offset, width).
// Every old coordinate is included exactly once. No arbitrary hash reduction.
fn layout()->Vec<Vec<(usize,usize,usize)>>{
    let mut header=vec![(0,0,32),(1,32,32),(2,64,64),(3,128,64),(4,192,1),(5,193,8)];
    for i in 0..=DEPTH{header.push((9+4*i,201+i,1));}
    let mut out=vec![header,vec![(6,0,64),(7,64,128)],vec![(8,0,128)]];
    for i in 0..=DEPTH{let o=9+4*i;out.push(vec![(o+1,0,64),(o+2,64,128)]);out.push(vec![(o+3,0,128)]);}
    for i in LEGACY_ARITY-3..LEGACY_ARITY{out.push(vec![(i,0,if i==LEGACY_ARITY-1{8}else{128})]);}
    out
}

// Only call on canonical parent state coordinates (Claim::states or verified
// parent step output). For circuit witnesses the parent range/binding constraints
// establish the required widths; pack_fields alone does not validate them.
pub fn pack_fields(z:&[F])->Vec<F>{
    assert_eq!(z.len(),LEGACY_ARITY);
    layout().iter().map(|g|g.iter().fold(F::ZERO,|a,(i,s,_)|a+z[*i]*pow2(*s))).collect()
}
pub fn claim_states(claim:&Claim)->Result<(Vec<F>,Vec<F>),String>{
    let (a,b)=claim.states()?;Ok((pack_fields(&a),pack_fields(&b)))
}

fn packed_lc(v:&[AllocatedNum<F>],g:&[(usize,usize,usize)])->LinearCombination<F>{
    g.iter().fold(LinearCombination::zero(),|lc,(i,s,_)|lc+(pow2(*s),v[*i].get_variable()))
}
fn bind_pack<CS:ConstraintSystem<F>>(cs:&mut CS,old:&[AllocatedNum<F>],packed:&[AllocatedNum<F>]){
    for (j,g) in layout().iter().enumerate(){
        cs.enforce(||format!("packed coordinate {j}"),|_|packed_lc(old,g),|lc|lc+CS::one(),|lc|lc+packed[j].get_variable());
    }
}
#[derive(Clone,Debug)]
pub struct AdmissionStep{pub inner:parent::AdmissionStep}
impl AdmissionStep{
    pub fn blank()->Self{Self{inner:parent::AdmissionStep::blank()}}
    // Separate entry only to exercise arbitrary unpacked assignments in tests.
    // The shape never depends on these values. Parent constrains ALL mutable
    // old fields and derives all outputs. Last three context limbs are carried
    // directly from the public input (same as v3).
    fn with_opening<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>],opening:&[F])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
        assert_eq!(z.len(),ARITY);assert_eq!(opening.len(),LEGACY_ARITY);
        let mut old=Vec::with_capacity(LEGACY_ARITY);
        for(i,v)in opening.iter().take(LEGACY_ARITY-3).enumerate(){
            old.push(AllocatedNum::alloc_infallible(cs.namespace(||format!("unpacked input {i}")),||*v));
        }
        old.extend_from_slice(&z[ARITY-3..]);
        bind_pack(&mut cs.namespace(||"input encoding"),&old,z);
        let next=self.inner.synthesize(&mut cs.namespace(||"exact eager relation"),&old)?;
        assert_eq!(next.len(),LEGACY_ARITY);
        let mut packed=Vec::with_capacity(ARITY);
        for (j,g) in layout().iter().take(ARITY-3).enumerate(){
            let value=g.iter().fold(F::ZERO,|acc,(i,s,_)|acc+next[*i].get_value().unwrap_or(F::ZERO)*pow2(*s));
            packed.push(AllocatedNum::alloc_infallible(cs.namespace(||format!("packed output {j}")),||value));
        }
        packed.extend_from_slice(&next[LEGACY_ARITY-3..]);
        bind_pack(&mut cs.namespace(||"output encoding"),&next,&packed);
        Ok(packed)
    }
}
impl StepCircuit<F> for AdmissionStep{
    fn arity(&self)->usize{ARITY}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
        self.with_opening(cs,z,&self.inner.before.fields(self.inner.genesis,self.inner.source))
    }
}
pub fn trace(actions:&[Action],claim:&Claim)->Result<Vec<AdmissionStep>,String>{
    Ok(parent::trace(actions,claim)?.into_iter().map(|inner|AdmissionStep{inner}).collect())
}

#[cfg(all(test,not(feature="depth18")))]
mod tests{
    use super::*;
    use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
    fn synth(step:&AdmissionStep,public:&[F],opening:&[F])->(bool,Vec<F>,usize){
        let mut cs=TestConstraintSystem::<F>::new();
        let z=public.iter().enumerate().map(|(i,v)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z {i}")),||*v)).collect::<Vec<_>>();
        let next=step.with_opening(&mut cs,&z,opening).unwrap();
        (cs.is_satisfied(),next.iter().map(|v|v.get_value().unwrap()).collect(),cs.num_constraints())
    }
    fn old_synth(step:&parent::AdmissionStep,z:&[F])->(bool,Vec<F>,usize){
        let mut cs=TestConstraintSystem::<F>::new();
        let z=z.iter().enumerate().map(|(i,v)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z {i}")),||*v)).collect::<Vec<_>>();
        let next=step.synthesize(&mut cs,&z).unwrap();
        (cs.is_satisfied(),next.iter().map(|v|v.get_value().unwrap()).collect(),cs.num_constraints())
    }
    fn fixture(source:&str)->(Claim,Vec<AdmissionStep>){
        let (c,a)=match source{
            "pyth"=>(include_str!("../../admission_fused/fixtures/pyth-expected.json"),include_str!("../../admission_fused/fixtures/pyth-steps.json")),
            "chainlink"=>(include_str!("../../admission_fused/fixtures/chainlink-expected.json"),include_str!("../../admission_fused/fixtures/chainlink-steps.json")),
            _=>panic!("unknown fixture")};
        let claim:Claim=serde_json::from_str(c).unwrap();let actions:Vec<Action>=serde_json::from_str(a).unwrap();let t=trace(&actions,&claim).unwrap();(claim,t)
    }
    #[test]
    fn layout_is_injective_bounded_and_covers_every_legacy_coordinate(){
        assert_eq!(ARITY,16);assert_eq!(LEGACY_ARITY,32);assert_eq!(HEADER_BITS,206);
        let mut seen=vec![false;LEGACY_ARITY];
        for group in layout(){let mut used=[false;254];for(i,o,w)in group{assert!(!seen[i]);seen[i]=true;assert!(o+w<=254);for b in o..o+w{assert!(!used[b]);used[b]=true;}}}
        assert!(seen.iter().all(|x|*x));assert!(201+19<254);
    }
    #[test]
    fn matched_all_steps_and_fixed_shape(){
        let mut shape=None;
        for source in ["pyth","chainlink"]{
            let(c,t)=fixture(source);let(mut z,end)=claim_states(&c).unwrap();
            for(i,s)in t.iter().enumerate(){
                let old=s.inner.before.fields(s.inner.genesis,s.inner.source);let old_expected=s.inner.after.fields(s.inner.genesis,s.inner.source);
                assert_eq!(z,pack_fields(&old));
                let (ok,out,n)=synth(s,&z,&old);assert!(ok,"{source} step {i}");assert_eq!(out,pack_fields(&old_expected));
                if let Some(prev)=shape{assert_eq!(n,prev);}else{shape=Some(n);}
                if i==0{let (old_ok,old_out,old_n)=old_synth(&s.inner,&old);assert!(old_ok);assert_eq!(old_out,old_expected);println!("SHZ_ADMISSION_PACK_COUNTS source={source} old_arity={LEGACY_ARITY} new_arity={ARITY} old_application={old_n} new_application={n}");}
                z=out;
            }
            assert_eq!(z,end);
        }
    }
    #[test]
    fn aliasing_openings_rejected_by_actual_parent_constraints(){
        let(_,steps)=fixture("pyth");let s=&steps[0];let old=s.inner.before.fields(s.inner.genesis,s.inner.source);let z=pack_fields(&old);
        // Make the packed equality pass, but inject one component into its neighbor.
        for (lo,hi,width) in [(0,1,32),(1,2,32),(2,3,64),(3,4,64),(4,5,1),(5,9,8),(6,7,64),(10,11,64)]{
            let mut forged=old.clone();forged[lo]+=pow2(width);forged[hi]-=F::ONE;
            assert_eq!(pack_fields(&forged),z,"test must preserve packed public input");
            assert!(!synth(s,&z,&forged).0,"alias escaped parent bounds: {lo}/{hi}");
        }
    }
    #[test]
    fn all_packed_coordinate_mutations_rejected_or_context_changes_carried(){
        let(_,steps)=fixture("pyth");let s=&steps[0];let old=s.inner.before.fields(s.inner.genesis,s.inner.source);let z=pack_fields(&old);
        for i in 0..ARITY-3{let mut wrong=z.clone();wrong[i]+=F::ONE;assert!(!synth(s,&wrong,&old).0,"changed packed coordinate {i}");}
        // Context is intentionally public and immutable, authenticated by Claim.
        let mut changed=z.clone();changed[ARITY-1]=F::from(2);let(ok,out,_)=synth(s,&changed,&old);assert!(ok);assert_eq!(out[ARITY-1],F::from(2));
    }
    #[test]
    fn forged_output_slot_and_early_carry_termination_rejected(){
        let(_,steps)=fixture("pyth");let s=steps.into_iter().find(|s|s.inner.after.pending).unwrap();let old=s.inner.before.fields(s.inner.genesis,s.inner.source);let z=pack_fields(&old);
        let mut a=s.clone();a.inner.after.carry.digest[0]^=1;assert!(!synth(&a,&z,&old).0);
        let mut a=s;a.inner.after.pending=false;a.inner.after.carry=Default::default();a.inner.after.level=0;assert!(!synth(&a,&z,&old).0);
    }
}
