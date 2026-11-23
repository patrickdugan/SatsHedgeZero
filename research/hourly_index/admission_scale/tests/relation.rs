use ff::Field;
use nova_snark::frontend::{ConstraintSystem, gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem};
use nova_snark::traits::circuit::StepCircuit;
use shz_hourly_index_admission_fused_nova as fused;
use shz_hourly_index_admission_packed_nova as packed;
use shz_hourly_index_admission_scale::{walk, expected_folds, AdmissionStep, Claim, F, DEPTH, CAP, ARITY};
use fused::{Action, Op, State, Slot, Summary};

fn claim(n:usize)->Claim {
    let data=match n {0=>include_str!("../fixtures/0-expected.json"),1=>include_str!("../fixtures/1-expected.json"),16=>include_str!("../fixtures/16-expected.json"),128=>include_str!("../fixtures/128-expected.json"),512=>include_str!("../fixtures/512-expected.json"),144000=>include_str!("../fixtures/144000-expected.json"),_=>panic!("unknown fixture")};
    serde_json::from_str(data).unwrap()
}
fn synth(s:&AdmissionStep,public:&[F])->(bool,Vec<F>,usize){
    let mut cs=TestConstraintSystem::<F>::new();
    let z=public.iter().enumerate().map(|(i,v)|AllocatedNum::alloc_infallible(cs.namespace(||format!("public {i}")),||*v)).collect::<Vec<_>>();
    let out=s.synthesize(&mut cs,&z).expect("depth18 fixed-shape synthesis");
    (cs.is_satisfied(),out.iter().map(|v|v.get_value().unwrap()).collect(),cs.num_constraints())
}
fn public(s:&AdmissionStep)->Vec<F>{packed::pack_fields(&s.inner.before.fields(s.inner.genesis,s.inner.source))}
fn terminal(s:&AdmissionStep)->Vec<F>{packed::pack_fields(&s.inner.after.fields(s.inner.genesis,s.inner.source))}
fn step(before:State,action:Action)->AdmissionStep{
    let after=fused::advance(&before,&action).unwrap();
    AdmissionStep{inner:fused::AdmissionStep{before,after,action,genesis:[0;32],source:1}}
}
#[test]
fn compile_profile_and_native_claims_have_exact_depth_and_encoding(){
    assert_eq!(DEPTH,18);assert_eq!(CAP,262144);assert_eq!(fused::ARITY,88);assert_eq!(ARITY,44);assert_eq!(packed::HEADER_BITS,220);
    assert_eq!(fused::MAX_STEPS,1<<20);assert!(packed::RELATION.ends_with("/depth18"));
    for n in [0,1,16,128,512]{
        let c=claim(n);let (initial,expected)=packed::claim_states(&c).unwrap();
        assert_eq!(initial.len(),44);assert_eq!(expected.len(),44);let mut seen=0u64;
        walk(&c, |_|{seen+=1;Ok(())}).unwrap();assert_eq!(seen,expected_folds(n as u64).unwrap());
    }
    let c=claim(144000);assert_eq!(c.steps,287996);assert!(packed::claim_states(&c).is_ok());
}
#[test]
fn depth18_fixed_shape_and_exact_output_on_small_history(){
    let c=claim(16);let (mut z,end)=packed::claim_states(&c).unwrap();let mut shape=None;
    walk(&c, |s|{
        assert_eq!(public(s),z);let(ok,out,n)=synth(s,&z);assert!(ok);assert_eq!(out,terminal(s));
        if let Some(old)=shape{assert_eq!(old,n)}else{shape=Some(n)}z=out;Ok(())
    }).unwrap();assert_eq!(z,end);
    println!("SHZ_ADMIT_DEPTH18_COUNTS depth={} arity={} application={} folds={}",DEPTH,ARITY,shape.unwrap(),c.steps);
}
// A local transition at the highest legal merge level. This is deliberately
// synthetic state, not a proof of a complete capacity-sized history.
fn high_merge()->AdmissionStep{
    let mut b=State::initial();b.leaf_count=CAP;b.operations=500_000;b.last_time=2000;
    b.pending=true;b.level=17;b.carry=Summary{min:1000,digest:[2;32]};
    b.frontier=vec![Slot::default();DEPTH+1];b.frontier[17]=Slot{occupied:true,min:0,digest:[1;32]};
    step(b,Action{op:Op::Carry,record:Default::default(),watermark:0})
}
#[test]
fn highest_merge_installs_root_and_rejects_wrong_routes(){
    let s=high_merge();assert!(!s.inner.after.pending);assert!(s.inner.after.frontier[18].occupied);
    assert!(!s.inner.after.frontier[17].occupied);assert_eq!(s.inner.after.leaf_count,CAP);
    let (ok,out,n)=synth(&s,&public(&s));assert!(ok);assert_eq!(out,terminal(&s));
    assert_eq!(n,synth(&AdmissionStep::blank(),&public(&AdmissionStep::blank())).2);
    let mut wrong=s.clone();wrong.inner.after.frontier[18].digest[0]^=1;assert!(!synth(&wrong,&public(&s)).0);
    let mut wrong=s.clone();wrong.inner.after.frontier[17]=wrong.inner.after.frontier[18].clone();wrong.inner.after.frontier[18]=Slot::default();assert!(!synth(&wrong,&public(&s)).0);
    let mut wrong=s.clone();wrong.inner.after.pending=true;wrong.inner.after.level=18;assert!(!synth(&wrong,&public(&s)).0);
}
#[test]
fn depth18_operation_budget_and_packed_high_bit_bound(){
    let mut before=State::initial();before.operations=(fused::MAX_STEPS-1) as u64;
    let good=step(before,Action::seal(1));assert!(synth(&good,&public(&good)).0);
    let mut bad=good.clone();bad.inner.before.operations+=1;bad.inner.after.operations+=1;
    assert!(!synth(&bad,&public(&bad)).0,"operation budget overflow");
    let good=AdmissionStep::blank();let mut z=public(&good);z[0]+=packed::pow2(packed::HEADER_BITS);
    assert!(!synth(&good,&z).0,"unused packed header bit");
    let mut z=public(&good);z[3]+=packed::pow2(192);assert!(!synth(&good,&z).0,"unused packed summary bit");
}
#[test]
fn wrong_depth_wrong_state_and_synthetic_claim_rejected(){
    let c=claim(16);let mut x=c.clone();x.header.depth=4;assert!(packed::claim_states(&x).is_err());
    let mut x=c.clone();x.final_state.frontier.iter_mut().find(|s|s.occupied).unwrap().digest[0]^=1;assert!(walk(&x, |_|Ok(())).is_err());
    let mut x=c;x.steps+=1;x.final_state.operations+=1;assert!(walk(&x, |_|Ok(())).is_err());
}
