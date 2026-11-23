use shz_hourly_index_admission_segments::{Plan,Claim,State,F,ARITY,validate_plan,walk_segment};
use nova_snark::frontend::{ConstraintSystem,gadgets::num::AllocatedNum,util_cs::test_cs::TestConstraintSystem};
use nova_snark::traits::circuit::StepCircuit;
fn fixture()->(Plan,Claim){(serde_json::from_str(include_str!("../fixtures/128-plan.json")).unwrap(),serde_json::from_str(include_str!("../../admission_scale/fixtures/128-expected.json")).unwrap())}
#[test]
fn native_independent_segments_match_all_packed_boundaries(){
 let(p,c)=fixture();validate_plan(&p,&c).unwrap();assert_eq!(ARITY,44);assert_eq!(p.segments.iter().map(|s|s.folds).collect::<Vec<_>>(),[63,64,63,66]);
 let mut prior=State::initial();for s in &p.segments{assert_eq!(s.before,prior);let mut k=0;walk_segment(s,&c,|step|{assert_eq!(step.inner.before.operations,s.before.operations+k);k+=1;Ok(())}).unwrap();assert_eq!(k,s.folds as u64);prior=s.after.clone();}assert_eq!(prior,c.final_state);
 for w in p.segments.windows(2){assert_eq!(w[0].states(&c).unwrap().1,w[1].states(&c).unwrap().0);}
}
#[test]
fn actual_r1cs_accepts_initial_and_terminal_transition_of_each_segment(){
 let(p,c)=fixture();let mut shape=None;
 for seg in &p.segments{let mut first=None;let mut last=None;walk_segment(seg,&c,|step|{if first.is_none(){first=Some(step.clone());}last=Some(step.clone());Ok(())}).unwrap();
 for step in [first.unwrap(),last.unwrap()]{let z=shz_hourly_index_admission_packed_nova::pack_fields(&step.inner.before.fields(step.inner.genesis,step.inner.source));let expected=shz_hourly_index_admission_packed_nova::pack_fields(&step.inner.after.fields(step.inner.genesis,step.inner.source));let mut cs=TestConstraintSystem::<F>::new();let z=z.iter().enumerate().map(|(i,v)|AllocatedNum::alloc_infallible(cs.namespace(||format!("state {i}")),||*v)).collect::<Vec<_>>();let out=step.synthesize(&mut cs,&z).unwrap();assert!(cs.is_satisfied());assert_eq!(out.iter().map(|x|x.get_value().unwrap()).collect::<Vec<_>>(),expected);if let Some(n)=shape{assert_eq!(n,cs.num_constraints());}else{shape=Some(cs.num_constraints());}}
 }
 println!("SHZ_ADMISSION_SEGMENT_R1CS arity={} constraints={}",ARITY,shape.unwrap());
}
#[test]
fn malformed_chains_are_rejected_before_verifying_proofs(){
 let(p,c)=fixture();let mut a=p.clone();a.segments.remove(1);assert!(validate_plan(&a,&c).is_err());let mut a=p.clone();a.segments.swap(0,1);assert!(validate_plan(&a,&c).is_err());let mut a=p.clone();a.segments[2].folds+=1;assert!(validate_plan(&a,&c).is_err());let mut a=p.clone();a.segments[0].after.frontier[0].digest[0]^=1;assert!(validate_plan(&a,&c).is_err());let mut a=p.clone();a.segments.last_mut().unwrap().after.operations+=1;assert!(validate_plan(&a,&c).is_err());let mut a=p;a.snapshot_pin="00".repeat(32);assert!(validate_plan(&a,&c).is_err());
}
#[test]
fn matching_fabricated_boundary_is_not_proof_of_reachability(){
 let(mut p,c)=fixture();let x=p.segments[0].after.frontier.iter_mut().find(|s|s.occupied).unwrap();x.digest[0]^=1;p.segments[1].before=p.segments[0].after.clone();
 validate_plan(&p,&c).unwrap();assert!(walk_segment(&p.segments[0],&c,|_|Ok(())).is_err());assert!(walk_segment(&p.segments[1],&c,|_|Ok(())).is_err());
}
