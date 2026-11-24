use nova_snark::frontend::{ConstraintSystem, gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem};
use nova_snark::traits::circuit::StepCircuit;
use shz_hourly_index_nova::{F,Fixture,HourStep};
use ff::Field;
fn fixture()->Fixture{serde_json::from_str(include_str!("../../fixtures/checkpoint.json")).unwrap()}
fn synthesize(step:&HourStep,state:&[F])->(bool,Vec<F>,usize){
 let mut cs=TestConstraintSystem::<F>::new();let z:Vec<_>=state.iter().enumerate().map(|(i,x)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*x)).collect();
 let out=step.synthesize(&mut cs,&z).expect("fixed-shape synthesis");
 (cs.is_satisfied(),out.iter().map(|x|x.get_value().unwrap()).collect(),cs.num_constraints())
}
#[test]
fn all_eight_paths_share_one_exact_checkpoint_and_fold_shape(){
 let f=fixture();let claim=f.claim();let steps=f.steps().unwrap();let mut state=claim.state(0).unwrap();let mut shape=None;
 for (i,step) in steps.iter().enumerate(){assert_eq!(hex::encode(step.native_root()),claim.checkpoint_root);let(ok,out,n)=synthesize(step,&state);assert!(ok,"hour {i}");if let Some(k)=shape{assert_eq!(n,k)}else{shape=Some(n)}state=out;}
 assert_eq!(state,claim.state(8).unwrap());println!("application constraints per fold: {}",shape.unwrap());
}
// Recompute the checkpoint root for every malformed opening. If the circuit
// merely checked Merkle inclusion, these attacks would pass. They must fail
// because of the internal arithmetic / schedule constraints.
fn reject_opening(mut step:HourStep){
 let f=fixture();let mut claim=f.claim();claim.checkpoint_root=hex::encode(step.native_root());let mut z=claim.state(0).unwrap();z[0]=F::from(step.position as u64);
 assert!(!synthesize(&step,&z).0,"invalid opening passed after root recomputation");
 // also keep a different proof path as a simple root-binding control
 step.siblings[0][0]^=1;assert!(!synthesize(&step,&z).0);
}
#[test]fn false_midpoint_fails_even_with_recomputed_root(){let mut s=fixture().steps().unwrap()[0].clone();s.index+=1;reject_opening(s)}
#[test]fn excessive_spread_fails_with_correct_midpoint(){let mut s=fixture().steps().unwrap()[0].clone();s.c=s.p*2;s.index=(s.p+s.c)/2;reject_opening(s)}
#[test]fn stale_report_fails_even_with_recomputed_root(){let mut s=fixture().steps().unwrap()[0].clone();s.pt-=301_000_000;s.ct=s.pt;reject_opening(s)}
#[test]fn future_report_fails(){let mut s=fixture().steps().unwrap()[0].clone();s.pt=(s.hour+1)*3_600_000_000+1;s.ct=s.pt;reject_opening(s)}
#[test]fn skew_fails_even_if_both_sources_fresh(){let mut s=fixture().steps().unwrap()[0].clone();s.ct=s.pt-60_000_001;reject_opening(s)}
#[test]fn zero_report_hash_fails(){let mut s=fixture().steps().unwrap()[0].clone();s.p_hash=[0;32];reject_opening(s)}
#[test]fn hold_with_value_fails(){let mut s=fixture().steps().unwrap()[4].clone();s.index=1;reject_opening(s)}
#[test]fn hold_without_reason_fails(){let mut s=fixture().steps().unwrap()[4].clone();s.reason=0;reject_opening(s)}
#[test]fn swapped_hour_fails(){let mut s=fixture().steps().unwrap()[0].clone();s.hour+=1;s.pt+=3_600_000_000;s.ct+=3_600_000_000;reject_opening(s)}
#[test]fn excessive_price_fails(){let mut s=fixture().steps().unwrap()[0].clone();s.p=10_000_000_000_000_001;s.c=s.p;s.index=s.p;reject_opening(s)}
#[test]fn wrong_public_root_and_count_fail(){let f=fixture();let s=f.steps().unwrap()[0].clone();let z=f.claim().state(0).unwrap();let mut bad=z.clone();bad[6]+=F::ONE;assert!(!synthesize(&s,&bad).0);let mut bad=z;bad[0]+=F::ONE;assert!(!synthesize(&s,&bad).0)}
