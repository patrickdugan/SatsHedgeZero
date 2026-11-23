use nova_snark::frontend::{ConstraintSystem, gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem};
use nova_snark::traits::circuit::StepCircuit;
use shz_hourly_index_policy_nova::{F,Fixture,HourStep,Claim, evidence_root,ARITY};
use ff::Field;
fn fixture()->Fixture{serde_json::from_str(include_str!("../fixtures/checkpoint.json")).unwrap()}
fn synthesize(step:&HourStep,state:&[F])->(bool,Vec<F>,usize){
 let mut cs=TestConstraintSystem::<F>::new();
 let z:Vec<_>=state.iter().enumerate().map(|(i,x)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*x)).collect();
 let out=step.synthesize(&mut cs,&z).expect("fixed-shape synthesis");
 (cs.is_satisfied(),out.iter().map(|x|x.get_value().unwrap()).collect(),cs.num_constraints())
}
fn h(s:&str)->[u8;32]{hex::decode(s).unwrap().try_into().unwrap()}
fn intermediate(claim:&Claim,pos:usize)->Vec<F>{
 let z=claim.state(0).unwrap();let mut state=z[..8].to_vec();state[0]=F::from(pos as u64);
 state.extend_from_slice(&z[8+2*pos..]);state.extend(std::iter::repeat(F::ZERO).take(2*pos));assert_eq!(state.len(),ARITY);state
}
fn change_evidence(claim:&mut Claim,s:&HourStep){
 claim.evidence_leaves[s.position as usize]=hex::encode(s.evidence_digest());
 let leaves=claim.evidence_leaves.iter().map(|x|h(x)).collect::<Vec<_>>();
 claim.evidence_root=hex::encode(evidence_root(h(&claim.genesis),h(&claim.policy_hash),claim.start_hour.parse().unwrap(),&leaves).unwrap());
}
fn evaluate(s:&HourStep,repin_evidence:bool)->bool{
 let mut claim=fixture().claim();claim.checkpoint_root=hex::encode(s.native_root());
 if repin_evidence{change_evidence(&mut claim,s);}
 synthesize(s,&intermediate(&claim,s.position as usize)).0
}
fn hold(s:&mut HourStep,reason:u8){s.status=2;s.reason=reason;s.p=0;s.c=0;s.index=0;s.pt=0;s.ct=0;s.p_hash=[0;32];s.c_hash=[0;32];}
fn valid(s:&mut HourStep){s.status=1;s.reason=0;s.p=s.candidates[0].price;s.c=s.candidates[1].price;s.pt=s.candidates[0].time;s.ct=s.candidates[1].time;s.p_hash=s.candidates[0].digest;s.c_hash=s.candidates[1].digest;s.index=(s.p+s.c)/2;}
#[test]
fn eight_folds_consume_all_receiver_pinned_digests_with_identical_shape(){
 let f=fixture();let claim=f.claim();let steps=f.steps().unwrap();let mut state=claim.state(0).unwrap();let mut shape=None;
 for (i,s) in steps.iter().enumerate(){assert_eq!(hex::encode(s.native_root()),claim.checkpoint_root);assert_eq!(hex::encode(s.evidence_digest()),claim.evidence_leaves[i]);let(ok,out,n)=synthesize(s,&state);assert!(ok,"hour {i}");if let Some(k)=shape{assert_eq!(n,k)}else{shape=Some(n)}state=out;}
 assert_eq!(state,claim.state(8).unwrap());println!("INDEX-POLICY-01 constraints per fold: {}",shape.unwrap());
}
#[test]
fn index02_allows_voluntary_hold_with_freshly_committed_leaf(){
 // Exercise the predecessor's actual R1CS, rather than only its native parser.
 let f:shz_hourly_index_nova::Fixture=serde_json::from_str(include_str!("../../fixtures/checkpoint.json")).unwrap();
 let mut s=f.steps().unwrap()[0].clone();assert_eq!(s.status,1);
 s.status=2;s.reason=1;s.p=0;s.c=0;s.index=0;s.pt=0;s.ct=0;s.p_hash=[0;32];s.c_hash=[0;32];
 let mut claim=f.claim();claim.checkpoint_root=hex::encode(s.native_root());
 let mut cs=TestConstraintSystem::<F>::new();let z:Vec<_>=claim.state(0).unwrap().iter().enumerate().map(|(i,x)|AllocatedNum::alloc_infallible(cs.namespace(||format!("old z{i}")),||*x)).collect();
 s.synthesize(&mut cs,&z).unwrap();assert!(cs.is_satisfied(),"expected v1 limitation");
}
#[test]fn fresh_pair_cannot_be_suppressed_even_with_recomputed_checkpoint(){let mut s=fixture().steps().unwrap()[1].clone();hold(&mut s,1);assert!(!evaluate(&s,false));}
#[test]fn wide_pair_must_hold_with_reason_two(){let mut s=fixture().steps().unwrap()[5].clone();hold(&mut s,1);assert!(!evaluate(&s,false));}
#[test]fn skew_reason_precedes_spread(){let mut s=fixture().steps().unwrap()[6].clone();s.candidates[1].price*=2;hold(&mut s,2);assert!(!evaluate(&s,true));hold(&mut s,3);assert!(evaluate(&s,true));}
#[test]fn missing_or_stale_must_hold(){let mut s=fixture().steps().unwrap()[7].clone();hold(&mut s,2);assert!(!evaluate(&s,false));valid(&mut s);assert!(!evaluate(&s,false));}
#[test]fn missing_candidate_with_nonzero_fields_is_impossible(){let mut s=fixture().steps().unwrap()[1].clone();s.candidates[0].present=false;hold(&mut s,1);assert!(!evaluate(&s,true));}
#[test]fn post_cutoff_candidate_invalid_even_when_held(){let mut s=fixture().steps().unwrap()[1].clone();s.candidates[0].time=(s.hour+1)*3_600_000_000+1;hold(&mut s,1);assert!(!evaluate(&s,true));}
#[test]fn valid_record_must_use_selected_evidence_price(){let mut s=fixture().steps().unwrap()[1].clone();s.p+=1;s.index=(s.p+s.c)/2;assert!(!evaluate(&s,false));}
#[test]fn valid_record_cannot_substitute_signed_report_digest(){let mut s=fixture().steps().unwrap()[1].clone();s.p_hash[0]^=1;assert!(!evaluate(&s,false));}
#[test]fn hold_does_not_hide_tampered_evidence_from_queue(){let mut s=fixture().steps().unwrap()[5].clone();s.candidates[1].digest[0]^=1;assert!(!evaluate(&s,false));}
#[test]fn exact_freshness_boundary_and_one_microsecond_beyond(){let mut s=fixture().steps().unwrap()[4].clone();assert!(evaluate(&s,false));s.candidates[1].time-=1;valid(&mut s);assert!(!evaluate(&s,true));hold(&mut s,1);assert!(evaluate(&s,true));}
#[test]fn exact_spread_boundary_and_one_unit_beyond(){let mut s=fixture().steps().unwrap()[1].clone();s.candidates[0].price=40_100_000_000;s.candidates[1].price=39_900_000_000;valid(&mut s);assert!(evaluate(&s,true));s.candidates[0].price+=1;valid(&mut s);assert!(!evaluate(&s,true));hold(&mut s,2);assert!(evaluate(&s,true));}
#[test]fn wrong_queue_head_fails_even_with_correct_output(){let f=fixture();let s=f.steps().unwrap()[1].clone();let mut z=intermediate(&f.claim(),1);z[8]+=F::ONE;assert!(!synthesize(&s,&z).0);}
#[test]fn queue_order_must_match_independently_retained_root(){let mut c=fixture().claim();c.evidence_leaves.swap(0,1);assert!(c.state(0).is_err());}
#[test]fn policy_version_pinned_in_receiver_state(){let mut c=fixture().claim();c.policy_hash="00".repeat(32);assert!(c.state(0).is_err());}
