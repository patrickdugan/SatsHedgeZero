use nova_snark::frontend::{ConstraintSystem,gadgets::num::AllocatedNum,util_cs::test_cs::TestConstraintSystem};
use nova_snark::traits::circuit::StepCircuit;
use shz_hourly_index_maximality_nova::{Claim,Fixture,HourOpening,HourStep,F,evidence_root};
use ff::Field;
fn fixture()->Fixture{serde_json::from_str(include_str!("../fixtures/openings.json")).unwrap()}
fn claim()->Claim{serde_json::from_str(include_str!("../fixtures/expected.json")).unwrap()}
fn synthesize(s:&HourStep,z:&[F])->(bool,Vec<F>,usize){
 let mut cs=TestConstraintSystem::<F>::new();let inputs=z.iter().enumerate().map(|(i,v)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*v)).collect::<Vec<_>>();
 let out=s.synthesize(&mut cs,&inputs).expect("fixed-shape synthesis");
 (cs.is_satisfied(),out.iter().map(|x|x.get_value().unwrap()).collect(),cs.num_constraints())
}
fn f_le(b:&[u8])->F{b.iter().rev().fold(F::ZERO,|x,y|x*F::from(256)+F::from(*y as u64))}
fn at_position(i:usize)->Vec<F>{let z=claim().state(0).unwrap();let mut out=vec![F::from(i as u64)];out.extend_from_slice(&z[1..10]);out.extend_from_slice(&z[10+i*2..]);out.extend(vec![F::ZERO;i*2]);out}
fn rebind(z:&mut [F],s:&HourStep){let d=s.evidence_digest();z[10]=f_le(&d[..16]);z[11]=f_le(&d[16..]);}
#[test]fn eight_valid_selection_folds_same_shape_and_exact_policy_queue(){let f=fixture();let c=claim();let steps=f.steps().unwrap();let mut z=c.state(0).unwrap();let mut shape=None;for(i,s)in steps.iter().enumerate(){assert_eq!(hex::encode(s.evidence_digest()),c.evidence_leaves[i]);let(ok,out,n)=synthesize(s,&z);assert!(ok,"hour {i}");if let Some(prev)=shape{assert_eq!(n,prev)}else{shape=Some(n)}z=out;}assert_eq!(z,c.state(8).unwrap());println!("application_constraints_per_paired_selection_fold={}",shape.unwrap());}
#[test]fn authentic_earlier_membership_fails_even_after_rebinding_evidence(){let mut f=fixture();let a:HourOpening=serde_json::from_str(include_str!("../fixtures/earlier.json")).unwrap();f.openings[1]=a;let s=f.steps().unwrap().remove(1);let mut z=at_position(1);rebind(&mut z,&s);assert!(!synthesize(&s,&z).0);}
#[test]fn changed_report_minimum_fails_with_evidence_rebound(){let mut s=fixture().steps().unwrap().remove(1);let mut z=at_position(1);s.sources[0].siblings[0].min=s.sources[0].siblings[0].min.wrapping_add(1);rebind(&mut z,&s);assert!(!synthesize(&s,&z).0);}
#[test]fn unsealed_cutoff_fails(){let mut s=fixture().steps().unwrap().remove(0);s.sources[0].seal=0;assert!(!synthesize(&s,&at_position(0)).0);}
#[test]fn false_absence_at_nonzero_index_fails(){let mut s=fixture().steps().unwrap().remove(0);s.sources[0].candidate.present=false;s.sources[0].candidate.price=0;s.sources[0].candidate.time=0;s.sources[0].candidate.digest=[0;32];let mut z=at_position(0);rebind(&mut z,&s);assert!(!synthesize(&s,&z).0);}
#[test]fn index_above_count_fails(){let mut s=fixture().steps().unwrap().remove(0);s.sources[0].index=15;assert!(!synthesize(&s,&at_position(0)).0);}
#[test]fn external_snapshot_or_evidence_substitution_rejected(){let s=fixture().steps().unwrap().remove(0);let mut z=at_position(0);z[6]+=F::ONE;assert!(!synthesize(&s,&z).0);let mut z=at_position(0);z[10]+=F::ONE;assert!(!synthesize(&s,&z).0);}
#[test]fn frozen_claim_uses_identical_policy_evidence(){let c=claim();let p:serde_json::Value=serde_json::from_str(include_str!("../../policy_nova/fixtures/expected.json")).unwrap();assert_eq!(c.evidence_root,p["evidence_root"].as_str().unwrap());let leaves=c.evidence_leaves.iter().map(|x|hex::decode(x).unwrap().try_into().unwrap()).collect::<Vec<[u8;32]>>();assert_eq!(hex::encode(evidence_root(hex::decode(c.genesis).unwrap().try_into().unwrap(),hex::decode(c.policy_hash).unwrap().try_into().unwrap(),c.start_hour.parse().unwrap(),&leaves).unwrap()),c.evidence_root);}
