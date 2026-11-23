use nova_snark::frontend::{ConstraintSystem,gadgets::num::AllocatedNum,util_cs::test_cs::TestConstraintSystem};
use nova_snark::traits::circuit::StepCircuit;
use shz_hourly_index_admission_nova::{F,Claim,Action,AdmissionStep,Op,State,Summary,Slot,trace,advance,hash,ARITY,DEPTH};
use ff::Field;
fn fixture(source:&str)->(Claim,Vec<AdmissionStep>){let (c,a)=match source{"pyth"=>(include_str!("../fixtures/pyth-expected.json"),include_str!("../fixtures/pyth-steps.json")),"chainlink"=>(include_str!("../fixtures/chainlink-expected.json"),include_str!("../fixtures/chainlink-steps.json")),_=>panic!("source")};let c:Claim=serde_json::from_str(c).unwrap();let a:Vec<Action>=serde_json::from_str(a).unwrap();let t=trace(&a,&c).unwrap();(c,t)}
fn synthesize(s:&AdmissionStep,state:&[F])->(bool,Vec<F>,usize){let mut cs=TestConstraintSystem::<F>::new();let z:Vec<_>=state.iter().enumerate().map(|(i,v)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*v)).collect();let out=s.synthesize(&mut cs,&z).expect("fixed shape");(cs.is_satisfied(),out.iter().map(|v|v.get_value().unwrap()).collect(),cs.num_constraints())}
fn reject(s:&AdmissionStep){let z=s.before.fields(s.genesis,s.source);assert!(!synthesize(s,&z).0,"malicious transition satisfied R1CS")}
fn step(op:Op)->AdmissionStep{fixture("pyth").1.into_iter().find(|s|s.action.op==op).unwrap()}
fn raw_leaf(s:&AdmissionStep)->Summary{let r=&s.action.record;let mut b=b"SHZ/LOG/LEAF/V2".to_vec();b.push(1);b.extend(r.price_e8.to_le_bytes());b.extend(r.publish_us.to_le_bytes());b.extend(r.report_hash);Summary{min:r.publish_us,digest:hash(&b)}}
#[test]fn both_histories_match_exact_max01_pins_and_one_shape(){let max:serde_json::Value=serde_json::from_str(include_str!("../../maximality/fixtures/expected.json")).unwrap();let mut shape=None;for source in ["pyth","chainlink"]{let(c,steps)=fixture(source);assert_eq!(c.pin,max["pins"][source].as_str().unwrap());let(mut z,final_z)=c.states().unwrap();assert_eq!(z.len(),ARITY);for(i,s)in steps.iter().enumerate(){let(ok,out,n)=synthesize(s,&z);assert!(ok,"{source} microstep {i}");if let Some(k)=shape{assert_eq!(n,k,"shape changed")}else{shape=Some(n)}z=out;}assert_eq!(z,final_z);}println!("application_constraints_per_microstep={}",shape.unwrap());}
#[test]fn recomputed_leaf_cannot_backfill_after_seal(){let(_,t)=fixture("pyth");let mut s=t.into_iter().find(|s|s.action.op==Op::Append&&s.before.sealed_through>0).unwrap();s.action.record.publish_us=s.before.sealed_through;s.after.last_time=s.action.record.publish_us;s.after.carry=raw_leaf(&s);reject(&s);}
#[test]fn equal_tail_fails_even_with_rehashed_leaf(){let mut s=fixture("pyth").1.into_iter().filter(|s|s.action.op==Op::Append).nth(1).unwrap();s.action.record.publish_us=s.before.last_time;s.after.last_time=s.action.record.publish_us;s.after.carry=raw_leaf(&s);reject(&s)}
#[test]fn forged_price_and_digest_fail_under_rehashed_leaf(){for(price,digest)in [(0,[1;32]),(10_000_000_000_000_001,[1;32]),(100_000,[0;32])]{let mut s=step(Op::Append);s.action.record.price_e8=price;s.action.record.report_hash=digest;s.after.carry=raw_leaf(&s);reject(&s)}}
#[test]fn infinity_timestamp_cannot_be_admitted(){let mut s=step(Op::Append);s.action.record.publish_us=u64::MAX;s.after.last_time=u64::MAX;s.after.carry=raw_leaf(&s);reject(&s)}
#[test]fn carry_minimum_and_digest_cannot_be_forged(){let s=step(Op::Carry);assert!(s.before.pending);let mut a=s.clone();a.after.carry.min+=1;reject(&a);let mut a=s;a.after.carry.digest[0]^=1;reject(&a)}
#[test]fn placement_cannot_drop_or_change_subtree(){let s=fixture("pyth").1.into_iter().find(|s|s.action.op==Op::Carry&&!s.after.pending).unwrap();let mut a=s.clone();let i=usize::from(a.before.level);a.after.frontier[i]=Slot::default();reject(&a);let mut a=s;a.after.frontier[i].digest[0]^=1;reject(&a)}
#[test]fn append_cannot_change_other_frontier_slot(){let mut s=step(Op::Append);s.after.frontier[0].digest[0]^=1;reject(&s)}
#[test]fn cannot_discard_pending_append(){let mut s=step(Op::Append);s.after.pending=false;s.after.carry=Summary::default();reject(&s)}
#[test]fn pending_carry_cannot_be_skipped_by_seal_or_append(){let s=step(Op::Carry);for op in [Op::Append,Op::Seal]{let mut a=s.clone();a.action.op=op;reject(&a)}}
#[test]fn seal_regression_and_equal_watermark_rejected(){let s=fixture("pyth").1.into_iter().filter(|s|s.action.op==Op::Seal).nth(1).unwrap();for w in [0,s.before.sealed_through,u64::MAX]{let mut a=s.clone();a.action.watermark=w;a.after.sealed_through=w;reject(&a)}}
#[test]fn seal_cannot_modify_history_or_count(){let s=step(Op::Seal);let mut a=s.clone();a.after.frontier[0].min+=1;reject(&a);let mut a=s;a.after.leaf_count+=1;reject(&a)}
#[test]fn unbound_count_or_previous_frontier_fails(){let s=step(Op::Append);let z=s.before.fields(s.genesis,s.source);for i in [0,1,9,11]{let mut a=z.clone();a[i]+=F::ONE;assert!(!synthesize(&s,&a).0)}}
#[test]fn invalid_mass_and_nonzero_idle_carry_fail(){let s=step(Op::Append);let mut a=s.clone();a.before.leaf_count+=1;reject(&a);let mut a=s;a.before.carry.digest[0]=1;reject(&a)}
#[test]fn receiver_rejects_wrong_pin_frontier_or_pending_terminal(){let(c,_)=fixture("pyth");let mut a=c.clone();a.pin="00".repeat(32);assert!(a.states().is_err());let mut a=c.clone();a.final_state.frontier.iter_mut().find(|x|x.occupied).unwrap().digest[0]^=1;assert!(a.states().is_err());let mut a=c;a.final_state.pending=true;assert!(a.states().is_err())}
#[test]fn blank_shape_and_empty_seal_valid(){let s=AdmissionStep::blank();let(ok,out,n)=synthesize(&s,&s.before.fields(s.genesis,s.source));assert!(ok);assert_eq!(out,s.after.fields(s.genesis,s.source));assert_eq!(n,synthesize(&step(Op::Append),&step(Op::Append).before.fields([0;32],1)).2);assert!(advance(&State::initial(),&Action::seal(0)).is_err());assert_eq!(DEPTH,4);}
#[test]fn full_prefix_cannot_append_beyond_capacity(){let mut b=State::initial();for i in 1..=15u64{let act=Action{op:Op::Append,record:shz_hourly_index_admission_nova::Record{price_e8:100_000, publish_us:i, report_hash:hash(&i.to_le_bytes())},watermark:0};b=advance(&b,&act).unwrap();while b.pending{b=advance(&b,&Action{op:Op::Carry,record:Default::default(),watermark:0}).unwrap()}}assert_eq!(b.leaf_count,16);let mut s=AdmissionStep{before:b.clone(),after:b.clone(),action:Action{op:Op::Append,record:shz_hourly_index_admission_nova::Record{price_e8:100_000,publish_us:16,report_hash:hash(b"extra")},watermark:0},genesis:[0;32],source:1};s.after.operations+=1;s.after.leaf_count+=1;s.after.last_time=16;s.after.pending=true;s.after.carry=raw_leaf(&s);reject(&s)}

fn synthesize_legacy(s:&AdmissionStep,state:&[F])->(bool,Vec<F>,usize){
 let mut cs=TestConstraintSystem::<F>::new();let z:Vec<_>=state.iter().enumerate().map(|(i,v)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*v)).collect();
 let out=s.synthesize_hash_variant::<_,false>(&mut cs,&z).expect("legacy fixed shape");
 (cs.is_satisfied(),out.iter().map(|v|v.get_value().unwrap()).collect(),cs.num_constraints())
}
#[test]
fn shared_hash_reduces_r1cs_with_identical_outputs_and_fixed_shape(){
 let (_,t)=fixture("pyth");
 let choices=[t.iter().find(|s|s.action.op==Op::Append).unwrap(),t.iter().find(|s|s.action.op==Op::Carry&&s.after.pending).unwrap(),t.iter().find(|s|s.action.op==Op::Carry&&!s.after.pending).unwrap(),t.iter().find(|s|s.action.op==Op::Seal).unwrap()];
 let mut shape=None;
 for s in choices{
  let z=s.before.fields(s.genesis,s.source);let (old_ok,old_out,old_n)=synthesize_legacy(s,&z);let (new_ok,new_out,new_n)=synthesize(s,&z);
  assert!(old_ok&&new_ok);assert_eq!(old_out,new_out);assert_eq!(new_out,s.after.fields(s.genesis,s.source));
  assert!(new_n<old_n,"shared SHA must reduce measured application constraints");
  if let Some(pair)=shape{assert_eq!(pair,(old_n,new_n));}else{shape=Some((old_n,new_n));}
 }
 let(old,new)=shape.unwrap();println!("SHZ_ADMISSION_SHARED_SHA_COUNTS legacy={} shared={} saved={} ratio={:.6}",old,new,old-new,new as f64/old as f64);
}
#[test]
fn append_cannot_use_node_digest_and_merge_cannot_use_leaf_digest(){
 let mut a=step(Op::Append);let mut node=b"SHZ/LOG/NODE/V2".to_vec();node.extend([0u8;80]);a.after.carry.digest=hash(&node);reject(&a);
 let mut m=fixture("pyth").1.into_iter().find(|s|s.action.op==Op::Carry&&s.after.pending).unwrap();m.after.carry.digest=raw_leaf(&m).digest;reject(&m);
}
#[test]
fn append_cannot_use_unpadded_or_double_padded_digest(){
 let mut a=step(Op::Append);let r=&a.action.record;let mut b=b"SHZ/LOG/LEAF/V2".to_vec();b.push(1);b.extend(r.price_e8.to_le_bytes());b.extend(r.publish_us.to_le_bytes());b.extend(r.report_hash);assert_eq!(b.len(),64);
 b.push(0x80);b.resize(120,0);b.extend(512u64.to_be_bytes());assert_eq!(b.len(),128);a.after.carry.digest=hash(&b);reject(&a);
}
