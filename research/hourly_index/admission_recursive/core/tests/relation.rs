use shz_admission_recursive_core::*;
const ID:[u32;8]=[1,2,3,4,5,6,7,8];
fn fixture()->(Claim,Plan){
 (serde_json::from_str(include_str!("../../../admission_scale/fixtures/128-expected.json")).unwrap(),
 serde_json::from_str(include_str!("../../../admission_segments/fixtures/128-plan.json")).unwrap())
}
fn leaves()->(Claim,Vec<LeafInput>,Vec<Journal>){
 let(c,p)=fixture();let inputs=benchmark_inputs(&p,&c,ID).unwrap();let j=inputs.iter().map(|w|execute_leaf(w).unwrap().1).collect();(c,inputs,j)
}
#[test]fn matches_independent_128_report_wire_and_terminal(){
 let(c,_,j)=leaves();assert_eq!(j.len(),4);let a=join(&j[0],&j[1]).unwrap();let b=join(&j[2],&j[3]).unwrap();let r=join(&a,&b).unwrap();
 assert_eq!(r,expected_root(&c,ID,4).unwrap());assert_eq!(r.end_op,256);let bytes=r.encode().unwrap();assert_eq!(bytes.len(),251);assert_eq!(Journal::decode(&bytes).unwrap(),r);
 let frozen:serde_json::Value=serde_json::from_str(include_str!("../../fixtures/128-reference-journal.json")).unwrap();assert_eq!(hex::encode(bytes),frozen["journal_hex"].as_str().unwrap());
}
#[test]fn every_small_plan_matches_exact_snapshot(){
 let c:Claim=serde_json::from_str(include_str!("../../fixtures/4-expected.json")).unwrap();
 for(n,s)in [(2,include_str!("../../fixtures/4-plan-2.json")),(4,include_str!("../../fixtures/4-plan-4.json"))]{let p:Plan=serde_json::from_str(s).unwrap();let w=benchmark_inputs(&p,&c,ID).unwrap();assert_eq!(w.len(),n);let mut j:Vec<_>=w.iter().map(|x|execute_leaf(x).unwrap().1).collect();while j.len()>1{j=j.chunks_exact(2).map(|a|join(&a[0],&a[1]).unwrap()).collect();}assert_eq!(j[0],expected_root(&c,ID,n).unwrap());}
}
#[test]fn wrong_child_boundary_and_context_rejected(){let(_,_,j)=leaves();for(a,b)in [(&j[1],&j[0]),(&j[0],&j[0]),(&j[0],&j[2])]{assert!(join(a,b).is_err());}let a=&j[0];let b=&j[1];let mut x=b.clone();x.start[0]^=1;assert!(join(a,&x).is_err());let mut x=b.clone();x.ctx.image_id[0]^=1;assert!(join(a,&x).is_err());let mut x=b.clone();x.ctx.snapshot_pin[0]^=1;assert!(join(a,&x).is_err());let mut x=b.clone();x.ctx.source=2;assert!(join(a,&x).is_err());let mut x=b.clone();x.start_op+=1;assert!(join(a,&x).is_err());let mut x=b.clone();x.start_reports+=1;assert!(join(a,&x).is_err());let mut x=b.clone();x.start_seal+=1;assert!(join(a,&x).is_err());}
#[test]fn leaf_derives_state_and_rejects_bad_price_time_hash_or_empty(){
 let(_,w,_)=leaves();let a=&w[0];for r in [Record{price_e8:0,..a.records[0].clone()},Record{report_hash:[0;32],..a.records[0].clone()},Record{publish_us:0,..a.records[0].clone()}]{let mut x=a.clone();x.records[0]=r;assert!(execute_leaf(&x).is_err());}let mut x=a.clone();x.records.swap(0,1);assert!(execute_leaf(&x).is_err());let mut x=a.clone();x.records.clear();assert!(execute_leaf(&x).is_err());let mut x=a.clone();x.before.sealed_through=x.records[0].publish_us;assert!(execute_leaf(&x).is_err());}
#[test]fn forged_intermediate_state_cannot_match_frozen_plan(){let(c,mut p)=fixture();let v=p.segments[0].after.frontier.iter_mut().find(|v|v.occupied).unwrap();v.digest[0]^=1;p.segments[1].before=p.segments[0].after.clone();assert!(benchmark_inputs(&p,&c,ID).is_err());}
#[test]fn root_is_receiver_pinned_and_height_bounded(){let(c,_,j)=leaves();assert!(expected_root(&c,ID,3).is_err());assert!(expected_root(&c,ID,128).is_err());assert!(expected_root(&c,[0;8],4).is_err());let mut c2=c.clone();c2.pin="00".repeat(32);assert!(expected_root(&c2,ID,4).is_err());let a=join(&j[0],&j[1]).unwrap();assert!(join(&a,&j[2]).is_err());}
#[test]fn decoder_rejects_bad_frame_and_range(){let(_,_,j)=leaves();let b=j[0].encode().unwrap();let mut a=b.clone();a.push(0);assert!(Journal::decode(&a).is_err());let mut a=b.clone();a[73]=4;assert!(Journal::decode(&a).is_err());let mut a=b.clone();a[138]=7;assert!(Journal::decode(&a).is_err());assert!(Journal::decode(&b[..250]).is_err());}
