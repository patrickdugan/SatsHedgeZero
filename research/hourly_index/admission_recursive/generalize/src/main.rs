//! ADMIT-14: independent statement, dynamic real-receipt workload and generalization.
use shz_stark_hash_compact::*;
use shz_admission_recursive_core::{Claim,expected_root};
use std::{fs,path::Path,time::Instant,panic::{catch_unwind,AssertUnwindSafe}};
type R<T>=Result<T,Box<dyn std::error::Error>>;
fn run()->R<()>{
    let args:Vec<_>=std::env::args().collect();
    if args.len()!=5{return Err("usage: shz-stark-generalize ARCHIVE_DIR RECEIVER_FIXTURE_DIR ORIGINAL_ARCHIVE_DIR NEW_OUTPUT_DIR".into())}
    let dir=Path::new(&args[1]);let fixture=Path::new(&args[2]);let original=Path::new(&args[3]);let out=Path::new(&args[4]);
    let approved:serde_json::Value=serde_json::from_str(include_str!("../../evidence/admit08-frozen-pins.json"))?;
    let registry:serde_json::Value=serde_json::from_str(include_str!("../../evidence/admit14-cases.json"))?;
    let pins:serde_json::Value=serde_json::from_slice(&fs::read(fixture.join("expected.json"))?)?;
    let case_id=pins["id"].as_str().ok_or("case id")?;
    let frozen=registry["cases"].as_array().ok_or("case registry")?.iter().find(|x|x["id"].as_str()==Some(case_id)).ok_or("unregistered receiver claim")?;
    for key in ["id","source","reports","leaves","folds","snapshot_pin","journal_sha256","proof_enabled"]{assert_eq!(pins[key],frozen[key],"receiver fixture changed: {key}");}
    assert_eq!(pins["sdk"],approved["sdk"]);assert_eq!(pins["image_id_words"],approved["image_id_words"]);
    let baseline=case_id=="pyth4-two";
    assert!(baseline||frozen["proof_enabled"]==true);
    let proof=fs::read(dir.join("proof/root.bin"))?;
    let journal=hex::decode(pins["journal_hex"].as_str().ok_or("journal pin")?)?;
    assert_eq!(hex::encode(sha(&journal)),frozen["journal_sha256"].as_str().unwrap());
    let image:[u32;8]=serde_json::from_value(approved["image_id_words"].clone())?;
    let claim:Claim=serde_json::from_slice(&fs::read(fixture.join("claim.json"))?)?;
    let leaves=frozen["leaves"].as_u64().ok_or("leaves")? as usize;
    assert_eq!(claim.pin,frozen["snapshot_pin"].as_str().unwrap());
    assert_eq!(claim.header.source,frozen["source"].as_str().unwrap());
    assert_eq!(claim.header.count,frozen["reports"].as_u64().unwrap());
    assert_eq!(claim.steps,frozen["folds"].as_u64().unwrap() as usize);
    let expected=expected_root(&claim,image,leaves)?;
    assert_eq!(expected.encode()?,journal,"Rust receiver expected journal differs from independently frozen JS bytes");
    let digest=sha(&proof);
    let old_bytes=fs::read(original.join("proof/root.bin"))?;
    assert_eq!(hex::encode(sha(&old_bytes)),approved["receipt_sha256"].as_str().unwrap());
    if baseline{assert_eq!(digest,sha(&old_bytes));}else{assert_ne!(digest,sha(&old_bytes),"fresh case reused archived proof bytes");}
    let r=decode_receipt(&proof,&journal)?;
    let old_journal=hex::decode(approved["journal_hex"].as_str().unwrap())?;
    let old=decode_receipt(&old_bytes,&old_journal)?;
    trace(&old,image)?;
    let t=Instant::now();let calls=trace(&r,image)?;let native_verify_seconds=t.elapsed().as_secs_f64();
    let count=calls.len();let work=calls.iter().map(Call::permutations).sum::<usize>();
    if count==0||count>MAX_CALLS{return Err("actual receipt outside replay call bound".into())}
    let rejects=|f:&dyn Fn()->bool|catch_unwind(AssertUnwindSafe(f)).map_or(true,|x|x);
    let bad_seal=fs::read(dir.join("proof/mutated-seal.bin"))?;
    assert_ne!(proof,bad_seal);
    assert!(rejects(&||match decode_receipt(&bad_seal,&journal){Ok(b)=>trace(&b,image).is_err(),Err(_)=>true}));
    // Bypass receipt hashes and journal-envelope equality: modify the journal
    // on an actual old cryptographic receipt and invoke the genuine verifier.
    if !baseline{
        assert_ne!(old_journal,journal);
        assert!(decode_receipt(&old_bytes,&journal).is_err());
        let mut substituted=old.clone();substituted.journal.bytes=journal.clone();
        assert!(rejects(&||trace(&substituted,image).is_err()),"old seal accepted new journal");
        let mut substituted=r.clone();substituted.journal.bytes=old_journal.clone();
        assert!(rejects(&||trace(&substituted,image).is_err()),"new seal accepted old journal");
    }
    fs::create_dir(out)?;
    let fused=true;
    let mut alternate=calls.clone();let c=&mut alternate[0];assert!(!c.words.is_empty());
    c.words[0]=(c.words[0]+1)%risc0_core::field::baby_bear::P;c.output=c.computed();assert!(c.valid_hash());
    let mut profiles=Vec::new();
    for cap in if fused{FUSED_PROFILES}else{PROFILES}{
        let dst=out.join(cap.to_string());fs::create_dir(&dst)?;
        let frames=partition(&calls,cap)?;let alt=partition(&alternate,cap)?;
        assert_eq!(frames.len(),alt.len());assert!(frames.iter().skip(1).eq(alt.iter().skip(1)));
        let start=initial(sha,digest,image,&journal,count as u32,cap);
        let mut root=start;let mut alt_root=start;let mut offset=0usize;let mut rows=Vec::new();
        for(i,(f,a))in frames.iter().zip(&alt).enumerate(){
            let n=validate_frame(f,cap)?;assert_eq!(validate_frame(a,cap)?,n);
            root=extend_commitment(sha,root,offset as u32,f);alt_root=extend_commitment(sha,alt_root,offset as u32,a);
            let permutations=parse_frame(f,cap)?.iter().map(Call::permutations).sum::<usize>();
            let name=format!("batch-{i:02}.bin");fs::write(dst.join(&name),f)?;
            rows.push(serde_json::json!({"index":i,"offset":offset,"calls":n,"permutations":permutations,"bytes":f.len(),"file":name,"commitment":hex::encode(root)}));offset+=n;
        }
        assert_eq!(offset,count);assert_ne!(root,alt_root);
        let tape=output_tape(&frames,cap)?;let alt_tape=output_tape(&alt,cap)?;
        let dec=|b:&[u8]|decode_tape(b,count,frames.len(),cap).unwrap();
        let start_time=Instant::now();let valid=replay(&r,image,dec(&tape),cap,start,root,sha);let elapsed=start_time.elapsed().as_secs_f64();assert!(valid.accepted());
        // Stronger attack: all committed hashes are correct, proof equations
        // pass with honest outputs, but the actual inputs open the wrong root.
        let mismatch=replay(&r,image,dec(&tape),cap,start,alt_root,sha);
        assert!(mismatch.upstream_verified&&mismatch.complete&&!mismatch.commitment_matches&&!mismatch.accepted());
        let bad=catch_unwind(AssertUnwindSafe(||replay(&r,image,dec(&alt_tape),cap,start,alt_root,sha))).map_or(true,|x|!x.accepted());assert!(bad);
        // Preserve all output words but move a frame boundary.
        let mut boundary=tape.clone();let a=u32::from_le_bytes(boundary[4..8].try_into().unwrap());let b=u32::from_le_bytes(boundary[8..12].try_into().unwrap());
        let (a,b)=if a<cap as u32{(a+1,b-1)}else{(a-1,b+1)};
        boundary[4..8].copy_from_slice(&a.to_le_bytes());boundary[8..12].copy_from_slice(&b.to_le_bytes());
        let wrong_boundary=match decode_tape(&boundary,count,frames.len(),cap){Ok(t)=>!replay(&r,image,t,cap,start,root,sha).accepted(),Err(_)=>true};assert!(wrong_boundary);
        let mut bad_frame=parse_frame(&frames[0],cap)?;bad_frame[0].output[0]=(bad_frame[0].output[0]+1)%risc0_core::field::baby_bear::P;
        let bad_frame=encode_frame(&bad_frame,cap)?;assert!(validate_frame(&bad_frame,cap).is_err());
        fs::write(dst.join("forged-output.bin"),bad_frame)?;
        if fused{
            let mut forged_last=parse_frame(frames.last().unwrap(),cap)?;
            forged_last[0].output[0]=(forged_last[0].output[0]+1)%risc0_core::field::baby_bear::P;
            let wrong=encode_frame(&forged_last,cap)?;assert!(validate_frame(&wrong,cap).is_err());
            fs::write(dst.join("forged-last.bin"),wrong)?;
            let mut different_last=parse_frame(frames.last().unwrap(),cap)?;
            let c=different_last.iter_mut().find(|c|!c.words.is_empty()).unwrap();
            c.words[0]=(c.words[0]+1)%risc0_core::field::baby_bear::P;c.output=c.computed();
            let wrong=encode_frame(&different_last,cap)?;assert!(validate_frame(&wrong,cap).is_ok());
            fs::write(dst.join("valid-wrong-last.bin"),wrong)?;
        }fs::write(dst.join("alternate-first.bin"),&alt[0])?;
        fs::write(dst.join("tape.bin"),&tape)?;fs::write(dst.join("alternate-tape.bin"),alt_tape)?;fs::write(dst.join("wrong-boundary.bin"),boundary)?;
        profiles.push(serde_json::json!({"cap":cap,"frame_count":frames.len(),"calls":count,"permutations":work,"frames":rows,"initial_commitment":hex::encode(start),"terminal_commitment":hex::encode(root),"alternate_terminal_commitment":hex::encode(alt_root),"tape_bytes":tape.len(),"full_transcript_bytes":frames.iter().map(|x|x.len()+4).sum::<usize>(),"native_compact_verify_seconds":elapsed,"native_verified":true,"upstream_pass_wrong_root_rejected":true,"wrong_boundary_rejected":true,"alternate_tape_rejected":true,"forged_output_rejected":true}));
    }
    assert!(profiles.iter().all(|p|p["frame_count"].as_u64().unwrap()>=2));
    let m=serde_json::json!({"schema":"shz/admit14-plan/v1","case_id":case_id,"source":claim.header.source,"reports":claim.header.count,"folds":claim.steps,"leaves":leaves,"snapshot_pin":claim.pin,"journal_hex":hex::encode(&journal),"image_id_words":image,"receipt_sha256":hex::encode(digest),"receipt_bytes":proof.len(),"calls":count,"permutations":work,"native_verify_seconds":native_verify_seconds,"native_actual_receipt_verified":true,"mutated_seal_rejected":true,"cross_journal_substitution_rejected":!baseline,"fresh_receipt":!baseline,"profiles":profiles,"near_verified":false,"production_ready":false});
    fs::write(out.join("manifest.json"),serde_json::to_vec_pretty(&m)?)?;println!("{m}");Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1)}}
