//! Replay the archived real receipt. Produce bounded deterministic frames and
//! independently verify the exact transcript, including a valid wrong-input attack.
use shz_stark_hash_replay::*;
use std::{fs,path::Path,time::Instant,panic::{catch_unwind,AssertUnwindSafe}};
type R<T>=Result<T,Box<dyn std::error::Error>>;
fn run()->R<()>{
    let args:Vec<_>=std::env::args().collect();
    if args.len()!=3{return Err("usage: shz-stark-hash-replay ARCHIVE_DIR NEW_OUTPUT_DIR".into())}
    let dir=Path::new(&args[1]);let out=Path::new(&args[2]);
    let pins:serde_json::Value=serde_json::from_str(include_str!("../../evidence/admit08-frozen-pins.json"))?;
    let proof=fs::read(dir.join("proof/root.bin"))?;
    let bad=fs::read(dir.join("proof/mutated-seal.bin"))?;
    let journal=hex::decode(pins["journal_hex"].as_str().ok_or("journal pin")?)?;
    let image:[u32;8]=serde_json::from_value(pins["image_id_words"].clone())?;
    let digest=sha(&proof);
    if hex::encode(digest)!=pins["receipt_sha256"].as_str().ok_or("proof pin")?{return Err("archived receipt substitution".into())}
    let r=decode_receipt(&proof,&journal)?;
    let t=Instant::now();let calls=trace(&r,image)?;let upstream_seconds=t.elapsed().as_secs_f64();
    let count=calls.len();let permutations=calls.iter().map(Call::permutations).sum::<usize>();
    if count!=4630||permutations!=5661{return Err(format!("unexpected actual hash workload {count}/{permutations}").into())}
    let frames=partition(&calls)?;
    let t=Instant::now();let start=initial_commitment(sha,digest,image,&journal,count as u32);
    let mut commit=start;let mut offset=0u32;let mut rows=Vec::new();
    fs::create_dir(out)?;
    for (i,f) in frames.iter().enumerate(){
        let n=validate_frame(f)?;commit=extend_commitment(sha,commit,offset,f);
        let parsed=parse_frame(f)?;let work=parsed.iter().map(Call::permutations).sum::<usize>();
        let path=format!("batch-{i:02}.bin");fs::write(out.join(&path),f)?;
        rows.push(serde_json::json!({"index":i,"offset":offset,"calls":n,"permutations":work,"bytes":f.len(),"file":path,"commitment":hex::encode(commit)}));offset+=n as u32;
    }
    let batch_seconds=t.elapsed().as_secs_f64();
    let raw=encode_transcript(&frames)?;
    let (opened,root,nframes)=open_transcript(sha,start,&raw)?;
    assert_eq!(opened,calls);assert_eq!(root,commit);assert_eq!(nframes,frames.len());assert_eq!(offset,count as u32);
    let t=Instant::now();if !verify_with_validated_calls(&r,image,opened.clone()){return Err("genuine replay rejected".into())}
    let final_seconds=t.elapsed().as_secs_f64();
    let invalid=|f:&dyn Fn()->bool|catch_unwind(AssertUnwindSafe(f)).map_or(true,|x|!x);
    let bad_r=decode_receipt(&bad,&journal)?;
    assert!(invalid(&||verify_with_validated_calls(&bad_r,image,opened.clone())));
    let mut wrong_image=image;wrong_image[0]^=1;
    assert!(invalid(&||verify_with_validated_calls(&r,wrong_image,opened.clone())));
    assert!(invalid(&||verify_with_validated_calls(&r,image,opened[..opened.len()-1].to_vec())));
    let mut extra=opened.clone();extra.push(extra[0].clone());
    assert!(invalid(&||verify_with_validated_calls(&r,image,extra.clone())));
    let mut bad_hash=opened.clone();bad_hash[0].output[0]=(bad_hash[0].output[0]+1)%risc0_core::field::baby_bear::P;
    let forged_frame=encode_frame(&bad_hash[..parse_frame(&frames[0])?.len()])?;
    assert!(validate_frame(&forged_frame).is_err());fs::write(out.join("forged-output.bin"),forged_frame)?;
    // An attacker may submit an entirely valid computation of a different input.
    // Recompute its correct output and even the complete transcript commitment;
    // exact callback input matching still forbids acceptance.
    let mut alt=opened.clone();assert!(!alt[0].words.is_empty());
    alt[0].words[0]=(alt[0].words[0]+1)%risc0_core::field::baby_bear::P;
    alt[0].output=alt[0].computed();assert!(alt[0].valid_hash());
    let af=partition(&alt)?;assert_eq!(af.len(),frames.len());assert!(af.iter().skip(1).eq(frames.iter().skip(1)));
    for f in &af{validate_frame(f)?;}
    let ar=encode_transcript(&af)?;let (ac,alt_root,_)=open_transcript(sha,start,&ar)?;
    assert_ne!(alt_root,commit);assert!(invalid(&||verify_with_validated_calls(&r,image,ac.clone())));
    fs::write(out.join("alternate-first.bin"),&af[0])?;fs::write(out.join("alternate-transcript.bin"),ar)?;
    fs::write(out.join("transcript.bin"),&raw)?;
    let m=serde_json::json!({"schema":"shz/admit11-hash-replay/v1","receipt_sha256":hex::encode(digest),"calls":count,"permutations":permutations,"frames":rows,"frame_count":frames.len(),"transcript_bytes":raw.len(),"initial_commitment":hex::encode(start),"terminal_commitment":hex::encode(commit),"alternate_terminal_commitment":hex::encode(alt_root),"upstream_verify_seconds":upstream_seconds,"native_batch_verify_seconds":batch_seconds,"native_cached_verify_seconds":final_seconds,"native_actual_receipt_verified":true,"forged_output_rejected":true,"wrong_input_with_valid_hash_rejected":true,"wrong_image_rejected":true,"mutated_seal_rejected":true,"missing_extra_call_rejected":true,"near_verified":false,"production_ready":false});
    fs::write(out.join("manifest.json"),serde_json::to_vec_pretty(&m)?)?;println!("{m}");Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1)}}
