//! Frozen actual-receipt differential and planning experiment.
use shz_stark_hash_compact::*;
use std::{fs,path::Path,time::Instant,panic::{catch_unwind,AssertUnwindSafe}};
type R<T>=Result<T,Box<dyn std::error::Error>>;
fn run()->R<()>{
    let args:Vec<_>=std::env::args().collect();
    if args.len()!=3{return Err("usage: shz-stark-hash-compact ARCHIVE_DIR NEW_OUTPUT_DIR".into())}
    let dir=Path::new(&args[1]);let out=Path::new(&args[2]);fs::create_dir(out)?;
    let pins:serde_json::Value=serde_json::from_str(include_str!("../../evidence/admit08-frozen-pins.json"))?;
    let proof=fs::read(dir.join("proof/root.bin"))?;
    let journal=hex::decode(pins["journal_hex"].as_str().ok_or("journal pin")?)?;
    let image:[u32;8]=serde_json::from_value(pins["image_id_words"].clone())?;
    let digest=sha(&proof);assert_eq!(hex::encode(digest),pins["receipt_sha256"].as_str().unwrap());
    let r=decode_receipt(&proof,&journal)?;let calls=trace(&r,image)?;
    let count=calls.len();let work=calls.iter().map(Call::permutations).sum::<usize>();assert_eq!((count,work),(4630,5661));
    let mut alternate=calls.clone();let c=&mut alternate[0];assert!(!c.words.is_empty());
    c.words[0]=(c.words[0]+1)%risc0_core::field::baby_bear::P;c.output=c.computed();assert!(c.valid_hash());
    let mut profiles=Vec::new();
    for cap in PROFILES{
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
        fs::write(dst.join("forged-output.bin"),bad_frame)?;fs::write(dst.join("alternate-first.bin"),&alt[0])?;
        fs::write(dst.join("tape.bin"),&tape)?;fs::write(dst.join("alternate-tape.bin"),alt_tape)?;fs::write(dst.join("wrong-boundary.bin"),boundary)?;
        profiles.push(serde_json::json!({"cap":cap,"frame_count":frames.len(),"calls":count,"permutations":work,"frames":rows,"initial_commitment":hex::encode(start),"terminal_commitment":hex::encode(root),"alternate_terminal_commitment":hex::encode(alt_root),"tape_bytes":tape.len(),"full_transcript_bytes":frames.iter().map(|x|x.len()+4).sum::<usize>(),"native_compact_verify_seconds":elapsed,"native_verified":true,"upstream_pass_wrong_root_rejected":true,"wrong_boundary_rejected":true,"alternate_tape_rejected":true,"forged_output_rejected":true}));
    }
    assert_eq!(profiles.iter().map(|p|p["frame_count"].as_u64().unwrap()).collect::<Vec<_>>(),vec![12,3,2]);
    let m=serde_json::json!({"schema":"shz/admit12-plan/v1","receipt_sha256":hex::encode(digest),"profiles":profiles,"near_verified":false,"production_ready":false});
    fs::write(out.join("manifest.json"),serde_json::to_vec_pretty(&m)?)?;println!("{m}");Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1)}}
