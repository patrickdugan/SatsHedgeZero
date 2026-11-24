use bincode::Options;
use risc0_zkvm::{Receipt,InnerReceipt,VerifierContext,SuccinctReceiptVerifierParameters};
use risc0_zkp::core::hash::poseidon2::Poseidon2HashSuite;
use shz_stark_fast_hash::fast_suite;
use sha2::{Digest,Sha256};
use std::{collections::BTreeMap,fs,time::Instant,panic::{catch_unwind,AssertUnwindSafe}};
fn decode(b:&[u8])->Receipt{
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(1024*1024).reject_trailing_bytes().deserialize(b).unwrap()
}
#[test]
fn actual_archived_receipt_matches_both_verifiers(){
    let Some(dir)=std::env::var_os("SHZ_FROZEN_PROOF_DIR")else{println!("archive replay not requested");return};
    let dir=std::path::PathBuf::from(dir);
    let pin:serde_json::Value=serde_json::from_str(include_str!("../../evidence/admit08-frozen-pins.json")).unwrap();
    let good=fs::read(dir.join("proof/root.bin")).unwrap();
    let bad=fs::read(dir.join("proof/mutated-seal.bin")).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&good)),pin["receipt_sha256"].as_str().unwrap());
    let receipt=decode(&good);
    let altered=decode(&bad);
    let image:[u32;8]=serde_json::from_value(pin["image_id_words"].clone()).unwrap();
    assert_eq!(hex::encode(&receipt.journal.bytes),pin["journal_hex"].as_str().unwrap());
    let succinct=match &receipt.inner{InnerReceipt::Succinct(s) if s.hashfn=="poseidon2"=>s,_=>panic!("wrong receipt kind")};
    assert_eq!(succinct.verifier_parameters.to_string(),pin["verifier_parameters"].as_str().unwrap());
    assert_eq!(receipt.journal.bytes,altered.journal.bytes);
    let mut report=vec![];
    for fast in [false,true]{
        let params=SuccinctReceiptVerifierParameters::default();
        assert_eq!(params.control_root.to_string(),pin["control_root"].as_str().unwrap());
        let suite=if fast{fast_suite()}else{Poseidon2HashSuite::new_suite()};
        let ctx=VerifierContext::empty().with_suites(BTreeMap::from([("poseidon2".into(),suite)])).with_succinct_verifier_parameters(params);
        let t=Instant::now();
        for _ in 0..20{receipt.verify_with_context(&ctx,image).unwrap();}
        let seconds=t.elapsed().as_secs_f64()/20.;
        assert!(catch_unwind(AssertUnwindSafe(||altered.verify_with_context(&ctx,image))).map_or(true,|r|r.is_err()));
        let mut wrong=image;wrong[0]^=1;
        assert!(receipt.verify_with_context(&ctx,wrong).is_err());
        report.push(serde_json::json!({"fast":fast,"native_mean_seconds":seconds,"valid":true,"mutated_seal_rejected":true,"wrong_image_rejected":true}));
    }
    println!("SHZ_FROZEN_RECEIPT_PARITY {}",serde_json::json!({"receipt_sha256":pin["receipt_sha256"],"arms":report,"native_only":true}));
}
