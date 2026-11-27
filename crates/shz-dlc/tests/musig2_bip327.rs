//! BIP-327 test vectors (`tests/vectors/bip327/*.json`, copied from the BIP's `vectors/`) against
//! `shz_dlc::musig2`, plus the adaptor extension and the nonce store.
//!
//! Error cases compare the error kind, and for invalid contributions the signer and contribution;
//! `value` errors compare the kind only (messages are not part of the interface). `det_sign` vectors
//! (deterministic signing) are not covered: the module has no deterministic signer.
use serde_json::Value;
use shz_dlc::musig2::*;
use shz_dlc::{bip340_verify, Bip340Signature};

fn load(name: &str) -> Value {
    let p = format!("{}/tests/vectors/bip327/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn a33(v: &Value) -> [u8; 33] {
    hx(v).try_into().unwrap()
}
fn a32(v: &Value) -> [u8; 32] {
    hx(v).try_into().unwrap()
}
fn a66(v: &Value) -> [u8; 66] {
    hx(v).try_into().unwrap()
}
/// Public nonces/keys in the vectors may be malformed (wrong length is not used; bad points are).
fn idx(v: &Value) -> Vec<usize> {
    v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize).collect()
}
fn bools(v: &Value) -> Vec<bool> {
    v.as_array().unwrap().iter().map(|x| x.as_bool().unwrap()).collect()
}
fn check_err(e: MusigError, want: &Value) {
    match (want["type"].as_str().unwrap(), &e) {
        ("value", MusigError::Value(_)) => {}
        ("invalid_contribution", MusigError::InvalidContribution { signer, contrib }) => {
            assert_eq!(*signer, want["signer"].as_u64().map(|x| x as usize), "{e:?} vs {want}");
            if let Some(c) = want.get("contrib") {
                assert_eq!(*contrib, c.as_str().unwrap(), "{e:?} vs {want}");
            }
        }
        _ => panic!("got {e:?}, wanted {want}"),
    }
}

#[test]
fn key_sort_vectors() {
    let d = load("key_sort_vectors.json");
    let pks: Vec<[u8; 33]> = d["pubkeys"].as_array().unwrap().iter().map(a33).collect();
    let want: Vec<[u8; 33]> = d["sorted_pubkeys"].as_array().unwrap().iter().map(a33).collect();
    assert_eq!(key_sort(&pks), want);
}

#[test]
fn key_agg_vectors() {
    let d = load("key_agg_vectors.json");
    let x: Vec<[u8; 33]> = d["pubkeys"].as_array().unwrap().iter().map(a33).collect();
    let t: Vec<Vec<u8>> = d["tweaks"].as_array().unwrap().iter().map(hx).collect();
    for c in d["valid_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        assert_eq!(key_agg(&pks).unwrap().xonly().to_vec(), hx(&c["expected"]));
    }
    for c in d["error_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let tw: Vec<[u8; 32]> = idx(&c["tweak_indices"]).iter().map(|&i| t[i].clone().try_into().unwrap()).collect();
        check_err(key_agg_and_tweak(&pks, &tw, &bools(&c["is_xonly"])).unwrap_err(), &c["error"]);
    }
}

#[test]
fn nonce_gen_vectors() {
    let d = load("nonce_gen_vectors.json");
    for c in d["test_cases"].as_array().unwrap() {
        let opt = |k: &str| if c[k].is_null() { None } else { Some(hx(&c[k])) };
        let sk = opt("sk").map(|v| <[u8; 32]>::try_from(v).unwrap());
        let aggpk = opt("aggpk").map(|v| <[u8; 32]>::try_from(v).unwrap());
        let msg = opt("msg");
        let extra = opt("extra_in");
        let (sec, pubn) = nonce_gen_internal(&a32(&c["rand_"]), sk.as_ref(), &a33(&c["pk"]), aggpk.as_ref(), msg.as_deref(), extra.as_deref()).unwrap();
        assert_eq!(sec.0.to_vec(), hx(&c["expected_secnonce"]));
        assert_eq!(pubn.to_vec(), hx(&c["expected_pubnonce"]));
    }
}

#[test]
fn nonce_agg_vectors() {
    let d = load("nonce_agg_vectors.json");
    let pn: Vec<[u8; 66]> = d["pnonces"].as_array().unwrap().iter().map(a66).collect();
    for c in d["valid_test_cases"].as_array().unwrap() {
        let ns: Vec<[u8; 66]> = idx(&c["pnonce_indices"]).iter().map(|&i| pn[i]).collect();
        assert_eq!(nonce_agg(&ns).unwrap().to_vec(), hx(&c["expected"]));
    }
    for c in d["error_test_cases"].as_array().unwrap() {
        let ns: Vec<[u8; 66]> = idx(&c["pnonce_indices"]).iter().map(|&i| pn[i]).collect();
        check_err(nonce_agg(&ns).unwrap_err(), &c["error"]);
    }
}

fn pubkeys_of(d: &Value) -> Vec<[u8; 33]> {
    d["pubkeys"].as_array().unwrap().iter().map(a33).collect()
}

#[test]
fn sign_verify_vectors() {
    let d = load("sign_verify_vectors.json");
    let sk = a32(&d["sk"]);
    let x = pubkeys_of(&d);
    let secn: Vec<Vec<u8>> = d["secnonces"].as_array().unwrap().iter().map(hx).collect();
    let pn: Vec<[u8; 66]> = d["pnonces"].as_array().unwrap().iter().map(a66).collect();
    let an: Vec<[u8; 66]> = d["aggnonces"].as_array().unwrap().iter().map(a66).collect();
    let msgs: Vec<Vec<u8>> = d["msgs"].as_array().unwrap().iter().map(hx).collect();
    for c in d["valid_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let ns: Vec<[u8; 66]> = idx(&c["nonce_indices"]).iter().map(|&i| pn[i]).collect();
        let agg = an[c["aggnonce_index"].as_u64().unwrap() as usize];
        assert_eq!(nonce_agg(&ns).unwrap(), agg);
        let msg = msgs[c["msg_index"].as_u64().unwrap() as usize].clone();
        let si = c["signer_index"].as_u64().unwrap() as usize;
        let s = Session { aggnonce: agg, pubkeys: pks.clone(), tweaks: vec![], is_xonly: vec![], msg: msg.clone(), adaptor: None };
        let mut sec = SecNonce(secn[0].clone().try_into().unwrap());
        let psig = sign(&mut sec, &sk, &s).unwrap();
        assert_eq!(psig.to_vec(), hx(&c["expected"]));
        assert!(partial_sig_verify(&psig, &ns, &pks, &[], &[], &msg, si).unwrap());
        // the nonce is burned: signing again refuses
        assert!(matches!(sign(&mut sec, &sk, &s), Err(MusigError::Value(_))));
    }
    for c in d["sign_error_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let agg = an[c["aggnonce_index"].as_u64().unwrap() as usize];
        let msg = msgs[c["msg_index"].as_u64().unwrap() as usize].clone();
        let mut sec = SecNonce(secn[c["secnonce_index"].as_u64().unwrap() as usize].clone().try_into().unwrap());
        let s = Session { aggnonce: agg, pubkeys: pks, tweaks: vec![], is_xonly: vec![], msg, adaptor: None };
        check_err(sign(&mut sec, &sk, &s).unwrap_err(), &c["error"]);
    }
    for c in d["verify_fail_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let ns: Vec<[u8; 66]> = idx(&c["nonce_indices"]).iter().map(|&i| pn[i]).collect();
        let msg = msgs[c["msg_index"].as_u64().unwrap() as usize].clone();
        let si = c["signer_index"].as_u64().unwrap() as usize;
        assert!(!partial_sig_verify(&a32(&c["sig"]), &ns, &pks, &[], &[], &msg, si).unwrap(), "{}", c["comment"]);
    }
    for c in d["verify_error_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let ns: Vec<[u8; 66]> = idx(&c["nonce_indices"]).iter().map(|&i| pn[i]).collect();
        let msg = msgs[c["msg_index"].as_u64().unwrap() as usize].clone();
        let si = c["signer_index"].as_u64().unwrap() as usize;
        check_err(partial_sig_verify(&a32(&c["sig"]), &ns, &pks, &[], &[], &msg, si).unwrap_err(), &c["error"]);
    }
}

#[test]
fn tweak_vectors() {
    let d = load("tweak_vectors.json");
    let sk = a32(&d["sk"]);
    let x = pubkeys_of(&d);
    let secn = hx(&d["secnonce"]);
    let pn: Vec<[u8; 66]> = d["pnonces"].as_array().unwrap().iter().map(a66).collect();
    let agg = a66(&d["aggnonce"]);
    let tw: Vec<Vec<u8>> = d["tweaks"].as_array().unwrap().iter().map(hx).collect();
    let msg = hx(&d["msg"]);
    for c in d["valid_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let ns: Vec<[u8; 66]> = idx(&c["nonce_indices"]).iter().map(|&i| pn[i]).collect();
        assert_eq!(nonce_agg(&ns).unwrap(), agg);
        let t: Vec<[u8; 32]> = idx(&c["tweak_indices"]).iter().map(|&i| tw[i].clone().try_into().unwrap()).collect();
        let xo = bools(&c["is_xonly"]);
        let si = c["signer_index"].as_u64().unwrap() as usize;
        let s = Session { aggnonce: agg, pubkeys: pks.clone(), tweaks: t.clone(), is_xonly: xo.clone(), msg: msg.clone(), adaptor: None };
        let mut sec = SecNonce(secn.clone().try_into().unwrap());
        let psig = sign(&mut sec, &sk, &s).unwrap();
        assert_eq!(psig.to_vec(), hx(&c["expected"]), "{}", c["comment"]);
        assert!(partial_sig_verify(&psig, &ns, &pks, &t, &xo, &msg, si).unwrap());
    }
    for c in d["error_test_cases"].as_array().unwrap() {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let t: Vec<[u8; 32]> = idx(&c["tweak_indices"]).iter().map(|&i| tw[i].clone().try_into().unwrap()).collect();
        let s = Session { aggnonce: agg, pubkeys: pks, tweaks: t, is_xonly: bools(&c["is_xonly"]), msg: msg.clone(), adaptor: None };
        let mut sec = SecNonce(secn.clone().try_into().unwrap());
        check_err(sign(&mut sec, &sk, &s).unwrap_err(), &c["error"]);
    }
}

#[test]
fn sig_agg_vectors() {
    let d = load("sig_agg_vectors.json");
    let x = pubkeys_of(&d);
    let pn: Vec<[u8; 66]> = d["pnonces"].as_array().unwrap().iter().map(a66).collect();
    let tw: Vec<Vec<u8>> = d["tweaks"].as_array().unwrap().iter().map(hx).collect();
    let ps: Vec<Vec<u8>> = d["psigs"].as_array().unwrap().iter().map(hx).collect();
    let msg = hx(&d["msg"]);
    let run = |c: &Value| {
        let pks: Vec<[u8; 33]> = idx(&c["key_indices"]).iter().map(|&i| x[i]).collect();
        let ns: Vec<[u8; 66]> = idx(&c["nonce_indices"]).iter().map(|&i| pn[i]).collect();
        let agg = a66(&c["aggnonce"]);
        assert_eq!(nonce_agg(&ns).unwrap(), agg);
        let t: Vec<[u8; 32]> = idx(&c["tweak_indices"]).iter().map(|&i| tw[i].clone().try_into().unwrap()).collect();
        let psigs: Vec<[u8; 32]> = idx(&c["psig_indices"]).iter().map(|&i| ps[i].clone().try_into().unwrap()).collect();
        let s = Session { aggnonce: agg, pubkeys: pks.clone(), tweaks: t.clone(), is_xonly: bools(&c["is_xonly"]), msg: msg.clone(), adaptor: None };
        (partial_sig_agg(&psigs, &s), key_agg_and_tweak(&pks, &t, &bools(&c["is_xonly"])))
    };
    for c in d["valid_test_cases"].as_array().unwrap() {
        let (sig, ctx) = run(c);
        let sig = sig.unwrap();
        assert_eq!(sig.to_vec(), hx(&c["expected"]));
        let s = Bip340Signature { r_x: sig[..32].try_into().unwrap(), s: sig[32..].try_into().unwrap() };
        bip340_verify(&ctx.unwrap().xonly(), &msg, &s).unwrap();
    }
    for c in d["error_test_cases"].as_array().unwrap() {
        check_err(run(c).0.unwrap_err(), &c["error"]);
    }
}

/// Two signers (trader, batcher) with a Taproot x-only tweak sign a CET adaptor: the aggregate
/// pre-signature is not a valid signature, completes with the oracle scalar into a valid BIP-340
/// signature for the tweaked key, and the scalar is recovered from the pair.
#[test]
fn adaptor_two_of_two_with_taproot_tweak() {
    use k256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar};
    let (sk1, sk2) = ([0x11u8; 32], [0x22u8; 32]);
    let pks = key_sort(&[individual_pk(&sk1).unwrap(), individual_pk(&sk2).unwrap()]);
    let tweak = shz_dlc::tagged_hash(b"TapTweak", &key_agg(&pks).unwrap().xonly());
    let ctx = key_agg_and_tweak(&pks, &[tweak], &[true]).unwrap();
    let msg = [0x5au8; 32];
    for trial in 0u8..8 {
        let t_bytes = shz_dlc::tagged_hash(b"oracle-scalar", &[trial]);
        let t = Scalar::from_repr(t_bytes.into()).unwrap();
        let tp = ProjectivePoint::GENERATOR * t;
        let (mut s1, p1) = nonce_gen(Some(&sk1), &individual_pk(&sk1).unwrap(), Some(&ctx.xonly()), Some(&msg), None).unwrap();
        let (mut s2, p2) = nonce_gen(Some(&sk2), &individual_pk(&sk2).unwrap(), Some(&ctx.xonly()), Some(&msg), None).unwrap();
        let s = Session { aggnonce: nonce_agg(&[p1, p2]).unwrap(), pubkeys: pks.clone(), tweaks: vec![tweak], is_xonly: vec![true], msg: msg.to_vec(), adaptor: Some(tp) };
        let ps1 = sign(&mut s1, &sk1, &s).unwrap();
        let ps2 = sign(&mut s2, &sk2, &s).unwrap();
        assert!(partial_sig_verify_internal(&ps1, &p1, &individual_pk(&sk1).unwrap(), &s).unwrap());
        assert!(partial_sig_verify_internal(&ps2, &p2, &individual_pk(&sk2).unwrap(), &s).unwrap());
        let mut bad = ps1;
        bad[31] ^= 1;
        assert!(!partial_sig_verify_internal(&bad, &p1, &individual_pk(&sk1).unwrap(), &s).unwrap());
        let pre = partial_sig_agg(&[ps1, ps2], &s).unwrap();
        let as_sig = |b: &[u8; 64]| Bip340Signature { r_x: b[..32].try_into().unwrap(), s: b[32..].try_into().unwrap() };
        assert!(bip340_verify(&ctx.xonly(), &msg, &as_sig(&pre)).is_err(), "pre-signature verifies on its own");
        let neg = adaptor_negated(&s).unwrap();
        let fin = adaptor_complete(&pre, &t_bytes, neg).unwrap();
        bip340_verify(&ctx.xonly(), &msg, &as_sig(&fin)).unwrap();
        assert_eq!(adaptor_extract(&pre, &fin, neg).unwrap(), t_bytes);
        let wrong = adaptor_complete(&pre, &shz_dlc::tagged_hash(b"other", &[trial]), neg).unwrap();
        assert!(bip340_verify(&ctx.xonly(), &msg, &as_sig(&wrong)).is_err());
    }
}

/// One nonce per CET id: persisted, burned on use, refused when reused or re-stored.
#[test]
fn nonce_store_refuses_reuse() {
    let dir = std::env::temp_dir().join(format!("shz-musig-nonces-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nonces.json");
    let _ = std::fs::remove_file(&path);
    let sk = [0x33u8; 32];
    let pk = individual_pk(&sk).unwrap();
    let mut st = NonceStore::open(&path).unwrap();
    for i in 0..3 {
        let (sec, _) = nonce_gen(Some(&sk), &pk, None, None, Some(format!("cet-{i}").as_bytes())).unwrap();
        st.put(&format!("cet-{i}"), &sec).unwrap();
    }
    let (dup, _) = nonce_gen(Some(&sk), &pk, None, None, None).unwrap();
    assert!(st.put("cet-1", &dup).is_err(), "a second nonce for the same CET");
    // survives reopening; taking burns it on disk before it is used
    let mut st = NonceStore::open(&path).unwrap();
    assert_eq!(st.len(), 3);
    let mut sec = st.take("cet-1").unwrap();
    assert!(st.take("cet-1").is_err(), "reuse of a burned nonce");
    let st2 = NonceStore::open(&path).unwrap();
    assert_eq!(st2.len(), 2, "the burn was persisted");
    // the taken nonce signs once
    let pks = vec![pk];
    let (_, pubn) = (0, {
        let mut p = [0u8; 66];
        use k256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar};
        for j in 0..2 {
            let k = Scalar::from_repr(<[u8; 32]>::try_from(&sec.0[32 * j..32 * (j + 1)]).unwrap().into()).unwrap();
            p[33 * j..33 * (j + 1)].copy_from_slice(&cbytes(&(ProjectivePoint::GENERATOR * k)));
        }
        p
    });
    let s = Session { aggnonce: nonce_agg(&[pubn]).unwrap(), pubkeys: pks, tweaks: vec![], is_xonly: vec![], msg: vec![1, 2, 3], adaptor: None };
    sign(&mut sec, &sk, &s).unwrap();
    assert!(sign(&mut sec, &sk, &s).is_err(), "secnonce zeroed after one signature");
    let _ = std::fs::remove_dir_all(&dir);
}
