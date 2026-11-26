//! A DLC settles against the deployed FROST 3-of-5 confederation's threshold
//! oracle (ops/public-relay): the announcement and attestation produced by
//! the Python members verify with `shz_dlc`, and the attestation completes the
//! adaptor signature of exactly the CET whose price prefix it covers.
use k256::ProjectivePoint;
use serde_json::Value;
use shz_dlc::*;
use shz_margin::{InverseContractSpec, compress_cet_ranges, lookup_cet_for_price};

fn fixture(name: &str) -> Value {
    let raw = std::fs::read_to_string(format!("{}/../../ops/public-relay/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    serde_json::from_str(&raw).unwrap()
}

/// Test-run event from ops/public-relay/test_dlc.py.
#[test]
fn threshold_oracle_attestation_settles_the_matching_cet_only() {
    settle(fixture("fixture_dlc_event.json"));
}

/// Event announced and attested by the deployed confederation
/// (SHZ-BTCUSD-20261125T0915Z, 58,992 USD, signers 1/2/3).
#[test]
fn live_deployed_event_settles_the_matching_cet_only() {
    settle(fixture("fixture_dlc_event_live.json"));
}

fn settle(f: Value) {
    let ann: OracleAnnouncement = serde_json::from_value(f["announcement"].clone()).unwrap();
    let att: OracleAttestation = serde_json::from_value(f["attestation"].clone()).unwrap();
    let oracle: [u8; 32] = hex::decode(f["oracle_pubkey_x"].as_str().unwrap()).unwrap().try_into().unwrap();
    assert_eq!(ann.oracle_pubkey_x, oracle);

    // Announcement authenticity: threshold BIP340 signature over the canonical core.
    let core = serde_json::to_string(&f["announcement_core"]).unwrap();
    let msg = tagged_hash(b"SHZ/DLC/ANNOUNCEMENT/V1", core.as_bytes());
    let sig = hex::decode(f["announcement_signature"].as_str().unwrap()).unwrap();
    bip340_verify(&oracle, &msg, &Bip340Signature { r_x: sig[..32].try_into().unwrap(), s: sig[32..].try_into().unwrap() }).unwrap();

    // Every digit signature uses the pre-committed nonce and verifies.
    att.verify_against(&ann).unwrap();

    // A 1,000 USD inverse contract entered at the attested price, 2x both sides.
    let spec = InverseContractSpec::from_leverages_v0(1_000, att.price_usd, 20_000, 20_000).unwrap();
    let nb = ann.num_bits();
    let cets = compress_cet_ranges(&spec, nb, 50).unwrap();
    let cet = lookup_cet_for_price(&cets, att.price_usd, nb).unwrap();
    let idx = cets.iter().position(|c| c == cet).unwrap() as u32;
    let funding = BtcOutPoint { txid: [9; 32], vout: 0 };
    let alice = [0x11u8; 32];
    let alice_pk = pubkey_x_from_secret(&alice).unwrap();

    let t_point = ann.anticipation_point(&cet.prefix_bits).unwrap();
    let sighash = cet_sighash(&[7; 32], &funding, idx, cet);
    let asig = adaptor_sign(&alice, &sighash, &t_point).unwrap();
    adaptor_verify(&alice_pk, &sighash, &t_point, &asig).unwrap();
    let t = att.secret_scalar_for_prefix(cet.prefix_bits.len()).unwrap();
    assert_eq!(ProjectivePoint::GENERATOR * t, t_point, "attestation reveals the adaptor secret of the matching CET");
    let completed = adaptor_complete(&asig, &t).unwrap();
    bip340_verify(&alice_pk, &sighash, &completed).unwrap();

    // Any CET for a different price range cannot be completed with this attestation.
    let other = cets.iter().position(|c| !c.matches_price(att.price_usd, nb)).unwrap();
    let oc = &cets[other];
    let ot = ann.anticipation_point(&oc.prefix_bits).unwrap();
    let osh = cet_sighash(&[7; 32], &funding, other as u32, oc);
    let oasig = adaptor_sign(&alice, &osh, &ot).unwrap();
    let wrong = adaptor_complete(&oasig, &att.secret_scalar_for_prefix(oc.prefix_bits.len()).unwrap()).unwrap();
    assert!(bip340_verify(&alice_pk, &osh, &wrong).is_err());
}
