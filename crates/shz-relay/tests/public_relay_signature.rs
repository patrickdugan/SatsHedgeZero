//! Cross-language check: a packet signed by the stdlib-Python public relayer
//! (ops/public-relay), single-key or FROST 3-of-5 aggregate, verifies with the Rust BIP340 verifier used elsewhere
//! in SHZ, and any change to the body breaks it.
use serde_json::Value;

fn message(body: &Value) -> [u8; 32] {
    // serde_json's default map is sorted, matching Python's sort_keys + compact separators.
    shz_dlc::tagged_hash(b"SHZ/PUBLIC-RELAY-PACKET/V1", serde_json::to_string(body).unwrap().as_bytes())
}

fn sig(v: &Value) -> shz_dlc::Bip340Signature {
    let b = hex::decode(v["signature"].as_str().unwrap()).unwrap();
    shz_dlc::Bip340Signature { r_x: b[..32].try_into().unwrap(), s: b[32..].try_into().unwrap() }
}

fn check(file: &str) {
    let raw = std::fs::read_to_string(format!("{}/../../ops/public-relay/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let f: Value = serde_json::from_str(&raw).unwrap();
    let pk: [u8; 32] = hex::decode(f["pubkey"].as_str().unwrap()).unwrap().try_into().unwrap();
    let pkt = &f["packet"];
    let msg = message(&pkt["body"]);
    assert_eq!(hex::encode(msg), pkt["digest"].as_str().unwrap());
    shz_dlc::bip340_verify(&pk, &msg, &sig(pkt)).unwrap();
    let mut tampered = pkt["body"].clone();
    tampered["seq"] = Value::from(tampered["seq"].as_u64().unwrap() + 1);
    assert!(shz_dlc::bip340_verify(&pk, &message(&tampered), &sig(pkt)).is_err());
}

#[test]
fn python_signed_packet_verifies_in_rust() {
    check("fixture_packet.json");
}

/// A live packet signed by the 3-of-5 FROST confederation is an ordinary
/// BIP340 signature under the group key.
#[test]
fn frost_aggregate_packet_verifies_in_rust() {
    check("fixture_frost_packet.json");
}
