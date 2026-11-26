//! Trusted-dealer keygen (`frost.keygen`, `frost_signer.py keygen`).

use crate::ec;
use crate::frost::Rng;
use crate::json::{J, hex};
use crate::member::obj;

pub fn keygen(t: i128, n: i128, rng: &mut dyn Rng) -> Result<(J, Vec<J>), String> {
    if !(1 < t && t <= n && n < 256) {
        return Err("need 1 < t <= n < 256".into());
    }
    let mut coeffs: Vec<k256::Scalar> = (0..t).map(|_| rng.scalar()).collect();
    if ec::y_odd(&ec::g_mul(&coeffs[0])) {
        coeffs = coeffs.iter().map(|a| -*a).collect();
    }
    let shares: Vec<(i128, k256::Scalar)> =
        (1..=n).map(|i| (i, coeffs.iter().enumerate().fold(k256::Scalar::ZERO, |acc, (k, a)| acc + a * &ec::pow_small(i, k)))).collect();
    let group_x = hex(&ec::x_bytes(&ec::g_mul(&coeffs[0])));
    let mut verification = J::obj();
    for (i, s) in &shares {
        verification.set(&i.to_string(), J::s(hex(&ec::ser(&ec::g_mul(s)))));
    }
    let group = obj(vec![
        ("scheme", J::s("FROST-secp256k1-BIP340/trusted-dealer")),
        ("threshold", J::Int(t)),
        ("signers", J::Int(n)),
        ("group_pubkey", J::s(group_x)),
        ("verification_shares", verification),
    ]);
    let out = shares
        .iter()
        .map(|(i, s)| obj(vec![("index", J::Int(*i)), ("secret_share", J::s(ec::scalar_hex(s))), ("group", group.clone())]))
        .collect();
    Ok((group, out))
}
