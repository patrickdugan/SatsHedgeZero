//! Latency microbenchmark for the DLC/CET path (single-key BIP340 view of the 3-of-5 FROST oracle).
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{ProjectivePoint, Scalar};
use shz_dlc::*;
use shz_margin::{InverseContractSpec, compress_cet_ranges};
use std::hint::black_box;
use std::time::{Duration, Instant};

const NUM_BITS: u8 = 20;
const BUDGET: Duration = Duration::from_secs(8);

fn report(name: &str, mut us: Vec<f64>, count_key: &str, count: usize) {
    us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = us.len();
    let p90 = us[((n * 9).div_ceil(10)).clamp(1, n) - 1];
    println!(
        "{{\"metric\":\"{name}\",\"n\":{n},\"median_us\":{:.1},\"p90_us\":{:.1},\"max_us\":{:.1},\"{count_key}\":{count}}}",
        us[n / 2],
        p90,
        us[n - 1]
    );
}

/// Runs `f` until `max_n` reps or the time budget is used; returns per-rep microseconds.
fn bench<F: FnMut()>(max_n: usize, mut f: F) -> Vec<f64> {
    let start = Instant::now();
    let mut out = Vec::new();
    while out.len() < max_n && (out.len() < 3 || start.elapsed() < BUDGET) {
        let t = Instant::now();
        f();
        out.push(t.elapsed().as_secs_f64() * 1e6);
    }
    out
}

fn main() {
    let sk = [0x42u8; 32];
    let pk = pubkey_x_from_secret(&sk).unwrap();
    let msg = oracle_digit_message("SHZ-BTCUSD-BENCH", 3, 1);

    report("bip340_sign", bench(2000, || { black_box(bip340_sign(&sk, &msg).unwrap()); }), "msgs", 1);
    let sig = bip340_sign(&sk, &msg).unwrap();
    report("bip340_verify", bench(2000, || { bip340_verify(&pk, &msg, black_box(&sig)).unwrap(); }), "sigs", 1);
    report("bip340_verify_joint", bench(2000, || { bip340_verify_joint(&pk, &msg, black_box(&sig)).unwrap(); }), "sigs", 1);

    // Oracle: single group key; per-digit nonces pre-committed (even-Y), signed after the fact.
    let oracle_sk = [0x77u8; 32];
    let (oracle_d, oracle_pk) = normalize_bip340_keypair(&oracle_sk).unwrap();
    let event_id = "SHZ-BTCUSD-BENCH-20261126T0000Z".to_string();
    let mut nonce_k = Vec::new();
    let mut nonce_x = Vec::new();
    for j in 0..NUM_BITS {
        let mut b = [0u8; 32];
        b[0] = 0x5a;
        b[31] = j + 1;
        let k = scalar_from_bytes(&b).unwrap();
        let p = (ProjectivePoint::GENERATOR * k).to_affine();
        let k = if bool::from(p.y_is_odd()) { -k } else { k };
        nonce_x.push(<[u8; 32]>::from(p.x()));
        nonce_k.push(k);
    }
    let ann = OracleAnnouncement {
        event_id: event_id.clone(),
        maturity_unix: 1_795_000_000,
        oracle_pubkey_x: oracle_pk,
        digit_nonces_x: nonce_x.clone(),
    };
    assert_eq!(ann.num_bits(), NUM_BITS);

    report("precompute_digit_points", bench(500, || { black_box(ann.precompute_digit_points().unwrap()); }), "digits", NUM_BITS as usize);
    let table = ann.precompute_digit_points().unwrap();
    let prefix: Vec<u8> = (0..12).map(|i| (i % 2) as u8).collect();
    report(
        "anticipation_point_from_table",
        bench(20000, || { black_box(OracleAnnouncement::anticipation_point_from_table(&table, &prefix).unwrap()); }),
        "prefix_len",
        prefix.len(),
    );

    let t_point = OracleAnnouncement::anticipation_point_from_table(&table, &prefix).unwrap();
    let sh = [0x33u8; 32];
    report("adaptor_sign", bench(1000, || { black_box(adaptor_sign(&sk, &sh, &t_point).unwrap()); }), "cets", 1);
    let asig = adaptor_sign(&sk, &sh, &t_point).unwrap();
    report("adaptor_verify", bench(1000, || { adaptor_verify(&pk, &sh, &t_point, black_box(&asig)).unwrap(); }), "cets", 1);
    let t_secret: Scalar = Scalar::from(5u64);
    report("adaptor_complete", bench(20000, || { let _ = black_box(adaptor_complete(&asig, &t_secret)); }), "cets", 1);

    // Full lifecycle: 1,000 USD inverse contract entered at 58,992, 2x both sides, 20-bit domain,
    // max payout error 50 sats (same parameters as tests/frost_oracle_settlement.rs).
    let price: u64 = 58_992;
    let bits: Vec<u8> = (0..NUM_BITS).map(|j| ((price >> (NUM_BITS - 1 - j)) & 1) as u8).collect();
    let digit_sigs = |bits: &[u8]| -> Vec<Bip340Signature> {
        (0..NUM_BITS as usize)
            .map(|j| {
                let m = oracle_digit_message(&event_id, j as u8, bits[j]);
                let e = bip340_challenge(&nonce_x[j], &oracle_pk, &m);
                let s = nonce_k[j] + e * oracle_d;
                Bip340Signature { r_x: nonce_x[j], s: s.to_bytes().into() }
            })
            .collect()
    };
    let (long_sk, short_sk) = ([0x11u8; 32], [0x22u8; 32]);
    let (long_pk, short_pk) = (pubkey_x_from_secret(&long_sk).unwrap(), pubkey_x_from_secret(&short_sk).unwrap());
    let spec = InverseContractSpec::from_leverages_v0(1_000, price, 20_000, 20_000).unwrap();
    let cet_count = compress_cet_ranges(&spec, NUM_BITS, 50).unwrap().len();

    let (mut offer_us, mut sign_us, mut att_us, mut settle_us) = (vec![], vec![], vec![], vec![]);
    let (mut signed_count, start) = (0usize, Instant::now());
    for _ in 0..50 {
        if !offer_us.is_empty() && start.elapsed() > BUDGET {
            break;
        }
        let t = Instant::now();
        let mut ch = LnDlcSubchannel::offer_v0(
            BtcOutPoint { txid: [9; 32], vout: 0 },
            spec.clone(),
            long_pk,
            short_pk,
            ann.clone(),
            144,
            50,
        )
        .unwrap();
        offer_us.push(t.elapsed().as_secs_f64() * 1e6);
        let t = Instant::now();
        signed_count = ch.sign_and_activate_cets(&long_sk, &short_sk).unwrap();
        sign_us.push(t.elapsed().as_secs_f64() * 1e6);
        let t = Instant::now();
        let sigs = digit_sigs(&bits);
        att_us.push(t.elapsed().as_secs_f64() * 1e6);
        let att = OracleAttestation {
            event_id: event_id.clone(),
            attested_timestamp_unix: 1_795_000_100,
            price_usd: price,
            digit_bits: bits.clone(),
            digit_signatures: sigs,
        };
        let t = Instant::now();
        let split = ch.settle_on_chain_with_attestation(&att).unwrap();
        settle_us.push(t.elapsed().as_secs_f64() * 1e6);
        black_box(split);
    }
    assert_eq!(signed_count, cet_count);
    report("offer_v0", offer_us, "cets", 0);
    report("sign_and_activate_cets", sign_us, "cets", signed_count);
    report("oracle_attest_sign_20_digits", att_us, "digit_sigs", NUM_BITS as usize);
    report("settle_on_chain_with_attestation", settle_us, "cets_in_set", signed_count);
}
