//! HFT-06 security review reproductions against 20a8edc (MNR-02 refund leaf heights).

use shz_dlc::pubkey_x_from_secret;
use shz_utxoref::mnr02::Mnr02TaprootTree;

fn keys() -> [[u8; 32]; 3] {
    std::array::from_fn(|i| pubkey_x_from_secret(&[(i + 1) as u8; 32]).unwrap())
}

/// F-09: a CLTV operand of 500,000,000 or more is a unix time, not a height. A refund
/// "height" just above the threshold is a 1985 timestamp, so the pre-signed refund is
/// final the moment the funding transaction confirms.
#[test]
fn refund_height_at_or_above_the_locktime_threshold_is_refused() {
    let [a, b, g] = keys();
    let tree = Mnr02TaprootTree::build(a, b, g, 499_999_990, 6, 144);
    assert!(
        tree.as_ref().map_or(true, |t| t.refund_cltv_height < 500_000_000),
        "refund CLTV operand {} is a timestamp in the past",
        tree.unwrap().refund_cltv_height
    );
}

/// F-09: `maturity_height + refund_delay_blocks` is an unchecked u32 add.
#[test]
fn refund_height_addition_does_not_wrap() {
    let [a, b, g] = keys();
    let r = std::panic::catch_unwind(|| Mnr02TaprootTree::build(a, b, g, u32::MAX - 10, 6, 144));
    match r {
        Err(_) => panic!("height addition overflowed (panic in debug, wrap to a near-zero height in release)"),
        Ok(Ok(t)) => panic!("wrapped refund height {} accepted", t.refund_cltv_height),
        Ok(Err(_)) => {}
    }
}
