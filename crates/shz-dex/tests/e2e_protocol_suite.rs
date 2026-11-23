//! End-to-end protocol & adversarial negative-control suite for `SatsHedgeZero`.

use shz_dex::{OracleSettlementPolicy, OrderSide, SignedOrderIntent, ZeroFeeOrderBook};
use shz_dlc::{BtcOutPoint, pubkey_x_from_secret};
use shz_margin::{CollateralAsset, InverseContractSpec, MarginError};
use shz_oracle::{
    OracleError,
    fraud_proofs::{CanonicalReferenceEvidence, DeviationFraudProof, NearBondedOracleVault},
    frost::FrostConfederation,
    pyth_near_relay::{
        PYTH_BTC_USD_FEED_ID, RelayProviderKind, RelayQuorumPolicy, SignedFeedObservation,
        assemble_near_relay_envelope,
    },
};

#[test]
fn test_partial_fills_multi_maker_price_time_priority_zero_fee() {
    let maker_a = [0x01u8; 32];
    let maker_b = [0x02u8; 32];
    let taker_c = [0x03u8; 32];

    let mut book = ZeroFeeOrderBook::new();

    // Maker B posts $2,000 ask at $100,000 first; Maker A posts better $1,200 ask at $99,900.
    let ask_b = SignedOrderIntent::new_signed_v0(
        &maker_b,
        BtcOutPoint {
            txid: [0xB0; 32],
            vout: 0,
        },
        OrderSide::Short,
        2_000,
        100_000,
        20_000, // 2x Short
        OracleSettlementPolicy::TradeLayerVwap,
        1,
    )
    .unwrap();
    let ask_a = SignedOrderIntent::new_signed_v0(
        &maker_a,
        BtcOutPoint {
            txid: [0xA0; 32],
            vout: 0,
        },
        OrderSide::Short,
        1_200,
        99_900,
        10_000, // 1x Covered SatsHedge Short
        OracleSettlementPolicy::TradeLayerVwap,
        2,
    )
    .unwrap();

    book.submit_order(ask_b).unwrap();
    book.submit_order(ask_a).unwrap();

    // Taker C bids $2,500 up to $100,000 -> sweeps $1,200 @ $99,900 first, then $1,300 @ $100,000!
    let bid_c = SignedOrderIntent::new_signed_v0(
        &taker_c,
        BtcOutPoint {
            txid: [0xC0; 32],
            vout: 1,
        },
        OrderSide::Long,
        2_500,
        100_000,
        50_000, // 5x Long
        OracleSettlementPolicy::TradeLayerVwap,
        3,
    )
    .unwrap();

    let tickets = book.submit_order(bid_c).unwrap();
    assert_eq!(tickets.len(), 2);

    assert_eq!(tickets[0].execution_price_usd, 99_900);
    assert_eq!(tickets[0].matched_usd_notional, 1_200);
    assert_eq!(tickets[0].protocol_fee_sats, 0);

    assert_eq!(tickets[1].execution_price_usd, 100_000);
    assert_eq!(tickets[1].matched_usd_notional, 1_300);
    assert_eq!(tickets[1].protocol_fee_sats, 0);

    // Remaining $700 of Maker B's ask stays on the book.
    assert_eq!(book.asks.len(), 1);
    assert_eq!(book.asks[0].open_usd_notional, 700);
}

#[test]
fn test_frost_quorum_rotation_and_honest_attestation_not_slashed() {
    let frost = FrostConfederation::keygen_deterministic(3, 5, &[0x33u8; 32]).unwrap();
    let maturity = 1_800_000_000u64;
    let ns = frost
        .announce_event("SHZ-HONEST-CONTROL", maturity, 16, &[0x34u8; 32])
        .unwrap();

    // Fewer than t=3 signers must fail.
    assert!(matches!(
        frost.threshold_attest_price(&ns, &[1, 2], maturity, 50_000),
        Err(OracleError::InsufficientQuorum { .. })
    ));

    // Distinct 3-of-5 subsets produce the exact same deterministic threshold signature!
    let att_123 = frost
        .threshold_attest_price(&ns, &[1, 2, 3], maturity, 50_100)
        .unwrap();
    let att_245 = frost
        .threshold_attest_price(&ns, &[2, 4, 5], maturity, 50_100)
        .unwrap();
    assert_eq!(att_123.digit_signatures, att_245.digit_signatures);

    // Honest attestation at $50,100 vs Pyth+Switchboard at $50,050 (10 bps diff <= 150 bps max)
    // MUST be rejected by the fraud-proof verifier (no false-positive slashing!).
    let pyth_sk = [0x41u8; 32];
    let swb_sk = [0x42u8; 32];
    let guardians = vec![
        (RelayProviderKind::Pyth, pubkey_x_from_secret(&pyth_sk).unwrap()),
        (
            RelayProviderKind::Switchboard,
            pubkey_x_from_secret(&swb_sk).unwrap(),
        ),
    ];
    let obs1 = SignedFeedObservation::new_signed(
        RelayProviderKind::Pyth,
        PYTH_BTC_USD_FEED_ID,
        5_005_000_000_000,
        1_000_000_000,
        -8,
        5_005_000_000_000,
        maturity,
        &pyth_sk,
    )
    .unwrap();
    let obs2 = SignedFeedObservation::new_signed(
        RelayProviderKind::Switchboard,
        PYTH_BTC_USD_FEED_ID,
        5_005_000_000_000,
        1_000_000_000,
        -8,
        5_005_000_000_000,
        maturity,
        &swb_sk,
    )
    .unwrap();
    let policy = RelayQuorumPolicy::default();
    let env = assemble_near_relay_envelope(
        "shz-guard.near",
        maturity,
        vec![obs1, obs2],
        &guardians,
        &policy,
    )
    .unwrap();

    let mut vault = NearBondedOracleVault::new(
        frost.group_pubkey_x,
        1_000_000_000_000_000_000_000_000_000u128,
        10_000_000,
        150,
        120,
        1_000_000_000_000_000_000u128,
    );
    let spurious = DeviationFraudProof {
        announcement: ns.announcement,
        dishonest_attestation: att_123,
        reference_evidence: CanonicalReferenceEvidence::NearPythRelay(env),
        challenger_near_account: "griefer.near".into(),
        victim_claim: None,
    };

    assert!(matches!(
        vault.submit_deviation_fraud_proof(&spurious, &guardians, &policy, &[], 0),
        Err(OracleError::FraudProofRejected(_))
    ));
    assert!(!vault.is_slashed);
}

#[test]
fn test_tap_asset_hook_determinism_and_v0_rejection() {
    let tap = CollateralAsset::TaprootAsset {
        asset_id: [0x77; 32],
        group_key: Some([0x88; 32]),
        script_version: 1,
    };
    let h1 = tap.tap_commitment_leaf_hash(500_000).unwrap();
    let h2 = tap.tap_commitment_leaf_hash(500_000).unwrap();
    let h3 = tap.tap_commitment_leaf_hash(500_001).unwrap();
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);

    let mut spec = InverseContractSpec::from_leverages_v0(500, 100_000, 50_000, 10_000).unwrap();
    spec.collateral = tap;
    assert!(matches!(
        spec.validate_v0(),
        Err(MarginError::TapAssetDisabledInV0 { .. })
    ));
}
