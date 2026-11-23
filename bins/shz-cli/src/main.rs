//! `shz` — Command-line runner and deterministic verification harness for `SatsHedgeZero`.

mod mnr02_regtest;

use std::path::PathBuf;
use serde::Serialize;
use shz_dex::{
    OracleSettlementPolicy, OrderSide, SignedOrderIntent, ZeroFeeOrderBook,
    evaluate_position_telemetry,
};
use shz_dlc::{BtcOutPoint, pubkey_x_from_secret};
use shz_margin::{InverseContractSpec, compress_cet_ranges};
use shz_nova_bitvm::{
    NovaBitvmDemoReport, VerificationHonestyFlags, build_verified_nova_bitvm_demo,
};
use shz_oracle::{
    fraud_proofs::{
        CanonicalReferenceEvidence, DeviationFraudProof, EquivocationFraudProof,
        NearBondedOracleVault, SlashVerdict, VictimRestitutionClaim,
    },
    frost::FrostConfederation,
    pyth_near_relay::{
        NearRelayEnvelope, PYTH_BTC_USD_FEED_ID, RelayProviderKind, RelayQuorumPolicy,
        SignedFeedObservation, assemble_near_relay_envelope,
    },
    tradelayer::{TradeLayerFill, TradeLayerVwapConfig, build_tradelayer_vwap_proof},
};

#[derive(Serialize)]
struct QuoteSummary {
    usd_notional: u64,
    entry_price_usd: u64,
    long_margin_sats: u64,
    short_margin_sats: u64,
    total_collateral_sats: u64,
    protocol_fee_sats: u64,
    long_liquidation_price_usd: u64,
    short_liquidation_price_usd: Option<u64>,
    short_is_covered_synthetic_usd: bool,
    compressed_20bit_cet_count: usize,
}

#[derive(Serialize)]
struct DexSimulationReceipt {
    event_id: String,
    execution_price_usd: u64,
    matched_usd_notional: u64,
    protocol_fee_sats: u64,
    compressed_cet_count: usize,
    tradelayer_vwap_price_usd: u64,
    tradelayer_merkle_root_hex: String,
    coop_close_mark_price_usd: u64,
    coop_close_long_sats: u64,
    coop_close_short_sats: u64,
    l1_cet_settled_price_usd: u64,
    l1_cet_long_sats: u64,
    l1_cet_short_sats: u64,
    short_hedged_usd_value_at_settlement: u64,
}

#[derive(Serialize)]
struct FraudSimulationReceipt {
    equivocation_verdict: SlashVerdict,
    equivocation_key_matches_confed_pubkey: bool,
    deviation_borsh_payload_bytes: usize,
    deviation_verdict: SlashVerdict,
}

#[derive(Serialize)]
struct NovaBitvmSummaryReceipt {
    row_count: u32,
    journal_276b_sha256_hex: String,
    batch_txid_hex: String,
    row0_transcript_600b_bytes: usize,
    nova_relation_version: String,
    nova_final_state_8_fields: [String; 8],
    secq_row0_trader_state_3_fields: [String; 3],
    bitvm3_304b_sha256_hex: String,
    bitvm3_public_input_limbs_be_dec: [String; 2],
    mnr02_bob_offline_txid_hex: String,
    honesty: VerificationHonestyFlags,
}

#[derive(Serialize)]
struct FullVerificationReport {
    protocol: &'static str,
    collateral_v0: &'static str,
    fee_bps: u16,
    dex_simulation: DexSimulationReceipt,
    fraud_simulation: FraudSimulationReceipt,
    nova_bitvm_summary: NovaBitvmSummaryReceipt,
}

fn run_quote(args: &[String]) -> QuoteSummary {
    let usd_notional = args.first().and_then(|s| s.parse().ok()).unwrap_or(1_000);
    let entry_price_usd = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let long_lev_x: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    let short_lev_x: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);

    let spec = InverseContractSpec::from_leverages_v0(
        usd_notional,
        entry_price_usd,
        long_lev_x * 10_000,
        short_lev_x * 10_000,
    )
    .expect("valid quote contract");
    let cets = compress_cet_ranges(&spec, 20, 250).expect("CET compression");

    QuoteSummary {
        usd_notional,
        entry_price_usd,
        long_margin_sats: spec.long_margin_sats,
        short_margin_sats: spec.short_margin_sats,
        total_collateral_sats: spec.total_collateral_sats(),
        protocol_fee_sats: 0,
        long_liquidation_price_usd: spec.long_liquidation_price_usd(),
        short_liquidation_price_usd: spec.short_liquidation_price_usd(),
        short_is_covered_synthetic_usd: spec.is_covered_synthetic_usd_short(),
        compressed_20bit_cet_count: cets.len(),
    }
}

fn run_dex_simulation() -> DexSimulationReceipt {
    let alice_sk = [0x11u8; 32]; // 10x Long
    let bob_sk = [0x22u8; 32]; // 1x SatsHedge Short
    let mut book = ZeroFeeOrderBook::new();

    let bob_ask = SignedOrderIntent::new_signed_v0(
        &bob_sk,
        BtcOutPoint {
            txid: [0xAA; 32],
            vout: 0,
        },
        OrderSide::Short,
        2_000,
        100_000,
        10_000, // 1.0x synthetic USD SatsHedge
        OracleSettlementPolicy::FrostBondedWithFallback,
        1,
    )
    .unwrap();
    book.submit_order(bob_ask).unwrap();

    let alice_bid = SignedOrderIntent::new_signed_v0(
        &alice_sk,
        BtcOutPoint {
            txid: [0xBB; 32],
            vout: 1,
        },
        OrderSide::Long,
        2_000,
        100_000,
        100_000, // 10.0x Long
        OracleSettlementPolicy::FrostBondedWithFallback,
        2,
    )
    .unwrap();
    let ticket = book.submit_order(alice_bid).unwrap().remove(0);

    // TradeLayer VWAP window computation around maturity ($108,200 VWAP)
    let tl_witness_1 = [0x31u8; 32];
    let tl_witness_2 = [0x32u8; 32];
    let fills = vec![
        TradeLayerFill {
            txid: [0x01; 32],
            block_height: 890_100,
            property_pair: "TL-BTC/USD".into(),
            price_usd: 108_000,
            volume_sats: 5_000_000,
            maker_id: [1; 20],
            taker_id: [2; 20],
        },
        TradeLayerFill {
            txid: [0x02; 32],
            block_height: 890_101,
            property_pair: "TL-BTC/USD".into(),
            price_usd: 108_400,
            volume_sats: 5_000_000,
            maker_id: [3; 20],
            taker_id: [4; 20],
        },
    ];
    let (tl_proof, _) = build_tradelayer_vwap_proof(
        "TL-BTC/USD",
        890_100,
        890_105,
        1_795_100_000,
        &fills,
        &TradeLayerVwapConfig::default(),
        &[tl_witness_1, tl_witness_2],
    )
    .unwrap();

    // 3-of-5 FROST confederation announces and signs the TradeLayer VWAP price
    let frost = FrostConfederation::keygen_deterministic(3, 5, &[0x44u8; 32]).unwrap();
    let event_id = "SHZ-BTCUSD-PERP-20261123";
    let nonce_state = frost
        .announce_event(event_id, 1_795_100_000, 20, &[0x55u8; 32])
        .unwrap();

    // Path A: Instant off-chain Lightning cooperative close at $108,000
    let mut sub_coop = ticket
        .into_subchannel_offer(nonce_state.announcement.clone(), 144, 250)
        .unwrap();
    let cet_count = sub_coop.sign_and_activate_cets(&alice_sk, &bob_sk).unwrap();
    let coop_split = sub_coop
        .cooperative_close_off_chain(108_000, &alice_sk, &bob_sk)
        .unwrap();

    // Path B: Unilateral L1 CET broadcast unlocked by 3-of-5 FROST attestation at TradeLayer VWAP ($108,200)
    let mut sub_l1 = ticket
        .into_subchannel_offer(nonce_state.announcement.clone(), 144, 250)
        .unwrap();
    sub_l1.sign_and_activate_cets(&alice_sk, &bob_sk).unwrap();
    let attestation = frost
        .threshold_attest_price(&nonce_state, &[1, 3, 5], 1_795_100_000, tl_proof.vwap_price_usd)
        .unwrap();
    let l1_split = sub_l1
        .settle_on_chain_with_attestation(&attestation)
        .unwrap();
    let tel = evaluate_position_telemetry(&sub_l1.spec, tl_proof.vwap_price_usd);

    DexSimulationReceipt {
        event_id: event_id.into(),
        execution_price_usd: ticket.execution_price_usd,
        matched_usd_notional: ticket.matched_usd_notional,
        protocol_fee_sats: ticket.protocol_fee_sats,
        compressed_cet_count: cet_count,
        tradelayer_vwap_price_usd: tl_proof.vwap_price_usd,
        tradelayer_merkle_root_hex: hex::encode(tl_proof.fills_merkle_root),
        coop_close_mark_price_usd: 108_000,
        coop_close_long_sats: coop_split.long_sats,
        coop_close_short_sats: coop_split.short_sats,
        l1_cet_settled_price_usd: tl_proof.vwap_price_usd,
        l1_cet_long_sats: l1_split.long_sats,
        l1_cet_short_sats: l1_split.short_sats,
        short_hedged_usd_value_at_settlement: tel.short_equity_usd_equivalent,
    }
}

fn run_fraud_simulation() -> FraudSimulationReceipt {
    // 1. Equivocation fraud proof (double-signing digit 2 -> full private key extraction)
    let frost_eq = FrostConfederation::keygen_deterministic(3, 5, &[0x66u8; 32]).unwrap();
    let ns_eq = frost_eq
        .announce_event("SHZ-EQUIVOCATION-CASE", 1_795_200_000, 20, &[0x67u8; 32])
        .unwrap();
    let sig0 = frost_eq
        .threshold_sign_digit(&ns_eq, &[1, 2, 3], 2, 0)
        .unwrap();
    let sig1 = frost_eq
        .threshold_sign_digit(&ns_eq, &[3, 4, 5], 2, 1)
        .unwrap();

    let mut vault_eq = NearBondedOracleVault::new(
        frost_eq.group_pubkey_x,
        10_000_000_000_000_000_000_000_000_000u128,
        50_000_000,
        150,
        120,
        10_000_000_000_000_000_000u128,
    );
    let eq_proof = EquivocationFraudProof {
        announcement: ns_eq.announcement.clone(),
        digit_idx: 2,
        sig_bit_zero: sig0,
        sig_bit_one: sig1,
        challenger_near_account: "slasher.near".into(),
    };
    let eq_verdict = vault_eq.submit_equivocation_fraud_proof(&eq_proof).unwrap();
    let extracted_sk = eq_verdict.extracted_btc_slash_secret_key.unwrap();
    let key_matches = pubkey_x_from_secret(&extracted_sk).unwrap() == frost_eq.group_pubkey_x;

    // 2. Dual-consensus (Pyth + Switchboard NEAR Borsh Relay + TradeLayer VWAP) Deviation Fraud Proof
    let maturity = 1_795_300_000u64;
    let frost_dev = FrostConfederation::keygen_deterministic(3, 5, &[0x77u8; 32]).unwrap();
    let ns_dev = frost_dev
        .announce_event("SHZ-DEVIATION-CASE", maturity, 20, &[0x78u8; 32])
        .unwrap();
    // Cheating FROST confederation signs $89,500 when real market is ~$100,550!
    let dishonest_att = frost_dev
        .threshold_attest_price(&ns_dev, &[2, 3, 4], maturity, 89_500)
        .unwrap();

    let pyth_sk = [0x81u8; 32];
    let swb_sk = [0x82u8; 32];
    let guardians = vec![
        (RelayProviderKind::Pyth, pubkey_x_from_secret(&pyth_sk).unwrap()),
        (
            RelayProviderKind::Switchboard,
            pubkey_x_from_secret(&swb_sk).unwrap(),
        ),
    ];
    let obs_pyth = SignedFeedObservation::new_signed(
        RelayProviderKind::Pyth,
        PYTH_BTC_USD_FEED_ID,
        10_050_000_000_000,
        2_000_000_000,
        -8,
        10_048_000_000_000,
        maturity - 3,
        &pyth_sk,
    )
    .unwrap();
    let obs_swb = SignedFeedObservation::new_signed(
        RelayProviderKind::Switchboard,
        PYTH_BTC_USD_FEED_ID,
        10_060_000_000_000,
        2_500_000_000,
        -8,
        10_055_000_000_000,
        maturity - 2,
        &swb_sk,
    )
    .unwrap();
    let policy = RelayQuorumPolicy::default();
    let relay_env = assemble_near_relay_envelope(
        "shz-oracle-guard.near",
        maturity,
        vec![obs_pyth, obs_swb],
        &guardians,
        &policy,
    )
    .unwrap();
    let relay_roundtrip = NearRelayEnvelope::from_borsh_bytes(&relay_env.to_borsh_bytes()).unwrap();

    let tl_w1 = [0x91u8; 32];
    let tl_w2 = [0x92u8; 32];
    let trusted_tl = [
        pubkey_x_from_secret(&tl_w1).unwrap(),
        pubkey_x_from_secret(&tl_w2).unwrap(),
    ];
    let tl_fills = vec![
        TradeLayerFill {
            txid: [0x10; 32],
            block_height: 890_200,
            property_pair: "TL-BTC/USD".into(),
            price_usd: 100_500,
            volume_sats: 4_000_000,
            maker_id: [1; 20],
            taker_id: [2; 20],
        },
        TradeLayerFill {
            txid: [0x11; 32],
            block_height: 890_201,
            property_pair: "TL-BTC/USD".into(),
            price_usd: 100_600,
            volume_sats: 4_000_000,
            maker_id: [3; 20],
            taker_id: [4; 20],
        },
    ];
    let (tl_proof, _) = build_tradelayer_vwap_proof(
        "TL-BTC/USD",
        890_200,
        890_205,
        maturity - 5,
        &tl_fills,
        &TradeLayerVwapConfig::default(),
        &[tl_w1, tl_w2],
    )
    .unwrap();

    let victim_spec =
        InverseContractSpec::from_leverages_v0(1_000, 100_000, 100_000, 100_000).unwrap();
    let dev_proof = DeviationFraudProof {
        announcement: ns_dev.announcement.clone(),
        dishonest_attestation: dishonest_att,
        reference_evidence: CanonicalReferenceEvidence::DualConsensus {
            relay: relay_roundtrip,
            tradelayer: tl_proof,
        },
        challenger_near_account: "watchdog.near".into(),
        victim_claim: Some(VictimRestitutionClaim {
            victim_near_account: "alice.near".into(),
            victim_is_long: true,
            contract_spec: victim_spec,
        }),
    };

    let borsh_payload = borsh::to_vec(&dev_proof).unwrap();
    let decoded_proof: DeviationFraudProof = borsh::from_slice(&borsh_payload).unwrap();

    let mut vault_dev = NearBondedOracleVault::new(
        frost_dev.group_pubkey_x,
        5_000_000_000_000_000_000_000_000_000u128,
        25_000_000,
        150,
        120,
        10_000_000_000_000_000_000u128,
    );
    let dev_verdict = vault_dev
        .submit_deviation_fraud_proof(&decoded_proof, &guardians, &policy, &trusted_tl, 2)
        .unwrap();

    FraudSimulationReceipt {
        equivocation_verdict: eq_verdict,
        equivocation_key_matches_confed_pubkey: key_matches,
        deviation_borsh_payload_bytes: borsh_payload.len(),
        deviation_verdict: dev_verdict,
    }
}

fn run_nova_demo() -> NovaBitvmDemoReport {
    build_verified_nova_bitvm_demo().expect("verified 2-contract Nova/BitVM3 demo")
}

fn summarize_nova_demo(demo: &NovaBitvmDemoReport) -> NovaBitvmSummaryReceipt {
    NovaBitvmSummaryReceipt {
        row_count: demo.row_count,
        journal_276b_sha256_hex: demo.journal.journal_sha256_hex.clone(),
        batch_txid_hex: demo.journal.batch_txid_hex.clone(),
        row0_transcript_600b_bytes: demo.row_transcripts_600b_hex[0].len() / 2,
        nova_relation_version: demo.nova_expected_statement.relation_version.clone(),
        nova_final_state_8_fields: demo.nova_expected_statement.final_state_fields.clone(),
        secq_row0_trader_state_3_fields: demo.secq_row0_claims[0].state_3_fields.clone(),
        bitvm3_304b_sha256_hex: demo.bitvm3_settlement_statement.statement_sha256_hex.clone(),
        bitvm3_public_input_limbs_be_dec: demo
            .bitvm3_settlement_statement
            .public_input_limbs_be_dec
            .clone(),
        mnr02_bob_offline_txid_hex: demo.mnr02_bridge.bob_offline_routed_txid_hex.clone(),
        honesty: demo.honesty,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("verify-all");

    match cmd {
        "quote" => {
            let summary = run_quote(&args[1..]);
            println!("{}", serde_json::to_string_pretty(&summary).unwrap());
        }
        "demo-dex" => {
            let receipt = run_dex_simulation();
            println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
        }
        "demo-fraud" => {
            let receipt = run_fraud_simulation();
            println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
        }
        "nova-demo" => {
            let report = run_nova_demo();
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "verify-all" => {
            let nova_demo = run_nova_demo();
            let report = FullVerificationReport {
                protocol: "SatsHedgeZero v0.2.0",
                collateral_v0: "VanillaBtc (P2TR UTXO / Lightning Subchannel; TAP v1 hook ready)",
                fee_bps: 0,
                dex_simulation: run_dex_simulation(),
                fraud_simulation: run_fraud_simulation(),
                nova_bitvm_summary: summarize_nova_demo(&nova_demo),
            };
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "mnr02-regtest" => {
            let default_bin = std::env::var("BITCOIND_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("bitcoind"));
            let bitcoind = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or(default_bin);
            let report = mnr02_regtest::run_mnr02_core_regtest(&bitcoind);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        _ => {
            eprintln!(
                "Usage: shz [quote [usd] [price] [long_x] [short_x] | demo-dex | demo-fraud | nova-demo | verify-all | mnr02-regtest [bitcoind_path]]"
            );
            std::process::exit(1);
        }
    }
}
