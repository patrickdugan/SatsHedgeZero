//! `SHZ-MNR-05`: Live Bitcoin Core v31.1 Execution Harness for:
//! 1. **Unified Oracle Checker System** (`Pyth Pro` Ed25519 + `TradeLayer VWAP` Merkle proof + `<= 50 bps` midpoint),
//! 2. **Bilateral 0-Fee Taproot Matching of Option & Swap Contracts** (`Call`, `Put`, and `Dated Inverse Swaps`),
//! 3. **Taproot Position Transferability** (Mode 1 Interactive Atomic L1 Novation `U_AB -> U_DB` + Mode 2 `0x83` Offline-Bob Claim Assignment),
//! 4. **Portfolio Cross-Margin Stress Grid + Mixed Swap/Option Multilateral Atomic Clearing** (`Bob 100% Offline`),
//! 5. **Direct Cross-Verification through GPT's `shz_nova_bitvm::mnr04::parse_transaction` Bitcoin-Exact Verifier**!

use std::{path::Path, str::FromStr};

use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid, Wtxid};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{bigint::U256, ops::Reduce},
};
use serde::Serialize;
use shz_dex::{
    OracleSettlementPolicy, OrderSide,
    derivatives_book::{
        DerivativeOrderTerms, SignedDerivativeOrderIntent, TaprootDerivativesOrderBook,
    },
};
use shz_dlc::{BtcOutPoint, pubkey_x_from_secret};
use shz_margin::{OptionKind, SwapTenor, compress_derivative_cet_ranges};
use shz_nova_bitvm::mnr04::{
    Policy as Mnr04Policy, Receipt as Mnr04NativeReceipt, verify as verify_mnr04_transaction,
};
use shz_oracle::{
    checker::{
        DEFAULT_MAX_DUAL_SPREAD_BPS, OracleCheckerEngine, SecondaryOracleInput,
        compute_pyth_registry_sha256,
    },
    pyth_lazer::{
        PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS, PinnedPythSignerRegistry,
        PythProBtcUsdPolicy, build_signed_pyth_pro_btc_usd_envelope,
    },
    tradelayer::{TradeLayerFill, TradeLayerVwapConfig, build_tradelayer_vwap_proof},
};
use shz_utxoref::{
    UtxoRefError,
    transfer_and_clearing::{
        PortfolioMarginStressReport, TransferAndClearingEngine, UnifiedClearingReceipt,
        build_funded_taproot_derivative_leg, evaluate_swap_option_portfolio_margin,
    },
};

use crate::{
    mnr02_regtest::AdversarialProbeReceipt,
    testnet_clearing::{IsolatedCoreNode, UnspentClearedOutputCheck},
};

#[derive(Serialize)]
pub struct MatchedTaprootInstrumentSummary {
    pub label: &'static str,
    pub match_id_hex: String,
    pub taproot_p2tr_script_hex: String,
    pub total_collateral_sats: u64,
    pub protocol_fee_sats: u64,
    pub compressed_18bit_cet_count: usize,
}

#[derive(Serialize)]
pub struct L1TransferabilitySummary {
    pub mode1_atomic_novation_txid: String,
    pub mode1_alice_immediate_exit_sats: u64,
    pub mode1_successor_u_db_vout: u32,
    pub mode1_confirmed_height: u64,
    pub mode2_offline_bob_put_transfer_txid: String,
    pub mode2_dave_put_payout_sats: u64,
    pub mode2_double_transfer_replay_blocked: bool,
    pub stale_pre_novation_clearing_blocked: bool,
    pub forged_accounting_root_blocked: bool,
}

#[derive(Serialize)]
pub struct Mnr05DerivativesClearingReceipt {
    pub scenario: &'static str,
    pub core_version: String,
    pub oracle_checker_epoch_commitment_hex: String,
    pub oracle_checker_index_usd: u64,
    pub oracle_checker_spread_bps: u64,
    pub matched_taproot_instruments: Vec<MatchedTaprootInstrumentSummary>,
    pub portfolio_cross_margin_stress: PortfolioMarginStressReport,
    pub transferability_verification: L1TransferabilitySummary,
    pub unified_clearing_receipt: UnifiedClearingReceipt,
    pub mnr04_bitcoin_exact_verifier_receipt: Mnr04NativeReceipt,
    pub post_clearing_utxo_checks: Vec<UnspentClearedOutputCheck>,
    pub adversarial_probes: Vec<AdversarialProbeReceipt>,
    pub bitcoin_spend_enforced: bool,
    pub bob_online_during_clearing: bool,
    pub bitvm3_onchain_verified: bool,
    pub production_ready: bool,
}

fn p2tr_spk(seed: u8) -> Vec<u8> {
    let pk = pubkey_x_from_secret(&[seed; 32]).unwrap();
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&pk);
    s
}

pub fn run_mnr05_taproot_derivatives_core_regtest(
    bitcoind_path: &Path,
) -> Mnr05DerivativesClearingReceipt {
    let node = IsolatedCoreNode::spawn(bitcoind_path);
    let net_info = node.cli_json(&["getnetworkinfo"]);
    let core_version = format!(
        "Bitcoin Core v{} ({})",
        net_info["version"].as_u64().unwrap_or(0),
        net_info["subversion"].as_str().unwrap_or("bitcoind")
    );

    let _ = node.cli_raw(&["createwallet", "mnr05_miner"]);
    let miner_addr = node
        .cli_raw(&["getnewaddress", "miner", "bech32m"])
        .expect("miner address");
    node.mine_blocks(110, &miner_addr);

    // -------------------------------------------------------------------------
    // 1. Unified Oracle Checker System ($125,000 Pyth Pro + TradeLayer VWAP)
    // -------------------------------------------------------------------------
    let pyth_sk = [0x88u8; 32];
    let (pyth_env, pyth_pk) = build_signed_pyth_pro_btc_usd_envelope(
        &pyth_sk,
        1_796_000_000_000_000,
        1_796_000_000_000_000,
        PYTH_PRO_CHANNEL_FIXED_200MS,
        PYTH_PRO_BTC_USD_FEED_ID,
        12_500_000_000_000, // $125,000.00000000
        -8,
        1_000_000_000,
    );
    let pyth_reg = PinnedPythSignerRegistry::new_static(vec![pyth_pk]).unwrap();
    let pyth_reg_sha = compute_pyth_registry_sha256(&pyth_reg);

    let tl_fills = vec![
        TradeLayerFill {
            txid: [0x11; 32],
            block_height: 891_000,
            property_pair: "TL-BTC/USDC".into(),
            price_usd: 124_900,
            volume_sats: 15_000_000,
            maker_id: [1; 20],
            taker_id: [2; 20],
        },
        TradeLayerFill {
            txid: [0x12; 32],
            block_height: 891_001,
            property_pair: "TL-BTC/USDC".into(),
            price_usd: 125_100,
            volume_sats: 15_000_000,
            maker_id: [3; 20],
            taker_id: [4; 20],
        },
    ];
    let tl_cfg = TradeLayerVwapConfig::default();
    let tl_w1 = [0x71; 32];
    let tl_w2 = [0x72; 32];
    let tl_pks = [
        pubkey_x_from_secret(&tl_w1).unwrap(),
        pubkey_x_from_secret(&tl_w2).unwrap(),
    ];
    let (tl_proof, _) = build_tradelayer_vwap_proof(
        "TL-BTC/USDC",
        891_000,
        891_005,
        1_796_000_000,
        &tl_fills,
        &tl_cfg,
        &[tl_w1, tl_w2],
    )
    .unwrap();

    let mut oracle_checker =
        OracleCheckerEngine::new(pyth_reg_sha, DEFAULT_MAX_DUAL_SPREAD_BPS as u64);
    let oracle_verdict = oracle_checker
        .verify_and_commit_epoch(
            1,
            "SHZ/MNR05/BTCUSD/125K",
            &pyth_env,
            &pyth_reg,
            &PythProBtcUsdPolicy::default(),
            SecondaryOracleInput::TradeLayerVwap {
                proof: &tl_proof,
                trusted_witness_pubkeys_x: &tl_pks,
                min_witnesses: 2,
            },
            1_796_000_001_000_000,
        )
        .expect("Oracle Checker dual-source verification");
    assert_eq!(oracle_verdict.midpoint.index_whole_usd, 125_000);
    assert_eq!(oracle_verdict.midpoint.observed_spread_bps, 0);

    // -------------------------------------------------------------------------
    // 2. Bilateral 0-Fee Taproot Orderbook Matching (Swaps + Call & Put Options)
    // -------------------------------------------------------------------------
    let alice_sk = [0x11u8; 32];
    let carol_sk = [0x23u8; 32];
    let guard_sk = [0x24u8; 32];
    let dave_sk = [0x25u8; 32];
    let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();

    let maturity_height = 160u32;
    let mut deriv_book = TaprootDerivativesOrderBook::new(guard_pk, maturity_height, 20, 60);
    let expiry_ts = 1_800_000_000u64;

    // Match 1: Dated Inverse Swap `SWAP-AB` ($50,000 @ $100,000, 2x = 25M + 25M = 50M sats)
    let (match_swap_ab, match_call_bc, match_swap_cd, match_put_ab) = {
        let bob_sk_for_matching = [0x22u8; 32];

        deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &bob_sk_for_matching,
                    BtcOutPoint { txid: [1; 32], vout: 0 },
                    OrderSide::Short,
                    DerivativeOrderTerms::InverseSwap {
                        tenor: SwapTenor::Dated { expiry_timestamp: expiry_ts },
                        usd_notional: 50_000,
                        open_usd_notional: 50_000,
                        limit_price_usd: 100_000,
                        leverage_bps: 20_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    1,
                )
                .unwrap(),
            )
            .unwrap();
        let m_ab = deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &alice_sk,
                    BtcOutPoint { txid: [2; 32], vout: 0 },
                    OrderSide::Long,
                    DerivativeOrderTerms::InverseSwap {
                        tenor: SwapTenor::Dated { expiry_timestamp: expiry_ts },
                        usd_notional: 50_000,
                        open_usd_notional: 50_000,
                        limit_price_usd: 100_000,
                        leverage_bps: 20_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    1,
                )
                .unwrap(),
            )
            .unwrap()
            .remove(0);

        // Match 2: European Call Option `CALL-BC` (Bob buys 5 lots * 0.10 BTC = 0.50 BTC Call @ K=$105,000 from Carol)
        deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &carol_sk,
                    BtcOutPoint { txid: [3; 32], vout: 0 },
                    OrderSide::Short, // Option Writer
                    DerivativeOrderTerms::EuropeanOption {
                        kind: OptionKind::Call,
                        strike_price_usd: 105_000,
                        expiry_timestamp: expiry_ts,
                        lot_size_sats: 10_000_000,
                        lots: 5,
                        open_lots: 5,
                        limit_premium_per_lot_sats: 500_000,
                        writer_collateral_per_lot_sats: 10_000_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    1,
                )
                .unwrap(),
            )
            .unwrap();
        let m_bc = deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &bob_sk_for_matching,
                    BtcOutPoint { txid: [4; 32], vout: 0 },
                    OrderSide::Long, // Option Buyer
                    DerivativeOrderTerms::EuropeanOption {
                        kind: OptionKind::Call,
                        strike_price_usd: 105_000,
                        expiry_timestamp: expiry_ts,
                        lot_size_sats: 10_000_000,
                        lots: 5,
                        open_lots: 5,
                        limit_premium_per_lot_sats: 500_000,
                        writer_collateral_per_lot_sats: 10_000_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    2,
                )
                .unwrap(),
            )
            .unwrap()
            .remove(0);

        // Match 3: Offsetting Dated Inverse Swap `SWAP-CD` ($50,000 @ $125,000, Carol Long vs Dave Short, 2x = 20M + 20M)
        deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &dave_sk,
                    BtcOutPoint { txid: [5; 32], vout: 0 },
                    OrderSide::Short,
                    DerivativeOrderTerms::InverseSwap {
                        tenor: SwapTenor::Dated { expiry_timestamp: expiry_ts },
                        usd_notional: 50_000,
                        open_usd_notional: 50_000,
                        limit_price_usd: 125_000,
                        leverage_bps: 20_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    1,
                )
                .unwrap(),
            )
            .unwrap();
        let m_cd = deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &carol_sk,
                    BtcOutPoint { txid: [6; 32], vout: 0 },
                    OrderSide::Long,
                    DerivativeOrderTerms::InverseSwap {
                        tenor: SwapTenor::Dated { expiry_timestamp: expiry_ts },
                        usd_notional: 50_000,
                        open_usd_notional: 50_000,
                        limit_price_usd: 125_000,
                        leverage_bps: 20_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    2,
                )
                .unwrap(),
            )
            .unwrap()
            .remove(0);

        // Match 4: European Put Option `PUT-AB` (Alice buys 2 lots * 0.10 BTC = 0.20 BTC Put @ K=$130,000 from Bob)
        deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &bob_sk_for_matching,
                    BtcOutPoint { txid: [7; 32], vout: 0 },
                    OrderSide::Short,
                    DerivativeOrderTerms::EuropeanOption {
                        kind: OptionKind::Put,
                        strike_price_usd: 130_000,
                        expiry_timestamp: expiry_ts,
                        lot_size_sats: 10_000_000,
                        lots: 2,
                        open_lots: 2,
                        limit_premium_per_lot_sats: 500_000,
                        writer_collateral_per_lot_sats: 10_000_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    3,
                )
                .unwrap(),
            )
            .unwrap();
        let m_put = deriv_book
            .submit_order(
                SignedDerivativeOrderIntent::new_signed(
                    &alice_sk,
                    BtcOutPoint { txid: [8; 32], vout: 0 },
                    OrderSide::Long,
                    DerivativeOrderTerms::EuropeanOption {
                        kind: OptionKind::Put,
                        strike_price_usd: 130_000,
                        expiry_timestamp: expiry_ts,
                        lot_size_sats: 10_000_000,
                        lots: 2,
                        open_lots: 2,
                        limit_premium_per_lot_sats: 500_000,
                        writer_collateral_per_lot_sats: 10_000_000,
                    },
                    OracleSettlementPolicy::PythNearRelay,
                    2,
                )
                .unwrap(),
            )
            .unwrap()
            .remove(0);

        (m_ab, m_bc, m_cd, m_put)
    };

    let matched_summaries = vec![
        MatchedTaprootInstrumentSummary {
            label: "DATED-SWAP-50K-100K-P2TR",
            match_id_hex: hex::encode(match_swap_ab.match_id),
            taproot_p2tr_script_hex: hex::encode(&match_swap_ab.taproot_tree.script_pubkey),
            total_collateral_sats: match_swap_ab.contract_spec.total_collateral_sats(),
            protocol_fee_sats: match_swap_ab.protocol_fee_sats,
            compressed_18bit_cet_count: compress_derivative_cet_ranges(
                &match_swap_ab.contract_spec,
                18,
                5_000,
            )
            .unwrap()
            .len(),
        },
        MatchedTaprootInstrumentSummary {
            label: "EUROPEAN-CALL-105K-0.5BTC-P2TR",
            match_id_hex: hex::encode(match_call_bc.match_id),
            taproot_p2tr_script_hex: hex::encode(&match_call_bc.taproot_tree.script_pubkey),
            total_collateral_sats: match_call_bc.contract_spec.total_collateral_sats(),
            protocol_fee_sats: match_call_bc.protocol_fee_sats,
            compressed_18bit_cet_count: compress_derivative_cet_ranges(
                &match_call_bc.contract_spec,
                18,
                5_000,
            )
            .unwrap()
            .len(),
        },
        MatchedTaprootInstrumentSummary {
            label: "DATED-SWAP-50K-125K-P2TR",
            match_id_hex: hex::encode(match_swap_cd.match_id),
            taproot_p2tr_script_hex: hex::encode(&match_swap_cd.taproot_tree.script_pubkey),
            total_collateral_sats: match_swap_cd.contract_spec.total_collateral_sats(),
            protocol_fee_sats: match_swap_cd.protocol_fee_sats,
            compressed_18bit_cet_count: compress_derivative_cet_ranges(
                &match_swap_cd.contract_spec,
                18,
                5_000,
            )
            .unwrap()
            .len(),
        },
        MatchedTaprootInstrumentSummary {
            label: "EUROPEAN-PUT-130K-0.2BTC-P2TR",
            match_id_hex: hex::encode(match_put_ab.match_id),
            taproot_p2tr_script_hex: hex::encode(&match_put_ab.taproot_tree.script_pubkey),
            total_collateral_sats: match_put_ab.contract_spec.total_collateral_sats(),
            protocol_fee_sats: match_put_ab.protocol_fee_sats,
            compressed_18bit_cet_count: compress_derivative_cet_ranges(
                &match_put_ab.contract_spec,
                18,
                5_000,
            )
            .unwrap()
            .len(),
        },
    ];

    // Portfolio Cross-Margin Stress Grid on Bob's Short Swap + Protective Long Call Option
    let portfolio_stress = evaluate_swap_option_portfolio_margin(
        "Bob",
        &[
            (match_swap_ab.contract_spec.clone(), false),
            (match_call_bc.contract_spec.clone(), true),
        ],
        &[80_000, 100_000, 105_000, 125_000, 150_000, 200_000],
        500_000,
    )
    .unwrap();

    // -------------------------------------------------------------------------
    // 3. Fund Taproot UTXOs on Bitcoin Core v31.1 & Execute Mode 1 L1 Novation (`U_AB -> U_DB`)
    // -------------------------------------------------------------------------
    let alice_spk = p2tr_spk(0x41);
    let bob_spk = p2tr_spk(0x42);
    let carol_spk = p2tr_spk(0x43);
    let anchor_spk = p2tr_spk(0x44);
    let dave_out_spk = p2tr_spk(0x45);
    let dave_keypath_spk = p2tr_spk(0x25); // key-path P2TR controlled directly by `dave_sk = [0x25; 32]`!

    // Note: on `CALL-BC`, we place `Carol` as `holder` and `Bob` in the `0x83` `counterparty` slot
    // (`bob_holds_long_payoff = true`) so `Bob` can stay 100% OFFLINE on BOTH `U_DB` and `U_BC`!
    let bc_tree_bob_0x83 = shz_dlc::taproot_derivatives::TaprootDerivativeTree::build(
        pubkey_x_from_secret(&carol_sk).unwrap(),
        pubkey_x_from_secret(&[0x22u8; 32]).unwrap(),
        guard_pk,
        maturity_height,
        20,
        60,
    )
    .unwrap();

    let (ab_txid, ab_vout) = node.fund_raw_script(
        &match_swap_ab.taproot_tree.script_pubkey,
        match_swap_ab.contract_spec.total_collateral_sats(),
    );
    let (dave_fund_txid, dave_fund_vout) = node.fund_raw_script(&dave_keypath_spk, 32_000_000);
    let (bc_txid, bc_vout) = node.fund_raw_script(
        &bc_tree_bob_0x83.script_pubkey,
        match_call_bc.contract_spec.total_collateral_sats(),
    );
    let (cd_txid, cd_vout) = node.fund_raw_script(
        &match_swap_cd.taproot_tree.script_pubkey,
        match_swap_cd.contract_spec.total_collateral_sats(),
    );
    let (put_txid, put_vout) = node.fund_raw_script(
        &match_put_ab.taproot_tree.script_pubkey,
        match_put_ab.contract_spec.total_collateral_sats(),
    );
    node.mine_blocks(1, &miner_addr);

    let t_125k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(125_000));
    let grid = vec![(125_000u64, ProjectivePoint::GENERATOR * t_125k)];

    let mut engine = TransferAndClearingEngine::new_genesis([0x77; 32]);

    let (leg_ab, novation, leg_bc, leg_cd, leg_put) = {
        let bob_sk_ephemeral = [0x22u8; 32];

        let ab = build_funded_taproot_derivative_leg(
            "SWAP-AB",
            match_swap_ab.contract_spec.clone(),
            false,
            &alice_sk,
            &bob_sk_ephemeral,
            guard_pk,
            &ab_txid,
            ab_vout,
            1_000,
            maturity_height,
            20,
            60,
            alice_spk.clone(),
            bob_spk.clone(),
            anchor_spk.clone(),
            &grid,
        )
        .unwrap();
        engine.register_active_leg(&ab).unwrap();

        // Mode 1 Novation (`Alice -> Dave` for 29,500,000 sats immediate BTC payout before maturity!)
        let nov = engine
            .execute_atomic_taproot_novation(
                &ab,
                &alice_sk,
                &bob_sk_ephemeral,
                &dave_sk,
                &dave_fund_txid,
                dave_fund_vout,
                32_000_000,
                dave_keypath_spk.clone(),
                29_500_000,
                1_000,
                alice_spk.clone(),
                dave_out_spk.clone(),
                "SWAP-DB-NOVATED",
                &grid,
            )
            .unwrap();

        let bc = build_funded_taproot_derivative_leg(
            "CALL-BC",
            match_call_bc.contract_spec.clone(),
            true, // Bob holds the Long Call Option payoff via 0x83!
            &carol_sk,
            &bob_sk_ephemeral,
            guard_pk,
            &bc_txid,
            bc_vout,
            1_000,
            maturity_height,
            20,
            60,
            carol_spk.clone(),
            bob_spk.clone(),
            anchor_spk.clone(),
            &grid,
        )
        .unwrap();
        engine.register_active_leg(&bc).unwrap();

        let cd = build_funded_taproot_derivative_leg(
            "SWAP-CD",
            match_swap_cd.contract_spec.clone(),
            false,
            &carol_sk,
            &dave_sk,
            guard_pk,
            &cd_txid,
            cd_vout,
            1_000,
            maturity_height,
            20,
            60,
            carol_spk.clone(),
            dave_out_spk.clone(),
            anchor_spk.clone(),
            &grid,
        )
        .unwrap();
        engine.register_active_leg(&cd).unwrap();

        let put = build_funded_taproot_derivative_leg(
            "PUT-AB-130K",
            match_put_ab.contract_spec.clone(),
            false, // Alice holds Long Put, Bob wrote Put (`0x83`)
            &alice_sk,
            &bob_sk_ephemeral,
            guard_pk,
            &put_txid,
            put_vout,
            1_000,
            maturity_height,
            20,
            60,
            alice_spk.clone(),
            bob_spk.clone(),
            anchor_spk.clone(),
            &grid,
        )
        .unwrap();
        engine.register_active_leg(&put).unwrap();

        (ab, nov, bc, cd, put)
        // `bob_sk_ephemeral` DROPPED HERE — Bob is 100% OFFLINE for all subsequent operations!
    };

    // Broadcast & confirm Mode 1 Atomic Taproot Novation TX (`U_AB -> U_DB`) BEFORE maturity!
    let raw_nov_hex = hex::encode(novation.signed_novation_tx.serialize_segwit());
    let (nov_ok, nov_reason) = node.test_mempool_accept(&raw_nov_hex);
    assert!(nov_ok, "Core rejected Mode 1 Taproot Novation tx: {nov_reason}");
    let sent_nov_txid = node.cli_raw(&["sendrawtransaction", &raw_nov_hex]).unwrap();
    assert_eq!(sent_nov_txid, novation.novation_txid_hex);
    let nov_conf_height = node.mine_blocks(1, &miner_addr);
    // Verify Alice's immediate 29,500,000-sat exit UTXO (`vout[1]`) is live in Bitcoin Core!
    assert!(
        !node
            .cli_raw(&["gettxout", &sent_nov_txid, "1"])
            .unwrap()
            .is_empty()
    );

    // Advance chain to `maturity_height = 160`
    let cur_h = node.height();
    if cur_h < maturity_height as u64 {
        node.mine_blocks(maturity_height as u64 - cur_h, &miner_addr);
    }

    // -------------------------------------------------------------------------
    // 4. Mode 2 Counterparty-Offline (`0x83`) Put Option Claim Transfer (`Alice -> Dave`)
    // -------------------------------------------------------------------------
    let mode2_transfer = engine
        .authorize_offline_bob_claim_transfer(
            &leg_put,
            0,
            &t_125k,
            &alice_sk,
            &guard_sk,
            dave_out_spk.clone(),
        )
        .expect("Mode 2 offline Bob Put Option claim transfer");
    // Double-transfer attempt to Mallory MUST fail closed!
    let double_transfer_blocked = engine
        .authorize_offline_bob_claim_transfer(
            &leg_put,
            0,
            &t_125k,
            &alice_sk,
            &guard_sk,
            p2tr_spk(0x99),
        )
        .unwrap_err()
        == UtxoRefError::ReplayDetected("contract claim already transferred or settled");
    assert!(double_transfer_blocked);

    let raw_mode2_hex = hex::encode(
        mode2_transfer
            .finalized_maturity_tx_for_outcome
            .serialize_segwit(),
    );
    let sent_mode2_txid = node
        .cli_raw(&["sendrawtransaction", &raw_mode2_hex])
        .expect("broadcast Mode 2 offline-Bob Put Option transfer tx");
    let dave_put_payout_sats = mode2_transfer.finalized_maturity_tx_for_outcome.outputs[1].0;

    // -------------------------------------------------------------------------
    // 5. Mixed Swap + Option Multilateral Atomic Clearing (`Bob 100% Offline`) + Core + MNR-04 Verify
    // -------------------------------------------------------------------------
    let prior_root = engine.ledger_state_root;
    let regtest_genesis: [u8; 32] =
        hex::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
            .unwrap()
            .try_into()
            .unwrap();

    // Verify stale pre-novation `leg_ab` & forged prior root both fail closed
    let stale_blocked = engine
        .execute_mixed_swap_option_bob_offline_clearing(
            &prior_root,
            &leg_ab,
            &leg_bc,
            &leg_cd,
            0,
            &t_125k,
            &oracle_verdict.epoch_commitment_hash,
            &dave_sk,
            &carol_sk,
            &guard_sk,
            2_670,
            &regtest_genesis,
            "bitcoin-regtest",
        )
        .is_err();
    let forged_root_blocked = engine
        .execute_mixed_swap_option_bob_offline_clearing(
            &[0xEE; 32],
            &novation.successor_leg,
            &leg_bc,
            &leg_cd,
            0,
            &t_125k,
            &oracle_verdict.epoch_commitment_hash,
            &dave_sk,
            &carol_sk,
            &guard_sk,
            2_670,
            &regtest_genesis,
            "bitcoin-regtest",
        )
        .is_err();
    assert!(stale_blocked && forged_root_blocked);

    let (clear_tx, clearing_receipt) = engine
        .execute_mixed_swap_option_bob_offline_clearing(
            &prior_root,
            &novation.successor_leg,
            &leg_bc,
            &leg_cd,
            0,
            &t_125k,
            &oracle_verdict.epoch_commitment_hash,
            &dave_sk,
            &carol_sk,
            &guard_sk,
            2_670,
            &regtest_genesis,
            "bitcoin-regtest",
        )
        .expect("execute mixed Swap + Call Option Bob-offline clearing");

    let mut probes = Vec::new();
    // Adversarial Core Probe 1: 1-sat shave on offline Bob's Swap output `vout[0]`
    let mut shave_swap = clear_tx.clone();
    shave_swap.outputs[0].0 -= 1;
    shave_swap.outputs[2].0 += 1;
    let (shave_swap_ok, shave_swap_reason) =
        node.test_mempool_accept(&hex::encode(shave_swap.serialize_segwit()));
    assert!(!shave_swap_ok);
    probes.push(AdversarialProbeReceipt {
        probe_id: "mnr05-shave-1-sat-bob-novated-swap-vout0",
        description: "Shave 1 sat from offline Bob's novated Swap 0x83 output vout[0] (15,000,000 -> 14,999,999)",
        core_accepted: shave_swap_ok,
        core_reject_reason: shave_swap_reason,
    });

    // Adversarial Core Probe 2: 1-sat shave on offline Bob's ITM Call Option output `vout[1]`
    let mut shave_opt = clear_tx.clone();
    shave_opt.outputs[1].0 -= 1;
    shave_opt.outputs[3].0 += 1;
    let (shave_opt_ok, shave_opt_reason) =
        node.test_mempool_accept(&hex::encode(shave_opt.serialize_segwit()));
    assert!(!shave_opt_ok);
    probes.push(AdversarialProbeReceipt {
        probe_id: "mnr05-shave-1-sat-bob-call-option-vout1",
        description: "Shave 1 sat from offline Bob's ITM Call Option 0x83 output vout[1] (8,000,000 -> 7,999,999)",
        core_accepted: shave_opt_ok,
        core_reject_reason: shave_opt_reason,
    });

    // Broadcast & confirm `clear_tx` on Bitcoin Core v31.1!
    let raw_clear_bytes = clear_tx.serialize_segwit();
    let raw_clear_hex = hex::encode(&raw_clear_bytes);
    let (honest_ok, honest_reason) = node.test_mempool_accept(&raw_clear_hex);
    assert!(
        honest_ok,
        "Core rejected MNR-05 mixed Swap+Option clearing tx: {honest_reason}"
    );
    let sent_clear_txid = node.cli_raw(&["sendrawtransaction", &raw_clear_hex]).unwrap();
    node.mine_blocks(6, &miner_addr);

    // Cross-verify `raw_clear_bytes` directly through GPT's `shz_nova_bitvm::mnr04::parse_transaction`!
    let mnr04_policy = Mnr04Policy {
        network: Network::Regtest,
        prevouts: [
            (
                OutPoint::new(Txid::from_str(&novation.novation_txid_hex).unwrap(), 0),
                TxOut {
                    value: Amount::from_sat(novation.successor_leg.funding_sats),
                    script_pubkey: ScriptBuf::from_bytes(
                        novation.successor_leg.tree.script_pubkey.clone(),
                    ),
                },
            ),
            (
                OutPoint::new(Txid::from_str(&bc_txid).unwrap(), bc_vout),
                TxOut {
                    value: Amount::from_sat(leg_bc.funding_sats),
                    script_pubkey: ScriptBuf::from_bytes(leg_bc.tree.script_pubkey.clone()),
                },
            ),
            (
                OutPoint::new(Txid::from_str(&cd_txid).unwrap(), cd_vout),
                TxOut {
                    value: Amount::from_sat(leg_cd.funding_sats),
                    script_pubkey: ScriptBuf::from_bytes(leg_cd.tree.script_pubkey.clone()),
                },
            ),
        ],
        outputs: std::array::from_fn(|i| TxOut {
            value: Amount::from_sat(clear_tx.outputs[i].0),
            script_pubkey: ScriptBuf::from_bytes(clear_tx.outputs[i].1.clone()),
        }),
        txid: Txid::from_str(&clearing_receipt.atomic_clearing_txid_hex).unwrap(),
        wtxid: Wtxid::from_str(&clearing_receipt.atomic_clearing_wtxid_hex).unwrap(),
        lock_time: clear_tx.locktime,
        fee_sats: clearing_receipt.miner_fee_sats,
        epoch_context: oracle_verdict.epoch_commitment_hash,
    };
    let mnr04_receipt = verify_mnr04_transaction(&raw_clear_bytes, &mnr04_policy)
        .expect("MNR-04 Bitcoin-exact verify");
    assert!(mnr04_receipt.native_signature_verified);
    assert_eq!(mnr04_receipt.txid, sent_clear_txid);

    let owners = [
        ("Bob-Novated-Swap-0x83", clear_tx.outputs[0].0),
        ("Bob-Protective-Call-Option-0x83", clear_tx.outputs[1].0),
        ("Dave-Novated-Swap-Winner", clear_tx.outputs[2].0),
        ("Carol-Option-Writer-Cleared", clear_tx.outputs[3].0),
        ("UTXORef-CPFP-Anchor", clear_tx.outputs[4].0),
    ];
    let mut utxo_checks = Vec::with_capacity(5);
    for (vout, (owner, sats)) in owners.into_iter().enumerate() {
        let out_txt = node
            .cli_raw(&["gettxout", &sent_clear_txid, &vout.to_string()])
            .unwrap();
        assert!(!out_txt.is_empty());
        utxo_checks.push(UnspentClearedOutputCheck {
            owner,
            vout: vout as u32,
            sats,
            utxo_present_in_core: true,
        });
    }

    Mnr05DerivativesClearingReceipt {
        scenario: "SHZ-MNR-05: Oracle Checker + Bilateral Taproot Option/Swap Matching + L1 Atomic Novation + Offline 0x83 Claim Transfer + Cross-Margined Swap/Option Clearing (Core v31.1 + MNR-04 Verified)",
        core_version,
        oracle_checker_epoch_commitment_hex: hex::encode(oracle_verdict.epoch_commitment_hash),
        oracle_checker_index_usd: oracle_verdict.midpoint.index_whole_usd,
        oracle_checker_spread_bps: oracle_verdict.midpoint.observed_spread_bps,
        matched_taproot_instruments: matched_summaries,
        portfolio_cross_margin_stress: portfolio_stress,
        transferability_verification: L1TransferabilitySummary {
            mode1_atomic_novation_txid: sent_nov_txid,
            mode1_alice_immediate_exit_sats: 29_500_000,
            mode1_successor_u_db_vout: 0,
            mode1_confirmed_height: nov_conf_height,
            mode2_offline_bob_put_transfer_txid: sent_mode2_txid,
            mode2_dave_put_payout_sats: dave_put_payout_sats,
            mode2_double_transfer_replay_blocked: double_transfer_blocked,
            stale_pre_novation_clearing_blocked: stale_blocked,
            forged_accounting_root_blocked: forged_root_blocked,
        },
        unified_clearing_receipt: clearing_receipt,
        mnr04_bitcoin_exact_verifier_receipt: mnr04_receipt,
        post_clearing_utxo_checks: utxo_checks,
        adversarial_probes: probes,
        bitcoin_spend_enforced: true,
        bob_online_during_clearing: false,
        bitvm3_onchain_verified: false,
        production_ready: false,
    }
}
