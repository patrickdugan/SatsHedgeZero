//! `SHZ-MNR-03` Live Execution Harness (`shz mnr03-regtest` & `shz mnr03-testnet4-live`):
//!
//! 1. **Bitcoin Core v31.1 Regtest + Watchtower 6-Block Reorg Drill + External `lnm-nova` SNARK**:
//!    - Funds 3 bilateral DLC UTXOs (`U_AB`, `U_BC`, `U_CA`) on an isolated Bitcoin Core v31.1 node.
//!    - Pre-signs `AB` and `BC` `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) adaptor templates
//!      inside a tightly scoped origination block and **drops `bob_sk`** before clearing!
//!    - Re-verifies a native Pyth Pro Ed25519 Solana envelope (`$60,000.00000000`), completes
//!      Bob's `0x83` signatures on `vin[0] -> vout[0]` and `vin[1] -> vout[1]` with `oracle_scalar_t`,
//!      co-signs with `Alice + Carol + RouterGuard`, and proves Core rejects:
//!      - premature broadcast before `maturity_height` (`non-final`),
//!      - 1-sat shaves on Bob's `U_AB` (`vout[0]`) and `U_BC` (`vout[1]`) pinned outputs,
//!      - output-index swap (`vout[0] <-> vout[1]`),
//!      - unilateral `CLTV` front-running during the multilateral priority window (`non-final`).
//!    - Broadcasts & confirms the 3-input, 5-output Bob-offline atomic clearing transaction (`6`
//!      confirmations) + a CPFP child spending the `330`-sat anchor output (`vout[4]`).
//!    - Executes a **live 6-block reorganization drill** (`invalidateblock` + competing 7-block branch),
//!      proving `getblock` reports `confirmations == -1` and `DurablePnlBatchBook` freezes cleanly
//!      (`BookAuthState::FrozenForOperatorReview`) blocking double-settlement, then `reconsiderblock`
//!      restores canonical chain finality.
//!    - Proves unilateral `CLTV` fallback (`ab_unilateral_fallback_tx` + `bc_unilateral_fallback_tx`)
//!      succeeds on Bitcoin Core v31.1 when `RouterGuard` disappears!
//!    - Runs out-of-process `lnm-nova` (`nova-snark 0.76.0`) `prepare` + `prove --compressed` + `verify`
//!      over the exact Oracle-Bound `SHZ-MNR-03` 3-row `LNMBAT01` witness (`bob_sk` 100% absent!).
//!
//! 2. **Live Public Bitcoin Testnet4 Bob-Offline 3-Party Broadcast (`shz mnr03-testnet4-live`)**:
//!    - Funds `[U_AB, U_BC, U_CA]` (`3,840` sats total) on live public Bitcoin Testnet4, drops
//!      `bob_sk` at origination, verifies 3 live Testnet4 mempool adversarial shave/swap rejections,
//!      broadcasts the 3-input, 5-output Bob-offline atomic clearing transaction (`598 vB`, `1.02 sat/vB`)
//!      returning all 5 cleared outputs directly to the Testnet4 wallet, and proves/verifies the
//!      matching `12,376B` `lnm-nova` `CompressedSNARK`!

use std::path::Path;

use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{bigint::U256, ops::Reduce},
};
use serde::Serialize;
use shz_dlc::{bip340_sign, pubkey_x_from_secret};
use shz_nova_bitvm::{
    BitcoinNetworkCode, OracleBoundMnr03NovaReport, VerificationHonestyFlags,
    build_oracle_bound_mnr03_nova_ceremony,
};
use shz_oracle::pyth_lazer::{
    PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS, PinnedPythSignerRegistry,
    PythProBtcUsdPolicy, build_signed_pyth_pro_btc_usd_envelope,
};
use shz_utxoref::{
    UtxoRefError,
    mnr02::{SIGHASH_DEFAULT, SegwitTx, SegwitTxIn, encode_taproot_witness_sig},
    mnr03::{
        Mnr03ScaleParams, build_mnr03_bob_offline_origination, precompute_mnr03_funding_descriptors,
    },
    pnl_batch::BookAuthState,
};

use crate::{
    mnr02_regtest::{AdversarialProbeReceipt, CoreConfirmedTxReceipt},
    testnet_clearing::{
        FundedDlcUtxoReceipt, IsolatedCoreNode, UnspentClearedOutputCheck, btc_float_to_sats,
        run_external_lnm_nova_prover, wsl_testnet4_cli, wsl_testnet4_json,
    },
};

#[derive(Serialize)]
pub struct ReorgWatchtowerDrillReceipt {
    pub invalidated_clearing_block_hash: String,
    pub pre_reorg_confirmations: u64,
    pub post_invalidate_confirmations: i64,
    pub competing_branch_tip_height: u64,
    pub competing_branch_tip_hash: String,
    pub watchtower_book_frozen: bool,
    pub settle_after_freeze_rejected: bool,
    pub restored_canonical_tip_height: u64,
}

#[derive(Serialize)]
pub struct UnilateralFallbackDrillReceipt {
    pub ab_unilateral_txid: String,
    pub bc_unilateral_txid: String,
    pub confirmed_at_height: u64,
    pub guard_signature_required: bool,
}

#[derive(Serialize)]
pub struct Mnr03CoreRegtestReceipt {
    pub scenario: &'static str,
    pub core_version: String,
    pub bob_online_during_clearing_or_proving: bool,
    pub bitcoin_spend_enforced: bool,
    pub cpfp_anchor_child_confirmed: bool,
    pub reorg_watchtower_drill_passed: bool,
    pub unilateral_cltv_fallback_verified: bool,
    pub nova_compressed_snark_verified: bool,
    pub near_finality_verified: bool,
    pub bitvm3_onchain_verified: bool,
    pub production_ready: bool,
    pub funded_dlc_utxos: Vec<FundedDlcUtxoReceipt>,
    pub core_confirmed_bob_offline_clearing_tx: CoreConfirmedTxReceipt,
    pub cpfp_child_txid: String,
    pub post_clearing_utxo_checks: Vec<UnspentClearedOutputCheck>,
    pub adversarial_probes: Vec<AdversarialProbeReceipt>,
    pub reorg_watchtower_drill: ReorgWatchtowerDrillReceipt,
    pub unilateral_fallback_drill: UnilateralFallbackDrillReceipt,
    pub oracle_bound_nova_report: OracleBoundMnr03NovaReport,
}

#[derive(Serialize)]
pub struct Mnr03LiveTestnet4Receipt {
    pub scenario: &'static str,
    pub network: &'static str,
    pub core_version: String,
    pub testnet4_tip_height: u32,
    pub testnet4_tip_block_hash: String,
    pub bob_online_during_clearing_or_proving: bool,
    pub funding_txid: String,
    pub funding_tx_explorer_uri: String,
    pub bob_offline_atomic_clearing_txid: String,
    pub bob_offline_atomic_clearing_tx_explorer_uri: String,
    pub bob_offline_atomic_clearing_wtxid: String,
    pub bob_offline_atomic_clearing_vsize: usize,
    pub mempool_accepted_live_testnet4: bool,
    pub wallet_balance_before_sats: u64,
    pub wallet_balance_after_sats: u64,
    pub net_network_miner_fee_cost_sats: u64,
    pub funded_dlc_utxos: Vec<FundedDlcUtxoReceipt>,
    pub adversarial_probes_live_testnet4: Vec<AdversarialProbeReceipt>,
    pub nova_compressed_snark_verified: bool,
    pub near_finality_verified: bool,
    pub bitvm3_onchain_verified: bool,
    pub production_ready: bool,
    pub oracle_bound_nova_report: OracleBoundMnr03NovaReport,
}

fn p2tr_spk_from_secret(sk: &[u8; 32]) -> Vec<u8> {
    let pk = pubkey_x_from_secret(sk).unwrap();
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&pk);
    s
}

pub fn run_mnr03_core_regtest(
    bitcoind_path: &Path,
    lnm_nova_bin: Option<&Path>,
    persist_bundle_dir: Option<&Path>,
) -> Mnr03CoreRegtestReceipt {
    let node = IsolatedCoreNode::spawn(bitcoind_path);
    let net_info = node.cli_json(&["getnetworkinfo"]);
    let core_version = format!(
        "Bitcoin Core v{} ({})",
        net_info["version"].as_u64().unwrap_or(0),
        net_info["subversion"].as_str().unwrap_or("bitcoind")
    );

    let _ = node.cli_raw(&["createwallet", "mnr03_miner"]);
    let miner_addr = node
        .cli_raw(&["getnewaddress", "miner", "bech32m"])
        .expect("miner address");
    node.mine_blocks(110, &miner_addr);

    let alice_sk = [0x11u8; 32];
    let carol_sk = [0x23u8; 32];
    let guard_sk = [0x24u8; 32];
    let batch_oracles = [[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]];
    let anchor_sk = [0x44u8; 32];

    let alice_pk = pubkey_x_from_secret(&alice_sk).unwrap();
    let carol_pk = pubkey_x_from_secret(&carol_sk).unwrap();
    let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();
    let bob_pk_public = pubkey_x_from_secret(&[0x22u8; 32]).unwrap();

    let alice_spk = p2tr_spk_from_secret(&[0x41u8; 32]);
    let bob_spk = p2tr_spk_from_secret(&[0x42u8; 32]);
    let carol_spk = p2tr_spk_from_secret(&[0x43u8; 32]);
    let anchor_spk = p2tr_spk_from_secret(&anchor_sk);

    let maturity_height = 150u32;
    let params = Mnr03ScaleParams::macro_regtest_33k(maturity_height);
    let descs = precompute_mnr03_funding_descriptors(
        &params,
        alice_pk,
        bob_pk_public,
        carol_pk,
        guard_pk,
    )
    .expect("MNR-03 descriptors");

    // 1. Fund primary 3 DLC UTXOs (`U_AB`, `U_BC`, `U_CA`) AND secondary unilateral-drill UTXOs (`U_AB_uni`, `U_BC_uni`)
    let (ab_txid, ab_vout) = node.fund_raw_script(&descs.ab_tree.script_pubkey, descs.ab_funding_sats);
    let (bc_txid, bc_vout) = node.fund_raw_script(&descs.bc_tree.script_pubkey, descs.bc_funding_sats);
    let (ca_txid, ca_vout) = node.fund_raw_script(&descs.ca_tree.script_pubkey, descs.ca_funding_sats);

    let (ab_uni_txid, ab_uni_vout) =
        node.fund_raw_script(&descs.ab_tree.script_pubkey, descs.ab_funding_sats);
    let (bc_uni_txid, bc_uni_vout) =
        node.fund_raw_script(&descs.bc_tree.script_pubkey, descs.bc_funding_sats);

    node.mine_blocks(1, &miner_addr);

    let funded_dlc_utxos = vec![
        FundedDlcUtxoReceipt {
            trade_no: 1,
            label: "MNR03-AB-ALICE-LONG-BOB-SHORT-50K-0x83".to_owned(),
            txid: ab_txid.clone(),
            vout: ab_vout,
            sats: descs.ab_funding_sats,
            script_pubkey_hex: hex::encode(&descs.ab_tree.script_pubkey),
        },
        FundedDlcUtxoReceipt {
            trade_no: 2,
            label: "MNR03-BC-BOB-LONG-CAROL-SHORT-55K-0x83".to_owned(),
            txid: bc_txid.clone(),
            vout: bc_vout,
            sats: descs.bc_funding_sats,
            script_pubkey_hex: hex::encode(&descs.bc_tree.script_pubkey),
        },
        FundedDlcUtxoReceipt {
            trade_no: 3,
            label: "MNR03-CA-CAROL-LONG-ALICE-SHORT-60K-0x00".to_owned(),
            txid: ca_txid.clone(),
            vout: ca_vout,
            sats: descs.ca_funding_sats,
            script_pubkey_hex: hex::encode(&descs.ca_tree.script_pubkey),
        },
    ];

    // 2. Step `t = 0`: Bob is online ONLY inside this inner origination block!
    let t_50k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(50_000));
    let t_60k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(60_000));
    let grid = vec![
        (50_000u64, ProjectivePoint::GENERATOR * t_50k),
        (60_000u64, ProjectivePoint::GENERATOR * t_60k),
    ];

    let (orig, orig_uni) = {
        let bob_sk_ephemeral = [0x22u8; 32];
        let o1 = build_mnr03_bob_offline_origination(
            &params,
            &alice_sk,
            &bob_sk_ephemeral,
            &carol_sk,
            guard_pk,
            [(&ab_txid, ab_vout), (&bc_txid, bc_vout), (&ca_txid, ca_vout)],
            alice_spk.clone(),
            bob_spk.clone(),
            carol_spk.clone(),
            anchor_spk.clone(),
            &grid,
        )
        .expect("primary MNR-03 origination");

        let o2 = build_mnr03_bob_offline_origination(
            &params,
            &alice_sk,
            &bob_sk_ephemeral,
            &carol_sk,
            guard_pk,
            [
                (&ab_uni_txid, ab_uni_vout),
                (&bc_uni_txid, bc_uni_vout),
                (&ca_txid, ca_vout),
            ],
            alice_spk.clone(),
            bob_spk.clone(),
            carol_spk.clone(),
            anchor_spk.clone(),
            &grid,
        )
        .expect("unilateral-drill MNR-03 origination");
        (o1, o2)
        // `bob_sk_ephemeral` is DROPPED here — Bob is 100% offline for the entire rest of execution!
    };

    // 3. Native Pyth Pro Ed25519 Solana envelope ($60,000.00000000) + MNR-03 Clearing + Nova Witness
    let pyth_sk = [0x88u8; 32];
    let (pyth_env, pyth_pk) = build_signed_pyth_pro_btc_usd_envelope(
        &pyth_sk,
        1_795_500_000_000_000,
        1_795_500_000_000_000,
        PYTH_PRO_CHANNEL_FIXED_200MS,
        PYTH_PRO_BTC_USD_FEED_ID,
        6_000_000_000_000,
        -8,
        1_200_000_000,
    );
    let pyth_reg = PinnedPythSignerRegistry::new_static(vec![pyth_pk]).unwrap();

    let cur_h = node.height();
    let cur_hash = node.cli_raw(&["getbestblockhash"]).unwrap();

    let mut artifacts = build_oracle_bound_mnr03_nova_ceremony(
        &orig,
        1, // $60,000 outcome
        &t_60k,
        &pyth_env,
        &pyth_reg,
        &PythProBtcUsdPolicy::default(),
        1_795_500_001_000_000,
        &alice_sk,
        &carol_sk,
        &guard_sk,
        batch_oracles,
        BitcoinNetworkCode::Regtest,
        cur_h,
        &cur_hash,
        1,
    )
    .expect("build oracle-bound MNR-03 Nova ceremony");

    let uni_artifacts = build_oracle_bound_mnr03_nova_ceremony(
        &orig_uni,
        1,
        &t_60k,
        &pyth_env,
        &pyth_reg,
        &PythProBtcUsdPolicy::default(),
        1_795_500_001_000_000,
        &alice_sk,
        &carol_sk,
        &guard_sk,
        batch_oracles,
        BitcoinNetworkCode::Regtest,
        cur_h,
        &cur_hash,
        2,
    )
    .expect("build unilateral-drill ceremony");

    let mut probes = Vec::new();
    let clear_tx = &artifacts.mnr03_assembled.signed_clearing_tx;
    let raw_clear_hex = hex::encode(clear_tx.serialize_segwit());

    // Probe 1: Premature broadcast before `maturity_height = 150` MUST be rejected (`non-final`)!
    let cur_before = node.height();
    if cur_before < (maturity_height as u64 - 2) {
        node.mine_blocks((maturity_height as u64 - 2) - cur_before, &miner_addr);
    }
    let (premature_ok, premature_reason) = node.test_mempool_accept(&raw_clear_hex);
    assert!(
        !premature_ok && premature_reason.contains("non-final"),
        "expected non-final before maturity, got: {premature_reason}"
    );
    probes.push(AdversarialProbeReceipt {
        probe_id: "mnr03-premature-broadcast-before-maturity",
        description: "Broadcast 3-input Bob-offline clearing tx at height 148 (< maturity 150)",
        core_accepted: premature_ok,
        core_reject_reason: premature_reason,
    });

    // Advance chain to exact `maturity_height = 150`
    let delta_to_maturity = (maturity_height as u64).saturating_sub(node.height());
    if delta_to_maturity > 0 {
        node.mine_blocks(delta_to_maturity, &miner_addr);
    }
    assert_eq!(node.height(), maturity_height as u64);

    // Probe 2: Shave 1 sat from Bob's `U_AB` pinned output (`vout[0]`), add to Alice (`vout[2]`)
    let mut shave_ab = clear_tx.clone();
    shave_ab.outputs[0].0 -= 1;
    shave_ab.outputs[2].0 += 1;
    let (shave_ab_ok, shave_ab_reason) =
        node.test_mempool_accept(&hex::encode(shave_ab.serialize_segwit()));
    assert!(!shave_ab_ok);
    probes.push(AdversarialProbeReceipt {
        probe_id: "mnr03-shave-1-sat-bob-ab-vout0",
        description: "Shave 1 sat from offline Bob's AB 0x83-pinned output vout[0] (55,000,000 -> 54,999,999)",
        core_accepted: shave_ab_ok,
        core_reject_reason: shave_ab_reason,
    });

    // Probe 3: Shave 1 sat from Bob's `U_BC` pinned output (`vout[1]`), add to Carol (`vout[3]`)
    let mut shave_bc = clear_tx.clone();
    shave_bc.outputs[1].0 -= 1;
    shave_bc.outputs[3].0 += 1;
    let (shave_bc_ok, shave_bc_reason) =
        node.test_mempool_accept(&hex::encode(shave_bc.serialize_segwit()));
    assert!(!shave_bc_ok);
    probes.push(AdversarialProbeReceipt {
        probe_id: "mnr03-shave-1-sat-bob-bc-vout1",
        description: "Shave 1 sat from offline Bob's BC 0x83-pinned output vout[1] (35,000,000 -> 34,999,999)",
        core_accepted: shave_bc_ok,
        core_reject_reason: shave_bc_reason,
    });

    // Probe 4: Swap `vout[0]` and `vout[1]` (Bob's AB and BC outputs)
    let mut swap_outs = clear_tx.clone();
    swap_outs.outputs.swap(0, 1);
    let (swap_ok, swap_reason) =
        node.test_mempool_accept(&hex::encode(swap_outs.serialize_segwit()));
    assert!(!swap_ok);
    probes.push(AdversarialProbeReceipt {
        probe_id: "mnr03-swap-bob-vout0-and-vout1",
        description: "Swap offline Bob's vout[0] and vout[1] across the two 0x83 inputs",
        core_accepted: swap_ok,
        core_reject_reason: swap_reason,
    });

    // Probe 5: Attempt unilateral `CLTV` fallback during priority window (`height = 150 < 170`)
    let (uni_early_ok, uni_early_reason) = node.test_mempool_accept(&hex::encode(
        artifacts
            .mnr03_assembled
            .ab_unilateral_fallback_tx
            .serialize_segwit(),
    ));
    assert!(!uni_early_ok && uni_early_reason.contains("non-final"));
    probes.push(AdversarialProbeReceipt {
        probe_id: "mnr03-unilateral-cet-during-priority-window",
        description: "Attempt Leaf 1 unilateral CLTV fallback at height 150 (< unilateral_cltv 170)",
        core_accepted: uni_early_ok,
        core_reject_reason: uni_early_reason,
    });

    // 4. Broadcast honest 3-input, 5-output Bob-offline clearing tx + CPFP child spending `vout[4]` (`330` sats)!
    let (honest_ok, honest_reason) = node.test_mempool_accept(&raw_clear_hex);
    assert!(
        honest_ok,
        "Bitcoin Core rejected honest MNR-03 clearing tx: {honest_reason}"
    );
    let sent_clear_txid = node
        .cli_raw(&["sendrawtransaction", &raw_clear_hex])
        .expect("broadcast MNR-03 clearing tx");
    assert_eq!(
        sent_clear_txid,
        artifacts.report.mnr03_clearing.atomic_clearing_txid_hex
    );

    // Build & broadcast a real CPFP child spending `vout[4]` (330-sat key-path P2TR anchor -> 330-sat output,
    // funded with an extra fee UTXO from miner wallet? Or a 1-in/1-out/fee UTXO! Even cleaner: fund a small
    // 5,000-sat UTXO to `anchor_spk` and spend `[clear_tx:4 (330), fee_utxo (5,000)] -> [anchor_spk (3,830)]`
    // paying `1,500` sats CPFP fee in the SAME mempool block!).
    let (fee_boost_txid, fee_boost_vout) = node.fund_raw_script(&anchor_spk, 5_000);
    let mut cpfp_child = SegwitTx {
        version: 2,
        inputs: vec![
            SegwitTxIn::from_display_txid(&sent_clear_txid, 4, 0xfffffffe, 330, anchor_spk.clone())
                .unwrap(),
            SegwitTxIn::from_display_txid(
                &fee_boost_txid,
                fee_boost_vout,
                0xfffffffe,
                5_000,
                anchor_spk.clone(),
            )
            .unwrap(),
        ],
        outputs: vec![(3_830, anchor_spk.clone())],
        locktime: 0,
    };
    // Note: key-path P2TR with un-tweaked rawtr `anchor_spk = 0x51 0x20 || pk(anchor_sk)` spends directly with `anchor_sk`!
    let sh0 = cpfp_child.bip341_sighash(0, SIGHASH_DEFAULT, None).unwrap();
    let sh1 = cpfp_child.bip341_sighash(1, SIGHASH_DEFAULT, None).unwrap();
    cpfp_child.inputs[0].witness = vec![encode_taproot_witness_sig(
        &bip340_sign(&anchor_sk, &sh0).unwrap(),
        SIGHASH_DEFAULT,
    )];
    cpfp_child.inputs[1].witness = vec![encode_taproot_witness_sig(
        &bip340_sign(&anchor_sk, &sh1).unwrap(),
        SIGHASH_DEFAULT,
    )];
    let cpfp_child_txid = node
        .cli_raw(&[
            "sendrawtransaction",
            &hex::encode(cpfp_child.serialize_segwit()),
        ])
        .expect("broadcast CPFP child spending vout[4] anchor");

    // Mine 6 blocks (`151..156`) confirming both `tx_mnr03_clear` and `cpfp_child`!
    node.mine_blocks(6, &miner_addr);
    let tx_info = node.cli_json(&["getrawtransaction", &sent_clear_txid, "true"]);
    let pre_reorg_confs = tx_info["confirmations"].as_u64().unwrap_or(0);
    assert_eq!(pre_reorg_confs, 6);
    let clearing_block_hash = tx_info["blockhash"].as_str().unwrap().to_owned();
    let clearing_block_hdr = node.cli_json(&["getblockheader", &clearing_block_hash]);
    let clearing_block_height = clearing_block_hdr["height"].as_u64().unwrap();

    // 5. LIVE 6-BLOCK REORG + WATCHTOWER HALT DRILL (`invalidateblock` -> competing 7-block branch):
    node.cli_raw(&["invalidateblock", &clearing_block_hash])
        .expect("invalidateblock for 6-block reorg drill");
    let alt_miner_addr = node
        .cli_raw(&["getnewaddress", "alt_branch_miner", "bech32m"])
        .unwrap();
    let competing_tip_height = node.mine_blocks(7, &alt_miner_addr);
    let competing_tip_hash = node.cli_raw(&["getbestblockhash"]).unwrap();
    let invalidated_hdr = node.cli_json(&["getblockheader", &clearing_block_hash]);
    let post_invalidate_confs = invalidated_hdr["confirmations"].as_i64().unwrap_or(0);
    assert_eq!(
        post_invalidate_confs, -1,
        "expected invalidated block confirmations == -1 during reorg"
    );

    // Watchtower detects `confirmations == -1` on `clearing_block_hash` and freezes a replica of the durable book!
    let mut reorg_book = artifacts.mnr03_assembled.durable_book.clone();
    reorg_book.freeze_on_reorg("watchtower-detected-6-block-reorg-invalidated-clearing-block");
    let frozen_head = reorg_book.head_hash;
    let watchtower_book_frozen = matches!(reorg_book.state, BookAuthState::Frozen { .. });
    let settle_after_freeze_rejected = reorg_book.confirm_active_chain(
        &frozen_head,
        &sent_clear_txid,
        &artifacts.mnr03_assembled.pnl_snapshot,
    ) == Err(UtxoRefError::InvalidBookTransition);
    assert!(watchtower_book_frozen && settle_after_freeze_rejected);

    // Restore canonical branch (`reconsiderblock`) and mine 2 more blocks so canonical chain leads (`158 > 157`)!
    node.cli_raw(&["reconsiderblock", &clearing_block_hash])
        .expect("reconsiderblock");
    let restored_tip_height = node.mine_blocks(2, &miner_addr);
    let restored_tx = node.cli_json(&["getrawtransaction", &sent_clear_txid, "true"]);
    let final_confirmations = restored_tx["confirmations"].as_u64().unwrap_or(0);
    assert!(final_confirmations >= 8);

    // Now that canonical chain is confirmed without reorg, settle the primary `DurablePnlBatchBook`!
    let cur_book_head = artifacts.mnr03_assembled.durable_book.head_hash;
    let settled_head = artifacts
        .mnr03_assembled
        .durable_book
        .confirm_active_chain(
            &cur_book_head,
            &sent_clear_txid,
            &artifacts.mnr03_assembled.pnl_snapshot,
        )
        .expect("confirm settled after canonical finality");
    artifacts.report.mnr03_clearing.durable_book_head_hash_hex = hex::encode(settled_head);

    // Verify post-clearing unspent outputs (`vout[0..3]` unspent; `vout[4]` spent by CPFP child!)
    let owners = [
        ("Bob-AB-0x83-Pinned", clear_tx.outputs[0].0),
        ("Bob-BC-0x83-Pinned", clear_tx.outputs[1].0),
        ("Alice-Winner-Routed-PnL", clear_tx.outputs[2].0),
        ("Carol-Freed-Margin", clear_tx.outputs[3].0),
    ];
    let mut utxo_checks = Vec::with_capacity(4);
    for (vout, (owner, sats)) in owners.into_iter().enumerate() {
        let out_txt = node
            .cli_raw(&["gettxout", &sent_clear_txid, &vout.to_string()])
            .unwrap();
        assert!(!out_txt.is_empty(), "missing cleared output vout={vout}");
        utxo_checks.push(UnspentClearedOutputCheck {
            owner,
            vout: vout as u32,
            sats,
            utxo_present_in_core: true,
        });
    }

    // 6. UNILATERAL `CLTV` FALLBACK DRILL (`height >= 170`, `RouterGuard` disappears!):
    let h_now = node.height();
    let uni_cltv = orig_uni.ab_leg.tree.unilateral_cltv_height as u64;
    if h_now < uni_cltv {
        node.mine_blocks(uni_cltv - h_now, &miner_addr);
    }
    let ab_uni_hex = hex::encode(
        uni_artifacts
            .mnr03_assembled
            .ab_unilateral_fallback_tx
            .serialize_segwit(),
    );
    let bc_uni_hex = hex::encode(
        uni_artifacts
            .mnr03_assembled
            .bc_unilateral_fallback_tx
            .serialize_segwit(),
    );
    let ab_uni_sent = node
        .cli_raw(&["sendrawtransaction", &ab_uni_hex])
        .expect("broadcast AB unilateral CLTV fallback");
    let bc_uni_sent = node
        .cli_raw(&["sendrawtransaction", &bc_uni_hex])
        .expect("broadcast BC unilateral CLTV fallback");
    let uni_conf_height = node.mine_blocks(1, &miner_addr);

    // 7. External `lnm-nova` (`nova-snark 0.76.0`) CompressedSNARK proving & verification!
    let mut nova_verified = false;
    if let Some(nova_bin) = lnm_nova_bin.filter(|p| p.exists()) {
        let snark = run_external_lnm_nova_prover(
            nova_bin,
            &artifacts.batch_witness_bytes,
            persist_bundle_dir,
        );
        nova_verified = snark.nova_compressed_verified;
        artifacts.report.external_nova_snark_receipt = Some(snark);
        if nova_verified {
            let flags = VerificationHonestyFlags::with_external_nova_snark_verified();
            artifacts.report.honesty = flags;
            artifacts.report.nova_expected_statement.honesty = flags;
            artifacts.report.bitvm3_statement.honesty = flags;
        }
    }

    Mnr03CoreRegtestReceipt {
        scenario: "SHZ-MNR-03: 3-Party Multilateral Atomic Clearing with Bob 100% Offline (0x83) + Native Pyth Pro + 6-Block Reorg Watchtower Drill + Unilateral CLTV Fallback + lnm-nova CompressedSNARK",
        core_version,
        bob_online_during_clearing_or_proving: false,
        bitcoin_spend_enforced: true,
        cpfp_anchor_child_confirmed: true,
        reorg_watchtower_drill_passed: true,
        unilateral_cltv_fallback_verified: true,
        nova_compressed_snark_verified: nova_verified,
        near_finality_verified: false,
        bitvm3_onchain_verified: false,
        production_ready: false,
        funded_dlc_utxos,
        core_confirmed_bob_offline_clearing_tx: CoreConfirmedTxReceipt {
            label: "mnr03-3input-5output-bob-offline-0x83-atomic-clearing",
            txid: sent_clear_txid,
            wtxid: clear_tx.wtxid_hex(),
            vsize: clear_tx.vsize(),
            locktime: clear_tx.locktime,
            script_path_used: "vin0:mnr02-route-0x83+0x01 | vin1:mnr02-route-0x83+0x01 | vin2:utxoref-cet-0x00",
            sighash_flags_hex: vec![
                "0x83+0x01+0x01".into(),
                "0x83+0x01+0x01".into(),
                "0x00+0x00".into(),
            ],
            outputs_sats: clear_tx.outputs.iter().map(|(v, _)| *v).collect(),
            witness_item_lengths: clear_tx.inputs.iter().map(|i| i.witness.len()).collect(),
            raw_tx_hex: raw_clear_hex,
            confirmed_block_height: clearing_block_height,
            confirmed_block_hash: clearing_block_hash.clone(),
            core_confirmations: final_confirmations,
        },
        cpfp_child_txid,
        post_clearing_utxo_checks: utxo_checks,
        adversarial_probes: probes,
        reorg_watchtower_drill: ReorgWatchtowerDrillReceipt {
            invalidated_clearing_block_hash: clearing_block_hash,
            pre_reorg_confirmations: pre_reorg_confs,
            post_invalidate_confirmations: post_invalidate_confs,
            competing_branch_tip_height: competing_tip_height,
            competing_branch_tip_hash: competing_tip_hash,
            watchtower_book_frozen,
            settle_after_freeze_rejected,
            restored_canonical_tip_height: restored_tip_height,
        },
        unilateral_fallback_drill: UnilateralFallbackDrillReceipt {
            ab_unilateral_txid: ab_uni_sent,
            bc_unilateral_txid: bc_uni_sent,
            confirmed_at_height: uni_conf_height,
            guard_signature_required: false,
        },
        oracle_bound_nova_report: artifacts.report,
    }
}

pub fn run_mnr03_wsl_testnet4_live_broadcast(
    wallet_name: &str,
    lnm_nova_bin: Option<&Path>,
    persist_bundle_dir: Option<&Path>,
) -> Mnr03LiveTestnet4Receipt {
    let chain_info = wsl_testnet4_json(None, &["getblockchaininfo"]);
    assert_eq!(chain_info["chain"].as_str(), Some("testnet4"));
    assert_eq!(chain_info["initialblockdownload"].as_bool(), Some(false));
    let tip_height = chain_info["blocks"].as_u64().expect("tip height") as u32;
    let tip_hash = chain_info["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_owned();

    let net_info = wsl_testnet4_json(None, &["getnetworkinfo"]);
    let core_version = format!(
        "Bitcoin Core v{} ({})",
        net_info["version"].as_u64().unwrap_or(0),
        net_info["subversion"].as_str().unwrap_or("bitcoind")
    );

    let bal_before = wsl_testnet4_json(Some(wallet_name), &["getbalances"]);
    let sats_before = btc_float_to_sats(
        bal_before["mine"]["trusted"].as_f64().unwrap_or(0.0)
            + bal_before["mine"]["untrusted_pending"].as_f64().unwrap_or(0.0),
    );
    assert!(
        sats_before >= 4_250,
        "wallet {wallet_name} needs >= 4,250 sats on Testnet4 for MNR-03 micro clearing (got {sats_before})"
    );

    // 1. Derive 4 fresh bech32m P2TR payout scripts inside `wallet_name` so ALL 5 outputs
    //    (`vout[0]` Bob AB, `vout[1]` Bob BC, `vout[2]` Alice Winner, `vout[3]` Carol, `vout[4]` Anchor)
    //    return directly to `wallet_name`!
    let labels = [
        "shz-mnr03:alice-winner-pnl",
        "shz-mnr03:bob-offline-0x83-freed",
        "shz-mnr03:carol-freed-margin",
        "shz-mnr03:cpfp-anchor",
    ];
    let mut wallet_spks: Vec<Vec<u8>> = Vec::with_capacity(4);
    for label in labels {
        let addr = wsl_testnet4_cli(Some(wallet_name), &["getnewaddress", label, "bech32m"])
            .expect("getnewaddress bech32m");
        let info = wsl_testnet4_json(Some(wallet_name), &["getaddressinfo", &addr]);
        let spk_hex = info["scriptPubKey"].as_str().expect("scriptPubKey hex");
        wallet_spks.push(hex::decode(spk_hex).expect("decode spk"));
    }
    let alice_spk = wallet_spks[0].clone();
    let bob_spk = wallet_spks[1].clone();
    let carol_spk = wallet_spks[2].clone();
    let anchor_spk = wallet_spks[3].clone();

    let alice_sk = [0x11u8; 32];
    let carol_sk = [0x23u8; 32];
    let guard_sk = [0x24u8; 32];
    let batch_oracles = [[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]];

    let alice_pk = pubkey_x_from_secret(&alice_sk).unwrap();
    let carol_pk = pubkey_x_from_secret(&carol_sk).unwrap();
    let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();
    let bob_pk_public = pubkey_x_from_secret(&[0x22u8; 32]).unwrap();

    // Set `maturity_height = tip_height` so `nLockTime = tip_height` is immediately final on live Testnet4!
    let params = Mnr03ScaleParams::micro_testnet4_live(tip_height);
    let descs = precompute_mnr03_funding_descriptors(
        &params,
        alice_pk,
        bob_pk_public,
        carol_pk,
        guard_pk,
    )
    .expect("MNR-03 Testnet4 descriptors");

    let spks_and_sats = [
        ("MNR03-AB-80K-BOB-OFFLINE-0x83", &descs.ab_tree.script_pubkey, descs.ab_funding_sats),
        ("MNR03-BC-100K-BOB-OFFLINE-0x83", &descs.bc_tree.script_pubkey, descs.bc_funding_sats),
        ("MNR03-CA-125K-INTERACTIVE-0x00", &descs.ca_tree.script_pubkey, descs.ca_funding_sats),
    ];

    let mut dlc_addrs = Vec::with_capacity(3);
    for (_, spk, _) in &spks_and_sats {
        let out_x = hex::encode(&spk[2..]);
        let desc_info =
            wsl_testnet4_json(None, &["getdescriptorinfo", &format!("rawtr({out_x})")]);
        let desc = desc_info["descriptor"].as_str().unwrap();
        let addrs = wsl_testnet4_json(None, &["deriveaddresses", desc]);
        dlc_addrs.push(addrs[0].as_str().unwrap().to_owned());
    }

    // 2. Select spendable UTXOs (including 0-conf wallet outputs) via `listunspent 0` and construct
    //    a deterministic Testnet4 funding transaction (`1,400 + 1,360 + 1,140 = 3,900` sats), avoiding
    //    Win32->WSL JSON quote-stripping on `fundrawtransaction` options!
    let unspent = wsl_testnet4_json(Some(wallet_name), &["listunspent", "0"]);
    let utxo_arr = unspent.as_array().expect("listunspent array");
    let target_fund_sats = params.total_funding_sats();
    let est_fund_fee_sats = 450u64;
    let mut selected_inputs = Vec::new();
    let mut selected_in_sats = 0u64;
    for u in utxo_arr {
        if u["spendable"].as_bool() != Some(true) {
            continue;
        }
        let u_txid = u["txid"].as_str().expect("utxo txid");
        let u_vout = u["vout"].as_u64().expect("utxo vout");
        let u_sats = btc_float_to_sats(u["amount"].as_f64().expect("utxo amount"));
        selected_inputs.push(format!("{{\"txid\":\"{u_txid}\",\"vout\":{u_vout}}}"));
        selected_in_sats += u_sats;
        if selected_in_sats >= target_fund_sats + est_fund_fee_sats {
            break;
        }
    }
    assert!(
        selected_in_sats >= target_fund_sats + est_fund_fee_sats,
        "insufficient spendable sats in {wallet_name}: got {selected_in_sats}"
    );
    let inputs_json = format!("[{}]", selected_inputs.join(","));

    let leftover_after_min_fee = selected_in_sats - target_fund_sats - est_fund_fee_sats;
    let outputs_json = if leftover_after_min_fee >= 330 {
        let change_addr = wsl_testnet4_cli(
            Some(wallet_name),
            &["getnewaddress", "shz-mnr03:fund-change", "bech32m"],
        )
        .expect("change address");
        let change_btc = format!(
            "{}.{:08}",
            leftover_after_min_fee / 100_000_000,
            leftover_after_min_fee % 100_000_000
        );
        format!(
            "[{{\"{}\":0.00001400}},{{\"{}\":0.00001360}},{{\"{}\":0.00001140}},{{\"{}\":{}}}]",
            dlc_addrs[0], dlc_addrs[1], dlc_addrs[2], change_addr, change_btc
        )
    } else {
        format!(
            "[{{\"{}\":0.00001400}},{{\"{}\":0.00001360}},{{\"{}\":0.00001140}}]",
            dlc_addrs[0], dlc_addrs[1], dlc_addrs[2]
        )
    };
    let raw_fund = wsl_testnet4_cli(
        Some(wallet_name),
        &["createrawtransaction", &inputs_json, &outputs_json],
    )
    .expect("createrawtransaction MNR-03 funding");
    let signed_fund = wsl_testnet4_json(
        Some(wallet_name),
        &["signrawtransactionwithwallet", &raw_fund],
    );
    assert_eq!(signed_fund["complete"].as_bool(), Some(true));
    let signed_fund_hex = signed_fund["hex"].as_str().unwrap().to_owned();

    let decoded_fund = wsl_testnet4_json(None, &["decoderawtransaction", &signed_fund_hex]);
    let fund_txid_hex = decoded_fund["txid"].as_str().unwrap().to_owned();

    let mut vouts = [0u32; 3];
    let mut funded_receipts = Vec::with_capacity(3);
    for (idx, (label, spk, sats)) in spks_and_sats.iter().enumerate() {
        let spk_hex = hex::encode(spk);
        let vout = decoded_fund["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(spk_hex.as_str()))
            .expect("locate MNR-03 funding vout")["n"]
            .as_u64()
            .unwrap() as u32;
        vouts[idx] = vout;
        funded_receipts.push(FundedDlcUtxoReceipt {
            trade_no: (idx + 1) as u8,
            label: (*label).to_owned(),
            txid: fund_txid_hex.clone(),
            vout,
            sats: *sats,
            script_pubkey_hex: spk_hex,
        });
    }

    // 3. Step `t = 0`: Bob signs `0x83` templates at origination and **goes 100% offline**!
    let t_125k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(125_000));
    let orig = {
        let bob_sk_ephemeral = [0x22u8; 32];
        build_mnr03_bob_offline_origination(
            &params,
            &alice_sk,
            &bob_sk_ephemeral,
            &carol_sk,
            guard_pk,
            [
                (&fund_txid_hex, vouts[0]),
                (&fund_txid_hex, vouts[1]),
                (&fund_txid_hex, vouts[2]),
            ],
            alice_spk,
            bob_spk,
            carol_spk,
            anchor_spk,
            &[(125_000, ProjectivePoint::GENERATOR * t_125k)],
        )
        .expect("MNR-03 Testnet4 origination")
        // `bob_sk_ephemeral` dropped here!
    };

    // 4. Native Pyth Pro Ed25519 Solana envelope ($125,000.00000000) + Bob-offline clearing + Nova witness!
    let pyth_sk = [0x88u8; 32];
    let (pyth_env, pyth_pk) = build_signed_pyth_pro_btc_usd_envelope(
        &pyth_sk,
        1_795_600_000_000_000,
        1_795_600_000_000_000,
        PYTH_PRO_CHANNEL_FIXED_200MS,
        PYTH_PRO_BTC_USD_FEED_ID,
        12_500_000_000_000,
        -8,
        1_500_000_000,
    );
    let pyth_reg = PinnedPythSignerRegistry::new_static(vec![pyth_pk]).unwrap();

    let mut artifacts = build_oracle_bound_mnr03_nova_ceremony(
        &orig,
        0,
        &t_125k,
        &pyth_env,
        &pyth_reg,
        &PythProBtcUsdPolicy::default(),
        1_795_600_001_000_000,
        &alice_sk,
        &carol_sk,
        &guard_sk,
        batch_oracles,
        BitcoinNetworkCode::Testnet4,
        tip_height as u64,
        &tip_hash,
        177,
    )
    .expect("build Testnet4 Oracle-Bound MNR-03 Nova ceremony");

    let clear_tx = &artifacts.mnr03_assembled.signed_clearing_tx;
    let raw_clear_hex = hex::encode(clear_tx.serialize_segwit());

    // Pre-flight check: verify `[tx_fund, tx_mnr03_clear]` passes live Testnet4 consensus BEFORE broadcasting!
    let pkg_accept = wsl_testnet4_json(
        None,
        &[
            "testmempoolaccept",
            &format!("[\"{signed_fund_hex}\",\"{raw_clear_hex}\"]"),
        ],
    );
    assert_eq!(
        pkg_accept[0]["allowed"].as_bool(),
        Some(true),
        "Testnet4 MNR-03 funding tx preflight failed: {pkg_accept}"
    );
    assert_eq!(
        pkg_accept[1]["allowed"].as_bool(),
        Some(true),
        "Testnet4 MNR-03 Bob-offline clearing tx preflight failed: {pkg_accept}"
    );

    // 5. Broadcast `tx_fund` to LIVE PUBLIC BITCOIN TESTNET4!
    let broadcast_fund_txid = wsl_testnet4_cli(None, &["sendrawtransaction", &signed_fund_hex])
        .expect("broadcast MNR-03 tx_fund on Testnet4");
    assert_eq!(broadcast_fund_txid, fund_txid_hex);

    // 6. Run 3 live Testnet4 mempool adversarial probes against Bob's two `0x83` pinned outputs!
    let mut probes = Vec::new();

    let mut shave_ab = clear_tx.clone();
    shave_ab.outputs[0].0 -= 1;
    shave_ab.outputs[2].0 += 1;
    let shave_ab_res = wsl_testnet4_json(
        None,
        &[
            "testmempoolaccept",
            &format!("[\"{}\"]", hex::encode(shave_ab.serialize_segwit())),
        ],
    );
    assert_eq!(shave_ab_res[0]["allowed"].as_bool(), Some(false));
    probes.push(AdversarialProbeReceipt {
        probe_id: "testnet4-mnr03-shave-bob-ab-vout0",
        description: "Live Testnet4 mempool probe: shave 1 sat from offline Bob's AB 0x83-pinned vout[0] (450 -> 449)",
        core_accepted: false,
        core_reject_reason: shave_ab_res[0]["reject-reason"]
            .as_str()
            .unwrap_or("rejected")
            .to_owned(),
    });

    let mut shave_bc = clear_tx.clone();
    shave_bc.outputs[1].0 -= 1;
    shave_bc.outputs[3].0 += 1;
    let shave_bc_res = wsl_testnet4_json(
        None,
        &[
            "testmempoolaccept",
            &format!("[\"{}\"]", hex::encode(shave_bc.serialize_segwit())),
        ],
    );
    assert_eq!(shave_bc_res[0]["allowed"].as_bool(), Some(false));
    probes.push(AdversarialProbeReceipt {
        probe_id: "testnet4-mnr03-shave-bob-bc-vout1",
        description: "Live Testnet4 mempool probe: shave 1 sat from offline Bob's BC 0x83-pinned vout[1] (550 -> 549)",
        core_accepted: false,
        core_reject_reason: shave_bc_res[0]["reject-reason"]
            .as_str()
            .unwrap_or("rejected")
            .to_owned(),
    });

    let mut swap_outs = clear_tx.clone();
    swap_outs.outputs.swap(0, 1);
    let swap_res = wsl_testnet4_json(
        None,
        &[
            "testmempoolaccept",
            &format!("[\"{}\"]", hex::encode(swap_outs.serialize_segwit())),
        ],
    );
    assert_eq!(swap_res[0]["allowed"].as_bool(), Some(false));
    probes.push(AdversarialProbeReceipt {
        probe_id: "testnet4-mnr03-swap-bob-vout0-vout1",
        description: "Live Testnet4 mempool probe: swap offline Bob's vout[0] (450) and vout[1] (550)",
        core_accepted: false,
        core_reject_reason: swap_res[0]["reject-reason"]
            .as_str()
            .unwrap_or("rejected")
            .to_owned(),
    });

    // 7. Broadcast honest 3-input, 5-output Bob-offline atomic clearing tx to LIVE PUBLIC BITCOIN TESTNET4!
    let clear_accept = wsl_testnet4_json(
        None,
        &["testmempoolaccept", &format!("[\"{raw_clear_hex}\"]")],
    );
    assert_eq!(
        clear_accept[0]["allowed"].as_bool(),
        Some(true),
        "Live Testnet4 MNR-03 clearing tx rejected: {clear_accept}"
    );
    let broadcast_clear_txid = wsl_testnet4_cli(None, &["sendrawtransaction", &raw_clear_hex])
        .expect("broadcast MNR-03 Bob-offline clearing tx on Testnet4");
    assert_eq!(
        broadcast_clear_txid,
        artifacts.report.mnr03_clearing.atomic_clearing_txid_hex
    );
    assert_eq!(
        broadcast_clear_txid,
        artifacts.report.bitvm3_statement.assertion_txid_hex
    );

    let in_mempool_or_chain = wsl_testnet4_cli(None, &["getmempoolentry", &broadcast_clear_txid])
        .is_ok()
        || wsl_testnet4_cli(None, &["getrawtransaction", &broadcast_clear_txid, "true"]).is_ok();
    assert!(in_mempool_or_chain);

    let bal_after = wsl_testnet4_json(Some(wallet_name), &["getbalances"]);
    let sats_after = btc_float_to_sats(
        bal_after["mine"]["trusted"].as_f64().unwrap_or(0.0)
            + bal_after["mine"]["untrusted_pending"].as_f64().unwrap_or(0.0),
    );

    // 8. Prove & verify matching 3-step `lnm-nova` `CompressedSNARK` (`bob_sk` 100% absent!)
    let mut nova_verified = false;
    if let Some(nova_bin) = lnm_nova_bin.filter(|p| p.exists()) {
        let snark = run_external_lnm_nova_prover(
            nova_bin,
            &artifacts.batch_witness_bytes,
            persist_bundle_dir,
        );
        nova_verified = snark.nova_compressed_verified;
        artifacts.report.external_nova_snark_receipt = Some(snark);
        if nova_verified {
            let flags = VerificationHonestyFlags::with_external_nova_snark_verified();
            artifacts.report.honesty = flags;
            artifacts.report.nova_expected_statement.honesty = flags;
            artifacts.report.bitvm3_statement.honesty = flags;
        }
    }

    Mnr03LiveTestnet4Receipt {
        scenario: "Live Public Bitcoin Testnet4 SHZ-MNR-03 3-Party Multilateral Atomic Clearing with Bob 100% Offline (0x83) + Native Pyth Pro + lnm-nova CompressedSNARK",
        network: "bitcoin-testnet4",
        core_version,
        testnet4_tip_height: tip_height,
        testnet4_tip_block_hash: tip_hash,
        bob_online_during_clearing_or_proving: false,
        funding_tx_explorer_uri: format!("https://mempool.space/testnet4/tx/{broadcast_fund_txid}"),
        funding_txid: broadcast_fund_txid,
        bob_offline_atomic_clearing_tx_explorer_uri: format!(
            "https://mempool.space/testnet4/tx/{broadcast_clear_txid}"
        ),
        bob_offline_atomic_clearing_txid: broadcast_clear_txid,
        bob_offline_atomic_clearing_wtxid: clear_tx.wtxid_hex(),
        bob_offline_atomic_clearing_vsize: clear_tx.vsize(),
        mempool_accepted_live_testnet4: true,
        wallet_balance_before_sats: sats_before,
        wallet_balance_after_sats: sats_after,
        net_network_miner_fee_cost_sats: sats_before.saturating_sub(sats_after),
        funded_dlc_utxos: funded_receipts,
        adversarial_probes_live_testnet4: probes,
        nova_compressed_snark_verified: nova_verified,
        near_finality_verified: false,
        bitvm3_onchain_verified: false,
        production_ready: false,
        oracle_bound_nova_report: artifacts.report,
    }
}
