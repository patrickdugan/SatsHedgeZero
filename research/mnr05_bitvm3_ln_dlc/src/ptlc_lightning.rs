//! `Gate 3`: Atomic PTLC / Adaptor Bridge for Live Lightning Channels (`LN <-> Multilateral DLC Vault`).
//!
//! Solves non-custodial instant off-chain Lightning exit + **Double-Offline (`Bob` AND `Alice`
//! both offline at L1 maturity!)** multilateral clearing:
//!
//! 1. **Oracle Bridge (`INDEX-03` -> `2-of-3` `FrostConfederation`):**
//!    - At `t = 0` (origination), a `2-of-3` FROST state oracle confederation publishes its
//!      20-bit `OracleAnnouncement` (`T(50_000)` and `T(60_000)` anticipation points).
//!    - `Bob` pre-signs `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) adaptor templates on
//!      `U_AB` (`99,000,000` sats) and `U_BC` (`90,000,000` sats) + `0x00` unilateral `CLTV`
//!      fallbacks (`maturity + grace`), and **`bob_sk` is immediately dropped**!
//! 2. **PTLC Lightning Atomic Swap (`Alice <-> RouterLP` Locked to `Y = y * G`):**
//!    - At `$60,000` (`INDEX-03` checkpoint midpoint `6_000_000_000_000` e8), `Alice` has
//!      `60,500,000` sats posted margin + **`+11,000,000` sats realized winner PnL** (`- 1,500`
//!      sats half-fee/anchor share = **`71,498,500` sats** total cleared entitlement).
//!    - `Alice` generates secret PTLC scalar `y` and public point `Y = y * G`.
//!    - `Alice` pre-signs two L1 BIP-340 **adaptor signatures locked to `Y`** (`alice_ab_0x01_asig`
//!      on `U_AB` and `alice_ca_0x00_asig` on `U_CA`) over the 3-input, 5-output L1 clearing
//!      transaction assigning `vout[2] = (71,498,500, router_lp_spk)` to `RouterLP`.
//!      (`RouterLP` cannot complete these without `y`!)
//!    - `RouterLP` offers an off-chain Lightning PTLC (`71,498,500` sats) to `Alice` inside their
//!      Lightning channel, pre-signing `lp_ln_ptlc_asig = adaptor_sign(router_lp_sk, ln_sh, &Y)`.
//!    - `Alice` claims her `71,498,500` sats off-chain on Lightning (`adaptor_complete(&lp_ln_ptlc_asig, &y)`),
//!      **and `alice_sk` is immediately dropped (`Alice` ALSO goes 100% offline!)**.
//! 3. **Atomic Extraction & Double-Offline L1 Clearing (`bob_sk` AND `alice_sk` BOTH Absent!):**
//!    - `RouterLP` extracts `y` from `Alice`'s Lightning PTLC claim via
//!      `shz_dlc::adaptor_extract_secret_verified`, completes `Alice`'s L1 `0x01` and `0x00`
//!      signatures with `y`, completes `Bob`'s L1 `0x83` signatures with the `2-of-3` FROST
//!      outcome scalar `t`, co-signs with `Carol` and `RouterGuard`, and produces:
//!      - The consensus-valid 3-input, 5-output SegWit clearing transaction (`348`-byte stripped base),
//!      - All **8 BIP-340 `(pubkey_x, sighash32, sig_rx, sig_s)` slots** ready for
//!        [`crate::secq_schnorr_circuit::prove_and_verify_secq_batch_auth`]!
#![forbid(unsafe_code)]

use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dlc::{
    adaptor_complete, adaptor_extract_secret_verified, adaptor_sign, adaptor_verify, bip340_sign,
    bip340_verify, lift_x_even, pubkey_x_from_secret, scalar_from_bytes, tagged_hash,
    Bip340Signature,
};
use shz_oracle::frost::FrostConfederation;
use shz_utxoref::{
    mnr02::{
        encode_taproot_witness_sig, SegwitTx, SegwitTxIn, SIGHASH_ALL, SIGHASH_DEFAULT,
        SIGHASH_SINGLE_ANYONECANPAY,
    },
    mnr03::{
        build_mnr03_bob_offline_origination, Mnr03OriginationBundle, Mnr03ScaleParams,
    },
    signing_target::{point_coordinates, DEFAULT_CPFP_ANCHOR_SATS, LEAF_VERSION_TAPSCRIPT},
    UtxoRefError,
};

use crate::{
    secq_schnorr_circuit::Bip340StepSlot,
    unified_batch_circuit::OracleOpeningWitness,
};

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Canonical `SHZIDX01 || checkpoint_root32` 40-byte Bitcoin `OP_RETURN` payload (`42`-byte scriptPubKey).
pub fn build_shzidx01_op_return_spk(checkpoint_root: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(42);
    spk.push(0x6a); // OP_RETURN
    spk.push(40); // push 40 bytes
    spk.extend_from_slice(b"SHZIDX01");
    spk.extend_from_slice(checkpoint_root);
    spk
}

///Deterministic canonical `INDEX-03` 8-hour BTC/USD checkpoint fixture (`$60,000.00000000` at hour `498,007`).
pub fn canonical_index03_clearing_oracle_witness(regtest_genesis: [u8; 32]) -> OracleOpeningWitness {
    let policy_hash = sha256_bytes(b"SHZ/INDEX03/POLICY/PYTH_CHAINLINK_50BPS/V1");
    let start_hour = 498_000u64;
    let pyth_rep = sha256_bytes(b"SHZ/INDEX03/PYTH_LAZER_REPORT/498007");
    let cl_rep = sha256_bytes(b"SHZ/INDEX03/CHAINLINK_V3_REPORT/498007");

    // Build all 8 hourly leaves (`498,000..498,007`) so the 3-level Merkle path for `pos = 7` is 100% genuine!
    let hourly_midpoints_e8: [u64; 8] = [
        5_965_000_000_000,
        5_972_000_000_000,
        5_980_000_000_000,
        5_985_000_000_000,
        5_990_000_000_000,
        5_994_000_000_000,
        5_998_000_000_000,
        6_000_000_000_000, // Maturity hour `498,007`: exact $60,000.00000000!
    ];

    let mut leaf_hashes = [[0u8; 32]; 8];
    for pos in 0..8usize {
        let hour_id = start_hour + pos as u64;
        let mid = hourly_midpoints_e8[pos];
        let pyth_p = mid + 50_000_000; // +$0.50
        let cl_p = mid - 50_000_000; // -$0.50 -> exact floor midpoint == `mid`, spread == 1.67 bps <= 50 bps!
        let ts_us = (hour_id * 3_600 + 3_595) * 1_000_000;

        let mut leaf = b"SHZ/HOUR/LEAF/V1".to_vec();
        leaf.extend_from_slice(&regtest_genesis);
        leaf.extend_from_slice(&policy_hash);
        leaf.extend_from_slice(&hour_id.to_le_bytes());
        leaf.extend_from_slice(&[1u8, 0u8]);
        for v in [pyth_p, cl_p, mid, ts_us, ts_us] {
            leaf.extend_from_slice(&v.to_le_bytes());
        }
        leaf.extend_from_slice(&pyth_rep);
        leaf.extend_from_slice(&cl_rep);
        leaf_hashes[pos] = sha256_bytes(&leaf);
    }

    let hash_node = |l: &[u8; 32], r: &[u8; 32]| -> [u8; 32] {
        let mut n = b"SHZ/HOUR/NODE/V1".to_vec();
        n.extend_from_slice(l);
        n.extend_from_slice(r);
        sha256_bytes(&n)
    };
    let l1: Vec<[u8; 32]> = (0..4)
        .map(|i| hash_node(&leaf_hashes[2 * i], &leaf_hashes[2 * i + 1]))
        .collect();
    let l2: Vec<[u8; 32]> = (0..2)
        .map(|i| hash_node(&l1[2 * i], &l1[2 * i + 1]))
        .collect();

    // Opening for maturity hour `position = 7` (`hour_id = 498,007`, `$60,000.00000000`)
    let pos = 7usize;
    let merkle_siblings = [
        leaf_hashes[pos ^ 1],
        l1[(pos >> 1) ^ 1],
        l2[(pos >> 2) ^ 1],
    ];
    let ts_us = (498_007u64 * 3_600 + 3_595) * 1_000_000;

    OracleOpeningWitness {
        position: pos as u8,
        start_hour,
        genesis: regtest_genesis,
        policy_hash,
        hour_id: 498_007,
        pyth_price_e8: 6_000_050_000_000,
        chainlink_price_e8: 5_999_950_000_000,
        index_price_e8: 6_000_000_000_000,
        pyth_publish_us: ts_us,
        chainlink_publish_us: ts_us,
        pyth_report_hash: pyth_rep,
        chainlink_report_hash: cl_rep,
        merkle_siblings,
    }
}

/// Off-chain Lightning PTLC channel state between `RouterLP` and `Alice`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LnPtlcAtomicBridgeReceipt {
    pub channel_id_hex: String,
    pub ptlc_point_compressed_hex: String,
    pub alice_posted_margin_sats: u64,
    pub alice_winner_pnl_sats: u64,
    pub alice_fee_share_sats: u64,
    pub ln_ptlc_settled_to_alice_sats: u64,
    pub router_lp_l1_reimbursement_vout2_sats: u64,
    pub alice_ln_balance_before_sats: u64,
    pub alice_ln_balance_after_sats: u64,
    pub router_lp_ln_balance_before_sats: u64,
    pub router_lp_ln_balance_after_sats: u64,
    pub ptlc_secret_extracted_and_verified: bool,
    pub bob_online_at_l1_clearing: bool,
    pub alice_online_at_l1_clearing: bool,
    pub frost_threshold_quorum: String,
    pub frost_attested_price_usd: u64,
    pub forged_ptlc_claim_rejected: bool,
}

/// Complete output of the `Gate 3` PTLC Lightning <-> L1 double-offline clearing ceremony.
#[derive(Clone, Debug)]
pub struct PtlcDoubleOfflineClearingBundle {
    pub signed_clearing_tx: SegwitTx,
    pub stripped_clearing_tx_348b: [u8; 348],
    pub ab_unilateral_fallback_tx: SegwitTx,
    pub bc_unilateral_fallback_tx: SegwitTx,
    pub bip340_auth_slots: [Bip340StepSlot; 8],
    pub receipt: LnPtlcAtomicBridgeReceipt,
}

fn ln_ptlc_claim_sighash(
    channel_id: &[u8; 32],
    seq_num: u64,
    amount_sats: u64,
    ptlc_point_compressed: &[u8; 33],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(81);
    pre.extend_from_slice(channel_id);
    pre.extend_from_slice(&seq_num.to_le_bytes());
    pre.extend_from_slice(&amount_sats.to_le_bytes());
    pre.extend_from_slice(ptlc_point_compressed);
    tagged_hash(b"SHZ/MNR05/LnPtlcClaim/v1", &pre)
}

fn materialize_unilateral(
    orig_leg: &shz_utxoref::mnr03::Mnr03BobLegOrigination,
    outcome_idx: usize,
    oracle_scalar_t: &Scalar,
) -> Result<SegwitTx, String> {
    let pre = &orig_leg.outcomes[outcome_idx];
    let cp_sig = adaptor_complete(&pre.counterparty_unilateral_adaptor_sig, oracle_scalar_t)
        .map_err(|e| format!("cp uni complete: {e}"))?;
    let bob_sig = adaptor_complete(&pre.bob_unilateral_adaptor_sig, oracle_scalar_t)
        .map_err(|e| format!("bob uni complete: {e}"))?;

    let sh = pre
        .unilateral_tx
        .bip341_sighash(0, SIGHASH_DEFAULT, Some(&orig_leg.tree.unilateral_leaf_hash))
        .map_err(|e| format!("uni sighash: {e}"))?;
    bip340_verify(&orig_leg.tree.alice_pubkey_x, &sh, &cp_sig)
        .map_err(|e| format!("cp uni verify: {e}"))?;
    bip340_verify(&orig_leg.tree.bob_pubkey_x, &sh, &bob_sig)
        .map_err(|e| format!("bob uni verify: {e}"))?;

    let (sig0, sig1) = if orig_leg.tree.sorted_ab[0] == orig_leg.tree.alice_pubkey_x {
        (cp_sig, bob_sig)
    } else {
        (bob_sig, cp_sig)
    };
    let mut tx = pre.unilateral_tx.clone();
    tx.inputs[0].witness = vec![
        encode_taproot_witness_sig(&sig1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&sig0, SIGHASH_DEFAULT),
        orig_leg.tree.unilateral_cet_script.clone(),
        orig_leg.tree.unilateral_control_block.clone(),
    ];
    Ok(tx)
}

/// Executes the complete `INDEX-03 -> 2-of-3 FROST -> Off-Chain LN PTLC -> Double-Offline L1`
/// atomic clearing ceremony, scoping BOTH `bob_sk` and `alice_sk` so NEITHER key exists when
/// the L1 clearing transaction is assembled and broadcast!
#[allow(clippy::too_many_arguments)]
pub fn execute_ptlc_lightning_double_offline_clearing(
    params: &Mnr03ScaleParams,
    outpoints_display: [(&str, u32); 3],
    alice_fallback_spk: Vec<u8>,
    bob_spk: Vec<u8>,
    carol_spk: Vec<u8>,
    router_lp_spk: Vec<u8>,
    anchor_spk: Vec<u8>,
    oracle_witness: &OracleOpeningWitness,
) -> Result<(Mnr03OriginationBundle, PtlcDoubleOfflineClearingBundle), String> {
    // 1. Initialize `2-of-3` FROST Confederation & pre-commit 20-bit numeric announcement at `t = 0`!
    let frost = FrostConfederation::keygen_deterministic(2, 3, &[0x61u8; 32])
        .map_err(|e| format!("FROST keygen: {e}"))?;
    let maturity_unix = oracle_witness.hour_id * 3_600 + 3_600;
    let nonce_state = frost
        .announce_event("SHZ-MNR05-BTC-USD-8H", maturity_unix, 20, &[0x62u8; 32])
        .map_err(|e| format!("FROST announce: {e}"))?;

    let bits_50k = shz_margin::decompose_price_bits(50_000, 20);
    let bits_60k = shz_margin::decompose_price_bits(60_000, 20);
    let pt_50k = nonce_state
        .announcement
        .anticipation_point(&bits_50k)
        .map_err(|e| format!("T(50k): {e}"))?;
    let pt_60k = nonce_state
        .announcement
        .anticipation_point(&bits_60k)
        .map_err(|e| format!("T(60k): {e}"))?;
    let outcome_grid = vec![(50_000u64, pt_50k), (60_000u64, pt_60k)];

    let carol_sk = [0x23u8; 32];
    let guard_sk = [0x24u8; 32];
    let router_lp_sk = [0x25u8; 32];
    let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();
    let carol_pk = pubkey_x_from_secret(&carol_sk).unwrap();
    let router_lp_pk = pubkey_x_from_secret(&router_lp_sk).unwrap();

    // 2. Step `t = 0`: `bob_sk` exists ONLY inside this origination block, then `Bob` disconnects!
    let alice_pk_public = pubkey_x_from_secret(&[0x11u8; 32]).unwrap();
    let orig = {
        let alice_sk_t0 = [0x11u8; 32];
        let bob_sk_ephemeral = [0x22u8; 32];
        build_mnr03_bob_offline_origination(
            params,
            &alice_sk_t0,
            &bob_sk_ephemeral,
            &carol_sk,
            guard_pk,
            outpoints_display,
            alice_fallback_spk,
            bob_spk.clone(),
            carol_spk.clone(),
            anchor_spk.clone(),
            &outcome_grid,
        )
        .map_err(|e| format!("MNR-03 origination: {e}"))?
        // `bob_sk_ephemeral` DROPPED — Bob is 100% offline from here on!
    };

    // 3. Verify `INDEX-03` oracle checkpoint midpoint -> `2-of-3` FROST threshold attestation `{1, 3}`!
    if !oracle_witness.index_price_e8.is_multiple_of(100_000_000) {
        return Err("expected integral USD clearing mark for fixture".into());
    }
    let settled_price_usd = oracle_witness.index_price_e8 / 100_000_000;
    assert_eq!(settled_price_usd, 60_000);
    let frost_attestation = frost
        .threshold_attest_price(&nonce_state, &[1, 3], maturity_unix, settled_price_usd)
        .map_err(|e| format!("FROST threshold attest: {e}"))?;
    frost_attestation
        .verify_against(&nonce_state.announcement)
        .map_err(|e| format!("FROST verify: {e}"))?;
    let oracle_scalar_t = frost_attestation
        .secret_scalar_for_prefix(20)
        .map_err(|e| format!("FROST scalar: {e}"))?;

    // Build the unsigned 3-input, 5-output L1 clearing transaction where `vout[2]` reimburses `RouterLP`:
    let bob_ab_out = orig.ab_leg.outcomes[1].bob_pinned_sats; // 55,000,000 sats
    let bob_bc_out = orig.bc_leg.outcomes[1].bob_pinned_sats; // 35,000,000 sats
    let alice_posted = params.alice_ab_margin_sats + params.alice_ca_margin_sats; // 60,500,000 sats
    let alice_winner_pnl = 11_000_000u64;
    let total_deduction = params.atomic_clearing_miner_fee_sats + DEFAULT_CPFP_ANCHOR_SATS; // 3,000 sats
    let alice_fee_share = total_deduction / 2; // 1,500 sats
    let carol_fee_share = total_deduction - alice_fee_share; // 1,500 sats
    let ln_ptlc_amount = alice_posted + alice_winner_pnl - alice_fee_share; // 71,498,500 sats
    let carol_cleared_out =
        (params.carol_bc_margin_sats + params.carol_ca_margin_sats) - 5_000_000 - carol_fee_share; // 82,498,500 sats

    let in_ab = SegwitTxIn::from_display_txid(
        &orig.ab_leg.funding_txid_display,
        orig.ab_leg.funding_vout,
        0xffff_fffe,
        orig.ab_leg.funding_sats,
        orig.ab_leg.tree.script_pubkey.clone(),
    )
    .map_err(|e| format!("in_ab: {e}"))?;
    let in_bc = SegwitTxIn::from_display_txid(
        &orig.bc_leg.funding_txid_display,
        orig.bc_leg.funding_vout,
        0xffff_fffe,
        orig.bc_leg.funding_sats,
        orig.bc_leg.tree.script_pubkey.clone(),
    )
    .map_err(|e| format!("in_bc: {e}"))?;
    let in_ca = SegwitTxIn::from_display_txid(
        &orig.ca_funding_txid_display,
        orig.ca_funding_vout,
        0xffff_fffe,
        orig.ca_funding_sats,
        orig.ca_tree.script_pubkey.clone(),
    )
    .map_err(|e| format!("in_ca: {e}"))?;

    let mut clearing_tx = SegwitTx {
        version: 2,
        inputs: vec![in_ab, in_bc, in_ca],
        outputs: vec![
            (bob_ab_out, bob_spk.clone()),                  // vout[0]: 55,000,000 -> Bob (0x83 pinned)
            (bob_bc_out, bob_spk),                          // vout[1]: 35,000,000 -> Bob (0x83 pinned)
            (ln_ptlc_amount, router_lp_spk),                // vout[2]: 71,498,500 -> RouterLP (reimbursing Alice LN exit!)
            (carol_cleared_out, carol_spk),                 // vout[3]: 82,498,500 -> Carol
            (DEFAULT_CPFP_ANCHOR_SATS, anchor_spk),         // vout[4]: 330 -> Anchor
        ],
        locktime: params.maturity_height,
    };

    let ab_sh_0x01 = clearing_tx
        .bip341_sighash(0, SIGHASH_ALL, Some(&orig.ab_leg.tree.route_leaf_hash))
        .map_err(|e| format!("ab_sh_0x01: {e}"))?;
    let ca_sh_0x00 = clearing_tx
        .bip341_sighash(2, SIGHASH_DEFAULT, Some(&orig.ca_tree.cet_leaf_hash))
        .map_err(|e| format!("ca_sh_0x00: {e}"))?;

    // 4. Step `t = 1`: Off-Chain Lightning PTLC Atomic Swap (`Alice <-> RouterLP`).
    //    `alice_sk` exists ONLY inside this off-chain LN block — once Alice claims her `71,498,500`
    //    sats on Lightning, `alice_sk` is DROPPED so BOTH `Bob` AND `Alice` are offline for L1 clearing!
    let channel_id = sha256_bytes(b"SHZ/MNR05/LN_CHANNEL/ROUTER_LP_ALICE/01");
    let alice_ln_before = 5_000_000u64;
    let lp_ln_before = 95_000_000u64;

    let (
        ptlc_point_y,
        ptlc_y_compressed,
        ln_claim_sh,
        lp_ln_ptlc_asig,
        lp_ln_completed_by_alice,
        alice_ab_0x01_asig,
        alice_ca_0x00_asig,
        forged_ptlc_claim_rejected,
    ) = {
        let alice_sk_ephemeral = [0x11u8; 32];
        let y_bytes = sha256_bytes(b"SHZ/MNR05/ALICE_PTLC_SECRET_Y/V1");
        let y_secret = scalar_from_bytes(&y_bytes).map_err(|e| format!("y scalar: {e}"))?;
        let y_point = ProjectivePoint::GENERATOR * y_secret;
        let y_comp = shz_dlc::encode_point_compressed(&y_point)
            .map_err(|e| format!("encode Y: {e}"))?;

        // Alice gives RouterLP adaptor pre-signatures on `vin[0]` (`0x01`) and `vin[2]` (`0x00`) locked to `Y`:
        let a_ab_asig = adaptor_sign(&alice_sk_ephemeral, &ab_sh_0x01, &y_point)
            .map_err(|e| format!("alice_ab adaptor_sign: {e}"))?;
        let a_ca_asig = adaptor_sign(&alice_sk_ephemeral, &ca_sh_0x00, &y_point)
            .map_err(|e| format!("alice_ca adaptor_sign: {e}"))?;
        adaptor_verify(&alice_pk_public, &ab_sh_0x01, &y_point, &a_ab_asig)
            .map_err(|e| format!("verify alice_ab_asig: {e}"))?;
        adaptor_verify(&alice_pk_public, &ca_sh_0x00, &y_point, &a_ca_asig)
            .map_err(|e| format!("verify alice_ca_asig: {e}"))?;

        // RouterLP locks `71,498,500` sats on their Lightning channel to `Y`:
        let ln_sh = ln_ptlc_claim_sighash(&channel_id, 42, ln_ptlc_amount, &y_comp);
        let lp_asig = adaptor_sign(&router_lp_sk, &ln_sh, &y_point)
            .map_err(|e| format!("lp_ln adaptor_sign: {e}"))?;
        adaptor_verify(&router_lp_pk, &ln_sh, &y_point, &lp_asig)
            .map_err(|e| format!("verify lp_ln_asig: {e}"))?;

        // Negative control: an unrelated signature CANNOT pass `adaptor_extract_secret_verified`!
        let unrelated_sig = bip340_sign(&router_lp_sk, &[0x99u8; 32]).unwrap();
        let forged_rejected = adaptor_extract_secret_verified(
            &router_lp_pk,
            &ln_sh,
            &y_point,
            &lp_asig,
            &unrelated_sig,
        )
        .is_err();

        // Alice claims her `71,498,500` sats off-chain on Lightning by completing `lp_asig` with `y_secret`!
        let lp_completed = adaptor_complete(&lp_asig, &y_secret)
            .map_err(|e| format!("alice complete LN PTLC: {e}"))?;
        let _alice_ln_cosig = bip340_sign(&alice_sk_ephemeral, &ln_sh)
            .map_err(|e| format!("alice LN cosig: {e}"))?;

        (
            y_point,
            y_comp,
            ln_sh,
            lp_asig,
            lp_completed,
            a_ab_asig,
            a_ca_asig,
            forged_rejected,
        )
        // `alice_sk_ephemeral` AND `y_secret` DROPPED — BOTH `Bob` AND `Alice` are now 100% offline!
    };
    if !forged_ptlc_claim_rejected {
        return Err("forged PTLC claim was not rejected".into());
    }

    let alice_ln_after = alice_ln_before + ln_ptlc_amount; // 76,498,500 sats
    let lp_ln_after = lp_ln_before - ln_ptlc_amount; // 23,501,500 sats

    // 5. Step `t = 2` (**Double-Offline L1 Clearing**: ZERO `bob_sk` and ZERO `alice_sk`!):
    //    `RouterLP` extracts `y` from Alice's Lightning claim and completes Alice's L1 signatures!
    let extracted_y = adaptor_extract_secret_verified(
        &router_lp_pk,
        &ln_claim_sh,
        &ptlc_point_y,
        &lp_ln_ptlc_asig,
        &lp_ln_completed_by_alice,
    )
    .map_err(|e| format!("RouterLP extract y from LN PTLC: {e}"))?;

    let alice_ab_0x01_sig: Bip340Signature = adaptor_complete(&alice_ab_0x01_asig, &extracted_y)
        .map_err(|e| format!("complete alice_ab_0x01: {e}"))?;
    let alice_ca_0x00_sig: Bip340Signature = adaptor_complete(&alice_ca_0x00_asig, &extracted_y)
        .map_err(|e| format!("complete alice_ca_0x00: {e}"))?;
    bip340_verify(&alice_pk_public, &ab_sh_0x01, &alice_ab_0x01_sig)
        .map_err(|e| format!("verify completed alice_ab_0x01: {e}"))?;
    bip340_verify(&alice_pk_public, &ca_sh_0x00, &alice_ca_0x00_sig)
        .map_err(|e| format!("verify completed alice_ca_0x00: {e}"))?;

    // Complete Bob's `0x83` adaptor pre-signatures on `vin[0]` and `vin[1]` using FROST `oracle_scalar_t`!
    let bob_ab_0x83_sig = adaptor_complete(
        &orig.ab_leg.outcomes[1].bob_route_0x83_adaptor_sig,
        &oracle_scalar_t,
    )
    .map_err(|e| format!("complete bob_ab_0x83: {e}"))?;
    let ab_sh_0x83 = clearing_tx
        .bip341_sighash(
            0,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&orig.ab_leg.tree.route_leaf_hash),
        )
        .map_err(|e| format!("ab_sh_0x83: {e}"))?;
    bip340_verify(&orig.ab_leg.tree.bob_pubkey_x, &ab_sh_0x83, &bob_ab_0x83_sig)
        .map_err(|e| format!("verify bob_ab_0x83: {e}"))?;

    let guard_ab_0x01_sig =
        bip340_sign(&guard_sk, &ab_sh_0x01).map_err(|e| format!("guard_ab_0x01: {e}"))?;

    clearing_tx.inputs[0].witness = vec![
        encode_taproot_witness_sig(&bob_ab_0x83_sig, SIGHASH_SINGLE_ANYONECANPAY),
        encode_taproot_witness_sig(&guard_ab_0x01_sig, SIGHASH_ALL),
        encode_taproot_witness_sig(&alice_ab_0x01_sig, SIGHASH_ALL),
        orig.ab_leg.tree.route_cet_script.clone(),
        orig.ab_leg.tree.route_control_block.clone(),
    ];

    let bob_bc_0x83_sig = adaptor_complete(
        &orig.bc_leg.outcomes[1].bob_route_0x83_adaptor_sig,
        &oracle_scalar_t,
    )
    .map_err(|e| format!("complete bob_bc_0x83: {e}"))?;
    let bc_sh_0x83 = clearing_tx
        .bip341_sighash(
            1,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&orig.bc_leg.tree.route_leaf_hash),
        )
        .map_err(|e| format!("bc_sh_0x83: {e}"))?;
    bip340_verify(&orig.bc_leg.tree.bob_pubkey_x, &bc_sh_0x83, &bob_bc_0x83_sig)
        .map_err(|e| format!("verify bob_bc_0x83: {e}"))?;

    let bc_sh_0x01 = clearing_tx
        .bip341_sighash(1, SIGHASH_ALL, Some(&orig.bc_leg.tree.route_leaf_hash))
        .map_err(|e| format!("bc_sh_0x01: {e}"))?;
    let carol_bc_0x01_sig =
        bip340_sign(&carol_sk, &bc_sh_0x01).map_err(|e| format!("carol_bc_0x01: {e}"))?;
    let guard_bc_0x01_sig =
        bip340_sign(&guard_sk, &bc_sh_0x01).map_err(|e| format!("guard_bc_0x01: {e}"))?;

    clearing_tx.inputs[1].witness = vec![
        encode_taproot_witness_sig(&bob_bc_0x83_sig, SIGHASH_SINGLE_ANYONECANPAY),
        encode_taproot_witness_sig(&guard_bc_0x01_sig, SIGHASH_ALL),
        encode_taproot_witness_sig(&carol_bc_0x01_sig, SIGHASH_ALL),
        orig.bc_leg.tree.route_cet_script.clone(),
        orig.bc_leg.tree.route_control_block.clone(),
    ];

    let carol_ca_0x00_sig =
        bip340_sign(&carol_sk, &ca_sh_0x00).map_err(|e| format!("carol_ca_0x00: {e}"))?;
    let (ca_pk0, ca_pk1, ca_sig0, ca_sig1) =
        if orig.ca_tree.party_pubkeys_sorted[0] == alice_pk_public {
            (
                alice_pk_public,
                carol_pk,
                alice_ca_0x00_sig,
                carol_ca_0x00_sig,
            )
        } else {
            (
                carol_pk,
                alice_pk_public,
                carol_ca_0x00_sig,
                alice_ca_0x00_sig,
            )
        };

    let mut ca_cet_script = Vec::with_capacity(68);
    ca_cet_script.push(0x20);
    ca_cet_script.extend_from_slice(&orig.ca_tree.party_pubkeys_sorted[0]);
    ca_cet_script.extend_from_slice(&[0xad, 0x20]);
    ca_cet_script.extend_from_slice(&orig.ca_tree.party_pubkeys_sorted[1]);
    ca_cet_script.push(0xac);

    let mut ca_tweak_in = [0u8; 64];
    ca_tweak_in[..32].copy_from_slice(&orig.ca_tree.internal_xonly);
    ca_tweak_in[32..].copy_from_slice(&orig.ca_tree.tap_merkle_root);
    let ca_tweak = <Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce(
        k256::U256::from_be_slice(&tagged_hash(b"TapTweak", &ca_tweak_in)),
    );
    let ca_internal_pt =
        lift_x_even(&orig.ca_tree.internal_xonly).map_err(|e| format!("ca lift_x: {e}"))?;
    let (_, ca_out_y) = point_coordinates(ca_internal_pt + ProjectivePoint::GENERATOR * ca_tweak)
        .map_err(|e: UtxoRefError| format!("ca coords: {e}"))?;
    let mut ca_ctrl = Vec::with_capacity(65);
    ca_ctrl.push(LEAF_VERSION_TAPSCRIPT | (ca_out_y[31] & 1));
    ca_ctrl.extend_from_slice(&orig.ca_tree.internal_xonly);
    ca_ctrl.extend_from_slice(&orig.ca_tree.refund_leaf_hash);

    clearing_tx.inputs[2].witness = vec![
        encode_taproot_witness_sig(&ca_sig1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&ca_sig0, SIGHASH_DEFAULT),
        ca_cet_script,
        ca_ctrl,
    ];

    let stripped_vec = clearing_tx.serialize_unsigned();
    let stripped_clearing_tx_348b: [u8; 348] = stripped_vec
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 348-byte stripped tx, got {}", v.len()))?;

    // Package all 8 exact BIP-340 witness signatures for `Mnr05SecqBip340Step`!
    let bip340_auth_slots = [
        Bip340StepSlot {
            step_idx: 0,
            sighash_flag: SIGHASH_SINGLE_ANYONECANPAY,
            pubkey_x: orig.ab_leg.tree.bob_pubkey_x,
            sighash32: ab_sh_0x83,
            sig_rx: bob_ab_0x83_sig.r_x,
            sig_s: bob_ab_0x83_sig.s,
        },
        Bip340StepSlot {
            step_idx: 1,
            sighash_flag: SIGHASH_ALL,
            pubkey_x: guard_pk,
            sighash32: ab_sh_0x01,
            sig_rx: guard_ab_0x01_sig.r_x,
            sig_s: guard_ab_0x01_sig.s,
        },
        Bip340StepSlot {
            step_idx: 2,
            sighash_flag: SIGHASH_ALL,
            pubkey_x: alice_pk_public,
            sighash32: ab_sh_0x01,
            sig_rx: alice_ab_0x01_sig.r_x,
            sig_s: alice_ab_0x01_sig.s,
        },
        Bip340StepSlot {
            step_idx: 3,
            sighash_flag: SIGHASH_SINGLE_ANYONECANPAY,
            pubkey_x: orig.bc_leg.tree.bob_pubkey_x,
            sighash32: bc_sh_0x83,
            sig_rx: bob_bc_0x83_sig.r_x,
            sig_s: bob_bc_0x83_sig.s,
        },
        Bip340StepSlot {
            step_idx: 4,
            sighash_flag: SIGHASH_ALL,
            pubkey_x: guard_pk,
            sighash32: bc_sh_0x01,
            sig_rx: guard_bc_0x01_sig.r_x,
            sig_s: guard_bc_0x01_sig.s,
        },
        Bip340StepSlot {
            step_idx: 5,
            sighash_flag: SIGHASH_ALL,
            pubkey_x: carol_pk,
            sighash32: bc_sh_0x01,
            sig_rx: carol_bc_0x01_sig.r_x,
            sig_s: carol_bc_0x01_sig.s,
        },
        Bip340StepSlot {
            step_idx: 6,
            sighash_flag: SIGHASH_DEFAULT,
            pubkey_x: ca_pk1,
            sighash32: ca_sh_0x00,
            sig_rx: ca_sig1.r_x,
            sig_s: ca_sig1.s,
        },
        Bip340StepSlot {
            step_idx: 7,
            sighash_flag: SIGHASH_DEFAULT,
            pubkey_x: ca_pk0,
            sighash32: ca_sh_0x00,
            sig_rx: ca_sig0.r_x,
            sig_s: ca_sig0.s,
        },
    ];

    let ab_uni = materialize_unilateral(&orig.ab_leg, 1, &oracle_scalar_t)?;
    let bc_uni = materialize_unilateral(&orig.bc_leg, 1, &oracle_scalar_t)?;

    let receipt = LnPtlcAtomicBridgeReceipt {
        channel_id_hex: hex::encode(channel_id),
        ptlc_point_compressed_hex: hex::encode(ptlc_y_compressed),
        alice_posted_margin_sats: alice_posted,
        alice_winner_pnl_sats: alice_winner_pnl,
        alice_fee_share_sats: alice_fee_share,
        ln_ptlc_settled_to_alice_sats: ln_ptlc_amount,
        router_lp_l1_reimbursement_vout2_sats: ln_ptlc_amount,
        alice_ln_balance_before_sats: alice_ln_before,
        alice_ln_balance_after_sats: alice_ln_after,
        router_lp_ln_balance_before_sats: lp_ln_before,
        router_lp_ln_balance_after_sats: lp_ln_after,
        ptlc_secret_extracted_and_verified: true,
        bob_online_at_l1_clearing: false,
        alice_online_at_l1_clearing: false,
        frost_threshold_quorum: "2-of-3 {signer_1, signer_3}".into(),
        frost_attested_price_usd: settled_price_usd,
        forged_ptlc_claim_rejected,
    };

    Ok((
        orig,
        PtlcDoubleOfflineClearingBundle {
            signed_clearing_tx: clearing_tx,
            stripped_clearing_tx_348b,
            ab_unilateral_fallback_tx: ab_uni,
            bc_unilateral_fallback_tx: bc_uni,
            bip340_auth_slots,
            receipt,
        },
    ))
}
