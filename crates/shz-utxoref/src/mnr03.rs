//! `SHZ-MNR-03`: 3-Party Multilateral Atomic Clearing with **Bob 100% Offline (`0x83`)**,
//! Unilateral `CLTV` Fallback, and Reorg-Safe `DurablePnlBatchBook` Progression.
//!
//! Bridges the gap between:
//! - `SHZ-MNR-02` (single-contract `U_AB` Bob-offline `0x83` closeout), and
//! - `clearing_3party` (3-input multilateral clearing previously signed with all 3 parties online).
//!
//! ### Protocol Flow (`t = 0` Origination -> `t = 1` Bob Goes Offline -> `t = 2` Maturity Clearing)
//! 1. **`t = 0` (Origination, Bob Online):**
//!    - **Trade 1 (`U_AB`):** `Alice` (Long) vs `Bob` (Short) on a 3-leaf `Mnr02TaprootTree`
//!      (`<P_Alice> OP_CHECKSIGVERIFY <P_Guard> OP_CHECKSIGVERIFY <P_Bob> OP_CHECKSIG`).
//!      Bob pre-signs a 1-in/1-out `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) adaptor
//!      signature for each outcome price committing strictly to `Output = (bob_ab_sats, bob_spk)`.
//!    - **Trade 2 (`U_BC`):** `Bob` (Long) vs `Carol` (Short) on a 3-leaf `Mnr02TaprootTree`
//!      (`<P_Carol> OP_CHECKSIGVERIFY <P_Guard> OP_CHECKSIGVERIFY <P_Bob> OP_CHECKSIG`).
//!      Bob pre-signs a 1-in/1-out `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) adaptor
//!      signature for each outcome price committing strictly to `Output = (bob_bc_sats, bob_spk)`.
//!    - Both `U_AB` and `U_BC` also carry pre-signed Leaf 1 unilateral `CLTV` fallback CETs
//!      (`locktime = maturity + grace`) and Leaf 2 `CLTV` refunds (`locktime = maturity + refund`).
//! 2. **`t = 1` (`bob_sk` Dropped — Bob 100% Offline!):**
//!    - **Trade 3 (`U_CA`):** `Carol` (Long) vs `Alice` (Short) on a 2-leaf `UTXORef` NUMS `P2TR`
//!      interactive bilateral tree, flattening all three parties' USD exposure (`delta_usd = 0`).
//! 3. **`t = 2` (Maturity, `bob_sk` STILL Offline!):**
//!    - Because BIP-341 `SigMsg(0x83, ext_flag = 1)` omits `input_index` under `ANYONECANPAY` and
//!      commits only to `this_input` and `SHA256(outputs[input_index])`, Bob's `t = 0` `0x83`
//!      adaptor signatures on `U_AB` (`vin[0] -> vout[0]`) and `U_BC` (`vin[1] -> vout[1]`) remain
//!      100% consensus-valid inside a **single 3-input, 5-output atomic Taproot clearing transaction**:
//!      - `vin[0]` (`U_AB`): `[bob_0x83_completed, guard_0x01, alice_0x01, route_script, ctrl_block]`
//!      - `vin[1]` (`U_BC`): `[bob_0x83_completed, guard_0x01, carol_0x01, route_script, ctrl_block]`
//!      - `vin[2]` (`U_CA`): `[sig_pk1_0x00, sig_pk0_0x00, cet_script, ctrl_block]`
//!      - `vout[0]`: Bob's pinned `U_AB` payout (`bob_ab_sats`, `bob_spk`)
//!      - `vout[1]`: Bob's pinned `U_BC` payout (`bob_bc_sats`, `bob_spk`)
//!      - `vout[2]`: Winner Alice's cleared principal + routed PnL (`alice_cleared_sats`, `alice_spk`)
//!      - `vout[3]`: Carol's freed margin (`carol_cleared_sats`, `carol_spk`)
//!      - `vout[4]`: `330`-sat `UTXORef` CPFP anchor (`330`, `anchor_spk`)

use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{bigint::U256, group::Group, ops::Reduce},
};
use serde::{Deserialize, Serialize};
use shz_dlc::{
    AdaptorSignature, BtcOutPoint, adaptor_complete, adaptor_sign, adaptor_verify, bip340_sign,
    bip340_verify, lift_x_even, pubkey_x_from_secret, tagged_hash,
};
use shz_margin::CollateralAsset;

use crate::{
    UtxoRefError,
    mnr02::{
        Mnr02TaprootTree, SIGHASH_ALL, SIGHASH_DEFAULT, SIGHASH_SINGLE_ANYONECANPAY, SegwitTx,
        SegwitTxIn, encode_taproot_witness_sig, inverse_long_pnl_trunc_sats,
    },
    pnl_batch::{
        AccountRecord, BookAuthState, DurablePnlBatchBook, FundedVaultUtxo, NettingSetSpec,
        PermittedRoute, PnlBatchSnapshotV1, RealizedObligation, RouteTarget, VaultRecord,
        solve_and_verify_pnl_batch,
    },
    signing_target::{
        DEFAULT_CPFP_ANCHOR_SATS, LEAF_VERSION_TAPSCRIPT, UtxoRefFundingOutput,
        derive_utxoref_funding_output, point_coordinates,
    },
};

/// Economic + sizing parameters for an `SHZ-MNR-03` 3-party Bob-offline clearing ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mnr03ScaleParams {
    pub label: String,
    pub notional_usd: u64,
    pub entry_ab_usd: u64,
    pub entry_bc_usd: u64,
    pub entry_ca_usd: u64,
    pub alice_ab_margin_sats: u64,
    pub bob_ab_margin_sats: u64,
    pub bob_bc_margin_sats: u64,
    pub carol_bc_margin_sats: u64,
    pub carol_ca_margin_sats: u64,
    pub alice_ca_margin_sats: u64,
    pub unilateral_fee_sats: u64,
    pub atomic_clearing_miner_fee_sats: u64,
    pub maturity_height: u32,
    pub grace_blocks: u32,
    pub refund_delay_blocks: u32,
    pub ca_refund_csv: u16,
}

impl Mnr03ScaleParams {
    /// Full `$33,000` notional macro fixture (`$50,000 -> $55,000 -> $60,000`) for Core regtest + Nova.
    pub fn macro_regtest_33k(maturity_height: u32) -> Self {
        Self {
            label: "MNR03-MACRO-33K-BOB-OFFLINE".to_owned(),
            notional_usd: 33_000,
            entry_ab_usd: 50_000,
            entry_bc_usd: 55_000,
            entry_ca_usd: 60_000,
            alice_ab_margin_sats: 33_000_000,
            bob_ab_margin_sats: 66_000_000,
            bob_bc_margin_sats: 30_000_000,
            carol_bc_margin_sats: 60_000_000,
            carol_ca_margin_sats: 27_500_000,
            alice_ca_margin_sats: 27_500_000,
            unilateral_fee_sats: 1_000,
            atomic_clearing_miner_fee_sats: 2_670, // + 330 anchor = 3,000 total deduction (1,500 Alice + 1,500 Carol)
            maturity_height,
            grace_blocks: 20,
            refund_delay_blocks: 60,
            ca_refund_csv: 144,
        }
    }

    /// Compact `$1` notional micro fixture (`$80,000 -> $100,000 -> $125,000`, `3,900` sats total funded,
    /// `610` sats clearing fee = `1.02 sat/vB` on `598 vB`) designed for live public Bitcoin Testnet4.
    pub fn micro_testnet4_live(maturity_height: u32) -> Self {
        Self {
            label: "MNR03-TESTNET4-MICRO-1USD-BOB-OFFLINE".to_owned(),
            notional_usd: 1,
            entry_ab_usd: 80_000,
            entry_bc_usd: 100_000,
            entry_ca_usd: 125_000,
            alice_ab_margin_sats: 500,
            bob_ab_margin_sats: 900,
            bob_bc_margin_sats: 350,
            carol_bc_margin_sats: 1_010,
            carol_ca_margin_sats: 570,
            alice_ca_margin_sats: 570,
            unilateral_fee_sats: 150,
            atomic_clearing_miner_fee_sats: 610, // + 330 anchor = 940 total deduction (470 Alice + 470 Carol)
            maturity_height,
            grace_blocks: 20,
            refund_delay_blocks: 60,
            ca_refund_csv: 144,
        }
    }

    pub fn ab_funding_sats(&self) -> u64 {
        self.alice_ab_margin_sats + self.bob_ab_margin_sats
    }

    pub fn bc_funding_sats(&self) -> u64 {
        self.bob_bc_margin_sats + self.carol_bc_margin_sats
    }

    pub fn ca_funding_sats(&self) -> u64 {
        self.carol_ca_margin_sats + self.alice_ca_margin_sats
    }

    pub fn total_funding_sats(&self) -> u64 {
        self.ab_funding_sats() + self.bc_funding_sats() + self.ca_funding_sats()
    }
}

/// Public funding scripts for the 3 DLC UTXOs (`U_AB`, `U_BC`, `U_CA`) so an L1 node can fund them first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mnr03FundingDescriptors {
    pub ab_tree: Mnr02TaprootTree,
    pub bc_tree: Mnr02TaprootTree,
    pub ca_tree: UtxoRefFundingOutput,
    pub ab_funding_sats: u64,
    pub bc_funding_sats: u64,
    pub ca_funding_sats: u64,
}

pub fn precompute_mnr03_funding_descriptors(
    params: &Mnr03ScaleParams,
    alice_pk: [u8; 32],
    bob_pk: [u8; 32],
    carol_pk: [u8; 32],
    guard_pk: [u8; 32],
) -> Result<Mnr03FundingDescriptors, UtxoRefError> {
    let ab_tree = Mnr02TaprootTree::build(
        alice_pk,
        bob_pk,
        guard_pk,
        params.maturity_height,
        params.grace_blocks,
        params.refund_delay_blocks,
    )?;
    let bc_tree = Mnr02TaprootTree::build(
        carol_pk,
        bob_pk,
        guard_pk,
        params.maturity_height,
        params.grace_blocks,
        params.refund_delay_blocks,
    )?;
    let ca_tree = derive_utxoref_funding_output(carol_pk, alice_pk, params.ca_refund_csv)?;
    Ok(Mnr03FundingDescriptors {
        ab_tree,
        bc_tree,
        ca_tree,
        ab_funding_sats: params.ab_funding_sats(),
        bc_funding_sats: params.bc_funding_sats(),
        ca_funding_sats: params.ca_funding_sats(),
    })
}

/// Origination-time pre-signed outcome for one bilateral `MNR-02` leg involving Bob (`AB` or `BC`).
#[derive(Debug, Clone)]
pub struct Mnr03LegPreSignedOutcome {
    pub price_usd: u64,
    pub bob_pinned_sats: u64,
    pub counterparty_unilateral_sats: u64,
    pub bob_route_0x83_adaptor_sig: AdaptorSignature,
    pub unilateral_tx: SegwitTx,
    pub counterparty_unilateral_adaptor_sig: AdaptorSignature,
    pub bob_unilateral_adaptor_sig: AdaptorSignature,
}

/// Public + pre-signed origination package for one Bob leg (`AB` or `BC`) — contains **ZERO secret keys**.
#[derive(Debug, Clone)]
pub struct Mnr03BobLegOrigination {
    pub channel_id: &'static str,
    pub tree: Mnr02TaprootTree,
    pub funding_txid_display: String,
    pub funding_vout: u32,
    pub funding_sats: u64,
    pub counterparty_spk: Vec<u8>,
    pub bob_spk: Vec<u8>,
    pub anchor_spk: Vec<u8>,
    pub outcomes: Vec<Mnr03LegPreSignedOutcome>,
    pub signed_refund_tx: SegwitTx,
}

/// Complete `t = 0` origination bundle for `AB` and `BC` created before Bob goes offline.
/// Contains **no secret keys** — `bob_sk` can be zeroized/dropped immediately after this returns!
#[derive(Debug, Clone)]
pub struct Mnr03OriginationBundle {
    pub params: Mnr03ScaleParams,
    pub ab_leg: Mnr03BobLegOrigination,
    pub bc_leg: Mnr03BobLegOrigination,
    pub ca_tree: UtxoRefFundingOutput,
    pub ca_funding_txid_display: String,
    pub ca_funding_vout: u32,
    pub ca_funding_sats: u64,
    pub alice_spk: Vec<u8>,
    pub bob_spk: Vec<u8>,
    pub carol_spk: Vec<u8>,
    pub anchor_spk: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn build_single_bob_leg_origination(
    channel_id: &'static str,
    counterparty_sk: &[u8; 32],
    bob_sk: &[u8; 32],
    guard_pk: [u8; 32],
    funding_txid_display: &str,
    funding_vout: u32,
    counterparty_margin_sats: u64,
    bob_margin_sats: u64,
    bob_is_long: bool,
    notional_usd: u64,
    entry_price_usd: u64,
    unilateral_fee_sats: u64,
    maturity_height: u32,
    grace_blocks: u32,
    refund_delay_blocks: u32,
    counterparty_spk: Vec<u8>,
    bob_spk: Vec<u8>,
    anchor_spk: Vec<u8>,
    outcome_prices_and_points: &[(u64, ProjectivePoint)],
) -> Result<Mnr03BobLegOrigination, UtxoRefError> {
    let counterparty_pk = pubkey_x_from_secret(counterparty_sk)
        .map_err(|_| UtxoRefError::InvalidCrypto("counterparty_sk"))?;
    let bob_pk =
        pubkey_x_from_secret(bob_sk).map_err(|_| UtxoRefError::InvalidCrypto("bob_sk"))?;

    let tree = Mnr02TaprootTree::build(
        counterparty_pk,
        bob_pk,
        guard_pk,
        maturity_height,
        grace_blocks,
        refund_delay_blocks,
    )?;

    let funding_sats = counterparty_margin_sats + bob_margin_sats;
    let uni_distributable = funding_sats
        .checked_sub(unilateral_fee_sats + DEFAULT_CPFP_ANCHOR_SATS)
        .ok_or(UtxoRefError::AccountingViolation(
            "leg collateral < unilateral fee + anchor",
        ))?;

    let base_input = SegwitTxIn::from_display_txid(
        funding_txid_display,
        funding_vout,
        0xfffffffe,
        funding_sats,
        tree.script_pubkey.clone(),
    )?;

    // 1. Pre-sign Leaf 2 Refund TX (`locktime = refund_cltv_height`) before funding!
    let refund_cp = counterparty_margin_sats
        .saturating_sub(unilateral_fee_sats / 2 + DEFAULT_CPFP_ANCHOR_SATS / 2);
    let refund_bob = uni_distributable - refund_cp;
    let mut signed_refund_tx = SegwitTx {
        version: 2,
        inputs: vec![base_input.clone()],
        outputs: vec![
            (refund_bob, bob_spk.clone()),
            (refund_cp, counterparty_spk.clone()),
            (DEFAULT_CPFP_ANCHOR_SATS, anchor_spk.clone()),
        ],
        locktime: tree.refund_cltv_height,
    };
    let refund_sh =
        signed_refund_tx.bip341_sighash(0, SIGHASH_DEFAULT, Some(&tree.refund_leaf_hash))?;
    let cp_ref_sig =
        bip340_sign(counterparty_sk, &refund_sh).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
    let bob_ref_sig =
        bip340_sign(bob_sk, &refund_sh).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
    let (sig_pk0, sig_pk1) = if tree.sorted_ab[0] == counterparty_pk {
        (cp_ref_sig, bob_ref_sig)
    } else {
        (bob_ref_sig, cp_ref_sig)
    };
    signed_refund_tx.inputs[0].witness = vec![
        encode_taproot_witness_sig(&sig_pk1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&sig_pk0, SIGHASH_DEFAULT),
        tree.refund_script.clone(),
        tree.refund_control_block.clone(),
    ];

    // 2. Pre-sign Bob's 1-in/1-out `0x83` route adaptor sig + both parties' `0x00` unilateral fallback CET!
    // Note on BIP-341 `0x83`: `SigMsg(0x83, ext_flag = 1)` commits strictly to `this_input` and
    // `SHA256(outputs[input_index])` — omitting `input_index`! Thus signing a 1-in/1-out template at
    // index 0 produces the EXACT same `TapSighash` as spending this input at ANY index `k` paired
    // with `(bob_pinned_sats, bob_spk)` at `outputs[k]`!
    let mut outcomes = Vec::with_capacity(outcome_prices_and_points.len());
    for &(price_usd, ref adaptor_pt) in outcome_prices_and_points {
        if bool::from(adaptor_pt.is_identity()) {
            return Err(UtxoRefError::InvalidCrypto("identity adaptor point"));
        }
        let pnl_long = inverse_long_pnl_trunc_sats(notional_usd, entry_price_usd, price_usd);
        let bob_delta = if bob_is_long { pnl_long } else { -pnl_long };

        let min_dust = DEFAULT_CPFP_ANCHOR_SATS as i128;
        let max_bob = (uni_distributable - DEFAULT_CPFP_ANCHOR_SATS) as i128;
        let bob_pinned_sats =
            ((bob_margin_sats as i128) + bob_delta).clamp(min_dust, max_bob) as u64;
        let counterparty_unilateral_sats = uni_distributable - bob_pinned_sats;

        let template_0x83 = SegwitTx {
            version: 2,
            inputs: vec![base_input.clone()],
            outputs: vec![(bob_pinned_sats, bob_spk.clone())],
            locktime: tree.maturity_height,
        };
        let sighash_0x83 = template_0x83.bip341_sighash(
            0,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&tree.route_leaf_hash),
        )?;
        let bob_route_0x83_adaptor_sig = adaptor_sign(bob_sk, &sighash_0x83, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob 0x83 adaptor_sign"))?;
        adaptor_verify(&bob_pk, &sighash_0x83, adaptor_pt, &bob_route_0x83_adaptor_sig)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob 0x83 adaptor_verify"))?;

        let unilateral_tx = SegwitTx {
            version: 2,
            inputs: vec![base_input.clone()],
            outputs: vec![
                (bob_pinned_sats, bob_spk.clone()),
                (counterparty_unilateral_sats, counterparty_spk.clone()),
                (DEFAULT_CPFP_ANCHOR_SATS, anchor_spk.clone()),
            ],
            locktime: tree.unilateral_cltv_height,
        };
        let uni_sh = unilateral_tx.bip341_sighash(
            0,
            SIGHASH_DEFAULT,
            Some(&tree.unilateral_leaf_hash),
        )?;
        let cp_uni_asig = adaptor_sign(counterparty_sk, &uni_sh, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("cp uni adaptor_sign"))?;
        let bob_uni_asig = adaptor_sign(bob_sk, &uni_sh, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob uni adaptor_sign"))?;
        adaptor_verify(&counterparty_pk, &uni_sh, adaptor_pt, &cp_uni_asig)
            .map_err(|_| UtxoRefError::InvalidCrypto("cp uni adaptor_verify"))?;
        adaptor_verify(&bob_pk, &uni_sh, adaptor_pt, &bob_uni_asig)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob uni adaptor_verify"))?;

        outcomes.push(Mnr03LegPreSignedOutcome {
            price_usd,
            bob_pinned_sats,
            counterparty_unilateral_sats,
            bob_route_0x83_adaptor_sig,
            unilateral_tx,
            counterparty_unilateral_adaptor_sig: cp_uni_asig,
            bob_unilateral_adaptor_sig: bob_uni_asig,
        });
    }

    Ok(Mnr03BobLegOrigination {
        channel_id,
        tree,
        funding_txid_display: funding_txid_display.to_owned(),
        funding_vout,
        funding_sats,
        counterparty_spk,
        bob_spk,
        anchor_spk,
        outcomes,
        signed_refund_tx,
    })
}

/// Step `t = 0` (Bob Online): Pre-signs `AB` and `BC` `0x83` adaptor templates + unilateral/refund
/// fallbacks so Bob can immediately disconnect (`bob_sk` is never needed again!).
#[allow(clippy::too_many_arguments)]
pub fn build_mnr03_bob_offline_origination(
    params: &Mnr03ScaleParams,
    alice_sk: &[u8; 32],
    bob_sk_at_origination_only: &[u8; 32],
    carol_sk: &[u8; 32],
    guard_pk: [u8; 32],
    outpoints_display: [(&str, u32); 3],
    alice_spk: Vec<u8>,
    bob_spk: Vec<u8>,
    carol_spk: Vec<u8>,
    anchor_spk: Vec<u8>,
    outcome_prices_and_points: &[(u64, ProjectivePoint)],
) -> Result<Mnr03OriginationBundle, UtxoRefError> {
    let alice_pk =
        pubkey_x_from_secret(alice_sk).map_err(|_| UtxoRefError::InvalidCrypto("alice_sk"))?;
    let carol_pk =
        pubkey_x_from_secret(carol_sk).map_err(|_| UtxoRefError::InvalidCrypto("carol_sk"))?;

    let ab_leg = build_single_bob_leg_origination(
        "AB",
        alice_sk,
        bob_sk_at_origination_only,
        guard_pk,
        outpoints_display[0].0,
        outpoints_display[0].1,
        params.alice_ab_margin_sats,
        params.bob_ab_margin_sats,
        false, // Bob is Short on AB
        params.notional_usd,
        params.entry_ab_usd,
        params.unilateral_fee_sats,
        params.maturity_height,
        params.grace_blocks,
        params.refund_delay_blocks,
        alice_spk.clone(),
        bob_spk.clone(),
        anchor_spk.clone(),
        outcome_prices_and_points,
    )?;

    let bc_leg = build_single_bob_leg_origination(
        "BC",
        carol_sk,
        bob_sk_at_origination_only,
        guard_pk,
        outpoints_display[1].0,
        outpoints_display[1].1,
        params.carol_bc_margin_sats,
        params.bob_bc_margin_sats,
        true, // Bob is Long on BC
        params.notional_usd,
        params.entry_bc_usd,
        params.unilateral_fee_sats,
        params.maturity_height,
        params.grace_blocks,
        params.refund_delay_blocks,
        carol_spk.clone(),
        bob_spk.clone(),
        anchor_spk.clone(),
        outcome_prices_and_points,
    )?;

    let ca_tree = derive_utxoref_funding_output(carol_pk, alice_pk, params.ca_refund_csv)?;

    Ok(Mnr03OriginationBundle {
        params: params.clone(),
        ab_leg,
        bc_leg,
        ca_tree,
        ca_funding_txid_display: outpoints_display[2].0.to_owned(),
        ca_funding_vout: outpoints_display[2].1,
        ca_funding_sats: params.ca_funding_sats(),
        alice_spk,
        bob_spk,
        carol_spk,
        anchor_spk,
    })
}

/// Complete, verified output of the `SHZ-MNR-03` 3-party Bob-offline clearing assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mnr03ClearingReceipt {
    pub label: String,
    pub bob_online_during_clearing: bool,
    pub settled_price_usd: u64,
    pub atomic_clearing_txid_hex: String,
    pub atomic_clearing_wtxid_hex: String,
    pub atomic_clearing_vsize: usize,
    pub bob_ab_pinned_output_sats: u64,
    pub bob_bc_pinned_output_sats: u64,
    pub bob_total_freed_collateral_sats: u64,
    pub bob_posted_margin_sats: u64,
    pub bob_freed_collateral_bps: u64,
    pub alice_winner_routed_pnl_sats: u64,
    pub alice_winner_cleared_output_sats: u64,
    pub carol_freed_collateral_sats: u64,
    pub cpfp_anchor_sats: u64,
    pub miner_fee_sats: u64,
    pub pnl_snapshot_hash_hex: String,
    pub next_accounting_state_root_hex: String,
    pub durable_book_head_hash_hex: String,
}

/// Assembled `SHZ-MNR-03` transaction + unilateral fallbacks + durable `UTXORef` PnL book.
#[derive(Debug, Clone)]
pub struct Mnr03AssembledClearing {
    pub signed_clearing_tx: SegwitTx,
    pub ab_unilateral_fallback_tx: SegwitTx,
    pub bc_unilateral_fallback_tx: SegwitTx,
    pub durable_book: DurablePnlBatchBook,
    pub pnl_snapshot: PnlBatchSnapshotV1,
    pub receipt: Mnr03ClearingReceipt,
}

fn display_hex_to_txid_bytes(txid_display_hex: &str) -> Result<[u8; 32], UtxoRefError> {
    hex::decode(txid_display_hex)
        .map_err(|_| UtxoRefError::InvalidTransaction("invalid txid hex"))?
        .try_into()
        .map_err(|_| UtxoRefError::InvalidTransaction("txid must be 32 bytes"))
}

/// Step `t = 2` (**Bob 100% Offline — ZERO `bob_sk` parameter!**):
/// Completes Bob's `t = 0` `0x83` adaptor pre-signatures on `U_AB` (`vin[0] -> vout[0]`) and
/// `U_BC` (`vin[1] -> vout[1]`) using only `oracle_scalar_t`, co-signs `vin[0]` (`Alice + Guard` `0x01`),
/// `vin[1]` (`Carol + Guard` `0x01`), and `vin[2]` (`Alice + Carol` `0x00`), and verifies the
/// multilateral PnL routing through `solve_and_verify_pnl_batch` + `DurablePnlBatchBook`!
pub fn assemble_mnr03_bob_offline_three_party_clearing(
    orig: &Mnr03OriginationBundle,
    selected_outcome_idx: usize,
    oracle_scalar_t: &Scalar,
    alice_sk: &[u8; 32],
    carol_sk: &[u8; 32],
    guard_sk: &[u8; 32],
    network_label: &str,
) -> Result<Mnr03AssembledClearing, UtxoRefError> {
    let alice_pk =
        pubkey_x_from_secret(alice_sk).map_err(|_| UtxoRefError::InvalidCrypto("alice_sk"))?;
    let carol_pk =
        pubkey_x_from_secret(carol_sk).map_err(|_| UtxoRefError::InvalidCrypto("carol_sk"))?;
    let guard_pk =
        pubkey_x_from_secret(guard_sk).map_err(|_| UtxoRefError::InvalidCrypto("guard_sk"))?;

    if alice_pk != orig.ab_leg.tree.alice_pubkey_x
        || carol_pk != orig.bc_leg.tree.alice_pubkey_x
        || guard_pk != orig.ab_leg.tree.router_guard_pubkey_x
        || guard_pk != orig.bc_leg.tree.router_guard_pubkey_x
    {
        return Err(UtxoRefError::InvalidCrypto(
            "online signer keys do not match origination trees",
        ));
    }

    let ab_pre = orig
        .ab_leg
        .outcomes
        .get(selected_outcome_idx)
        .ok_or(UtxoRefError::AccountingViolation("selected_outcome_idx out of bounds"))?;
    let bc_pre = orig
        .bc_leg
        .outcomes
        .get(selected_outcome_idx)
        .ok_or(UtxoRefError::AccountingViolation("selected_outcome_idx out of bounds"))?;
    if ab_pre.price_usd != bc_pre.price_usd {
        return Err(UtxoRefError::AccountingViolation("AB/BC outcome price mismatch"));
    }
    let settled_price_usd = ab_pre.price_usd;

    // Economic PnL across all 3 inverse legs at `settled_price_usd`:
    let pnl_ab = inverse_long_pnl_trunc_sats(
        orig.params.notional_usd,
        orig.params.entry_ab_usd,
        settled_price_usd,
    ); // Alice Long vs Bob Short
    let pnl_bc = inverse_long_pnl_trunc_sats(
        orig.params.notional_usd,
        orig.params.entry_bc_usd,
        settled_price_usd,
    ); // Bob Long vs Carol Short
    let pnl_ca = inverse_long_pnl_trunc_sats(
        orig.params.notional_usd,
        orig.params.entry_ca_usd,
        settled_price_usd,
    ); // Carol Long vs Alice Short

    let alice_net_pnl = pnl_ab - pnl_ca;
    let bob_net_pnl = pnl_bc - pnl_ab;
    let carol_net_pnl = pnl_ca - pnl_bc;
    if alice_net_pnl + bob_net_pnl + carol_net_pnl != 0 {
        return Err(UtxoRefError::AccountingViolation(
            "3-party inverse PnL failed zero-sum conservation",
        ));
    }
    if alice_net_pnl <= 0 || bob_net_pnl >= 0 || carol_net_pnl >= 0 {
        return Err(UtxoRefError::AccountingViolation(
            "expected Alice net winner and Bob/Carol net payers at clearing mark",
        ));
    }
    let bob_to_alice_sats = (-bob_net_pnl) as u64;
    let carol_to_alice_sats = (-carol_net_pnl) as u64;
    let alice_routed_pnl_sats = alice_net_pnl as u64;

    let bob_ab_out = ab_pre.bob_pinned_sats;
    let bob_bc_out = bc_pre.bob_pinned_sats;
    let bob_total_freed = bob_ab_out + bob_bc_out;
    let bob_posted_total = orig.params.bob_ab_margin_sats + orig.params.bob_bc_margin_sats;
    if bob_total_freed + bob_to_alice_sats != bob_posted_total {
        return Err(UtxoRefError::AccountingViolation(
            "Bob's 0x83 pinned outputs do not equal posted margin minus net loss",
        ));
    }

    // Online participants (Alice & Carol) split the clearing tx miner fee + 330-sat CPFP anchor evenly
    // so Bob's origination-pinned `0x83` outputs are preserved 100% intact!
    let total_deduction = orig.params.atomic_clearing_miner_fee_sats + DEFAULT_CPFP_ANCHOR_SATS;
    let alice_deduction = total_deduction / 2;
    let carol_deduction = total_deduction - alice_deduction;

    let alice_posted_total = orig.params.alice_ab_margin_sats + orig.params.alice_ca_margin_sats;
    let carol_posted_total = orig.params.carol_bc_margin_sats + orig.params.carol_ca_margin_sats;

    let alice_cleared_out = (alice_posted_total + alice_routed_pnl_sats)
        .checked_sub(alice_deduction)
        .ok_or(UtxoRefError::AccountingViolation("Alice output underflow"))?;
    let carol_cleared_out = carol_posted_total
        .checked_sub(carol_to_alice_sats + carol_deduction)
        .ok_or(UtxoRefError::AccountingViolation("Carol output underflow"))?;

    if bob_ab_out < DEFAULT_CPFP_ANCHOR_SATS
        || bob_bc_out < DEFAULT_CPFP_ANCHOR_SATS
        || alice_cleared_out < DEFAULT_CPFP_ANCHOR_SATS
        || carol_cleared_out < DEFAULT_CPFP_ANCHOR_SATS
    {
        return Err(UtxoRefError::AccountingViolation(
            "cleared output below 330-sat P2TR dust threshold",
        ));
    }

    // Verify exact L1 satoshi conservation: `sum(inputs) - sum(outputs) == atomic_clearing_miner_fee_sats`
    let sum_inputs = orig.params.total_funding_sats();
    let sum_outputs =
        bob_ab_out + bob_bc_out + alice_cleared_out + carol_cleared_out + DEFAULT_CPFP_ANCHOR_SATS;
    if sum_inputs != sum_outputs + orig.params.atomic_clearing_miner_fee_sats {
        return Err(UtxoRefError::AccountingViolation(
            "3-input, 5-output clearing transaction failed exact satoshi conservation",
        ));
    }

    // Verify capacitated PnL routing via `UTXORef` Edmonds-Karp + `DurablePnlBatchBook`!
    let ab_txid = display_hex_to_txid_bytes(&orig.ab_leg.funding_txid_display)?;
    let bc_txid = display_hex_to_txid_bytes(&orig.bc_leg.funding_txid_display)?;
    let ca_txid = display_hex_to_txid_bytes(&orig.ca_funding_txid_display)?;

    let pnl_snapshot = PnlBatchSnapshotV1 {
        network: network_label.to_owned(),
        epoch_id: 1,
        previous_state_root: [0x33; 32],
        netting_sets: vec![NettingSetSpec {
            id: "mnr03-btc-inverse".into(),
            collateral: CollateralAsset::VanillaBtc,
        }],
        vaults: vec![
            VaultRecord {
                id: "vault-bob".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                change_script_pubkey: orig.bob_spk.clone(),
                fee_sats: 0,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: ab_txid,
                        vout: orig.ab_leg.funding_vout,
                    },
                    sats: bob_posted_total,
                    script_pubkey: orig.ab_leg.tree.script_pubkey.clone(),
                }],
            },
            VaultRecord {
                id: "vault-carol".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                change_script_pubkey: orig.carol_spk.clone(),
                fee_sats: carol_deduction,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: bc_txid,
                        vout: orig.bc_leg.funding_vout,
                    },
                    sats: carol_posted_total,
                    script_pubkey: orig.bc_leg.tree.script_pubkey.clone(),
                }],
            },
            VaultRecord {
                id: "vault-alice".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                change_script_pubkey: orig.alice_spk.clone(),
                fee_sats: alice_deduction,
                protected_sats: 0,
                utxos: vec![FundedVaultUtxo {
                    outpoint: BtcOutPoint {
                        txid: ca_txid,
                        vout: orig.ca_funding_vout,
                    },
                    sats: alice_posted_total,
                    script_pubkey: orig.ca_tree.script_pubkey.clone(),
                }],
            },
        ],
        accounts: vec![
            AccountRecord {
                id: "bob".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                vault_id: "vault-bob".into(),
                equity_sats: bob_posted_total,
                locked_sats: 0,
                payout_sats: 0,
                payout_script_pubkey: None,
            },
            AccountRecord {
                id: "carol".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                vault_id: "vault-carol".into(),
                equity_sats: carol_posted_total - carol_deduction,
                locked_sats: 0,
                payout_sats: 0,
                payout_script_pubkey: None,
            },
            AccountRecord {
                id: "alice".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                vault_id: "vault-alice".into(),
                equity_sats: alice_posted_total - alice_deduction,
                locked_sats: 0,
                payout_sats: alice_routed_pnl_sats,
                payout_script_pubkey: Some(orig.alice_spk.clone()),
            },
        ],
        obligations: vec![
            RealizedObligation {
                id: "mnr03-bob-to-alice".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                from_account_id: "bob".into(),
                to_account_id: "alice".into(),
                sats: bob_to_alice_sats,
            },
            RealizedObligation {
                id: "mnr03-carol-to-alice".into(),
                netting_set_id: "mnr03-btc-inverse".into(),
                from_account_id: "carol".into(),
                to_account_id: "alice".into(),
                sats: carol_to_alice_sats,
            },
        ],
        consumed_obligation_ids: vec![],
        spent_outpoints: vec![],
        routes: vec![
            PermittedRoute {
                from_vault_id: "vault-bob".into(),
                to_target: RouteTarget::Payout("alice".into()),
                capacity_sats: bob_to_alice_sats,
            },
            PermittedRoute {
                from_vault_id: "vault-carol".into(),
                to_target: RouteTarget::Payout("alice".into()),
                capacity_sats: carol_to_alice_sats,
            },
        ],
    };

    let snap_hash = pnl_snapshot.snapshot_hash();
    let verified_batch = solve_and_verify_pnl_batch(&pnl_snapshot, &snap_hash)?;
    assert_eq!(verified_batch.vault_residuals_sats["vault-bob"], bob_total_freed);
    assert_eq!(verified_batch.vault_residuals_sats["vault-carol"], carol_cleared_out);
    assert_eq!(verified_batch.direct_payouts_sats["alice"], alice_routed_pnl_sats);

    // Construct the 3-input, 5-output atomic Taproot clearing transaction (`locktime = maturity_height`)
    let in_ab = SegwitTxIn::from_display_txid(
        &orig.ab_leg.funding_txid_display,
        orig.ab_leg.funding_vout,
        0xfffffffe,
        orig.ab_leg.funding_sats,
        orig.ab_leg.tree.script_pubkey.clone(),
    )?;
    let in_bc = SegwitTxIn::from_display_txid(
        &orig.bc_leg.funding_txid_display,
        orig.bc_leg.funding_vout,
        0xfffffffe,
        orig.bc_leg.funding_sats,
        orig.bc_leg.tree.script_pubkey.clone(),
    )?;
    let in_ca = SegwitTxIn::from_display_txid(
        &orig.ca_funding_txid_display,
        orig.ca_funding_vout,
        0xfffffffe,
        orig.ca_funding_sats,
        orig.ca_tree.script_pubkey.clone(),
    )?;

    let mut clearing_tx = SegwitTx {
        version: 2,
        inputs: vec![in_ab, in_bc, in_ca],
        outputs: vec![
            (bob_ab_out, orig.bob_spk.clone()),                      // vout[0]: pinned by Bob's AB 0x83 sig!
            (bob_bc_out, orig.bob_spk.clone()),                      // vout[1]: pinned by Bob's BC 0x83 sig!
            (alice_cleared_out, orig.alice_spk.clone()),             // vout[2]: Winner Alice principal + routed PnL
            (carol_cleared_out, orig.carol_spk.clone()),             // vout[3]: Carol freed collateral
            (DEFAULT_CPFP_ANCHOR_SATS, orig.anchor_spk.clone()),     // vout[4]: 330-sat CPFP anchor
        ],
        locktime: orig.params.maturity_height,
    };

    // 1. Complete & verify Bob's `0x83` adaptor sig on `vin[0]` (`AB -> vout[0]`) + sign `Alice + Guard` `0x01`!
    let bob_ab_completed = adaptor_complete(&ab_pre.bob_route_0x83_adaptor_sig, oracle_scalar_t)
        .map_err(|_| UtxoRefError::InvalidCrypto("complete Bob AB 0x83"))?;
    let ab_sh_0x83 = clearing_tx.bip341_sighash(
        0,
        SIGHASH_SINGLE_ANYONECANPAY,
        Some(&orig.ab_leg.tree.route_leaf_hash),
    )?;
    bip340_verify(&orig.ab_leg.tree.bob_pubkey_x, &ab_sh_0x83, &bob_ab_completed)
        .map_err(|_| UtxoRefError::InvalidCrypto("Bob AB 0x83 failed on 3-input clearing tx"))?;

    let ab_sh_0x01 =
        clearing_tx.bip341_sighash(0, SIGHASH_ALL, Some(&orig.ab_leg.tree.route_leaf_hash))?;
    let alice_ab_sig = bip340_sign(alice_sk, &ab_sh_0x01)
        .map_err(|_| UtxoRefError::InvalidCrypto("alice AB 0x01"))?;
    let guard_ab_sig = bip340_sign(guard_sk, &ab_sh_0x01)
        .map_err(|_| UtxoRefError::InvalidCrypto("guard AB 0x01"))?;

    clearing_tx.inputs[0].witness = vec![
        encode_taproot_witness_sig(&bob_ab_completed, SIGHASH_SINGLE_ANYONECANPAY),
        encode_taproot_witness_sig(&guard_ab_sig, SIGHASH_ALL),
        encode_taproot_witness_sig(&alice_ab_sig, SIGHASH_ALL),
        orig.ab_leg.tree.route_cet_script.clone(),
        orig.ab_leg.tree.route_control_block.clone(),
    ];

    // 2. Complete & verify Bob's `0x83` adaptor sig on `vin[1]` (`BC -> vout[1]`) + sign `Carol + Guard` `0x01`!
    let bob_bc_completed = adaptor_complete(&bc_pre.bob_route_0x83_adaptor_sig, oracle_scalar_t)
        .map_err(|_| UtxoRefError::InvalidCrypto("complete Bob BC 0x83"))?;
    let bc_sh_0x83 = clearing_tx.bip341_sighash(
        1,
        SIGHASH_SINGLE_ANYONECANPAY,
        Some(&orig.bc_leg.tree.route_leaf_hash),
    )?;
    bip340_verify(&orig.bc_leg.tree.bob_pubkey_x, &bc_sh_0x83, &bob_bc_completed)
        .map_err(|_| UtxoRefError::InvalidCrypto("Bob BC 0x83 failed on 3-input clearing tx"))?;

    let bc_sh_0x01 =
        clearing_tx.bip341_sighash(1, SIGHASH_ALL, Some(&orig.bc_leg.tree.route_leaf_hash))?;
    let carol_bc_sig = bip340_sign(carol_sk, &bc_sh_0x01)
        .map_err(|_| UtxoRefError::InvalidCrypto("carol BC 0x01"))?;
    let guard_bc_sig = bip340_sign(guard_sk, &bc_sh_0x01)
        .map_err(|_| UtxoRefError::InvalidCrypto("guard BC 0x01"))?;

    clearing_tx.inputs[1].witness = vec![
        encode_taproot_witness_sig(&bob_bc_completed, SIGHASH_SINGLE_ANYONECANPAY),
        encode_taproot_witness_sig(&guard_bc_sig, SIGHASH_ALL),
        encode_taproot_witness_sig(&carol_bc_sig, SIGHASH_ALL),
        orig.bc_leg.tree.route_cet_script.clone(),
        orig.bc_leg.tree.route_control_block.clone(),
    ];

    // 3. Sign interactive bilateral `vin[2]` (`CA`) with `Alice + Carol` `SIGHASH_DEFAULT (0x00)`!
    let ca_sh_0x00 =
        clearing_tx.bip341_sighash(2, SIGHASH_DEFAULT, Some(&orig.ca_tree.cet_leaf_hash))?;
    let alice_ca_sig = bip340_sign(alice_sk, &ca_sh_0x00)
        .map_err(|_| UtxoRefError::InvalidCrypto("alice CA 0x00"))?;
    let carol_ca_sig = bip340_sign(carol_sk, &ca_sh_0x00)
        .map_err(|_| UtxoRefError::InvalidCrypto("carol CA 0x00"))?;
    let (sig_pk0, sig_pk1) = if orig.ca_tree.party_pubkeys_sorted[0] == alice_pk {
        (alice_ca_sig, carol_ca_sig)
    } else {
        (carol_ca_sig, alice_ca_sig)
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
    let ca_tweak = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tagged_hash(
        b"TapTweak",
        &ca_tweak_in,
    )));
    let ca_internal_pt = lift_x_even(&orig.ca_tree.internal_xonly)
        .map_err(|_| UtxoRefError::InvalidCrypto("CA NUMS lift_x"))?;
    let (_, ca_out_y) = point_coordinates(ca_internal_pt + ProjectivePoint::GENERATOR * ca_tweak)?;
    let ca_parity = ca_out_y[31] & 1;
    let mut ca_cet_control_block = Vec::with_capacity(65);
    ca_cet_control_block.push(LEAF_VERSION_TAPSCRIPT | ca_parity);
    ca_cet_control_block.extend_from_slice(&orig.ca_tree.internal_xonly);
    ca_cet_control_block.extend_from_slice(&orig.ca_tree.refund_leaf_hash);

    clearing_tx.inputs[2].witness = vec![
        encode_taproot_witness_sig(&sig_pk1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&sig_pk0, SIGHASH_DEFAULT),
        ca_cet_script,
        ca_cet_control_block,
    ];

    // 4. Also materialize the grace-delayed unilateral fallback CETs (`locktime = maturity + grace`)
    //    proving unilateral recovery remains 100% intact if Guard/Carol/Alice disappears!
    let ab_uni = materialize_leg_unilateral(&orig.ab_leg.tree, ab_pre, oracle_scalar_t)?;
    let bc_uni = materialize_leg_unilateral(&orig.bc_leg.tree, bc_pre, oracle_scalar_t)?;

    // 5. Advance `DurablePnlBatchBook` up to `BookAuthState::Signed` (caller calls `confirm_active_chain`
    //    ONLY after L1 confirmation, or `freeze_on_reorg` if a chain reorg is detected!).
    let mut book = DurablePnlBatchBook::new_genesis("shz-mnr03-book", [0x33; 32]);
    let init_head = book.head_hash;
    let res_head = book.reserve_before_signing(&init_head, &pnl_snapshot)?;
    let sig_head = book.record_signed_outcome(
        &res_head,
        Ok((clearing_tx.txid_hex(), clearing_tx.serialize_segwit())),
    )?;
    assert!(matches!(book.state, BookAuthState::Signed { .. }));

    let receipt = Mnr03ClearingReceipt {
        label: orig.params.label.clone(),
        bob_online_during_clearing: false,
        settled_price_usd,
        atomic_clearing_txid_hex: clearing_tx.txid_hex(),
        atomic_clearing_wtxid_hex: clearing_tx.wtxid_hex(),
        atomic_clearing_vsize: clearing_tx.vsize(),
        bob_ab_pinned_output_sats: bob_ab_out,
        bob_bc_pinned_output_sats: bob_bc_out,
        bob_total_freed_collateral_sats: bob_total_freed,
        bob_posted_margin_sats: bob_posted_total,
        bob_freed_collateral_bps: (bob_total_freed * 10_000) / bob_posted_total,
        alice_winner_routed_pnl_sats: alice_routed_pnl_sats,
        alice_winner_cleared_output_sats: alice_cleared_out,
        carol_freed_collateral_sats: carol_cleared_out,
        cpfp_anchor_sats: DEFAULT_CPFP_ANCHOR_SATS,
        miner_fee_sats: orig.params.atomic_clearing_miner_fee_sats,
        pnl_snapshot_hash_hex: hex::encode(snap_hash),
        next_accounting_state_root_hex: hex::encode(verified_batch.next_accounting_state_root),
        durable_book_head_hash_hex: hex::encode(sig_head),
    };

    Ok(Mnr03AssembledClearing {
        signed_clearing_tx: clearing_tx,
        ab_unilateral_fallback_tx: ab_uni,
        bc_unilateral_fallback_tx: bc_uni,
        durable_book: book,
        pnl_snapshot,
        receipt,
    })
}

fn materialize_leg_unilateral(
    tree: &Mnr02TaprootTree,
    pre: &Mnr03LegPreSignedOutcome,
    oracle_scalar_t: &Scalar,
) -> Result<SegwitTx, UtxoRefError> {
    let cp_sig = adaptor_complete(&pre.counterparty_unilateral_adaptor_sig, oracle_scalar_t)
        .map_err(|_| UtxoRefError::InvalidCrypto("cp uni complete"))?;
    let bob_sig = adaptor_complete(&pre.bob_unilateral_adaptor_sig, oracle_scalar_t)
        .map_err(|_| UtxoRefError::InvalidCrypto("bob uni complete"))?;

    let sh = pre.unilateral_tx.bip341_sighash(
        0,
        SIGHASH_DEFAULT,
        Some(&tree.unilateral_leaf_hash),
    )?;
    bip340_verify(&tree.alice_pubkey_x, &sh, &cp_sig)
        .map_err(|_| UtxoRefError::InvalidCrypto("cp uni verify"))?;
    bip340_verify(&tree.bob_pubkey_x, &sh, &bob_sig)
        .map_err(|_| UtxoRefError::InvalidCrypto("bob uni verify"))?;

    let (sig_pk0, sig_pk1) = if tree.sorted_ab[0] == tree.alice_pubkey_x {
        (cp_sig, bob_sig)
    } else {
        (bob_sig, cp_sig)
    };
    let mut tx = pre.unilateral_tx.clone();
    tx.inputs[0].witness = vec![
        encode_taproot_witness_sig(&sig_pk1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&sig_pk0, SIGHASH_DEFAULT),
        tree.unilateral_cet_script.clone(),
        tree.unilateral_control_block.clone(),
    ];
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::{bigint::U256, ops::Reduce};

    fn p2tr_spk(seed: u8) -> Vec<u8> {
        let pk = pubkey_x_from_secret(&[seed; 32]).unwrap();
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&pk);
        s
    }

    #[test]
    fn test_mnr03_bob_offline_macro_and_micro_3party_atomic_clearing_and_reorg_freeze() {
        let alice_sk = [0x11u8; 32];
        let carol_sk = [0x23u8; 32];
        let guard_sk = [0x24u8; 32];
        let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();

        let t_50k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(50_000));
        let t_60k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(60_000));
        let t_125k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(125_000));

        // 1. Macro $33,000 fixture ($50k -> $55k -> $60k): `bob_sk` scoped strictly inside origination block!
        let macro_params = Mnr03ScaleParams::macro_regtest_33k(150);
        let macro_orig = {
            let bob_sk_ephemeral = [0x22u8; 32];
            build_mnr03_bob_offline_origination(
                &macro_params,
                &alice_sk,
                &bob_sk_ephemeral,
                &carol_sk,
                guard_pk,
                [(&"01".repeat(32), 0), (&"02".repeat(32), 0), (&"03".repeat(32), 0)],
                p2tr_spk(0x41),
                p2tr_spk(0x42),
                p2tr_spk(0x43),
                p2tr_spk(0x44),
                &[
                    (50_000, ProjectivePoint::GENERATOR * t_50k),
                    (60_000, ProjectivePoint::GENERATOR * t_60k),
                ],
            )
            .unwrap()
            // `bob_sk_ephemeral` is dropped here!
        };

        let mut cleared = assemble_mnr03_bob_offline_three_party_clearing(
            &macro_orig,
            1, // $60,000 mark
            &t_60k,
            &alice_sk,
            &carol_sk,
            &guard_sk,
            "bitcoin-regtest",
        )
        .unwrap();

        assert!(!cleared.receipt.bob_online_during_clearing);
        assert_eq!(cleared.receipt.bob_ab_pinned_output_sats, 55_000_000); // 66M - 11M
        assert_eq!(cleared.receipt.bob_bc_pinned_output_sats, 35_000_000); // 30M + 5M
        assert_eq!(cleared.receipt.bob_total_freed_collateral_sats, 90_000_000); // 93.75% of 96M freed!
        assert_eq!(cleared.receipt.bob_freed_collateral_bps, 9_375);
        assert_eq!(cleared.receipt.alice_winner_routed_pnl_sats, 11_000_000);
        assert_eq!(cleared.receipt.alice_winner_cleared_output_sats, 71_498_500);
        assert_eq!(cleared.receipt.carol_freed_collateral_sats, 82_498_500);

        // Simulate a watchtower reorg detection BEFORE settling `DurablePnlBatchBook`:
        cleared
            .durable_book
            .freeze_on_reorg("reorg-invalidated-block-151");
        let frozen_head = cleared.durable_book.head_hash;
        assert_eq!(
            cleared
                .durable_book
                .confirm_active_chain(
                    &frozen_head,
                    &cleared.receipt.atomic_clearing_txid_hex,
                    &cleared.pnl_snapshot,
                )
                .unwrap_err(),
            UtxoRefError::InvalidBookTransition
        );

        // 2. Micro $1 Testnet4 live fixture ($80k -> $100k -> $125k, 3,900 sats total funded)
        let micro_params = Mnr03ScaleParams::micro_testnet4_live(163_000);
        assert_eq!(micro_params.total_funding_sats(), 3_900);
        let micro_orig = {
            let bob_sk_ephemeral = [0x22u8; 32];
            build_mnr03_bob_offline_origination(
                &micro_params,
                &alice_sk,
                &bob_sk_ephemeral,
                &carol_sk,
                guard_pk,
                [(&"11".repeat(32), 0), (&"12".repeat(32), 1), (&"13".repeat(32), 2)],
                p2tr_spk(0x41),
                p2tr_spk(0x42),
                p2tr_spk(0x43),
                p2tr_spk(0x44),
                &[(125_000, ProjectivePoint::GENERATOR * t_125k)],
            )
            .unwrap()
        };
        let mut micro_cleared = assemble_mnr03_bob_offline_three_party_clearing(
            &micro_orig,
            0,
            &t_125k,
            &alice_sk,
            &carol_sk,
            &guard_sk,
            "bitcoin-testnet4",
        )
        .unwrap();
        assert_eq!(micro_cleared.receipt.bob_ab_pinned_output_sats, 450);
        assert_eq!(micro_cleared.receipt.bob_bc_pinned_output_sats, 550);
        assert_eq!(micro_cleared.receipt.bob_total_freed_collateral_sats, 1_000);
        assert_eq!(micro_cleared.receipt.alice_winner_cleared_output_sats, 1_050);
        assert_eq!(micro_cleared.receipt.carol_freed_collateral_sats, 910);
        assert_eq!(micro_cleared.receipt.miner_fee_sats, 610);
        assert!(micro_cleared.receipt.atomic_clearing_vsize <= 605);

        // Confirm settled cleanly when no reorg occurs
        let cur_head = micro_cleared.durable_book.head_hash;
        micro_cleared
            .durable_book
            .confirm_active_chain(
                &cur_head,
                &micro_cleared.receipt.atomic_clearing_txid_hex,
                &micro_cleared.pnl_snapshot,
            )
            .unwrap();
        assert_eq!(micro_cleared.durable_book.last_settled_epoch, 1);
    }
}
