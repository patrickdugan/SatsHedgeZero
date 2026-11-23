//! Taproot DLC Position Transferability (Novation + `0x83` Offline Claim Assignment) and
//! Unified Cross-Margin / Multilateral Clearing Engine (`transfer_and_clearing.rs`).
//!
//! Directly extends `SHZ-MNR-03` and GPT's `SHZ-MNR-04` (`docs/SHZ_MNR04_BITCOIN_EXACT_NOVA.md`
//! lines 19 & 66–68) by incorporating:
//! 1. **Enforceable Taproot Position Transferability (2 Modes)**:
//!    - **Mode 1 (`execute_atomic_taproot_novation`, Interactive L1 Novation `U_AB -> U_DB`):**
//!      Pre-signs the successor 4-leaf `TaprootDerivativeTree` (`Dave <-> Bob`) FIRST, then
//!      spends `U_AB` (`Leaf 0` 2-of-2 `0x00`) + `U_Dave_Funding` (`0x00`) in one atomic Taproot
//!      transaction funding `U_DB` and paying `Alice` her immediate liquid BTC exit! Consumes
//!      `U_AB`'s nullifier so stale/revoked pre-novation packages can never be replayed.
//!    - **Mode 2 (`authorize_offline_bob_claim_transfer`, Counterparty-Offline `0x83` Assignment):**
//!      When `Bob` is offline (`bob_sk` absent), `Alice + ClearingGuard` sign a nullifier-bound
//!      `Leaf 1` (`0x01`) assignment redirecting `Alice`'s maturity slice to `Dave`'s `P2TR` while
//!      preserving `Bob`'s origination-pinned `0x83` `vout[0]`, blocking double-assignment!
//! 2. **Portfolio Cross-Margin Stress Grid (`evaluate_swap_option_portfolio_margin`)**:
//!    - Evaluates mixed **Inverse Swap + European Call/Put Option** portfolios across an explicit
//!      price stress grid `G` (matching `SHZ-TL-USD-01`'s scenario-solvency model), quantifying exact
//!      cross-margin relief when protective Options cap Swap tail risk.
//! 3. **Nullifier-Gated Unified Swap + Option Atomic Clearing (`UnifiedMarginClearingEngine`)**:
//!    - Enforces prior accounting root continuity, active-contract membership, and transfer/spend
//!      nullifier non-reuse before solving `UTXORef` Edmonds-Karp max-flow routing and assembling
//!      a single multi-input BIP-341 Taproot clearing transaction (`Bob` 100% offline via `0x83`
//!      across BOTH his Swap and his Option!).

use std::collections::BTreeSet;

use k256::{ProjectivePoint, Scalar, elliptic_curve::group::Group};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dlc::{
    AdaptorSignature, BtcOutPoint, adaptor_complete, adaptor_sign, adaptor_verify, bip340_sign,
    bip340_verify, pubkey_x_from_secret, tagged_hash,
    taproot_derivatives::{MIN_P2TR_DUST_SATS, TaprootDerivativeTree},
};
use shz_margin::{CollateralAsset, DerivativeContractSpec};

use crate::{
    UtxoRefError,
    mnr02::{
        SIGHASH_ALL, SIGHASH_DEFAULT, SIGHASH_SINGLE_ANYONECANPAY, SegwitTx, SegwitTxIn,
        encode_taproot_witness_sig,
    },
    pnl_batch::{
        AccountRecord, FundedVaultUtxo, NettingSetSpec, PermittedRoute, PnlBatchSnapshotV1,
        RealizedObligation, RouteTarget, VaultRecord, solve_and_verify_pnl_batch,
    },
    signing_target::DEFAULT_CPFP_ANCHOR_SATS,
};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn display_txid_to_bytes(txid_hex: &str) -> Result<[u8; 32], UtxoRefError> {
    hex::decode(txid_hex)
        .map_err(|_| UtxoRefError::InvalidTransaction("invalid txid hex"))?
        .try_into()
        .map_err(|_| UtxoRefError::InvalidTransaction("txid must be 32 bytes"))
}

/// Computes canonical outpoint/contract nullifier preventing replay of novated or settled legs.
pub fn contract_outpoint_nullifier(txid_display_hex: &str, vout: u32) -> Result<[u8; 32], UtxoRefError> {
    let txid = display_txid_to_bytes(txid_display_hex)?;
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&txid);
    buf[32..].copy_from_slice(&vout.to_le_bytes());
    Ok(tagged_hash(b"SHZ/TRANSFER-CLEARING-NULLIFIER/V1", &buf))
}

/// Pre-signed outcome entry on a 4-leaf `TaprootDerivativeTree` where `bob_pubkey_x` sits in the
/// `0x83` (`counterparty_pubkey_x`) slot of `Leaf 1` (`routed_clearing_leaf`).
#[derive(Debug, Clone)]
pub struct TransferableLegOutcome {
    pub price_usd: u64,
    pub bob_0x83_pinned_sats: u64,
    pub holder_unilateral_sats: u64,
    pub bob_0x83_adaptor_sig: AdaptorSignature,
    pub unilateral_tx: SegwitTx,
    pub holder_unilateral_adaptor_sig: AdaptorSignature,
    pub bob_unilateral_adaptor_sig: AdaptorSignature,
}

/// Funded, pre-signed 4-leaf Taproot Option or Swap leg (`zero secret keys` stored).
#[derive(Debug, Clone)]
pub struct FundedTaprootDerivativeLeg {
    pub leg_id: String,
    pub contract: DerivativeContractSpec,
    /// `true` if `Bob` (`counterparty_pubkey_x` in `tree`) holds the Long/OptionBuyer economic side
    /// (e.g. `Bob` bought a Call Option from `Carol`, while still using `0x83` so `Bob` can stay offline!).
    pub bob_holds_long_payoff: bool,
    pub tree: TaprootDerivativeTree,
    pub funding_txid_display: String,
    pub funding_vout: u32,
    pub funding_sats: u64,
    pub unilateral_fee_sats: u64,
    pub holder_spk: Vec<u8>,
    pub bob_spk: Vec<u8>,
    pub anchor_spk: Vec<u8>,
    pub signed_refund_tx: SegwitTx,
    pub outcomes: Vec<TransferableLegOutcome>,
}

/// Step `t = 0`: Pre-signs a 4-leaf Taproot Option or Swap leg (`Leaf 1` `0x83` Bob template +
/// `Leaf 2` `OP_CLTV` unilateral CET + `Leaf 3` `OP_CLTV` refund) before `bob_sk` goes offline.
#[allow(clippy::too_many_arguments)]
pub fn build_funded_taproot_derivative_leg(
    leg_id: &str,
    contract: DerivativeContractSpec,
    bob_holds_long_payoff: bool,
    holder_sk: &[u8; 32],
    bob_sk_at_origination_only: &[u8; 32],
    clearing_guard_pk: [u8; 32],
    funding_txid_display: &str,
    funding_vout: u32,
    unilateral_fee_sats: u64,
    maturity_height: u32,
    grace_blocks: u32,
    refund_delay_blocks: u32,
    holder_spk: Vec<u8>,
    bob_spk: Vec<u8>,
    anchor_spk: Vec<u8>,
    outcome_prices_and_points: &[(u64, ProjectivePoint)],
) -> Result<FundedTaprootDerivativeLeg, UtxoRefError> {
    contract
        .validate_v0()
        .map_err(|_| UtxoRefError::AccountingViolation("invalid derivative contract"))?;
    let holder_pk =
        pubkey_x_from_secret(holder_sk).map_err(|_| UtxoRefError::InvalidCrypto("holder_sk"))?;
    let bob_pk = pubkey_x_from_secret(bob_sk_at_origination_only)
        .map_err(|_| UtxoRefError::InvalidCrypto("bob_sk"))?;

    let tree = TaprootDerivativeTree::build(
        holder_pk,
        bob_pk,
        clearing_guard_pk,
        maturity_height,
        grace_blocks,
        refund_delay_blocks,
    )
    .map_err(|_| UtxoRefError::InvalidFunding("4-leaf TaprootDerivativeTree build failed"))?;

    let funding_sats = contract.total_collateral_sats();
    let uni_dist = funding_sats
        .checked_sub(unilateral_fee_sats + DEFAULT_CPFP_ANCHOR_SATS)
        .ok_or(UtxoRefError::AccountingViolation(
            "collateral < unilateral fee + anchor",
        ))?;

    let base_in = SegwitTxIn::from_display_txid(
        funding_txid_display,
        funding_vout,
        0xfffffffe,
        funding_sats,
        tree.script_pubkey.clone(),
    )?;

    // 1. Pre-sign Leaf 3 Refund TX (`locktime = refund_cltv_height`)
    let init_bob = if bob_holds_long_payoff {
        contract.holder_contribution_sats()
    } else {
        contract.counterparty_contribution_sats()
    };
    let refund_bob = init_bob
        .saturating_sub(unilateral_fee_sats / 2 + DEFAULT_CPFP_ANCHOR_SATS / 2)
        .clamp(MIN_P2TR_DUST_SATS, uni_dist - MIN_P2TR_DUST_SATS);
    let refund_holder = uni_dist - refund_bob;

    let mut signed_refund_tx = SegwitTx {
        version: 2,
        inputs: vec![base_in.clone()],
        outputs: vec![
            (refund_bob, bob_spk.clone()),
            (refund_holder, holder_spk.clone()),
            (DEFAULT_CPFP_ANCHOR_SATS, anchor_spk.clone()),
        ],
        locktime: tree.refund_cltv_height,
    };
    let ref_sh =
        signed_refund_tx.bip341_sighash(0, SIGHASH_DEFAULT, Some(&tree.refund_leaf_hash))?;
    let h_ref_sig =
        bip340_sign(holder_sk, &ref_sh).map_err(|_| UtxoRefError::InvalidCrypto("refund sign"))?;
    let b_ref_sig = bip340_sign(bob_sk_at_origination_only, &ref_sh)
        .map_err(|_| UtxoRefError::InvalidCrypto("refund sign"))?;
    let (sig0, sig1) = if tree.sorted_pair[0] == holder_pk {
        (h_ref_sig, b_ref_sig)
    } else {
        (b_ref_sig, h_ref_sig)
    };
    signed_refund_tx.inputs[0].witness = vec![
        encode_taproot_witness_sig(&sig1, SIGHASH_DEFAULT),
        encode_taproot_witness_sig(&sig0, SIGHASH_DEFAULT),
        tree.refund_script.clone(),
        tree.refund_control_block.clone(),
    ];

    // 2. Pre-sign Leaf 1 `0x83` Bob adaptor sig + Leaf 2 `0x00` unilateral fallback CET!
    let mut outcomes = Vec::with_capacity(outcome_prices_and_points.len());
    for &(price_usd, ref adaptor_pt) in outcome_prices_and_points {
        if bool::from(adaptor_pt.is_identity()) {
            return Err(UtxoRefError::InvalidCrypto("identity adaptor point"));
        }
        let split = contract.payout_at_price(price_usd);
        let raw_bob_economic = if bob_holds_long_payoff {
            split.long_sats
        } else {
            split.short_sats
        };
        let bob_0x83_pinned_sats =
            raw_bob_economic.clamp(MIN_P2TR_DUST_SATS, uni_dist - MIN_P2TR_DUST_SATS);
        let holder_unilateral_sats = uni_dist - bob_0x83_pinned_sats;

        let tpl_0x83 = SegwitTx {
            version: 2,
            inputs: vec![base_in.clone()],
            outputs: vec![(bob_0x83_pinned_sats, bob_spk.clone())],
            locktime: tree.maturity_height,
        };
        let sh_0x83 = tpl_0x83.bip341_sighash(
            0,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&tree.routed_clearing_leaf_hash),
        )?;
        let bob_0x83_adaptor_sig =
            adaptor_sign(bob_sk_at_origination_only, &sh_0x83, adaptor_pt)
                .map_err(|_| UtxoRefError::InvalidCrypto("bob 0x83 adaptor_sign"))?;
        adaptor_verify(&bob_pk, &sh_0x83, adaptor_pt, &bob_0x83_adaptor_sig)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob 0x83 adaptor_verify"))?;

        let unilateral_tx = SegwitTx {
            version: 2,
            inputs: vec![base_in.clone()],
            outputs: vec![
                (bob_0x83_pinned_sats, bob_spk.clone()),
                (holder_unilateral_sats, holder_spk.clone()),
                (DEFAULT_CPFP_ANCHOR_SATS, anchor_spk.clone()),
            ],
            locktime: tree.unilateral_cltv_height,
        };
        let sh_uni = unilateral_tx.bip341_sighash(
            0,
            SIGHASH_DEFAULT,
            Some(&tree.unilateral_cet_leaf_hash),
        )?;
        let h_uni = adaptor_sign(holder_sk, &sh_uni, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("holder uni sign"))?;
        let b_uni = adaptor_sign(bob_sk_at_origination_only, &sh_uni, adaptor_pt)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob uni sign"))?;

        outcomes.push(TransferableLegOutcome {
            price_usd,
            bob_0x83_pinned_sats,
            holder_unilateral_sats,
            bob_0x83_adaptor_sig,
            unilateral_tx,
            holder_unilateral_adaptor_sig: h_uni,
            bob_unilateral_adaptor_sig: b_uni,
        });
    }

    Ok(FundedTaprootDerivativeLeg {
        leg_id: leg_id.to_owned(),
        contract,
        bob_holds_long_payoff,
        tree,
        funding_txid_display: funding_txid_display.to_owned(),
        funding_vout,
        funding_sats,
        unilateral_fee_sats,
        holder_spk,
        bob_spk,
        anchor_spk,
        signed_refund_tx,
        outcomes,
    })
}

/// Receipt & artifacts of **Mode 1: Interactive Atomic L1 Taproot Position Novation (`U_AB -> U_DB`)**.
#[derive(Debug, Clone)]
pub struct AtomicTaprootNovationResult {
    pub signed_novation_tx: SegwitTx,
    pub novation_txid_hex: String,
    pub consumed_old_nullifier: [u8; 32],
    pub alice_immediate_exit_sats: u64,
    pub dave_change_sats: u64,
    pub successor_leg: FundedTaprootDerivativeLeg,
}

///Receipt of **Mode 2: Counterparty-Offline (`0x83`) Transferable Claim Assignment (`Alice -> Dave`)**.
#[derive(Debug, Clone)]
pub struct OfflineClaimTransferResult {
    pub consumed_assignment_nullifier: [u8; 32],
    pub transferee_spk: Vec<u8>,
    pub finalized_maturity_tx_for_outcome: SegwitTx,
}

/// Portfolio Cross-Margin Stress Grid summary across mixed Inverse Swaps & European Options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortfolioMarginStressReport {
    pub party_id: String,
    pub evaluated_prices_usd: Vec<u64>,
    pub sum_standalone_margins_sats: u64,
    pub worst_case_portfolio_loss_sats: u64,
    pub required_portfolio_margin_sats: u64,
    pub cross_margin_relief_sats: u64,
    pub cross_margin_relief_bps: u64,
    pub scenario_solvent_across_grid: bool,
}

/// Evaluates worst-case portfolio PnL across a discrete price grid `stress_prices_usd` for a
/// participant holding a mix of Inverse Swaps and European Options (`(contract, holds_long_side)`).
pub fn evaluate_swap_option_portfolio_margin(
    party_id: &str,
    positions: &[(DerivativeContractSpec, bool)],
    stress_prices_usd: &[u64],
    risk_buffer_sats: u64,
) -> Result<PortfolioMarginStressReport, UtxoRefError> {
    if positions.is_empty() || stress_prices_usd.is_empty() {
        return Err(UtxoRefError::AccountingViolation(
            "portfolio positions and stress_prices_usd must be non-empty",
        ));
    }
    let mut sum_standalone = 0u64;
    for (spec, is_long) in positions {
        sum_standalone += if *is_long {
            spec.holder_contribution_sats()
        } else {
            spec.counterparty_contribution_sats()
        };
    }

    let mut worst_loss_sats = 0u64;
    for &p in stress_prices_usd {
        if p == 0 {
            continue;
        }
        let mut net_pnl: i128 = 0;
        for (spec, is_long) in positions {
            let holder_pnl = spec.holder_realized_pnl_sats(p);
            net_pnl += if *is_long { holder_pnl } else { -holder_pnl };
        }
        if net_pnl < 0 {
            worst_loss_sats = worst_loss_sats.max((-net_pnl) as u64);
        }
    }

    let required_raw = worst_loss_sats.saturating_add(risk_buffer_sats);
    let required_portfolio_margin_sats = required_raw.min(sum_standalone);
    let relief = sum_standalone.saturating_sub(required_portfolio_margin_sats);
    let relief_bps = (relief * 10_000).checked_div(sum_standalone).unwrap_or(0);

    Ok(PortfolioMarginStressReport {
        party_id: party_id.to_owned(),
        evaluated_prices_usd: stress_prices_usd.to_vec(),
        sum_standalone_margins_sats: sum_standalone,
        worst_case_portfolio_loss_sats: worst_loss_sats,
        required_portfolio_margin_sats,
        cross_margin_relief_sats: relief,
        cross_margin_relief_bps: relief_bps,
        scenario_solvent_across_grid: sum_standalone >= worst_loss_sats,
    })
}

/// Receipt for the Unified Mixed-Instrument (Novated Swap + Protective Option + Offsetting Swap)
/// Multilateral Clearing Transaction + `MNR-04` Bitcoin-Exact Commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedClearingReceipt {
    pub epoch_id: u64,
    pub settled_price_usd: u64,
    pub bob_online_during_clearing: bool,
    pub atomic_clearing_txid_hex: String,
    pub atomic_clearing_wtxid_hex: String,
    pub atomic_clearing_vsize: usize,
    pub stripped_348b_sha256d_be_limbs_dec: [String; 2],
    pub mnr04_style_tx_commitment_hex: String,
    pub outputs_sats: Vec<u64>,
    pub bob_swap_0x83_output_sats: u64,
    pub bob_call_option_0x83_output_sats: u64,
    pub bob_total_received_sats: u64,
    pub dave_novated_winner_output_sats: u64,
    pub carol_freed_collateral_sats: u64,
    pub miner_fee_sats: u64,
    pub consumed_nullifiers_hex: Vec<String>,
    pub prior_ledger_root_hex: String,
    pub next_ledger_root_hex: String,
}

/// Stateful Transferability & Unified Margin Clearing Engine tracking active contract outpoints,
/// transfer/spend nullifiers, and persistent `ledger_state_root` continuity.
#[derive(Debug, Clone)]
pub struct TransferAndClearingEngine {
    pub epoch_id: u64,
    pub ledger_state_root: [u8; 32],
    pub active_nullifiers: BTreeSet<[u8; 32]>,
    pub consumed_nullifiers: BTreeSet<[u8; 32]>,
}

impl TransferAndClearingEngine {
    pub fn new_genesis(genesis_root: [u8; 32]) -> Self {
        Self {
            epoch_id: 0,
            ledger_state_root: genesis_root,
            active_nullifiers: BTreeSet::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn register_active_leg(&mut self, leg: &FundedTaprootDerivativeLeg) -> Result<[u8; 32], UtxoRefError> {
        let nf = contract_outpoint_nullifier(&leg.funding_txid_display, leg.funding_vout)?;
        if self.consumed_nullifiers.contains(&nf) || !self.active_nullifiers.insert(nf) {
            return Err(UtxoRefError::ReplayDetected("leg outpoint already registered or consumed"));
        }
        Ok(nf)
    }

    /// **Mode 1 Transferability — Interactive Atomic L1 Taproot Novation (`U_AB -> U_DB`):**
    /// Transfers `Alice`'s live Option or Swap position on `old_leg` to `Dave` in one atomic
    /// Taproot transaction:
    /// 1. Verifies `old_leg` is currently active and un-nullified.
    /// 2. Computes the deterministic unsigned novation `txid` FIRST so `Dave + Bob` pre-sign all
    ///    refund + unilateral + `0x83` outcomes on the successor `U_DB` BEFORE anyone signs `U_AB`!
    /// 3. Signs `vin[0]` (`U_AB` via `Leaf 0` `coop_novation_leaf`, `0x00`) and `vin[1]`
    ///    (`Dave`'s key-path `P2TR` funding UTXO, `0x00`), paying `Alice` `assignment_price_sats`
    ///    immediately and retiring `U_AB`'s nullifier permanently!
    #[allow(clippy::too_many_arguments)]
    pub fn execute_atomic_taproot_novation(
        &mut self,
        old_leg: &FundedTaprootDerivativeLeg,
        alice_sk: &[u8; 32],
        bob_sk_for_interactive_novation: &[u8; 32],
        dave_sk: &[u8; 32],
        dave_funding_txid_display: &str,
        dave_funding_vout: u32,
        dave_funding_sats: u64,
        dave_funding_spk: Vec<u8>,
        assignment_price_sats: u64,
        novation_miner_fee_sats: u64,
        alice_exit_spk: Vec<u8>,
        dave_spk: Vec<u8>,
        new_leg_id: &str,
        outcome_prices_and_points: &[(u64, ProjectivePoint)],
    ) -> Result<AtomicTaprootNovationResult, UtxoRefError> {
        let old_nf =
            contract_outpoint_nullifier(&old_leg.funding_txid_display, old_leg.funding_vout)?;
        if self.consumed_nullifiers.contains(&old_nf) || !self.active_nullifiers.contains(&old_nf) {
            return Err(UtxoRefError::ReplayDetected(
                "cannot novate inactive or already-transferred contract",
            ));
        }
        if assignment_price_sats < MIN_P2TR_DUST_SATS {
            return Err(UtxoRefError::AccountingViolation(
                "Alice assignment_price_sats below 330-sat P2TR dust",
            ));
        }

        let alice_pk =
            pubkey_x_from_secret(alice_sk).map_err(|_| UtxoRefError::InvalidCrypto("alice_sk"))?;
        let bob_pk = pubkey_x_from_secret(bob_sk_for_interactive_novation)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob_sk"))?;
        let dave_pk =
            pubkey_x_from_secret(dave_sk).map_err(|_| UtxoRefError::InvalidCrypto("dave_sk"))?;

        if alice_pk != old_leg.tree.holder_pubkey_x || bob_pk != old_leg.tree.counterparty_pubkey_x
        {
            return Err(UtxoRefError::InvalidCrypto(
                "Alice/Bob keys do not match old_leg Taproot tree",
            ));
        }

        let grace_blocks = old_leg.tree.unilateral_cltv_height - old_leg.tree.maturity_height;
        let refund_delay_blocks = old_leg.tree.refund_cltv_height - old_leg.tree.maturity_height;
        let db_tree = TaprootDerivativeTree::build(
            dave_pk,
            bob_pk,
            old_leg.tree.clearing_guard_pubkey_x,
            old_leg.tree.maturity_height,
            grace_blocks,
            refund_delay_blocks,
        )
        .map_err(|_| UtxoRefError::InvalidFunding("successor U_DB tree build failed"))?;

        // Conservation across novation:
        // Inputs = `old_leg.funding_sats + dave_funding_sats`
        // Outputs = `U_DB (old_leg.funding_sats) + Alice (assignment_price_sats) + Dave_Change + Anchor (330)`
        // Therefore `Dave_Change = dave_funding_sats - assignment_price_sats - novation_miner_fee_sats - 330`!
        let dave_change_sats = dave_funding_sats
            .checked_sub(assignment_price_sats + novation_miner_fee_sats + DEFAULT_CPFP_ANCHOR_SATS)
            .ok_or(UtxoRefError::AccountingViolation(
                "Dave funding UTXO insufficient for assignment price + fee + anchor",
            ))?;

        let mut outputs = vec![
            (old_leg.funding_sats, db_tree.script_pubkey.clone()),
            (assignment_price_sats, alice_exit_spk),
        ];
        if dave_change_sats >= MIN_P2TR_DUST_SATS {
            outputs.push((dave_change_sats, dave_spk.clone()));
        }
        outputs.push((DEFAULT_CPFP_ANCHOR_SATS, old_leg.anchor_spk.clone()));

        let mut novation_tx = SegwitTx {
            version: 2,
            inputs: vec![
                SegwitTxIn::from_display_txid(
                    &old_leg.funding_txid_display,
                    old_leg.funding_vout,
                    0xfffffffe,
                    old_leg.funding_sats,
                    old_leg.tree.script_pubkey.clone(),
                )?,
                SegwitTxIn::from_display_txid(
                    dave_funding_txid_display,
                    dave_funding_vout,
                    0xfffffffe,
                    dave_funding_sats,
                    dave_funding_spk,
                )?,
            ],
            outputs,
            locktime: 0,
        };
        let novation_txid_hex = novation_tx.txid_hex();

        // Pre-sign ALL successor `U_DB` refund + unilateral + `0x83` packages BEFORE signing `novation_tx`!
        let successor_leg = build_funded_taproot_derivative_leg(
            new_leg_id,
            old_leg.contract.clone(),
            old_leg.bob_holds_long_payoff,
            dave_sk,
            bob_sk_for_interactive_novation,
            old_leg.tree.clearing_guard_pubkey_x,
            &novation_txid_hex,
            0, // vout[0] of novation_tx IS U_DB!
            old_leg.unilateral_fee_sats,
            old_leg.tree.maturity_height,
            grace_blocks,
            refund_delay_blocks,
            dave_spk,
            old_leg.bob_spk.clone(),
            old_leg.anchor_spk.clone(),
            outcome_prices_and_points,
        )?;

        // Sign `vin[0]` (`U_AB` Leaf 0 `coop_novation_leaf`, `0x00`)
        let sh_ab = novation_tx.bip341_sighash(
            0,
            SIGHASH_DEFAULT,
            Some(&old_leg.tree.coop_novation_leaf_hash),
        )?;
        let sig_alice = bip340_sign(alice_sk, &sh_ab)
            .map_err(|_| UtxoRefError::InvalidCrypto("alice novation sign"))?;
        let sig_bob = bip340_sign(bob_sk_for_interactive_novation, &sh_ab)
            .map_err(|_| UtxoRefError::InvalidCrypto("bob novation sign"))?;
        let (sig0, sig1) = if old_leg.tree.sorted_pair[0] == alice_pk {
            (sig_alice, sig_bob)
        } else {
            (sig_bob, sig_alice)
        };
        novation_tx.inputs[0].witness = vec![
            encode_taproot_witness_sig(&sig1, SIGHASH_DEFAULT),
            encode_taproot_witness_sig(&sig0, SIGHASH_DEFAULT),
            old_leg.tree.coop_novation_script.clone(),
            old_leg.tree.coop_novation_control_block.clone(),
        ];

        // Sign `vin[1]` (`Dave` key-path P2TR input, `0x00`)
        let sh_dave = novation_tx.bip341_sighash(1, SIGHASH_DEFAULT, None)?;
        let sig_dave = bip340_sign(dave_sk, &sh_dave)
            .map_err(|_| UtxoRefError::InvalidCrypto("dave novation sign"))?;
        novation_tx.inputs[1].witness = vec![encode_taproot_witness_sig(&sig_dave, SIGHASH_DEFAULT)];

        // Atomically retire `old_nf` and activate `new_nf`!
        self.active_nullifiers.remove(&old_nf);
        self.consumed_nullifiers.insert(old_nf);
        let new_nf = contract_outpoint_nullifier(&novation_txid_hex, 0)?;
        self.active_nullifiers.insert(new_nf);

        Ok(AtomicTaprootNovationResult {
            signed_novation_tx: novation_tx,
            novation_txid_hex,
            consumed_old_nullifier: old_nf,
            alice_immediate_exit_sats: assignment_price_sats,
            dave_change_sats: if dave_change_sats >= MIN_P2TR_DUST_SATS {
                dave_change_sats
            } else {
                0
            },
            successor_leg,
        })
    }

    /// **Mode 2 Transferability — Counterparty-Offline (`0x83`) Claim Assignment (`Alice -> Dave`):**
    /// When `Bob` is **100% offline** (`bob_sk` absent!), `Alice` assigns her Option/Swap maturity
    /// claim to `Dave` (`transferee_spk`) via `Leaf 1` (`0x01` co-signed with `ClearingGuard`),
    /// burning the contract's nullifier so `Alice` can never double-sell the claim!
    pub fn authorize_offline_bob_claim_transfer(
        &mut self,
        leg: &FundedTaprootDerivativeLeg,
        selected_outcome_idx: usize,
        oracle_scalar_t: &Scalar,
        alice_sk: &[u8; 32],
        clearing_guard_sk: &[u8; 32],
        transferee_spk: Vec<u8>,
    ) -> Result<OfflineClaimTransferResult, UtxoRefError> {
        let nf = contract_outpoint_nullifier(&leg.funding_txid_display, leg.funding_vout)?;
        if self.consumed_nullifiers.contains(&nf) || !self.active_nullifiers.contains(&nf) {
            return Err(UtxoRefError::ReplayDetected(
                "contract claim already transferred or settled",
            ));
        }
        let pre = leg
            .outcomes
            .get(selected_outcome_idx)
            .ok_or(UtxoRefError::AccountingViolation("outcome idx out of bounds"))?;

        let mut tx = SegwitTx {
            version: 2,
            inputs: vec![SegwitTxIn::from_display_txid(
                &leg.funding_txid_display,
                leg.funding_vout,
                0xfffffffe,
                leg.funding_sats,
                leg.tree.script_pubkey.clone(),
            )?],
            outputs: vec![
                (pre.bob_0x83_pinned_sats, leg.bob_spk.clone()), // vout[0] pinned by offline Bob's 0x83!
                (pre.holder_unilateral_sats, transferee_spk.clone()), // vout[1] redirected to Transferee Dave!
                (DEFAULT_CPFP_ANCHOR_SATS, leg.anchor_spk.clone()),
            ],
            locktime: leg.tree.maturity_height,
        };

        let bob_completed = adaptor_complete(&pre.bob_0x83_adaptor_sig, oracle_scalar_t)
            .map_err(|_| UtxoRefError::InvalidCrypto("complete Bob 0x83"))?;
        let sh_0x83 = tx.bip341_sighash(
            0,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&leg.tree.routed_clearing_leaf_hash),
        )?;
        bip340_verify(&leg.tree.counterparty_pubkey_x, &sh_0x83, &bob_completed)
            .map_err(|_| UtxoRefError::InvalidCrypto("offline Bob 0x83 verify failed"))?;

        let sh_0x01 =
            tx.bip341_sighash(0, SIGHASH_ALL, Some(&leg.tree.routed_clearing_leaf_hash))?;
        let sig_alice =
            bip340_sign(alice_sk, &sh_0x01).map_err(|_| UtxoRefError::InvalidCrypto("alice 0x01"))?;
        let sig_guard = bip340_sign(clearing_guard_sk, &sh_0x01)
            .map_err(|_| UtxoRefError::InvalidCrypto("guard 0x01"))?;

        tx.inputs[0].witness = vec![
            encode_taproot_witness_sig(&bob_completed, SIGHASH_SINGLE_ANYONECANPAY),
            encode_taproot_witness_sig(&sig_guard, SIGHASH_ALL),
            encode_taproot_witness_sig(&sig_alice, SIGHASH_ALL),
            leg.tree.routed_clearing_script.clone(),
            leg.tree.routed_clearing_control_block.clone(),
        ];

        self.active_nullifiers.remove(&nf);
        self.consumed_nullifiers.insert(nf);

        Ok(OfflineClaimTransferResult {
            consumed_assignment_nullifier: nf,
            transferee_spk,
            finalized_maturity_tx_for_outcome: tx,
        })
    }

    /// **Unified Mixed Swap + Option Multilateral Atomic Clearing (`Bob 100% Offline` via `0x83`!):**
    /// Settles:
    /// - `novated_swap_db` (`vin[0] -> vout[0]` Bob `0x83` Swap residual; `Dave` holds Long Swap),
    /// - `protective_option_bc` (`vin[1] -> vout[1]` Bob `0x83` ITM Call Option payout; `Carol` wrote Call),
    /// - `offsetting_swap_cd` (`vin[2]`, interactive `Leaf 0` `0x00` between `Carol` and `Dave`),
    ///
    /// while verifying prior `expected_prior_ledger_root`, consuming all 3 active nullifiers (rejecting
    /// any stale pre-novation `U_AB` leg!), routing net PnL via `UTXORef` Edmonds-Karp, and emitting
    /// the `MNR-04`-compatible 348-byte stripped TXID limbs + commitment!
    #[allow(clippy::too_many_arguments)]
    pub fn execute_mixed_swap_option_bob_offline_clearing(
        &mut self,
        expected_prior_ledger_root: &[u8; 32],
        novated_swap_db: &FundedTaprootDerivativeLeg,
        protective_option_bc: &FundedTaprootDerivativeLeg,
        offsetting_swap_cd: &FundedTaprootDerivativeLeg,
        selected_outcome_idx: usize,
        oracle_scalar_t: &Scalar,
        oracle_epoch_commitment: &[u8; 32],
        dave_sk: &[u8; 32],
        carol_sk: &[u8; 32],
        clearing_guard_sk: &[u8; 32],
        atomic_miner_fee_sats: u64,
        genesis_hash_bytes: &[u8; 32],
        network_label: &str,
    ) -> Result<(SegwitTx, UnifiedClearingReceipt), UtxoRefError> {
        if &self.ledger_state_root != expected_prior_ledger_root {
            return Err(UtxoRefError::PriorLedgerMismatch);
        }

        // 1. Enforce active membership & zero replay across all 3 legs!
        let nf_db = contract_outpoint_nullifier(
            &novated_swap_db.funding_txid_display,
            novated_swap_db.funding_vout,
        )?;
        let nf_bc = contract_outpoint_nullifier(
            &protective_option_bc.funding_txid_display,
            protective_option_bc.funding_vout,
        )?;
        let nf_cd = contract_outpoint_nullifier(
            &offsetting_swap_cd.funding_txid_display,
            offsetting_swap_cd.funding_vout,
        )?;
        if nf_db == nf_bc || nf_bc == nf_cd || nf_db == nf_cd {
            return Err(UtxoRefError::ReplayDetected("duplicate leg in clearing batch"));
        }
        for nf in [nf_db, nf_bc, nf_cd] {
            if self.consumed_nullifiers.contains(&nf) || !self.active_nullifiers.contains(&nf) {
                return Err(UtxoRefError::ReplayDetected(
                    "clearing leg is stale/novated, unregistered, or already settled",
                ));
            }
        }

        let db_pre = novated_swap_db
            .outcomes
            .get(selected_outcome_idx)
            .ok_or(UtxoRefError::AccountingViolation("db outcome idx"))?;
        let bc_pre = protective_option_bc
            .outcomes
            .get(selected_outcome_idx)
            .ok_or(UtxoRefError::AccountingViolation("bc outcome idx"))?;
        let cd_pre = offsetting_swap_cd
            .outcomes
            .get(selected_outcome_idx)
            .ok_or(UtxoRefError::AccountingViolation("cd outcome idx"))?;
        if db_pre.price_usd != bc_pre.price_usd || bc_pre.price_usd != cd_pre.price_usd {
            return Err(UtxoRefError::AccountingViolation("outcome mark mismatch"));
        }
        let settled_price_usd = db_pre.price_usd;

        // 2. Offline Bob's two `0x83`-pinned outputs (`vout[0]` Swap residual + `vout[1]` Call Option payout)!
        let bob_swap_out = db_pre.bob_0x83_pinned_sats;
        let bob_opt_out = bc_pre.bob_0x83_pinned_sats;
        let bob_total_out = bob_swap_out + bob_opt_out;

        // Remaining pool available to online Dave & Carol across all 3 UTXOs:
        let total_funded = novated_swap_db.funding_sats
            + protective_option_bc.funding_sats
            + offsetting_swap_cd.funding_sats;
        let online_distributable = total_funded
            .checked_sub(bob_total_out + DEFAULT_CPFP_ANCHOR_SATS + atomic_miner_fee_sats)
            .ok_or(UtxoRefError::AccountingViolation(
                "total funded < Bob 0x83 outputs + fee + anchor",
            ))?;

        // Exact bilateral shares for Dave & Carol across the 3 contracts:
        // - From `U_DB`: Dave gets `novated_swap_db.funding_sats - bob_swap_out` (before fee/anchor)
        // - From `U_BC`: Carol gets `protective_option_bc.funding_sats - bob_opt_out` (before fee/anchor)
        // - From `U_CD`: `offsetting_swap_cd.contract.payout_at_price(settled_price_usd)`
        //   (`Carol = Holder/Long`, `Dave = Counterparty/Short` on `U_CD`)
        let dave_from_db = novated_swap_db.funding_sats - bob_swap_out;
        let carol_from_bc = protective_option_bc.funding_sats - bob_opt_out;
        let cd_split = offsetting_swap_cd.contract.payout_at_price(settled_price_usd);
        let carol_from_cd = cd_split.long_sats;
        let dave_from_cd = cd_split.short_sats;

        let fee_plus_anchor = atomic_miner_fee_sats + DEFAULT_CPFP_ANCHOR_SATS;
        let dave_fee_share = fee_plus_anchor / 2;
        let carol_fee_share = fee_plus_anchor - dave_fee_share;

        let dave_cleared_out = (dave_from_db + dave_from_cd)
            .checked_sub(dave_fee_share)
            .ok_or(UtxoRefError::AccountingViolation("Dave cleared output underflow"))?;
        let carol_cleared_out = (carol_from_bc + carol_from_cd)
            .checked_sub(carol_fee_share)
            .ok_or(UtxoRefError::AccountingViolation("Carol cleared output underflow"))?;
        assert_eq!(dave_cleared_out + carol_cleared_out, online_distributable);

        if bob_swap_out < MIN_P2TR_DUST_SATS
            || bob_opt_out < MIN_P2TR_DUST_SATS
            || dave_cleared_out < MIN_P2TR_DUST_SATS
            || carol_cleared_out < MIN_P2TR_DUST_SATS
        {
            return Err(UtxoRefError::AccountingViolation(
                "cleared output below 330-sat P2TR dust",
            ));
        }

        // 3. Verify multilateral routing through `UTXORef` Edmonds-Karp (`solve_and_verify_pnl_batch`)!
        let dave_initial = novated_swap_db.contract.holder_contribution_sats()
            + offsetting_swap_cd.contract.counterparty_contribution_sats();
        let dave_net_gain = (dave_from_db + dave_from_cd).saturating_sub(dave_initial);

        let next_epoch = self.epoch_id + 1;
        let snap = PnlBatchSnapshotV1 {
            network: network_label.to_owned(),
            epoch_id: next_epoch,
            previous_state_root: self.ledger_state_root,
            netting_sets: vec![NettingSetSpec {
                id: "mnr05-mixed-swap-option".into(),
                collateral: CollateralAsset::VanillaBtc,
            }],
            vaults: vec![
                VaultRecord {
                    id: "vault-pool".into(),
                    netting_set_id: "mnr05-mixed-swap-option".into(),
                    change_script_pubkey: protective_option_bc.holder_spk.clone(),
                    fee_sats: carol_fee_share,
                    protected_sats: 0,
                    utxos: vec![FundedVaultUtxo {
                        outpoint: BtcOutPoint {
                            txid: display_txid_to_bytes(&novated_swap_db.funding_txid_display)?,
                            vout: novated_swap_db.funding_vout,
                        },
                        sats: bob_total_out + carol_cleared_out + carol_fee_share + dave_net_gain,
                        script_pubkey: novated_swap_db.tree.script_pubkey.clone(),
                    }],
                },
                VaultRecord {
                    id: "vault-dave".into(),
                    netting_set_id: "mnr05-mixed-swap-option".into(),
                    change_script_pubkey: novated_swap_db.holder_spk.clone(),
                    fee_sats: dave_fee_share,
                    protected_sats: 0,
                    utxos: vec![FundedVaultUtxo {
                        outpoint: BtcOutPoint {
                            txid: display_txid_to_bytes(&offsetting_swap_cd.funding_txid_display)?,
                            vout: offsetting_swap_cd.funding_vout,
                        },
                        sats: dave_initial,
                        script_pubkey: offsetting_swap_cd.tree.script_pubkey.clone(),
                    }],
                },
            ],
            accounts: vec![
                AccountRecord {
                    id: "pool".into(),
                    netting_set_id: "mnr05-mixed-swap-option".into(),
                    vault_id: "vault-pool".into(),
                    equity_sats: bob_total_out + carol_cleared_out + dave_net_gain,
                    locked_sats: 0,
                    payout_sats: 0,
                    payout_script_pubkey: None,
                },
                AccountRecord {
                    id: "dave".into(),
                    netting_set_id: "mnr05-mixed-swap-option".into(),
                    vault_id: "vault-dave".into(),
                    equity_sats: dave_initial - dave_fee_share,
                    locked_sats: 0,
                    payout_sats: dave_net_gain,
                    payout_script_pubkey: Some(novated_swap_db.holder_spk.clone()),
                },
            ],
            obligations: if dave_net_gain > 0 {
                vec![RealizedObligation {
                    id: format!("mnr05-pnl-epoch-{next_epoch}"),
                    netting_set_id: "mnr05-mixed-swap-option".into(),
                    from_account_id: "pool".into(),
                    to_account_id: "dave".into(),
                    sats: dave_net_gain,
                }]
            } else {
                vec![]
            },
            consumed_obligation_ids: vec![],
            spent_outpoints: vec![],
            routes: if dave_net_gain > 0 {
                vec![PermittedRoute {
                    from_vault_id: "vault-pool".into(),
                    to_target: RouteTarget::Payout("dave".into()),
                    capacity_sats: dave_net_gain,
                }]
            } else {
                vec![]
            },
        };
        let verified_pnl = solve_and_verify_pnl_batch(&snap, &snap.snapshot_hash())?;

        // 4. Assemble and sign the 3-input, 5-output Taproot transaction (`bob_sk` 100% ABSENT!)
        let maturity_locktime = novated_swap_db
            .tree
            .maturity_height
            .max(protective_option_bc.tree.maturity_height)
            .max(offsetting_swap_cd.tree.maturity_height);

        let mut tx = SegwitTx {
            version: 2,
            inputs: vec![
                SegwitTxIn::from_display_txid(
                    &novated_swap_db.funding_txid_display,
                    novated_swap_db.funding_vout,
                    0xfffffffe,
                    novated_swap_db.funding_sats,
                    novated_swap_db.tree.script_pubkey.clone(),
                )?,
                SegwitTxIn::from_display_txid(
                    &protective_option_bc.funding_txid_display,
                    protective_option_bc.funding_vout,
                    0xfffffffe,
                    protective_option_bc.funding_sats,
                    protective_option_bc.tree.script_pubkey.clone(),
                )?,
                SegwitTxIn::from_display_txid(
                    &offsetting_swap_cd.funding_txid_display,
                    offsetting_swap_cd.funding_vout,
                    0xfffffffe,
                    offsetting_swap_cd.funding_sats,
                    offsetting_swap_cd.tree.script_pubkey.clone(),
                )?,
            ],
            outputs: vec![
                (bob_swap_out, novated_swap_db.bob_spk.clone()), // vout[0]: Bob's 0x83 Swap residual
                (bob_opt_out, protective_option_bc.bob_spk.clone()), // vout[1]: Bob's 0x83 ITM Call Option payout!
                (dave_cleared_out, novated_swap_db.holder_spk.clone()), // vout[2]: Novated Winner Dave
                (carol_cleared_out, protective_option_bc.holder_spk.clone()), // vout[3]: Option Writer / Swap Counterparty Carol
                (DEFAULT_CPFP_ANCHOR_SATS, novated_swap_db.anchor_spk.clone()), // vout[4]: 330-sat CPFP anchor
            ],
            locktime: maturity_locktime,
        };

        // Sign `vin[0]` (`U_DB` Leaf 1: offline Bob `0x83` + Guard `0x01` + Dave `0x01`)
        let bob_db_sig = adaptor_complete(&db_pre.bob_0x83_adaptor_sig, oracle_scalar_t)
            .map_err(|_| UtxoRefError::InvalidCrypto("complete Bob DB 0x83"))?;
        let sh_db_83 = tx.bip341_sighash(
            0,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&novated_swap_db.tree.routed_clearing_leaf_hash),
        )?;
        bip340_verify(
            &novated_swap_db.tree.counterparty_pubkey_x,
            &sh_db_83,
            &bob_db_sig,
        )
        .map_err(|_| UtxoRefError::InvalidCrypto("Bob DB 0x83 verify failed"))?;

        let sh_db_01 = tx.bip341_sighash(
            0,
            SIGHASH_ALL,
            Some(&novated_swap_db.tree.routed_clearing_leaf_hash),
        )?;
        let sig_dave_db =
            bip340_sign(dave_sk, &sh_db_01).map_err(|_| UtxoRefError::InvalidCrypto("dave 0x01"))?;
        let sig_guard_db = bip340_sign(clearing_guard_sk, &sh_db_01)
            .map_err(|_| UtxoRefError::InvalidCrypto("guard 0x01"))?;
        tx.inputs[0].witness = vec![
            encode_taproot_witness_sig(&bob_db_sig, SIGHASH_SINGLE_ANYONECANPAY),
            encode_taproot_witness_sig(&sig_guard_db, SIGHASH_ALL),
            encode_taproot_witness_sig(&sig_dave_db, SIGHASH_ALL),
            novated_swap_db.tree.routed_clearing_script.clone(),
            novated_swap_db.tree.routed_clearing_control_block.clone(),
        ];

        // Sign `vin[1]` (`U_BC` Call Option Leaf 1: offline Bob `0x83` + Guard `0x01` + Carol `0x01`)
        let bob_bc_sig = adaptor_complete(&bc_pre.bob_0x83_adaptor_sig, oracle_scalar_t)
            .map_err(|_| UtxoRefError::InvalidCrypto("complete Bob BC 0x83"))?;
        let sh_bc_83 = tx.bip341_sighash(
            1,
            SIGHASH_SINGLE_ANYONECANPAY,
            Some(&protective_option_bc.tree.routed_clearing_leaf_hash),
        )?;
        bip340_verify(
            &protective_option_bc.tree.counterparty_pubkey_x,
            &sh_bc_83,
            &bob_bc_sig,
        )
        .map_err(|_| UtxoRefError::InvalidCrypto("Bob BC 0x83 verify failed"))?;

        let sh_bc_01 = tx.bip341_sighash(
            1,
            SIGHASH_ALL,
            Some(&protective_option_bc.tree.routed_clearing_leaf_hash),
        )?;
        let sig_carol_bc = bip340_sign(carol_sk, &sh_bc_01)
            .map_err(|_| UtxoRefError::InvalidCrypto("carol 0x01"))?;
        let sig_guard_bc = bip340_sign(clearing_guard_sk, &sh_bc_01)
            .map_err(|_| UtxoRefError::InvalidCrypto("guard 0x01"))?;
        tx.inputs[1].witness = vec![
            encode_taproot_witness_sig(&bob_bc_sig, SIGHASH_SINGLE_ANYONECANPAY),
            encode_taproot_witness_sig(&sig_guard_bc, SIGHASH_ALL),
            encode_taproot_witness_sig(&sig_carol_bc, SIGHASH_ALL),
            protective_option_bc.tree.routed_clearing_script.clone(),
            protective_option_bc.tree.routed_clearing_control_block.clone(),
        ];

        // Sign `vin[2]` (`U_CD` Interactive Leaf 0 `coop_novation_leaf`, `0x00` Carol + Dave)
        let sh_cd_00 = tx.bip341_sighash(
            2,
            SIGHASH_DEFAULT,
            Some(&offsetting_swap_cd.tree.coop_novation_leaf_hash),
        )?;
        let carol_pk = pubkey_x_from_secret(carol_sk)
            .map_err(|_| UtxoRefError::InvalidCrypto("carol_pk"))?;
        let sig_carol_cd = bip340_sign(carol_sk, &sh_cd_00)
            .map_err(|_| UtxoRefError::InvalidCrypto("carol 0x00"))?;
        let sig_dave_cd = bip340_sign(dave_sk, &sh_cd_00)
            .map_err(|_| UtxoRefError::InvalidCrypto("dave 0x00"))?;
        let (sig0, sig1) = if offsetting_swap_cd.tree.sorted_pair[0] == carol_pk {
            (sig_carol_cd, sig_dave_cd)
        } else {
            (sig_dave_cd, sig_carol_cd)
        };
        tx.inputs[2].witness = vec![
            encode_taproot_witness_sig(&sig1, SIGHASH_DEFAULT),
            encode_taproot_witness_sig(&sig0, SIGHASH_DEFAULT),
            offsetting_swap_cd.tree.coop_novation_script.clone(),
            offsetting_swap_cd.tree.coop_novation_control_block.clone(),
        ];

        // 5. Compute exact 348-byte stripped transaction SHA256d big-endian u128 limbs & `MNR-04` commitment!
        let stripped = tx.serialize_unsigned();
        debug_assert_eq!(stripped.len(), 348);
        let raw_sha256d = sha256(&sha256(&stripped));
        let limb_hi = u128::from_be_bytes(raw_sha256d[..16].try_into().unwrap());
        let limb_lo = u128::from_be_bytes(raw_sha256d[16..].try_into().unwrap());

        let raw_segwit = tx.serialize_segwit();
        let mut commit_h = Sha256::new();
        commit_h.update(b"shz/mnr05/mixed-swap-option-clearing/v1\0");
        commit_h.update(genesis_hash_bytes);
        commit_h.update(self.ledger_state_root);
        commit_h.update(verified_pnl.next_accounting_state_root);
        commit_h.update(oracle_epoch_commitment);
        commit_h.update(nf_db);
        commit_h.update(nf_bc);
        commit_h.update(nf_cd);
        commit_h.update(atomic_miner_fee_sats.to_be_bytes());
        commit_h.update((raw_segwit.len() as u64).to_be_bytes());
        commit_h.update(&raw_segwit);
        let mnr04_style_commitment: [u8; 32] = commit_h.finalize().into();

        // Advance engine state & consume nullifiers atomically!
        let prior_root = self.ledger_state_root;
        for nf in [nf_db, nf_bc, nf_cd] {
            self.active_nullifiers.remove(&nf);
            self.consumed_nullifiers.insert(nf);
        }
        self.epoch_id = next_epoch;
        self.ledger_state_root = verified_pnl.next_accounting_state_root;

        let receipt = UnifiedClearingReceipt {
            epoch_id: next_epoch,
            settled_price_usd,
            bob_online_during_clearing: false,
            atomic_clearing_txid_hex: tx.txid_hex(),
            atomic_clearing_wtxid_hex: tx.wtxid_hex(),
            atomic_clearing_vsize: tx.vsize(),
            stripped_348b_sha256d_be_limbs_dec: [limb_hi.to_string(), limb_lo.to_string()],
            mnr04_style_tx_commitment_hex: hex::encode(mnr04_style_commitment),
            outputs_sats: tx.outputs.iter().map(|(v, _)| *v).collect(),
            bob_swap_0x83_output_sats: bob_swap_out,
            bob_call_option_0x83_output_sats: bob_opt_out,
            bob_total_received_sats: bob_total_out,
            dave_novated_winner_output_sats: dave_cleared_out,
            carol_freed_collateral_sats: carol_cleared_out,
            miner_fee_sats: atomic_miner_fee_sats,
            consumed_nullifiers_hex: vec![
                hex::encode(nf_db),
                hex::encode(nf_bc),
                hex::encode(nf_cd),
            ],
            prior_ledger_root_hex: hex::encode(prior_root),
            next_ledger_root_hex: hex::encode(self.ledger_state_root),
        };

        Ok((tx, receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::{bigint::U256, ops::Reduce};
    use shz_margin::{InverseContractSpec, InverseOptionSpec, OptionKind, SwapTenor};

    fn spk(seed: u8) -> Vec<u8> {
        let pk = pubkey_x_from_secret(&[seed; 32]).unwrap();
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&pk);
        s
    }

    #[test]
    fn test_taproot_novation_portfolio_cross_margin_and_mixed_swap_option_clearing_with_bob_offline() {
        let alice_sk = [0x11u8; 32];
        let carol_sk = [0x23u8; 32];
        let guard_sk = [0x24u8; 32];
        let dave_sk = [0x25u8; 32];
        let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();

        let t_125k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(125_000));
        let grid = vec![(125_000u64, ProjectivePoint::GENERATOR * t_125k)];

        // 1. Portfolio Cross-Margin Check for Bob:
        //    - Bob is Short $50,000 Swap @ $100,000 (2x = 25,000,000 sats)
        //    - Bob hedges upside by buying a 0.50 BTC Call Option @ K = $105,000 (premium = 2,500,000 sats)
        let bob_swap = DerivativeContractSpec::InverseSwap {
            tenor: SwapTenor::Dated {
                expiry_timestamp: 1_800_000_000,
            },
            spec: InverseContractSpec::from_leverages_v0(50_000, 100_000, 20_000, 20_000).unwrap(),
        };
        let bob_protective_call = DerivativeContractSpec::EuropeanOption(
            InverseOptionSpec::new_v0(
                OptionKind::Call,
                105_000,
                1_800_000_000,
                50_000_000,
                2_500_000,
                50_000_000,
            )
            .unwrap(),
        );
        let stress_report = evaluate_swap_option_portfolio_margin(
            "Bob",
            &[
                (bob_swap.clone(), false),         // Bob is Short Swap
                (bob_protective_call.clone(), true), // Bob is Long Call Option
            ],
            &[80_000, 100_000, 105_000, 125_000, 150_000, 200_000],
            500_000,
        )
        .unwrap();
        assert!(stress_report.scenario_solvent_across_grid);
        // Standalone margin = 25,000,000 + 2,500,000 = 27,500,000 sats; hedged worst loss at $105k is only ~4.88M!
        assert!(stress_report.cross_margin_relief_sats > 20_000_000);

        // 2. Originate Swap AB, Call Option BC, and Offsetting Swap CD, then Novate AB -> DB, then drop `bob_sk`!
        let swap_cd = DerivativeContractSpec::InverseSwap {
            tenor: SwapTenor::Dated {
                expiry_timestamp: 1_800_000_000,
            },
            spec: InverseContractSpec::from_leverages_v0(50_000, 125_000, 20_000, 20_000).unwrap(),
        };

        let mut engine = TransferAndClearingEngine::new_genesis([0x77; 32]);

        let (leg_ab, novation, leg_bc, leg_cd) = {
            let bob_sk_ephemeral = [0x22u8; 32];
            let ab = build_funded_taproot_derivative_leg(
                "SWAP-AB",
                bob_swap,
                false, // Bob is Short Swap
                &alice_sk,
                &bob_sk_ephemeral,
                guard_pk,
                &"01".repeat(32),
                0,
                1_000,
                180,
                20,
                60,
                spk(0x41),
                spk(0x42),
                spk(0x44),
                &grid,
            )
            .unwrap();
            engine.register_active_leg(&ab).unwrap();

            // Novate Alice's Swap position to Dave at $110,000 (`Alice` receives 29,500,000 sats immediately!)
            let nov = engine
                .execute_atomic_taproot_novation(
                    &ab,
                    &alice_sk,
                    &bob_sk_ephemeral,
                    &dave_sk,
                    &"09".repeat(32),
                    0,
                    32_000_000,
                    spk(0x25),
                    29_500_000,
                    1_000,
                    spk(0x41),
                    spk(0x45),
                    "SWAP-DB-NOVATED",
                    &grid,
                )
                .unwrap();

            let bc = build_funded_taproot_derivative_leg(
                "CALL-OPT-BC",
                bob_protective_call,
                true, // Bob is Long Call Option (while STILL using 0x83 so Bob can go offline!)
                &carol_sk,
                &bob_sk_ephemeral,
                guard_pk,
                &"02".repeat(32),
                0,
                1_000,
                180,
                20,
                60,
                spk(0x43),
                spk(0x42),
                spk(0x44),
                &grid,
            )
            .unwrap();
            engine.register_active_leg(&bc).unwrap();

            // CD is Carol vs Dave (no Bob!)
            let cd = build_funded_taproot_derivative_leg(
                "SWAP-CD",
                swap_cd,
                false,
                &carol_sk,
                &dave_sk,
                guard_pk,
                &"03".repeat(32),
                0,
                1_000,
                180,
                20,
                60,
                spk(0x43),
                spk(0x45),
                spk(0x44),
                &grid,
            )
            .unwrap();
            engine.register_active_leg(&cd).unwrap();

            (ab, nov, bc, cd)
            // `bob_sk_ephemeral` DROPPED here!
        };

        // Adversarial 1: Attempting to clear using the stale pre-novation `leg_ab` MUST fail closed!
        let prior_root = engine.ledger_state_root;
        assert_eq!(
            engine
                .execute_mixed_swap_option_bob_offline_clearing(
                    &prior_root,
                    &leg_ab, // STALE NOVATED LEG!
                    &leg_bc,
                    &leg_cd,
                    0,
                    &t_125k,
                    &[0x99; 32],
                    &dave_sk,
                    &carol_sk,
                    &guard_sk,
                    2_670,
                    &[0x0f; 32],
                    "bitcoin-regtest",
                )
                .unwrap_err(),
            UtxoRefError::ReplayDetected(
                "clearing leg is stale/novated, unregistered, or already settled"
            )
        );

        // Adversarial 2: Forged prior accounting root MUST fail closed!
        assert_eq!(
            engine
                .execute_mixed_swap_option_bob_offline_clearing(
                    &[0xEE; 32],
                    &novation.successor_leg,
                    &leg_bc,
                    &leg_cd,
                    0,
                    &t_125k,
                    &[0x99; 32],
                    &dave_sk,
                    &carol_sk,
                    &guard_sk,
                    2_670,
                    &[0x0f; 32],
                    "bitcoin-regtest",
                )
                .unwrap_err(),
            UtxoRefError::PriorLedgerMismatch
        );

        // Honest clearing with `novation.successor_leg` (`U_DB`) + `leg_bc` (Call Option) + `leg_cd` (`bob_sk` 100% offline!):
        let (tx, receipt) = engine
            .execute_mixed_swap_option_bob_offline_clearing(
                &prior_root,
                &novation.successor_leg,
                &leg_bc,
                &leg_cd,
                0,
                &t_125k,
                &[0x99; 32],
                &dave_sk,
                &carol_sk,
                &guard_sk,
                2_670,
                &[0x0f; 32],
                "bitcoin-regtest",
            )
            .unwrap();

        assert!(!receipt.bob_online_during_clearing);
        assert_eq!(tx.serialize_unsigned().len(), 348);
        // At $125,000:
        // - Bob's Short $50k Swap (`U_DB`): loss = 50k * 1e8 * 25k / (100k * 125k) = 10,000,000 sats -> `25M - 10M = 15,000,000` sats!
        // - Bob's Long 0.50 BTC Call Option (`K = $105k`, `U_BC`): intrinsic = 50M * 20k / 125k = `8,000,000` sats!
        assert_eq!(receipt.bob_swap_0x83_output_sats, 15_000_000);
        assert_eq!(receipt.bob_call_option_0x83_output_sats, 8_000_000);
        assert_eq!(receipt.bob_total_received_sats, 23_000_000);
    }
}
