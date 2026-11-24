//! Partial-Liquidation Dutch Auction Engine (`Track 1`).
//!
//! Instead of wiping out 100% of an under-collateralized account on a wick, computes the exact
//! minimum notional tranche `close_notional_usd` and time-decaying Dutch auction price discount
//! needed to bring `equity / remaining_notional` safely back to `target_restore_margin_bps`.
#![forbid(unsafe_code)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{MarginError, SATS_PER_BTC};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PartialLiquidationPlan {
    pub healthy: bool,
    pub current_margin_bps: u32,
    pub maintenance_margin_bps: u32,
    pub target_restore_margin_bps: u32,
    pub total_notional_usd: u64,
    pub tranche_notional_usd: u64,
    pub remaining_notional_usd: u64,
    pub auction_discount_bps: u32,
    pub auction_fill_price_usd: u64,
    pub auction_penalty_sats: u64,
    pub post_tranche_equity_sats: u64,
    pub post_tranche_margin_bps: u32,
}

/// Computes a partial-liquidation Dutch auction tranche for an account holding `total_notional_usd`
/// (`is_long`) with current mark-to-market `equity_sats` at `mark_price_usd`.
#[allow(clippy::too_many_arguments)]
pub fn compute_partial_liquidation_tranche(
    is_long: bool,
    total_notional_usd: u64,
    equity_sats: u64,
    mark_price_usd: u64,
    maintenance_margin_bps: u32,
    target_restore_margin_bps: u32,
    auction_elapsed_ms: u64,
    auction_duration_ms: u64,
    max_discount_bps: u32,
) -> Result<PartialLiquidationPlan, MarginError> {
    if total_notional_usd == 0 || mark_price_usd == 0 {
        return Err(MarginError::InvalidParameter("notional and mark_price must be > 0"));
    }
    if maintenance_margin_bps == 0 || target_restore_margin_bps <= maintenance_margin_bps {
        return Err(MarginError::InvalidParameter(
            "require 0 < maintenance_margin_bps < target_restore_margin_bps",
        ));
    }
    if max_discount_bps >= maintenance_margin_bps {
        return Err(MarginError::InvalidParameter(
            "max_discount_bps must be < maintenance_margin_bps to avoid bad debt",
        ));
    }

    let pos_value_sats = ((total_notional_usd as u128) * SATS_PER_BTC).div_ceil(mark_price_usd as u128);
    let current_margin_bps = (((equity_sats as u128) * 10_000) / pos_value_sats.max(1)) as u32;

    if current_margin_bps >= maintenance_margin_bps {
        return Ok(PartialLiquidationPlan {
            healthy: true,
            current_margin_bps,
            maintenance_margin_bps,
            target_restore_margin_bps,
            total_notional_usd,
            tranche_notional_usd: 0,
            remaining_notional_usd: total_notional_usd,
            auction_discount_bps: 0,
            auction_fill_price_usd: mark_price_usd,
            auction_penalty_sats: 0,
            post_tranche_equity_sats: equity_sats,
            post_tranche_margin_bps: current_margin_bps,
        });
    }

    let dur = auction_duration_ms.max(1);
    let clamped_ms = auction_elapsed_ms.min(dur);
    let discount_bps = (((max_discount_bps as u128) * (clamped_ms as u128)) / (dur as u128)) as u32;

    let fill_price_usd = if is_long {
        ((mark_price_usd as u128 * (10_000 - u128::from(discount_bps))) / 10_000).max(1) as u64
    } else {
        ((mark_price_usd as u128 * (10_000 + u128::from(discount_bps))).div_ceil(10_000)) as u64
    };

    // Solve for minimum closed notional `dQ` such that:
    // `(equity - dQ_sats * discount_bps / 10_000) >= (Q_sats - dQ_sats) * target_bps / 10_000`
    // Rearranging:
    // `dQ * (target_bps - discount_bps) >= Q * target_bps - equity_usd_equiv`!
    let target_u = u128::from(target_restore_margin_bps);
    let disc_u = u128::from(discount_bps);
    let denom_bps = target_u.saturating_sub(disc_u).max(1);

    let required_sats_at_full = (pos_value_sats * target_u).div_ceil(10_000);
    let deficit_sats = required_sats_at_full.saturating_sub(equity_sats as u128);

    // `dQ_sats >= deficit_sats * 10_000 / (target_bps - discount_bps)`
    let tranche_sats = (deficit_sats * 10_000).div_ceil(denom_bps);
    let tranche_usd = ((tranche_sats * (mark_price_usd as u128)).div_ceil(SATS_PER_BTC) as u64)
        .clamp(1, total_notional_usd);

    let remaining_usd = total_notional_usd - tranche_usd;
    let closed_sats = ((tranche_usd as u128) * SATS_PER_BTC).div_ceil(mark_price_usd as u128);
    let penalty_sats = ((closed_sats * disc_u).div_ceil(10_000)) as u64;
    let post_equity = equity_sats.saturating_sub(penalty_sats);

    let post_margin_bps = if remaining_usd == 0 {
        10_000
    } else {
        let rem_sats = ((remaining_usd as u128) * SATS_PER_BTC).div_ceil(mark_price_usd as u128);
        (((post_equity as u128) * 10_000) / rem_sats.max(1)) as u32
    };

    Ok(PartialLiquidationPlan {
        healthy: false,
        current_margin_bps,
        maintenance_margin_bps,
        target_restore_margin_bps,
        total_notional_usd,
        tranche_notional_usd: tranche_usd,
        remaining_notional_usd: remaining_usd,
        auction_discount_bps: discount_bps,
        auction_fill_price_usd: fill_price_usd,
        auction_penalty_sats: penalty_sats,
        post_tranche_equity_sats: post_equity,
        post_tranche_margin_bps: post_margin_bps,
    })
}
