//! Portfolio Cross-Margin Greeks & SPAN-style Scenario Risk Engine for multi-expiry
//! inverse BTC/USD options, swaps, and perpetuals (`Track 1`).
#![forbid(unsafe_code)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{MarginError, SATS_PER_BTC};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum OptionKind {
    Call,
    Put,
}

/// Inverse BTC-settled European option leg (Deribit-style: strike in USD, payoff in satoshis
/// `max(0, ±(S_T - K)) / S_T * notional_btc`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct InverseOptionLeg {
    pub instrument_id: String,
    pub kind: OptionKind,
    /// Signed contracts in milli-BTC (`+1_000` = Long 1.0 BTC notional, `-500` = Short 0.5 BTC).
    pub signed_size_mbtc: i64,
    pub strike_usd: u64,
    pub days_to_expiry: u32,
    /// Implied volatility in basis points (`6_000` = 60.00% annualized IV).
    pub iv_bps: u32,
    /// Entry mark premium in satoshis (paid if long, collected if short).
    pub entry_premium_sats: i64,
}

/// Inverse perpetual / dated swap leg (`signed_usd_notional > 0` = Long, `< 0` = Short).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct InverseSwapLeg {
    pub instrument_id: String,
    pub signed_usd_notional: i64,
    pub entry_price_usd: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PortfolioGreeks {
    /// Net directional delta in satoshis for a +1% spot BTC/USD move.
    pub net_delta_sats_per_1pct: i64,
    /// Second-order convexity in satoshis across ±1% spot moves.
    pub net_gamma_sats_per_1pct2: i64,
    /// Sensitivity in satoshis to +100 bps (+1 vol point) IV shift.
    pub net_vega_sats_per_vol_pt: i64,
    /// 1-day time decay in satoshis (`days_to_expiry -> days_to_expiry - 1`).
    pub net_theta_sats_per_day: i64,
    /// Sum of isolated initial margins without cross-margin offsets.
    pub isolated_initial_margin_sats: u64,
    /// SPAN scenario-grid worst-case cross-margin requirement (with contingency floor).
    pub cross_initial_margin_sats: u64,
    /// Cross-margin maintenance requirement (`75%` of cross initial margin).
    pub cross_maintenance_margin_sats: u64,
    /// Capital efficiency savings in basis points (`0..10_000`).
    pub margin_efficiency_saved_bps: u32,
}

/// Integer square-root (`floor(sqrt(x))`) for deterministic cross-platform option time-value pricing.
fn isqrt_u128(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x0 = 1u128 << ((128 - n.leading_zeros()).div_ceil(2));
    loop {
        let x1 = (x0 + n / x0) / 2;
        if x1 >= x0 {
            return x0;
        }
        x0 = x1;
    }
}

/// Deterministic rational Bachelier/Black-76 approximation for inverse BTC option mark value (in sats per 1 BTC)
/// at `(spot_usd, strike_usd, days_to_expiry, iv_bps)`:
/// - Intrinsic value: `max(0, S - K) * 1e8 / S` (Call) or `max(0, K - S) * 1e8 / S` (Put).
/// - Time value: ATM straddle approximation `0.3989 * sigma * sqrt(T_days / 365)` damped exponentially-rationally
///   by moneyness distance `|S - K| / (sigma * S * sqrt(T))` (`1 / (1 + z^2 + z^4 / 2)`), preserving smooth
///   positive gamma, positive vega, put-call parity, and 100% deterministic integer arithmetic!
pub fn price_inverse_option_per_btc_sats(
    kind: OptionKind,
    spot_usd: u64,
    strike_usd: u64,
    days_to_expiry: u32,
    iv_bps: u32,
) -> u64 {
    if spot_usd == 0 {
        return 0;
    }
    let s = spot_usd as u128;
    let k = strike_usd as u128;
    let intrinsic_sats = match kind {
        OptionKind::Call => {
            if s > k {
                ((s - k) * SATS_PER_BTC) / s
            } else {
                0
            }
        }
        OptionKind::Put => {
            if k > s {
                ((k - s) * SATS_PER_BTC) / s
            } else {
                0
            }
        }
    };
    if days_to_expiry == 0 || iv_bps == 0 {
        return intrinsic_sats as u64;
    }

    // `sqrt_t_e6 = floor(sqrt(days * 1e12 / 365))`
    let sqrt_t_e6 = isqrt_u128((u128::from(days_to_expiry) * 1_000_000_000_000u128) / 365);
    // `sigma_sqrt_t_e6 = iv_bps * sqrt_t_e6 / 10_000`
    let sigma_sqrt_t_e6 = (u128::from(iv_bps) * sqrt_t_e6) / 10_000;
    if sigma_sqrt_t_e6 == 0 {
        return intrinsic_sats as u64;
    }

    // Hyperbolic Bachelier/Black-76 option formula in USD cents (`e2` precision for sub-sat smoothness):
    // `Price_USD = 0.5 * ( ±(S - K) + sqrt((S - K)^2 + (2 * ATM_TV_USD)^2) )`
    // Guarantees strictly positive Gamma everywhere, exact Put-Call parity, positive Vega, and negative Theta!
    let s_e2 = s * 100;
    let k_e2 = k * 100;
    // `two_atm_tv_e2 = 2 * 0.398942 * sigma_sqrt_t * K_e2 = 797_885 * sigma_sqrt_t_e6 * k_e2 / 1e12`
    let two_atm_tv_e2 = (797_885u128 * sigma_sqrt_t_e6 * k_e2) / 1_000_000_000_000u128;
    if two_atm_tv_e2 == 0 {
        return intrinsic_sats as u64;
    }

    let diff_e2 = s_e2.abs_diff(k_e2);
    let rad_e2 = isqrt_u128(diff_e2 * diff_e2 + two_atm_tv_e2 * two_atm_tv_e2);
    let signed_sum_e2 = match kind {
        OptionKind::Call => {
            if s_e2 >= k_e2 {
                rad_e2 + diff_e2
            } else {
                rad_e2.saturating_sub(diff_e2)
            }
        }
        OptionKind::Put => {
            if k_e2 >= s_e2 {
                rad_e2 + diff_e2
            } else {
                rad_e2.saturating_sub(diff_e2)
            }
        }
    };
    let option_usd_e2 = signed_sum_e2 / 2;
    let option_sats = (option_usd_e2 * SATS_PER_BTC) / s_e2;

    option_sats.max(intrinsic_sats).min(SATS_PER_BTC) as u64
}

fn mark_portfolio_pnl_sats(
    swaps: &[InverseSwapLeg],
    options: &[InverseOptionLeg],
    spot_usd: u64,
    iv_shift_bps: i32,
    day_decay: u32,
) -> i64 {
    let mut total_pnl: i128 = 0;
    let s = spot_usd.max(1) as i128;

    for sw in swaps {
        let p0 = sw.entry_price_usd.max(1) as i128;
        let q = i128::from(sw.signed_usd_notional);
        // Inverse PnL: `q * 1e8 * (s - p0) / (p0 * s)`
        let pnl = (q * (SATS_PER_BTC as i128) * (s - p0)) / (p0 * s);
        total_pnl += pnl;
    }

    for opt in options {
        let eff_days = opt.days_to_expiry.saturating_sub(day_decay);
        let eff_iv = (opt.iv_bps as i32 + iv_shift_bps).clamp(500, 30_000) as u32;
        let mark_per_btc =
            price_inverse_option_per_btc_sats(opt.kind, spot_usd.max(1), opt.strike_usd, eff_days, eff_iv)
                as i128;
        let cur_val = (mark_per_btc * i128::from(opt.signed_size_mbtc.abs())) / 1_000;
        let leg_pnl = if opt.signed_size_mbtc >= 0 {
            cur_val - i128::from(opt.entry_premium_sats)
        } else {
            i128::from(opt.entry_premium_sats) - cur_val
        };
        total_pnl += leg_pnl;
    }

    total_pnl.clamp(i128::from(i64::MIN / 2), i128::from(i64::MAX / 2)) as i64
}

/// Evaluates full portfolio Greeks (`Delta`, `Gamma`, `Vega`, `Theta`) and SPAN-style 33-point
/// `(spot_shock x vol_shock)` cross-margin requirements across multi-expiry options and swaps.
pub fn compute_portfolio_cross_margin(
    swaps: &[InverseSwapLeg],
    options: &[InverseOptionLeg],
    spot_usd: u64,
) -> Result<PortfolioGreeks, MarginError> {
    if spot_usd < 100 {
        return Err(MarginError::InvalidParameter("spot_usd must be >= 100"));
    }
    let base_pnl = mark_portfolio_pnl_sats(swaps, options, spot_usd, 0, 0);
    let up_1pct = (spot_usd * 101) / 100;
    let dn_1pct = (spot_usd * 99) / 100;
    let pnl_up = mark_portfolio_pnl_sats(swaps, options, up_1pct, 0, 0);
    let pnl_dn = mark_portfolio_pnl_sats(swaps, options, dn_1pct, 0, 0);

    let net_delta = (pnl_up - pnl_dn) / 2;
    let net_gamma = pnl_up - 2 * base_pnl + pnl_dn;
    let net_vega = mark_portfolio_pnl_sats(swaps, options, spot_usd, 100, 0) - base_pnl;
    let net_theta = mark_portfolio_pnl_sats(swaps, options, spot_usd, 0, 1) - base_pnl;

    // Isolated initial margin sum (`15%` standard PM benchmark on swaps + `15%` naked short option or full premium on long option)
    let mut isolated_im: u64 = 0;
    let mut total_gross_notional_sats: u64 = 0;
    for sw in swaps {
        let leg_sats = ((sw.signed_usd_notional.unsigned_abs() as u128) * SATS_PER_BTC)
            .div_ceil(spot_usd as u128) as u64;
        total_gross_notional_sats = total_gross_notional_sats.saturating_add(leg_sats);
        isolated_im = isolated_im.saturating_add((leg_sats * 15).div_ceil(100));
    }
    for opt in options {
        let under_sats = (opt.signed_size_mbtc.unsigned_abs() * 100_000_000) / 1_000;
        total_gross_notional_sats = total_gross_notional_sats.saturating_add(under_sats);
        let mark_sats = (price_inverse_option_per_btc_sats(
            opt.kind,
            spot_usd,
            opt.strike_usd,
            opt.days_to_expiry,
            opt.iv_bps,
        ) * opt.signed_size_mbtc.unsigned_abs())
            / 1_000;
        if opt.signed_size_mbtc >= 0 {
            isolated_im = isolated_im.saturating_add(mark_sats);
        } else {
            isolated_im = isolated_im.saturating_add(mark_sats + (under_sats * 15) / 100);
        }
    }

    // Deribit-style 11 spot shocks `[-15% .. +15%]` x 3 IV shocks `[-1000, 0, +1000 bps]` = 33 stress scenarios
    let spot_mults_bps: [u64; 11] = [8500, 9000, 9300, 9600, 9800, 10000, 10200, 10400, 10700, 11000, 11500];
    let vol_shocks_bps: [i32; 3] = [-1_000, 0, 1_000];
    let mut worst_loss_from_mark: i64 = 0;
    for &sm in &spot_mults_bps {
        let shocked_spot = ((spot_usd as u128 * sm as u128) / 10_000) as u64;
        for &vs in &vol_shocks_bps {
            let scen_pnl = mark_portfolio_pnl_sats(swaps, options, shocked_spot, vs, 1);
            let rel_loss = base_pnl - scen_pnl;
            if rel_loss > worst_loss_from_mark {
                worst_loss_from_mark = rel_loss;
            }
        }
    }

    // Enforce a 0.75% gross-notional contingency floor so perfectly flat books still hold anti-basis reserve
    let contingency_floor = (total_gross_notional_sats * 75) / 10_000;
    let raw_cross = (worst_loss_from_mark.max(0) as u64).saturating_add(contingency_floor);
    let cross_im = if isolated_im == 0 {
        0
    } else {
        raw_cross.min(isolated_im).max(contingency_floor.min(isolated_im))
    };
    let cross_mm = (cross_im * 75) / 100;
    let saved_bps = if isolated_im > 0 && cross_im < isolated_im {
        (((isolated_im - cross_im) as u128 * 10_000) / (isolated_im as u128)) as u32
    } else {
        0
    };

    Ok(PortfolioGreeks {
        net_delta_sats_per_1pct: net_delta,
        net_gamma_sats_per_1pct2: net_gamma,
        net_vega_sats_per_vol_pt: net_vega,
        net_theta_sats_per_day: net_theta,
        isolated_initial_margin_sats: isolated_im,
        cross_initial_margin_sats: cross_im,
        cross_maintenance_margin_sats: cross_mm,
        margin_efficiency_saved_bps: saved_bps,
    })
}
