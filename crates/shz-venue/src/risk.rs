//! Liquidation risk for venue accounts.
//!
//! Every lot is a fully collateralized DLC leg whose payout is clamped to its two margins,
//! so an account can never owe more than it posted: the contract itself is the backstop.
//! This module adds the part a perps venue shows and enforces on top of that:
//!
//! - per-lot bankruptcy price (the lot pays its owner 0 at or beyond it);
//! - account margin ratio at the mark: exact clamped DLC value of the open lots divided by
//!   their notional in sats at the mark;
//! - the maintenance and bankruptcy prices of the whole position, found by bisection on that
//!   same exact value;
//! - a risk state (`flat`, `ok`, `warning`, `maintenance`, `bankrupt`);
//! - below maintenance, the partial-liquidation Dutch-auction plan from `shz_margin`, whose
//!   discount grows from the moment the breach was first seen.
//!
//! The venue never signs for an account. Below maintenance it accepts only orders that
//! reduce the position; the account's own client executes the plan with its own key.

use serde_json::{Value, json};
use shz_dex::{
    OrderSide,
    routing::positions::Lot,
};
use shz_margin::{CollateralAsset, InverseContractSpec, SATS_PER_BTC, ZeroFeePolicy, liquidation_auction::compute_partial_liquidation_tranche};

pub const MAINTENANCE_BPS: u32 = 500;
pub const WARNING_BPS: u32 = 750;
pub const TARGET_RESTORE_BPS: u32 = 800;
pub const MAX_DISCOUNT_BPS: u32 = 200;
pub const AUCTION_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Flat,
    Ok,
    Warning,
    Maintenance,
    Bankrupt,
}
impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Flat => "flat",
            State::Ok => "ok",
            State::Warning => "warning",
            State::Maintenance => "maintenance",
            State::Bankrupt => "bankrupt",
        }
    }
    /// Below maintenance: only position-reducing orders are accepted.
    pub fn reduce_only(self) -> bool {
        matches!(self, State::Maintenance | State::Bankrupt)
    }
}

fn spec(l: &Lot) -> Option<InverseContractSpec> {
    if l.qty == 0 || l.price == 0 || l.margin == 0 || l.opp_margin == 0 {
        return None;
    }
    let (long, short) = if l.side == OrderSide::Long { (l.margin, l.opp_margin) } else { (l.opp_margin, l.margin) };
    Some(InverseContractSpec {
        usd_notional: l.qty,
        entry_price_usd: l.price,
        long_margin_sats: long,
        short_margin_sats: short,
        collateral: CollateralAsset::VanillaBtc,
        fee_policy: ZeroFeePolicy::ZERO,
    })
}

/// Price at or beyond which the lot pays its owner nothing. `None` for a short covered
/// at 1x or more (no upside price wipes it).
pub fn lot_bankruptcy_price(l: &Lot) -> Option<u64> {
    let s = spec(l)?;
    if l.side == OrderSide::Long { Some(s.long_liquidation_price_usd()) } else { s.short_liquidation_price_usd() }
}

fn lot_bankrupt_at(l: &Lot, mark: u64) -> bool {
    match (l.side, lot_bankruptcy_price(l)) {
        (OrderSide::Long, Some(p)) => mark <= p,
        (OrderSide::Short, Some(p)) => mark >= p,
        _ => false,
    }
}

fn notional_usd(pos: &[Lot]) -> u64 {
    pos.iter().map(|l| l.qty).sum()
}

fn side(pos: &[Lot]) -> Option<OrderSide> {
    pos.first().map(|l| l.side)
}

/// Exact clamped DLC payout of the lots to their owner at `price` (as `Position::value_at`).
pub fn value_at(pos: &[Lot], price: u64) -> u64 {
    pos.iter().filter_map(|l| spec(l).map(|s| (l.side, s.payout_at_price(price))))
        .map(|(side, p)| if side == OrderSide::Long { p.long_sats } else { p.short_sats }).sum()
}

fn notional_sats(q: u64, price: u64) -> u128 {
    ((q as u128) * SATS_PER_BTC).div_ceil(price.max(1) as u128)
}

/// Exact clamped value of the open lots at `price`, over their notional in sats, in bps.
pub fn margin_bps(pos: &[Lot], price: u64) -> Option<u64> {
    let q = notional_usd(pos);
    if q == 0 || price == 0 {
        return None;
    }
    Some(((value_at(pos, price) as u128) * 10_000 / notional_sats(q, price).max(1)) as u64)
}

/// The price, on the side that hurts this position, where the margin ratio falls below `bps`:
/// for a long the highest price at which it is below, for a short the lowest. `None` when no
/// price in range gets there (a covered short).
pub fn threshold_price(pos: &[Lot], mark: u64, bps: u64) -> Option<u64> {
    let side = side(pos)?;
    let below = |p: u64| margin_bps(pos, p).is_some_and(|r| r < bps);
    let top = pos.iter().map(|l| l.price).max().unwrap_or(mark).max(mark);
    let bottom = pos.iter().map(|l| l.price).min().unwrap_or(mark).min(mark);
    match side {
        OrderSide::Long => {
            // below(p) holds for p <= x. Bracket: lo breached, hi not.
            let (mut lo, mut hi) = (1u64, top.saturating_mul(4));
            if !below(lo) {
                return None;
            }
            if below(hi) {
                return Some(hi);
            }
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if below(mid) { lo = mid } else { hi = mid }
            }
            Some(lo)
        }
        OrderSide::Short => {
            // below(p) holds for p >= x on the upside. Bracket: lo not breached, hi breached.
            let (mut lo, mut hi) = ((bottom / 4).max(1), top.saturating_mul(10));
            if !below(hi) {
                return None;
            }
            if below(lo) {
                return Some(lo);
            }
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if below(mid) { hi = mid } else { lo = mid }
            }
            Some(hi)
        }
    }
}

pub fn state(pos: &[Lot], mark: u64) -> State {
    let Some(r) = margin_bps(pos, mark) else { return State::Flat };
    if pos.iter().any(|l| lot_bankrupt_at(l, mark)) {
        State::Bankrupt
    } else if r < MAINTENANCE_BPS as u64 {
        State::Maintenance
    } else if r < WARNING_BPS as u64 {
        State::Warning
    } else {
        State::Ok
    }
}

/// Full risk view of a position at `mark`. `breach_elapsed_ms` is the time since the account
/// was first seen below maintenance (drives the auction discount).
pub fn view(pos: &[Lot], mark: Option<u64>, breach_elapsed_ms: Option<u64>) -> Value {
    let lots: Vec<Value> = pos.iter().map(|l| json!({"entry_usd": l.price, "qty_usd": l.qty, "bankruptcy_price_usd": lot_bankruptcy_price(l)})).collect();
    let params = json!({"maintenance_bps": MAINTENANCE_BPS, "warning_bps": WARNING_BPS, "target_restore_bps": TARGET_RESTORE_BPS,
                        "max_discount_bps": MAX_DISCOUNT_BPS, "auction_ms": AUCTION_MS});
    let Some(mark) = mark.filter(|_| notional_usd(pos) > 0) else {
        return json!({"state": if notional_usd(pos) == 0 { "flat" } else { "unknown" }, "lots": lots, "params": params});
    };
    let st = state(pos, mark);
    let side = side(pos).expect("lots");
    let q = notional_usd(pos);
    let equity = value_at(pos, mark);
    let mut v = json!({
        "state": st.name(), "reduce_only": st.reduce_only(), "mark_usd": mark,
        "margin_bps": margin_bps(pos, mark), "equity_sats": equity, "notional_usd": q,
        "liquidation_price_usd": threshold_price(pos, mark, MAINTENANCE_BPS as u64),
        "bankruptcy_price_usd": threshold_price(pos, mark, 1),
        "lots": lots, "params": params,
    });
    if st.reduce_only()
        && let Ok(plan) = compute_partial_liquidation_tranche(side == OrderSide::Long, q, equity, mark, MAINTENANCE_BPS,
            TARGET_RESTORE_BPS, breach_elapsed_ms.unwrap_or(0), AUCTION_MS, MAX_DISCOUNT_BPS)
    {
        let reduce = if side == OrderSide::Long { "short" } else { "long" };
        v["liquidation"] = json!({
            "reduce_side": reduce,
            "tranche_usd": plan.tranche_notional_usd,
            "limit_usd": plan.auction_fill_price_usd,
            "auction_discount_bps": plan.auction_discount_bps,
            "penalty_sats": plan.auction_penalty_sats,
            "post_margin_bps": plan.post_tranche_margin_bps,
            "elapsed_ms": breach_elapsed_ms.unwrap_or(0),
        });
    }
    v
}

/// Below maintenance only an order on the opposite side, no larger than the committed
/// position, is accepted. Cancels are always accepted (checked by the caller).
pub fn gate(pos: &[Lot], mark: Option<u64>, order_side: OrderSide, quantity: u64) -> Result<(), String> {
    let Some(mark) = mark else { return Ok(()) };
    let st = state(pos, mark);
    if !st.reduce_only() {
        return Ok(());
    }
    let held = notional_usd(pos);
    if side(pos) == Some(order_side) || quantity > held {
        return Err(format!("account is {} (margin below {} bps): only orders that reduce the position, up to {held} USD, are accepted",
                           st.name(), MAINTENANCE_BPS));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const P0: u64 = 100_000;

    /// `qty` USD at `price`, both sides at `lev_x10` tenths of leverage (10x = 100).
    fn lot(side: OrderSide, qty: u64, price: u64, lev_x10: u32) -> Lot {
        let m = InverseContractSpec::margin_for_leverage_bps(qty, price, lev_x10 * 1_000).unwrap();
        Lot { side, qty, price, margin: m, opp_margin: m }
    }

    #[test]
    fn lot_bankruptcy_prices_match_the_contract_spec() {
        // 10x from 100k: long wiped at 90,909, short at 111,112 (shz-margin's own test values).
        assert_eq!(lot_bankruptcy_price(&lot(OrderSide::Long, 1_000, P0, 100)), Some(90_909));
        assert_eq!(lot_bankruptcy_price(&lot(OrderSide::Short, 1_000, P0, 100)), Some(111_112));
        // a 1x short is a covered synthetic dollar: no upside price wipes it
        assert_eq!(lot_bankruptcy_price(&lot(OrderSide::Short, 1_000, P0, 10)), None);
    }

    #[test]
    fn margin_ratio_and_states_walk_down_with_the_mark() {
        let pos = [lot(OrderSide::Long, 1_000, P0, 100)];
        // at entry a 10x lot holds 10% of notional
        assert_eq!(margin_bps(&pos, P0), Some(1_000));
        assert_eq!(state(&pos, P0), State::Ok);
        let liq = threshold_price(&pos, P0, MAINTENANCE_BPS as u64).unwrap();
        let bk = threshold_price(&pos, P0, 1).unwrap();
        // maintenance (5%) sits between entry and bankruptcy, about halfway for 10x
        assert!(bk < liq && liq < P0, "bk {bk} liq {liq}");
        assert!((94_000..96_000).contains(&liq), "liq {liq}");
        assert!(margin_bps(&pos, liq).unwrap() < MAINTENANCE_BPS as u64);
        assert!(margin_bps(&pos, liq + 1).unwrap() >= MAINTENANCE_BPS as u64);
        assert_eq!(state(&pos, liq + 1_000), State::Warning);
        assert_eq!(state(&pos, liq), State::Maintenance);
        assert_eq!(state(&pos, 90_909), State::Bankrupt);
        assert_eq!(value_at(&pos, 80_000), 0, "a loss never exceeds the lot margin");
    }

    #[test]
    fn short_thresholds_are_on_the_upside_and_covered_shorts_never_liquidate() {
        let pos = [lot(OrderSide::Short, 1_000, P0, 50)];
        let liq = threshold_price(&pos, P0, MAINTENANCE_BPS as u64).unwrap();
        assert!(liq > P0 && liq < 120_000, "liq {liq}");
        assert!(margin_bps(&pos, liq).unwrap() < MAINTENANCE_BPS as u64);
        assert!(margin_bps(&pos, liq - 1).unwrap() >= MAINTENANCE_BPS as u64);
        assert_eq!(threshold_price(&[lot(OrderSide::Short, 1_000, P0, 10)], P0, MAINTENANCE_BPS as u64), None);
        assert_eq!(state(&[lot(OrderSide::Short, 1_000, P0, 10)], 1_000_000), State::Ok);
    }

    #[test]
    fn several_lots_at_different_entries_and_leverage() {
        let pos = [lot(OrderSide::Long, 500, 100_000, 100), lot(OrderSide::Long, 300, 98_000, 50), lot(OrderSide::Long, 200, 101_000, 20)];
        let liq = threshold_price(&pos, 100_000, MAINTENANCE_BPS as u64).unwrap();
        assert!(margin_bps(&pos, liq).unwrap() < MAINTENANCE_BPS as u64 && margin_bps(&pos, liq + 1).unwrap() >= MAINTENANCE_BPS as u64);
        // the 10x lot is wiped first; the account turns bankrupt as soon as any lot is
        assert_eq!(state(&pos, lot_bankruptcy_price(&pos[0]).unwrap()), State::Bankrupt);
    }

    #[test]
    fn plan_and_gate_below_maintenance() {
        let pos = [lot(OrderSide::Long, 1_000, P0, 100)];
        let liq = threshold_price(&pos, P0, MAINTENANCE_BPS as u64).unwrap();
        let v = view(&pos, Some(liq), Some(30_000));
        assert_eq!(v["state"], "maintenance");
        assert_eq!(v["reduce_only"], true);
        let l = &v["liquidation"];
        assert_eq!(l["reduce_side"], "short");
        let tranche = l["tranche_usd"].as_u64().unwrap();
        assert!(tranche > 0 && tranche <= 1_000);
        assert!(l["post_margin_bps"].as_u64().unwrap() >= TARGET_RESTORE_BPS as u64 - 10);
        // half the auction elapsed: half the maximum discount, below the mark for a long
        assert_eq!(l["auction_discount_bps"], MAX_DISCOUNT_BPS / 2);
        assert!(l["limit_usd"].as_u64().unwrap() < liq);
        // healthy accounts carry no plan and are not gated
        assert!(view(&pos, Some(P0), None).get("liquidation").is_none());
        assert!(gate(&pos, Some(P0), OrderSide::Long, 5_000).is_ok());
        // below maintenance: increasing or flipping is refused, reducing is accepted
        assert!(gate(&pos, Some(liq), OrderSide::Long, 5).is_err());
        assert!(gate(&pos, Some(liq), OrderSide::Short, 1_001).is_err());
        assert!(gate(&pos, Some(liq), OrderSide::Short, 1_000).is_ok());
        assert!(gate(&pos, None, OrderSide::Long, 5).is_ok(), "no mark: no gate");
        assert_eq!(view(&[], Some(P0), None)["state"], "flat");
    }
}
