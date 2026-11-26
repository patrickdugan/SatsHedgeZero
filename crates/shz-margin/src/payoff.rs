//! Worst-case-loss (max-loss) margin engine.
//!
//! Margin for a portfolio of legs is its worst-case loss over the DLC price-outcome
//! domain, computed per collateral asset. A new leg needs only the increase in the
//! portfolio's worst-case loss ([`margin_delta`]). See `docs/SHZ_MAXLOSS_MARGIN.md`.
//!
//! # Units
//!
//! * `Asset::Btc`: satoshis.
//! * `Asset::Usd`: micro-USD (1e-6 USD, the 6-decimal convention of USDT).
//!
//! # Exactness
//!
//! [`pnl`] returns `floor` of the exact rational PnL of the whole portfolio in one
//! asset at one price (a single rounding, in the direction that overstates loss).
//! Between breakpoints every leg is affine in `1/P` (BTC-settled legs) or in `P`
//! (USD-settled legs), so the total is affine and monotone and its extremes sit at
//! the breakpoints; a single floor of a monotone function is monotone, so
//! [`max_loss`] is the exact minimum over every integer price of the domain.
//! Per-lot DLC payouts round half-even each, so the sum of individually rounded
//! lot payouts can differ from [`pnl`] by under one satoshi per lot; the clamp
//! tests are exact rational comparisons.
//!
//! # Input bounds
//!
//! Intermediate products use `i128`/`u128` (and exact big integers for clamp tests
//! and fraction sums). [`validate`] checks the documented bounds: prices and
//! `qty_usd` below `2^40`, BTC-denominated amounts below `2^53`, `qty_btc_e8` below
//! `2^50`.

use crate::{CollateralAsset, InverseContractSpec, ZeroFeePolicy, SATS_PER_BTC};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;

const MAX_PRICE: u64 = 1 << 40;
const MAX_QTY_USD: u64 = 1 << 40;
const MAX_SATS: u64 = 1 << 53;
const MAX_QTY_BTC_E8: u64 = 1 << 50;
/// Linear (USD-settled) payoffs are `qty_btc_e8 * (P - K)` in 1e-8 BTC * USD; this is
/// the divisor that converts to micro-USD (`1e8 / 1e6`).
const LINEAR_TO_MICRO_USD: i128 = 100;
const E8: u64 = 100_000_000;

/// Collateral / settlement asset. Margin never nets across assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Asset {
    /// Satoshis.
    Btc,
    /// A Bitcoin-native USD stablecoin (RGB USDT, Taproot Assets), micro-USD.
    Usd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Long,
    Short,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptionKind {
    Call,
    Put,
}

/// One open perpetual lot with the semantics of the router's `positions::Lot`:
/// `margin_sats` is this account's own margin, `opp_margin_sats` the counterparty's.
/// Settles in BTC through `InverseContractSpec::payout_at_price`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpLot {
    pub side: Side,
    pub qty_usd: u64,
    pub entry_usd: u64,
    pub margin_sats: u64,
    pub opp_margin_sats: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Leg {
    /// BTC-settled inverse perpetual lot.
    Perp(PerpLot),
    /// BTC-settled inverse option. Call pays `Q*1e8*max(0, 1/K - 1/P)` sats, put pays
    /// `Q*1e8*max(0, 1/P - 1/K)` sats. The long pays `premium_sats`, the short receives it.
    InverseOption {
        kind: OptionKind,
        long: bool,
        qty_usd: u64,
        strike_usd: u64,
        premium_sats: u64,
    },
    /// USD-settled linear option: call pays `Q*(P-K)+` USD, put `Q*(K-P)+` USD with
    /// `Q = qty_btc_e8 / 1e8` BTC. `premium_usd` is in micro-USD.
    LinearOption {
        kind: OptionKind,
        long: bool,
        qty_btc_e8: u64,
        strike_usd: u64,
        premium_usd: u64,
    },
    /// A constant already-realized PnL in `asset` (a closed perp lot).
    Realized { asset: Asset, pnl: i128 },
}

/// DLC outcome domain: every integer price in `[p_min, p_max]` is an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceDomain {
    pub p_min: u64,
    pub p_max: u64,
}

impl PriceDomain {
    /// `[1, 2^num_bits - 1]`, the digit-decomposition domain of a DLC oracle.
    pub fn from_bits(num_bits: u8) -> Self {
        assert!((1..=40).contains(&num_bits), "num_bits must be in 1..=40");
        Self { p_min: 1, p_max: (1u64 << num_bits) - 1 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayoffError {
    #[error("domain must satisfy 1 <= p_min <= p_max < 2^40")]
    Domain,
    #[error("leg {0} has an amount or price outside the documented bounds")]
    Bounds(usize),
}

/// Check the documented input bounds. [`pnl`] and [`max_loss`] assume them.
pub fn validate(legs: &[Leg], domain: PriceDomain) -> Result<(), PayoffError> {
    if domain.p_min == 0 || domain.p_min > domain.p_max || domain.p_max >= MAX_PRICE {
        return Err(PayoffError::Domain);
    }
    for (i, leg) in legs.iter().enumerate() {
        let ok = match *leg {
            Leg::Perp(l) => {
                l.entry_usd >= 1
                    && l.entry_usd < MAX_PRICE
                    && l.qty_usd < MAX_QTY_USD
                    && l.margin_sats < MAX_SATS
                    && l.opp_margin_sats < MAX_SATS
            }
            Leg::InverseOption { qty_usd, strike_usd, premium_sats, .. } => {
                (1..MAX_PRICE).contains(&strike_usd) && qty_usd < MAX_QTY_USD && premium_sats < MAX_SATS
            }
            Leg::LinearOption { qty_btc_e8, strike_usd, premium_usd, .. } => {
                strike_usd < MAX_PRICE && qty_btc_e8 < MAX_QTY_BTC_E8 && premium_usd < MAX_SATS
            }
            Leg::Realized { pnl, .. } => pnl.unsigned_abs() < (1u128 << 100),
        };
        if !ok {
            return Err(PayoffError::Bounds(i));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal exact big integer (little-endian u64 limbs) for clamp tests and
// fraction sums whose products exceed u128.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Big(Vec<u64>);

impl Big {
    fn one() -> Self {
        Big(vec![1])
    }
    fn zero() -> Self {
        Big(Vec::new())
    }
    fn trim(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }
    fn mul_u64(&mut self, m: u64) {
        let mut carry: u128 = 0;
        for limb in &mut self.0 {
            let t = (*limb as u128) * (m as u128) + carry;
            *limb = t as u64;
            carry = t >> 64;
        }
        if carry > 0 {
            self.0.push(carry as u64);
        }
        self.trim();
    }
    fn add(&mut self, o: &Big) {
        let mut carry = 0u128;
        let n = self.0.len().max(o.0.len());
        self.0.resize(n, 0);
        for i in 0..n {
            let t = self.0[i] as u128 + *o.0.get(i).unwrap_or(&0) as u128 + carry;
            self.0[i] = t as u64;
            carry = t >> 64;
        }
        if carry > 0 {
            self.0.push(carry as u64);
        }
    }
    fn cmp_big(&self, o: &Big) -> Ordering {
        self.0
            .len()
            .cmp(&o.0.len())
            .then_with(|| self.0.iter().rev().cmp(o.0.iter().rev()))
    }
}

fn prod_big(f: &[u64]) -> Big {
    let mut b = Big::one();
    for &x in f {
        b.mul_u64(x);
    }
    b
}

/// `prod(a) >= prod(b)` over unsigned factors, exact.
fn prod_ge(a: &[u64], b: &[u64]) -> bool {
    fn fast(f: &[u64]) -> Option<u128> {
        f.iter().try_fold(1u128, |acc, &x| acc.checked_mul(x as u128))
    }
    match (fast(a), fast(b)) {
        (Some(x), Some(y)) => x >= y,
        _ => prod_big(a).cmp_big(&prod_big(b)) != Ordering::Less,
    }
}

/// `floor(sum r_i / d_i)` for `0 <= r_i < d_i`, exact.
fn floor_frac_sum(fr: &[(u64, u64)]) -> usize {
    if fr.len() < 2 {
        return 0;
    }
    let mut n = Big::zero();
    let mut d = Big::one();
    for &(r, dd) in fr {
        n.mul_u64(dd);
        let mut t = d.clone();
        t.mul_u64(r);
        n.add(&t);
        d.mul_u64(dd);
    }
    let mut m = 0usize;
    let mut thr = d.clone();
    while m < fr.len() && n.cmp_big(&thr) != Ordering::Less {
        m += 1;
        thr.add(&d);
    }
    m
}

/// `floor(base + sum n_i / d_i)` exactly.
fn floor_total(base: i128, terms: &[(i128, u64)]) -> i128 {
    let mut acc = base;
    let mut fr: Vec<(u64, u64)> = Vec::new();
    for &(n, d) in terms {
        let dd = d as i128;
        acc += n.div_euclid(dd);
        let r = n.rem_euclid(dd) as u64;
        if r != 0 {
            fr.push((r, d));
        }
    }
    acc + floor_frac_sum(&fr) as i128
}

// ---------------------------------------------------------------------------
// PnL
// ---------------------------------------------------------------------------

fn sign(side: Side) -> i128 {
    match side {
        Side::Long => 1,
        Side::Short => -1,
    }
}

/// Accumulator for BTC-settled PnL: `int + sum coef[E]/E + b/P`.
#[derive(Default)]
struct BtcAcc {
    int: i128,
    coef: BTreeMap<u64, i128>,
    b: i128,
}

impl BtcAcc {
    fn finish(self, price: u64) -> i128 {
        let mut terms: Vec<(i128, u64)> = self.coef.into_iter().map(|(e, c)| (c, e)).collect();
        terms.push((self.b, price));
        floor_total(self.int, &terms)
    }
}

fn perp_into(acc: &mut BtcAcc, l: &PerpLot, price: u64) {
    let s = sign(l.side);
    let q = l.qty_usd as i128 * SATS_PER_BTC as i128;
    let diff = price.abs_diff(l.entry_usd);
    // sigma = sign of the unclamped PnL u = s * Q*1e8*(P - P0) / (P0 * P).
    let sigma = s * match price.cmp(&l.entry_usd) {
        Ordering::Greater => 1,
        Ordering::Equal => 0,
        Ordering::Less => -1,
    };
    let lhs = [l.qty_usd, E8, diff];
    // u <= -own  (loss reaches the posted margin)
    let lo = match sigma {
        -1 => prod_ge(&lhs, &[l.margin_sats, l.entry_usd, price]),
        0 => l.margin_sats == 0,
        _ => false,
    };
    // u >= opp  (gain reaches the counterparty margin)
    let hi = match sigma {
        1 => prod_ge(&lhs, &[l.opp_margin_sats, l.entry_usd, price]),
        0 => l.opp_margin_sats == 0,
        _ => false,
    };
    if lo {
        acc.int -= l.margin_sats as i128;
    } else if hi {
        acc.int += l.opp_margin_sats as i128;
    } else {
        *acc.coef.entry(l.entry_usd).or_insert(0) += s * q;
        acc.b -= s * q;
    }
}

fn inverse_option_into(acc: &mut BtcAcc, kind: OptionKind, long: bool, qty_usd: u64, strike: u64, premium: u64, price: u64) {
    let s: i128 = if long { 1 } else { -1 };
    let q = qty_usd as i128 * SATS_PER_BTC as i128;
    acc.int += -s * premium as i128;
    match kind {
        OptionKind::Call if price > strike => {
            *acc.coef.entry(strike).or_insert(0) += s * q;
            acc.b -= s * q;
        }
        OptionKind::Put if price < strike => {
            *acc.coef.entry(strike).or_insert(0) -= s * q;
            acc.b += s * q;
        }
        _ => {}
    }
}

fn btc_pnl(legs: &[Leg], price: u64) -> i128 {
    let mut acc = BtcAcc::default();
    for leg in legs {
        match *leg {
            Leg::Perp(l) => perp_into(&mut acc, &l, price),
            Leg::InverseOption { kind, long, qty_usd, strike_usd, premium_sats } => {
                inverse_option_into(&mut acc, kind, long, qty_usd, strike_usd, premium_sats, price)
            }
            Leg::Realized { asset: Asset::Btc, pnl } => acc.int += pnl,
            _ => {}
        }
    }
    acc.finish(price)
}

fn usd_pnl(legs: &[Leg], price: u64) -> i128 {
    let mut lin: i128 = 0; // 1e-8 BTC * USD
    let mut micro: i128 = 0;
    for leg in legs {
        match *leg {
            Leg::LinearOption { kind, long, qty_btc_e8, strike_usd, premium_usd } => {
                let s: i128 = if long { 1 } else { -1 };
                let intrinsic = match kind {
                    OptionKind::Call => price.saturating_sub(strike_usd),
                    OptionKind::Put => strike_usd.saturating_sub(price),
                } as i128;
                lin += s * qty_btc_e8 as i128 * intrinsic;
                micro -= s * premium_usd as i128;
            }
            Leg::Realized { asset: Asset::Usd, pnl } => micro += pnl,
            _ => {}
        }
    }
    micro + lin.div_euclid(LINEAR_TO_MICRO_USD)
}

/// Exact total PnL of the legs settled in `asset` at `price`, as one floored value
/// (negative is a loss). `price` must be at least 1.
pub fn pnl(legs: &[Leg], asset: Asset, price: u64) -> i128 {
    debug_assert!(price >= 1);
    match asset {
        Asset::Btc => btc_pnl(legs, price),
        Asset::Usd => usd_pnl(legs, price),
    }
}

// ---------------------------------------------------------------------------
// Breakpoints and max loss
// ---------------------------------------------------------------------------

/// Real-valued clamp prices of a perp lot: `floor(P0*Q1e8 / (Q1e8 + M_long*P0))` and,
/// when the short side is levered, `ceil(P0*Q1e8 / (Q1e8 - M_short*P0))`.
/// These are `long_liquidation_price_usd` / `short_liquidation_price_usd` of the lot.
fn perp_clamp_prices(l: &PerpLot) -> (u64, Option<u64>) {
    let (m_long, m_short) = match l.side {
        Side::Long => (l.margin_sats, l.opp_margin_sats),
        Side::Short => (l.opp_margin_sats, l.margin_sats),
    };
    let spec = InverseContractSpec {
        usd_notional: l.qty_usd,
        entry_price_usd: l.entry_usd,
        long_margin_sats: m_long,
        short_margin_sats: m_short,
        collateral: CollateralAsset::VanillaBtc,
        fee_policy: ZeroFeePolicy::ZERO,
    };
    (spec.long_liquidation_price_usd(), spec.short_liquidation_price_usd())
}

/// Every integer price at which the portfolio's `asset` payoff can change shape, with
/// one neighbour on each side, clipped to the domain and sorted.
pub fn breakpoints(legs: &[Leg], asset: Asset, domain: PriceDomain) -> Vec<u64> {
    let mut raw: Vec<u64> = vec![domain.p_min, domain.p_max];
    for leg in legs {
        match (*leg, asset) {
            (Leg::Perp(l), Asset::Btc) if l.qty_usd > 0 => {
                raw.push(l.entry_usd);
                let (down, up) = perp_clamp_prices(&l);
                raw.push(down);
                if let Some(u) = up {
                    raw.push(u);
                }
            }
            (Leg::InverseOption { strike_usd, .. }, Asset::Btc) => raw.push(strike_usd),
            (Leg::LinearOption { strike_usd, .. }, Asset::Usd) => raw.push(strike_usd),
            _ => {}
        }
    }
    let mut out: Vec<u64> = Vec::with_capacity(raw.len() * 4);
    for c in raw {
        for p in [c.saturating_sub(1), c, c.saturating_add(1), c.saturating_add(2)] {
            if p >= domain.p_min && p <= domain.p_max {
                out.push(p);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The worst loss of `asset` over the domain and the lowest price where it occurs.
/// `(0, p_min)` when the portfolio cannot lose.
pub fn worst_case(legs: &[Leg], asset: Asset, domain: PriceDomain) -> (u128, u64) {
    debug_assert!(validate(legs, domain).is_ok());
    let mut worst: i128 = 0;
    let mut at = domain.p_min;
    for p in breakpoints(legs, asset, domain) {
        let v = pnl(legs, asset, p);
        if v < worst {
            worst = v;
            at = p;
        }
    }
    (worst.unsigned_abs(), at)
}

/// Exact worst-case loss of the legs in `asset` over every integer price of `domain`.
pub fn max_loss(legs: &[Leg], asset: Asset, domain: PriceDomain) -> u128 {
    worst_case(legs, asset, domain).0
}

/// Extra collateral of `asset` the `new_legs` need on top of `existing`:
/// `max(0, max_loss(existing + new) - max_loss(existing))`.
pub fn margin_delta(existing: &[Leg], new_legs: &[Leg], asset: Asset, domain: PriceDomain) -> u128 {
    let mut all = Vec::with_capacity(existing.len() + new_legs.len());
    all.extend_from_slice(existing);
    all.extend_from_slice(new_legs);
    max_loss(&all, asset, domain).saturating_sub(max_loss(existing, asset, domain))
}

/// Collateral required per asset (`Btc` sats, `Usd` micro-USD).
pub fn required_collateral(legs: &[Leg], domain: PriceDomain) -> BTreeMap<Asset, u128> {
    [Asset::Btc, Asset::Usd].into_iter().map(|a| (a, max_loss(legs, a, domain))).collect()
}

/// True when the posted collateral of every asset covers that asset's worst-case loss.
/// An asset missing from `collateral_by_asset` counts as zero. A portfolio funded this
/// way cannot owe more than it posted at any outcome, so it needs no liquidation.
pub fn fully_funded(legs: &[Leg], collateral_by_asset: &BTreeMap<Asset, u128>, domain: PriceDomain) -> bool {
    [Asset::Btc, Asset::Usd]
        .into_iter()
        .all(|a| collateral_by_asset.get(&a).copied().unwrap_or(0) >= max_loss(legs, a, domain))
}

// ---------------------------------------------------------------------------
// Perp fills, FIFO like `shz_dex::routing::positions::settle`
// ---------------------------------------------------------------------------

/// Result of netting one perp fill against open lots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerpFill {
    /// Lots after the fill, oldest first (a flip appends one new lot).
    pub lots: Vec<PerpLot>,
    pub closed_usd: u64,
    /// Own margin of the closed slices.
    pub released_margin_sats: u64,
    /// DLC payout of the closed slices at the fill price.
    pub payout_sats: u64,
}

impl PerpFill {
    /// Realized PnL of the closed slices: payout minus released margin.
    pub fn realized_pnl_sats(&self) -> i128 {
        self.payout_sats as i128 - self.released_margin_sats as i128
    }
}

fn part(total: u64, x: u64, of: u64) -> u64 {
    (total as u128 * x as u128 / of as u128) as u64
}

fn lot_payout(l: &PerpLot, x: u64, m: u64, o: u64, price: u64) -> u64 {
    let (long, short) = if l.side == Side::Long { (m, o) } else { (o, m) };
    let spec = InverseContractSpec {
        usd_notional: x,
        entry_price_usd: l.entry_usd,
        long_margin_sats: long,
        short_margin_sats: short,
        collateral: CollateralAsset::VanillaBtc,
        fee_policy: ZeroFeePolicy::ZERO,
    };
    let p = spec.payout_at_price(price);
    if l.side == Side::Long {
        p.long_sats
    } else {
        p.short_sats
    }
}

/// Apply `fill` (a lot at `fill.entry_usd`, the settlement price of what it closes) to
/// `lots`: opposite-side lots close oldest first, each valued as its opening DLC leg
/// pays at the fill price, margins split pro rata; any excess quantity becomes a new lot.
pub fn apply_perp_fill(lots: &[PerpLot], fill: PerpLot) -> PerpFill {
    let mut out: Vec<PerpLot> = lots.to_vec();
    let mut left = fill.qty_usd;
    let (mut released, mut payout) = (0u64, 0u64);
    let mut i = 0;
    while left > 0 && i < out.len() {
        if out[i].side == fill.side {
            i += 1;
            continue;
        }
        let lot = &mut out[i];
        let x = left.min(lot.qty_usd);
        let (m, o) = if x == lot.qty_usd {
            (lot.margin_sats, lot.opp_margin_sats)
        } else {
            (part(lot.margin_sats, x, lot.qty_usd), part(lot.opp_margin_sats, x, lot.qty_usd))
        };
        payout += lot_payout(lot, x, m, o, fill.entry_usd);
        released += m;
        lot.qty_usd -= x;
        lot.margin_sats -= m;
        lot.opp_margin_sats -= o;
        left -= x;
        if lot.qty_usd == 0 {
            out.remove(i);
        } else {
            i += 1;
        }
    }
    let closed = fill.qty_usd - left;
    if left > 0 {
        let closed_margin = if closed == 0 { 0 } else { part(fill.margin_sats, closed, fill.qty_usd) };
        let opp_open = if closed == 0 {
            fill.opp_margin_sats
        } else {
            fill.opp_margin_sats - part(fill.opp_margin_sats, closed, fill.qty_usd)
        };
        out.push(PerpLot {
            side: fill.side,
            qty_usd: left,
            entry_usd: fill.entry_usd,
            margin_sats: fill.margin_sats - closed_margin,
            opp_margin_sats: opp_open,
        });
    }
    PerpFill { lots: out, closed_usd: closed, released_margin_sats: released, payout_sats: payout }
}

/// Portfolio after netting a perp fill: perp lots replaced by the post-fill lots, the
/// closed slices' realized PnL added as a constant BTC leg, all other legs untouched.
pub fn legs_after_perp_fill(existing: &[Leg], fill: PerpLot) -> Vec<Leg> {
    let lots: Vec<PerpLot> = existing
        .iter()
        .filter_map(|l| if let Leg::Perp(p) = l { Some(*p) } else { None })
        .collect();
    let res = apply_perp_fill(&lots, fill);
    let mut after: Vec<Leg> = existing.iter().copied().filter(|l| !matches!(l, Leg::Perp(_))).collect();
    after.extend(res.lots.iter().copied().map(Leg::Perp));
    let realized = res.realized_pnl_sats();
    if realized != 0 {
        after.push(Leg::Realized { asset: Asset::Btc, pnl: realized });
    }
    after
}

/// Extra BTC collateral a perp fill needs: `max(0, max_loss(after) - max_loss(existing))`
/// where `after` is [`legs_after_perp_fill`]. A fill that only closes lots needs 0
/// (unless the closed lots were hedging other legs); a flip needs only the excess.
pub fn margin_delta_perp_fill(existing: &[Leg], fill: PerpLot, domain: PriceDomain) -> u128 {
    let after = legs_after_perp_fill(existing, fill);
    max_loss(&after, Asset::Btc, domain).saturating_sub(max_loss(existing, Asset::Btc, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn range(&mut self, lo: u64, hi: u64) -> u64 {
            lo + self.next() % (hi - lo + 1)
        }
        fn flip(&mut self) -> bool {
            self.next() & 1 == 1
        }
    }

    fn dom(p_max: u64) -> PriceDomain {
        PriceDomain { p_min: 1, p_max }
    }

    fn rand_side(r: &mut Rng) -> Side {
        if r.flip() {
            Side::Long
        } else {
            Side::Short
        }
    }

    fn rand_kind(r: &mut Rng) -> OptionKind {
        if r.flip() {
            OptionKind::Call
        } else {
            OptionKind::Put
        }
    }

    fn rand_leg(r: &mut Rng, p_max: u64) -> Leg {
        match r.range(0, 3) {
            0 | 1 => {
                let entry = r.range(1, p_max);
                let q = r.range(1, 40);
                let full = q * 100_000_000 / entry;
                Leg::Perp(PerpLot {
                    side: rand_side(r),
                    qty_usd: q,
                    entry_usd: entry,
                    margin_sats: r.range(0, full.max(1) * 2),
                    opp_margin_sats: r.range(0, full.max(1) * 2),
                })
            }
            2 => Leg::InverseOption {
                kind: rand_kind(r),
                long: r.flip(),
                qty_usd: r.range(1, 40),
                strike_usd: r.range(1, p_max),
                premium_sats: r.range(0, 500_000),
            },
            _ => Leg::LinearOption {
                kind: rand_kind(r),
                long: r.flip(),
                qty_btc_e8: r.range(1, 300_000_000),
                strike_usd: r.range(1, p_max),
                premium_usd: r.range(0, 2_000_000),
            },
        }
    }

    fn brute(legs: &[Leg], asset: Asset, d: PriceDomain) -> u128 {
        let worst = (d.p_min..=d.p_max).map(|p| pnl(legs, asset, p)).min().unwrap().min(0);
        worst.unsigned_abs()
    }

    #[test]
    fn breakpoint_max_loss_equals_brute_force_on_every_integer_price() {
        let mut r = Rng(0x9E37_79B9_7F4A_7C15);
        let mut nonzero = 0;
        for case in 0..400 {
            let p_max = [63u64, 127, 255, 511][case % 4];
            let d = dom(p_max);
            let n = r.range(1, 8) as usize;
            let legs: Vec<Leg> = (0..n).map(|_| rand_leg(&mut r, p_max)).collect();
            assert_eq!(validate(&legs, d), Ok(()));
            for asset in [Asset::Btc, Asset::Usd] {
                let got = max_loss(&legs, asset, d);
                let want = brute(&legs, asset, d);
                assert_eq!(got, want, "case {case} {asset:?} legs {legs:?}");
                if want > 0 {
                    nonzero += 1;
                }
            }
        }
        assert!(nonzero > 300, "generator must produce losing portfolios, got {nonzero}");
    }

    #[test]
    fn domain_not_starting_at_one() {
        let mut r = Rng(7);
        for _ in 0..100 {
            let legs: Vec<Leg> = (0..5).map(|_| rand_leg(&mut r, 200)).collect();
            let d = PriceDomain { p_min: r.range(20, 60), p_max: r.range(100, 255) };
            for asset in [Asset::Btc, Asset::Usd] {
                assert_eq!(max_loss(&legs, asset, d), brute(&legs, asset, d));
            }
        }
    }

    #[test]
    fn pnl_matches_dex_lot_payout_within_rounding() {
        // A single lot has one term so the floor model and the DLC payout agree to < 1 sat.
        let mut r = Rng(11);
        for _ in 0..500 {
            let entry = r.range(1, 300);
            let q = r.range(1, 60);
            let lot = PerpLot {
                side: rand_side(&mut r),
                qty_usd: q,
                entry_usd: entry,
                margin_sats: r.range(0, 800_000),
                opp_margin_sats: r.range(0, 800_000),
            };
            let p = r.range(1, 400);
            let paid = lot_payout(&lot, q, lot.margin_sats, lot.opp_margin_sats, p) as i128;
            let want = paid - lot.margin_sats as i128;
            let got = pnl(&[Leg::Perp(lot)], Asset::Btc, p);
            assert!((got - want).abs() <= 1, "lot {lot:?} p {p} got {got} want {want}");
        }
    }

    #[test]
    fn floor_total_matches_u128_reference_and_multi_limb_products() {
        fn gcd(a: u128, b: u128) -> u128 {
            if b == 0 {
                a
            } else {
                gcd(b, a % b)
            }
        }
        let mut r = Rng(99);
        // Smooth denominators share prime factors, so the lcm fits u128 while the product
        // of the denominators spans several limbs: the big-integer path against an
        // independent lcm reference.
        let primes = [2u64, 3, 5, 7, 11, 13];
        let (mut checked, mut multi_limb) = (0, 0);
        for _ in 0..2_000 {
            let k = r.range(2, 8) as usize;
            let mut terms: Vec<(i128, u64)> = Vec::new();
            let mut l: u128 = 1;
            for _ in 0..k {
                let mut d: u64 = 1;
                while let Some(nd) = d.checked_mul(primes[r.range(0, 5) as usize]) {
                    if nd > (1 << 56) || r.range(0, 9) == 0 {
                        break;
                    }
                    d = nd;
                }
                terms.push(((r.next() >> 40) as i128 - (1 << 23), d));
                l = l / gcd(l, d as u128) * d as u128;
            }
            if l > 1 << 90 {
                continue;
            }
            let sum: i128 = terms.iter().map(|&(n, d)| n * (l / d as u128) as i128).sum();
            assert_eq!(floor_total(0, &terms), sum.div_euclid(l as i128), "terms {terms:?}");
            checked += 1;
            if terms.iter().map(|t| 64 - t.1.leading_zeros()).sum::<u32>() > 128 {
                multi_limb += 1;
            }
        }
        assert!(checked > 500 && multi_limb > 100, "checked {checked} multi_limb {multi_limb}");
        // exact integer sum must not be pushed down by a fractional estimate
        assert_eq!(floor_total(0, &[(1, 3), (1, 6), (1, 2)]), 1);
        assert_eq!(floor_total(0, &[(-1, 3), (-1, 6), (-1, 2)]), -1);
        assert_eq!(floor_total(0, &[(1, 3), (1, 3)]), 0);
    }

    // --- perp fills -------------------------------------------------------

    fn lot(side: Side, q: u64, e: u64, m: u64, o: u64) -> PerpLot {
        PerpLot { side, qty_usd: q, entry_usd: e, margin_sats: m, opp_margin_sats: o }
    }

    #[test]
    fn closing_leg_needs_no_margin_even_in_drawdown() {
        let d = DOMAIN_20;
        // long $1000 @ 100k with 1x margin (1_000_000 sats), now $50k: deep drawdown.
        let long = lot(Side::Long, 1_000, 100_000, 1_000_000, 1_000_000);
        let existing = [Leg::Perp(long)];
        let close = lot(Side::Short, 1_000, 50_000, 2_000_000, 0);
        assert_eq!(margin_delta_perp_fill(&existing, close, d), 0);
        // partial close
        let part_close = lot(Side::Short, 400, 50_000, 800_000, 0);
        assert_eq!(margin_delta_perp_fill(&existing, part_close, d), 0);
    }

    const DOMAIN_20: PriceDomain = PriceDomain { p_min: 1, p_max: (1 << 20) - 1 };

    #[test]
    fn closing_never_increases_requirement_randomized() {
        let mut r = Rng(2024);
        for _ in 0..300 {
            let entry = r.range(1, 255);
            let q = r.range(1, 50);
            let side = rand_side(&mut r);
            let l = lot(side, q, entry, r.range(1, 900_000), r.range(0, 900_000));
            let opp = if side == Side::Long { Side::Short } else { Side::Long };
            let cq = r.range(1, q);
            let fill = lot(opp, cq, r.range(1, 255), 0, 0);
            let d = dom(255);
            assert_eq!(margin_delta_perp_fill(&[Leg::Perp(l)], fill, d), 0, "lot {l:?} fill {fill:?}");
        }
    }

    #[test]
    fn flip_charges_only_the_excess() {
        let d = DOMAIN_20;
        let long = lot(Side::Long, 1_000, 100_000, 1_000_000, 1_000_000);
        let existing = [Leg::Perp(long)];
        // sell $3000 at the entry price: closes $1000, opens $2000 short
        let flip = lot(Side::Short, 3_000, 100_000, 3_000_000, 3_000_000);
        let residual = lot(Side::Short, 2_000, 100_000, 2_000_000, 2_000_000);
        let on_flat = max_loss(&[Leg::Perp(residual)], Asset::Btc, d);
        let before = max_loss(&existing, Asset::Btc, d);
        assert_eq!(before, 1_000_000);
        let got = margin_delta_perp_fill(&existing, flip, d);
        assert_eq!(got, on_flat - before, "flip needs the residual's loss minus what is already posted");
        assert!(got > 0 && got < on_flat);
        let res = apply_perp_fill(&[long], flip);
        assert_eq!(res.closed_usd, 1_000);
        assert_eq!(res.lots.len(), 1);
        assert_eq!(res.lots[0].side, Side::Short);
        assert_eq!(res.lots[0].qty_usd, 2_000);
        assert_eq!(res.lots[0].margin_sats, 2_000_000);
        assert_eq!(res.released_margin_sats, 1_000_000);
        assert_eq!(res.payout_sats, 1_000_000);
    }

    #[test]
    fn fifo_closes_oldest_first_and_matches_dex_split() {
        let a = lot(Side::Long, 100, 50_000, 300_000, 200_000);
        let b = lot(Side::Long, 100, 60_000, 250_000, 150_000);
        let res = apply_perp_fill(&[a, b], lot(Side::Short, 150, 55_000, 0, 0));
        assert_eq!(res.closed_usd, 150);
        assert_eq!(res.lots.len(), 1);
        assert_eq!(res.lots[0].entry_usd, 60_000);
        assert_eq!(res.lots[0].qty_usd, 50);
        assert_eq!(res.lots[0].margin_sats, 250_000 - 125_000);
        assert_eq!(res.lots[0].opp_margin_sats, 150_000 - 75_000);
        assert_eq!(res.released_margin_sats, 300_000 + 125_000);
    }

    // --- combos and options ----------------------------------------------

    const E: u64 = 100_000_000;

    fn short_call(q: u64, k: u64, prem: u64) -> Leg {
        Leg::InverseOption { kind: OptionKind::Call, long: false, qty_usd: q, strike_usd: k, premium_sats: prem }
    }

    #[test]
    fn short_inverse_call_is_fully_fundable_in_btc() {
        let d = DOMAIN_20;
        let (q, k) = (10_000u64, 100_000u64);
        let naked = max_loss(&[short_call(q, k, 0)], Asset::Btc, d);
        // loss at the domain top p: ceil(Q*1e8*(p-K)/(K*p)); bounded by the sup Q*1e8/K
        let p = d.p_max as u128;
        let at_top = (q as u128 * E as u128 * (p - k as u128)).div_ceil(k as u128 * p);
        let sup = (q as u128 * E as u128) / k as u128;
        assert_eq!(naked, at_top);
        assert!(naked < sup, "naked {naked} sup {sup}");
        assert_eq!(max_loss(&[short_call(q, k, 0)], Asset::Usd, d), 0);
        let prem = 1_000_000u64;
        assert_eq!(max_loss(&[short_call(q, k, prem)], Asset::Btc, d), naked - prem as u128);
    }

    #[test]
    fn covered_call_needs_less_than_naked_call() {
        let d = DOMAIN_20;
        let (q, k) = (10_000u64, 100_000u64);
        let naked = max_loss(&[short_call(q, k, 0)], Asset::Btc, d);
        // long perp of the same notional, entered at the strike, counterparty margin deep
        // enough that its gain clamp never bites in the domain
        let perp = Leg::Perp(lot(Side::Long, q, k, 100_000_000, 100_000_000));
        // the call's marginal requirement given the perp: above the strike both legs
        // move by the same amount in opposite directions
        let call_on_top = margin_delta(&[perp], &[short_call(q, k, 0)], Asset::Btc, d);
        assert!(call_on_top < naked, "covered {call_on_top} naked {naked}");
        assert_eq!(call_on_top, 0);
        // with a thin counterparty margin the perp's gain is capped and the call is partly naked
        let capped = Leg::Perp(lot(Side::Long, q, k, 1_000_000, 2_000_000));
        let partial = margin_delta(&[capped], &[short_call(q, k, 0)], Asset::Btc, d);
        assert!(partial > 0 && partial < naked, "partial {partial} naked {naked}");
    }

    #[test]
    fn call_spread_is_bounded_by_the_strike_gap() {
        let d = DOMAIN_20;
        let (q, k1, k2) = (10_000u64, 100_000u64, 120_000u64);
        let long_call = Leg::InverseOption { kind: OptionKind::Call, long: true, qty_usd: q, strike_usd: k2, premium_sats: 0 };
        let spread = [short_call(q, k1, 0), long_call];
        let gap = q as u128 * E as u128 * (k2 - k1) as u128 / (k1 as u128 * k2 as u128);
        let loss = max_loss(&spread, Asset::Btc, d);
        // the gap is 1666666.67 sats; loss rounds up to the next sat
        assert_eq!(loss, gap + 1);
        assert!(loss < max_loss(&[short_call(q, k1, 0)], Asset::Btc, d));
    }

    #[test]
    fn cash_secured_usd_put_is_fully_funded_in_usd_and_needs_no_btc() {
        let d = PriceDomain { p_min: 1, p_max: (1 << 20) - 1 };
        let (q_e8, k, prem) = (100_000_000u64, 100_000u64, 2_000_000_000u64); // 1 BTC, K $100k, $2000
        let short_put = Leg::LinearOption { kind: OptionKind::Put, long: false, qty_btc_e8: q_e8, strike_usd: k, premium_usd: prem };
        // payoff Q*(K-P)+ <= Q*K; at p_min = 1 the loss is Q*(K-1) - premium, in micro-USD
        let want = (k as u128 - 1) * 1_000_000 - prem as u128;
        assert_eq!(max_loss(&[short_put], Asset::Usd, d), want);
        assert!(want < k as u128 * 1_000_000 - prem as u128 + 1);
        assert_eq!(max_loss(&[short_put], Asset::Btc, d), 0);
        let mut posted = BTreeMap::new();
        posted.insert(Asset::Usd, want);
        assert!(fully_funded(&[short_put], &posted, d));
        posted.insert(Asset::Usd, want - 1);
        assert!(!fully_funded(&[short_put], &posted, d));
    }

    #[test]
    fn naked_inverse_put_loss_is_set_by_the_domain_floor() {
        let (q, k) = (1_000u64, 100u64);
        let short_put = Leg::InverseOption { kind: OptionKind::Put, long: false, qty_usd: q, strike_usd: k, premium_sats: 0 };
        // Q*1e8*(1/p - 1/K) at p_min, exact here: 1e11*(K-p)/(K*p)
        for p_min in [1u64, 2, 4, 5, 10] {
            let d = PriceDomain { p_min, p_max: 255 };
            let want = (q as u128 * E as u128 * (k - p_min) as u128).div_ceil(k as u128 * p_min as u128);
            assert_eq!(max_loss(&[short_put], Asset::Btc, d), want, "p_min {p_min}");
        }
        let lo = max_loss(&[short_put], Asset::Btc, PriceDomain { p_min: 1, p_max: 255 });
        let hi = max_loss(&[short_put], Asset::Btc, PriceDomain { p_min: 10, p_max: 255 });
        assert!(lo > hi * 9, "loss grows without bound as the floor falls: {lo} vs {hi}");
        // the same put, USD-quoted and cash-secured, stays bounded by Q*K
        let usd_put = Leg::LinearOption { kind: OptionKind::Put, long: false, qty_btc_e8: 100_000_000, strike_usd: k, premium_usd: 0 };
        assert!(max_loss(&[usd_put], Asset::Usd, PriceDomain { p_min: 1, p_max: 255 }) <= k as u128 * 1_000_000);
    }

    #[test]
    fn btc_put_spread_is_bounded_without_a_stablecoin() {
        let d = DOMAIN_20;
        let (q, k_hi, k_lo) = (10_000u64, 100_000u64, 80_000u64);
        let short_hi = Leg::InverseOption { kind: OptionKind::Put, long: false, qty_usd: q, strike_usd: k_hi, premium_sats: 0 };
        let long_lo = Leg::InverseOption { kind: OptionKind::Put, long: true, qty_usd: q, strike_usd: k_lo, premium_sats: 0 };
        let gap = q as u128 * E as u128 * (k_hi - k_lo) as u128 / (k_hi as u128 * k_lo as u128);
        let spread = max_loss(&[short_hi, long_lo], Asset::Btc, d);
        assert!(spread <= gap, "spread {spread} gap {gap}");
        assert!(spread + gap / 1000 >= gap);
        assert!(spread * 100 < max_loss(&[short_hi], Asset::Btc, d));
        assert_eq!(max_loss(&[short_hi, long_lo], Asset::Usd, d), 0);
    }

    #[test]
    fn margin_is_per_asset_with_no_cross_netting() {
        let d = DOMAIN_20;
        let btc_loss = Leg::InverseOption { kind: OptionKind::Call, long: false, qty_usd: 1_000, strike_usd: 100_000, premium_sats: 0 };
        let usd_gain = Leg::LinearOption { kind: OptionKind::Call, long: true, qty_btc_e8: 100_000_000, strike_usd: 100_000, premium_usd: 0 };
        let both = [btc_loss, usd_gain];
        assert_eq!(max_loss(&both, Asset::Btc, d), max_loss(&[btc_loss], Asset::Btc, d));
        assert_eq!(max_loss(&both, Asset::Usd, d), 0);
        let mut posted = BTreeMap::new();
        posted.insert(Asset::Usd, 10u128.pow(15));
        assert!(!fully_funded(&both, &posted, d), "USD collateral cannot fund a BTC loss");
        posted.insert(Asset::Btc, max_loss(&both, Asset::Btc, d));
        assert!(fully_funded(&both, &posted, d));
        assert_eq!(required_collateral(&both, d)[&Asset::Btc], max_loss(&[btc_loss], Asset::Btc, d));
    }

    #[test]
    fn margin_delta_zero_for_reducing_option_and_flat_for_hedge() {
        let d = DOMAIN_20;
        let sc = short_call(1_000, 100_000, 0);
        let lc = Leg::InverseOption { kind: OptionKind::Call, long: true, qty_usd: 1_000, strike_usd: 100_000, premium_sats: 0 };
        assert_eq!(margin_delta(&[sc], &[lc], Asset::Btc, d), 0);
        assert!(margin_delta(&[], &[sc], Asset::Btc, d) > 0);
    }

    #[test]
    fn validate_rejects_out_of_bounds() {
        let d = dom(255);
        let bad = Leg::Perp(lot(Side::Long, 1, 0, 0, 0));
        assert_eq!(validate(&[bad], d), Err(PayoffError::Bounds(0)));
        assert_eq!(validate(&[], PriceDomain { p_min: 0, p_max: 5 }), Err(PayoffError::Domain));
        assert_eq!(PriceDomain::from_bits(17), PriceDomain { p_min: 1, p_max: 131_071 });
    }
}
