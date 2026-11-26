# Max-loss margin

Engine: `crates/shz-margin/src/payoff.rs` (`shz_margin::payoff`). Pure functions, no I/O.

## The rule

Margin of an account is the worst-case loss of its whole portfolio over the DLC
price-outcome domain `[p_min, p_max]` (every integer USD price the oracle can attest;
`p_min >= 1`, `p_max = 2^bits - 1`). A new leg needs only the increase:

```
margin_delta(existing, new) = max(0, max_loss(existing + new) - max_loss(existing))
```

A leg that reduces exposure, such as a closing perp fill in drawdown, needs nothing.
A flip needs only the excess over what is already posted. An account that posts
`max_loss` in each asset can owe nothing it has not posted at any outcome, so it never
needs liquidating and a closing leg is never blocked.

## Assets and units

Margin is computed and funded per asset; there is no cross-asset netting (netting at a
price reintroduces liquidation).

| `Asset` | Unit | Legs |
|---|---|---|
| `Btc` | satoshis | `Perp`, `InverseOption`, `Realized{Btc}` |
| `Usd` | micro-USD (1e-6 USD, USDT's 6 decimals) | `LinearOption`, `Realized{Usd}` |

Inverse (BTC-settled) calls are fully fundable in BTC: short call max loss is below
`Q*1e8/K` sats. Inverse puts are not (loss `Q*1e8*(1/P - 1/K)` grows as `P -> p_min`),
so puts are USD-quoted `LinearOption`s cash-secured in a Bitcoin-native USD token
(payoff `Q_btc*(K-P)+ <= Q_btc*K`). BTC-only put spreads are bounded by
`Q*1e8*(1/K_lo - 1/K_hi)`. The USD asset maps to `CollateralAsset::TaprootAsset` (or an
RGB asset), which v0 keeps disabled.

## Why checking breakpoints is exact

For one asset, every leg is piecewise affine in `x = 1/P` (BTC-settled) or in `P`
(USD-settled). The kinks are strikes, and for a perp lot the two clamp prices where
the DLC payout hits the loss cap or the gain cap
(`long_liquidation_price_usd`, `short_liquidation_price_usd`). Between consecutive
kinks the total of all legs is a single affine function of `x` (or `P`), hence
monotone, so its minimum over a run of integer prices is at an end of the run.
`breakpoints` returns each kink with `-1, 0, +1, +2` around it plus the domain ends, so
both sides of every regime change are evaluated. The clamp tests inside `pnl` are exact
rational comparisons (big-integer products), and `pnl` floors the exact rational total
once, which stays monotone. The test
`breakpoint_max_loss_equals_brute_force_on_every_integer_price` checks `max_loss`
against a scan of every integer price for 400 seeded random portfolios in both assets.

Rounding: `pnl` is one floor of the exact total (loss rounds up). The router's per-lot
DLC payouts round half-even each, so a sum of lot payouts can differ from `pnl` by under
one satoshi per lot.

## API

```rust
pub enum Asset { Btc, Usd }
pub enum Side { Long, Short }
pub enum OptionKind { Call, Put }
pub struct PerpLot { pub side: Side, pub qty_usd: u64, pub entry_usd: u64,
                     pub margin_sats: u64, pub opp_margin_sats: u64 }   // shz-dex Lot semantics
pub enum Leg {
    Perp(PerpLot),
    InverseOption { kind, long: bool, qty_usd, strike_usd, premium_sats },
    LinearOption  { kind, long: bool, qty_btc_e8, strike_usd, premium_usd /* micro-USD */ },
    Realized { asset: Asset, pnl: i128 },
}
pub struct PriceDomain { pub p_min: u64, pub p_max: u64 }
impl PriceDomain { pub fn from_bits(num_bits: u8) -> Self }

pub fn validate(legs: &[Leg], domain: PriceDomain) -> Result<(), PayoffError>;
pub fn pnl(legs: &[Leg], asset: Asset, price: u64) -> i128;
pub fn breakpoints(legs: &[Leg], asset: Asset, domain: PriceDomain) -> Vec<u64>;
pub fn worst_case(legs: &[Leg], asset: Asset, domain: PriceDomain) -> (u128, u64); // (loss, price)
pub fn max_loss(legs: &[Leg], asset: Asset, domain: PriceDomain) -> u128;
pub fn margin_delta(existing: &[Leg], new_legs: &[Leg], asset: Asset, domain: PriceDomain) -> u128;
pub fn required_collateral(legs: &[Leg], domain: PriceDomain) -> BTreeMap<Asset, u128>;
pub fn fully_funded(legs: &[Leg], collateral_by_asset: &BTreeMap<Asset, u128>, domain: PriceDomain) -> bool;

pub fn apply_perp_fill(lots: &[PerpLot], fill: PerpLot) -> PerpFill;
pub fn legs_after_perp_fill(existing: &[Leg], fill: PerpLot) -> Vec<Leg>;
pub fn margin_delta_perp_fill(existing: &[Leg], fill: PerpLot, domain: PriceDomain) -> u128;
```

Premiums: the long pays `premium`, the short receives it, and `max_loss` is net of it
(cash-secured USD put: `K*Q - premium`).

## Wiring into the router

* Call `validate` once per account snapshot (inputs must be below the documented bounds:
  prices and `qty_usd` under 2^40, sats under 2^53, `qty_btc_e8` under 2^50).
* Capacity check for a fill: `margin_delta_perp_fill(account_legs, fill_lot, domain)` for
  perp fills (the fill is netted FIFO exactly like `positions::settle`; opposite-side lots
  close oldest first with margins split pro rata, and the closed slices' realized PnL
  stays in the portfolio as a constant `Leg::Realized{Btc}`), `margin_delta(...)` for
  options and any other new leg. The account must have at least the delta free in the
  asset of the leg.
* `Leg::Realized` is the account's realized PnL since its deposit (the router's
  `Balance.realized_pnl`); keep it in the leg list so that cash and open exposure are
  margined together.
* Closing a lot that hedged an option can raise the requirement (the covered call becomes
  naked); the delta is then positive, which is the intended behavior.
* Cost: one `pnl` evaluation per breakpoint, about 4 candidates per distinct strike or
  entry per asset; no allocation beyond the candidate list.
