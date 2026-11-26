# Options and combos on the Lightninger router

Code: `crates/shz-dex/src/routing/options.rs` (`OptionsDesk`), journaled through
`crates/shz-dex/src/routing/tiered_durable.rs`. Tests: `crates/shz-dex/tests/hft06_options.rs`.
Margin engine: `crates/shz-margin/src/payoff.rs` (docs/SHZ_MAXLOSS_MARGIN.md).

## B1. Single-leg options

| Piece | What it is |
|---|---|
| Instrument | `Instrument::{Perp, Option(Series)}`. `Series{kind, asset, strike_usd, event_id}`; id = `tagged_hash("SHZ/OPTIONS/SERIES/V1", ...)`. Each series has its own book (bids and asks), separate from the perpetual books. |
| Listing | `list_series(series, announcement)`: the announcement must come from the desk's oracle key, carry the series' `event_id`, and have the desk's digit count; the strike must lie in the domain. |
| Order | `IntentV7` (`OPTION_INTENT_VERSION = 7`), BIP340-signed by the account owner over `tagged_hash("SHZ/HFT06/INTENT/V7", ...)`. Fields: `version, scope, router, channel, owner, sequence, expires_us, action, legs: [LegOrder{series, long, qty}], premium_milli, cancel_target, signature`. Post: one leg, premium per unit (post-only, a crossing post is refused). Take: fills against the best quotes, all or none, within `premium_milli` (most the taker pays net, in thousandths of the asset unit). Cancel: the account's own quote. |
| Units | `Asset::Btc` series are inverse options: `qty` USD notional, premium in millisats per unit, payoff and collateral in sats. |
| Collateral | `fund_options(channel, sats)` moves sats from the perpetual allocation (`Balance::cap` and `free` drop) into the options sub-account (`OptionAccount::btc_free`); `defund_options` moves free collateral back. |
| Margin | One rule: `btc_locked` is always the account's option worst case over the oracle domain (premium excluded: it moves in cash at the fill). Legs offset only within one expiry (one oracle event settles at one price), so the requirement is the sum over expiries of `payoff::max_loss` of that expiry's legs (`OptionsDesk::required`, `legs_by_event`); `c4_legs_offset_only_within_one_expiry` holds a long near call against a short far call and locks the naked far call. Each fill recomputes it for every account touched; the account must hold `free + locked + premium received - premium paid >= new worst case`. A long option needs only its premium; a written call locks `Q*1e8*(1/K - 1/p_max)` sats. Every option portfolio is `fully_funded`, so none needs liquidation. |
| Premium through clearing | Each take is one `OptionBatch` with a `BatchClearing`: one row per account, `collected` = premium paid into the pool, `paid` = premium paid out, `net = paid - collected`. Premium is one integer per fill, so the rows sum to zero and pool cash is unchanged. |
| Expiry | `expire_series(series, attestation)` verifies every digit signature against the listed announcement (`OracleAttestation::verify_against`; every series of one event must be listed on the same announcement), clamps the price to the domain, and expires every open series of that asset on that event in one `OptionBatch` (`OptionBatchKind::Expiry{event_id, series, price_usd}`): resting quotes are cancelled and each account's positions in those series pay out as one amount, losers from their locked collateral. A net winner gets the floor of its payoff and a net loser pays the ceiling; the dust (under one unit per short) goes to the clearing fund (`cash` and `fund` both rise), so `cash - claims - fund + carry == book` and `sum(realized) + cash == fund0` still hold (perpetual plus option realized). The series is closed for trading afterwards. |
| Makers | Quotes reserve nothing. A maker that cannot fund its side when hit is dropped from every book and matching restarts without it. |
| Journal | New events: `EnableOptions{oracle_key, num_bits}` (clearing must be active), `ListSeries`, `FundOptions{channel, sats, to_options}`, `SubmitOption{intent, now}`, `ExpireSeries{series, attestation}`. Older journals contain none of them and replay unchanged; the desk replays to the same state (`b1_journal_replays`). |

## B2. Combos

`enable_combos()` (journaled `EnableCombos`, once) lets a Take carry up to `MAX_LEGS` (4) legs in
one asset, each on a different series. The whole intent matches in one pass: every leg must fill
completely against resting quotes, the taker's net premium over all legs must be within
`premium_milli` (negative = a minimum credit), and the taker's collateral is checked once against
the worst case of its whole option portfolio after all legs. Any failure rejects the intent and
changes nothing; success is one `OptionBatch` holding every leg's fills and one clearing report.

| Test | Legs | Taker's locked collateral |
|---|---|---|
| `b2_call_spread_margined_on_the_combined_payoff` | sell 100k call, buy 110k call (1,000 USD) | 90,910 sats (`Q*1e8*(1/100k - 1/110k)`, rounded up), against 904,633 for the naked short call |
| `b2_covered_call` | buy 50k call (the cover), sell 110k call (2,000 USD) | 0; the 50k call covers up to 4,400 USD of 110k calls, and selling 5,000 in all locks the uncovered worst case |
| `b2_collar` | buy 50k call, buy 90k put, sell 110k call (1 USD each) | 0; only the net premium moves |
| `b2_all_or_none` | an unfillable leg, a limit one milli short, a duplicate series, 5 legs | rejected, state unchanged |

The cover in a BTC covered call is either the BTC collateral itself (a single short inverse call
is fully funded at `Q*1e8*(1/K - 1/p_max)` sats) or a lower-strike long call, as in the test.
An inverse put written for BTC locks its worst case at the bottom of the oracle domain
(`1e8*(1/1 - 1/K)` sats per USD, almost a bitcoin per USD of notional), which is why the collar
test uses 1 USD legs and why puts are USD-settled in C.

## C. Dual collateral

| Piece | What it is |
|---|---|
| Switch | `enable_usd_collateral()` (journaled `EnableUsdCollateral`, once). Before it, `Asset::Usd` series cannot list and USD transfers are refused. |
| Rails | `shz_margin::CollateralAsset` gains `Rgb{contract_id}` beside `TaprootAsset{asset_id, group_key, script_version}`; both stay refused for v0 channel funding (`RgbAssetDisabledInV0`, `TapAssetDisabledInV0`). An account's first USD deposit fixes its rail; a deposit on the other rail is refused, and `VanillaBtc` is not a USD rail. |
| Balances | Per asset: `btc_free/btc_locked/realized_btc` (sats) and `usd_free/usd_locked/realized_usd` (micro-USD). `deposit_usd(channel, rail, micro_usd)` and `withdraw_usd(channel, micro_usd)` are journaled `UsdTransfer{channel, rail, micro_usd, deposit}`. |
| USD puts | `Asset::Usd` series are linear: `qty` in 1e-8 BTC, premium in thousandths of a micro-USD per unit. A written put locks `Q*(K - p_min)` USD, cash-secured (`c1_usd_cash_secured_put`: 0.01 BTC at 90k locks $899.99; expiry at 80k pays $100 through the USD clearing line). |
| No cross-asset netting | Margin is computed per asset and a combo must stay in one asset. BTC collateral does not secure a USD put (`c2_assets_do_not_net`: a writer holding a whole bitcoin of option collateral and no USD is dropped as an unfunded maker). |
| `fully_funded` | `OptionsDesk::fully_funded(channel)`: posted collateral in each asset covers the sum of each expiry's worst case. Locked collateral is set to exactly that on every fill and expiry, so every option portfolio is fully funded and the desk has no liquidation path. |
| BTC put spreads | The no-stablecoin alternative (`c3_btc_put_spread`): selling the 90k put and buying the 80k put (1,000 USD) locks 138,889 sats (`Q*1e8*(1/80k - 1/90k)`), against about 1,000 BTC for the naked 90k put; the buyer of the spread locks nothing. |
| USD clearing line | USD batches have their own pool line (`cash_before = 0`, `cash_after` = dust kept by the venue); BTC pool cash is untouched by USD batches. |

**On-chain TAP and RGB transfers are simulated.** `deposit_usd` and `withdraw_usd` record the operator's credit and debit; nothing here verifies a Taproot Assets proof or an RGB consignment, and no USD moves on chain.

Not built here: option batches commit inside the router without the sealed/prepared/committed
channel-acknowledgement round that perpetual batches use (no lane signs an option batch), and the
venue (`crates/shz-venue`) exposes no option endpoints yet.
