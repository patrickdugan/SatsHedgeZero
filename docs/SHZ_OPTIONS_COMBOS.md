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
| `b2_collar` | buy 50k call, buy 90k put, sell 110k call (1 USD each, all BTC) | 0; only the net premium moves (the two-asset collar is `c3`) |
| `b2_all_or_none` | an unfillable leg, a limit one milli short, a duplicate series, 5 legs | rejected, state unchanged |

The cover in a BTC covered call is either the BTC collateral itself (a single short inverse call
is fully funded at `Q*1e8*(1/K - 1/p_max)` sats) or a lower-strike long call, as in the test.
An inverse put written for BTC locks its worst case at the bottom of the oracle domain
(`1e8*(1/1 - 1/K)` sats per USD, almost a bitcoin per USD of notional), which is why the collar
test uses 1 USD legs and why puts are USD-settled in C.

## C. Hybrid multi-asset clearing

BTC stays the primary asset; a USD stablecoin is a registered settlement asset beside it.
Inverse perpetuals keep margining and settling in BTC only (nothing in this section touches them).

| Piece | What it is |
|---|---|
| Asset registry | `SettleAsset::{Btc, Stable{protocol: StableProtocol::{Rgb, Tap}, id, decimals}}`. `register_stable(asset)` (journaled `RegisterStable{asset}`, once per asset, decimals 6..=18) opens that asset's clearing pool. USDT on RGB is the first registration; a second stablecoin is another registration (`c2` registers an 8-decimal Taproot Assets one). `SettleAsset::collateral()` maps to `shz_margin::CollateralAsset::{TaprootAsset, Rgb{contract_id}}`, both still refused for v0 channel funding (`TapAssetDisabledInV0`, `RgbAssetDisabledInV0`). |
| What settles where | Calls settle in BTC (a written call is fully funded at `Q*1e8*(1/K - 1/p_max)` sats). Puts settle in BTC, margined to the bottom of the outcome domain, or in a registered stablecoin, cash-secured: the writer posts `Q*(K - p_min)` USD and is capped there (`c1_usdt_cash_secured_put`: 0.01 BTC at 90k locks 899,990,000 base units = $899.99). Stablecoin calls are refused at listing. |
| Premium asset | Premium is paid in the leg's settlement asset: sats for BTC series, stablecoin units for stablecoin puts. Paying it in the other asset would need a conversion price at the fill, which is a cross-asset exchange the router does not make; in the leg's own asset the writer's premium lands where its obligation sits. A Take states one net limit per asset: `premium_milli` for the first leg's asset, `other_limits: [AssetLimit{asset, premium_milli}]` for each other asset (exactly once each; serialized only when non-empty, so single-asset intents keep the B1 JSON and digest). |
| Balances | `OptionAccount::balances: {SettleAsset -> AssetBalance{free, locked, realized}}`. BTC comes from the perpetual allocation (`fund_options`/`defund_options`); stablecoins through `deposit_stable(channel, asset, units)` / `withdraw_stable` (journaled `StableTransfer{channel, asset, units, deposit}`). |
| Margin | Per asset: `locked` = sum over expiries of `payoff::max_loss` of that asset's legs on that expiry (`required(k, asset)`, `groups(k)`). No netting across assets or across stablecoins: BTC does not secure a USDT put and one stablecoin does not secure another's (`c2_assets_do_not_net`). |
| Clearing | Per asset inside one batch: `OptionBatch::clearing: [AssetClearing{asset, report: BatchClearing}]`, one net amount per account per asset. BTC clears against the router's clearing ledger; each stablecoin against its own `ClearingState` (fund, waterfall layers, deferred claims, identity `cash - claims - fund + carry == 0`), listed by `OptionsDesk::stable_pools()`. The tests check every pool's identity and `sum(realized) + cash == fund0` per asset after every step. |
| Collar | `c3_collar_clears_in_two_assets`: one signed intent buys the USDT put (writer cash-secured in USDT) and sells the BTC call (covered by BTC collateral); the batch carries a BTC report and a USDT report, each netting to zero; one expiry settles both assets in one batch. |
| `fully_funded` | `OptionsDesk::fully_funded(channel)`: locked collateral covers every expiry's worst case in every asset the account settles in. Locked is set to exactly that on every fill and expiry, so every option portfolio is fully funded and exempt from liquidation; BTC perpetual positions keep the existing risk path. |
| BTC put spreads | The no-stablecoin alternative (`c5_btc_put_spread`): selling the 90k put and buying the 80k put (1,000 USD) locks 138,889 sats, against about 1,000 BTC for the naked 90k put. |

**On-chain movement of the stablecoin side is simulated.** `deposit_stable` and `withdraw_stable`
record the adapter's credit and debit; nothing here verifies a Taproot Assets proof or an RGB
consignment, and no stablecoin moves on chain or in a channel.

Compatibility with `research/shz-rgb-01-utexo-sdk` (withdrawal reservations): its
`WithdrawalRequest`/`WithdrawalReceiptV1` are BTC-only (`amount_sats`) and bind a perpetual batch
(`clearing_sequence`, `batch_digest`, `clearing_digest`). A stablecoin withdrawal there would add a
`SettleAsset` field (absent = BTC) and bind an option batch's per-asset clearing digest. Its
`Balance` adds `withdrawal_reserved`/`withdrawn`; `fund_options` moves `cap` and `free` together and
stays conserved under that wider identity. Both branches edit `State::new` and `State::apply` in
`tiered_durable.rs`, so a merge conflicts there textually.

## C3. Lane acknowledgements for option batches

`enable_option_acks()` (journaled `EnableOptionAcks`, once) makes option batches wait for the
same owner/peer/monitor round perpetual batches use. Until it is journaled, option batches apply
when they are matched, as in B1/B2; journals without it replay unchanged.

| Piece | What it is |
|---|---|
| Staging | A Take that fills, and every `expire_series`, produces an `OptionBatch` that is staged (`OptionOutcome::Staged`, `pending_option()`, `pending_option_since()`) and moves nothing. One batch is staged at a time; every other option event returns `Hold` until it resolves. Perpetual batches keep running meanwhile. |
| Message | `OPTION_ACK_TAG_V4 = "SHZ/HFT06/CHANNEL-ACK/V4"`. `option_ack_message(disposition, channel)` hashes the router config, the batch digest (`OptionBatch::digest`: kind, fills, every asset's clearing digest), sequence, disposition, channel, and, for every asset the lane moves in, the asset id, the lane's `ClearingRow` and that asset's `BatchClearing::digest`. Each lane therefore signs its per-asset net and the whole per-asset net vector. |
| Commit | `resolve_option(OptionAckBundle{sequence, batch, disposition: Commit, acks: [OptionAck{channel, signatures: [owner, peer, monitor]}]}, now)`, one ack per lane in `OptionBatch::channels()` order (every account with a clearing row in any asset). The staged desk replaces the current one; the BTC pool takes the batch's dust as a delta, so perpetual resolutions in between are kept. |
| Abort | `ABORT_AFTER_US` after staging, peer and monitor alone (owner signature all-zero) may sign a `FencedAbort`: nothing moves, the makers' quotes are pulled, and the taker's intent sequence stays used. |
| Recovery | A staged batch is journaled state: after a restart it is still staged and resolves there. An exact retry of the bundle that resolved the last batch returns `false` (idempotent); a conflicting bundle is refused. |
| Tests | `d1_option_batches_commit_only_on_lane_acks` (two-asset collar and its expiry; missing lane, wrong signature, early abort, ownerless commit refused), `d2_staged_batch_aborts_after_the_deadline_and_replays`, `d3_staged_batch_survives_restart_and_retries_are_idempotent`. Perpetual batches add a separate prepare step (owner approvals) before acks because their acks carry channel heads built at prepare time; the option V4 ack carries the owner signature over the batch itself, so staging plus the ack bundle is the whole round. |

Option acknowledgements do not advance the lanes' commitment heads: the stablecoin side moves
through the simulated adapter, and the BTC side of an option batch is not yet a channel state
update. The venue (`crates/shz-venue`) does not drive this round yet (session lt-venue-options).
