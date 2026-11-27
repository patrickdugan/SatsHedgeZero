# SHZ venue: options (testnet, off by default)

The router's options desk (docs/SHZ_OPTIONS_COMBOS.md, `shz_dex::routing::options`) exposed on the
venue: series listed from the FROST relay's DLC events, signed `IntentV7` orders (single legs and
all-or-none combos), the C3 owner/peer/monitor acknowledgement round, automatic expiry on the
oracle's attestation, and an Options tab in the trading page. Code: `crates/shz-venue/src/core/options.rs`,
`ui/venue/options.js`, `ui/venue/crypto.js` (IntentV7 encoder).

## Switching it on

```
shz-venue --options [--stable-usdt <RGB contract id, 32-byte hex>] ...
```

Without `--options` every option endpoint answers 404 (`GET /api/options/series` answers
`{"enabled": false}`), `status.options.enabled` is false and the page shows no Options tab.
`--options` journals, once each, in the state dir's router journal:

* `EnableOptions{oracle_key = --group-key, num_bits = 20}`: series list only on announcements by
  the pinned FROST group key with 20 digits (outcome domain 1 ..= 1,048,575 USD).
* `EnableCombos`, `EnableOptionAcks`.
* `RegisterStable{Rgb, id, decimals 6}` for `--stable-usdt` (shown as USDT). Deposits and
  withdrawals are the simulated RGB/TAP adapter: nothing moves on chain.

These records stay in the journal; restarting without `--options` hides the endpoints but does
not remove the desk.

## Listing and expiry

Every 3 s the venue reads `GET {relay}/v1/dlc/events`. An `announced` event whose maturity is at
least 60 s ahead (at most four unexpired events) is fetched from `/v1/dlc/event/{id}` and listed
after these checks: `announcement_digest` is the tagged hash (`SHZ/DLC/ANNOUNCEMENT/V1`) of the
canonical core (sorted keys, compact), `announcement_signature` verifies under the pinned key
with the core's `announcement_nonce_x`, and `shz_dlc_announcement` matches the core (event id,
maturity, oracle key, digit nonces, 20 digits). Strikes: the at-the-money strike (mark rounded
to a step of 1, 2 or 5 x 10^k not above 1% of the mark) and two steps each side. Per strike:
a BTC call, a BTC put and, with `--stable-usdt`, a USDT cash-secured put.

Once a listed event is past maturity the venue polls it; when its status is `attested` it calls
`expire_series` with `shz_dlc_attestation` (the router verifies every digit signature against the
listed announcement). The expiry batch goes through the same acknowledgement round as a trade;
if it is fence-aborted (a holder did not sign) it is retried 30 s later.

## Units

| Series asset | `qty` unit | `premium_milli` | collateral / payoff | page contract |
|---|---|---|---|---|
| BTC (inverse) | 1 USD notional | millisats per unit | sats | 100 USD |
| USDT (linear) | 1e-8 BTC | thousandths of a base unit (1e-6 USDT) per unit | base units | 0.01 BTC |

A short BTC call locks about `qty * 1e8 / K` sats; a short BTC put is margined down to 1 USD
(about `qty * 1e8` sats), so naked BTC puts are written only inside spreads; a short USDT put
locks `(K - 1) * qty / 1e8` USDT (cash-secured).

## Endpoints

| Method and path | Body / answer |
|---|---|
| `GET /api/options/series` | `{enabled, mark_usd, oracle, num_bits, domain, assets[{code, kind, protocol, id, decimals, pool}], staged, events[{event_id, maturity_unix, status, price_usd}], series[...]}`; each series: `id, kind, asset{...}, asset_code, strike_usd, event_id, maturity_unix, settled_price_usd, contract_qty, bid/ask {premium_milli, qty}, last_premium_milli, worst_case_per_contract {short, long}, margin_per_contract {short, long}` (base units, premium excluded) |
| `GET /api/options/book/{series}` | `{series, bids: [[premium_milli, qty, n]], asks: [...]}` (bids are long quotes) |
| `GET /api/options/batches?limit=` | option batches, newest first: `n` (venue number), `seq` (router sequence; an aborted batch's sequence is reused), `kind` trade/expiry, `phase` staged/committed/aborted, fills, per-asset `clearing{asset, rows[{channel, owner, pnl, collected, paid, net}], cash_before, cash_after, pool_net, fund_after, layer}`, `acks` |
| `GET /api/options/account/{owner}` | same as `options` in `GET /api/account/{owner}` |
| `POST /api/options/intent-id` | `{intent}` -> `{id}` |
| `POST /api/options/intents` | `{intent}` -> `{id, outcome: posted/cancelled/staged, batch}`; 409 `an option batch is still settling` while one is staged |
| `POST /api/options/{fund,defund,deposit,withdraw}` | `{owner, amount, asset (deposit/withdraw), expires_us, signature}` |

`options` in the account view: `balances[{asset, descriptor, free, locked, realized, required}]`,
`legs[{series, kind, asset, strike_usd, event_id, maturity_unix, net, settled_price_usd}]`,
`fully_funded`, `open_orders`, `fills`, `intents`, `pending_signatures` (the account's option
acks; they also appear in the account's `pending_signatures`), `last_sequence`.

### IntentV7 JSON

```
{version: 7, owner, channel: {txid, vout}, sequence, expires_us, action: post|take|cancel,
 legs: [{series, long, qty}], premium_milli, other_limits: [{asset, premium_milli}],
 cancel_target, signature}
```

The id is `tagged_hash("SHZ/HFT06/INTENT/V7", u32 version || scope (network, u64 epoch, policy) ||
u32 router || txid || u32 vout || owner || u64 sequence || u64 expires_us || u8 action ||
u64 #legs || (series || u8 long || u64 qty)* || i64 premium_milli || cancel_target ||
[u64 #other_limits || (asset || i64 premium_milli)*  only when non-empty])`, integers little-endian,
asset = `01` for BTC or `02 || u8 protocol (rgb 0, tap 1) || id || u8 decimals`. Scope and router
come from `GET /api/template`. Post: one leg, `premium_milli` > 0 per unit. Take: `premium_milli`
is the most the taker pays net in the first leg's asset in thousandths of a base unit (premium
base units x 1000; negative = the least it must receive), each other asset among the legs once in
`other_limits`. The sequence counts per account across option intents.

### Collateral transfers

`signature` is BIP340 by the owner over `tagged_hash("SHZ/VENUE/OPTIONS-TRANSFER/V1", u8 op ||
owner || asset || u64 amount || u64 expires_us)` with op fund 1, defund 2, deposit 3, withdraw 4
(fund/defund use the BTC asset byte). `expires_us` must lie in the next 10 minutes and grow with
every transfer of the owner (nonce, kept in memory). Fund/defund move sats between the perpetual
allocation (cap and free) and the options sub-account.

`ui/venue/test/options_vector.json` holds IntentV7 ids and transfer digests checked by both
`cargo test -p shz-venue` and `node --test ui/venue/test/options.test.mjs`.

## Acknowledgement round

With acks on, every option trade or expiry is staged by the router (one at a time). The venue
then, for each lane in `OptionBatch::channels()`, computes the V4 message
(`option_ack_message(Commit, channel)`), signs it with the lane's peer and monitor keys (the
simulated channel adapter, as for perpetual acks) and posts a pending owner signature
`opt{n}:ack:{txid}:{vout}` (kind `option_ack`, context: batch, router sequence, digest, the lane's
per-asset rows). The page signs pending signatures automatically (`POST /api/signatures`). When
every owner has signed, the venue calls `resolve_option` (Commit). If a lane is still unsigned
`ABORT_AFTER_US` (10 s) after staging, the venue resolves a FencedAbort bundle with peer and
monitor signatures: nothing moves, the taker's sequence stays used and the makers' quotes behind
the fills are pulled.

## Stream events (`/api/stream`)

`options_series` (new series listed), `option_book {series}`, `option_batch {phase, batch}` for
staged, committed and aborted batches (with fills and per-asset clearing), `option_fill {batch,
fill}` per committed fill, `option_expiry {event_id, price_usd, series, batch, clearing}`, and
`account` after every change.

## Page

Options tab (header switch Perpetual / Options, shown only when enabled): chain per expiry, strike
ladder with calls left and puts right per asset (badge), bid/ask premium per contract and the
worst-case loss of writing one contract; ticket for single legs (take or post) and combo presets
(call spread, collar = long put one strike below the mark in USDT when listed + short call one
strike above in BTC, covered call); collateral add/remove; the bottom panel's Options tab lists
per-asset balances, positions, open quotes (cancel), fills and pending option acks.

## Drill

`node ops/venue-bench/options_drill/drill.mjs` runs a scripted relay (mark packets and DLC events in
the dlc_coord.py format under a local test key), a venue without `--options` (all off) and one with
it, and checks: listing (an event under 60 s to maturity stays unlisted), a BTC call bought, a USDT
cash-secured put sold, a collar combo with a BTC limit in `other_limits` (and the same combo with an
unmeetable limit refused whole), each staged then committed by acks; a take whose taker withholds
its ack fence-aborted at 10 s; automatic expiry at the attested price; every committed batch's
per-asset clearing rows equal each account's balance change; restart recovery. `--demo` stops after
the makers quote and keeps everything running for a browser at `http://127.0.0.1:18295/`.
Result log: `ops/venue-bench/results/options-drill.jsonl`.
