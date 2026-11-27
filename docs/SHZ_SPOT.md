# SHZ spot: BTC/USDT swaps (testnet, off by default)

A fully funded BTC/stablecoin spot market on the router's options desk, exposed by the venue
behind `--spot`. Code: `crates/shz-dex/src/routing/options/spot.rs` (router),
`crates/shz-venue/src/core/spot.rs` (venue), `ui/venue/spot.js` (page),
`ops/venue-mm/spot_mm.py` (demo maker), `ops/venue-bench/spot_drill/drill.mjs` (drill).

**Settlement is on the venue ledger. USDT is a simulated adapter credit; nothing moves on chain.**
The real path is RGB-02 (below), not built here.

## Design

* **One wallet per account.** Spot shares the options desk's per-account, per-asset balances
  (`OptionAccount.balances`, `AssetBalance{free, locked, realized}`). BTC enters that wallet from the
  perpetual allocation (`fund_options`), the stablecoin through the simulated adapter
  (`deposit_stable`). A resting spot order takes its lock **out of `free`** and the spot desk records it
  on the order, so option margin (`locked` is always the options' worst-case loss and is recomputed on
  every option fill), `defund_options` and `withdraw_stable` can never reach spot-locked funds, and
  spot fills never touch option collateral. Sharing was clean because the options code only ever reads
  and writes `free + locked`; spot locks live outside both. `realized` is unchanged by spot (an
  exchange of assets is not PnL).
* **Pair.** `SpotPair{quote, lot_sats, tick}`: BTC (base, sats) against one registered stablecoin.
  Its id is `tagged_hash("SHZ/SPOT/PAIR/V1", btc ‖ quote ‖ lot ‖ tick)`. Listing requires
  `lot_sats * tick` to be a multiple of 10^8, so the stablecoin amount of every fill,
  `sats * price / 10^8`, is an exact integer: no rounding anywhere, no dust, no pool residue.
* **Fully funded.** No margin, no leverage, no liquidation. A resting sell locks its sats; a resting
  buy locks `qty_sats * price / 10^8` stablecoin base units. A take pays its side out of `free` and is
  refused (`Capacity`) if it cannot pay every fill.
* **Orders: `SpotIntent`, intent version 8** (a new intent type rather than a variant of
  `IntentV7`: option legs, per-asset premium limits and combos do not apply to a swap). Signed by the
  account owner (BIP340) over

  ```
  tagged_hash("SHZ/HFT06/SPOT-INTENT/V8",
    u32 version ‖ scope (network 32, epoch u64, policy 32) ‖ u32 router ‖ channel txid 32 ‖ u32 vout ‖
    owner 32 ‖ u64 sequence ‖ u64 expires_us ‖ u8 action (1 post, 2 take, 3 cancel) ‖ pair 32 ‖
    u8 buy ‖ u64 qty_sats ‖ u64 price ‖ cancel_target 32)
  ```

  (integers little-endian). The replay counter (`last_sequence`) is the account's one desk sequence,
  shared with `IntentV7`. Shared vector: `ui/venue/test/spot_vector.json`, checked by the Rust venue
  test, the node test and `spot_mm.py --selftest`.
  * **Post** rests at `price` for `qty_sats`, post-only: it is refused (`Bounds`) if it would cross
    the best opposite order.
  * **Take** is immediate-or-cancel: it fills against the opposite side in price-time priority at
    the makers' prices while they are within its limit `price`, up to `qty_sats`; the rest is dropped.
    The taker's own resting orders are skipped (no self-trade). Nothing crossing: `NoLiquidity`.
  * **Cancel** pulls the account's resting order `cancel_target` and returns its remaining lock to `free`.
* **One batch per take.** A take is one `OptionBatch` of the new kind `OptionBatchKind::Spot{taker}`
  with its fills in `OptionBatch::spot` (`SpotFill{pair, seller, buyer, maker, taker, taker_buys,
  sats, price, quote_units}`) and one `AssetClearing` per asset (BTC first, then the stablecoin): one
  `ClearingRow` per account per asset with `net = received - paid` over all its fills in the batch.
  Each asset's nets sum to zero, the pool's cash and fund do not move (`pool_net == 0`), so each
  pool's clearing identity is untouched. BTC rows go through the router's BTC clearing ledger, the
  stablecoin's through its pool; the BTC ledger is asserted unchanged.
* **Batch digest.** `OptionBatch::digest` adds kind byte 3 and, only when `spot` is non-empty, the
  fill list. Every option batch's digest is byte-identical to before.

## Atomicity on the venue ledger

`EnableSpot` is refused unless `EnableOptionAcks` is on, so **every** spot batch is staged
(`OptionOutcome::Staged`) and goes through the option acknowledgement round:

1. The router stages the batch against a copy of the desk; the live desk is unchanged and every
   other options or spot mutation returns `Hold` until it resolves.
2. Each lane with a clearing row signs the V4 message (`option_ack_message`, tag
   `SHZ/HFT06/CHANNEL-ACK/V4`): config, batch digest, sequence, disposition, channel and the lane's
   row in **each** asset. The venue adds the peer and monitor signatures (simulated channel adapter)
   and posts one pending owner signature per lane; the browser and the maker bot sign theirs.
3. **Commit** needs owner, peer and monitor on every lane. The staged desk replaces the live one in
   one step: the BTC leg and the stablecoin leg land together.
4. **FencedAbort** after `ABORT_AFTER_US` (10 s) needs peer and monitor only. Nothing moves in
   either asset; the taker's sequence stays used; every maker order in the batch is pulled and its
   remaining lock returned to `free`. Ownerless commits (`EnableOwnerlessExpiry`) apply to expiry and
   void batches only; a spot batch always needs every owner.

So on the venue ledger both legs settle or neither does. That is a property of this ledger and its
simulated channel adapter (venue-held peer and monitor keys), not of any on-chain transfer.

## On-chain settlement (not built): RGB-02

The real path is SHZ-RGB-02: an atomic BTC/RGB swap over Lightning (circular HTLC through Utexo RLN,
one preimage releasing the BTC leg and the RGB USDT leg), assessed on branch
`research/shz-rgb-01-utexo-sdk` (PR #33). It is blocked upstream by strict-signer gate S01. Until it
lands, `deposit_stable`/`withdraw_stable` are the simulated adapter and a committed spot batch moves
ledger balances only.

## Journal

New events, appended to the router journal enum (existing journals replay byte-identically; spot
does not exist until `EnableSpot` is journaled):

| Event | Effect |
|---|---|
| `EnableSpot` | spot desk on (options desk and option acks must be on), once |
| `ListSpotPair{pair}` | list a pair against a registered stablecoin |
| `SubmitSpot{intent, now}` | post / cancel, or stage a take's batch (resolved by `ResolveOption`) |

`DurableTieredRouter`: `enable_spot`, `spot_active`, `list_spot_pair`, `submit_spot`; the batch is read
and resolved with `pending_option`, `option_ack_message`, `resolve_option` like an option batch.
Tests: `crates/shz-dex/tests/hft06_spot.rs` (partial fills across levels and sides, cancel,
refused orders, abort unlocking both sides, journal replay with a staged batch, digest binding).

## Venue

`shz-venue --options --stable-usdt <RGB contract id> --spot` journals `EnableSpot` and lists
BTC/USDT (RGB, 6 decimals) with **1,000-sat lots and a 0.1 USDT tick** (`TICK = 100_000` base
units). `--spot` without `--options --stable-usdt` exits with an error. Off by default.

| Endpoint | |
|---|---|
| `GET /api/spot/book?depth=` | `{pair, bids: [[price, sats, orders]], asks, last, mark_usd, staged}` |
| `GET /api/spot/trades?limit=` | committed fills, newest first |
| `GET /api/spot/account/{owner}` | wallet per asset (`free`, `spot_locked`, `option_locked`), open orders, fills, intents, pending spot acks |
| `POST /api/spot/intents` | `{"intent": SpotIntent JSON}` → `{id, outcome: posted/cancelled/staged, batch}` |
| `POST /api/spot/intent-id` | the id the venue computes for an intent (encoder check) |
| `GET /v1/candles?instrument=SHZ-BTCUSDT-SPOT` | candles from committed spot fills (USDT per BTC, volume in BTC) |

`GET /api/account/{owner}` gains `spot` (same as the spot account view); `GET /api/status` gains
`spot` (summary or `{"enabled": false}`). Spot batches appear in `GET /api/options/batches` with
`kind: "spot"` and a `spot` fill list; venue batch numbers are shared with option batches.

SpotIntent JSON: `{version: 8, owner, channel: {txid, vout}, sequence, expires_us, action:
"post"|"take"|"cancel", pair, buy: bool (or side: "buy"|"sell"), qty_sats, price, cancel_target,
signature}`; `pair` defaults to the venue's pair.

Stream events (`/api/stream`): `spot_book` (book changed), `spot_batch` `{phase: staged | committed |
aborted, n, fills}`, `spot_trade` `{trade}` per committed fill; the shared `option_batch` event also
fires for spot batches (`batch.kind == "spot"`). `/v1/stream?instrument=SHZ-BTCUSDT-SPOT` pushes
candles on spot trades.

Venue log: `opt_spot_intent` records (last per id wins) and the shared `opt_batch` records; on restart
spot intents are restored and any whose batch resolved while spot was not yet switched back on are
reconciled from the batch.

## Page

The product switch gains **Spot** when `/api/spot/book` answers: BitcoinWisdom chart on
`SHZ-BTCUSDT-SPOT` (relay-only instrument in the vendored chart; its classic depth rail reads the spot
book), BTC/USDT book and tape (click a level to price the ticket), and a ticket: Limit (post) or Take
(IOC, blank limit = best + 0.5%) with a book-walk estimate. Orders are signed in the browser
(`signSpotIntent`, BIP340 in `sign.wasm`); the spot batch's owner acknowledgement is signed by the
page's auto-signer. The **Spot** bottom tab lists the wallet, open orders (cancel), fills, intents and
pending acks. Balances are moved on the Options ticket (BTC from the perpetual allocation, USDT through
the simulated adapter).

## Demo maker

`python ops/venue-mm/spot_mm.py run --server <venue>`: its own demo account, funds `--fund-sats`
BTC (default 150,000) and `--deposit-usdt` (default 2,000), quotes `--levels` (3) each side at
`--spread-bps` (20) + k·`--step-bps` (10) from the oracle mark, `--size-sats` (40,000) each, bids
rounded down and asks up to the tick; requotes on a `--requote-bps` mark move, a fill or pull of one
of its orders, or every `--refresh-s`; signs its spot acks. `--selftest` checks the ladder and the
shared vector.

## Drill

`node ops/venue-bench/spot_drill/drill.mjs` (local venue, scripted signed mark relay, `spot_mm.py`,
a browser-style client on the page's own `crypto.js`/`spot.js`): 32/32 checks in
`ops/venue-bench/results/spot-drill.jsonl`. `--demo` keeps relay, venue, maker and client running on
`http://127.0.0.1:18395/`.

## Switching it on live

1. Deploy a build containing this change; the venue already runs `--options --stable-usdt`.
2. Add `--spot` to the venue unit. On start it journals `EnableSpot` and `ListSpotPair` once (two
   records); restarts after that journal nothing new.
3. Run `spot_mm.py` as a unit beside the options maker (its own key in its state dir). Demo accounts
   hold 200,000 sats, so its BTC side is bounded by that cap.
4. The spot market is then live on the venue ledger only; the page labels USDT as a simulated credit.
