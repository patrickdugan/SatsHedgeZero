# SHZ liquidation drill

The liquidation path of the venue run end to end, on a local venue, against a scripted mark.
Risk states, the reduce-only gate, the Dutch-auction plan, client-side auto-liquidation,
closing takes from an account with no free margin, and multilateral clearing of closes
past bankruptcy had unit tests but had never run together: the live mark has not moved ~5%.

Code: `ops/venue-bench/liq_drill/` (`drill.mjs`, `summarize.mjs`, `seed_fund0/`).
Raw logs: `ops/venue-bench/results/liq-drill-*.jsonl`. Nothing in `crates/**` or `ui/venue/**` was changed.

```
node ops/venue-bench/liq_drill/drill.mjs --fund 1000000 --out ops/venue-bench/results/liq-drill-fund.jsonl
node ops/venue-bench/liq_drill/drill.mjs --fund 0       --out ops/venue-bench/results/liq-drill-fund0.jsonl --port 18195 --relay-port 18191
node ops/venue-bench/liq_drill/drill.mjs --fund 1000000 --quick split150 --out ops/venue-bench/results/liq-drill-quick-split150-stuck.jsonl   # finding F1
node ops/venue-bench/liq_drill/summarize.mjs ops/venue-bench/results/liq-drill-fund.jsonl            # tables below
```

Needs a debug `shz-venue` (`cargo build -p shz-venue`) and, for `--fund 0`, the seeder
(`cd ops/venue-bench/liq_drill/seed_fund0 && cargo build --offline`). The drill talks only to 127.0.0.1.

## 1. Setup

| Piece | What it is |
|---|---|
| Relay | In-process Node server with `/v1/pubkey`, `/v1/latest`, `/v1/stream` (SSE). Packets are `shz-public-relay/v1` bodies with `status VALID` and `median_e8` from the scripted path, digest `tagged_hash("SHZ/PUBLIC-RELAY-PACKET/V1", canonical json)`, BIP340-signed by a **test group key** (`sha256("shz-liq-drill/test-group-key/v1")`). A heartbeat repeats the current price every second so the 15 s mark age never lapses. |
| Venue | The real `shz-venue` debug binary (HEAD `9d5ac54`), fresh state dir, `--relay http://127.0.0.1:18091 --group-key <test key>`. It pins the key, verifies every packet, and runs margin release + clearing V3 + closing loans as deployed. The mark is the scripted one: the venue never sees another price. |
| Fund 0 | `CLEARING_FUND_SATS` is a constant (1,000,000), so the fund-0 run seeds `router.wal` with `seed_fund0` (a 70-line standalone cargo project that builds the same router config as `Venue::open` and journals `EnableMarginRelease` then `EnableClearing{0}`); `Venue::open` then finds clearing already on. |
| Accounts | Demo accounts, 200,000 sats cap each. **A** long 10x 2,000 USD (vs B), **B** short 10x, **C** long 8x 1,600 USD (vs D), **D** short 10x. A and C commit their whole cap, so they hold **0 free margin**. Different leverages: 10x, 10x, 8x, 10x. Facing each other: B posts the ask A takes, C posts the bid D takes. |
| Makers | 12 more demo accounts (MM1..MM12, 5x, one 500 USD quote each) supply the book the liquidations sell into: bids 30..58 bps under the mark (MM1-8), asks 30..42 bps above it (MM9-12, enabled for the gap). They requote around each new mark (steps inside the 2% collar are requoted before the mark moves; a gap is requoted after it). |
| Client | The drill client imports the **real** `planTakes` and `describe` from `ui/venue/liquidate.js` and drives them with a **port of `maybeLiquidate`** from `ui/venue/venue.js`: Standard tier, `leverage_bps 100000`, `max_fee_ppm 0`, `max_fee_sats 1`, takes sized by `planTakes` against the live book, 5 s throttle. **No browser page was loaded** (the drill is a Node process, no DOM). A has auto-liquidation on all the time; C's client is offline until the gap, as if its owner were away. |
| Path | 100,000 -> 99k, 98k, 97k, 96k, 95k, 94k, 93k, 92k (-8%) in 1% steps, hold at 92k until the 60 s auction has run its course, **gap to 88,000 (-12%)**, then back 90k, 92k, ..., 100,000, then a pairwise unwind to a flat book. |

Closing takes are single-flight per account in the default runs (the next take is sent after the previous batch resolved).
Before `f785f47` this was the only way to avoid F1; the venue now enforces it, and `--serialize false` exercises that.

## 2. Result

Venue at `f785f47` (F1-F3 fixed, section 7). Three full runs, **30/30 assertions each**, every batch committed, book flat at the end:
`results/liq-drill-fund.jsonl` (fund 1,000,000), `results/liq-drill-fund0.jsonl` (fund 0), `results/liq-drill-fund-unserialized.jsonl`
(fund 1,000,000, page-style take bursts, `--serialize false`). The pre-fix logs that evidence F1-F3 are in commit `cc9a79b`.

| Requirement | Result |
|---|---|
| Risk transitions ok -> warning -> maintenance -> bankrupt | A: ok -> warning (97,000) -> maintenance (95,000). C: ok -> warning (95,000) -> maintenance (93,000) -> **bankrupt** (88,000). Prices match the venue's `liquidation_price_usd` / `bankruptcy_price_usd` (A 95,454 / 90,918; C 93,333 / 88,897). |
| Reduce-only gate refuses increases | C in maintenance and in bankruptcy: an increasing take, a flip (held+1 USD) and a new increasing quote all return 409 `only orders that reduce the position`; a 1 USD reducing take is accepted. |
| Auction plan: tranche and discount growth | C at 92,000 with its client offline: 175 plan samples, discount 26 -> 200 bps (linear in `elapsed_ms`, capped at 60 s), limit 91,760 -> 90,160. **`tranche_usd` equals the committed notional in every sample** (new assertion). |
| Closing takes with 0 free margin succeed | Control at 100,000: A (free 0) cannot increase by 10 USD (`Capacity`) but can reduce by 10 USD. Liquidation: A's first take filled with 970 sats free against 52,790 sats of leg margin; C's four takes filled with 34 sats free. |
| Close past bankruptcy gives a clearing `shortfall`, layer `Fund` | Fund run: C's closes in batches 8 and 13-16, shortfalls 16, 8,292, 8,537, 8,765, 1,780 sats (27,390), all `Fund`; fund 1,000,000 -> 972,610. |
| Fund 0: `Haircut` / `Carried` | Batch 8 `Carried` 16; batch 9 D's gain haircut by that 16; batches 13-16 `Haircut` 27,374 off D's deferred claim. D ends flat with an unpaid claim of 71,726 sats that the pool holds in cash. |
| Solvency identity 0 after every batch | `identity == 0` and `sum(realized_pnl) + pool cash == fund0` in every snapshot (32 fund, 31 fund 0, 26 burst; a snapshot is taken only if the journal did not move during the read). Per-batch conservation holds on all 32 / 32 / 28 batches. |
| Client-side auto-liquidation driven | The real `planTakes`/`describe` from `ui/venue/liquidate.js`, driven by a port of the page's `maybeLiquidate`. The page itself was not loaded. |

With the whole position as the tranche, A is closed in 2 rounds (1,990 -> 990 -> 0, at 54 s and 59 s, 16 s after the breach) instead of 11; C in one round of 4 takes.
In the burst run the venue refuses every reducing take after the first while a fill is unsettled (409 `a previous fill of this account is still settling`), so a page-style plan executes one take per 5 s round: A in 4 rounds, C in 4, and no batch is ever stuck.

### Fund 1,000,000 run

#### Assertions

|  | assertion |
|---|---|
| PASS | venue pins the drill relay key and verifies its packets |
| PASS | venue verified the mark (signed by the test key) |
| PASS | multilateral clearing is on with the requested fund |
| PASS | B and C quotes rest |
| PASS | A and D opening takes fill |
| PASS | positions committed: A +2000, B -2000, C +1600, D -1600 USD |
| PASS | A and C hold 0 free margin (their whole demo cap is committed) |
| PASS | control: a healthy account with 0 free margin cannot INCREASE (rejected: Capacity) |
| PASS | control: the same account CAN reduce by 10 USD with 0 free margin (closing loan) |
| PASS | reduce-only gate (C maintenance): increase, flip and a new increasing quote are all refused |
| PASS | reduce-only gate (C maintenance): a reducing order is accepted |
| PASS | reduce-only gate (C bankrupt): increase, flip and a new increasing quote are all refused |
| PASS | reduce-only gate (C bankrupt): a reducing order is accepted |
| PASS | book is flat after the unwind |
| PASS | A walked ok -> warning -> maintenance |
| PASS | C walked ok -> warning -> maintenance -> bankrupt |
| PASS | auction discount only grows while the breach lasts (C, client offline) |
| PASS | auction discount reaches the 200 bps cap after the 60 s auction |
| PASS | the auction limit moves away from the mark as the discount grows (C at 92,000) |
| PASS | plan carries a tranche and the reduce side |
| PASS | the plan closes the whole position (tranche_usd == committed notional) in every sample |
| PASS | client auto-liquidation closed A (planTakes from ui/venue/liquidate.js) |
| PASS | client auto-liquidation closed C past bankruptcy |
| PASS | closing takes with free margin below the leg margin filled (closing loan): A and C had 0 free |
| PASS | a close past bankruptcy produced a clearing shortfall |
| PASS | with a fund, the shortfall layer is Fund |
| PASS | every committed batch conserves (sum of nets + pool delta = 0) and the pool never goes negative |
| PASS | the pool cash chain is continuous batch to batch |
| PASS | solvency identity is 0 and sum(realized)+cash == fund0 at every checked batch |
| PASS | no batch aborted for a missing signature |

#### Risk state transitions

| t (s) | account | from | to | mark | margin bps | net USD |
|---|---|---|---|---|---|---|
| 1.28 | A | flat | ok | 100,000 | 1,000 | 2,000 |
| 1.29 | D | flat | ok | 100,000 | 1,000 | -1,600 |
| 1.29 | B | flat | ok | 100,000 | 1,000 | -2,000 |
| 1.29 | C | flat | ok | 100,000 | 1,250 | 1,600 |
| 25.27 | A | ok | warning | 97,000 | 670 | 1,990 |
| 43.3 | A | warning | maintenance | 95,000 | 450 | 1,990 |
| 43.3 | C | ok | warning | 95,000 | 687 | 1,600 |
| 59.25 | A | maintenance | flat | - | - | 0 |
| 69.58 | C | warning | maintenance | 93,000 | 462 | 1,600 |
| 149.9 | C | maintenance | bankrupt | 88,000 | 0 | 1,599 |
| 157.34 | C | bankrupt | flat | - | - | 0 |

#### Auction plan (first and last sample per account and mark)

| account | mark | samples | first: t / discount / limit / tranche | last: t / discount / limit / tranche | post_margin_bps (plan) | margin_bps (observed) |
|---|---|---|---|---|---|---|
| A | 95,000 | 55 | 43.3 s / 0 bps / 95,000 / 1990 | 59.17 s / 53 bps / 94,496 / 490 | - | 450 |
| C | 93,000 | 27 | 69.58 s / 0 bps / 93,000 / 1600 | 77.45 s / 26 bps / 92,758 / 1600 | - | 462 |
| C | 92,000 | 175 | 77.54 s / 26 bps / 91,760 / 1600 | 129.57 s / 200 bps / 90,160 / 1600 | - | 350 |
| C | 88,000 | 5 | 149.9 s / 200 bps / 86,240 / 1599 | 157.01 s / 200 bps / 86,240 / 99 | - | 0 |

#### Client liquidation takes (planTakes from ui/venue/liquidate.js)

| t (s) | account | mark | net before | free before | plan tranche / limit / discount | takes (qty@limit) | outcome |
|---|---|---|---|---|---|---|---|
| 54.17 | A | 95,000 | 1,990 | 970 | 1990 / 94,677 / 34 bps | 500@94,715, 500@94,677 | filled @94,715, filled @94,677 |
| 59.2 | A | 95,000 | 990 | 44,960 | 990 / 94,515 / 51 bps | 500@94,639, 490@94,601 | filled @94,639, filled @94,601 |
| 157.3 | C | 88,000 | 1,598 | 34 | 1598 / 86,240 / 200 bps | 499@87,595, 500@87,560, 500@87,525, 99@87,490 | filled @87,595, filled @87,560, filled @87,525, filled @87,490 |

2 further plan evaluations found no bid inside the auction limit (client waits for the discount to grow).

#### Reduce-only gate probes

| account | state | held USD | increase | flip | new increasing quote |
|---|---|---|---|---|---|
| C | maintenance | 1600 | 409 account is maintenance (margin below 500 bps): only orders that reduce the position, up to 1600 USD, are accepted | 409 account is maintenance (margin below 500 bps): only orders that reduce the position, up to 1600 USD, are accepted | 409 account is maintenance (margin below 500 bps): only orders that reduce the position, up to 1600 USD, are accepted |
| C | bankrupt | 1599 | 409 account is bankrupt (margin below 500 bps): only orders that reduce the position, up to 1599 USD, are accepted | 409 account is bankrupt (margin below 500 bps): only orders that reduce the position, up to 1599 USD, are accepted | 409 account is bankrupt (margin below 500 bps): only orders that reduce the position, up to 1599 USD, are accepted |

#### Batches with a clearing shortfall

| t (s) | batch | layer | shortfall | fund absorbed | haircut | carry after | fund after | claims after | rows (who: pnl / released / collected / shortfall / paid / claim after) |
|---|---|---|---|---|---|---|---|---|---|
| 154.56 | 8 | Fund | 16 | 16 | 0 | 0 | 999,984 | 0 | C: -141 / 125 / 125 / 16 / 0 / 0 |
| 158.26 | 13 | Fund | 8,292 | 8,292 | 0 | 0 | 991,692 | 0 | C: -70,667 / 62,375 / 62,375 / 8,292 / 0 / 0 |
| 158.32 | 14 | Fund | 8,537 | 8,537 | 0 | 0 | 983,155 | 0 | C: -71,037 / 62,500 / 62,500 / 8,537 / 0 / 0 |
| 158.37 | 15 | Fund | 8,765 | 8,765 | 0 | 0 | 974,390 | 0 | C: -71,265 / 62,500 / 62,500 / 8,765 / 0 / 0 |
| 158.42 | 16 | Fund | 1,780 | 1,780 | 0 | 0 | 972,610 | 0 | C: -14,155 / 12,375 / 12,375 / 1,780 / 0 / 0 |

32 batches settled; clearing layers reached: None 5, Margin 22, Fund 5.

#### Solvency identity

32 snapshots (one per committed batch, journal digest unchanged across the read): identity == 0 in 32; sum(realized_pnl) + pool cash == fund0 in 32.

Last snapshot (after batch final): identity 0, sum realized 27,390, pool cash 972,610, fund0 1,000,000, fund 972,610, carry 0, claims 0, open book 0.

#### Final accounts (demo cap 200,000 sats each)

| account | free | committed | realized pnl | equity | net USD | claim |
|---|---|---|---|---|---|---|
| A | 87,673 | 0 | -112,327 | 87,673 | 0 | 0 |
| B | 199,600 | 0 | -400 | 199,600 | 0 | 0 |
| C | 34 | 0 | -199,966 | 34 | 0 | 0 |
| D | 411,659 | 0 | 211,659 | 411,659 | 0 | 0 |

### Fund 0 run

#### Batches with a clearing shortfall

| t (s) | batch | layer | shortfall | fund absorbed | haircut | carry after | fund after | claims after | rows (who: pnl / released / collected / shortfall / paid / claim after) |
|---|---|---|---|---|---|---|---|---|---|
| 154.12 | 8 | Carried | 16 | 0 | 0 | 16 | 0 | 0 | C: -141 / 125 / 125 / 16 / 0 / 0 |
| 155.47 | 9 | Haircut | 0 | 0 | 16 | 0 | 0 | 0 | D: 53,185 / 40,000 / 0 / 0 / 53,169 / 0 |
| 157.48 | 13 | Haircut | 8,292 | 0 | 8,292 | 0 | 0 | 90,808 | C: -70,667 / 62,375 / 62,375 / 8,292 / 0 / 0 |
| 157.56 | 14 | Haircut | 8,537 | 0 | 8,537 | 0 | 0 | 82,271 | C: -71,037 / 62,500 / 62,500 / 8,537 / 0 / 0 |
| 157.62 | 15 | Haircut | 8,765 | 0 | 8,765 | 0 | 0 | 73,506 | C: -71,265 / 62,500 / 62,500 / 8,765 / 0 / 0 |
| 157.68 | 16 | Haircut | 1,780 | 0 | 1,780 | 0 | 0 | 71,726 | C: -14,155 / 12,375 / 12,375 / 1,780 / 0 / 0 |

32 batches settled; clearing layers reached: None 4, Margin 22, Carried 1, Haircut 5.

#### Solvency identity

31 snapshots (one per committed batch, journal digest unchanged across the read): identity == 0 in 31; sum(realized_pnl) + pool cash == fund0 in 31.

Last snapshot (after batch final): identity 0, sum realized -71,726, pool cash 71,726, fund0 0, fund 0, carry 0, claims 71,726, open book 0.

#### Final accounts (demo cap 200,000 sats each)

| account | free | committed | realized pnl | equity | net USD | claim |
|---|---|---|---|---|---|---|
| A | 87,673 | 0 | -112,327 | 87,673 | 0 | 0 |
| B | 199,600 | 0 | -400 | 199,600 | 0 | 0 |
| C | 34 | 0 | -199,966 | 34 | 0 | 0 |
| D | 312,543 | 0 | 112,543 | 312,543 | 0 | 71,726 |

### Burst run (`--serialize false`)

#### Client liquidation takes (planTakes from ui/venue/liquidate.js)

| t (s) | account | mark | net before | free before | plan tranche / limit / discount | takes (qty@limit) | outcome |
|---|---|---|---|---|---|---|---|
| 53.52 | A | 95,000 | 1,990 | 970 | 1990 / 94,677 / 34 bps | 500@94,715, 500@94,677 | filled @94,715, refused (409 still settling) |
| 58.65 | A | 95,000 | 1,490 | 23,071 | 1490 / 94,515 / 51 bps | 500@94,677, 500@94,639, 490@94,601 | filled @94,677, refused (409 still settling), refused (409 still settling) |
| 63.78 | A | 95,000 | 990 | 44,960 | 990 / 94,354 / 68 bps | 500@94,639, 490@94,601 | filled @94,639, refused (409 still settling) |
| 68.88 | A | 95,000 | 490 | 66,637 | 490 / 94,192 / 85 bps | 490@94,601 | filled @94,601 |
| 165.03 | C | 88,000 | 1,598 | 34 | 1599 / 86,240 / 200 bps | 499@87,595, 500@87,560, 500@87,525, 100@87,490 | refused (409 still settling), filled @87,560, refused (409 still settling), refused (409 still settling) |
| 170.06 | C | 88,000 | 1,098 | 34 | 1098 / 86,240 / 200 bps | 499@87,595, 500@87,525, 99@87,490 | filled @87,595, refused (409 still settling), refused (409 still settling) |
| 175.04 | C | 88,000 | 599 | 34 | 599 / 86,240 / 200 bps | 500@87,525, 99@87,490 | filled @87,525, refused (409 still settling) |
| 180.04 | C | 88,000 | 99 | 34 | 99 / 86,240 / 200 bps | 99@87,490 | filled @87,490 |

2 further plan evaluations found no bid inside the auction limit (client waits for the discount to grow).

#### Batches with a clearing shortfall

| t (s) | batch | layer | shortfall | fund absorbed | haircut | carry after | fund after | claims after | rows (who: pnl / released / collected / shortfall / paid / claim after) |
|---|---|---|---|---|---|---|---|---|---|
| 165.08 | 8 | Fund | 16 | 16 | 0 | 0 | 999,984 | 0 | C: -141 / 125 / 125 / 16 / 0 / 0<br>D: 53,185 / 40,000 / 0 / 0 / 53,185 / 0 |
| 166.03 | 9 | Fund | 8,537 | 8,537 | 0 | 0 | 991,447 | 0 | C: -71,037 / 62,500 / 62,500 / 8,537 / 0 / 0 |
| 170.62 | 10 | Fund | 8,292 | 8,292 | 0 | 0 | 983,155 | 0 | C: -70,667 / 62,375 / 62,375 / 8,292 / 0 / 0 |
| 175.66 | 11 | Fund | 8,765 | 8,765 | 0 | 0 | 974,390 | 0 | C: -71,265 / 62,500 / 62,500 / 8,765 / 0 / 0 |
| 180.72 | 12 | Fund | 1,780 | 1,780 | 0 | 0 | 972,610 | 0 | C: -14,155 / 12,375 / 12,375 / 1,780 / 0 / 0 |

28 batches settled; clearing layers reached: None 1, Margin 22, Fund 5.

#### Solvency identity

26 snapshots (one per committed batch, journal digest unchanged across the read): identity == 0 in 26; sum(realized_pnl) + pool cash == fund0 in 26.

Last snapshot (after batch final): identity 0, sum realized 27,390, pool cash 972,610, fund0 1,000,000, fund 972,610, carry 0, claims 0, open book 0.

## 3. Method notes

- The venue's own numbers are the oracle: the drill asserts nothing the venue did not compute. Risk prices, plan fields and clearing rows are read from `/api/account`, `/api/status` and `/api/explorer/batches`.
- Marks are one signed packet per second plus an immediate packet on each scripted change. The venue's Standard-tier feed lags 200 ms behind (`ExecutionPolicy::defaults(FeedOnly)`).
- Makers requote before a step inside the collar and after a gap; a 4 s maintainer keeps quotes alive (they expire after 120 s).
- Closing takes are single-flight per account in the default runs; the venue refuses a second one since `f785f47` (see F1, section 7).

## 4. Findings (as found at `9d5ac54`; all three fixed in the venue at `f785f47`, section 7)

None of these were fixed (`crates/**` and `ui/venue/**` are untouched). Each has a deterministic reproduction in the drill.

### F1. HIGH. Two closing takes by one account in different batch windows wedge settlement for the whole venue

**Reproduction (12 s, no liquidation needed):**

```
node ops/venue-bench/liq_drill/drill.mjs --fund 1000000 --quick split150 --out /tmp/split150.jsonl     # wedged before f785f47; now asserts the 409
node ops/venue-bench/liq_drill/drill.mjs --fund 1000000 --quick split0   --out /tmp/split0.jsonl       # control
```

A holds a 2,000 USD long with 0 free margin at a healthy 100,000 mark. It sells 10 USD, waits 150 ms (so the second
take lands in the next 100 ms batch window, before batch 2 has resolved), and sells 10 USD again. Both takes fill.
Batch 2 stays `prepared` and batch 3 `sealed` for ever (`liq-drill-quick-split150-stuck.jsonl`); with a 0 ms gap
(same window, one batch) everything commits (`liq-drill-quick-split0-control.jsonl`).
The venue logs `tick: resolve: router rejected operation: Bounds` on every 20 ms tick: 416 lines in the 12 s of the
repro and 6,015 in the full run below (`liq-drill-quick-split150-venue-log.txt`, `liq-drill-fund-unserialized-venue-log.txt`).

**It happens on its own in a liquidation.** `--serialize false` runs the page's behaviour (all takes of a plan sent
back to back): `liq-drill-fund-unserialized.jsonl`. A's liquidation went through, but around D's take-profit and C's
liquidation (C's takes land in several windows) batch 15 stuck in `prepared` and batches 16-19 sat `sealed` behind
it (the `wedged` record in that file; 6,015 `Bounds` errors in the venue log). Nothing after that settles: no fill
commits, no position or balance moves. Two earlier runs of the same script showed the same thing (logs not kept):
one wedged at batch 15 with all five approvals and all five acks already signed, one at batch 4, in the middle of
A's second tranche.

**Cause (from the code and the two repros; not instrumented).** A take that reduces the position borrows its leg
margin from the lots it closes: `tiered.rs` `take()` does `b.committed -= loan` at take time and remembers the loan
in `loans[taker_id]` (lines 458-467). When a batch resolves, `plan_resolution` (`durable.rs` 269-288) adds only *that
batch's* loans back to `committed`, applies the settlement, and then requires `balance.committed ==
settlement.margin_after` (line 279). If the same account has a later batch in flight with its own loan, that loan has
already been taken out of `committed`, so the equality fails and `resolve` returns `Bounds`. Two takes in one window
make one batch and one loan total, which is why the 0 ms control passes.

**Why it never recovers.** `Venue::advance_settlement` (`core.rs`) only calls `deadline_abort` from its `_` arm,
which is reached when the head batch is not ready. A prepared batch with every ack signed takes the commit arm,
`resolve` returns `Err`, `advance_settlement` returns that `Err`, and the 10 s abort deadline is never consulted.
A restart would replay the same prepared batch (untested here).

**Impact.** Any account that closes twice within one commit latency (the page sends a plan's takes back to back; the
router's windows are 100 ms) can freeze settlement for every account. In a liquidation burst this is likely: a
3-4 take plan straddles a window boundary often enough that it hit C in the one run that used the page's pattern.
**Suggested direction:** compare against `margin_after` plus the loans still outstanding for the account, or refuse a
loan while the account has an earlier unresolved loan batch, and let `advance_settlement` abort or skip a head batch
whose `resolve` errors instead of retrying it every tick.

The drill's default runs are single-flight (next take after the previous batch resolved) so that the rest of the
path could be exercised; `--serialize false` shows the wedge.

### F2. MEDIUM. A partial liquidation never restores the margin ratio, so the account is liquidated in full, as a geometric series

`position.risk.liquidation.post_margin_bps` promises 800 (the target) after the tranche. After A's first tranche
(910 of 1,990 USD, filled at 94,715 / 94,677) its `margin_bps` is **still 450**. It stays 450-455 through 11 rounds,
5 s apart, with tranches of 910, 505, 275, 147, 77, 40, 19, 10, 4, 2, 1 USD, and A only leaves `maintenance` by
reaching `flat` at t = 105 s (60 s after the breach). Meanwhile the released margin (A's free balance 970 -> 87,915
sats) sits idle outside the account's equity.

Cause: `risk::margin_bps` is the value of the open lots over their notional. Closing a slice of a lot releases that
slice's margin to the free balance and leaves the remaining lot at the same ratio; `compute_partial_liquidation_tranche`
assumes the equity stays behind the smaller notional (a cross-margin account). So a "partial liquidation" can only
end by closing everything, one halving at a time, with the auction discount drifting to its 200 bps cap meanwhile.
In these runs the book was tight, so the cost was time, not price; on a thin book the late rounds are the ones that
get the worst limits.

**Suggested direction:** count the account's free balance as equity in `margin_bps` and the plan, or make the plan
close the whole position (and say so), or size the tranche on the lot-level ratio.
Evidence: `liq-drill-fund.jsonl`, kinds `liq_take` (`margin_bps_before`, `plan.tranche_usd`) and `auction_plan`.

### F3. MEDIUM. The reduce-only gate and `planTakes` size against committed lots, so an account in maintenance can flip short

**Reproduction (7 s):** `node ops/venue-bench/liq_drill/drill.mjs --fund 1000000 --quick overshoot` (flipped before `f785f47`; now asserts no flip).
A is in maintenance at 95,000 with 100 USD left after four settled sells (free 82,839 sats from the released margin).
Two takes of 90 USD go in back to back. Each is below the 100 USD `held` the gate checks (`risk::gate` uses
`lots_of(owner)`, which is committed lots only), so both pass; the router fills both (the second needs fresh margin
for its 80 USD excess, which the released margin pays). A ends **short 80 USD** and `state: ok`
(`liq-drill-quick-overshoot.jsonl`, kind `overshoot_result`: `before.notional_usd 100`, `after.net_usd -80`).
`planTakes` has the same blind spot: it caps its takes at `risk.notional_usd`, which is also committed lots only
(`position.net_usd`, which includes unsettled fills, is not used). In an earlier run, when F1 froze settlement, the
client kept selling (net_before 61 USD but takes of 442 + 105 USD) and A ended at -381 USD (log not kept).
Without free margin the router's own check (`Capacity`) stops the flip (C, free 34, could not overshoot), so this
needs an account that has just released margin, which is exactly an account that has been partially liquidated.

**Suggested direction:** gate and plan on `net_usd` (committed plus unsettled), as the position panel already does.

### F4. LOW. Observations

- `liquidation.penalty_sats` (up to 36,341 sats in C's plan) is advisory: the clearing rows have no penalty column and
  A's realized loss is exactly its fills' PnL. Nothing in these runs charged it.
- With fund 0 a winner can end flat with an unpaid deferred claim (D: 72,741 sats in the fund-0 run) until it next
  appears in a batch. Documented (`SHZ_VENUE_CLEARING.md`), but worth surfacing in the UI (`deferred_claim_sats` is
  already in the position JSON).
- In an early run the makers' quotes from the previous step were still inside the 2% collar and A sold into them
  above the mark (95,712 against 95,000). That was the drill's maker, now requoting before each step; the collar
  was working as designed.

## 5. What this does not cover

- The real page was not loaded. `planTakes` is the shipped code; the loop around it is a port of `maybeLiquidate`
  (same intent fields, same 5 s throttle; the page also reacts to the WebSocket `risk`/`account` events, the drill polls every 150 ms).
- Only the long side was liquidated. Shorts (B, D, makers) were never near maintenance in a down move; the up-side mirror was not run.
- Settlement is the venue's simulated channel adapter; the clearing fund is a ledger number (`CLEARING_FUND_SATS`), no on-chain output backs it.
- The mark is a clean scripted path; an oracle `HOLD`, a stale mark or a relay outage during a breach were not tried.
- One maker book shape (12 accounts, tight quotes); thin or one-sided books were not swept, and a gap that leaves no bid inside the collar was not run.
- Timings are wall clock on a debug build on this machine; the 60 s auction clock does not scale (`--scale` only shortens the drill's holds).

## 6. Files

| File | |
|---|---|
| `ops/venue-bench/liq_drill/drill.mjs` | the drill (relay, venue, accounts, makers, client, assertions) |
| `ops/venue-bench/liq_drill/summarize.mjs` | JSONL to the tables above |
| `ops/venue-bench/liq_drill/seed_fund0/` | standalone cargo project that seeds a journal with clearing fund 0 |
| `ops/venue-bench/results/liq-drill-fund.jsonl`, `liq-drill-fund0.jsonl` | the two full runs (30/30, venue `f785f47`; pre-fix versions in `cc9a79b`) |
| `ops/venue-bench/results/liq-drill-fund-unserialized.jsonl` (+ `-venue-log.txt`, pre-fix) | page-style take bursts (30/30 at `f785f47`; the pre-fix wedge is in `cc9a79b`) |
| `ops/venue-bench/results/liq-drill-quick-split150-stuck.jsonl` (+ `-venue-log.txt`, pre-fix), `liq-drill-quick-split0-control.jsonl` | F1 repro and control, asserting the fix |
| `ops/venue-bench/results/liq-drill-quick-overshoot.jsonl` | F3 repro, asserting the fix |

JSONL kinds: `mark_set`, `risk_transition`, `auction_plan`, `liq_take` / `liq_result` / `liq_idle`, `gate_probe`, `batch` (full clearing rows), `shortfall_batch`, `solvency`, `assert`, `summary`.

## 7. Fixes after the drill (venue `f785f47`, 2026-11-27) and regression

- **F1:** the venue refuses a position-reducing take while the account has any fill not yet committed
  (`core.rs` `submit`, `unsettled_of`): 409 `a previous fill of this account is still settling`. At most one closing
  loan is in flight per account. The router's balance check (`plan_resolution` compares `committed` with `margin_after`
  without the account's other outstanding loans) is unchanged; a router-level fix is in progress in another session.
- **F2:** the liquidation plan's `tranche_usd` is the whole position, priced by the Dutch auction
  (`penalty_sats` and `post_margin_bps` left the plan JSON).
- **F3:** the reduce-only gate sizes against the net position including unsettled fills.

Regression with the drill (venue debug build of `f785f47`):

| Run | Result |
|---|---|
| `--fund 1000000` | 30/30; A closed in 2 rounds (was 11); tranche == notional in every plan sample |
| `--fund 0` | 30/30; `Carried` then `Haircut` as before |
| `--fund 1000000 --serialize false` | 30/30; 13 reducing takes refused with the 409 (10 liquidation takes, 3 of D's take-profit), no batch stuck (pre-fix: wedged at batch 15) |
| `--quick split150` | 3/3: first take commits, the second 150 ms later is refused with the 409, no batch stuck, A at 1,990 (pre-fix: wedged) |
| `--quick split0` | 3/3: second take refused (the first had already filled), no batch stuck |
| `--quick overshoot` | 3/3: first 90 USD reduce commits, the second is refused, A ends long 10 USD (pre-fix: short 80) |

The burst run's control step now pauses the maker loop, requotes and waits for the control ask to rest before the
`Capacity` probe (it saw `NoLiquidity` when the 4 s maker loop cancelled the ask first).
