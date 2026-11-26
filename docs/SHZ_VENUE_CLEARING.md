# SHZ venue: multilateral clearing

Audit of the venue's central-counterparty netting (margin release, `SHZ/HFT06/CHANNEL-ACK/V2`)
and the multilateral clearing that replaces it (`SHZ/HFT06/CHANNEL-ACK/V3`).

Code: `crates/shz-dex/src/routing/clearing.rs` (ledger and per-batch clearing),
`crates/shz-dex/src/routing/positions.rs` (exact lot entry values), the durable routers
`tiered_durable.rs` (venue) and `durable.rs` (HFT-05). Tests:
`crates/shz-dex/tests/hft06_clearing.rs`. Run with
`cargo test --locked -p shz-dex --test hft06_clearing`.

## 1. Audit of margin release (V2)

Margin release values a closed lot as its own opening DLC leg at the closing fill's price:
`payout_at_price` with the lot's margin and the margin of the account that took the other side
of the *opening* fill (`opp_margin`). A loss stops at the lot's margin, a gain at `opp_margin`.
That clamp is correct for one bilateral contract. The venue, however, nets each account FIFO
against whoever is on the other side of the closing fill (novation), so a lot's gain is paid
from a pool, not by the account whose margin caps it. Per-lot clamps then stop adding up across
a chain of lots, and nothing keeps the sum of realized PnL at zero.

Each finding below is a test in `hft06_clearing.rs` that runs the sequence under V2 and asserts
the defect with its exact numbers, then runs it under V3 and asserts the fix. The sequences were
first written as plain correctness assertions and failed under V2 with the numbers quoted here.
"Account n" is lane `n`; all fills are 1,000 USD unless stated.

| # | Finding | Sequence | V2 result | Test |
|---|---------|----------|-----------|------|
| A1 | **Insolvency.** A lot closed past its bankruptcy price pays only its margin, but the new counterparty's lot is valued from the closing price. When the price recovers, that gain is paid in full while the original counterparty owes nothing. | 1 long 100x vs 2 at 100,000; 1 sells to 3 at 98,000; 2 buys from 3 at 100,000 | accounts hold **+10,408 sats** more than deposited (1: −10,000, 2: 0, 3: +20,408) | `a1_recovery_after_a_clamped_close_pays_an_unfunded_gain` |
| A2 | **Stranded sats.** A long facing a defaulted 100x short keeps a gain cap equal to the short's old margin. Losses later collected from other accounts never reach it. | 2 short 100x vs 1 at 100,000; 2 buys from 3 at 102,000; 1 sells to 3 at 104,000 | 3 pays 18,854, 1 receives only 10,000: **−18,854 sats** leave the accounts with no ledger entry | `a2_a_gain_capped_at_a_stale_counterparty_margin_strands_sats` |
| A3 | **Phantom backing.** After a novated close, the new lot's `opp_margin` is the closing leg's margin, which margin release returned to the closer's free balance. It is not committed anywhere. | 1 long vs 2 at 100,000; 1 sells to 3 at 101,000 with a 100x leg | long lots claim 9,901 sats of short margin; the open short (2) has 1,000,000 committed | `a3_a_novated_lot_is_backed_by_released_margin` |
| A4 | **Rounding drift.** Without any clamp (1x legs, ±20 USD moves), half-even per-slice payouts and floored margin splits leave a residue on a flat book. | 4 seeded random sequences of 40 fills, then flattened | flat-book sums 1, 0, −2, −3 sats | `a4_rounding_drift_without_clamps` |
| A5 | **Random sequences.** Seeded random fills over 4 accounts (price walk with ±6% jumps, leverage 1x–100x, partial closes, flips), then flattened. | 6 seeds × 40 fills | every seed breaks conservation; running surplus paid up to **198,804 sats**; flat-book residues from −35,585 to +130,002 | `a5_random_sequences` |

Per-account conservation (`free + resting + pending + committed + paid_fees == cap + realized_pnl`)
holds in every case; what fails is the cross-account sum, i.e. the venue's own solvency. A1-type
sequences are what a liquidation engine produces: a liquidated account is closed near or past its
bankruptcy price against whoever is bidding, while its original counterparties stay open.

## 2. Multilateral clearing (V3)

### Valuation

Every lot carries an exact entry value in sats, `value(qty, price) = floor(qty · 1e8 / price)` of
its opening leg, split with remainders kept on partial closes (`Position` keeps it parallel to the
lots; `Lot` is unchanged). Each closed slice realizes its **unclamped** PnL against the slice of the
closing leg's value (telescoping split, exact in sum): `entry − exit` for a long, `exit − entry` for
a short. A fill's value enters its long and its short leg identically, so on a flat book the PnL of
all closes sums to exactly zero, at any prices and any split pattern. This removes A3 and A4 at the
root: the gain cap `opp_margin` is no longer used.

### One net amount per account per batch

`clearing::clear` runs once per committed batch over all its accounts:

1. Each account's legs net against its FIFO lots (`positions::settle`); its PnL is summed over
   every slice it closed (`ClearingRow::pnl`).
2. **Losses** are collected from the margin those closes release, then from the loser's own
   deferred claim. The rest is the account's `shortfall` (closed past its bankruptcy price).
3. **Default waterfall** for the batch's total shortfall, recorded in `BatchClearing::layer`:
   1. defaulter's released margin and own claim (step 2: `Margin`, `OwnClaim`);
   2. the venue's clearing fund (`Fund`);
   3. pro-rata haircut on every outstanding winning claim: deferred claims of all accounts (in
      key order) and this batch's gains (in batch order), floors first, the remainder one sat at
      a time (`Haircut`); haircuts of accounts not in the batch are listed in `claim_haircuts`;
   4. whatever no claim can absorb is carried (`Carried`) and haircuts the next gains first.
4. **Gains** and the batch accounts' deferred claims are paid in cash from the clearing pool,
   pro rata when the pool cannot pay all of them. The unpaid part is a deferred claim, paid in
   the next batch the account is part of. The pool never pays cash it does not hold.

Each row's `net = paid − collected` is the one sats amount the channel adapter moves on that lane;
the pool's own line is `cash_after − cash_before`. The account's `Settlement::payout` becomes
`released − collected + paid`, so `realized_pnl` moves by exactly `net`.

### Invariants (checked on every batch, every test)

* `Σ row.net + (cash_after − cash_before) == 0` for every batch (`clear` rejects otherwise).
* `cash ≥ 0`: the pool (fund plus collected losses minus paid gains) never fronts.
* `Σ realized_pnl + cash == fund0`: every sat an account realized came out of, or went into,
  the pool.
* Clearing identity `cash − claims − fund + carry == book`, where `book` is the signed entry
  value of every open lot (long `+`, short `−`). Proof sketch: opening a fill adds `+v` and `−v`
  to `book`; closes change `book` by `−Σ pnl`; collections, payments, deferrals, fund use and
  haircuts change the left side by `GL − GG` (gross losses minus gross gains of the batch),
  which is `−Σ pnl`.
* **Solvency on a flat book.** With no open lots, `book = 0`, so `cash = claims + fund − carry`.
  Carry is non-zero only after the fund and every claim are exhausted, which with `cash ≥ 0`
  forces `carry = 0`. So the pool holds **exactly every deferred claim plus the unused fund**, and
  `Σ realized_pnl + claims == fund0 − fund`: winners are owed precisely what losers paid plus the
  fund used.

`a5_random_sequences` replays the six V2-breaking seeds under V3 with funds of 0, 30,000 and
10,000,000 sats (18 runs of 40 random fills plus the flattening fills): all invariants hold on every batch, and the runs
reach every waterfall layer (with fund 0: 23 haircut and 25 carried batches; with 30,000: 17 fund,
10 haircut, 15 carried) and 79 deferred-claim rows.

Under V3 the A-sequences give: A1 (fund 0) 1 −10,000, 2 0, 3 +10,000 (3's gain haircut by the
carried 10,408); A1 (fund 50,000) 3 is paid 20,408 and the fund ends at 39,592; A2: 1 receives
28,854 (2's margin plus 3's loss), sum zero; A4: zero residue on every seed.

### Margin model decisions

* **Isolated per batch.** A defaulter's loss reaches the margin released by its closes in that
  batch and its own deferred claim, never its free balance or the margin of lots it keeps open.
  This keeps the DLC promise that a loss never exceeds the margin behind the closed exposure.
* **No fronting.** A gain realized while its losing counterpart is still open is paid from the
  pool if the pool holds the cash (the fund counts) and deferred otherwise. A venue that wants
  winners paid at once posts a clearing fund; the fund is fronting liquidity and the first loss
  layer at the same time.
* **Deferred claims move only with the account's lane.** Cash can only move on lanes that sign the
  batch, so a deferred claim is paid when its account is next in any committed batch.

### Acknowledgements and replay

`DurableTieredRouter::enable_clearing(fund_sats)` journals `EnableClearing{fund_sats}` once
(margin release must already be active). The HFT-05 `DurableRouter` gains the same call and V3 tag; the tests drive the tiered router only. The ledger
opens from current positions and balances: `cash = fund0 − Σ realized_pnl`, and fund (or carry)
is set so the identity holds; `legacy = cash − book − fund0` records what V2 history left behind
(positive: stranded sats, which become fund capacity; negative: paid-out gains no loser funded,
which reduce it). Journals without the event replay exactly as before (V1/V2 tags, V2 settlement
values); a batch prepared before the switch commits under V3.

After the switch, Commit acknowledgements use `SHZ/HFT06/CHANNEL-ACK/V3` (`SHZ/HFT/CHANNEL-ACK/V3`
for HFT-05): the V2 message (with `Settlement::payout` the cleared cash credit), then byte `2`, the
lane's `ClearingRow`, and `BatchClearing::digest()` (tag `SHZ/HFT/CLEARING/V1`) over every row, the
non-participant haircuts, shortfall, fund use, haircut, layer and pool totals. Every lane therefore
signs the whole net settlement vector. `c3_acknowledgements_bind_the_clearing` rebuilds the digest
independently; `c4_enabling_on_a_live_journal_folds_v2_history_and_replays` switches on mid-journal
after the A2 sequence and reopens the journal to the same state.

### Read API (for the venue)

* `clearing(sequence) -> Option<&BatchClearing>`: rows (pnl, released, collected,
  own_claim_used, shortfall, haircut, claim before/after, paid, net), `claim_haircuts`,
  `shortfall`, `fund_absorbed`, `haircut`, `layer`, pool cash before/after, fund, carry, claims.
* `clearing_state() -> Option<&ClearingState>`: `claim(channel)`, `claims()`, `cash`, `fund`,
  `carry`, `fund0`, `legacy`.
* `clearing_summary() -> Option<Summary>`: totals plus `book` and `identity` (always 0).
* `clearing_active()`, and `Position::pnl_at(price)` / `Position::book_value()` for the exact
  unclamped valuation that clearing settles on.

All result types derive `Serialize`.

## 3. Liquidation tie-in

Liquidation closes are ordinary reduce-only fills, so they clear like any other batch. Under V3 a
lot's loss side is unchanged (bankruptcy price depends only on its own margin), so a risk monitor
built on `InverseContractSpec` liquidation prices stays correct for losers. The gain side differs:
V3 no longer caps a lot's gain at `opp_margin`, so equity of a winning position is
`margin + pnl_at(mark)`, not the clamped `value_at(mark)`. A liquidation that fills past the
bankruptcy price shows up as a row `shortfall` and the batch `layer` (`Fund`, `Haircut` or
`Carried`), which is the signal for sizing the clearing fund.

### Closing legs need no free margin

With clearing active, a taker leg that reduces the account's position borrows its leg margin
from the lots it closes (`TieredRouter::closing_loan`): only the flip excess and the taker fee
(zero on the Standard tier) come from `free`. The closable quantity is the opposite lots minus
every unresolved leg of the account on the leg's side, a lower bound on what the leg closes
whatever earlier batches do, so two closes in flight never borrow the same lot margin twice.
Between match and resolution the loan sits in `pending` and `committed` is lower by it; a
Commit repays it from the closing leg's margin that settlement credits back, a fenced abort
from the refund, so `committed == position margin` holds again after every resolution.
Maker quotes still hold their full margin from `free` when posted. Without clearing (old
journals) the check is unchanged. Tests: `p1_a_reducing_leg_needs_no_free_margin` (0-free
long closes and ends flat with its payout; a 0-free loser with a 100x and a 1x lot closes
both), `p2_a_flip_needs_margin_for_the_excess_only` (exact excess margin passes, one sat less
is refused), `p3_aborted_or_repeated_closes_do_not_double_borrow`. The perp-only rule here is
the max-loss delta for inverse perps; it is to be replaced by `shz_margin::payoff::margin_delta`
once that lands.

## 4. Deploying

Not deployed. Deploying needs the venue to call `enable_clearing(fund_sats)` after
`enable_margin_release()` in `Venue::open` (the change is the venue session's; `crates/shz-venue`
is not touched here). Effects on the live venue:

* one journaled `EnableClearing` record; the existing journal is folded in (`legacy` reports what
  V2 left behind);
* Commit acks switch to the V3 tag; the venue's simulated adapter computes them through
  `ack_message`, so it keeps working unchanged; anyone signing by hand must sign the V3 message;
* realized PnL is paid from the pool: with a zero fund, early winners see deferred claims until
  the matching losses are collected; with a fund they are paid at once;
* winners are no longer capped at their opening counterparty's margin; losers are capped at the
  margin their closes release, as before.
