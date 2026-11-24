# SHZ HFT-06: tiered router and Lightning fee ledger

Code: `crates/shz-dex/src/routing/tiered.rs`, `tiered_durable.rs`, `ln_fees.rs`.
Tests: `crates/shz-dex/tests/hft06_router.rs`, `hft06_tiered_durable.rs`, `hft06_ln_fees.rs`.
Builds on HFT-01 (router, partitioned collateral), HFT-03 (100 ms batches), HFT-04
(oracle packets) and HFT-05 (durable WAL, signed channel acknowledgements).

## 1. Tiered admission and matching (`tiered.rs`)

One `TieredRouter` per router id, with its own private book and the same
`Registry`/`Allocation`/`Balance` partition as HFT-01. HFT-01..05 code paths are unchanged.

| Element | Behaviour |
|---|---|
| `FeedTier` | `Standard`, `Intermediate`, `Premium` |
| `TariffSchedule` | versioned ppm per tier, maker and taker. Candidate: Standard 0/0, Intermediate maker 0 (configurable) / taker 50, Premium 20/200. Taker <= 200 ppm and maker <= taker per tier. `id()` is a tagged hash of every field. |
| `ExecutionPolicy` | per-tier feed delay and order delay, selected by `Arm`: `FeedOnly`, `SchedulerOnly`, `Combined`. The inactive mechanism is ignored by every accessor and by `id()`. Default lags are Standard 200 ms, Intermediate 100 ms, Premium 0. |
| `Entitlement` | `(client, tier, tariff_version, valid_from, valid_until, relay_key)` signed with BIP340 under `SHZ/HFT06/ENTITLEMENT/V1` by the pinned relay operator key. |
| `IntentV6` | owner-signed under `SHZ/HFT06/INTENT/V1`. Binds scope, router, channel, owner, sequence, expiry, action, side, tier, tariff version, entitlement digest, execution policy id, quantity, limit, leverage, fee caps, `max_mark_age_us`, `early_window_opt_in`, cancel target. |
| `MarkView` | the only oracle input: packet digest, sequence, price or HOLD, boundary, public release. `from_packet` builds it from an HFT-04 `Packet`; certificate verification stays upstream. |

Admission rejects: wrong scope or router, bad signature, non-increasing sequence per channel,
tariff or execution-policy mismatch, missing/expired/forged/wrong-client/wrong-tier entitlement,
fee cap below tariff, and expiry at or before the due time. Due time is `now + order_delay(tier)`.
An entitlement that lapses while an order is queued rejects at execution.

Matching is fill-or-kill against one maker quote with price-time priority:

- A mark is visible to a tier at `boundary + feed_delay(tier)`. HOLD marks are visible to every
  tier at their boundary, so a HOLD cannot be hidden from a slower tier.
- A mark is privileged while `now < public_release_us`. During that time a taker only matches makers
  with `early_window_opt_in`; public-only resting orders are skipped (`EarlyWindowProtected`).
- Stale-quote guard: the match is refused when mark age exceeds `min(taker, maker).max_mark_age_us`
  (`StaleMark`). The 200 bps collar applies to posts and to every candidate maker (`Collar`).
- HOLD, no visible mark, or `set_emergency_hold(true)` reject posts and takes. Cancels always succeed.
- Cancels carry zero order delay for every tier and `process_one` drains all due cancels before any
  due post or take.

`TieredFill` wraps a standard `Fill` and binds the packet digest, mark sequence, both entitlement
digests, tariff version, execution policy id, both tiers and the early-window flag.
`Fill.mark_id = tagged_hash("SHZ/HFT06/FILL-BINDING/V1", packet_digest || tariff_version ||
execution_policy_id || maker_entitlement || taker_entitlement)`. Maker fees use the maker tier's
`maker_ppm` with HFT-01 cumulative rounding; taker fees use the taker tier's `taker_ppm`.
`RevenuePolicy` splits each fill's fees: oracle = floor(total * bps / 10000) (default 7000), router =
remainder, so the split conserves exactly.

`seal_batch` uses `Batch::seal_legs`, the single implementation that `Router::seal_fill_batch`
also calls. Existing batch digests are unchanged (all HFT-01..05 tests pass).

### No double counting of lead

`ExecutionPolicy::lead(a, b)` returns the feed lead and the order lead separately. `FeedOnly` and
`SchedulerOnly` report the one active mechanism. `Combined` reports both and an `effective_us` equal
to their sum with `double_counted = true`; that sum is a configured bound, not a measurement. A
benchmark must report each mechanism separately and the measured combined advantage, never the sum of
configured delays.

### Confidentiality

The engine takes `MarkView` in and returns nothing about resting orders to the oracle side. It owns no
callback, channel or trait object toward the oracle.

## 2. Lightning fee ledger (`ln_fees.rs`)

`FeeLedger` records obligations per `(router id, batch sequence, batch digest)`:

`Accrued` (sealed `Batch` observed) -> `Committed` (an `AckBundle` with `Disposition::Commit` that
equals the bundle the `DurableRouter` or `DurableTieredRouter` recorded, with each channel's `fee_evidence`) or `Reversed`
(`FencedAbort`). Collection is recorded per recipient when `LightningAdapter::verify_fee_receipt`
accepts a `FeeReceipt`.

Per recipient: `accrued`, `reversed`, `committed`, `collected`, `outstanding = committed - collected`.
Accrued-only and reversed amounts are never revenue and never instructed.

- `RecipientPolicy` splits `oracle_due_sats`: upkeep share `floor(due * bps / 10000)`, the remainder
  across operators by weight with largest-remainder rounding (ties by ascending key). The router gets
  `router_due_sats`. Sum equals `oracle_due + router_due` for every batch. DLC settlement fee is
  `DLC_SETTLEMENT_FEE_SATS = 0` and each observed leg must carry the zero DLC fee policy.
- Receipts: duplicates with the same payment hash are no-ops when identical and rejected when different.
  A receipt may not exceed the recipient's outstanding amount over its referenced committed batches.
  Amounts are whole sats expressed in msat.
- `GroupCommit { max_obligations, max_delay_us }`: `poll(now)` emits per-recipient
  `SettlementInstruction`s for committed, uninstructed batches once either bound is reached.
- Durability: hash-chained, length-prefixed journal, fsync before apply. Reopen replays to identical
  state, a torn or altered tail fails closed, and a persisted-but-unapplied event is applied on reopen.
- Disconnection: `AdapterError::Disconnected` leaves obligations outstanding. Time passing changes no
  quantity; only instruction emission can occur. The ledger holds no handle to channel balances.
- `reconcile(&router)` (either router) compares committed totals per role with `fee_totals()`, batch phases,
  digests and fee evidence, and reports `Mismatch` entries.

## 2a. Durable tiered router (`tiered_durable.rs`, gate G-LN-2)

`DurableTieredRouter` is the HFT-05 `DurableRouter` design applied to `TieredRouter`. Tests:
`crates/shz-dex/tests/hft06_tiered_durable.rs`.

- Journal: magic `SHZWAL06`, a genesis frame holding the configuration hash, then length-prefixed JSON
  events (`ingest_mark`, `submit` with its `Entitlement`, `process_one`, `set_emergency_hold`,
  `seal_batch`, `prepare`, `resolve`) chained by `SHZ/HFT/WAL-FRAME/V1`. Each frame is fsynced before
  the command is applied or answered. Rejected commands are journaled because they can advance the
  clock. A failed write poisons the writer. A torn or altered tail, a foreign magic, or a different
  configuration fails closed (`Corrupt`, `Config`). `open(.., Some(tip))` rejects a rolled-back valid
  prefix (`Rollback`). The file is locked exclusively for the writer lifetime.
- Configuration hash (`SHZ/HFT06/WAL-CONFIG/V1`): scope, router id, tariff id, execution policy id,
  revenue split, entitlement key, fee recipients, every allocation with both signatures, and each
  lane's peer, monitor and initial head.
- Resolution: `Sealed -> Prepared` (every channel owner's `BatchApproval` verifies) `-> Committed` or
  `Aborted` (`FencedAbort`). A bundle carries per-channel owner, peer and monitor BIP340 signatures,
  heads, evidence and fee evidence, in batch account order. Resolution is strictly in sequence, an
  exact retry is idempotent, a different bundle for a resolved sequence is rejected, and time alone
  never releases collateral. A fenced abort frees collateral, keeps the commitment head and cancels
  the batch's surviving maker quotes.
- Shared gate: `durable::plan_resolution` and `durable::ack_message` verify both routers. The HFT-05
  digest tag stays `SHZ/HFT/CHANNEL-ACK/V1`; the tiered router signs under `SHZ/HFT06/CHANNEL-ACK/V1`
  with its own configuration hash, so acknowledgements cannot cross routers.
- `ln_fees::ResolutionSource` (`batch`, `acknowledgement`, `fee_totals`, `next_resolution`) is
  implemented for both routers. `FeeLedger::observe_resolution` and `reconcile` accept either.
- Verified in the tests: replay after restart (book, marks, fills, balances, batches, phases), restart
  at every stage reaching the same state, crash between append and apply, torn and corrupt tails,
  configuration substitution on nine fields, pinned-tip rollback, the acknowledgement state machine,
  HFT-05 bundle and HFT-05 domain-tag rejection, and a premium/intermediate/standard loop with commits,
  one fenced abort, mock-adapter receipts and a clean reconcile.

## 3. Modelled versus external gates

Modelled and tested: tier and tariff logic, entitlement signatures, delay arms, early-window
protection, stale-quote and collar guards, HOLD, cancel priority, fee conservation, batch sealing,
the obligation state machine, receipt idempotence and overpayment checks, group commit, journal
recovery, the tiered durable router, and reconciliation against both routers, all with synthetic funds and a mock adapter.

External gates, not provided here:

- Real LDK commitment updates and channel monitors. `commitment_status` is a trait method with a mock.
- Real fee receipt verification. `MockAdapter` checks `sha256(preimage) == payment_hash` and a synthetic
  recipient signature; a production adapter must verify an actual Lightning payment.
- Real clocks and transport for feed timing, relay key custody and entitlement distribution.
- The ledger journal is single-writer and needs an independently stored tip for rollback detection.

`production_ready = false`.
