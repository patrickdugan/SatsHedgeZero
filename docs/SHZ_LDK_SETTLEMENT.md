# LDK settlement of the venue's clearing (G-LN-1a)

The venue clears each committed batch multilaterally into one net sats amount per account
(`ClearingRow::net`, docs/SHZ_VENUE_CLEARING.md). Until now the channel adapter that moves
those amounts was simulated. `crates/shz-ldk` moves them through real LDK channel updates on
regtest and binds the persisted channel state of both channel parties to the batch's V3
acknowledgement.

Code: `crates/shz-ldk` (`journal.rs`, `node.rs`, `adapter.rs`), one read API in
`crates/shz-dex/src/routing/tiered_durable.rs` (`planned_clearing`). Test:
`crates/shz-ldk/tests/regtest_settlement.rs`.

```
SHZ_BITCOIND=<path to bitcoind 31.x> cargo test --locked -p shz-ldk -- --ignored --nocapture
```

`SHZ_LDK_RECEIPT=<file>` also writes a JSON receipt of every batch.

## Dependency cost

Measured before adding it, in a scratch crate with the same dependencies and the workspace's
dev profile (no debuginfo, dependencies at `opt-level = 2`), Rust 1.99 MSVC:

| Item | Size |
| --- | --- |
| Registry download (`lightning` 0.2.8, `lightning-net-tokio` 0.2.0, `bitcoin` 0.32, `secp256k1` 0.29, `tokio` and their dependencies) | 75 MB |
| Target directory for a binary using them | 236 MB |

D: had 2.2 GB free, so it fits. `ldk-node` was not used: it hides the `Persist` layer this gate
depends on and pulls in a wallet, Esplora/Electrum clients and SQLite.

## Topology

* One LDK node for the venue (the clearing pool) and one per account.
* One lane = one channel between the venue node and that account's node. The lane's
  `BtcOutPoint` is the channel's funding outpoint (txid in internal byte order,
  `Txid::to_byte_array`). The venue's allocation registry is built from these outpoints.
* Peers talk over loopback TCP (`lightning-net-tokio`). Bitcoin Core regtest is the chain
  source (blocks fed through `chain::Listen`), the broadcaster and the funding wallet.
* Payments are single-hop keysends over the lane's own channel (`DirectRouter`): `net > 0`
  the venue pays the account, `net < 0` the account pays the venue. No routing fee exists on a
  direct channel. The payment id is `tagged_hash("SHZ/HFT06/LDK-PAYMENT-ID/V1", sequence ‖
  outpoint)`, so LDK refuses to pay one lane twice for one batch.
* Node settings: `max_inbound_htlc_value_in_flight_percent_of_channel = 100` (a lane's net
  may use the whole balance), constant 253 sat/kW feerate (commitment fees never change, so a
  holder balance moves by exactly the payments), no anchors, 3 confirmations.

Margin is not in the channel. DLC collateral stays outside LDK channel commitments as decided in
docs/SHZ_HFT_06_LDK.md; the channel carries the net cash the clearing moves.

## Commitment evidence

LDK emits no event for a commitment number or `revoke_and_ack`. Every channel state change
does pass through `Persist` on the `ChainMonitor`, and LDK sends the counterparty the
messages for a new state only after the monitor update completed. `JournalingPersist<P>`
wraps the real persister (`FilePersist`: one file per monitor, written to a temporary name,
fsynced, renamed):

1. the inner persister writes the monitor durably;
2. on `Completed`, a `MonitorRecord` is derived from the monitor just written and appended to
   the node's lane journal, then fsynced;
3. only then `Completed` goes back to LDK. A journal write failure returns
   `UnrecoverableError`, so LDK cannot advance the channel without a record. An inner
   `InProgress` is passed through with no record: asynchronous persistence has no evidence path
   yet.

`MonitorRecord`: monitor name (`<funding txid>_<index>`), channel id, funding outpoint,
`get_latest_update_id()`, SHA-256 of the serialized monitor, the holder balance on the current
holder commitment (`Balance::ClaimableOnChannelClose`, excluding the commitment fee and HTLCs),
and the pending-HTLC amount (zero exactly when no HTLC is on the persisted state). Its digest is
`tagged_hash("SHZ/HFT06/LDK-MONITOR-RECORD/V1", encoding)`.

The lane journal is append-only: `magic ‖ (len ‖ record ‖ digest)*` with
`digest = tagged_hash("SHZ/HFT06/LDK-LANE-JOURNAL/V1", previous ‖ frame number ‖ record)`. A
torn or altered frame fails the read.

## One batch

1. The router seals and prepares the batch (all owners approve).
2. `DurableTieredRouter::planned_clearing(sequence)` returns the `BatchClearing` a Commit
   would apply (prepared batch at the head of the queue only). It is the same computation the
   V3 acknowledgement message and `resolve` use.
3. `LdkSettlement::settle(sequence, &clearing)` walks the rows in batch order. For each lane
   with `net != 0` it sends the keysend, waits for `PaymentSent` with a preimage that hashes to
   the payment hash (`PaymentFailed` is an error), then waits until both nodes list no HTLC on
   the channel and both nodes' latest journal records show no pending HTLC and exactly the
   balance the ledger implies: `owner = owner_base + Σ net`, `venue = venue_base − Σ net`.
   Lanes with `net == 0` take the current records after the same check.
4. Evidence per lane:
   `tagged_hash("SHZ/HFT06/LDK-MONITOR/V1", sequence ‖ outpoint ‖ net ‖ payment hash ‖ venue record digest ‖ owner record digest)`.
   The ack's next head: `revision + 1`, `commitment + 1`,
   `state = tagged_hash("SHZ/HFT06/LDK-LANE-STATE/V1", previous state ‖ evidence)`. The
   initial head (`commitment 0`) binds the baseline records of both sides.
5. Before signing, every signer runs `attest` on its own journal file, re-read from disk and
   chain-verified: the record the settlement names for its side is journaled, no later channel
   update superseded it, no HTLC is pending on it, its balance equals the ledger's, and the
   evidence is this settlement's digest. Owner checks the account node's journal, the venue
   (pinned peer) the venue node's, the monitor both.
6. The three BIP340 signatures go over the V3 message (`ack_message`), which binds the lane's
   clearing row and the digest of the whole net vector; `resolve` commits the batch.

`Head::commitment` keeps HFT-05's rule (exactly one step per Commit). LDK's own counter, the
monitor `update_id`, is not one step per batch (an HTLC add, its `commitment_signed`,
`revoke_and_ack` and the removal are several updates), so it is carried inside the evidence
through the records rather than in `Head::commitment`.

## Regtest result

`ldk_lanes_move_the_cleared_net_amounts`, Bitcoin Core 31.1 on Windows, 2026-11-26: passed on
four consecutive runs, about 10 s each.

Setup: venue node plus three account nodes; the venue opens a 1,000,000 sat channel to each
account and pushes 400,000 sats; 6 blocks; all channels usable. The venue router is built on
those funding outpoints with margin release and multilateral clearing (fund 50,000 sats). Six
1,000 USD trades replay the A1 and A2 sequences of docs/SHZ_VENUE_CLEARING.md, one batch each.
Baselines: account 400,000 sats, venue 599,817 sats per lane (600,000 less the 183 sat
commitment fee the opener pays).

| Batch | Trade | Layer | Rows (lane: net) | Pool net | Fund after |
| --- | --- | --- | --- | --- | --- |
| 1 | 1 long 100x vs 2 at 100,000 | none | 1: 0, 2: 0 | 0 | 50,000 |
| 2 | 1 sells to 3 at 98,000 (past bankruptcy) | Fund | 1: −10,000, 3: 0 | +10,000 | 39,592 |
| 3 | 2 buys from 3 at 100,000 | none | 2: 0, 3: +20,408 | −20,408 | 39,592 |
| 4 | 2 short 100x vs 1 at 100,000 | none | 1: 0, 2: 0 | 0 | 39,592 |
| 5 | 2 buys from 3 at 102,000 (past bankruptcy) | Fund | 2: −10,000, 3: 0 | +10,000 | 29,984 |
| 6 | 1 sells to 3 at 104,000 | Margin | 1: +38,462, 3: −18,854 | −19,608 | 29,984 |

After every batch the test asserts, for each lane, that what the channel moved equals the
account's `realized_pnl`, that the owner's persisted monitor shows `400,000 + realized` and the
venue's `599,817 − realized`, that the venue's channels together moved by the pool's
`cash − fund0`, that the committed clearing equals the one the channels moved, and that the
clearing identity is 0. Final: realized 1: +28,462, 2: −10,000, 3: +1,554; venue channels
−20,016 in total, which is the 20,016 sats of fund used; pool cash 29,984.

Each non-zero lane payment advanced both monitors by 5 updates (`update_id` 0 → 5 → 10 on lanes
1 and 3), so `Head.commitment` could not have tracked `update_id` one step per batch.

The test also checks the signer guard: with the ledger amount one sat above what the
persisted monitor shows, `attest` returns `Balance`, and with evidence that is not this
settlement's digest it returns `Evidence`.

CI: `.github/workflows/shz-ldk-settlement-regtest.yml` runs the same test on Linux against
the SHA256-pinned Core 31.1 tarball and annotates the receipt.

## Crash recovery (G-LN-1b)

**Persistence order.** LDK accepts a `ChannelMonitor` that is *behind* the `ChannelManager`
(the manager replays its in-flight monitor updates on load); a monitor *ahead* of a stale
manager makes LDK force-close the channel. So `JournalingPersist` answers every `Persist`
call `InProgress` and queues it, and each node's worker flushes in this order:

1. `ChannelManager` serialized, fsynced, renamed over `manager.bin`;
2. each queued monitor written by the inner persister, its `MonitorRecord` appended to the
   lane journal and fsynced;
3. `ChainMonitor::channel_monitor_updated` for each queued update id.

On disk the manager is never behind a monitor, and the peer receives a new state only after
step 3, so every state it can see has a journal record. A lane counts as settled only when
the journaled record's `update_id` equals the live monitor's, so an ack never names a record
that a queued write is about to supersede.

**Restart.** `LdkNode::restart` reads every `*.monitor` file, decodes `manager.bin` with
`ChannelManagerReadArgs` over those monitors, hands the monitors to the `ChainMonitor` with
`load_existing_monitor`, reopens the lane journal (chain verified, latest record per channel
rebuilt) and syncs blocks from the manager's best block. Peers reconnect and the channel
reestablishment finishes or fails what was in flight.

**Adapter state.** `LdkSettlement` writes `settlement.json` (fsync, atomic rename) after `bind`,
before every payment (sequence, attempt, payment hash in flight) and after every lane (Σ net
moved, last settled batch, its payment hash). `LdkSettlement::load` reopens it. Payment
preimages are derived from a per-venue random salt, the batch, the lane and the attempt, so
the payment hash is on disk before the payment exists.

**Resume rule.** `settle` on a batch that is still Prepared waits, per lane, until neither
node has an HTLC on the channel or a pending outbound payment, then reads both journaled
balances:

* pre-batch balance: the lane is paid with a new attempt (new payment id and preimage);
* post-batch balance: the lane already moved (a payment that completed before or during the
  crash); it is not paid again and the in-flight hash goes into the evidence;
* anything else: error, nothing is signed.

So every lane ends at exactly its pre- or post-batch balance, and the batch resolves only
once all lanes are post-batch, which is the clearing ledger's Commit. No LN payment is
reversed; a lane whose HTLC failed is simply at pre-batch and is paid again.

**Test.** `ldk_batches_survive_node_crashes_mid_settlement` runs the same six batches with
three crashes, each armed with `LdkNode::crash_at` to stop the node's worker dead inside a
flush and drop its connections:

| Batch | Node | Crash point | Then |
| --- | --- | --- | --- |
| 3 (venue pays account 3) | venue | after `manager.bin`, before the monitor | whole venue restarts: LDK node from disk, router journal reopened (`DurableTieredRouter::open`, batch still Prepared), adapter reloaded from `settlement.json` |
| 5 (account 2 pays venue) | account 2 | after manager and monitor, before `channel_monitor_updated` | account node restarts, reconnects |
| 6 (venue pays 1, account 3 pays venue) | account 3 | after `manager.bin`, before the monitor | account node restarts, reconnects |

Each time `settle` fails while the node is down, the batch stays Prepared, and after the
restart `settle` completes it and `run` checks the ledger as in G-LN-1a. Result on Core 31.1,
2026-11-27: both tests passed (40 s together). Final balances and every lane's monitor
`update_id` (5 per payment) match the crash-free run exactly, so no lane was paid twice and
none was skipped. A second run to confirm stability was blocked: another session's
in-progress edit to `crates/shz-dex/src/routing/options.rs` did not compile at the time.

Not covered by 1b: a crash *between* blocks (no blocks are mined during the batches, so
monitors and manager share a best block on restart), and force-close handling (none occurred;
the adapter does not handle a closed lane).

## What this does not cover

* **Cross-lane atomicity.** Lanes settle one after another. If a lane fails, the lanes before
  it have moved and the batch stays unresolved: nothing is signed and no reservation is
  released, as HFT-05 requires. `settle` with the same batch skips settled lanes and retries
  the rest. Reversing a moved lane is not implemented.
* **Independent monitor (G-LN-1c).** The monitor signer here reads the venue's own journal
  file. A replica fed from a separate process is G-LN-1c.
* **Fees.** `fee_evidence` is zero; a lane whose batch fee is non-zero cannot resolve with this
  ack. The Standard tier used in the test charges no fee. BOLT12 fee collection is a separate
  gate.
* **One channel per account.** `DirectRouter` pays over the payer's only usable channel to the
  payee; several lanes between the same two nodes would need per-lane channel selection.
* **Asynchronous persistence.** `InProgress` from the inner persister yields no record.
* Regtest only. Crashes are simulated in-process (worker stopped dead, sockets dropped), not with a process kill.
