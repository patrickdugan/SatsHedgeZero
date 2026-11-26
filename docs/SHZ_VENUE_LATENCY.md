# SHZ venue latency: front-end execution and back-end clearing (2026-11-26)

Measured on the public testnet deployment at https://shz-venue.170-75-168-145.sslip.io/ (witness host:
1 vCPU, 2 GB RAM, shared with the FROST relay, five FROST members, the public relay and a pruned testnet4
node). Venue build `dc2ace0` on `main`. Tools: `ops/venue-bench/`, `crates/shz-dlc/examples/dlc_bench.rs`.
Raw rows: `ops/venue-bench/results/2026-11-26/`. All figures are medians with p90 in brackets unless stated.

## Front end: from "take" to committed

`exec_bench.mjs` is a browser-equivalent client (same `ui/venue/crypto.js`, BIP340 in BigInt JS, about
17 ms per signature on the laptop). It sends a signed FOK take, then times the venue's WebSocket events.
Times are from the moment the take is sent.

| Run | n | take ack | fill seen | batch sealed | prepared | committed |
|---|---|---|---|---|---|---|
| self, on the host (localhost) | 28/30 | 19 ms [33] | 33 ms [48] | 94 ms [118] | 160 ms [222] | **200 ms [287]** |
| self, laptop over the internet | 20/20 | 295 ms [423] | 300 ms [428] | 368 ms [488] | 938 ms [1081] | **1.63 s [1.88]** |
| vs resident makers, 2 s maker poll | 12/12 | 285 ms [308] | 290 ms [313] | 353 ms [398] | 2.28 s [2.35] | **4.46 s [4.51]** |
| vs resident makers, 0.25 s maker poll | 10/10 | 295 ms [377] | 290 ms [422] | 351 ms [645] | 825 ms [1225] | **1.34 s [1.97]** |

- **self**: the bench owns both sides (A posts 1 USD inside the makers' best quote, B takes it) and signs
  the moment approvals or acks come due, so the numbers are the venue's own.
- **vs resident makers**: a taker against `shz-venue-mm` and `shz-venue-mm-utxo`. Those makers sign batch
  approvals and channel acks in their poll loop.
- Network: the laptop's TCP connect to the host is about 260 ms, so one HTTP request costs about one
  round trip. In the 2 localhost failures the bench maker's posts were refused with Capacity, so the takes found NoLiquidity (finding 4).

Venue-side breakdown (venue clock, from the batch record) for the localhost run: match -> 100 ms window end
41 ms [62], window end -> sealed 21 ms [23], sealed -> prepared 52 ms [81], prepared -> committed
51 ms [81], **match -> committed 167 ms [238]**. Over the internet, each settlement phase costs one signing
round: the client fetches its account and posts the signatures, about 2 round trips, 540-600 ms each.

What a user sees: the fill is confirmed in one round trip (about 300 ms from this laptop, about 35 ms
next to the host). The batch commit lands about 1.3-1.6 s after sending from this laptop and 0.2 s
next to the host.

## Back end: oracle, FROST, DLC, CETs

### Oracle packets (live, every 5 s)

`oracle_pipeline.py` on the host: two samples of 132 and 110 packets, all VALID, signed by 3 of 5.

| Stage | sample 1 median [p90 / p99] | sample 2 median [p90 / p99] |
|---|---|---|
| slot -> last fast-source fetch | 124 ms [312 / 381] | 125 ms [309 / 342] |
| fetch -> assembled body | 3 ms [10 / 131] | 3 ms [17 / 294] |
| assembled -> FROST-signed, published and verified by the venue | 249 ms [435 / 1280] | 248 ms [457 / 1031] |
| **slot -> verified mark in the venue** | **397 ms [663 / 1604]** | **398 ms [698 / 1279]** |

A FROST round, with Python members over localhost HTTP, costs about a quarter second. The p99 tail rises
when the shared CPU is busy: sample 1 overlapped a release build, and sample 2's 5.6 s maximum came
during a bench run. The venue's own BIP340 check of a packet is about 0.15 ms on the host (below).

### DLC attestation (live)

`dlc_watch.py` polled `/v1/dlc/events` every 250 ms on the host. Events are announced about 60 min
before maturity (15-minute BTC/USD, 20 digit nonces, 3-of-5 FROST, 4-of-5 decision lock).

| Event (maturity) | attested after maturity | outcome |
|---|---|---|
| 04:30Z | 43.2 s | 60,953 USD |
| 04:45Z | 40.8 s | 60,940 USD |
| 05:00Z | 44.6 s | 60,898 USD |
| 05:15Z | 41.2 s | 60,817 USD |

Maturity to attestation: **about 42 s** (40.8-44.6 s, 4 of 4 events attested, ±0.25 s poll resolution).

The outcome packet is ready about 0.4 s after maturity. The delay comes from the coordinator loop
(`ops/public-relay/dlc_coord.py`, `tick`, every 5 s). It attests only after maturity + 5 s. In the same
tick, before attesting, it runs the distributed nonce setup for the event that just entered the 60-minute
horizon. See finding 5.

### DLC / CET compute (`dlc_bench`, release)

A 1,000 USD inverse contract at 58,992 USD, 2x both sides, 20-bit outcome, CET ranges compressed to a
50-sat maximum payout error: **19,192 CETs** (same spec as `tests/frost_oracle_settlement.rs`).

| Operation | witness host (1 vCPU, Linux) | laptop (Windows) | count |
|---|---|---|---|
| BIP340 sign | 0.149 ms | 0.269 ms | 1 |
| BIP340 verify (per oracle packet) | 0.149 ms | 0.238 ms | 1 |
| BIP340 verify, joint check | 0.119 ms | 0.201 ms | 1 |
| precompute digit points | 3.2 ms | 5.7 ms | 20 digits |
| anticipation point from table | 4.4 µs | 8.8 µs | 1 CET (12-bit prefix) |
| adaptor sign | 0.158 ms | 0.348 ms | 1 CET |
| adaptor verify | 0.152 ms | 0.356 ms | 1 CET |
| adaptor complete | 0.1 µs | 0.2 µs | 1 CET |
| `offer_v0` | 0.012 ms | 0.081 ms | - |
| **`sign_and_activate_cets` (pre-sign every CET)** | **17.2 s** | **36.0 s** | 19,192 CETs |
| oracle attestation signing, single-key simulation | 0.056 ms | 0.033 ms | 20 digits |
| **`settle_on_chain_with_attestation`** | **6.6 ms** | **15.5 ms** | 1 CET of 19,192 |

Single runs for the lifecycle rows (one pass is 17-36 s). Per-operation rows: n = 500-20,000. The laptop
was the slower machine in this run.

- Pre-signing (`sign_and_activate_cets`) is the per-contract setup cost: 2 adaptor signatures and
  2 adaptor verifications per CET, 76,768 operations at 0.15-0.35 ms each. It runs once, when a
  contract is opened, not per trade.
- Settlement after attestation is cheap: 20 digit-signature verifications (about 3 ms on the host, 4.8 ms on
  the laptop), the CET lookup, and completing 2 adaptors.
- The attestation signing in the bench is a single-key simulation (scalar math), a lower bound. The live
  3-of-5 rounds are in the table above.

## Findings

1. **Signature requests were not pushed (fixed, `dc2ace0`).** Sealing and preparing a batch created
   pending approvals and acks, but only a `batch` event was streamed. A client that signs on `account`
   events waited for an unrelated change: 2.2 s median, 17.7 s p90 sealed -> prepared on localhost,
   with 16 of 20 timeouts. The venue now emits `account` at both points. The browser was not affected:
   it refreshes its account on `batch` events.
2. **Maker poll loop dominated commit time (fixed, `9ed1e72`).** The makers' 2 s poll put about 2 s on
   each phase. At 0.25 s, commit against them fell from 4.46 s to 1.34 s.
3. **One silent participant halted all clearing (fixed, see below).** Batches resolve strictly in sequence. `prepare`
   needs every account's approval, and the only alternative to commit, `FencedAbort`, also needs the
   owner's ack signature. Nothing times out. During this bench, one bench run exited before signing, and
   batch 22 sat in `sealed` and held every later batch until the leftover was signed. Any visitor can
   do this deliberately by trading and never signing. Fix: `DurableTieredRouter::expire` (journaled
   `Expire` event) accepts a `FencedAbort` of the head batch once the router clock is `ABORT_AFTER_US`
   (10 s) past its window end. Each lane needs the peer and monitor signatures; the owner's may be
   all-zero. A commit can never take this path. The venue applies it in `deadline_abort`. Verified
   with `ops/venue-bench/stall_check.mjs` against a local venue: the silent taker's batch aborted
   10.01 s after its window, the next batch committed 81 ms later, and the silent account went back to
   200,000 free with a flat position. After a restart the aborted batch restored with its fee-ledger
   entry reversed, and a second run passed.
4. **Margin was never released (fixed, `0c6e924`).** No path in `shz-dex` routing or `shz-venue`
   decreased `committed`: offsetting fills did not net, and positions never closed. Two bench accounts
   that were net flat after 48 alternating 5 USD fills had 196,949 of 200,000 sats committed and were
   refused with Capacity. Each 5 USD fill at 2x locked about 4,100 sats, so the 500,000-sat UTXO maker
   could do about 120 fills and the 200,000-sat demo maker about 48 before they stopped quoting for good.
   Now each account carries FIFO lots; a committed leg against the open side closes lots, releases
   their margin, and credits the lot's exact DLC payout at the closing price, with the settlement bound
   into every lane's channel ack (`docs/SHZ_VENUE_API.md`, Margin release). On deploy the live journal
   replayed unchanged and the one-time `EnableMarginRelease` rebuilt positions from its committed
   batches: the two 196,949-sat accounts went to 0 committed (realized +593 / -593), the UTXO maker
   from 57,504 to 0 (realized +140), every one of the 15 accounts conserved, and each account's
   committed equals the margin behind its open lots. A 60-trade self bench on one fresh pair of demo
   accounts then completed 60 of 60 (localhost, match -> committed median 169 ms, p90 230 ms), ending
   with both accounts at 0 committed and flat, realized +690 / -690
   (`results/2026-11-26/exec_self_local_release.jsonl`).
5. **DLC attestation waits behind nonce setup (open).** About 40 s after maturity, with the outcome
   packet ready at about 0.4 s. Attesting before setting up new events in `tick`, or running setup on its
   own thread, removes most of it. The remaining floor is the maturity + 5 s gate and one 5 s tick.
6. **CET pre-signing is 17 s per contract on the host (36 s on the laptop).** It is per contract, not per trade, but
   it scales with the CET count. Coarser compression, or parallel signing on a host with more than one
   core, are the levers. The witness host has one vCPU.

## Reproduce

```
# on the host (localhost numbers)
node ops/venue-bench/exec_bench.mjs --server http://127.0.0.1:8096 --mode self --n 30
python3 ops/venue-bench/oracle_pipeline.py --venue http://127.0.0.1:8096 --relay http://127.0.0.1:8091
python3 ops/venue-bench/dlc_watch.py --minutes 65
cargo run --release -p shz-dlc --example dlc_bench
# from anywhere
node ops/venue-bench/exec_bench.mjs --server https://shz-venue.170-75-168-145.sslip.io --mode mm --n 10
```

Each `exec_bench` fill holds about 4,100 sats on each side until a later committed fill offsets it
(finding 4), so `--mode self` alternating sides can run indefinitely on one pair of accounts.
