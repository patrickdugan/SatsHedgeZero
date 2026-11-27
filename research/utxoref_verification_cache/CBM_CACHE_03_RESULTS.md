# CBM-CACHE-03 results: incremental graph certificates for UTXORef clearing

Status: experimental library code and synthetic benchmarks. Production clearing
(`solve_and_verify_pnl_batch`, the durable book, signing, settlement roots) is unchanged except
for the Phase 0 book fixes. CPU only; no proofs, no GPU, no live funds, nothing deployed.

The four kinds of statement below are kept apart: **proven** (math notes, with proofs),
**finite audit** (exhaustive or randomized checks that passed), **measured** (wall time and
work counters on one machine), **projection** (economic consequences under stated assumptions).

## Phase 0: durable reservation book (fixed, CI green)

Commit `74035bf`. Both source-level concerns from CBM-CACHE-02 were real:

1. `reserve_before_signing` checked obligation replay against the book but checked vault inputs
   only against the caller's `snapshot.spent_outpoints`. A snapshot that left an already-spent
   vault UTXO out of its replay set was reserved. Fixed: inputs are checked against the book's
   durable `spent_outpoints`, and the snapshot's replay sets must contain the book's settled
   history (so the snapshot hash commits to it).
2. `confirm_active_chain` copied replay sets from a caller-supplied snapshot without binding it
   to the reservation. A substituted snapshot marked the wrong obligations consumed and the
   wrong outpoints spent. Fixed: the snapshot hash must equal the reserved
   `verified_batch.snapshot_hash`; otherwise the call is rejected without mutation.

`crates/shz-utxoref/tests/pnl_book_guards.rs` (6 tests): reject-without-mutation compared on the
serialized book; restart (serde round trip) at Ready, Reserved and Signed; two writers racing on
one head (`HeadHashMismatch`, then `ReservationActive`); reorg freeze blocks reserve and confirm.
Four of the six fail on the previous code. Callers (`shz-nova-bitvm` clearing_3party,
`shz-cli` mnr03_harness, `shz-hftd` engine) use genesis or epoch-1 books with empty history, so
the stricter rule does not change them. CI on `74035bf` (push and PR runs): every check green,
including strict workspace clippy (picked up from main's `9a7261a` via the merge commit
`4f563ec`) and the native replay workflow.

## Phase 1: math (proven)

`CBM_CACHE_03_MATH.md`. For the vault-funding network every feasible flow is a maximum flow
(the sink capacities bound the value), so a flow witness is a feasibility and optimality
certificate and a cut below demand is an infeasibility certificate. Transport conditions:
flow transport is exact and costs `O(|Delta|)` after a diff (T1); cut transport is sound and not
complete (T2); node insertion and deletion (T3); residual repair yields a maximum flow, with at
most `min(R, O(|V||E|))` augmentations where `R` is the sats the mutation moved (T4);
simultaneous mutations are the union (T5). Demand increases never transport a flow; this is why
batch growth needs repair rather than transport. Budgeted admission with unequal sizes and
savings is unsplittable flow on a path, which is strongly NP-hard. The ER-39 unit-cost greedy
is not optimal for it; the LP relaxation is a min-cost flow, giving an exact upper bound. What
transfers from BPD ER-27..42: bound screening (exactly, with integers), admission policies
(safely, because every certificate is re-verified), compact history and top-K selection. Flow
invariants do not come from ER.

## Phase 2-3: implementation (finite audit)

`crates/shz-utxoref/src/flow_cert.rs`, `src/clearing_gym.rs`, `examples/cbm03_gym.rs`,
`tests/flow_cert_differential.rs`. Experimental, not called by production code.

* `FlowProblem::from_snapshot` re-runs validation steps 1-5 of the solver with the same errors,
  then builds the network with stable node keys, merged parallel routes and a canonical
  commitment.
* Certificates are index-form flows and min cuts with a shared node-set frame (translated by key
  when the node set differs). The checks are exact and use checked integer arithmetic.
* Repair clips an old flow, cancels the resulting imbalances along the flow's own support, and
  augments.
* Cache: byte budget covering payloads, entry metadata and frames (each frame counted once).
  Policies: cold, exact memo, LRU, frequency, GDSF-style utility, and a causal online score;
  optional repair; optional compact frames (hash only).
* Offline bounds: min-cost-flow LP upper bound and density-greedy lower bound over the reuse
  structure of an unbounded run.

Audits that passed:

| audit | scope |
|---|---|
| gym candidates vs `solve_and_verify_pnl_batch` (accept/reject and exact deficit) | 15,975 held-out and 10,126 dev comparisons: every candidate up to 512 accounts, every 4th at 2,048, and every window's final batch |
| every cache arm vs cold verdict | 3,330 held-out arm replays over 17,955 candidates (and the 2,048 re-run below); 0 wrong verdicts, 0 false acceptances |
| policy x repair x budget unit sweep | 2 sizes x 2 connectivities x 3 regimes x 2 seeds x 6 policies x 2 x 3 budgets |
| tampered flow and cut certificates applied to the next candidates | 500+ cases; no tampered certificate proved a false verdict |
| random layered graphs with mutations, node deletion and insertion | 400 cases: transported flows only when cold is feasible, cuts respect weak duality, repair equals cold max flow |
| offline bounds vs brute force | 300 random instances: greedy <= optimum <= LP bound |

Deficits proven by a transported cut are lower bounds (13,277 held-out rejections were proven
with a bound below the exact deficit); a cold or repaired path reports the exact deficit.

## Phase 4: clearing gym (measured)

One Windows 11 laptop, release build of `cbm03_gym` (binary SHA256 in the receipts), one
process per configuration, sequential runs. Held-out seeds 101-103 were fixed before any
held-out run; dev seeds 1-2 were used for the smoke pilot and the arm settings (retrieval 4).
Each run: 8 batch-growth windows of 24 candidates (plus partial-fill retries and a payout
candidate), canonical settlement of each window's batch, mutation between windows. Window
latency = candidate construction (validation + network) + screening + the canonical settlement
solve, so it includes cache overhead and is the end-to-end clearing selection time of the
window.

Screening at a 1 MiB budget, held-out, 3 seeds per row (screen time summed; window percentiles
pooled over 24 windows):

| accounts | routes | regime | cold screen ms | repair screen ms | speedup | EK edge inspections (repair/cold) | cold window p50/p99 ms | repair window p50/p99 ms | windows >200 ms cold / repair |
|---:|---|---|---:|---:|---:|---:|---|---|---|
| 128 | sparse | stable | 24.9 | 7.8 | 3.2x | 0.104 | 6.1 / 7.2 | 5.5 / 6.3 | 0 / 0 |
| 128 | dense | churn | 28.8 | 9.1 | 3.2x | 0.108 | 6.7 / 9.5 | 6.0 / 8.6 | 0 / 0 |
| 512 | sparse | stable | 215.8 | 29.0 | 7.5x | 0.046 | 32.5 / 41.1 | 25.3 / 29.6 | 0 / 0 |
| 512 | dense | churn | 298.1 | 43.2 | 6.9x | 0.065 | 37.0 / 57.6 | 27.2 / 37.6 | 0 / 0 |
| 2,048 | sparse | stable | 2,924.9 | 143.9 | 20.3x | 0.023 | 228.5 / 330.7 | 122.9 / 148.3 | 24 / 0 |
| 2,048 | sparse | rotating | 2,973.6 | 173.0 | 17.2x | 0.032 | 229.4 / 325.3 | 121.3 / 148.9 | 24 / 0 |
| 2,048 | sparse | churn | 3,007.4 | 200.5 | 15.0x | 0.042 | 218.6 / 320.1 | 107.2 / 150.9 | 18 / 0 |
| 2,048 | dense | stable | 3,945.9 | 212.8 | 18.5x | 0.029 | 300.5 / 452.9 | 161.1 / 194.6 | 24 / 0 |
| 2,048 | dense | rotating | 3,975.6 | 261.0 | 15.2x | 0.035 | 312.4 / 481.9 | 166.0 / 217.6 | 24 / 1 |
| 2,048 | dense | churn | 3,828.7 | 257.7 | 14.9x | 0.043 | 280.7 / 463.2 | 145.5 / 217.7 | 24 / 3 |

"repair" is `repair_only`: on a miss, warm-start from the most recent feasible flow certificate,
with no transport retrieval. All sizes, connectivities and regimes are in
`cbm03_receipts/summary_heldout.md`. At 32 accounts repair is 1.5-2.3x faster than cold; at
8 accounts (two vaults) it is slower (0.53-0.66x), because the cold solve is a handful of
augmentations and the cache bookkeeping costs more than it saves.

Findings:

* **Repair carries the gain.** 97-99.5% of candidates go through repair at 128 accounts and
  above. Augmenting paths drop 10-50x. At 2,048 accounts a 24-candidate window fits in 200 ms
  at p99 on sparse routes, while the cold solver misses 66 of 72 sparse windows and all 72
  dense ones.
* **Transport rarely hits during batch growth** (negative result). Every accepted obligation
  raises some vault's demand, which by T1 can never transport. Exact-memo hits are 0-3%,
  structural transport (mostly cuts rejecting repeats of an infeasible candidate) 1-22%.
  Retrieval costs `O(|E|)` per tried cut, and below 2,048 accounts LRU transport without repair
  is slower than cold (0.72-0.97x). With repair, adding transport retrieval (`lru_repair`)
  halves repair's speedup.
* **Admission policy barely matters at these budgets** (negative result). Above 1 MiB every
  policy holds every useful certificate, and the hits differ by at most 1 in 308 between LRU,
  frequency and the causal score. The causal score is an online priority, not a trained model;
  no learned controller was trained, because there is no admission headroom to learn.
* **Frames dominate small budgets.** At 2,048 accounts one node-key frame is about 170 KB, so at
  64 KiB every certificate is bypassed and every arm is cold. Compact frames (32-byte node-set
  hash; reuse only on an identical node set, which holds for every gym trace) fix this:

| arm (2,048 accounts, 18 runs, 3,600 candidates) | 64 KiB screen ms | 1 MiB | 64 MiB | hits at 64 KiB | saved by hits at 64 KiB (insp.) | offline LP bound (insp.) |
|---|---:|---:|---:|---:|---:|---:|
| cold | 20,731 | 20,731 | 20,731 | 0 | 0 | 0 |
| repair_only | 20,769 (all bypassed) | 1,240 | 1,248 | 0 | 0 | 678,881,998 at >= 1 MiB |
| repair_compact | 1,726 | 1,627 | 1,633 | 8 | 19,824,835 | 678,881,998 |
| lru_repair_compact | 1,670 | 1,815 | 1,832 | 234 | 497,024,897 | 678,881,998 |
| lru (no repair) | 20,785 (all bypassed) | 20,587 | 20,799 | 0 | 0 | 678,881,998 at >= 1 MiB |

  The offline bound column is the min-cost-flow LP over the hits of an unbounded run, with the
  frame's bytes subtracted from the budget. At 64 KiB with compact frames, LRU captures 73% of
  that bound; at 1 MiB and above, the full-frame LRU captures 98% (665.4M of 678.9M). The
  greedy lower bound is within 16 inspections of the LP bound in every row, so the bound is
  essentially tight. The hits' savings are small next to repair's (repair alone removes 96.5% of
  20.7 s of screening). `repair_compact` is about 30% slower than `repair_only` at 1 MiB; the
  cause was not investigated.
* **The new bottleneck is candidate construction.** After repair, the window at 2,048 accounts is
  dominated by `FlowProblem::from_snapshot`: validation and network construction over
  string-keyed maps, re-run per candidate by design, plus the canonical settlement solve.
  Incremental candidate construction is the next lever; it was not built.
* **Memory.** Certificate cache peak is under 10 MiB at every budget; process peak RSS at 2,048
  accounts is 249 MiB, almost all of it the in-memory reference trace (thousands of candidate
  networks kept for replay).

Reproduce (Windows, git bash; Linux the same without `.exe`):

```sh
cargo build --release --locked -p shz-utxoref --example cbm03_gym
python research/utxoref_verification_cache/cbm03_sweep.py --bin target/release/examples/cbm03_gym --split dev --out research/utxoref_verification_cache/cbm03_receipts
python research/utxoref_verification_cache/cbm03_sweep.py --bin target/release/examples/cbm03_gym --split heldout --out research/utxoref_verification_cache/cbm03_receipts
python research/utxoref_verification_cache/cbm03_sweep.py --bin target/release/examples/cbm03_gym --split heldout --sizes 2048 --tag _2048v2 --out research/utxoref_verification_cache/cbm03_receipts
python research/utxoref_verification_cache/cbm03_summarize.py research/utxoref_verification_cache/cbm03_receipts/sweep_heldout.jsonl
cargo test --locked -p shz-utxoref
```

The `sweep_heldout.jsonl` and dev runs used binary SHA256
`e37a7da492a49c0c21179e69adba7568a87bcdf4ccacc45ceb08adbab163463b` (source `bc2d13f` plus the
`window_ms` output field). The `_2048v2` and Phase 5 runs used
`164f0d55f6710647e71d15955ce50e6b672d30e2589c96901e4241526f500942` (compact frames,
frame-corrected oracle); verdicts and cold work are identical between the two on the 2,048
configurations. Timings are single runs on one machine, not cross-hardware validated.

## Phase 5: where the capital bound moves (measured, then projected)

`cbm03_gym --phase5`: 4 windows of 400 candidates each (a saturating arrival stream), held-out
seeds 101-103, every regime. For each arm, the candidates are screened in arrival order until
the per-window compute budget would be exceeded. The budget covers candidate construction,
screening, and a reserve equal to the window's full-batch canonical solve time. The accepted
prefix is then settled by the canonical solver. "Windows over budget" counts windows where the
actual prefix settlement overran the reserve; the reserve is an estimate, so those windows are
reported, not hidden. Sums over 9 runs (3 regimes x 3 seeds) per row; full table in
`cbm03_receipts/summary_phase5.md`.

| accounts | routes | budget | cold: candidates cleared | repair: cleared | gross cleared cold / repair (Msat) | netting efficiency cold / repair | windows over budget cold / repair |
|---:|---|---:|---:|---:|---|---|---|
| 512 | sparse | 200 ms | 4,727 / 14,436 | 6,905 (1.46x) | 38.2 / 55.2 | 0.112 / 0.153 | 1 / 6 |
| 512 | dense | 200 ms | 2,265 / 14,436 | 3,611 (1.59x) | 36.7 / 57.4 | 0.070 / 0.115 | 8 / 8 |
| 512 | sparse | 50 ms | 1,197 | 1,680 (1.40x) | 10.0 / 14.4 | 0.024 / 0.047 | 4 / 6 |
| 2,048 | sparse | 200 ms | 220 / 14,436 | 497 (2.26x) | 2.0 / 4.8 | 0.000 / 0.000 | 10 / 7 |
| 2,048 | dense | 200 ms | 137 / 14,436 | 260 (1.90x) | 2.3 / 4.2 | 0.000 / 0.004 | 1 / 2 |
| 2,048 | either | 50 ms | 0 | 0-1 | 0 / 0.02 | - | 10-15 / 7-13 |

(netting efficiency = 1 - sum of positive net account deltas / gross obligation volume.)

What the measurements say:

* **Faster feasibility buys larger batches in a fixed window, which net more.** At 512 accounts
  and 200 ms, repair clears 46-59% more candidates. Gross cleared volume rises by the same
  factor, and netting efficiency rises from 0.11 to 0.15 (sparse) and from 0.07 to 0.12 (dense).
* **At 2,048 accounts both arms are construction-bound.** Building and validating one candidate
  network costs several milliseconds at this size. A 200 ms window clears at most 3.4% of a
  400-candidate stream even with repair, and nothing fits in 50 ms. Repair's 15-20x screening
  speedup becomes a 1.9-2.3x throughput gain here. Incremental candidate construction (sharing
  validation and the network across candidates of one window) is the lever that remains; it was
  not built.
* **The canonical allocation moves sats it need not move.** With no obligations at all (the
  2,048 rows at 50 ms clear nothing), the canonical solver's route allocations still send 75
  Msat (sparse) and 143 Msat (dense) across vaults. Edmonds-Karp picks the first shortest
  path, and a cross-vault route is as short as self-retention. The `lp_advance_sats` column is
  therefore an upper bound on the transfers a batch requires, not the requirement. A canonical
  min-cost allocation (cost on cross-vault edges, fixed tie order) would make it the
  requirement, and is also the canonical flow that section 6 of the math notes says
  certificates would need to replace the settlement; that changes settlement roots and needs
  the equivalence gate.

Capital-time projection (assumptions stated; not measured on any chain or channel). Take
`C = sum_i a_i (t_reusable,i - t_locked,i)` over collateral locked for clearing. Split the path
to reuse into compute (`t_c`: candidate screening plus settlement solve, measured above,
milliseconds), confirmation (`t_f`: 6 blocks = 3,600 s for an on-chain UTXORef settlement), and
cadence (`T`: the time an obligation that misses a window waits for the next one; 600 s if every
window is one on-chain settlement, 0.2 s for an LN-channel netting window). Then:

* **Compute-constrained reuse is negligible against confirmation.** For a batch's cross-vault
  advance `A`, compute contributes `A t_c` and confirmation `A t_f`. With `t_c` at most 0.2 s and
  `t_f` = 3,600 s, compute is at most 0.006% of the advance's capital-time, whatever the cache
  does. Measured compute capital-time at 512 sparse, 200 ms: 1.03e7 sat·s cold and 1.17e7 sat·s
  repair over 36 windows; repair is larger because it settles larger batches.
* **Deferral is where faster feasibility can matter.** An obligation that misses the window
  waits `T`. At 512 sparse, 200 ms, repair defers 60.2 Msat against cold's 77.1 Msat (36
  windows), so `Delta C = 16.9 Msat x T`. That is 1.0e10 sat·s (about 101 BTC·s, 2.8 BTC·s
  per window) at `T` = 600 s, and 3.4e6 sat·s at `T` = 0.2 s. At 2,048 sparse the difference is
  2.8 Msat x `T`.
* **Conditions.** The projection holds only when (1) the candidate stream saturates the window,
  as the gym's 400-candidate stream does by construction; real arrival rates are unmeasured, and
  with fewer candidates than the cold solver can screen the difference is zero; (2) the
  settlement cadence is fixed, not stretched to fit the batch; (3) deferred obligations stay
  valid and collateralized until the next window. Maturity, confirmation depth, dispute
  windows, liquidity on the routes, and the waterfall's protected balances are unchanged by any
  of this. Protected collateral enters the network as sink demand and is never reduced by the
  cache.

Certificate reuse (transport and memo hits) contributes little to any of these quantities; the
gain is repair. No sat-second figure here is a measurement of locked collateral on a live
system.
## Promotion gates

Production clearing is unchanged: `solve_and_verify_pnl_batch` still computes every settled
batch, its route allocations, residuals and next accounting root. Before any certificate path
may decide a production candidate:

1. **Equivalence of verdicts (met in the gym, not in production).** Zero wrong verdicts and zero
   false acceptances against cold Edmonds-Karp and against `solve_and_verify_pnl_batch` on every
   candidate (canonical comparison on every candidate up to 512 accounts, every fourth at 2,048).
   Required again on recorded production candidate traces.
2. **No settlement substitution (by construction).** Certificates decide feasibility only. The
   chosen batch is settled by the canonical solver. Replacing the canonical allocation needs a
   canonical flow, an equivalence proof and root-level differential tests (math notes §6); not
   attempted.
3. **Validation is never cached.** `FlowProblem::from_snapshot` re-runs steps 1-5 of the solver
   (replay, domain, equity, payout checks) on every candidate; only the network's feasibility is
   reused. Durable reservation, spent-outpoint and confirmation checks stay on the book
   (Phase 0 fixes) and are independent of any cache.
4. **Real traces.** All workloads here are synthetic. Locality on real clearing candidates is
   unmeasured; the gate is a recorded trace of candidate snapshots from the venue or the n-party
   packer, replayed with the same differential harness.
5. **Regtest and restart.** The cache is process-local and holds only certificates that are fully
   re-verified on use; it carries no authorization. A wiring that keeps that property still needs a
   regtest run through reserve, sign, confirm and a reorg.
6. **Memory.** The byte budget covers certificate payloads, entry metadata and node-set frames
   counted once; it is not an OS limit. Process peak RSS is reported separately.
