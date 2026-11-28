# ZKL-25: overlap-neighborhood degree-tier search

ZKL-24 workflow 46045439254 passed the nine Python regressions and six
indexed Lean replays (only propext and Quot.sound). Its actual matrix
degree-zero search found no candidate among 64447 eligible primary and
9518 eligible secondary rows. This is bounded evidence, not essentiality.

Reuse the original captured artifact from run 46042490831 and existing
pins, including the exact merge checkout SHA. Search 65536 primary rows
and the full secondary prefix. Build bounded nonconstant-wire incidence
postings, discarding saturated lists at 64 entries. Sample 64 target
rows per matrix, stratified on linear/quadratic residual degree with a
fixed seed, before running the solver. For each target compare a disjoint
256-row window and an overlapping graph neighborhood (four hops, three
additions per hop). Both choose at most 12 retained rows and at most 10
multiplier wires. Keep the full original wire IDs and ordered public map.
Target pools can differ between arms; no pure scoring-policy effect claim.

Use the previously tested sparse Search and LazyColumns implementations
through a restricted global-ID adapter. Search the selected monomial
span cumulatively by degree 0, 1, 2 (up to 792 candidate columns), with
100000 coefficient-work units per target. Record exhausted degrees and
work/support caps separately. A complete selected span miss is still
inconclusive for the full matrix. Prefix storage is capped at 400000 input
terms, row expansion at 128 terms, and the actual campaign has a 512 MiB
virtual-address-space limit.

All found local certificates are independently verified after the full
stream is checked against the pinned original hash. For the first success
in each arm/degree cell, stream the full matrix again to bind exact
original indices and the hypothetical single-deletion hash. Replay these
sources plus four synthetic cross-window positive fixtures (degrees one
and two, both scalar fields) in pinned MathCan 8040c011f2fda4031cc6833a6e6f867d8eaaf095. Essential control
has an explicit violating assignment. Each deletion is independent; no
composition, circuit rewrite, relaxed-Nova equivalence, production VK
match or key reuse is claimed. Global row lookups and well-formedness
remain the external premises of the indexed Lean theorem.

## Recovery (ZKL-25 receipts, run 46072770036)

Run 46072770036 (head 14d03d8) passed: 21:49:45–21:50:04 UTC for both
actual searches, Lean replay 21:50:24–21:50:27. Workflow 46103947349
(73a613c, recover_zkl25.py) downloaded artifacts 15234030635 and
15234005619 and the pinned capture 15220907562, rechecked the source
commit, capture.json and vk.bin hashes, re-streamed both matrices against
their canonical pins and re-replayed every Lean source in MathCan 8040c01.
The files are in zkl25_recovered/ (annotation-bundle.tar.gz holds the exact
downloaded artifact files; recovered-manifest.txt their SHA256).

| matrix | rows | wires | eligible prefix rows | size skips | targets | certificates |
|---|---|---|---|---|---|---|
| primary (Fr) | 962221 | 956072 | 64447 | 1089 | 64 × 2 arms | 0 |
| secondary (Fq) | 10538 | 10523 | 9518 | 1020 | 64 × 2 arms | 0 |

No actual-matrix certificate exists, so there are no bound actual receipts
and the six replayed sources of the ZKL-25 run are the four synthetic
fixtures (all `[propext, Quot.sound]`). Failure modes of the 256 attempts:
248 exhausted the selected degree-0/1/2 span, 8 hit the 100000-unit work cap
(primary graph 2, window 3; secondary graph 2, window 1), 0 hit the support
cap. The 10-wire multiplier pool was truncated in 237 of 256 attempts; the
graph arm had 16 empty neighborhoods (2 primary, 14 secondary) because every
target wire was a saturated hub (posting list over 64) and 61 neighborhoods
with fewer than 12 rows. These are bounded misses, not essentiality.
Recovery CPU: primary stream 15.9 s wall, 20608 KiB peak RSS; secondary
0.34 s, 19280 KiB.
