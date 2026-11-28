# ZKL-26: expanded algebraic search on the pinned Nova matrices

Inputs: the ZKL-22 capture (run 46042490831, artifact 15220907562) and the
pins in zkl22_capture_pins.json, rechecked in every run. No Nova setup is
repeated; the ZKL-22 workflow is now manual only.

Two independent analyses.

1. full_matrix_scan.py streams all rows once. Per wire: term occurrences,
   first/last row and A/B/C membership. Per row: a 12-byte hash of the
   scale-normalized residual. It reports separately (a) unconstrained wires
   (no occurrence; public wires listed apart), (b) dead-output rows (a
   non-public wire occurs once, linearly: C only, or A/B against a nonzero
   constant), (c) zero-residual rows, (d) proportional duplicate candidates.
   scan_findings.py re-verifies every duplicate candidate as an exact integer
   proportional identity from the streamed rows, binds the first one (full
   deletion hash) and emits an indexed Lean source; it binds the first C-only
   dead-output row and emits a source for MathCan dead_output_delete. The
   single-occurrence premise of that theorem is established by the scan,
   outside Lean, like the ZKL-24 row lookups.

2. graph_dependency.py --zkl26 compares four arms on the same targets:
   window (ZKL-24/25 disjoint 256-row window), graph (ZKL-25 overlap),
   adaptive (overlap rounds 12/18/24 rows with 10/13/16 multiplier wires,
   hub wires contribute their producer row), directed (backward
   producer slice by first occurrence, then consumers; linear rows reduced
   to RREF with the newest wire as pivot and substituted out of the target and
   the quadratic rows; degree-0/1 multipliers on the reduced quadratic rows;
   the result is translated back to original rows and independently checked).
   Two target pools of 512 per matrix: degree-stratified random, and one
   representative per motif (relative wire offsets and unit-coefficient
   pattern), most repeated motifs first. Every arm has the same per-target
   budget: 100000 coefficient-work units and 40 ms process CPU.

Outcomes are kept separate: verified_redundancy (exact certificate,
independent verifier), counterexample (an exact assignment satisfying every
retained local row and violating the target, checked by evaluation: no
certificate of any degree exists over that neighborhood), exhausted_span
(all offered columns used, no solution, no counterexample constructed) and
incomplete (work, CPU, support or degree cap). A counterexample refutes only
the local implication; no outcome here establishes global essentiality.

## Results (workflow 46105804434, commit 37c097f)

Both pins rechecked; files in zkl26_results/ (annotation-bundle.tar.gz is
the SHA256-checked export).

### Full-matrix scan

| | primary (Fr) | secondary (Fq) |
|---|---|---|
| rows / wires | 962221 / 956072 | 10538 / 10523 |
| unconstrained wires (incl. public) | 0 | 0 |
| public wire occurrences | 1 each (rows 962219, 962220) | 1 each (rows 10536, 10537) |
| single-occurrence wires | 22 | 14 |
| of which linear, C only (dead outputs) | 2 (rows 4219, 5439; wires 4269, 5485) | 2 (rows 3984, 5204; wires 4004, 5220) |
| zero-residual rows | 0 | 0 |
| proportional duplicate rows (12-byte normalized hash) | 0 (962221 distinct) | 0 (10538 distinct) |
| scan wall / peak RSS | 26.2 s / 19152 KiB | 0.54 s / 18588 KiB |

Each public wire occurs once, in the final inputize rows: the scan finds no
unconstrained statement input. The dead-output rows sit 235 rows apart in
both matrices (4219−3984 = 5439−5204 = 235), which places them in Nova's
own augmented verifier circuit, which precedes the step circuit, not in
Mnr05UnifiedBatchStep. The first dead row of each matrix was bound with a
full deletion hash (primary → 0f41a2d9…3f7e, secondary → a5a5edbe…6fc4) and
its indexed_dead_output_delete source replayed.

### Search (512 stratified + 512 motif targets per matrix)

Per-target budget 100000 coefficient-work units and 40 ms CPU for every arm.
Counts are per pool (512 targets each).

| matrix / pool | arm | verified | counterexample | exhausted | incomplete | CPU s |
|---|---|---|---|---|---|---|
| primary / stratified | window | 0 | 192 | 306 | 14 | 8.0 |
| | graph | 0 | 326 | 172 | 14 | 9.6 |
| | adaptive | 0 | 269 | 2 | 241 | 19.7 |
| | directed | 0 | 196 | 298 | 18 | 3.2 |
| primary / motif | window | 0 | 392 | 111 | 9 | 9.6 |
| | graph | 0 | 370 | 133 | 9 | 10.2 |
| | adaptive | 0 | 405 | 23 | 84 | 21.2 |
| | directed | 0 | 70 | 435 | 7 | 4.5 |
| secondary / stratified | window | 0 | 229 | 271 | 12 | 8.8 |
| | graph | 0 | 426 | 71 | 15 | 7.6 |
| | adaptive | 0 | 417 | 8 | 87 | 13.1 |
| | directed | **1** | 382 | 110 | 19 | 3.5 |
| secondary / motif | window | 0 | 414 | 88 | 10 | 10.8 |
| | graph | 0 | 424 | 71 | 17 | 10.9 |
| | adaptive | 0 | 405 | 6 | 101 | 21.7 |
| | directed | 0 | 99 | 398 | 15 | 6.4 |

Best outcome per distinct target over all four arms: primary 1006 targets,
888 local counterexample, 109 exhausted span, 9 incomplete; secondary 989
targets, 1 verified, 870 counterexample, 109 exhausted, 9 incomplete. Each arm
contributes counterexamples no other arm finds (primary: window 14, graph 76,
adaptive 44, directed 58). adaptive spends its budget on the 24-row rounds
(CPU cap in 438–498 of 512 targets) and directed is the cheapest arm.
Motif pools: primary 3516 motifs over 64447 eligible rows (largest 16905),
secondary 837 motifs (largest 3178).

The one verified redundancy: secondary row 5209 = −w5224·row5210 +
w5225·row5211 (mod q), degree 1, found by the directed arm after linear
substitution; bound deletion hash 1b9c8daf…4351; its indexed Lean source
replayed. It is five rows after dead row 5204, in the same Nova gadget.
Lean replay: 22 fixtures + 3 actual sources, all [propext, Quot.sound].
Search wall / peak RSS: primary 1:53 / 217356 KiB, secondary 1:21 / 64828
KiB, under the 512 MiB address-space cap.
