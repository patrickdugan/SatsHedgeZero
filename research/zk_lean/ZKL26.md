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
