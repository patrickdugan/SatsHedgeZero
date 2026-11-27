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
