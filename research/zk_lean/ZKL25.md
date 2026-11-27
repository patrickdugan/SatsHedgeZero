# ZKL-25: graph-connected bounded polynomial multiplier search

ZKL-24 searched the first 65536 primary rows and all 10538 secondary rows
using disjoint windows and constant multipliers. It found no duplicate,
proportional or multirow candidate within the budget. The full pinned hashes
were rechecked. Nine Python regressions passed. The earlier generated Lean
replay exposed an open free variable in decide and an unwanted Classical.choice
dependency, addressed in the revised MathCan 8040c011f2fda4031cc6833a6e6f867d8eaaf095 and ZKL-24 generator.

Use the same immutable ZKL-22 artifact and exact checkout, VK, manifest and
canonical full matrix pins. Retain at most 65536 prefix rows, 350000 input terms
and 350000 modular residual terms, excluding oversized and zero residuals.
Store original global wire IDs and row numbers. Build bounded inverted postings
for nonconstant monomials and wires; high-fanout hubs above 128 entries are
excluded. Sample up to 64 targets per side (32 linear, 32 quadratic, no more
than ten active target wires), seed 25001, independent of solver success.
Nearby control and graph arm each use up to twelve retained rows. The graph arm
takes up to eight first-hop rows, plus a second-hop expansion seeded by the first
four. It uses shared monomial and wire overlap, with deterministic distance ties.
Both arms offer multipliers in degree tiers 0, 1, 2, at most ten selected
multiplier wires, 792 columns and 50000 sparse coefficient work per trial.
The 512 MiB process cap remains. Candidate pool count is not full ideal coverage.

Use the same exact integer verifier as prior stages. Every local success
must independently verify. Rebind the first success per degree across arms
to the full stream, check all rows and the single-deletion hash again, and
emit an indexed contextual Lean theorem. Report every trial and abstention
including empty neighborhoods and work/support caps. The remaining unbound
local successes cannot be promoted. Six controlled fixtures (three minimum
multiplier tiers over Fr and Fq) undergo kernel replay alongside actual bound
representatives. No constraint mutation, proof reuse or production approval.
No completeness or relaxed-R1CS equivalence claim.
