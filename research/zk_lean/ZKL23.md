# ZKL-23: streaming global row-position binding

MathCan f7f5cf1c00ca4b3c2f12eb4fb8a68ae852524f67 adds a contextual deletion theorem. If the global shape is
prefix ++ target :: suffix and the local retained rows occur in the retained
context, an exact local polynomial implication proves ordinary acceptance
equivalence for arbitrary surroundings. Original well-formedness and context
membership are explicit premises. No hash equality is treated as a Lean proof.

The binding checker validates the whole original stream against an operator
supplied canonical SHA256, selects exact global row positions, preserves global
wire IDs and public order, hashes the hypothetical single-row deletion, and
independently verifies the local polynomial identity. The generated proof
checks that local identity and retains the context premises. External streaming
binding and the native exporter remain separate trust boundaries.

Discovery searches at most 8192 initial rows for one non-identical pair with
nonzero proportional polynomial residuals; supports are bounded. No candidate
is an inconclusive result. Tests use Fr and Fq, high global wire IDs, independent
whole-shape hash comparison, and tampered indices/hashes/coefficients/context.
No production rows are removed; no key or proof reuse is authorized. The
scoped CI replays the synthetic fixture implications in Lean. Actual Nova
capture remains a separate gate.

## Actual capture integration

The ZKL-22 capture workflow now invokes the local discovery/binding checker
for each actual augmented row stream and attempts Lean replay of any
candidate. Its original matrix pins come from the fresh same-setup streaming
audit, so this is not independent production VK binding. Candidate files,
receipts and original artifacts are preserved. Zero discovered candidates
is explicitly inconclusive. The contextual theorem retains the external
full-matrix membership and well-formedness premises. No circuit or
verification parameters are rewritten.
