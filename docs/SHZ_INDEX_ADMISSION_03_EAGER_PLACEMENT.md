# INDEX-ADMIT-03: eager placement in the authenticated binary frontier

Registered 2026-11-24. Base SHZ PR #14 `bb96fa53130ef55d2bd60e90dc0e8c8e4c3d8b39`. Isolated `research/hourly_index/admission_fused` crate. No changes to prior proof fixtures, keys, source adapters, NEAR verifier, SPV, or FROST. Relation `shz/ordered-admission-frontier-nova/v3-eager-placement/depth4`; new verifier identity, same MAX-01 tree/leaf/snapshot encodings and POLICY-01 source evidence.

## Transition reduction

ADMIT-02 performs one append (leaf hash), zero or more occupied-slot merges (node hashes), and a final placement-only fold per report. Both hash branches in its selected SHA gadget occupy two compression blocks, even during a placement-only fold. The new relation installs the newly hashed summary in its destination immediately when that slot is empty. Only a collision creates a pending carry. A pending state facing an empty slot is forbidden.

Let `a,m,s` be the Boolean one-hot append, merge and seal flags. Pending iff merge at input. For depth D, `e_i` is the input occupancy bit and `q_i` the constrained one-hot merge-source selector; `sum(q_i)=m`, `sum(i*q_i)=level`, `q_D=0`, and `q_i*(1-e_i)=0`. The destination selector is `t_0=a`, `t_i=q_(i-1)` for i>0. Enforce `q_i*t_i=0` and define:

```
place_i    = t_i * (1-e_i)
continue_i = t_i * e_i
pending'   = sum(continue_i)
level'     = sum(i*continue_i)
```

Require `continue_D=0` and `sum(place_i+continue_i)=a+m`. The summary R is the exact leaf hash of the bounded normalized report when a=1, or the exact node hash of the selected older subtree and carry when m=1. Its minimum is the report timestamp or selected left minimum, respectively. The same selected padded SHA256 transcript from ADMIT-02 is used. Install R exactly in the selected empty destination, or hold R in the carry when pending'=1. Clear the merged source slot. Preserve every other slot. Zero the carry and level when idle. Seal does not write any subtree. The original state count, bound, chronological order, mandatory merge and strict watermark conditions remain.

No routing selector is trusted from an input witness; it is constrained by the existing opcode, level and occupancy fields. The output state is fully determined by the input state and the admitted action. In particular, an attempted placement into an occupied slot cannot discard an existing authenticated subtree, an append cannot delay an available placement, and a final root cannot contain a pending carry. The circuit retains the 32-field state and injective digest limbs. A verifier reconstructs the snapshot from the proved terminal frontier and requires the independently retained pin and exact fold count.

## Equivalence to the predecessor

Each old run from one idle state to the next consists of APPEND, k occupied CARRY merges, and one empty CARRY placement. With eager placement the last hash-producing operation incorporates the final empty placement. If k=0, the append itself places the leaf. If k>0, the last merge places the parent. The induction preserves exactly the left/right order, child minima and SHA256 bytes of every node. At each idle boundary all fields except the operation counter agree. Intermediate seals are identical. Conversely, inserting the corresponding placement into each v3 append sequence reconstructs a v2 sequence. The old and new circuits intentionally accept different intermediate-state encodings and use distinct verifier keys. This is a mathematical trace correspondence, with executable native and R1CS regressions, not a machine-checked theorem about Nova internals.

For n admitted reports and s seals, the sentinel makes n+1 leaves. The merge count is `M=n+1-popcount(n+1)`. The old fold count is `2n+M+s`; the new count is `n+M+s`. At n=144000, depth 18, one seal, the new count is 287996 rather than 431996, hence 575992 rather than 863992 two-block SHA compression invocations. Repeated old/new paths count at least 10656000 blocks in the comparison model. This is an analytical count, not a measured large-log proving or NEAR gas speedup. Both current proof circuits are depth 4.

## Registered comparison and adversarial controls

- Reproduce both frozen MAX-01 pins with identical ordered records and seals. Pyth 36->24 folds; Chainlink 23->16. Test every possible prefix at depth 4 against the direct tree and the old native accumulator, including the empty and full log. Compare all idle-state boundaries after removing the step counter.
- Actual R1CS same-shape tests for all operations, two sources and states. Recompute malformed report hashes when attacking arithmetic and timing. Reject wrong destinations, dropped or duplicated summaries, pending overwrite, wrong carry level, the old valid placement-only transition, source substitution and altered proof state. Keep shared SHA padding parity tests and the old proof-negative controls.
- Match actual application constraint count per fold against the parent crate and require total constraint count over each frozen history to decrease. Persist compressed proof/verification receipts, resource data and the precise verifier identity. The new proof must verify against the existing snapshot pin, not a new economic root. No measured result is asserted before CI completes.

## Security and practical limitations

Native structural log admission is relative to committed normalized records. Source signature verification, report digest nullifiers, admission completeness and external seal authority remain separate. Proving from the sentinel ensures the minimum-tree construction but does not prove messages never received. The depth-18 model is not an authorization or a performance result. Full transparent NEAR verification, canonical Bitcoin finality, and FROST/DLC settlement gates remain disabled. No toxic-waste setup introduced. No mainnet changes.
