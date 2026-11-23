# INDEX-ADMIT-02: one SHA-256 gadget for two exact protocol messages

Registered 2026-11-24. Parent: PR #13 at `a1875e4fb51b2f77b5f71bb78ebb1d3d35d5ef33`. Independent continuation; no changes to Gemini's verifier, provider adapters, SPV or FROST. New relation `shz/ordered-admission-frontier-nova/v2-shared-sha/depth4` and new verifier-key identity. The 32-field state, canonical genesis, terminal frontier reconstruction, exact MAX-01 snapshot and POLICY-01 evidence format are preserved.

## Constraint construction

`SHZ/LOG/LEAF/V2 || present=1 || price_u64le || time_u64le || report_digest32` is exactly 64 bytes. `SHZ/LOG/NODE/V2 || left.min_u64le || left.digest32 || right.min_u64le || right.digest32` is 95 bytes. Both require two standard SHA-256 compression blocks. Their SHA padding differs: the one bit occurs at bit offset 512 or 760, the length in the last 64 bits is 512 or 760 encoded big-endian. Build both padded transcripts from the **same constrained input bits** already used by the transition, with literal domains, padding and lengths. For each bit, enforce `m = node + append*(leaf-node)` with Boolean opcode `append` bound to the one-hot operation predicate. Constant/constant positions simplify algebraically using only the public circuit shape. Apply precisely two Nova SHA-256 compression gadgets with the literal standard IV. Use the selected digest for the append or merge carry, gated by the original transition rules. On placement and sealing no selected digest may enter the output state. No branch depends on a private witness value at synthesis time. The compile-time legacy arm exists solely for R1CS comparison; the StepCircuit always uses shared SHA.

For Boolean a, if a=1, m equals the fully padded leaf; otherwise m equals the fully padded node. The compression function is identical to the upstream SHA-256 implementation for two blocks. Therefore all valid v1 transitions have identical v2 outputs, and a v2 transition with a wrong carry hash cannot be accepted by changing the selected preimage, padding, or digest without violating the bit-select or hash constraints. Other transition rules are unchanged. This is a relation-equivalence argument under SHA-256 soundness; not a formal proof of Nova's implementation. Use explicit domain-separated verifier identifiers; legacy proof bytes must not be accepted under the v2 key.

## Measurable gates

- Run the original reference tests and reproduce both frozen source snapshot pins without modifying fixtures.
- Exercise shared SHA at both exact message lengths with several allocated byte patterns and compare digest bits against native SHA-256.
- Exercise APPEND, MERGE, PLACE, SEAL with the same witness and initial state under both compiled circuit variants; compare actual R1CS constraint counts, satisfaction, and exact outputs. Require fixed shape within each variant and a strictly smaller v2 constraint count.
- Preserve all original malicious-transition tests; add cross-opcode digest substitution and double-padding rejection. Reject altered final state and proof encodings at the independent verifier boundary.
- Generate and independently verify both real compressed v2 proofs, pinned to the existing MAX-01 source snapshots. Record the actual constraint counts, key identity/size, proof size, time, and resource receipt. Do not infer proof or NEAR gas speed from compression-block counts.

## Work estimate

The previous circuit always executes four SHA compression blocks per microstep. The new circuit always executes two, plus the constrained bit multiplexer. At 144,000 reports, depth 18, one seal, there are 431,996 microsteps. The model predicts 863,992 SHA compression blocks versus 1,727,984 for v1 and a lower bound of 10,656,000 for repeated old/new paths. This is exactly a 50% reduction in hash-block count relative to v1; the percentage reduction in measured R1CS and wall time must be obtained from CI. Depth 18 remains analytical only. See `research/hourly_index/admission/evidence/shared-sha-work-model.json`.

Source signature authentication, digest nullifiers, provider completeness, independently authorized watermarks, full proof verification on NEAR and Bitcoin finality remain separate unsatisfied gates. No production or DLC settlement authorization.
