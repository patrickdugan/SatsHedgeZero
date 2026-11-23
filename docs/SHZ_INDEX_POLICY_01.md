# SHZ-INDEX-POLICY-01: Necessary HOLD decisions and receiver-pinned evidence

Registered 2026-11-24. Parent: SHZ INDEX-02, PR #10, `9274722ac8aed09170f12da66729115f1554bd27`. Dedicated branch, separate from the agent implementing source authentication, transparent NEAR verification, SPV, and FROST. This is an application-relation experiment; no new verifier backend or mainnet authorization.

## Why change the circuit?

INDEX-02 proves that a claimed VALID leaf meets the price and time inequalities, and that a HOLD leaf has zero-valued price/time/digest fields with a nonzero reason. The prover chooses the status. An otherwise eligible hour can be replaced with a canonical HOLD and a fresh checkpoint root. Collision resistance binds a chosen commitment but cannot establish that the chosen output is policy-correct. This is a liveness/integrity gap, not an allegation that the old proof can forge an already pinned root.

The new relation proves **VALID if and only if the selected committed observations qualify**. HOLD is then necessary relative to those observations; its reason is uniquely determined. Source admission and selection completeness are explicit upstream obligations, not asserted by a SNARK over an arbitrarily chosen root.

## 1. Deterministic observation and classification policy

Policy version:

`SHA256(ASCII("SHZ/DUAL-ORACLE-50BPS-5MIN/HOLD-NECESSITY/V2"))`

This intentionally changes the policy digest, while preserving the exact INDEX-01 hourly record and `SHZIDX01` OP_RETURN wire formats. It is a new policy and verifier identity, never a reinterpretation of archived v1 proofs.

For each source `s` in the fixed order Pyth, Chainlink, an externally authenticated admitted-log snapshot `L_s` contains normalized BTC/USD reports with positive bounded prices, strictly increasing publication timestamps, unique nonzero signed-report digests, and no unauthenticated entries. For hour h, define cutoff `t_h=(h+1)*3,600,000,000` microseconds. Select the latest entry `r_s` with `publish_us <= t_h`, or canonical absence. Equal timestamps with distinct entries are rejected at admission in this research profile; a production policy must freeze an unambiguous provider-specific deduplication rule. Provider outages and messages never admitted to a log cannot be established from a root alone.

A present candidate requires price in [1, 10^16] e8, nonzero signed-report digest, positive publication time at or before the cutoff. A malformed candidate is rejected, rather than used as an excuse to HOLD. An absent candidate is exactly `(false,0,0,zero32)`. Let:

- `F_s = present_s AND (publish_s >= t_h-300,000,000)`.
- `A = F_P AND F_C`.
- `K = |publish_P-publish_C| <= 60,000,000`.
- `D = 20,000*|price_P-price_C| <= 50*(price_P+price_C)`.

Then `V = A*K*D` in Boolean arithmetic and the deterministic reason is

`reason = (1-A) + 3*A*(1-K) + 2*A*K*(1-D)`.

Thus the reason precedence is missing/stale (1), skew (3), spread (2). A qualified leaf has reason 0, status 1, source fields equal to the candidates, and `index=floor((p+c)/2)`. A disqualified leaf has status 2, the prescribed nonzero reason, and zero output price/time/report fields. Its evidence still commits the actual source candidates. The oracle may not arbitrarily hide a qualified price under a fresh root when the receiver evidence pin is unchanged.

## 2. Evidence encoding and proof state

Candidate encoding: `present_u8 || price_u64le || publish_us_u64le || report_hash32` (49 bytes). Candidate order is fixed. The evidence leaf is:

```
E_h = SHA256("SHZ/HOUR/EVIDENCE/V1" || genesis32 || policy32 || hour_u64le
             || encode(pyth) || encode(chainlink))
node_E = SHA256("SHZ/EVIDENCE/NODE/V1" || left32 || right32)
evidence_root = SHA256("SHZ/8H/EVIDENCE/V1" || genesis32 || policy32
                      || start_hour_u64le || balanced_merkle_8(E_0,...,E_7))
```

An independent receiver must retain the canonical evidence root from a verified admission/selection pipeline, or explicitly choose its trust model. Given eight public leaf digests, it cheaply recomputes the evidence root using native SHA256; it does not trust the manifest for this identity. The reference `policy.mjs` reads a *complete supplied snapshot* under receiver-pinned log hashes and chooses the latest admitted predecessor by binary search. The reference log format is SHA256 of `"SHZ/ADMITTED-LOG/V1" || genesis32 || policy32 || source_u8 || count_u64le || (price_u64le || publish_us_u64le || report_hash32)*`. This is a native selection witness pipeline, not a ZK source-selection or admission proof. It rejects omission/substitution relative to the fixed snapshot hash. The frozen logs are synthetic, and their roots are not authentic Pyth/Chainlink commitments.

The Nova state is 24 Pallas field elements. The first eight are the original INDEX-02 state: count, aligned start hour, 2x128-bit genesis limbs, policy limbs, and output checkpoint limbs. The remaining 16 are an ordered queue of eight 256-bit evidence digests (two 128-bit limbs each, little-endian by digest bytes). The root is checked by the receiver against those exact public limbs; **a future NEAR verifier must perform that same root-to-state binding**. Field reduction of arbitrary 256-bit hashes is forbidden.

Each fold:

1. Constrains position to count, hour to start+position, and policy to the fixed version.
2. Opens the first evidence digest, including both normalized candidates, using a constrained SHA256.
3. Enforces all candidate bounds, and exact signed integer comparisons via disjoint bounded-slack branches. The comparison Boolean `g` requires `g*x` nonnegative and bounded, and `(1-g)*(-x-1)` nonnegative and bounded. All integer expressions and slacks are far below the Pallas modulus (at most 80 bits), so the sign cannot be changed by field wraparound. Constrain each Boolean product and the reason formula.
4. Equates the same record price/time/hash allocations used in the SHA256 leaf to `V` times candidate values, using injective digest limbs. The existing midpoint, range, HOLD encoding, and checkpoint-path checks remain in R1CS. The status Boolean is equated to `V` rather than assumed.
5. Increments count literally, carries the immutable eight-field header, shifts the digest queue, and appends two explicitly constrained zero fields.

The initial state contains exactly eight pinned evidence digests and count 0. The terminal state has count 8 and an empty zeroed queue. Each output leaf is proved against the same output checkpoint, with a three-level ordered Merkle path. A queue prevents the prover skipping/reordering evidence, and replaces a second Merkle-path computation per hour with native verification of the public evidence root. This adds one candidate SHA256 per fold and extra state fields; actual constraints, key bytes, memory and prover cost are CI measurements. Pallas/Vesta Nova with Spartan/IPA compression retains the no-toxic-waste requirement. Witness privacy properties and the chosen proof implementation require separate review.

## 3. Falsification and implementation boundaries

A test directly exercises the predecessor's R1CS: a zeroed voluntary HOLD with a freshly recomputed root satisfies v1. The corresponding v2 test retains the selected evidence and recomputes the output root; it must fail. Other R1CS cases deliberately recompute both roots when testing malformed evidence, so SHA binding cannot mask missing arithmetic predicates. Include exact boundary comparisons, wrong reason, stale-as-valid, output price/report substitution, missing-candidate smuggling, evidence mutation under HOLD, queue-head substitution and state/shape checks. The persisted proof verifier additionally requires the receiver's expected claim and rejects changed checkpoint, changed evidence root, and wrong fold count. Do not treat a pending CI run as proof of any test result.

For the production admission layer, an alternative to fetching full logs is a time-ordered append-only authenticated map with leaf indices and length, using predecessor/successor proofs at cutoff and explicit beginning/end sentinels. Require adjacency (or a certified end boundary), sorted immutable admission enforced by the state transition, independent roots pinned before selecting, and a policy for finality, late reports, equivocation and data availability. Proving only inclusion of the selected report cannot prove maximality. A root of a withheld log does not prove source completeness. A receipt from an unauthorized relayer is insufficient. Gemini's source/NEAR work can supply this external evidence contract without editing this crate.

Flags after a successful native proof: `hold_necessity_relative_to_pinned_evidence=true`; `source_log_completeness_proven=false`, `source_authentication=false`, `hold_necessity_unconditional=false`, `near_nova_verified=false`, `bitcoin_anchor_finality_verified=false`, `can_authorize_oracle_epoch=false`, `can_authorize_dlc_settlement=false`, `production_ready=false`. No settlement authorization until upstream evidence authentication, on-NEAR cryptographic verification, independently verified Bitcoin finality, and FROST/DLC policy binding pass their own gates.
