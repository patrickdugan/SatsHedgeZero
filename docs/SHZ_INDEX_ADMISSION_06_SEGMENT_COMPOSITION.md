# INDEX-ADMIT-06: parallel segment proofs with exact frontier continuity

Parent: ADMIT-05, `14dfaebbf44a04e2bee78625fe2dff09f2169915`. Research-only, synthetic admission profile. The original depth-18 relation and its 44 packed public-state fields are unchanged. No NEAR/source/SPV/FROST changes.

## Statement

Let `T` be the ADMIT-05 single-step relation over the packed frontier. It binds the source/network context, counters, ordered admission, carry transitions and seal. Given a receiver-owned terminal claim `C`, compute its canonical initial and expected terminal states `z0,zK` using `claim_states`. For `k` nonempty segments, independently verify

`Verify(vk, pi_i, n_i, z_i) = z_(i+1)`

for `i=0..k-1`, with the locally reconstructed key and canonical bounded proof encoding. Check the full 44-field equality at every joint, not only the root digest. Require `sum(n_i)=C.steps`, first state canonical genesis, terminal state exactly `zK`, and verify that `C` reconstructs the independently pinned MAX-01 snapshot. Every segment carries its global operation ordinal; an internal Nova step counter starts anew. This is sound composition by induction under the original proof soundness assumption. Arbitrary starting states are valid inputs to the segment circuit, so an isolated segment is insufficient evidence of reachability. A fabricated boundary may pass structural equality if both adjacent metadata objects are edited; it must fail cryptographic verification against the actual proofs. No proof receipt, proof hash, or manifest is substituted for verification.

## Partition and cost

The native planner streams the same synthetic records as ADMIT-05, cutting after completed appends when no carry is pending. If N reports have arrived, the number of merges is `N+1-popcount(N+1)`, and the idle prefix has `2N+1-popcount(N+1)` folds. The last segment includes the final seal. For 128 reports split into four 32-report segments, the lengths are 63, 64, 63, 66 folds, summing to 256. All segments independently replay from their declared starts. The largest segment consumes 66/256 of the serial folding workload. With four independent workers, the ideal folding-only speedup is 256/66=3.879x; proof compression, repeated setup, I/O, scheduling, the native prepass and actual CPU limits reduce this. No wall-time speedup is asserted before a measured run.

The full 144,000-report plan can use 64 segments of 2250 reports. Total folds remain 287,996. Each worker independently reconstructs its proof parameters, which may be shared in a future in-process implementation. The default proof limit is 256 folds per process; the large plan requires explicit budget. The planner uses bounded storage for segment boundaries and streams transitions instead of storing all microstates. The proof bundle count, proof bytes and verifier work grow linearly in the number of segments.

## Verification and negative controls

The Rust chain verifier reconstructs the key once, checks each manifest against the receiver's expected context and plan, decodes bounded proof bytes, verifies the actual proof, checks the expected full endpoint, and carries that endpoint to the next verification. It rejects omitted or repeated intervals, swapped order, incorrect fold counts, wrong sentinel, substituted terminal, early seal and wrong context. Registered cryptographic controls reuse a valid decoded proof against the wrong start/end/count and another segment's statement, bypassing metadata checks. CI additionally substitutes a real proof from segment 1 into segment 0 and recomputes the declared proof hash. All whole-history and aggregate flags remain false until the corresponding proof check succeeds.

## Next: succinct aggregation

A separate circuit must prove the verification of the segment proofs themselves (including a pinned verifier identity, input/output equality and exact interval accounting). A balanced binary recursion tree could combine adjacent authenticated intervals, using a domain-separated claim carrying the start/end state commitments, operation range, source/network and relation identity. The parent relation must verify both child proofs, constrain shared state equality, and enforce disjoint consecutive ranges. The final verifier must check the canonical genesis and independently retained terminal claim. A hash tree of proof digests alone cannot establish these claims. Benchmark foreign-field MSM, transcript, sumcheck and IPA operations before selecting a recursive backend. This milestone establishes the native chain composition and a reproducible proof workload for that next experiment.

Source signatures, provider completeness, watermark authority, NEAR verifier feasibility, Bitcoin anchoring and settlement authorization remain unsatisfied. No production changes.
