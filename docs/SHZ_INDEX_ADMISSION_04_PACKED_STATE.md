# INDEX-ADMIT-04: injective packed frontier state

Registered November 24, 2026. Parent ADMIT-03 `1ff5da1150a7b5016e1e2c9ad10dce955de0d974` (PR #15). Work is isolated under `research/hourly_index/admission_packed`; no edits to Gemini's external-source, NEAR verifier, SPV, or FROST work. Relation `shz/ordered-admission-frontier-nova/v4-packed-state/depth4`.

## 1. Encoding

The previous depth-D state has `12+4(D+1)` fields: four counters/times, pending, level, three carry coordinates, four coordinates per frontier slot, and three context coordinates. The new state has `6+2(D+1)` fields. Every old coordinate is accounted for exactly once.

Pack the metadata into a single Pallas scalar using disjoint little-endian integer bit ranges:

| Item | Offset | Width |
|---|---:|---:|
| operation ordinal | 0 | 32 |
| leaf count (including sentinel) | 32 | 32 |
| last admitted timestamp | 64 | 64 |
| sealed watermark | 128 | 64 |
| pending carry | 192 | 1 |
| carry level | 193 | 8 |
| occupied frontier slot i | 201+i | 1 |

For a summary `(min_u64, digest32)`, retain the same injective little-endian 128-bit digest limbs `lo`, `hi`. Its two packed fields are `min + 2^64 * lo` and `hi`. Apply this rule to the carry and to every frontier slot, in order from level zero. Carry the two genesis limbs and source ID directly as immutable context.

Header bit width `201+D+1` is 206 for depth 4, 220 for depth 18, and 226 for depth 24. Each packed summary coordinate is at most 192 bits. All are below 2^254, which is below the Pallas scalar modulus. Thus valid bounded component encodings cannot wrap in the field. This layout also keeps the 32-bit operation/count fields wide enough for the projected depth-18 admission workload. The compiled v4 circuit is still depth 4 with 128 maximum microsteps; the larger-depth results are encoding capacity estimates only.

## 2. Constrained lifting, not a witness-controlled decoder

Let `P` denote the linear packing map with the fixed coefficients above. Given packed public state `p`, allocate the original mutable field coordinates `z` as circuit witnesses, carry public context unchanged, and constrain `P(z)=p`. Invoke the existing ADMIT-03 `StepCircuit` on those allocations in the same R1CS. It binds operation/count ranges, each timestamp/minimum to 64-bit decompositions, each digest limb to 128-bit decompositions, Boolean flags, and the carry level to the selected frontier level. Its step bound/count bound are tighter than the 32-bit encoding widths. It derives all mutable output coordinates `z'` by the unchanged one-hot append/merge/seal transition, including the shared SHA-256 gadget and eager placement. Allocate packed output `p'` and enforce `P(z')=p'`. The last three public coordinates are unchanged.

For a canonical parent input, every independently accepted packed opening is unique: the range constraints put every linear combination in an interval of integers strictly below the field modulus, and the component ranges do not overlap. The parent transition then fixes each canonical output coordinate. By induction from the same sentinel-only genesis, the packed circuit enforces the identical admitted history as ADMIT-03. The proof is accepted only if its initial and final packed states equal the receiver's encoding of the validated parent claim. Receiver-side reconstruction of the MAX-01 snapshot continues to use the original frontier bytes and `Claim::states`. The packing adds equality constraints and allocations; the application constraint count may increase slightly. It reduces the recursive state arity; any effect on Nova augmentation, proof size, memory or runtime must be measured.

An unchecked linear equation is insufficient. For instance increasing a 64-bit minimum by `2^64` while decreasing the adjacent digest limb by 1 preserves the packed value. The circuit test deliberately supplies such a forged unpacked assignment to the actual R1CS. It must fail the original range/bit-binding constraints even though the packing equality holds. Additional attacks cross operation/count/timestamp/Boolean/occupancy boundaries, tamper with output digest/carry, mutate packed public inputs, and substitute a final seal or sentinel in the compressed proof verifier. Public source/genesis are context selected independently by the receiver, not proven source authentication.

## 3. Registered comparison

| Depth | Original fields | Packed fields | Header bits |
|---:|---:|---:|---:|
| 4 | 32 | 16 | 206 |
| 18 | 88 | 44 | 220 |
| 24 | 112 | 56 | 226 |

No change in folds or SHA block counts. The frozen Pyth/Chainlink histories remain 24/16 folds. The exact two MAX-01 snapshot pins and the POLICY-01 evidence root are inherited unchanged. CI tests all 40 microsteps for exact packed output and fixed shape, compares matched parent and v4 application constraint counts, runs malicious openings that preserve the packed field, and generates actual transparent compressed proofs of both histories. The independent verifier reconstructs its key, checks the receiver claim and version, and rejects modified public context, genesis/sentinel, seal, step count and trailing proof bytes. Profile augmented constraint counts, proof/key bytes, wall times, and peak RSS. Reference tests passed locally (12 new and 27 inherited); Rust and proof results are pending until CI. Do not report a 2x proving speed or gas reduction from the arity alone.

Structural admission is a separate proof from authentication and completeness of the admitted log. All source authentication, watermark authority, full Nova verification on NEAR, Bitcoin anchor finality, and DLC settlement flags remain false. This changes neither the 40-byte SHZIDX01 packet nor the hourly policy.
