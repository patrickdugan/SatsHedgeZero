# SHZ-INDEX-ADMIT-05: depth-18 admission and bounded proving ladder

Research registration 2026-11-24. Parent PR #16 at `d30346a6a62a2d7b24c4f3a7fcb43756e2d5a760`. This work is independent of provider adapters, NEAR proof verification, SPV and FROST. It scales the existing packed admission relation, preserving exact MAX-01 SHA-256 snapshot encodings. No authorization for mainnet funds.

## 1. Circuit profile

The existing eager-placement and packed-state crates have a compile-time `depth18` feature. Default depth-4 code, limits and relation identifiers are preserved. In depth-18 builds:

- Tree capacity: `2^18` leaves, including the mandatory absence sentinel; at most 262,143 real reports.
- Frontier: 19 slots. Legacy state: 88 fields. Packed state: 44 fields, with a 220-bit header, 192-bit timestamp-plus-digest groups and 128-bit digest limbs. No arbitrary 256-bit digest reduction.
- Maximum operation count: `2^20`. The application constraint for the ordinal uses a 20-bit bounded slack, and the native state/claim validator enforces the same ceiling. Packed counter coordinates remain 32-bit, and the operation/count constraints enforce the stricter bounds. Default depth 4 continues to use 128 operations and seven-bit slack.
- Relation identifier: `shz/ordered-admission-frontier-nova/v4-packed-state/depth18`; this is a new circuit and new verifier key. A depth-4 proof must never be accepted as depth 18.
- Shared two-block SHA-256 gadget, canonical padding, operation one-hot gates, strict timestamp ordering and seal monotonicity, eager destination routing, pending/occupancy constraints, exact hash bytes and terminal snapshot reconstruction stay as in ADMIT-03/04.

The terminal frontier still has to reconstruct the independently supplied snapshot pin in the native verifier. This circuit proves structural admission and monotonic sealing from a sentinel-only genesis, with provider signatures, report completeness and watermark authority explicitly external. It is not a general provider data feed importer.

## 2. Scaling arithmetic

For N real reports, there are N+1 leaves including the sentinel. With a final seal, the number of merges is `N+1-popcount(N+1)` and the number of eager placement folds is

```
F(N) = N + merges + 1 = 2N + 2 - popcount(N+1).
```

The fixed-shape application executes two SHA-256 compression blocks per fold, even on the seal. At N=144,000, F=287,996 and there are 575,992 compression blocks. At capacity F=524,287, below the 20-bit operation ceiling. The proof step bound is independent of the report count and explicitly constrained. The full-size model is not a measured proof runtime.

## 3. Independently generated claims and streaming witness

`research/hourly_index/admission_scale/fixtures/build.mjs` generates a synthetic 200-ms stream. It compares a streaming frontier against the independent full MAX-01 tree builder at every registered ladder size, reconstructs the exact same header/pin, and checks the packed-state round trip. The public expected claims are committed before the Rust proof run. The deterministic fixture uses domain-separated synthetic report digests; none is a provider-signed report.

The Rust `walk` generator starts from sentinel genesis and holds only one before/after transition in memory. The prover receives the expected claim separately and does not read a giant witness JSON file or allocate a vector of all intermediate frontier states. It computes each operation and passes it to Nova, checks exact terminal state, then compresses the actual proof. Native witness streaming is O(depth) frontier memory apart from cryptographic prover state. The JS independent full-tree builder retains entries and the tree for comparison, so its peak process RSS must not be confused with the streamed Rust prover's memory. The compressed verifier reconstructs the circuit key independently and verifies receiver-owned state and step count, rejecting wrong source, sentinel, seal and step count plus trailing bytes.

## 4. Local native workload receipt

`evidence/native-scale-20261124.json` records a single local Node 22.16.0 CPU run at sizes 0, 1, 16, 128, 512, 2,048, 8,192, 144,000. The full run used 16.63 wall seconds and 165,672 KiB peak RSS for reference state generation, full-tree hashing, and fixture output. The 144,000-report snapshot pin is `bbc0234e9018423aa18cdb7ac57a094f4a325c9a330f34e014fd2c7ddb2909c2`. All five registered native reference tests passed. These measurements establish native reconstruction only, with `nova_verified=false`.

Prior depth-4 proof baseline, independently verified via run [45280073326](https://github.com/patrickdugan/SatsHedgeZero/actions/runs/45280073326): 58,793 application constraints, 71,734/10,349 augmented primary/secondary constraints, 16 packed fields, 12,008-byte compressed proof, 36,290,592-byte serialized verification-key representation. The Pyth 24-fold run used 5.496 s folding; Chainlink 16-fold run used 3.542 s. These figures describe depth 4 and may not be transferred to depth 18.

## 5. Acceptance and benchmark policy

- Preserve all expected depth-4 behavior under default features. Build depth 18 in the separate scale crate. The CI tests actual R1CS at depth 18: a full 16-report synthetic history, highest legal merge (local transition at level 17 to the root, not a full-capacity history), fixed shape, operation ceiling, unused packed high bits, wrong depth/claim, and corrupted destination outputs.
- Replay the entire 144,000-report native Rust stream against the separately generated claim.
- Run actual Pallas/Vesta Nova + Spartan/IPA transparent compressed proofs for 16, 128, and 512 reports sequentially by default; independently verify saved proofs with receiver-owned claims. A manual workflow can choose a 128/512/2,048-report ceiling. Retain intermediate receipts even if a later run fails or times out. CPU only, two Rayon threads, 90-minute workflow limit. No rented compute is used automatically.
- Each valid result records exact circuit/version, key digest and serialized size, constraint counts, proof bytes, folding throughput, compression and verification time, prover/verifier peak RSS, and proof rejection controls. All ladder sizes must have the same reconstructed key. `aggregate.mjs` reports an extrapolation from the largest measured fold throughput to 287,996 folds, marked `measured:false` and excluding setup/compression.
- The full workload is native-only in automatic CI. CLI proof runs above 512 require an explicit `SHZ_SCALE_MAX_REPORTS` budget; larger jobs must be separately planned. Current prover streams witness generation, but it does not checkpoint/resume an interrupted recursive proving job. That is a further engineering gate before a long full-scale proof.

The 144,000-report proof is **not** complete merely because the depth-18 circuit or native replay passes. Depth-18 MAX-01 selection circuit scaling, source-signature verification, report admission provenance/completeness, authorized seals, complete NEAR Nova verification, Bitcoin anchoring and FROST/DLC settlement remain separate open gates. This branch does not change those implementations.
