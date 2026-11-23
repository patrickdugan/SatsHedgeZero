# INDEX-ADMIT-07: balanced transparent STARK composition for admission

Registered 2026-11-24. Parent ADMIT-06 (`bf1b207f9addf23a2be9f0b8a96f1cc7879bf792`). The verified depth-18 Nova chain for 128 reports contains four 12,904-byte proofs, 51,616 bytes in total, and a serialized 43,653,952-byte verifier key (CI #45283295751). Native chain verification, including negative controls, was 3.973497928 s with one reconstructed key. This key and foreign-field verifier workload motivate a second transparent proof backend. Existing Nova proofs and relations stay unchanged.

## 1. Backend and statement

The experiment uses RISC Zero zkVM 3.0.6 succinct STARK receipts and recursive proof composition. The leaf guest proves the original ADMIT-05/06 structural state transition directly, using the same fixed-depth-18 SHA-256 tree commitments and bounded report admission, mandatory binary carries and monotone seals. The source is an extracted native state machine with the field-specific encoding methods removed. This is an alternate backend for the same structural semantics; the guest does **not** verify the ADMIT-06 Nova compressed proofs. A wrapper of those exact Nova proofs requires a separate foreign-field workload and interoperability experiment. No trusted ceremony is used by the registered succinct receipt route. No Groth16 receipt is accepted.

For approved guest image I, let context C=(network genesis, fixed POLICY-01 digest, source id, depth=18, independently expected MAX-01 snapshot pin, I). Encode fields in this order, with byte-array digests in original digest order, source and depth as bytes, and I as eight little-endian u32 words. The endpoint commitment is:

`D(C,S) = SHA256("SHZ/ADMIT/STATE/V1" || C || operations_u64 || leaf_count_u64 || last_time_u64 || sealed_through_u64 || pending_u8 || level_u8 || carry.min_u64 || carry.digest32 || (occupied_u8 || min_u64 || digest32) * 19)`

All integers little-endian. This binds the entire frontier, including empty slots and pending state. Endpoints are validated idle states. The journal is precisely 251 bytes:

`SHZAGG01 || C || height_u8 || start_op_u64 || end_op_u64 || start_reports_u64 || end_reports_u64 || start_seal_u64 || end_seal_u64 || D(C,S_start) || D(C,S_end)`.

The leaf program validates its input state, appends actual normalized report records, resolves all carries, and optionally advances a seal watermark. It derives the terminal state. The report budget is 4096 and operation budget 8192 per leaf. Nonempty interval required. Leaf height is exactly zero. No provider signatures or completeness evidence are inferred from these normalized values. The benchmark host derives the frozen synthetic records independently from the ADMIT-06 plan and checks all endpoints.

## 2. Balanced recursive join and soundness

The join program decodes both exact child journals, checks equal context and equal height h<6, consecutive operation and report ranges, equal boundary seal, and full endpoint-digest equality. It constructs a parent journal with outer endpoints and height h+1. Crucially it calls `env::verify` on the actual journal bytes of **each** child, using the shared context's image I. The host supplies real child receipts as assumptions. `ProverOpts::succinct` resolves the assumptions through the zkVM STARK recursion circuit. Ordinary `Receipt::verify(I)` rejects unresolved assumptions. No native report or digest alone qualifies as a proof.

One image handles both leaf and join, avoiding embedding its own recursively defined image digest. The outer verifier independently knows I from the audited compiled program; it verifies the root under I and requires the root's journal context I to be exactly that image. Every join enforces equal child context and verifies both children under I. A leaf can only output height 0, and a join increments two equal heights. Induction on height gives a finite tree of exactly 2^h proved nonempty intervals, all under the approved image. With collision resistance of D, equality of adjacent endpoints binds identical state coordinates. The independent outer verifier reconstructs D for the canonical sentinel genesis and the terminal frontier of its retained Claim, checks its original MAX-01 snapshot pin, and compares every byte of the expected root journal. Arbitrary leaf starts therefore do not imply whole-history reachability in isolation.

This theorem assumes sound STARK proofs and collision resistance of SHA256; it is not a formal proof of RISC Zero's implementation. Production must pin the audited guest image, approved recursion control root, exact SDK/toolchain and soundness parameters independently of all proof bundles. Only the receiver-owned image and endpoint claim confer meaning. The state hashes are deterministic commitments; low-entropy private data may remain guessable.

## 3. Registered falsification and resource gates

- 12 local Node tests compare the exact reference journal bytes, the 128-report four-segment plan, the two- and four-leaf plans for four reports, wrong contexts/ranges/heights, forged boundary, reordered/duplicated child and altered final pin. Frozen journal uses synthetic ID words [1..8] for cross-language byte parity only, never an approved guest ID.
- Run actual Rust core tests over the same frozen claims, comparing the independent journal bytes and malicious inputs.
- Default actual proof: two leaf receipts and one recursive join over four synthetic reports. Manually select four leaves/two levels for the deeper gate. Each proof invocation has 8 Mi-cycle session ceiling and segment exponent 18. One local CPU process, bounded Rayon threads, no cloud billing, no dev mode. The host requires `InnerReceipt::Succinct`, verifies actual seals, exports only the root receipt and journal plus metrics. Independently verify the persisted root in another invocation. Attempt actual child-receipt substitution while retaining correct parent input journal bytes, plus tampered child journal and actual root proof negative controls. Record failures precisely. Do not infer proof validity from these registered checks before a successful run.
- Compare proof bytes, seal bytes, guest cycles, proving/verification wall time, memory, image ID and exact expected endpoint. No comparison of the tiny STARK fixture with the 128-report Nova chain as if workloads were matched. Next run 128 reports and a balanced 64-segment plan only after measuring resource use. A 64-leaf tree has six join levels and 63 joins, with 287,996 total structural transitions for 144,000 reports under ADMIT-06's existing profile.

RISC Zero sources: https://dev.risczero.com/proof-system/ and https://dev.risczero.com/api/zkvm/composition, https://docs.rs/risc0-zkvm/3.0.6/risc0_zkvm/struct.Receipt.html. The transparent succinct receipt is STARK-based; the optional Groth16 compression is excluded.

## 4. Unresolved NEAR gate

A successful root receipt would be independently verifiable native STARK evidence of structural admission. NEAR still needs a reviewed on-chain transparent STARK verifier and exact pinned receipt/control-root binding, with sandbox gas measurements. The alternative backend does not solve the already separate source authentication, provider completeness, watermark authority, maximality depth18 selection, POLICY-01 composition, Bitcoin finality or DLC attestation gates. All NEAR and production flags remain false. The first deployment target is a verifiable structural source snapshot consumed by the existing selection/policy pipeline, not automatic settlement authorization.

## Superseding security update (ADMIT-08)

The original 3.0.6 dependency was withdrawn. See [ADMIT-08](SHZ_INDEX_ADMISSION_08_PATCHED_STARK_VERIFIER.md) for the patched SDK/control-root gate. No 3.0.6 receipts are accepted.
