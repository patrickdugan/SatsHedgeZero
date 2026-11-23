# SHZ-NOVA-G16-02: Sonobe decider soundness admission gate

**Research blocker, 2026-11-23.** [Sonobe issue #280](https://github.com/ethereum/sonobe/issues/280) reports a concrete potential forgery of an older Nova on-chain decider. The report says the in-circuit field folding and external KZG commitment folding may use distinct unconstrained challenges, while caller-provided commitments may be disconnected from the instances bound in Groth16. The author describes an arbitrary-statement forging proof of concept. A maintainer asked whether the new [LegoGroth16 decider PR #259](https://github.com/ethereum/sonobe/pull/259) fixes the issue. At inspection #280 remains open and #259 remains an unmerged draft. Current upstream `main` at `7f042351e73d38f99c05167ba41f1e282178b067` marks LegoGroth16 as pending.

## Before any SHZ Nova-decider authorization

1. Constrain one Fiat-Shamir fold challenge `r` across field variables and commitment folding. A privately supplied alternate challenge must fail.
2. Bind every running/incoming witness commitment to the same exact instances, transcript and public inputs checked inside Groth16. Replacing any external commitment must fail.
3. Constrain the relaxed error-vector commitment and previous-state relation. Selecting an arbitrary error vector `E = Az ◦ Bz - uCz` for a false target instance must fail.
4. Reproduce the #280 alleged arbitrary-`(i,z0,zi)` attack against the exact pinned candidate; the actual verifier must reject it, including public values selected independently of the prover.
5. Verify the KZG opening and Groth16 proof against one pinned transcript and public-input mapping; include *all* native checks in the verifier contract or in a proof of their correctness.
6. Bind SHZ's Pyth/Chainlink report digests, Bitcoin TXID, signed payout scripts, original DLC funding outpoints and oracle epoch through canonical bit/byte encodings. Split 256-bit hashes into two 128-bit limbs instead of reducing arbitrary digests modulo BN254's field order.

## Boundary

The staged `PRICE_MEAN_V1` proof proves only the authenticated-input *arithmetic* relation once sources are supplied. It contains no Nova verifier, Bitcoin spending authorization or mint authority. Keep `can_authorize_nova_decider() == false` and `production_ready = false`. The existing Pallas/Spartan Nova 0.76.0 proof retains its independent verifier and evidence.

This admission gate documents the unresolved report; it does not claim that the unmerged #259 revision contains the same defect.
