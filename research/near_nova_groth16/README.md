# SHZ-NOVA-G16-01: NEAR Groth16 proof gateway

**Stage:** research / stacked on SHZ PR #3.  `production_ready = false`.

This prototype separates (1) a real BN254 Groth16 verification path using NEAR's native alt-bn128 host functions, (2) a Groth16 arithmetic circuit for the Pyth/Chainlink index, and (3) the *still-unimplemented* Nova-to-Groth16 decider. The Groth16 arithmetic proof **does not verify any Nova proof**, authorize Bitcoin spends, authenticate a Chainlink report, or supply NEAR finality to a Bitcoin verifier.

## Local and CI usage

```sh
cargo test --manifest-path research/near_nova_groth16/near_contract/Cargo.toml
cargo test --manifest-path research/near_nova_groth16/proof_demo/Cargo.toml
cargo run --manifest-path research/near_nova_groth16/proof_demo/Cargo.toml --example gen_vector -- /tmp/shz-near-g16-vector.json
cargo check --manifest-path research/near_nova_groth16/near_contract/Cargo.toml --target wasm32-unknown-unknown
node --test research/near_nova_groth16/tests/*.test.mjs
```

The Rust prover demo prints a valid Groth16 proof (randomly generated in tests, so it must not be treated as a stable verifier key); `near_contract` imports the same point-byte convention used by NEAR's alt_bn128 host functions. The contract accepts an immutable verification key at initialization and verifies proofs with exact three public inputs, `Pyth_price_e8`, `Chainlink_price_e8`, and `index_price_e8`. It checks source identity and nonce *only when their authoritative registries are integrated*. The demo circuit proves checked, nonzero 64-bit prices, integer midpoint rounding, and an absolute spread of at most 50 basis points. It does not check source signatures; source authenticity must be verified by a separate independent verifier before accepting any output.

The exact circuit is part of the Groth16 proving key; any change demands a new trusted setup or a verifiable delegated ceremony, new verifying-key pin, and a new protocol version. The demo uses an unsafe single-party test setup for research only.

`receipt_gate.mjs` reads and checks frozen SHZ-MNR-03 evidence, refuses to mark the existing Pallas/Spartan proof as Groth16 wrapped, detects the different Nova journal and actual Bitcoin TXIDs, and generates a machine-readable work order. This is intentionally a validation/coordination tool, not a cryptographic verifier.

## Full Nova → Groth16 criteria

The next variant must implement an **in-circuit** verifier for the exact Nova 0.76.0 Pallas/Vesta Spartan/IPA compressed proof over the already pinned verifier key **or** migrate an independently reviewed SHZ application circuit to a BN254/Grumpkin Nova + Sonobe Groth16/KZG decider with precise byte-level equivalence to the original MNR-03 statement. The latter is the preferred experiment because Sonobe already has an on-chain decider, although its verification may entail a separate KZG pairing check as well as Groth16. Keep both proofs and statements clearly versioned.

A compressed Nova proof's SHA-256, a signed assertion that a verifier returned true, or a Groth16 proof of arithmetic over the receipt **does not imply** that Groth16 checked Nova's verifier. Until the circuit enforces the actual Nova relation and the Groth16 verification key for that relation is pinned, `nova_verified_inside_circuit = false` and no value or token may be minted as a consequence of this experiment.

See `docs/SHZ_NOVA_GROTH16_NEAR.md` for soundness and deployment gates.
