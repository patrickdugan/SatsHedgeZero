# ADMIT-07: transparent STARK admission and balanced recursive joins

Research-only alternate backend for the exact structural admission and sealing relation in ADMIT-06. It reproves normalized report transitions and composes real RISC Zero succinct receipts. It does not verify or wrap the existing Nova compressed proof bytes. No source, seal authority, data availability, or NEAR verifier claim.

- `core`: extracted ADMIT-05 native state machine, canonical state digest, 251-byte journal, balanced join predicate; ordinary Rust without zkVM.
- `methods/guest`: one pinned RISC Zero guest image, either executes a leaf or checks both child receipt assumptions and joins them.
- `host`: bounded local prover/independent verifier. Real succinct receipts only; no developer mode, network proving, or Groth16 wrapping.
- `reference.mjs`: independent JS encoder and exact root composition against the ADMIT-06 plans.

Run the cheap gates first:

```sh
node --test tests/reference.test.mjs
cargo test --manifest-path core/Cargo.toml
```

Install the RISC Zero Rust toolchain with `rzup`. Use the exact pinned SDK in the Cargo manifests (zkVM 3.1.0, build 3.0.7). From this directory:

```sh
export RISC0_PROVER=local
unset RISC0_DEV_MODE
cargo build --release -p shz-admission-recursive-host
/usr/bin/time -v target/release/shz-admission-recursive-host prove fixtures/4-expected.json fixtures/4-plan-2.json out-2
target/release/shz-admission-recursive-host verify fixtures/4-expected.json 2 out-2/root.bin
```

The default CI proves two leaves with one join on a four-report fixture; a manual four-leaf gate exercises two levels. The 128-report frozen plan is a native reference gate, not a registered default STARK proof run. Receipts and image identities from a green workflow are research evidence only. Independently pin the audited image and receipt verifier control root before deployment.
