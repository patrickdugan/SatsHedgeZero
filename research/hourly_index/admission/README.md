# INDEX-ADMIT-01

Fixed-depth-4 transparent Nova candidate for structural append/seal history. It composes byte-exactly with MAX-01 and POLICY-01; no new oracle trust, NEAR, or Bitcoin claims. See [the mathematical specification](../../../docs/SHZ_INDEX_ADMISSION_01.md).

```sh
B=research/hourly_index/admission
node "$B/fixtures/build.mjs"
node --test "$B/tests/frontier.test.mjs"
cargo generate-lockfile --manifest-path "$B/Cargo.toml"
cargo test --release --locked --manifest-path "$B/Cargo.toml" -- --test-threads=1
cargo build --release --locked --manifest-path "$B/Cargo.toml"
for source in pyth chainlink; do
  "$B/target/release/shz-hourly-index-admission-nova" prove "$B/fixtures/$source-steps.json" "$B/fixtures/$source-expected.json" "/tmp/admission-$source"
  "$B/target/release/shz-hourly-index-admission-nova" verify "$B/fixtures/$source-expected.json" "/tmp/admission-$source"
done
```

The fixture claims are synthetic independent test expectations. A real receiver must retain the admitted snapshot identity and authenticate the seal and source registry. It must reconstruct the root from the proved final frontier, verify the pinned circuit, and match the verified pins to the maximality proof. A verifier receipt alone cannot establish validity. `evidence/hash-work-model.json` is a workload model, not actual proof cost. The local Node reference passes 21 tests. The Rust R1CS, native compressed-proof and independent-verification gates are run in CI; no local Rust toolchain was available at registration.
