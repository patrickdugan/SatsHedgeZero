# INDEX-MAX-01: one-path observation maximality

Read [formal relation](../../../docs/SHZ_INDEX_MAXIMALITY_01.md). This independent crate is stacked on INDEX-POLICY-01. No edits to the oracle adapters, NEAR contract or existing policy circuit. Native reference and append/seal transitions share a canonical authenticated minimum tree; the selection circuit binds both source snapshot pins and the exact policy evidence queue. The synthetic fixtures are not live reports.

```sh
node research/hourly_index/maximality/fixtures/build.mjs
node --test research/hourly_index/maximality/tests/log.test.mjs
node research/hourly_index/maximality/benchmark.mjs
cargo test --release --manifest-path research/hourly_index/maximality/Cargo.toml -- --test-threads=1 --nocapture
cargo build --release --manifest-path research/hourly_index/maximality/Cargo.toml
B=research/hourly_index/maximality
$B/target/release/shz-hourly-index-maximality-nova prove $B/fixtures/openings.json $B/fixtures/expected.json /tmp/shz-max-proof
$B/target/release/shz-hourly-index-maximality-nova verify $B/fixtures/openings.json $B/fixtures/expected.json /tmp/shz-max-proof
```

All proof claims are conditional on independently authenticated ordered sealed snapshot pins. A full log root of omitted reports cannot prove provider completeness. Native reference depth 18 scale benchmark is separate from the depth 4 R1CS and no NEAR verifier is implemented here.
