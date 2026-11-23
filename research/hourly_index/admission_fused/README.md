# INDEX-ADMIT-03: eager placement

An isolated Nova circuit that eliminates one placement-only fold per admitted report. Same MAX-01 SHA256 snapshot pins, same 32-field state layout, new transition relation and verifier key. See [specification](../../../docs/SHZ_INDEX_ADMISSION_03_EAGER_PLACEMENT.md).

From repository root:

```sh
B=research/hourly_index/admission_fused
node "$B/fixtures/build.mjs"
node --test "$B/tests/frontier.test.mjs"
cargo test --release --manifest-path "$B/Cargo.toml" -- --test-threads=1 --nocapture
cargo build --release --manifest-path "$B/Cargo.toml"
"$B/target/release/shz-hourly-index-admission-fused-nova" prove "$B/fixtures/pyth-steps.json" "$B/fixtures/pyth-expected.json" /tmp/shz-eager-proof
"$B/target/release/shz-hourly-index-admission-fused-nova" verify "$B/fixtures/pyth-expected.json" /tmp/shz-eager-proof
```

Repeat for Chainlink, with a new output directory. The independently authorized snapshot must be pinned before verification. The fixture is synthetic. Source authentication, external seal authority, provider completeness, NEAR proof verification, Bitcoin finality, and all settlement authorization flags remain false. No trusted setup. Actual proof results require the dedicated CI gate.
