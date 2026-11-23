# INDEX-ADMIT-04: compact frontier state

An isolated Nova circuit adapter around ADMIT-03 (pinned parent commit `1ff5da1150a7b5016e1e2c9ad10dce955de0d974`). It reduces the number of folded public-state coordinates without changing any SHA-256 hash, accepted report, frontier update, seal, or snapshot pin. The existing typed Claim and witness JSON are unchanged. This is a new relation and verification key; old proof bytes cannot authorize the new relation.

```sh
node --test research/hourly_index/admission_packed/tests/packing.test.mjs
node --test research/hourly_index/admission_fused/tests/frontier.test.mjs
cargo test --release --manifest-path research/hourly_index/admission_packed/Cargo.toml -- --nocapture --test-threads=1
B=research/hourly_index/admission_packed
F=research/hourly_index/admission_fused/fixtures
cargo build --release --manifest-path "$B/Cargo.toml"
"$B/target/release/shz-hourly-index-admission-packed-nova" prove "$F/pyth-steps.json" "$F/pyth-expected.json" /tmp/shz-packed-pyth
"$B/target/release/shz-hourly-index-admission-packed-nova" verify "$F/pyth-expected.json" /tmp/shz-packed-pyth
```

See [`SHZ_INDEX_ADMISSION_04_PACKED_STATE.md`](../../../docs/SHZ_INDEX_ADMISSION_04_PACKED_STATE.md). Twelve independent BigInt encoding tests and the inherited 27 JS reference tests passed locally. Rust compilation, actual constraints and proof measurements require the registered CI workflow. Depth 18 and 24 are integer encoding checks, not larger compiled Nova circuits. Source authentication, authorized watermarks, provider completeness, full transparent verification on NEAR, and settlement remain unproven.
