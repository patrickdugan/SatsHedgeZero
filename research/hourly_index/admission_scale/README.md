# INDEX-ADMIT-05: depth-18 benchmark

This isolated crate selects the `depth18` feature in both parent admission crates, preserving depth-4 defaults and using the existing transparent Nova/Spartan/IPA proof system. See [specification](../../../docs/SHZ_INDEX_ADMISSION_05_DEPTH18.md) for the scope and registered tests. The source stream is synthetic.

From repository root:

```sh
B=research/hourly_index/admission_scale
node --test "$B/tests/reference.test.mjs"
node "$B/fixtures/build.mjs" /tmp/shz-depth18-claims
cargo generate-lockfile --manifest-path "$B/Cargo.toml"
CARGO_BUILD_JOBS=2 cargo test --release --locked --manifest-path "$B/Cargo.toml" -- --test-threads=1 --nocapture
CARGO_BUILD_JOBS=2 cargo build --release --locked --manifest-path "$B/Cargo.toml"
EXE="$B/target/release/shz-hourly-index-admission-scale"
"$EXE" trace "$B/fixtures/144000-expected.json"
RAYON_NUM_THREADS=2 "$EXE" prove "$B/fixtures/128-expected.json" /tmp/shz-depth18-128
RAYON_NUM_THREADS=2 "$EXE" verify "$B/fixtures/128-expected.json" /tmp/shz-depth18-128
```

The default proving budget is 512 reports; a larger local run needs an explicitly configured `SHZ_SCALE_MAX_REPORTS`. The independent verifier does not trust expectations supplied by the prover. Output directories must be new. The native full reference receipt does not attest cryptographic verification; the full 144,000-report proof remains open. No automatic GPU, cloud allocation, or mainnet settlement is authorized.
