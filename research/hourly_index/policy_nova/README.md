# INDEX-POLICY-01

Independent policy circuit on top of INDEX-02. See [specification](../../../docs/SHZ_INDEX_POLICY_01.md) for the relation, precise evidence bytes, queue-state encoding, and trust boundary. Frozen synthetic fixture includes four VALID hours, one missing, one stale, one wide-spread and one skewed hour. The checkpoint still uses `SHZIDX01` plus the output root; the receiver separately pins the evidence root. A regenerated policy digest distinguishes the necessary-HOLD relation from v1.

```sh
node research/hourly_index/policy_nova/fixtures/build.mjs
node --test research/hourly_index/policy_nova/tests/*.test.mjs
cargo generate-lockfile --manifest-path research/hourly_index/policy_nova/Cargo.toml
cargo test --release --locked --manifest-path research/hourly_index/policy_nova/Cargo.toml -- --test-threads=1 --nocapture
cargo build --release --locked --manifest-path research/hourly_index/policy_nova/Cargo.toml
D=research/hourly_index/policy_nova
"$D/target/release/shz-hourly-index-policy-nova" prove "$D/fixtures/checkpoint.json" "$D/fixtures/expected.json" /tmp/shz-policy-proof
"$D/target/release/shz-hourly-index-policy-nova" verify "$D/fixtures/checkpoint.json" "$D/fixtures/expected.json" /tmp/shz-policy-proof
```

The expected fixture demonstrates an independently supplied claim interface, not trusted source provenance. In production, build/obtain the evidence root independently of the prover using authenticated source log snapshots. The proof verifier must compare both the output checkpoint and evidence root to independently accepted expectations. The old INDEX-02 relation remains intact. A v2 record with a new policy digest requires a separately registered version and verification identity. No changes to NEAR contracts, source importers, SPV, or FROST in this branch.

Local Node reference: 20 tests passed. Rust compiler, R1CS and persisted Nova proof checks require the dedicated CI workflow. Do not assume a complete transparent proof, NEAR execution, or source authenticity until measured. All production flags remain disabled.
