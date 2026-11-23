# SHZ-INDEX-01: hourly oracle index / eight-hour checkpoint

Deterministic JavaScript reference and native NEAR contract. The current verification relation is public SHA256, not a zero-knowledge SNARK.

```sh
node research/hourly_index/fixtures/generate.mjs
npm --prefix research/hourly_index test
cargo test --manifest-path research/hourly_index/near_contract/Cargo.toml
cargo build --release --target wasm32-unknown-unknown --manifest-path research/hourly_index/near_contract/Cargo.toml
npm --prefix research/hourly_index install
npm --prefix research/hourly_index run sandbox
```

The fixture `fixtures/checkpoint.json` has eight UTC hourly slots, seven qualified two-source prices and one `HOLD`. All hashes, packet bytes and inclusion paths are reproducible. Native NEAR accepts only an owner-staged **research** checkpoint and independently checks the leaf arithmetic and SHA256 inclusion. The `bitcoin_packet.mjs` parser recomputes Bitcoin non-witness TXIDs and checks an exact 40-byte payload in `OP_RETURN`, plus Merkle inclusion relative to a supplied *untrusted* header.

See [`docs/SHZ_HOURLY_INDEX_ZK_CONTRACT.md`](../../docs/SHZ_HOURLY_INDEX_ZK_CONTRACT.md) for the frozen proposed transparent ZK witness relation and the gates that remain open. This workstream is isolated from the existing Groth16 and IPA research branches.
