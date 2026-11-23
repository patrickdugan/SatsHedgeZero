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

The fixture `fixtures/checkpoint.json` has eight UTC hourly slots, seven qualified two-source prices and one `HOLD`. All hashes, packet bytes and inclusion paths are reproducible. Native NEAR stores hourly owner-published **research** records immediately. An eight-hour checkpoint may be staged only when it agrees with all eight previously published hours. The contract independently checks the leaf arithmetic and SHA256 inclusion; research owner publication is not source authentication. The `bitcoin_packet.mjs` parser recomputes Bitcoin non-witness TXIDs and checks an exact 40-byte payload in `OP_RETURN`, plus Merkle inclusion relative to a supplied *untrusted* header.

See [`docs/SHZ_HOURLY_INDEX_ZK_CONTRACT.md`](../../docs/SHZ_HOURLY_INDEX_ZK_CONTRACT.md) for the frozen proposed transparent ZK witness relation and the gates that remain open. This workstream is isolated from the existing Groth16 and IPA research branches.

## Verified NEAR sandbox milestone

[GitHub Actions run #45211089127](https://github.com/patrickdugan/SatsHedgeZero/actions/runs/45211089127) passed the Node fixture and negative tests, Rust host tests, WASM release build, and actual NEAR sandbox. Eight hourly records were published individually before the checkpoint root was staged; seven qualified and one remained HOLD. The contract verified every inclusion path and rejected a substituted source report. An independent on-chain inclusion check used **1.509153 TGas** receipt gas. Receipt: `evidence/sandbox-20261123.json`. All source authentication, Bitcoin header finality, ZK witness and DLC authorization flags remain false.
