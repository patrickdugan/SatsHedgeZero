# SHZ-BTCUSD-20261127T184800Z segment 0

Settlement `867d59121fe3ba5ec6c0cb5a1da5116e2563c7e595b314949c584ce2bf0fc135` (broadcast, regtest): batches 1..3, fee 628 sats at 1 sat/vB, 628 vB.

| File | Content |
| --- | --- |
| `package.json` | what the venue showed each trader (input, output, net per batch row, 0x83 sighash) |
| `signatures.json` | trader signatures collected before the deadline |
| `manifest.json`, `batches.json`, `txs.json` | `dlc-batcher prove` inputs (manifest, V3 batch vectors, signed settlement with its signature slots) |
| `venue_batches.json` | the segment's explorer batches with the pool pre-state, for `trace::from_venue` |
| `settlement.json` | the result posted to the venue |
| `joint_statement.json`, `guest_input.json`, `prove.log` | written by the prover |

Re-prove from a clean checkout (table 4, 2 rows per batch):

```
cd research/lightninger_dlc_batcher
CARGO_INCREMENTAL=0 cargo build --release --bin dlc-batcher
LIGHTNINGER_DLC_BATCH_VENUE=artifacts/epochs/regtest-batchless/SHZ-BTCUSD-20261127T184800Z/seg0/venue_batches.json \
LIGHTNINGER_DLC_BATCH_GUEST_DIR=/tmp/guest-SHZ-BTCUSD-20261127T184800Z-0 \
target/release/dlc-batcher prove artifacts/epochs/regtest-batchless/SHZ-BTCUSD-20261127T184800Z/seg0 4 2
```

The clearing fold alone, through the clearing crate:

```
cd research/lightninger_bitvm3_clearing
cargo run --release -- prove-clearing journal:../lightninger_dlc_batcher/artifacts/epochs/regtest-batchless/SHZ-BTCUSD-20261127T184800Z/seg0/venue_batches.json 3 4 2 867d59121fe3ba5ec6c0cb5a1da5116e2563c7e595b314949c584ce2bf0fc135
```
