# SHZ-BTCUSD-20261127T180130Z segment 0

Settlement `237f9f2412cfc4015b2c7cbbde6d1f816215f3fb9ec0d4884c92e9d0536b761d` (broadcast, regtest): batches 9..9, fee 628 sats at 1 sat/vB, 628 vB.

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
LIGHTNINGER_DLC_BATCH_VENUE=artifacts/epochs/regtest-drill/SHZ-BTCUSD-20261127T180130Z/seg0/venue_batches.json \
LIGHTNINGER_DLC_BATCH_GUEST_DIR=/tmp/guest-SHZ-BTCUSD-20261127T180130Z-0 \
target/release/dlc-batcher prove artifacts/epochs/regtest-drill/SHZ-BTCUSD-20261127T180130Z/seg0 4 2
```

The clearing fold alone, through the clearing crate:

```
cd research/lightninger_bitvm3_clearing
cargo run --release -- prove-clearing journal:../lightninger_dlc_batcher/artifacts/epochs/regtest-drill/SHZ-BTCUSD-20261127T180130Z/seg0/venue_batches.json 1 4 2 237f9f2412cfc4015b2c7cbbde6d1f816215f3fb9ec0d4884c92e9d0536b761d
```
