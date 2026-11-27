# SHZ-BTCUSD-20261127T1847Z segment 0

Settlement `8f090e367d157bd205e66221d29cf8276805cbae4dcb880318f2407f9b752141` (broadcast, regtest): batches 1..2, fee 477 sats at 1 sat/vB, 477 vB.

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
LIGHTNINGER_DLC_BATCH_VENUE=D:/shz/SatsHedgeZero/ops/mvp-drill/receipt-regtest/epochs/SHZ-BTCUSD-20261127T1847Z/seg0/venue_batches.json \
LIGHTNINGER_DLC_BATCH_GUEST_DIR=/tmp/guest-SHZ-BTCUSD-20261127T1847Z-0 \
target/release/dlc-batcher prove D:/shz/SatsHedgeZero/ops/mvp-drill/receipt-regtest/epochs/SHZ-BTCUSD-20261127T1847Z/seg0 4 2
```

The clearing fold alone, through the clearing crate:

```
cd research/lightninger_bitvm3_clearing
cargo run --release -- prove-clearing journal:../lightninger_dlc_batcher/D:/shz/SatsHedgeZero/ops/mvp-drill/receipt-regtest/epochs/SHZ-BTCUSD-20261127T1847Z/seg0/venue_batches.json 2 4 2 8f090e367d157bd205e66221d29cf8276805cbae4dcb880318f2407f9b752141
```
