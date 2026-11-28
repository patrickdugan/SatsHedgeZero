# SHZ-BTCUSD-20261128T0315Z segment 0 (testnet4)

Settlement `84c2f2f8cc521fa8ade0e9fb9366d54f41cfb1bf24b50f41e476c7e38c610664` (broadcast, testnet4,
https://mempool.space/testnet4/tx/84c2f2f8cc521fa8ade0e9fb9366d54f41cfb1bf24b50f41e476c7e38c610664):
batches 1..2, 2 signers, fee 477 sats at 1 sat/vB, 477 vB, manifest
`ccaf0d861f43ec4a7c895b645774c7a83161547358080b28afe7ce8559ae5555`.

The first real-coin epoch of the Lightninger venue (`shz-venue --collateral-chain testnet4` on the
witness box, port 8099; daemon `shz_batcher` a1e3619 with `BROADCAST=1`, operator liquidity
`9c3f2827…:0`). Two traders deposited 50,000 sats each in `8f9ce3863d474d998008edd66224c28b565e916cddefb83dc48cf7e35920fcb9`
(outputs 0 and 1, to `account(T, B, 164164)`), traded $100 at 10x (trader 0 short at 59,941, closed
at 59,991: trader 0 −139, trader 1 +139 sats), and both signed their 0x83 entries
(`ops/mvp-drill/testnet4_epoch.mjs`). Payouts: trader 0 rolled to 49,861, trader 1 to 50,139, refund
height 164179. Proving runs on Colab; this directory holds the prover inputs only.

| File | Content |
| --- | --- |
| `package.json` | what the venue showed each trader (input, output, net per batch row, 0x83 sighash) |
| `signatures.json` | trader signatures collected before the deadline |
| `manifest.json`, `batches.json`, `txs.json` | `dlc-batcher prove` inputs (manifest, V3 batch vectors, signed settlement with its signature slots) |
| `venue_batches.json` | the segment's explorer batches with the pool pre-state, for `trace::from_venue` |
| `settlement.json` | the result the daemon posted to the venue |

Prove from a clean checkout (table 4, 2 rows per batch); the statement must name settlement_txid
`84c2f2f8cc521fa8ade0e9fb9366d54f41cfb1bf24b50f41e476c7e38c610664`:

```
cd research/lightninger_dlc_batcher
CARGO_INCREMENTAL=0 cargo build --release --bin dlc-batcher
LIGHTNINGER_DLC_BATCH_VENUE=$PWD/artifacts/epochs/testnet4/SHZ-BTCUSD-20261128T0315Z/seg0/venue_batches.json \
LIGHTNINGER_DLC_BATCH_GUEST_DIR=/tmp/guest-SHZ-BTCUSD-20261128T0315Z-0 \
target/release/dlc-batcher prove $PWD/artifacts/epochs/testnet4/SHZ-BTCUSD-20261128T0315Z/seg0 4 2
```

(`prove` resolves a relative segment path against `artifacts/`, so pass it absolute.) It writes
`joint_statement.json` (`bitvm3_statement_sha256`), `guest_input.json` and `prove.log` here.

The clearing fold alone, through the clearing crate:

```
cd research/lightninger_bitvm3_clearing
cargo run --release -- prove-clearing journal:../lightninger_dlc_batcher/artifacts/epochs/testnet4/SHZ-BTCUSD-20261128T0315Z/seg0/venue_batches.json 2 4 2 84c2f2f8cc521fa8ade0e9fb9366d54f41cfb1bf24b50f41e476c7e38c610664
```
