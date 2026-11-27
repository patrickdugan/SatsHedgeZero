# A/B variant B: prover inputs

Variant B of the DLC batch (MuSig2 key path: accounts with internal key MuSig2(trader, batcher) + CLTV refund leaf; 9 key-path signatures (8 MuSig2 adaptor signatures completed with the oracle scalar, 1 operator)). Same venue batches (306..313) and oracle event
(`SHZ-BTCUSD-20261127T1345Z`, CET 527) as the other variant. The settlement was mined on regtest
(`../regtest_receipt.json`, height 112).

| File | Content |
| --- | --- |
| `txs.json` | the signed settlement (label `settlement`), prevout amounts and scriptPubKeys, one bound slot per signature, M17 flags |
| `manifest.json` | the epoch manifest (accounts, collateral, payout scripts, operator input) |
| `batches.json` | the venue batches' `BatchClearing` vectors (relation format) |

Expected `settlement_txid`: **`a8b118138e543582330eb3ad5ad5fd31b308db9483d0300b95304107043e46d6`**

## Commands (clean checkout, Linux)

```
git clone https://github.com/patrickdugan/SatsHedgeZero && cd SatsHedgeZero/research/lightninger_dlc_batcher
cargo build --release --locked --bin dlc-batcher
export LIGHTNINGER_DLC_BATCH_GUEST_DIR=$PWD/guest-B
/usr/bin/time -v ./target/release/dlc-batcher prove ab/B 8 2 2> prove-B.log
```

`prove ab/B 8 2` (table 8, 2 rows per batch) folds the clearing of the 8 batches, M17 over all 9
settlement inputs, the bind-mode TapSighash and Secq folds over every signature, checks the binding
(7 altered bindings must be rejected) and the settlement relation (4 negatives), and writes
`artifacts/ab/B/joint_statement.json` (fold receipts: constraints, fold and compress seconds, proof
bytes) and `guest_input.json`, plus the SP1 guest inputs in `$LIGHTNINGER_DLC_BATCH_GUEST_DIR`.
`joint_statement.json` must name `settlement.txid = a8b118138e543582330eb3ad5ad5fd31b308db9483d0300b95304107043e46d6`. Report its fold receipts, the
wall time, and `Maximum resident set size` from `prove-B.log`.

Local smoke check at K = 2 (no compression): `cargo test --release --test ab ab_prover_inputs_smoke -- --ignored`.
