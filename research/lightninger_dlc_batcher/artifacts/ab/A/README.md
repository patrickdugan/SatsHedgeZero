# A/B variant A: prover inputs

Variant A of the DLC batch (script leaf: accounts `<T> CHECKSIGVERIFY <B> CHECKSIG` + CLTV refund leaf (NUMS internal key); 17 signatures (8 trader adaptor signatures completed with the oracle scalar, 8 batcher, 1 operator)). Same venue batches (306..313) and oracle event
(`SHZ-BTCUSD-20261127T1345Z`, CET 527) as the other variant. The settlement was mined on regtest
(`../regtest_receipt.json`, height 112).

| File | Content |
| --- | --- |
| `txs.json` | the signed settlement (label `settlement`), prevout amounts and scriptPubKeys, one bound slot per signature, M17 flags |
| `manifest.json` | the epoch manifest (accounts, collateral, payout scripts, operator input) |
| `batches.json` | the venue batches' `BatchClearing` vectors (relation format) |

Expected `settlement_txid`: **`5caa42e17b8b0cb8a504d10ca65a36f40168a447a60599d20cf9ffed3bfc6bf0`**

## Commands (clean checkout, Linux)

```
git clone https://github.com/patrickdugan/SatsHedgeZero && cd SatsHedgeZero/research/lightninger_dlc_batcher
cargo build --release --locked --bin dlc-batcher
export LIGHTNINGER_DLC_BATCH_GUEST_DIR=$PWD/guest-A
/usr/bin/time -v ./target/release/dlc-batcher prove ab/A 8 2 2> prove-A.log
```

`prove ab/A 8 2` (table 8, 2 rows per batch) folds the clearing of the 8 batches, M17 over all 9
settlement inputs, the bind-mode TapSighash and Secq folds over every signature, checks the binding
(7 altered bindings must be rejected) and the settlement relation (4 negatives), and writes
`artifacts/ab/A/joint_statement.json` (fold receipts: constraints, fold and compress seconds, proof
bytes) and `guest_input.json`, plus the SP1 guest inputs in `$LIGHTNINGER_DLC_BATCH_GUEST_DIR`.
`joint_statement.json` must name `settlement.txid = 5caa42e17b8b0cb8a504d10ca65a36f40168a447a60599d20cf9ffed3bfc6bf0`. Report its fold receipts, the
wall time, and `Maximum resident set size` from `prove-A.log`.

Local smoke check at K = 2 (no compression): `cargo test --release --test ab ab_prover_inputs_smoke -- --ignored`.
