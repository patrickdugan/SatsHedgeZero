# Live Bitcoin Testnet4 3-Party, 3-Trade DLC Collation & BitVM3 Nova Margin Clearing

## 1. Overview

This report records the end-to-end execution of multilateral inverse BTC/USD DLC collation, `UTXORef` capacitated PnL routing (`solve_and_verify_pnl_batch` + `DurablePnlBatchBook`), unencumbered collateral release, out-of-process `lnm-nova` (`nova-snark 0.76.0` Spartan + IPA) `CompressedSNARK` proving, and live on-chain Bitcoin Testnet4 transaction execution.

All three counterparties (**Alice**, **Bob**, **Carol**) execute signed `0 bps`-fee P2P inverse BTC/USD orders across three sequential price levels, lock collateral in `UTXORef` NUMS `P2TR` DLC contracts (`<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`), and settle atomically in a single 3-input, 4-output BIP-341 Taproot clearing transaction (`txid == journal.batch_txid == bitvm3_statement.settlement_txid`) that:
1. **Routes realized PnL directly to Winner Alice** upon closing out on Trade 3, and
2. **Frees unencumbered collateral immediately back to Loser Bob** (and Market-Maker Carol) once their net USD delta is flattened.

---

## 2. Live Public Bitcoin Testnet4 On-Chain Execution (`$1` Micro-Triangle: `$80k -> $100k -> $125k`)

Executed against a synchronized Bitcoin Core v31.1 Testnet4 node at block height **`162,905`** (`00000000003c7b7ed5977f97e3286329502d8a6d6d32f4b1ed073aa76fb32484`):

- **3-DLC Funding Transaction (`tx_fund`):**
  - `txid`: `2fc1511cfeb53b4e5d014d013139d4e3d397d876954564c84b3f1ad6a4cf6312`
  - Explorer: https://mempool.space/testnet4/tx/2fc1511cfeb53b4e5d014d013139d4e3d397d876954564c84b3f1ad6a4cf6312
- **3-Input Collated `LNMBAT01` Atomic Clearing Transaction (`tx_clear`):**
  - `txid`: `c9136b4e090d92e00ffb76416d2af207146abacc095c452443f77160cc3c4551`
  - `wtxid`: `e0b0d8e59502377cd303263670bc5bbff93a1c7ed5f16d3a2cc24a64ac40a6bf` (`505 vB`, `nLockTime = 162,905`)
  - Explorer: https://mempool.space/testnet4/tx/c9136b4e090d92e00ffb76416d2af207146abacc095c452443f77160cc3c4551

| Trade / Party | Entry / Action | Posted Margin (sats) | Net Realized PnL (sats) | Freed Collateral (sats) | Final Cleared Output (sats) |
| --- | --- | ---: | ---: | ---: | ---: |
| **Trade 1** (`vout 0`) | Alice Long `$1` (`2x`) vs Bob Short `$1` (`1.25x`) @ `$80,000` | `625 + 1,000` | `+450` / `-450` | — | Spent in `c9136b4e...` |
| **Trade 2** (`vout 1`) | Bob Long `$1` (`2x`) vs Carol Short `$1` (`1.6x`) @ `$100,000` | `500 + 625` | `+200` / `-200` | — | Spent in `c9136b4e...` |
| **Trade 3** (`vout 2`) | Carol Long `$1` (`2x`) vs Alice Short `$1` (`2x`) @ `$125,000` | `400 + 400` | `0` / `0` | — | Spent in `c9136b4e...` |
| **Alice (Winner)** | Closed Long on 3rd trade @ `$125,000` (`$0` net delta) | `1,025` | **`+450`** (`250` Bob + `200` Carol) | `1,025` | **`1,475`** |
| **Bob (Loser)** | Flattened Short on 2nd trade @ `$100,000` (`$0` net delta) | `1,500` | **`-250`** | **`1,250` (`83.33%`)** | **`1,250`** |
| **Carol (MM)** | Flattened Short on 3rd trade @ `$125,000` (`$0` net delta) | `1,025` | **`-200`** | **`825` (`80.49%`)** | **`825`** |
| **CPFP Anchor** | Aggregated `3 x 330` sats | `990` | — | — | **`990`** |

Live Testnet4 mempool adversarial probes rejected 1-sat shaving of both Bob's freed collateral and Alice's routed PnL with `mempool-script-verify-flag-failed (Invalid Schnorr signature)`.

---

## 3. Full-Scale `$33,000`-Per-Leg Clearing (`$50,000 -> $55,000 -> $60,000`)

Confirmed on isolated Bitcoin Core v31.1 (`evidence/clearing_33k_core_nova_receipt.json`):

| Party | Role | Posted Margin (sats) | Net Realized PnL (sats) | Freed Collateral (sats) | Final Cleared Output (sats) |
| --- | --- | ---: | ---: | ---: | ---: |
| **Alice (Winner)** | Long `$33k` @ `$50k` (`2x`), Closed Short `$33k` @ `$60k` (`2x`) | `60,500,000` | **`+11,000,000`** | `60,500,000` | **`71,500,000`** |
| **Bob (Loser)** | Short `$33k` @ `$50k` (`1x`), Flattened Long `$33k` @ `$55k` (`2x`) | `96,000,000` | **`-6,000,000`** | **`90,000,000` (`93.75%`)** | **`90,000,000`** |
| **Carol (MM)** | Short `$33k` @ `$55k` (`1x`), Closed Long `$33k` @ `$60k` (`2x`) | `87,500,000` | **`-5,000,000`** | **`82,500,000` (`94.29%`)** | **`82,500,000`** |

---

## 4. `lnm-nova` (`nova-snark 0.76.0`) CompressedSNARK & `304B` Testnet4 BitVM3 Binding

Both 3-row `LNMBAT01` witnesses (`evidence/testnet4_live_nova_bundle/` and `evidence/clearing_33k_nova_bundle/`) were folded and compressed out-of-process by `lnm-nova` (`lnmarkets/sha256-transcript-accounting/v2`) and verified against independently derived receiver pins (`expected_pins.json`):

- **Engine:** `nova-snark 0.76.0` (`CompressedSNARK` over Pallas/Vesta with Spartan + IPA)
- **Steps Folded:** `3` (`3 x 600-byte` signed-row transcripts)
- **Augmented Circuit Size:** `275,234` primary R1CS constraints / `10,349` secondary constraints
- **Compressed Proof Size:** `12,376` bytes (`proof.bin`)
- **Pinned Verifier Key SHA-256:** `4eafbd223936cc3c1e9b16e750f1946a57cd5413f86578f6f1d37d9abb53e38b` (`101,826,448` serialized bytes)
- **304-Byte `UTXOREF_L2_SETTLEMENT_GROTH16_V0` Statement:** `network_code = 1` (`Testnet4`), `settlement_txid = journal.batch_txid`, `verifying_key_hash = 4eafbd22...e38b`.
- **Honesty Boundary:** `native_statement_verified: true`, `nova_snark_verified: true`, `bitvm3_onchain_verified: false`, `production_ready: false`.
