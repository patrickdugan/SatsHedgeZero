# Lightninger MVP drill and staging

The venue side of the MVP ([`docs/SHZ_MVP_COLLATERAL.md`](../../docs/SHZ_MVP_COLLATERAL.md)) against
the settlement daemon `shz_batcher` ([`ops/shz-batcher/README.md`](../shz-batcher/README.md)).

| File | |
| --- | --- |
| `client.mjs` | three browser-less traders over three epochs: deposit, activate, trade, review and sign every settlement entry with `ui/venue/settle.js` (the browser's code), leave one package unsigned (`--refuse 2:1`), withdraw, wait for statements |
| `drill_regtest.sh` | regtest node + `shz-venue --collateral-chain regtest` (live FROST marks from the relay) + `shz_batcher run` (60 s epochs; segment prover inputs written for Colab, no local proving) + miner + `client.mjs`; receipt in `receipt-regtest/` |
| `staging_box.sh` | the same stack on the witness box beside the live units: `NET=regtest` on port 8098, `NET=testnet4` (read-only venue on the box's pruned node) on port 8099 |

## Regtest drill receipt (`receipt-regtest/`, 2026-11-27 18:45-18:54 UTC)

Venue at this commit, daemon `shz_batcher` 02a861b (60 s epochs, 25 s signing window, `--prove
--table 4 --rows 2`), Bitcoin Core 31.1 regtest, marks from the live FROST relay. Traders 0, 1, 2
deposited 200,000 sats each to `account(T, B, 171)`; the venue credited each at 1 confirmation and
the owners signed `collateral` registrations. $200 round trips at 10x, closed $300 away.

| Epoch | Trades | Settlement | Result |
| --- | --- | --- | --- |
| `1847Z` | A: 0 vs 1, batches 1-2 (0: −1,672, 1: +1,672) | `8f090e36…2141`, 2 signers | rolled to 198,328 / 201,672; statement `3ae60cf9…d467` (171 s) |
| `1848Z` | B: 2 vs 1, batches 3-4 (1: +1,687, 2: −1,687) | `d43bc6f8…e930`, 1 signer; trader 2 left its package unsigned and was dropped (`rolled`), fronted 1,687 | trader 1 rolled to 203,359; trader 2 untouched; statement `eb4744a8…522e` (186 s) |
| `1849Z` | none | `6a36da39…86fd`, 2 signers (no-batch settlement: trader 2's carried net, trader 0 near its refund height) | trader 2 rolled to 198,313 (−1,687 carried), trader 0 to 198,328; no proof queued by the daemon |
| `1850Z` | C: 0 vs 2, batches 5-6 (0: −1,687, 2: +1,687); then trader 0 asked to withdraw, and its next order was refused | `66e40421…195f`, 3 signers, mined at 165 | trader 0 paid 196,641 sats to its address (`66e40421…:1`, = 200,000 + realized), account closed; trader 2 rolled to 200,000 (= 200,000 + realized); trader 1 refreshed; statement `df9c98e7…3f72` (232 s) |

Every signature was over a sighash the client computed itself with `ui/venue/settle.js` and the
venue recomputed before accepting the package. The client's checks (`check`, `chain-withdrawal`
steps) compare each account's on-chain value with its realized PnL: both hold. The daemon queued
no proof for the carry-only settlement of `1849Z`; the client was stopped after the three other
statements arrived, and `venue_settlements.json` was rebuilt from the venue's journal.

## First testnet4 epoch (`receipt-testnet4/`, 2026-11-28 03:10-04:34 local, `testnet4_epoch.mjs`)

Venue https://lightninger-testnet4.170-75-168-145.sslip.io/ (box port 8099, `--collateral-chain
testnet4`), daemon `shz_batcher` a1e3619 with `BROADCAST=1` and operator liquidity `9c3f2827…:0`.

| Step | Result |
| --- | --- |
| Deposit | `8f9ce3863d474d998008edd66224c28b565e916cddefb83dc48cf7e35920fcb9`: 50,000 sats to each trader's `account(T, B, 164164)` (outputs 0 and 1), mined at 163,743; both addresses recomputed locally before funding; credited and activated at 4 confirmations |
| Fill | $100 at 10x: trader 0 short at 59,941 (batch 1), closed at 59,991 (batch 2); realized −139 / +139 sats |
| Settlement | epoch `SHZ-BTCUSD-20261128T0315Z`, both traders signed their 0x83 entries (sighash recomputed by `settle.js` and the venue); `84c2f2f8cc521fa8ade0e9fb9366d54f41cfb1bf24b50f41e476c7e38c610664`, 477 vB, fee 477, mined at 163,750 |
| Payouts | trader 0 `84c2f2f8…:1` 49,861 = 50,000 − 139; trader 1 `84c2f2f8…:0` 50,139 = 50,000 + 139; both read back from mempool.space testnet4; refund height 164,179 |
| Statement | prover inputs in `research/lightninger_dlc_batcher/artifacts/epochs/testnet4/SHZ-BTCUSD-20261128T0315Z/seg0/`, proved on Colab (no local proof) |

## Staging on the witness box

`~/shz-staging` holds `bin/shz-venue` and `bin/shz_batcher` (built in WSL Ubuntu 24.04 from this
tree), `ui/` (copy of `ui/venue`) and `staging_box.sh`.

```
ssh tradelayer-witness '~/shz-staging/staging_box.sh status'                       # regtest staging, http://170.75.168.145:8098
ssh tradelayer-witness '~/shz-staging/staging_box.sh faucet <bcrt1 address> 0.003' # regtest coins for a deposit
ssh tradelayer-witness 'NET=testnet4 ~/shz-staging/staging_box.sh status'          # testnet4 staging, http://170.75.168.145:8099
```

The testnet4 instance starts read-only: deposits are watched and credited, but its daemon waits
for an operator liquidity output (`OPERATOR=<txid:vout>`), and broadcasts settlements only with
`BROADCAST=1` (otherwise it stages each one after `testmempoolaccept`).
