# Lightninger MVP drill and staging

The venue side of the MVP ([`docs/SHZ_MVP_COLLATERAL.md`](../../docs/SHZ_MVP_COLLATERAL.md)) against
the settlement daemon `shz_batcher` ([`ops/shz-batcher/README.md`](../shz-batcher/README.md)).

| File | |
| --- | --- |
| `client.mjs` | three browser-less traders: deposit to their collateral addresses, activate, trade round trips, review and sign every settlement entry with `ui/venue/settle.js` (the browser's code), withdraw |
| `drill_regtest.sh` | regtest node + `shz-venue --collateral-chain regtest` (live FROST marks from the relay) + `shz_batcher run` (60 s epochs) + miner + `client.mjs`; receipt in `receipt-regtest/` |
| `staging_box.sh` | the same stack on the witness box beside the live units: `NET=regtest` on port 8098, `NET=testnet4` (read-only venue on the box's pruned node) on port 8099 |

## Regtest drill receipt (`receipt-regtest/`, 2026-11-27 18:24-18:27 UTC)

Venue b3105fc + this commit, daemon `shz_batcher` from `research/lightninger_dlc_batcher` (60 s
epochs, 25 s signing window), Bitcoin Core 31.1 regtest, marks from the live FROST relay.

| Step | Result |
| --- | --- |
| Deposits | three traders, 200,000 sats each to `account(T, B, 171)`; the venue watcher saw each at 1 confirmation; owners signed `collateral` registrations (label `regtest collateral`, channel = deposit outpoint) |
| Trades | trader 0 short / trader 1 long $200 at 10x, closed $300 higher (batches 1-2): trader 0 −1,669, trader 1 +1,669 realized |
| Epoch `SHZ-BTCUSD-20261127T1826Z` | settlement `edce3696…17d7`, both traders signed their entries (0x83, sighash recomputed by `settle.js` and the venue); the venue rolled trader 0 to `edce3696…:1` 198,331 sats and trader 1 to `:0` 201,669 sats, refund height 173, at 1 confirmation |
| Withdrawal | trader 0 (flat) signed a withdrawal to a fresh wallet address; the router debited its 198,331 free sats; its next order was refused (`a withdrawal is pending`) |
| Trades | trader 2 long / trader 1 short $200, closed $300 lower (batches 3-4): trader 1 +1,688, trader 2 −1,688 |
| Epoch `SHZ-BTCUSD-20261127T1827Z` | settlement `4bab58b8…828b`, 3 signers, 628 vB, mined at 145: trader 0's 198,331 sats to its address (`4bab58b8…:1`, seen by `scantxoutset`), trader 1 rolled to 203,357, trader 2 to 198,312; the venue closed trader 0's account (`withdrawn in full by 4bab58b8…`) |

What the drill found in the daemon (reported to its session): a withdrawal requested after an
account's last trade waits for the next segment of new batches, because the daemon builds
settlements only from segments; the drill keeps trader 1 and 2 trading so the next epoch has one.

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
