# Testnet4 demo: one venue fill, one DLC, real co-signs (not broadcast)

Prover inputs for the Lightninger testnet4 demo. Every transaction here passed Bitcoin Core 31.1
`testmempoolaccept` on testnet4 (local node and the witness host's pruned node, tip 163,663) and
none is broadcast yet.

| File | Content |
| --- | --- |
| `venue_fill.json` | The live venue fill and the batch that committed it: fill `6f469f5c…32b9`, $1 at $61,464, Alice long 1x (maker) vs Bob short 1x (taker), 1,627 sats margin each, **batch 301** (`committed`, layer `None`), both approvals and channel acks signed by the owners. Also the venue clearing summary before and after (`cash` 1,000,114, `fund` 1,000,002, `book` 112, `identity` 0) and batch 300. `name` = `testnet4_batch301`. |
| `txs.json` | `funding`, `cet`, `refund` in the `core_sighash_txs.json` shape: `signed_hex`, prevout `amounts` and `spks`, one slot per signature. Funding: 5 key-path slots (`script_path: null`). CET and refund: 2 tapscript slots each, pk0's signature first, `script_path {key, tapleaf, codesep: 4294967295}`. |
| `oracle_event.json` | Event `SHZ-BTCUSD-20261127T1345Z` as served by the FROST relay (`/v1/dlc/event/<id>`, announcement + threshold signature + attestation), attested price **$61,346**, matching CET 527 (prefix length 13), and the attestation scalar for that prefix. |
| `cets.json` | All 1,022 compressed CETs (full 20-bit outcome domain, max error 2 sats): price range, prefix, anticipation point, payouts, and the three adaptor signatures each (Alice and Bob on the unilateral CET, Bob's 0x83 route signature). |
| `receipt.json` | Heights, keys, amounts, fees and both `testmempoolaccept` results. |
| `joint_statement.json` | `prove-cet` output: M17 folds of all 7 inputs, bind-mode TapSighash and Secq folds of all 9 signatures, the binding check with its negative cases, the batch-301 clearing fold, and the 304-byte statement over all of them. |

## The contract

- Funding `e6bbb87d249d1f57f622038833ff34e4cebef549de54e1403762d9f8fa02700e:0`, 3,254 sats (= 1,627 + 1,627) to
  `tb1ptfwrch2xa5har2dkxlc4stta0cnlsug5udlafc3sewc3ehcxpjhs3faj2s`, from every UTXO of wallet `bitvm-arena-staging`
  (5 P2TR inputs, 3,741 sats), 341 vB, fee 487 sats (1.43 sat/vB), no change. The inputs are locked
  persistently in that wallet.
- Output: MNR-02 tree under the UTXORef NUMS internal key: route leaf (Alice, router guard, Bob), unilateral CET
  leaf `163662 CLTV DROP <pk0> CHECKSIGVERIFY <pk1> CHECKSIG`, refund leaf at CLTV 164093. Alice and Bob's keys
  are their venue owner keys (`c6d83916…a105`, `14ca6dec…47de`).
- CET `cac6a1a58bf8ee7562411deb4755baf6182fc7a24e6e46f6a0e60ee5bca29a3f` (257 vB, fee 300 sats, nLockTime 163662):
  Bob (short) 1,629, Alice (long) 995, CPFP anchor 330. `payout_at_price(61346)` is short 1,630 / long 1,624;
  Alice pays the CET fee and anchor (995 + 300 + 330 = 1,625).
- Refund `6e303661dcb86b6db1c34cc01d7baf95b50d3eb9678350189e4d38610785d401`: pre-signed, `non-final` until height 164093.
- The CET spends a script leaf: shz-dlc has no MuSig2 adaptor signatures, so a 2-of-2 key-path CET is not available.

## Reproduce

```
node ops/venue-bench/dlc_demo/fill.mjs --keys <keys.json> --out venue_fill.json
shz dlc-testnet4-demo originate --keys <keys.json> --fill venue_fill.json --event <announced event json> --wallet bitvm-arena-staging --state state.json
shz dlc-testnet4-demo settle --keys <keys.json> --fill venue_fill.json --state state.json --event <attested event json> --out research/lightninger_bitvm3_clearing/artifacts/testnet4_demo
lightninger-bitvm3-clearing prove-clearing journal:artifacts/testnet4_demo/venue_fill.json 1 4 2
lightninger-bitvm3-clearing prove-tapsighash testnet4:cet      # also testnet4:refund, testnet4:funding
lightninger-bitvm3-clearing prove-cet journal:artifacts/testnet4_demo/venue_fill.json 1 4 2 testnet4_demo/txs.json
```

`bitcoin-cli` for `shz` comes from `SHZ_BITCOIN_CLI_DIRECT=1`, `SHZ_WSL_BITCOIN_CLI=<bitcoin-cli.exe>`,
`SHZ_WSL_BITCOIN_DATADIR=C:\BitcoinTestnet`. The keys file stays outside the repo. Signing is deterministic, so
`settle` rebuilds the package and checks it against the CET digest recorded at origination.

## Local proofs on these inputs (release build, this host)

| Command | Primary constraints | Wall time | Receipt |
| --- | ---: | ---: | --- |
| `prove-clearing journal:artifacts/testnet4_demo/venue_fill.json 1 4 2` | 297,967 | 51 s | `../clearing_journal_testnet4_batch301_k1_A4_R2.json` |
| `prove-tapsighash testnet4:cet` (bind mode, 2 tapscript signatures) | 650,982 | 105 s | `../tapsighash_testnet4_cet.json` |
| `prove-tapsighash testnet4:refund` (bind mode, 2 tapscript signatures) | 650,982 | 122 s | `../tapsighash_testnet4_refund.json` |
| `prove-tapsighash testnet4:funding` (5 key-path signatures) | 633,300 | 143 s | `../tapsighash_testnet4_funding.json` |

Each TapSighash run also folds the same signatures through the MNR-05 Secq256k1 BIP-340 step and checks both end in the same accumulator.

## Settlement binding

Both statements below are `UtxoRefL2SettlementStatementV0` on testnet4 (`network_code` 1,
`chain_genesis_hash` = the testnet4 genesis `00000000da84…f043`) and name the CET as
`settlement_txid = cac6a1a58bf8ee7562411deb4755baf6182fc7a24e6e46f6a0e60ee5bca29a3f`, the
transaction `prove-tapsighash testnet4:cet` proves the signatures of. `prove-clearing journal:<path>`
takes it from label `cet` of `txs.json` beside the journal (or `--settlement-txid=<hex>` as the
sixth argument).

- **Clearing statement** (`prove-clearing journal:artifacts/testnet4_demo/venue_fill.json 1 4 2`,
  `../clearing_journal_testnet4_batch301_k1_A4_R2.json`): batch 301 cleared from the venue state,
  `commitment_hash` = the clearing fold's `z_K`, `contract_id = SHA256("lightninger/venue/testnet4")`.
  Statement SHA-256 `5e64f54fffedbd024b1c56615db5fc9699e9819d262cbddfaa6c4697d7768e60`.
- **Joint statement** (`prove-cet journal:artifacts/testnet4_demo/venue_fill.json 1 4 2 testnet4_demo/txs.json`,
  `joint_statement.json`, the binding of commit 7b792af on these inputs): `commitment_hash` covers,
  per transaction, every M17 input fold's `z_0`/`z_K`, the bind-mode TapSighash and Secq folds'
  `z_K`, and the clearing fold's `z_0`/`z_K`; `contract_id = SHA256("LIGHTNINGER/DLC/CONTRACT/V1" ‖
  funding outpoint)` (the outpoint the CET spends, `e6bbb87d…700e:0`).
  Statement SHA-256 `e0f5be99e7c0415b1497556c32a357634e38e81fad8229346e6a860747599d66`.

| Transaction | M17 (inputs, steps) | Signatures | TapSighash bind (constraints, compress) | Secq compress | Binding |
| --- | ---: | ---: | --- | ---: | --- |
| funding `e6bbb87d…` | 5, 85 | 5 key path | 762,348, 52.1 s | 19.4 s | verified; 6 altered bindings rejected |
| CET `cac6a1a5…` | 1, 23 (CLTV claim checked natively) | 2 tapscript | 650,982, 54.9 s | 19.8 s | verified; 6 altered bindings rejected |
| refund `6e303661…` | 1, 23 | 2 tapscript | 650,982, 54.0 s | 15.8 s | verified; 6 altered bindings rejected |

Clearing fold in the joint run: 297,967 constraints, compressed in 27.1 s. One run, 355 s,
2,064 MiB peak. The M17 runs use Core's standard Taproot flags (`m17_flags` 0x1105b in `txs.json`:
P2SH, DERSIG, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, NULLDUMMY, TAPROOT).

## Broadcast (funding first, CET after the funding confirms)

```powershell
$cli = "C:\Users\patri\bitcoin-core-31.1\bin\bitcoin-cli.exe"; $t = Get-Content D:\shz\SatsHedgeZero\research\lightninger_bitvm3_clearing\artifacts\testnet4_demo\txs.json -Raw | ConvertFrom-Json
& $cli -datadir=C:\BitcoinTestnet sendrawtransaction ($t | Where-Object label -eq funding).signed_hex
& $cli -datadir=C:\BitcoinTestnet sendrawtransaction ($t | Where-Object label -eq cet).signed_hex
```
