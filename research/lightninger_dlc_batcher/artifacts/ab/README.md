# A/B: script-leaf (A) vs MuSig2 key-path (B) DLC batch

Built by `tests/ab.rs` from the same venue batches (306..313) and the same oracle event
(`SHZ-BTCUSD-20261127T1345Z`, attested $61,346, CET 527 of the single-trade demo; its anticipation
point and attestation scalar complete every adaptor signature). The table is in
[`docs/SHZ_DLC_BATCHER.md`](../../../../docs/SHZ_DLC_BATCHER.md) section 9.

| File | Content |
| --- | --- |
| `A/`, `B/` | prover inputs per variant, with the Colab commands (`README.md`) |
| `regtest_receipt.json` | regtest run: one funding for both variants, sizes, signing times, Core verdicts, everything mined at 112 |
| `testnet4_receipt.json` | testnet4 run from wallet `lt-dlc-batcher`: signed, package `testmempoolaccept`, **not broadcast** |

## Testnet4 (not broadcast)

Checked at tip 163,684 against wallet `lt-dlc-batcher`'s coin `9e657f56…abb7:1` (500,000 sats, unconfirmed
at the time). Every package below was accepted by `testmempoolaccept` as `[funding, tx]`.

| Transaction | txid | vB |
| --- | --- | ---: |
| funding (both variants: 2 × 8 accounts × 1,000, 2 × liquidity 2,000, 2 × CET funding 3,254) | `142e6f5b06708087415c20f4cc1091e4a21eefb370d00cc67de31bbddff82d57` | 971 |
| A settlement (9 inputs, script leaf) | `af10ba81adb00d14d2184fcc7076a6d8be47d36586ce9b0e3c182c7d1d22addb` | 1,382 |
| B settlement (9 inputs, MuSig2 key path) | `060fa6391e337aaac7bee68d1e58fec1ceaf9c273894efb52865c5a654754811` | 964 |
| A CET (CET 527, 2-of-2 script leaf) | `16c9f34c39e6fdec5616db7b4b3569cba2c0f6ba446b112bdf8ca42775daaaa5` | 247 |
| B CET (CET 527, MuSig2 key path) | `abf0238ffaf189bc361b80f88b799be53c63f54f41ff8a5d47f7484945fc8b4c` | 197 |

Both tampered settlements (account 3 paid one sat less) were refused (`Invalid Schnorr signature`) and
both account-0 refunds were `non-final`. The funding spends `lt-dlc-batcher`'s coin, so it needs that
coin's parent (`9e657f56…`) confirmed or in the mempool.

Broadcast, funding first (each later transaction spends a different funding output, so any subset works):

```powershell
$cli = "C:\Users\patri\bitcoin-core-31.1\bin\bitcoin-cli.exe"; $r = Get-Content D:\shz\SatsHedgeZero\research\lightninger_dlc_batcher\artifacts\ab\testnet4_receipt.json -Raw | ConvertFrom-Json
& $cli -datadir=C:\BitcoinTestnet sendrawtransaction $r.funding.hex
& $cli -datadir=C:\BitcoinTestnet sendrawtransaction $r.A.settlement.hex
& $cli -datadir=C:\BitcoinTestnet sendrawtransaction $r.B.settlement.hex
& $cli -datadir=C:\BitcoinTestnet sendrawtransaction $r.A.cet.hex
& $cli -datadir=C:\BitcoinTestnet sendrawtransaction $r.B.cet.hex
```

Amounts: the funding locks 26,508 sats from the wallet coin (fee 972, the rest back to the wallet as change); after both settlements each
trader holds 1,000 + net (972, 1,028, 964, 1,036, 920, 1,080, 920, 1,080) twice; the CETs pay Bob
1,629 and Alice 995 plus a 330-sat anchor each.
