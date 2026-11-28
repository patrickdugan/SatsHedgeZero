# shz-batcher: Lightninger settlement daemon

Binary `shz_batcher` (`research/lightninger_dlc_batcher/src/bin/shz_batcher.rs`). Design of the accounts,
settlement, statement and claim graph: [`docs/SHZ_DLC_BATCHER.md`](../../docs/SHZ_DLC_BATCHER.md).
Venue contract: section "Co-sign contract" below.

```
cd research/lightninger_dlc_batcher
CARGO_INCREMENTAL=0 cargo +1.99.0-x86_64-pc-windows-msvc build --release --bin shz_batcher --bin dlc-batcher
```

## What one maturity does

1. **Gate on the oracle** (`--oracle`): the maturity's event in the venue's `/api/explorer/dlc` must be
   `attested`. `unattestable*`, or no attestation `--attest-wait-secs` after maturity, skips the
   epoch: nothing settles and its batches roll into the next epoch.
2. **Collect batches**: committed batches with `seq > last_settled_seq` and `committed_us <= maturity`,
   stopping at the first batch still in flight. Aborted seqs split them into contiguous segments
   (the clearing fold chains consecutive seqs); each segment is one settlement, in order, chained in
   the mempool.
3. **Accounts**: every active account whose channel has a row in the segment, carries a net from an
   earlier non-signed segment, asked to withdraw, or is within `refund_delta / 2` blocks of its
   refund height. Each account's output is checked unspent with the state's amount and script
   (`gettxout`). Channels with no on-chain account (venue demo allocations) go to the manifest's
   `carried` list with their exact net.
4. **Package**: per account the input, the output (`roll` to `account(T, B, tip + refund_delta)`, or
   `withdraw` to the trader's signed address), `collateral + carry_in + net`, the rows, the 0x83
   sighash. Posted to `POST /api/settlement/package` (signed `X-SHZ-Batcher`), kept in
   `state.json` so a restart reuses it and signatures already given stay valid.
5. **Signatures** until all signed or `--sign-secs` passed; each verified (BIP340, 0x83) against the
   sighash the daemon computed. Non-signers drop out with no re-signing (0x83 commits to the trader's
   own input and output only); their segment net goes to `carried` and to their `carry_in`.
6. **Settlement**: inputs = signers then the operator's liquidity; outputs = payouts, `OP_RETURN SHZB
   || manifest_hash`, operator change. Batcher signs each account input (SIGHASH_DEFAULT), operator
   its input. Checked by `relation::check_settlement` and `testmempoolaccept`.
7. **Broadcast** on regtest, or testnet4 with `--broadcast`; otherwise write the staged package
   (`settlement.json`: hex, txid, `testmempoolaccept`, the `sendrawtransaction` command) and leave the
   batches unsettled. Result posted to `POST /api/settlement/result`.
8. **Proof inputs**: every settled segment writes `manifest.json`, `batches.json`, `txs.json`,
   `venue_batches.json` and a `README.md` with the exact `dlc-batcher prove` and `prove-clearing journal:`
   commands; Antigravity proves them on Colab from a clean checkout. Nothing is proved on the laptop.
   `--prove` (only on a prover host): `dlc-batcher prove <seg dir> A R` in a background queue (clearing fold of the
   segment, M17 + TapSighash bind + Secq over the settlement, the 304-byte joint statement); the
   statement SHA-256 is posted to the venue with the txid.

Every tick also checks pending settlements for confirmation and, when one has waited
`--bump-after-blocks` blocks (or `--bump-after-secs`), spends the operator's latest change in a CPFP
child at `--bump-rate` sat/vB over the whole unconfirmed ancestor package (`cpfp.json` in the
segment's receipts). `shz_batcher bump --bump-rate R` does it by hand.

## Commands

| | |
| --- | --- |
| `init --operator TXID:VOUT [--start-seq N] [--t0 UNIX]` | new state: operator liquidity (must pay `<O> CHECKSIG`), first seq to settle after, first maturity grid point |
| `run` | the daemon |
| `bump --bump-rate R` | CPFP the operator's unconfirmed change |
| `status` | print `state.json` |
| `pubkeys --keys F` | batcher and operator x-only keys |
| `traders --trader-keys F [--refuse i:n] [--withdraw i:n]` | regtest trader bots (check package against the venue's batches, sign) |
| `drill-setup --trader-keys F --channels venue_batches.json --out registry.json` | regtest: fund accounts and liquidity, write the venue registry |
| `vector` | co-sign test vector (sighash, signature, withdrawal, POST auth) |

Common flags: `--network regtest|testnet4 --venue URL --cli bitcoin-cli --cli-args "..." --state DIR
--keys FILE --receipts DIR --epoch-secs 900 --sign-secs 120 --settle-delay-secs 5 --oracle
--attest-wait-secs 120 --refund-delta N --fee-rate F --bump-rate F --bump-after-blocks N
--bump-after-secs N --broadcast --prove --table 4 --rows 2 --max-epochs N`.

The keys file (`{"batcher_sk": hex, "operator_sk": hex}`) lives outside the repo.

## Drill

`ops/shz-batcher/drill_regtest.sh`: regtest node, mock venue (`mock_venue.py`, the contract below over
replayed venue batches 306..313 under `drill_plan.json`), daemon, trader bots, a miner every 25 s.
Receipts: `research/lightninger_dlc_batcher/artifacts/epochs/regtest-drill/`.

## Co-sign contract (venue side)

The venue hosts; the daemon is a client. Daemon POSTs carry `X-SHZ-Batcher` = BIP340 by the batcher
key over `tagged_hash("SHZ/BATCHER/POST/V1", body)`.

| Endpoint | Who | Body / response |
| --- | --- | --- |
| `GET /api/explorer/accounts` | daemon | kind `utxo` entries carry `account: {refund_height, spk, collateral_sats, funding?: {txid, vout}}`; `outpoint` is the venue channel |
| `GET /api/explorer/batches?limit=500` | daemon | `seq, phase, committed_us, clearing, accounts` |
| `GET /api/explorer/dlc` | daemon | oracle events with `maturity_unix`, `status` |
| `POST /api/settlement/package` | daemon | the package (see `package.json` in any receipt) |
| `GET /api/settlement/package?owner=T` | trader | `{epoch, segment, deadline_us, tx, account}` |
| `POST /api/settlement/signature` | trader | `{epoch, segment, owner, sig}`, 65 bytes ending `83`; 400 bad sig, 409 past deadline |
| `GET /api/settlement/signatures?epoch=E&segment=k` | daemon | `{signatures: [{owner, sig, received_us}]}` |
| `POST /api/settlement/result` | daemon | `{epoch, segment, status, txid, manifest_hash, statement_sha256, payouts, rolled, ...}` |
| `GET /api/explorer/settlements` | anyone | results, newest first |
| `POST /api/settlement/withdraw` | trader | `{owner, spk, time_us, sig}`, sig over `tagged_hash("SHZ/WITHDRAW/V1", owner ‖ u32le len ‖ spk ‖ u64le time_us)` |
| `GET /api/settlement/withdrawals` | daemon | pending requests |

What the trader signs: BIP341 tapscript sighash with hash type 0x83 over its own input (outpoint,
amount, account script, sequence), its own output, `tx.version`, `tx.locktime`, the settle leaf hash,
key version 0, codesep `0xffffffff`. `shz_batcher vector` prints a worked example.

## testnet4 switch-on

The testnet4 stack runs on the witness box from lt-mvp-accounts' `~/shz-staging/staging_box.sh`
(`ops/mvp-drill/staging_box.sh`): `shz-venue --collateral-chain testnet4` on port 8099 against the box's
pruned node, and this daemon with keys generated there (`~/shz-staging-testnet4/batcher-keys.json`):
batcher `0d947ae42a0f6b841acf8af9375bc6f1e71cf298c87842ec684da7a5944ea806`, operator
`c8dfbe622417e3285e046563da12376259240682356fa1979f999128365407af` (liquidity script
`5120a2716d2e2d2c3a7f4bb97baecf2266c4a714a4cb7632044882774153ef3b54df`,
`tb1p5fck6t3d9sa87jae0whv7gnxcjn3ffxtwceqgjyzwaq48mem2n0scmtdyn`). The daemon there runs 900 s epochs,
180 s signing, refund delta 432, and stages every settlement until `BROADCAST=1`.

1. Operator liquidity, signed by wallet `lt-dlc-batcher` on the laptop's Core 31.1 node and accepted by
   `testmempoolaccept` (not broadcast): `9c3f2827721887febbad2deb24cbd9cc11166df87cab3b67a3a32b318f48d79d`,
   154 vB, output 0 = 300,000 sats to the operator script, output 1 = 199,690 sats wallet change, fee 310
   (2 sat/vB), spending `9e657f56…:1` (500,000 sats, confirmed).
   ```
   bitcoin-cli -datadir=C:\BitcoinTestnet sendrawtransaction $(cat D:/shz/tmp/shz-batcher/testnet4/operator-funding-box.hex)
   ```
2. Staged daemon (settlements built, signed, `testmempoolaccept`ed, written with their
   `sendrawtransaction` command; nothing broadcast):
   ```
   ssh tradelayer-witness 'NET=testnet4 OPERATOR=9c3f2827721887febbad2deb24cbd9cc11166df87cab3b67a3a32b318f48d79d:0 ~/shz-staging/staging_box.sh start'
   ```
3. Switch-on (the daemon broadcasts its settlements and CPFP children):
   ```
   ssh tradelayer-witness 'NET=testnet4 ~/shz-staging/staging_box.sh stop; NET=testnet4 BROADCAST=1 OPERATOR=9c3f2827721887febbad2deb24cbd9cc11166df87cab3b67a3a32b318f48d79d:0 ~/shz-staging/staging_box.sh start'
   ```
   Fee per settlement at the box script's `--fee-rate 1`: 2 accounts 477 vB (477 sats), 4 accounts
   779 vB (779 sats), about 151 vB per further account; CPFP to 5 sat/vB after 3 blocks
   unconfirmed. The operator change also fronts the pool's net for the epoch.

Switched on 2026-11-27: operator liquidity `9c3f2827…:0` broadcast from the laptop node and confirmed
at 21:57Z; the box daemon runs with `BROADCAST=1` since 21:59Z (`last settled seq 0`). The testnet4
venue is public over HTTPS at https://lightninger-testnet4.170-75-168-145.sslip.io/ (Caddy site added
on the box, proxying 127.0.0.1:8099). Settlements start with the first confirmed deposit.
