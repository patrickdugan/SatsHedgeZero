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
8. **Proof** (`--prove`): `dlc-batcher prove <seg dir> A R` in a background queue (clearing fold of the
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

Keys: `D:/shz/tmp/shz-batcher/testnet4-keys.json` (outside the repo): batcher
`b5392214e769b360949e8f5136305f501ada4b5c4c330c57ccf4c02cb3300fdb`, operator
`e2ece9f1549f062fac8c2e368a24938ac139ece149ce35920bc5df94d9b97793` (liquidity script
`5120add1fbcec30263debe5da4839db6008514e77218b499e5ad0bf721b6ae3be19f`,
`tb1p4hglhnkrqf3aa0ja5jpemdsqs52wwusckjv7ttgt7usmdt3mux0smkfr9p`).

1. Operator liquidity, signed by wallet `lt-dlc-batcher` and accepted by `testmempoolaccept` on the
   local Core 31.1 node (not broadcast): `f38ec18867b238b7488e4002e48b2d08a030fecbd195266720d0e3949b98d678`,
   154 vB, output 0 = 300,000 sats to the operator script, output 1 = 199,690 sats wallet change, fee 310
   (2 sat/vB). It spends `9e657f56…:1` (500,000 sats, unconfirmed incoming).
   ```
   bitcoin-cli -datadir=C:\BitcoinTestnet sendrawtransaction $(cat D:/shz/tmp/shz-batcher/testnet4/operator-funding.hex)
   ```
2. The venue runs with `--collateral-chain testnet4 --batcher-key b5392214…` (lt-mvp-accounts' flags);
   traders deposit to `account(T, B, h)` from the venue UI.
3. State:
   ```
   shz_batcher init --network testnet4 --cli C:/Users/patri/bitcoin-core-31.1/bin/bitcoin-cli.exe \
     --cli-args "-datadir=C:\BitcoinTestnet" --keys D:/shz/tmp/shz-batcher/testnet4-keys.json \
     --state D:/shz/tmp/shz-batcher/testnet4-state --venue https://shz-venue.170-75-168-145.sslip.io \
     --operator f38ec18867b238b7488e4002e48b2d08a030fecbd195266720d0e3949b98d678:0 --epoch-secs 900
   ```
4. Staged run (every settlement built, signed, `testmempoolaccept`ed, written with its
   `sendrawtransaction` command to `settlement.json`; batches stay unsettled):
   ```
   shz_batcher run <same flags> --epoch-secs 900 --oracle --attest-wait-secs 120 --sign-secs 300 \
     --refund-delta 432 --fee-rate 2 --bump-rate 5 --bump-after-blocks 3 --prove --table 4 --rows 2
   ```
5. Switch-on: the same command with `--broadcast`. Fee per settlement at 2 sat/vB: 2 accounts 477 vB
   (954 sats), 4 accounts 779 vB (1,558 sats), about 151 vB per further account; the operator change
   also fronts the pool's net for the epoch (positive when winners outweigh losers).
