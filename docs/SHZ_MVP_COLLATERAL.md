# Lightninger MVP: on-chain collateral accounts on the venue

`shz-venue --collateral-chain regtest|testnet4` replaces `TESTNET DEMO CREDIT` with real collateral.
A trader deposits to a Taproot collateral account, trades on the venue, co-signs each epoch's
settlement in the browser, and withdraws. The settlement daemon is `shz_batcher`
([`ops/shz-batcher/README.md`](../ops/shz-batcher/README.md)); the account script, settlement
and statement are [`docs/SHZ_DLC_BATCHER.md`](SHZ_DLC_BATCHER.md). Code:
[`crates/shz-venue/src/core/collateral.rs`](../crates/shz-venue/src/core/collateral.rs),
[`ui/venue/settle.js`](../ui/venue/settle.js), [`ui/venue/collateral.js`](../ui/venue/collateral.js).

## Flags

```
shz-venue --collateral-chain regtest|testnet4 --bitcoind-rpc http://127.0.0.1:PORT
          --bitcoind-auth-file FILE --batcher-key <B x-only hex>
          [--refund-blocks 432] [--min-conf 1] [--min-lock refund-blocks/2] [--chain-poll-ms 15000]
```

`--bitcoind-auth-file` holds `user:password` (a bitcoind `.cookie` works as is). The watcher uses
`getblockcount`, `scantxoutset` and `gettxout` only, so a pruned node without a wallet or txindex
serves it. Demo registration is refused while the flag is on.

## Account lifecycle

1. **Deposit address.** `POST /api/collateral/address {owner}` issues `account(T, B, h)` with
   `T` = the owner key, `B` = `--batcher-key`, `h` = tip + `--refund-blocks` (journaled `coll_addr`;
   reissued with a later `h` if it goes stale unfunded). The UI shows the address, a QR code, `h`, and
   the last height a deposit is credited at (`h - --min-lock`).
2. **Credit.** The watcher scans issued addresses with `scantxoutset` every new block. At
   `--min-conf` confirmations the owner signs a registration (`/api/register/draft {kind:
   "collateral"}`, then `/api/register`); the venue takes the outpoint and value from its own scan, not
   from the client. The router allocation is the deposit value, the venue channel is the deposit
   outpoint (it never changes; clearing rows reference it), the label is `regtest collateral` /
   `testnet4 collateral` (journaled `coll_deposit`). `kind: "utxo"` with `refund_height` registers an
   outpoint the daemon funded, after `gettxout` on the venue's node shows it pays `account(T, B, h)`.
3. **Trade.** Unchanged: intents, batch approvals, V3 lane acks. Every committed batch's clearing row
   carries the account's `net`.
4. **Settle.** At each maturity the daemon posts one package per contiguous segment of committed
   batches (`POST /api/settlement/package`, signed `X-SHZ-Batcher`). The venue checks every entry
   against its own records before anyone sees it:
   - the input is the account's current collateral output (or the roll output of an earlier open
     package of the same owner), with the account's value and `account(T, B, h)` script and settle leaf;
   - the output pays exactly `collateral + sum of the account's clearing-row net` since its last applied
     settlement (the daemon's `collateral + carry_in + net` must agree);
   - a `roll` output pays `account(T, B, h')` with `tip + 6 < h' <= tip + 2*refund_blocks + 144`, a
     `withdraw` output pays the address in the owner's signed withdrawal;
   - the sighash type is `SINGLE|ANYONECANPAY` and the sighash recomputes.
5. **Co-sign.** The browser fetches `GET /api/settlement/package?owner=T`, rebuilds the account
   scripts from its key, checks input, output and `input + carry + net = output`, computes the 0x83
   sighash itself (`settle.js reviewEntry`), shows collateral in, net, the batches, where the output
   goes and the new refund height, and signs on a click (`POST /api/settlement/signature`). The daemon
   drops accounts that did not sign by the deadline; their net carries to the next settlement.
6. **Confirm.** `POST /api/settlement/result` closes the package. Each payout is applied only when
   `gettxout` shows it at `--min-conf` (journaled `coll_settled`): a roll moves the account to the new
   outpoint, value and refund height; a withdrawal closes the account.
7. **Withdraw.** `POST /api/settlement/withdraw {owner, spk|address, time_us, sig}` (BIP340 over
   `tagged_hash("SHZ/WITHDRAW/V1", owner || u32le len || spk || u64le time_us)`). The account must be
   flat with no resting orders; its free balance leaves the router at once (journaled
   `CollateralTransfer`) and new orders are refused. The next settlement pays the whole account to
   the address.
8. **Refund.** At height `h` the owner alone spends the collateral output through the refund leaf
   (shown with its control block in the Collateral tab). The watcher sees the output spent outside a
   settlement and closes the account.

Agents with a grant cannot sign settlements or withdrawals: both verify against the owner key, and
neither is in the agent API's pending-signature set.

## Endpoints

| Endpoint | Who | |
| --- | --- | --- |
| `POST /api/collateral/address` | trader | issue / return the deposit address |
| `GET /api/collateral/<owner>` | trader | address, seen deposit and confirmations, account (outpoint, value, refund leaf), withdrawal, open packages, payouts confirming |
| `GET /api/explorer/accounts` | daemon | `account: {refund_height, spk, collateral_sats, outpoint, funding}` on collateral accounts |
| `POST /api/settlement/package` | daemon | per-account entries, checked as above |
| `GET /api/settlement/package?owner=T` | trader | that owner's entry plus the venue's `net`, `batches`, `sighash` |
| `POST /api/settlement/signature` | trader | 65 bytes ending `83`; 400 bad signature, 409 past deadline |
| `GET /api/settlement/signatures?epoch=&segment=` | daemon | collected signatures |
| `POST /api/settlement/result` | daemon | closes the package; payouts await confirmation |
| `GET /api/explorer/settlements` | anyone | results, newest first |
| `POST /api/settlement/withdraw`, `GET /api/settlement/withdrawals` | trader, daemon | withdrawal requests |
| `GET /api/settlement/epoch`, `GET /api/settlement/open` | anyone | each account's value and net since its last settlement; open packages |

## Not built

- Open positions at maturity settle as realized `net` only; per-outcome adaptor signatures (one 0x83
  signature per CET outcome) are in `docs/SHZ_DLC_BATCHER.md` section 8.
- Fees stay on the venue's fee ledger; the settlement moves clearing `net` only.
- Partial withdrawals: 0x83 covers one output per account, so a withdrawal pays the whole account.
- Options and spot under `--collateral-chain`: their batches are not in the settlement net.
