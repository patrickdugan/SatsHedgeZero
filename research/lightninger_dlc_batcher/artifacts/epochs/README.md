# Settlement daemon receipts

One directory per daemon run, one `<event>/seg<k>/` per settled segment (`README.md` inside each has the
re-prove commands). Daemon: `src/bin/shz_batcher.rs`; ops: [`ops/shz-batcher`](../../../../ops/shz-batcher).

## `regtest-drill/` — laptop, Bitcoin Core 31.1 regtest, mock venue, 90 s epochs, prover on

`ops/shz-batcher/drill_regtest.sh`: venue batches 306..313 replayed under `ops/shz-batcher/drill_plan.json`
(seq 6 aborted, epoch 18:00:00Z unattestable), eight accounts of 20,000 sats, operator liquidity 200,000,
fee rate 1 sat/vB, CPFP to 5 sat/vB after 6 s unconfirmed, sign window 20 s. `summary.json` collects
every segment.

| Epoch | Segment | Batches | Settlement | Signed | Not signed (carried) | Statement SHA-256 | Prove |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 17:57:00Z | 0 | 1..3 | `2c2264f5…` | 4 | — | `05c7a3fc86e186dd42240d6a3f89dc2c974fb49abc61118d72d6d0a312a74e4d` | 975 s |
| 17:58:30Z | 0 | 4..5 | `b79dd541…` | 3 | trader 2 (−36, drill non-signer) | `728c8f9f292836c03402648fb29a5912482b837af698b15c47378bc151aa7eca` | 232 s |
| 17:58:30Z | 1 | 7..8 | `eaf7f147…` | 3 (trader 2 pays its −36 carry) | trader 5 (+80, signed 1.4 s after the deadline, venue 409) | `df9b4962569c9d6613ecb3793abc23a1007aafdcd149278812db02adc9ca132e` | 290 s |
| 18:00:00Z | — | — | not settled: oracle `unattestable_no_valid_packet`, seq 9 rolls forward | | | | |
| 18:01:30Z | 0 | 9..9 | `237f9f24…` | 3 (trader 5 withdraws 20,080 = 20,000 + carried 80) | — | `8d71b1d985cec242156fbda1ddc0a1dbf985195baa37a63169e57a9fc4ff26b0` | 336 s |

Every settlement passed `relation::check_settlement` and `testmempoolaccept`, was broadcast and mined;
epoch 17:57:00Z's was CPFP'd (`cpfp.json`). Each statement comes from `dlc-batcher prove`: clearing fold
of the segment (table 4, 2 rows), M17 per input, TapSighash bind + Secq over every signature, binding
and relation negatives (including a carried net stated 1 sat off), the 304-byte joint statement.

## `staging-box/` — witness box, `shz-batcher@staging` systemd unit, own regtest node, mock venue, 120 s epochs, prover off

`ops/shz-batcher/staging_box.sh`: same plan, trader and daemon keys generated on the box, venue on
127.0.0.1:8197 (the live venue units untouched). The unit was restarted 13 s into epoch 17:56Z's sign
window: it resumed the posted package with its original deadline and settled it (`daemon.log`,
"resuming the posted package").

| Epoch | Segment | Batches | Settlement | Signed | Rolled |
| --- | --- | --- | --- | --- | --- |
| 17:54Z | 0 | 1..3 | `ce2c99d7…` | 4 | — |
| 17:56Z | 0 | 4..5 | `a100ff68…` | 3 | trader 2 (−36) |
| 17:56Z | 1 | 7..8 | `740e3771…` | 4 (trader 2 pays its −36 carry) | — |
| 17:58Z | — | — | unattestable, rolled | | |
| 18:00Z | 0 | 9..9 | `419e8e5b…` | 3 (trader 5 withdraws 20,080) | — |

## `regtest-staged/` — the testnet4 no-broadcast path on regtest (`--stage`)

Settlements built, signed and `testmempoolaccept`ed, written with their `sendrawtransaction` command;
nothing broadcast and the batches stay unsettled, so each later epoch re-settles from the same seq.

## `regtest-batchless/` — epochs with no new batches (`drill_plan_batchless.json`)

One epoch of batches (306, 307, 310) where trader 0 leaves its package unsigned (−28 carried) and trader 3
asks to withdraw, then epochs with no batches.

| Epoch | Batches | Settlement | Paid |
| --- | --- | --- | --- |
| 18:48:00Z | 1..3 | `867d5912…` | 3 signers; trader 0 rolled (−28 carried) |
| 18:49:30Z | none | `e146f2a3…` | trader 0 rolled to 19,972 (carry −28); trader 3 withdrew 20,036 |
| 18:51:00Z | none | — | nothing to settle |
