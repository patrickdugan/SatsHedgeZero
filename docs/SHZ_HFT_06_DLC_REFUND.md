# SHZ-HFT-06: unattested DLC events resolve by refund

A contract bound to a threshold-oracle DLC event (FROST 3-of-5, BIP340, 20 binary digits) settles one of two ways on Bitcoin:

1. **Attested.** The oracle publishes the digit signatures at maturity. The sum of the signature scalars over the matching CET's digit prefix is the discrete log of that CET's anticipation point, so it completes the adaptor signatures of exactly that CET. The unilateral CET leaf (or the Bob-offline route leaf) then spends the funding output.
2. **Unattested.** The oracle publishes nothing. No CET can be completed, and the refund leaf of the MNR-02 taproot tree becomes spendable at its CLTV height.

## How the refund works

The MNR-02 funding output has a refund leaf:

```
<refund_cltv_height> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG
```

- **Pre-signed before funding.** `build_origination_package` builds the refund transaction, signs it with both parties' keys (`SIGHASH_DEFAULT`), and verifies both signatures before the funding transaction is broadcast. Neither party can be left holding funds they cannot recover.
- **No oracle signature is needed.** The refund spends on the CLTV height and the two party signatures alone.
- **Locktime semantics.** A height lock `N` is final once the chain tip is at `N`; the refund first confirms in block `N + 1`. At tip `N - 1` Core's `testmempoolaccept` returns `non-final`.
- **Outputs.** Each party receives its margin minus half of the shared fee and the CPFP anchor (`(1000 + 330) / 2 = 665` sats in the regtest drill). A 330-sat anchor output is included.
- **CPFP.** The anchor output is spent together with an independent fee-bump UTXO by a child transaction, so the refund can be fee-bumped without a pre-signed fee rate.

## Choosing heights from an event

```
shz dlc-refund-plan --event FILE --tip-height H --tip-time UNIX \
    [--block-secs 600] [--attest-window-secs 30] [--grace-blocks 6] \
    [--refund-delay-blocks 144] [--fast-factor 2] [--min-gap-secs 21600] [--force]
```

`FILE` is a fixture (`announcement_core`) or a raw `/v1/dlc/event` response (`core`). The command prints JSON with:

- `maturity_height = tip_height + ceil((maturity_unix + attest_window - tip_time) / block_secs)`: the first height expected at or after the attestation due time.
- `unilateral_cltv_height = maturity_height + grace_blocks` and `refund_cltv_height = maturity_height + refund_delay_blocks`.
- `min_gap_secs_at_fast_speed`: heights are block counts, so if blocks arrive `fast-factor` times faster than `block-secs`, the refund height arrives earlier in wall time. The gap is the refund time at that speed minus the attestation due time.

The command exits with an error when the gap is below `--min-gap-secs` (default 6 hours) unless `--force` is given. With the defaults (144-block delay, 2x speed) the gap is about 11.6 hours. A 20-block delay is refused.

## What the oracle publishes for unattested events

For an event the confederation cannot attest, `GET /v1/dlc/event/<id>` returns status `unattestable` and an `unattestable_signature`: a threshold BIP340 signature by the group key over `tagged_hash("SHZ/DLC/UNATTESTABLE/V1", event_id utf8)`. The notice is informational: it tells counterparties to stop waiting. The on-chain refund does not read it.

## Commands and local result

```
cargo test --locked -p shz-cli
cargo run --locked --release --bin shz -- dlc-oracle-regtest <path-to-bitcoind-31.1> > receipt.json
```

`dlc-oracle-regtest` starts an isolated Core 31.1 regtest node, sizes each contract with `dlc-refund-plan` arithmetic (tip one hour before maturity), and runs two scenarios with a 1,000 USD inverse contract at 2x on both sides, entered at 60,000 USD, with 19,105 compressed CETs (max error 50 sats):

- **A, attested** (live event `SHZ-BTCUSD-20261125T0915Z`, 58,992 USD): the attestation completes the adaptor signatures of CET 8415 (prefix length 18, range 58,992-58,995). A CET of another range is not completable. The unilateral CET is `non-final` at tip 117 and confirms at height 119 with outputs `[861783, 803555, 330]` sats; `payout_at_price(58992)` is short 861,812 and long 804,856 (long output plus the 1,000-sat fee and 330-sat anchor is 804,885), within the 102-sat compression tolerance.
- **B, unattested** (test event, attestation never used; the live attestation cannot complete its CETs): premature refund at tip 269 for CLTV 270 is rejected with `non-final`; the pre-signed refund confirms at height 271 with outputs `[832669, 832669, 330]`; the CPFP child (2 mempool ancestors) confirms in the same block. Each party's 833,334-sat margin is returned minus 665 sats.

The full receipt (txids, heights, rejection reasons) is `evidence/hft06/dlc_oracle_regtest_windows.json`. CI: `.github/workflows/shz-hft06-dlc-refund-regtest.yml` runs the same command against SHA256-pinned Core 31.1 and prints txids, heights, and rejection reasons as `::notice` annotations.
