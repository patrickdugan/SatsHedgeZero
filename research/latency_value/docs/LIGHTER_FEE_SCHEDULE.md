# Lighter fee and latency schedule (control arm)

Sources read 2026-11-25. D = Lighter documentation, T = third party.

| Account type | Maker fee | Taker fee | Taker latency | Maker / cancel latency | Notes |
|---|---:|---:|---:|---:|---|
| Standard | 0 | 0 | 300 ms | 0 ms / 300 ms | REST 60 weighted req/min (D) |
| Plus (opt-in) | 0.5 bp | 0.5 bp | 300 ms | 0 ms / 300 ms | sendTx 4,000/min (D); on 2026-10-22 maker latency 200→0 ms, cancel 200→300 ms (T, cipher-intelligence) |
| Premium (opt-in) | 0.40 bp list | 2.80 bp list | 140 ms | cancel and post-only add no latency | staking ladder below (D) |

Premium staking ladder, staked LIT → (discount, maker bp / taker bp): 0 → (0%, 0.40/2.80); 1k → (2.5%, 0.39/2.73); 3k → (5%, 0.38/2.66); 10k → (10%, 0.36/2.52); 30k → (15%, 0.34/2.38); 100k → (20%, 0.32/2.24); 300k → (25%, 0.30/2.10); 500k → (30%, 0.28/1.96). Source: https://docs.lighter.xyz/trading/trading-fees (D). Rate limits: https://docs.lighter.xyz/developers/reference/rate-limits.md (D).

History: no official changelog. A 2026-02-07 article (T, coingabbar) announced LIT fee tiers for 2026-02-08 with Premium 0.2/2 bp and 150 ms; by 2026-08 third parties cite 0.40/2.80 bp and 140 ms. No fee-schedule change between 2026-10-01 and 2026-11-25 was found. The study window (2026-09-16 to 2026-11-23) is therefore evaluated against the current schedule, with the Plus latency change of 2026-10-22 noted as a T-sourced caveat.

## Historical evidence in the data

The public trades dataset carries per-trade `maker_fee` / `taker_fee` integers. Allium documents them as ppm of notional (https://docs.allium.so/historical-data/supported-blockchains/lighter/raw/trades.md). The observed taker rates on 2026-11-01 are exactly the ladder above (280, 273, 266, 252, 238, 224, 210, 196 ppm) plus 50 ppm, and maker rates 28–40 ppm. The sum of per-trade fees over perpetual markets matches DefiLlama `lighter-perps` dailyFees (results/revenue.json, `fee_unit_check`). This is direct historical evidence that the staking discounts were in force during the window.

Using these fields is a trade-level observation of the fee charged. The study never groups by account, never loads account identifiers, and never assigns an account to a tier.

## How the control arm is evaluated

`analysis.TIERSETS`:
- `lighter_list`: Standard 300 ms / 0, Plus 300 ms / 0.5 bp, Premium 140 ms / 2.80 bp.
- `lighter_staked_max`: Premium at the 500k-LIT rate, 1.96 bp.

Plus has the same taker latency as Standard, so it can never win on execution in this model; its documented value is rate limits and 0 ms maker latency, which a displayed-depth IOC replay cannot price. Its ex-post share is reported as zero by construction and its observed volume share is reported from the trades data.
