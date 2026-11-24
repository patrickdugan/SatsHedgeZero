# SHZ-LV experiment specification

Written 2026-11-25 before any ETH or SOL result, before any policy was trained on the full development windows, and before the CI held-out days (2026-11-22, 2026-11-23) were fetched. The BTC 2026-10-11 single-day results were already known from PR #30/#32 and from the engine cross-check.

## Data

| Market | Local window (UTC) | Hours | Source |
|---|---|---:|---|
| BTC | 2026-10-11 .. 2026-10-27 | 408 | local cache `cross-market-l2/BTC/archive/books` |
| ETH | 2026-11-01 .. 2026-11-21 | 504 | local cache `swing-l2/books` (TradingMoneyball November ETH archive) |
| SOL | 2026-10-11 .. 2026-11-21 | 1008 | local cache `cross-market-l2/SOL/archive/books` |
| all | 2026-09-16 .. 2026-11-21 | 67 days | public trades dataset (AWS public blockchain, Lighter core mainnet) |
| BTC, ETH, SOL | 2026-11-22, 2026-11-23 | 144 | CI only, CryptoHFTData public endpoint + public trades on S3 |

Clock: recorder "received" clock as primary (PR #30 definition); BTC 2026-10-11 also on the publication clock. Dirty hours dropped in full.

## Arms

* SHZ candidate: Standard 300 ms / 0 bp, Intermediate 200 ms / 0.5 bp, Premium 100 ms / 2 bp (taker).
* Lighter control: Standard 300 / 0, Plus 300 / 0.5, Premium 140 / 2.80 list and 1.96 at the maximum staking discount.
* Sizes $100, $1k, $10k, $100k; IOC limit ±20 bp; horizons 200 ms, 1 s, 5 s, 30 s.
* Feed-only arm: oracle mark seen 100 or 200 ms early, edge net of half spread and fee.

## Hypotheses (from the SHZ-HFT-04 design note) and decision rules

* H1: Premium is ex-post optimal ~0.1% of market time. Reported: share of covered seconds where Premium is the ex-post winner for the momentum cohort, $1k and $10k, with day-block bootstrap 95% CI. H1 is "consistent" if the CI overlaps [0.05%, 0.2%], "rejected (lower/higher)" otherwise.
* H2: Intermediate is ex-post optimal ~2% of time. Same rule with [1%, 4%].
* H3: Free execution suffices for most activity: Standard (or no common fill) ≥ 90% of decisions.
* H4: Paid windows carry disproportionate matched volume: volume share / time share > 1 with the CI of the volume share excluding the time share.
* H5 (policy): a causal policy beats free-only out of sample: held-out mean net saving per common decision > 0 with the bootstrap CI excluding 0. PR #30's question is H5 for training on BTC 2026-10-11 only.

## Splits

Chronological; train, freeze, test. BTC Oct 11 → Oct 12–27; BTC Oct 11–20 → Oct 21–27; ETH Nov 1–14 → Nov 15–21; SOL Oct 11–Nov 7 → Nov 8–21. Final frozen policies trained on all local days per market, evaluated in CI on Nov 22–23 only. Gradient-boosting margin tuned on the last 25% of training days. No hyper-parameter is chosen on test days.

## Revenue calibration

Perps scope (market_id < 2048) of the public trades vs DefiLlama `lighter-perps` dailyFees on exact UTC dates; parent `lighter` reported separately. Actual paid shares are trade-level fee-rate observations; adoption by tier is not identified at account level and is not attempted.
