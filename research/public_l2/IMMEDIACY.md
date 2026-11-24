# Conditional value of immediacy

Extends the PR #30 public L2 day calibration (Oct 11 and Nov 23, 2026, full UTC days, receive clock, $1k probes, +/-20 bp limit, causal direction). PR #30 reports retrospective tier winners. This module asks which of those winners a causal policy can select in advance, and whether a sparse scalp recovers the paid-tier fees.

## Method

`immediacy.py hour` replays one BTC hour (optionally with the ETH hour) and emits per-cell sufficient statistics only. `immediacy.py aggregate` trains and evaluates policies from those cells. No raw rows or price sequences leave the hour; the output carries input SHA-256 hashes.

Features at decision second T use book events with effective time strictly before T and grid history T-1s to T-30s:

- top-5 depth imbalance, signed toward the trade side, and its change over 1 s and 5 s
- depletion and replenishment of the consumed side's top-5 depth over 1 s
- spread (bps) and microprice offset (bps, signed)
- realized volatility over 1, 5, 30 s, and the PR #30 score
- cross-market residual: BTC 1 s return minus beta times ETH 1 s return, beta from the prior 300 pairs only (at least 60); the feature is `na` when no ETH hour is supplied
- client request congestion: unavailable. Public L2 does not observe it. It has no feature column, no proxy, and is listed under `unavailable_features`.

Targets per decision (all three tiers fully filled): net saving of premium (100 ms, 2 bps) and intermediate (200 ms, 0.5 bps) versus free (300 ms, 0 bps), fee included as `fee * price / mid`.

Model: fixed a-priori bin edges; a policy is a lookup from a feature cell to a tier. Cell choice maximizes the ridge-shrunk mean net saving `sum / (n + 100)` with at least 100 common fills, otherwise free. Families: one per feature, plus `score_imb` (score bin x imbalance bin), fixed in advance as the primary. Validation is chronological only: Oct 11 fit then Nov 23 test, and within-day rolling origins at hours 6, 12, 18 (train hours before the origin, test the next six hours).

Reported separately: retrospective optimal frequencies (ex post winners) and achievable policy selection rates; paid-tier precision and recall; mean net saving when selected; calibration of predicted versus realized saving.

Scalp test: entry in the causal direction at tier T, exit after 15 s and 60 s at the same tier (limit +/-20 bp, same size), both legs pay the tier fee. Closed P&L is fill-to-fill, so spread and walk-the-book cost are inside it; `mean_entry_exit_cost_ex_fee_bps` separates them from the mid-to-mid move. A missed entry fill opens nothing. A non-full exit is unresolved exposure, counted and marked to mid separately, never entered as zero. Entries whose exit falls past the hour end are censored and excluded. The 5 and 10 per day figures are `N x mean closed net bps` over all eligible directional seconds, the expectation of uniform sampling of N spaced entries (61 s spacing is always satisfiable); no sparse sample is drawn. Fee recovery is read from each tier's mean closed net bps with its standard error, compared against the free tier (unpaired).

Revenue: `sum(fee * adopted notional) * 0.70`. The provider file has no trade prints, so the weight is a labeled proxy: top-5 depth removed from the consumed side in the second before the decision, valued at mid (`depth_reduction_proxy_usd_top5_direction_side`). It includes cancels. Retrospective-optimal and achievable-policy adoption are reported separately.

## Commands

```
python -m unittest research/public_l2/test_immediacy.py -v
python research/public_l2/immediacy.py hour --book BTC.parquet [--eth-book ETH.parquet] --hour 2026-11-23T12:00:00 --output H.immediacy.json
python research/public_l2/immediacy.py aggregate --root hourly --output immediacy_report.json
```

CI: `.github/workflows/shz-hft06-immediacy-calibration.yml` (push to `research/shz-hft06-oracle-relay-20261124`, workflow_dispatch). Downloads happen only there, 200 MB cap per file, raw files deleted, artifacts retained 14 days. The ETH hour is optional; a missing file is logged and the cross-market feature stays `na` for that hour.

## Evidence classes

- Historical observation: replay of public Lighter L2 visible depth on two fixed dates.
- Synthetic: only the unit-test fixture books in `test_immediacy.py`.
- Production claim: none. No executed orders, queue position, client congestion, rate-limit effect or trade prints. The dates are not a representative sample; two days cannot establish a stable tail.

## Blockers

- TradingMoneyball private caches (sparse 5/10 per day scalp counterfactual, volume-weighted oracle revenue) are not on this machine. The core takes any `pilot.Book`-compatible message stream, so an adapter that yields `(effective_ms, kind, seq, prev, levels)` tuples from those caches runs unchanged; it is not written.
- Core execution tapes are unavailable here, so the volume weight stays a proxy.
- Client request congestion is unobservable in public L2.
- The workflow has not run yet; only the local unit tests and a synthetic aggregation smoke test have.
