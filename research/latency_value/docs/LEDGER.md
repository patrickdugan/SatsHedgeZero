# SHZ-LV continuation ledger

Branch: `research/price-of-200ms-20261125` (stacked on PR #32 `research/l2-revenue-join-20261124`). Paper: RTG-site branch `research/price-of-200ms-paper-20261125`, `papers/price-of-200ms/`. Raw data: local cache only (archive licence). `production_ready = false`.

## Completed gates

| Gate | Result | Evidence |
|---|---|---|
| G-CI-32 PR #32 CI repaired | `trade_weights` used `pyarrow.Table.iter_batches` (absent); fixed to `to_batches`, selftest added, public annotations. Run 45439371860 green: Nov 23 BTC 24/24 hours, ex-post winner volume free 86.2% / middle 10.6% / premium 1.89%; Oct 11 96.9 / 2.55 / 0.09%. | commit a2ebf39 on `research/l2-revenue-join-20261124` |
| G-REP-1 PR #30 Oct 11 reproduction | `pilot.py` on local files: 65,455 / 285 / 7 / 20,653 (received), 65,536 / 276 / 10 / 20,578 (publication); identical to PR #30. | `python public_l2/pilot.py` per local hour + `public_l2/aggregate_day.py`; PR #30 counts in `public_l2/REVENUE_JOIN.md`; engine-based clock sensitivity in `results/sensitivity_BTC_publication_20261011.json` |
| G-REP-2 Local = provider bytes | 24/24 BTC 2026-10-11 local files match CI download sha256 | `manifests/l2_inventory.json` vs run 45439371860 annotations |
| G-ENG-1 Engine parity | `engine.py` reproduces `pilot.py` winners exactly on 2026-10-11T12 (2,873 free / 4 middle) | engine selftest; tests |
| G-DATA-1 Inventory | BTC 408, ETH 1,418 (Nov 1–21: 504), SOL 1,008 unique hours; 0 conflicting versions; intra-hour gaps only in Sep ETH; 96 unreadable auxiliary files | `manifests/l2_inventory.json` |
| G-RUN-1 Replay | 1,920 study hours, 0 dirty, 0 missing, 0 errors | local `replay_log_*.jsonl` (cache) |
| G-HYP-1..4 Rare-event test | H1 rejected for BTC (0.022%), consistent ETH/SOL (0.23/0.26%); H2 consistent all; H3, H4 hold all | `results/analysis_*.json`, paper Table 3 |
| G-POL-1 Causal policy (H5) | Rejected all markets: free-only not beaten out of sample; ETH boosting −0.00012 bp [−0.00025, −0.00001] | `results/policy_*.json`, `results/diagnostics_*.json` |
| G-REV-1 Fee units/scope | Per-trade perps fees / DefiLlama lighter-perps dailyFees median 0.9956 (p10–p90 0.9921–0.9992), 67 days | `results/revenue.json` |
| G-REV-2 Observed regime fees | top 1% of seconds: 12.8 / 26.2 / 21.0% of fees (BTC/ETH/SOL) on 5.5 / 7.0 / 6.2% of volume | `analysis_*.json` `observed_fee_revenue_by_regime` |
| G-SHZ-1 Economics | break-even, β*, elasticities, oracle-lead transfer, router competition | `results/shz_economics.json` |
| G-HO-1 Held-out days 2026-11-22/23 (CI) | Run 45448542688 (commit afb8bc4), all jobs green, 48/48 clean hours per market. Frozen policies: BTC (Oct 11-trained and full-window, $1k and $10k) 0 paid choices; SOL 0; ETH boosting 5 paid choices, +0.00006 bp [−0.00000, 0.00011], threshold 0. Ex-post oracle 0.019–0.023 (BTC), 0.028 (ETH), 0.038 (SOL) bp. Ex-post $1k momentum time share intermediate / premium: BTC 3.69% / 0.197%, ETH 4.91% / 0.257%, SOL 4.99% / 0.377%; volume share 8.4% / 1.5%, 11.7% / 2.3%, 10.7% / 2.7%. | public notices on run 45448542688 jobs; artifacts `heldout-{BTC,ETH,SOL}` (14 days) |
| G-PAPER-1 Draft v0.1 | RTG paper with tables from `paper_tables.py` | RTG-site `papers/price-of-200ms/` |

## Failed or rejected hypotheses

- Premium tier valuable ~0.1% of time on BTC: measured 0.022% [0.017, 0.028] (about 5× lower).
- Richer causal features rescue PR #30's free-only result: no. Best causal cell mean premium saving 0.71 / 2.09 / 1.07 bp vs 2 bp fee.
- A 2 bp premium taker fee maximises latency revenue: no; revenue-maximising fee 0.37–1.28 bp in every market.
- 70/30 federation/router split is neutral: it makes routers the binding constraint for N ≥ 2 at base costs (β* = 0.47 at 3 routers).

## Outstanding experiments

| ID | What | Why open | Command / next step |
|---|---|---|---|
| G-HO-2 | Further fresh held-out days after any policy change | the held-out job now runs only on dispatch or a `[heldout]` commit | `workflow_dispatch` on `shz-price-of-200ms` with new dates in the matrix |
| G-ETH-2 | ETH 2026-09-25..10-31 (cached, unused) for a longer ETH development window | compute time | `python run_replay.py --symbol ETH --books <cache>/swing-l2/books --first 2026-09-25 --last 2026-10-31` then `run_study.py` with an extended ETH window |
| G-XV-1 | Cross-venue divergence feature (Binance/Coinbase) | no local cross-venue tick data; current `xdiv5` is cross-market within Lighter | add a public cross-venue trade source with matching clocks |
| G-SUB-1 | Sub-second decision grid (250 ms) | one-second grid kept for PR #30 parity | `GRID_MS` in `common.py`; engine supports it, re-run ~4× compute |
| G-MAKER-1 | Maker-side value (0 ms maker / cancel priority) | displayed-depth IOC replay cannot price quote protection | needs a queue-position model or L3 data |
| G-NET-1 | Measured multi-site oracle delivery (from HFT-06) | loopback only | unchanged from HFT-06 ledger |
| G-LEGAL-1 | Data licensing, derivatives and fee arrangements | counsel | unchanged |

## Artifact paths

- Code: `research/latency_value/*.py`; tests `research/latency_value/tests/`
- Spec: `docs/SPEC.md`; fee schedule control: `docs/LIGHTER_FEE_SCHEDULE.md`
- Manifests: `manifests/l2_inventory.json`, `manifests/lighter_trades_daily.json`, `manifests/defillama_lighter.json`
- Results: `results/analysis_{BTC,ETH,SOL}.json`, `results/policy_*.json`, `results/diagnostics_*.json`, `results/revenue.json`, `results/shz_economics.json`, `results/sensitivity_BTC_publication_20261011.json`, `results/RECEIPT.json`
- Frozen policies: `frozen/*.pkl` with `frozen/MANIFEST.json` sha256
- Figures: `figures/fig1..fig8*.png`
- Local cache (not published): `%SHZ_LV_CACHE%` = `C:\Users\patri\shz-research\cache` (hours/, days/, trades_*.npz)
