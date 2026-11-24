# SHZ-LV: the price of 200 milliseconds

Empirical latency-value and fee-formation study on public Lighter data, applied to the SHZ federated oracle and router design. Experiment specification: [docs/SPEC.md](docs/SPEC.md). Continuation ledger: [docs/LEDGER.md](docs/LEDGER.md). Lighter fee/latency control arm: [docs/LIGHTER_FEE_SCHEDULE.md](docs/LIGHTER_FEE_SCHEDULE.md).

No live orders, no account credentials, no private trading data. The public trades dataset's fee fields are used per trade; nothing is grouped by account and account identifiers are never loaded. Raw L2 rows, prices and per-second tables stay in a local cache (archive licence); the repository holds code, manifests (hashes and counts), aggregate results and figures.

## Layout

| Path | Role |
|---|---|
| `common.py` | markets, tiers, delays, sizes, horizons, paths |
| `inventory.py` | hash and sequence-continuity manifest of local L2 hours → `manifests/l2_inventory.json` |
| `trades_daily.py` | per-day aggregates of the public trades dataset (volume, fees by rate, scopes) → `manifests/lighter_trades_daily.json`; per-second local cache |
| `engine.py` | causal displayed-depth replay of one hour (IOC fills at 100/140/200/300 ms, 20 ms mid series) |
| `run_replay.py` | parallel, resumable replay into the local cache |
| `features.py` | day assembly, causal features, ex-post fields kept separate |
| `analysis.py` | tier economics, rare-event test, WTP / demand curves, markouts, oracle lead, observed fees by regime |
| `policy.py` | chronological train → freeze → held-out evaluation; free-only, PR #30 bins, threshold, gradient boosting, ex-post oracle |
| `revenue.py` | DefiLlama × public-trades calibration with consistent scopes |
| `shz_model.py` | SHZ federation economics, break-even, router competition |
| `evaluate_frozen.py`, `ci/heldout.sh` | CI evaluation of frozen policies on fresh public days |
| `figures.py` | paper figures from committed aggregates |
| `verify_receipts.py` | CI recomputation of committed receipts |

## Reproduce

```
python -m venv venv && venv/Scripts/python -m pip install -r requirements.txt
set SHZ_LV_ARCHIVE=<dir holding the TradingMoneyball/Codex offload cache>
set SHZ_LV_CACHE=<scratch dir with ~20 GB>
python trades_daily.py --trades-dir %SHZ_LV_ARCHIVE%/swing-l2/trades --first 2026-09-16 --last 2026-11-21 --output manifests/lighter_trades_daily.json
python run_replay.py --symbol BTC --books %SHZ_LV_ARCHIVE%/cross-market-l2/BTC/archive/books --first 2026-10-11 --last 2026-10-27
python run_replay.py --symbol ETH --books %SHZ_LV_ARCHIVE%/swing-l2/books --first 2026-11-01 --last 2026-11-21
python run_replay.py --symbol SOL --books %SHZ_LV_ARCHIVE%/cross-market-l2/SOL/archive/books --first 2026-10-11 --last 2026-11-21
python run_study.py
python -m pytest -q tests && python verify_receipts.py
```
