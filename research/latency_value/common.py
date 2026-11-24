"""Shared constants for the price-of-200ms study (SHZ-LV).

All timestamps are integer milliseconds since the Unix epoch, UTC.
"""
from __future__ import annotations

from datetime import datetime, UTC
from pathlib import Path
import os

# Lighter public market indices and integer scaling, as observed in the public
# trades dataset (usdc_amount has 6 decimals). Verified by
# trades_daily.verify_scaling against usdc_amount on every processed day.
MARKETS = {
    "ETH": dict(market_id=0, price_decimals=2, size_decimals=4),
    "BTC": dict(market_id=1, price_decimals=1, size_decimals=5),
    "SOL": dict(market_id=2, price_decimals=3, size_decimals=3),
}

# Candidate SHZ service tiers (taker latency ms, taker fee bps).
SHZ_TIERS = (("standard", 300, 0.0), ("intermediate", 200, 0.5), ("premium", 100, 2.0))
# Lighter documented schedule control (see docs/LIGHTER_FEE_SCHEDULE.md):
# Standard 300 ms / 0 bp, Plus 300 ms / 0.5 bp taker, Premium 140 ms / 2.8 bp
# taker list price; staking-discounted variants are evaluated separately.
LIGHTER_TIERS = (("standard", 300, 0.0), ("plus", 300, 0.5), ("premium", 140, 2.8))
DELAYS_MS = (100, 140, 200, 300)
SIZES_USD = (100, 1_000, 10_000, 100_000)
HORIZONS_MS = (200, 1_000, 5_000, 30_000)
LIMIT_BPS = 20.0          # IOC limit distance from arrival mid
GRID_MS = 1_000           # decision grid
FINE_MS = 20              # mid sampling grid for markouts and fills
MAX_AGE_MS = 2_000        # book considered stale after this long without a message
WARMUP_MS = 60_000        # causal feature warmup inside each hour
TRADE_VISIBILITY_LAG_MS = 250  # trades usable as features only after this lag

CACHE = Path(os.environ.get("SHZ_LV_CACHE", r"C:\Users\patri\shz-research\cache"))
ARCHIVE_ROOT = Path(os.environ.get(
    "SHZ_LV_ARCHIVE", r"D:\Codex-offload\2026-11-22\trading-systems\work"))


def utc_ms(text: str) -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp() * 1000)


def ms_to_iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%S")
