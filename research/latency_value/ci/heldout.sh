#!/usr/bin/env bash
# Bounded public-data held-out evaluation for one market.
# Usage: heldout.sh SYMBOL DAY [DAY...]
# Raw books and trades stay in $RUNNER_TEMP and are deleted; only aggregate
# JSON leaves the job.
set -euo pipefail
SYM="$1"; shift
DAYS=("$@")
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export SHZ_LV_CACHE="$RUNNER_TEMP/lv-cache"
RAW="$RUNNER_TEMP/lv-raw"
mkdir -p "$SHZ_LV_CACHE" "$RAW/books" "$RAW/trades" "$ROOT/ci-out"
trap 'rm -rf "$RAW"' EXIT
fetch_books() {  # day
  local day="$1" h
  for i in $(seq 0 23); do
    h=$(printf '%02d' "$i")
    if ! curl --fail --silent --show-error --location --retry 2 --max-time 120 --max-filesize 300000000 \
        "https://api.cryptohftdata.com/v1/download?file=lighter/$day/$h/${SYM}_orderbook.parquet" \
        -o "$RAW/books/$day-$h.parquet"; then
      rm -f "$RAW/books/$day-$h.parquet"
      echo "$SYM,$day,$h,download_failed" >> "$ROOT/ci-out/failures-$SYM.csv"
    fi
    sleep 1.1
  done
}
for day in "${DAYS[@]}"; do
  curl --fail --silent --show-error --location --retry 2 --max-time 600 \
    "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/lighter/core/mainnet/trades/date=$day/trades.parquet" \
    -o "$RAW/trades/$day.parquet"
  sha256sum "$RAW/trades/$day.parquet" | sed "s#$RAW/##" >> "$ROOT/ci-out/sha256-$SYM.txt"
  fetch_books "$day"
done
ls "$RAW/books" | wc -l
sha256sum "$RAW"/books/*.parquet | sed "s#$RAW/##" >> "$ROOT/ci-out/sha256-$SYM.txt" || true
cd "$ROOT"
first="${DAYS[0]}"; last="${DAYS[${#DAYS[@]}-1]}"
python trades_daily.py --trades-dir "$RAW/trades" --first "$first" --last "$last" --output "ci-out/trades-$SYM.json" --workers 1
python run_replay.py --symbol "$SYM" --books "$RAW/books" --first "$first" --last "$last" --workers 2
cp "$SHZ_LV_CACHE/replay_log_received_$SYM.jsonl" "ci-out/replay-log-$SYM.jsonl"
python evaluate_frozen.py --symbol "$SYM" --days "${DAYS[@]}" --output "ci-out/heldout-$SYM.json"
