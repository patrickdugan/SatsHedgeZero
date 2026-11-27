#!/usr/bin/env bash
# Regtest drill of the settlement daemon against the mock venue (ops/shz-batcher/mock_venue.py):
# four 90 s epochs over replayed venue batches 306..313 with an aborted seq (two segments), a
# non-signer (trader 2 leaves its second package unsigned; its net is carried), an unattestable
# epoch (its batch rolls into the next), a withdrawal (trader 5), CPFP of slow settlements, and the
# joint-statement prover per settled segment.
#
#   ops/shz-batcher/drill_regtest.sh [WORKDIR]      (WORKDIR default D:/shz/tmp/shz-batcher/drill)
#
# Env: BITCOIN_BIN (folder with bitcoind/bitcoin-cli), TRADER_KEYS (venue owner keys file),
# RECEIPTS (default research/lightninger_dlc_batcher/artifacts/epochs/regtest-drill), MAX_EPOCHS (4),
# DAEMON_FLAGS (default "--prove --table 4 --rows 2"; "--stage" runs the testnet4 no-broadcast path),
# PLAN (default ops/shz-batcher/drill_plan.json), TRADER_FLAGS (default "--refuse 2:2 --withdraw 5:2").
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CRATE="$REPO/research/lightninger_dlc_batcher"
W="${1:-D:/shz/tmp/shz-batcher/drill}"
BIN="${BITCOIN_BIN:-C:/Users/patri/bitcoin-core-31.1/bin}"
TRADER_KEYS="${TRADER_KEYS:-D:/shz/tmp/dlc-batch/keys.json}"
RECEIPTS="${RECEIPTS:-$CRATE/artifacts/epochs/regtest-drill}"
EXE=""; [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && EXE=".exe"
SB="$CRATE/target/release/shz_batcher$EXE"
PORT=18643; VPORT=8197
CLI_ARGS="-regtest -rpcuser=lbc -rpcpassword=lbc -rpcport=$PORT -datadir=$W/node"
cli() { "$BIN/bitcoin-cli$EXE" $CLI_ARGS "$@"; }

rm -rf "$W/node" "$W/state" "$RECEIPTS"; mkdir -p "$W/node" "$W/state" "$W/logs"
"$BIN/bitcoind$EXE" -regtest -server=1 -txindex=1 -fallbackfee=0.0001 -rpcuser=lbc -rpcpassword=lbc -rpcport=$PORT -port=18644 -listen=0 -dnsseed=0 -datadir="$W/node" >/dev/null 2>&1 &
BTCD=$!
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; cli stop >/dev/null 2>&1 || true; wait "$BTCD" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 100); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 0.3; done
cli createwallet w >/dev/null
SINK=$(cli getnewaddress "" bech32m)
cli generatetoaddress 110 "$SINK" >/dev/null

KEYS="$W/batcher-keys.json"
[ -f "$KEYS" ] || python -c "import json,secrets;print(json.dumps({'batcher_sk':secrets.token_hex(32),'operator_sk':secrets.token_hex(32)}))" > "$KEYS"
COMMON=(--network regtest --cli "$BIN/bitcoin-cli$EXE" --cli-args "$CLI_ARGS" --keys "$KEYS" --state "$W/state" --venue "http://127.0.0.1:$VPORT" --receipts "$RECEIPTS")
SETUP=$("$SB" drill-setup "${COMMON[@]}" --refund-delta 40 --trader-keys "$TRADER_KEYS" --channels "$CRATE/artifacts/venue_batches.json" --collateral 20000 --liquidity 200000 --out "$W/registry.json")
echo "setup: $SETUP"
OPERATOR=$(python -c "import json,sys;print(json.loads(sys.argv[1])['operator'])" "$SETUP")
BKEY=$("$SB" pubkeys --keys "$KEYS" | python -c "import json,sys;print(json.load(sys.stdin)['batcher'])")
NOW=$(date +%s); T0=$(( (NOW + 45 + 89) / 90 * 90 ))
python "$REPO/ops/shz-batcher/mock_venue.py" --port $VPORT --source "$CRATE/artifacts/venue_batches.json" --plan "${PLAN:-$REPO/ops/shz-batcher/drill_plan.json}" \
  --registry "$W/registry.json" --batcher-key "$BKEY" --t0 $T0 --log "$W/logs/venue.log" >"$W/logs/venue.out" 2>&1 &
pids+=($!)
sleep 1
"$SB" init "${COMMON[@]}" --epoch-secs 90 --operator "$OPERATOR" --start-seq 0 --t0 $T0
"$SB" traders --venue "http://127.0.0.1:$VPORT" --trader-keys "$TRADER_KEYS" ${TRADER_FLAGS:---refuse 2:2 --withdraw 5:2} --for-secs 900 >"$W/logs/traders.log" 2>&1 &
pids+=($!)
( while true; do sleep 25; cli generatetoaddress 1 "$SINK" >/dev/null 2>&1 || break; done ) &
pids+=($!)
echo "t0 $T0 ($(( T0 - NOW ))s from now); daemon log $W/logs/daemon.log"
"$SB" run "${COMMON[@]}" --epoch-secs 90 --sign-secs 20 --settle-delay-secs 3 --oracle --attest-wait-secs 15 --refund-delta 40 \
  --fee-rate 1 --bump-rate 5 --bump-after-blocks 0 --bump-after-secs 6 --max-epochs "${MAX_EPOCHS:-4}" ${DAEMON_FLAGS:---prove --table 4 --rows 2} 2>&1 | tee "$W/logs/daemon.log"
cli generatetoaddress 1 "$SINK" >/dev/null
"$SB" status "${COMMON[@]}" > "$RECEIPTS/state_after.json"
cp "$W/logs/daemon.log" "$W/logs/traders.log" "$W/logs/venue.log" "$RECEIPTS/"
curl -s "http://127.0.0.1:$VPORT/api/explorer/settlements" > "$RECEIPTS/venue_settlements.json"
cli getblockchaininfo > "$RECEIPTS/chain.json"
echo "receipts in $RECEIPTS"
