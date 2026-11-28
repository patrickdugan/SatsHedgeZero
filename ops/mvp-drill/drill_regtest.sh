#!/usr/bin/env bash
# Lightninger MVP drill on regtest: a regtest node, the venue with --collateral-chain regtest (live
# FROST marks from the relay), the settlement daemon shz_batcher (60 s epochs; it writes each settled
# segment's prover inputs and README, and proofs run on Colab, never locally), a miner every 5 s, and
# three browser-less traders
# (ops/mvp-drill/client.mjs) that deposit, activate, trade over three epochs, co-sign settlements in
# ui/venue/settle.js (one trader leaves one package unsigned), and withdraw.
#
#   ops/mvp-drill/drill_regtest.sh [WORKDIR]          (default D:/shz/tmp/mvp-drill)
#
# Env: BITCOIN_BIN (folder with bitcoind/bitcoin-cli), VENUE_BIN (shz-venue), BATCHER_BIN (shz_batcher),
# VPORT (venue port, default 8098), OUT (receipt dir, default ops/mvp-drill/receipt-regtest).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
W="${1:-D:/shz/tmp/mvp-drill}"
EXE=""; [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && EXE=".exe"
BIN="${BITCOIN_BIN:-C:/Users/patri/AppData/Local/Programs/BitcoinCore/bitcoin-31.1/bin}"
VENUE_BIN="${VENUE_BIN:-D:/shz/target-msvc/release/shz-venue$EXE}"
SB="${BATCHER_BIN:-$REPO/research/lightninger_dlc_batcher/target/release/shz_batcher$EXE}"
VPORT="${VPORT:-8098}"; PORT=18743
OUT="${OUT:-$REPO/ops/mvp-drill/receipt-regtest}"
NODE="${NODE:-node}"

rm -rf "$W/node" "$W/venue" "$W/daemon" "$OUT"; mkdir -p "$W/node" "$W/venue" "$W/daemon" "$W/logs" "$OUT/epochs"
# Local regtest RPC credentials: random per run, kept in the work dir (never printed).
[ -f "$W/rpcpass" ] || python -c "import secrets;print(secrets.token_hex(16))" > "$W/rpcpass"
PASS=$(cat "$W/rpcpass"); printf 'drill:%s' "$PASS" > "$W/rpcauth"
CLI_ARGS="-regtest -rpcuser=drill -rpcpassword=$PASS -rpcport=$PORT -datadir=$W/node"
cli() { "$BIN/bitcoin-cli$EXE" $CLI_ARGS "$@"; }
"$BIN/bitcoind$EXE" -regtest -server=1 -txindex=1 -fallbackfee=0.0001 -rpcuser=drill -rpcpassword="$PASS" -rpcport=$PORT -port=18744 -listen=0 -dnsseed=0 -datadir="$W/node" >/dev/null 2>&1 &
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
PK=$("$SB" pubkeys --keys "$KEYS")
BKEY=$(python -c "import json,sys;print(json.loads(sys.argv[1])['batcher'])" "$PK")
OKEY=$(python -c "import json,sys;print(json.loads(sys.argv[1])['operator'])" "$PK")

"$VENUE_BIN" --listen 127.0.0.1:$VPORT --state "$W/venue" --ui "$REPO/ui/venue" --collateral-chain regtest \
  --bitcoind-rpc http://127.0.0.1:$PORT --bitcoind-auth-file "$W/rpcauth" --batcher-key "$BKEY" \
  --refund-blocks 60 --min-lock 20 --min-conf 1 --chain-poll-ms 1500 >"$W/logs/venue.log" 2>&1 &
pids+=($!)
for _ in $(seq 60); do curl -s "http://127.0.0.1:$VPORT/api/status" | grep -q '"tip_height":[1-9]' && break; sleep 0.5; done

# Operator liquidity: one output paying the <O> CHECKSIG leaf.
OPADDR=$("$NODE" "$REPO/ops/mvp-drill/client.mjs" opaddr "$OKEY" bcrt)
OPTX=$(cli sendtoaddress "$OPADDR" 0.01)
cli generatetoaddress 1 "$SINK" >/dev/null
OPVOUT=$(cli getrawtransaction "$OPTX" true | python -c "import json,sys;t=json.load(sys.stdin);a=sys.argv[1];print([o['n'] for o in t['vout'] if o['scriptPubKey'].get('address')==a][0])" "$OPADDR")

COMMON=(--network regtest --cli "$BIN/bitcoin-cli$EXE" --cli-args "$CLI_ARGS" --keys "$KEYS" --state "$W/daemon" --venue "http://127.0.0.1:$VPORT" --receipts "$OUT/epochs")
NOW=$(date +%s); T0=$(( (NOW + 60) / 60 * 60 ))
"$SB" init "${COMMON[@]}" --epoch-secs 60 --operator "$OPTX:$OPVOUT" --start-seq 0 --t0 $T0
( while true; do sleep 5; cli generatetoaddress 1 "$SINK" >/dev/null 2>&1 || break; done ) &
pids+=($!)
"$SB" run "${COMMON[@]}" --epoch-secs 60 --sign-secs 25 --settle-delay-secs 3 --refund-delta 40 --fee-rate 1 --bump-rate 5 \
  --bump-after-blocks 3 --table 4 --rows 2 >"$W/logs/daemon.log" 2>&1 &
pids+=($!)
echo "venue http://127.0.0.1:$VPORT  batcher $BKEY  operator $OPTX:$OPVOUT  t0 $T0"

"$NODE" "$REPO/ops/mvp-drill/client.mjs" --venue "http://127.0.0.1:$VPORT" --cli "$BIN/bitcoin-cli$EXE" --cli-args "$CLI_ARGS" \
  --keys "$W/trader-keys.json" --out "$OUT/receipt.json" --epoch-secs 60 --refuse 2:1 2>&1 \
  | tee "$W/logs/client.log" && RC=0 || RC=$?

# Receipts are collected whatever the client's outcome.
cp "$W/logs/daemon.log" "$W/logs/client.log" "$OUT/"
grep -v -i "rpcpassword" "$W/logs/venue.log" > "$OUT/venue.log" || true
curl -s "http://127.0.0.1:$VPORT/api/explorer/settlements" > "$OUT/venue_settlements.json"
curl -s "http://127.0.0.1:$VPORT/api/explorer/accounts" > "$OUT/venue_accounts.json"
cli getblockchaininfo > "$OUT/chain.json"
exit $RC
