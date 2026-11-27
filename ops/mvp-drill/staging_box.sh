#!/usr/bin/env bash
# Lightninger MVP staging on the witness box, beside (not touching) the live units.
#
#   NET=regtest  (default) ~/shz-staging/staging_box.sh start|stop|status|faucet <address> [btc]
#     a regtest node, shz-venue --collateral-chain regtest on 0.0.0.0:8098 with its own state dir and
#     the box's FROST marks (relay 127.0.0.1:8091), the settlement daemon shz_batcher gated on the
#     real oracle maturities (900 s, --oracle), a miner (one block a minute), a faucet.
#   NET=testnet4 ~/shz-staging/staging_box.sh start|stop|status
#     shz-venue --collateral-chain testnet4 on 0.0.0.0:8099 against the box's pruned testnet4 node
#     (read-only: getblockcount, scantxoutset, gettxout; cookie auth), state in ~/shz-staging-testnet4.
#     The daemon starts only once OPERATOR=<txid:vout> names a funded <O> CHECKSIG output; it stages
#     each settlement (testmempoolaccept + the sendrawtransaction command) and broadcasts only with
#     BROADCAST=1.
#
# Binaries (bin/shz-venue, bin/shz_batcher) and ui/ are copied into ~/shz-staging by the operator.
set -euo pipefail
NET="${NET:-regtest}"
BASE="$HOME/shz-staging"
BTC="$HOME/rehearsal/btc"
if [ "$NET" = regtest ]; then
  S="$BASE"; VPORT="${VPORT:-8098}"; PORT=18843
  mkdir -p "$S/btc"
  [ -f "$S/rpcpass" ] || (umask 077; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$S/rpcpass")
  PASS=$(cat "$S/rpcpass"); (umask 077; printf 'staging:%s' "$PASS" > "$S/rpcauth")
  AUTH="$S/rpcauth"
  CLI_ARGS="-regtest -rpcuser=staging -rpcpassword=$PASS -rpcport=$PORT -datadir=$S/btc"
  EPOCH_FLAGS=(--refund-delta 144)
  VENUE_FLAGS=(--refund-blocks 288 --min-lock 60 --min-conf 1 --chain-poll-ms 5000)
else
  S="$HOME/shz-staging-testnet4"; VPORT="${VPORT:-8099}"; PORT=48332
  AUTH="$HOME/rehearsal/btc-data/testnet4/.cookie"
  CLI_ARGS="-testnet4 -datadir=$HOME/rehearsal/btc-data -rpcport=$PORT"
  EPOCH_FLAGS=(--refund-delta 432)
  VENUE_FLAGS=(--refund-blocks 432 --min-lock 144 --min-conf 1 --chain-poll-ms 30000)
fi
mkdir -p "$S/venue" "$S/daemon" "$S/receipts" "$S/logs" "$S/run"
cli() { "$BTC/bitcoin-cli" $CLI_ARGS "$@"; }
alive() { [ -f "$S/run/$1.pid" ] && kill -0 "$(cat "$S/run/$1.pid")" 2>/dev/null; }
spawn() { local name=$1; shift; nohup "$@" >>"$S/logs/$name.log" 2>&1 & echo $! > "$S/run/$name.pid"; }
keys() {
  [ -f "$S/batcher-keys.json" ] || (umask 077; python3 -c "import json,secrets;print(json.dumps({'batcher_sk':secrets.token_hex(32),'operator_sk':secrets.token_hex(32)}))" > "$S/batcher-keys.json")
  PK=$("$BASE/bin/shz_batcher" pubkeys --keys "$S/batcher-keys.json")
  BKEY=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['batcher'])" "$PK")
  OSPK=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['operator_spk'])" "$PK")
}
op_address() { cli deriveaddresses "$(cli getdescriptorinfo "raw($OSPK)" | python3 -c 'import json,sys;print(json.load(sys.stdin)["descriptor"])')" | python3 -c 'import json,sys;print(json.load(sys.stdin)[0])'; }

start() {
  if [ "$NET" = regtest ] && ! alive bitcoind; then
    spawn bitcoind "$BTC/bitcoind" -regtest -server=1 -txindex=1 -fallbackfee=0.0001 -rpcuser=staging -rpcpassword="$PASS" \
      -rpcport=$PORT -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -port=18844 -listen=0 -dnsseed=0 -dbcache=50 -maxmempool=50 -datadir="$S/btc"
    for _ in $(seq 100); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 0.5; done
  fi
  if [ "$NET" = regtest ]; then
    cli loadwallet w >/dev/null 2>&1 || cli createwallet w >/dev/null 2>&1 || true
    [ "$(cli getblockcount)" -ge 110 ] || cli generatetoaddress 110 "$(cli getnewaddress '' bech32m)" >/dev/null
  fi
  keys
  alive venue || spawn venue "$BASE/bin/shz-venue" --listen 0.0.0.0:$VPORT --state "$S/venue" --ui "$BASE/ui" --relay http://127.0.0.1:8091 \
    --collateral-chain "$NET" --bitcoind-rpc http://127.0.0.1:$PORT --bitcoind-auth-file "$AUTH" --batcher-key "$BKEY" "${VENUE_FLAGS[@]}"
  if [ "$NET" = regtest ] && ! alive miner; then
    SINK=$(cli getnewaddress '' bech32m)
    spawn miner bash -c "while true; do sleep 60; '$BTC/bitcoin-cli' $CLI_ARGS generatetoaddress 1 $SINK >/dev/null || exit 1; done"
  fi
  COMMON=(--network "$NET" --cli "$BTC/bitcoin-cli" --cli-args "$CLI_ARGS" --keys "$S/batcher-keys.json" --state "$S/daemon" --venue "http://127.0.0.1:$VPORT" --receipts "$S/receipts")
  if [ ! -f "$S/daemon/state.json" ]; then
    if [ "$NET" = regtest ]; then
      OTX=$(cli sendtoaddress "$(op_address)" 0.05)
      cli generatetoaddress 1 "$(cli getnewaddress '' bech32m)" >/dev/null
      OV=$(cli getrawtransaction "$OTX" true | python3 -c "import json,sys;t=json.load(sys.stdin);print([o['n'] for o in t['vout'] if o['scriptPubKey']['hex']==sys.argv[1]][0])" "$OSPK")
      OPERATOR="$OTX:$OV"; sleep 2
    fi
    if [ -z "${OPERATOR:-}" ]; then
      echo "daemon not started: fund the operator's <O> CHECKSIG output $(op_address) on $NET, then OPERATOR=<txid:vout> NET=$NET $0 start"
    else
      "$BASE/bin/shz_batcher" init "${COMMON[@]}" --epoch-secs 900 --operator "$OPERATOR"
    fi
  fi
  BC=(); [ "${BROADCAST:-0}" = 1 ] && BC=(--broadcast)
  if [ -f "$S/daemon/state.json" ] && ! alive daemon; then
    spawn daemon "$BASE/bin/shz_batcher" run "${COMMON[@]}" --epoch-secs 900 --sign-secs 180 --settle-delay-secs 5 \
      --oracle --attest-wait-secs 300 "${EPOCH_FLAGS[@]}" --fee-rate 1 --bump-rate 5 --bump-after-blocks 3 "${BC[@]}"
  fi
  status
}
stop() {
  for n in daemon miner venue; do alive $n && kill "$(cat "$S/run/$n.pid")" || true; done
  if [ "$NET" = regtest ]; then cli stop >/dev/null 2>&1 || true; fi
}
status() {
  for n in bitcoind venue miner daemon; do printf '%-9s %s\n' $n "$(alive $n && echo "up (pid $(cat "$S/run/$n.pid"))" || echo down)"; done
  echo "$NET tip $(cli getblockcount 2>/dev/null || echo '-')"
  curl -s -m 3 http://127.0.0.1:$VPORT/api/status | python3 -c 'import json,sys;s=json.load(sys.stdin);print("venue", s["network"], "collateral", json.dumps(s["collateral"]))' 2>/dev/null || echo "venue unreachable"
}
faucet() { [ "$NET" = regtest ] || { echo "faucet is regtest only"; exit 2; }; cli sendtoaddress "$1" "${2:-0.002}"; }
case "${1:-status}" in start) start ;; stop) stop ;; status) status ;; faucet) faucet "$2" "${3:-}" ;; *) echo "usage: NET=regtest|testnet4 $0 start|stop|status|faucet <address> [btc]"; exit 2 ;; esac
