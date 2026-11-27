#!/usr/bin/env bash
# Staging run of shz-batcher on the witness box: its own regtest bitcoind, the daemon under
# ops/shz-batcher/shz-batcher.service (instance "staging"), fresh trader keys generated here, and a
# venue on VENUE_URL (default: mock_venue.py on 127.0.0.1:8197 replaying venue batches 306..313;
# set VENUE_URL to a real staging venue speaking the co-sign contract to use it instead).
# Touches no existing unit; every unit it starts is named shz-batcher* or shz-staging-*.
#
#   sudo STAGE=/tmp/shz-batcher-stage bash staging_box.sh setup     # install and fund
#   sudo bash staging_box.sh start | stop | collect
set -euo pipefail
STAGE="${STAGE:-/tmp/shz-batcher-stage}"   # uploaded: shz_batcher, mock_venue.py, drill_plan.json, venue_batches.json, shz-batcher.service
SRC_BTC="${SRC_BTC:-/home/ubuntu/rehearsal/btc}"   # Bitcoin Core 31.1 binaries, copied to $BTC
BTC=/opt/shz-batcher/btc
U=shzbatcher
HOME_DIR=/var/lib/shz-batcher
NODE=$HOME_DIR/regtest
PORT=18543
VPORT=8197
VENUE_URL="${VENUE_URL:-http://127.0.0.1:$VPORT}"
EPOCH="${EPOCH:-120}"
CLI_ARGS="-regtest -rpcuser=shzstage -rpcpassword=shzstage -rpcport=$PORT -datadir=$NODE"
cli() { sudo -u $U "$BTC/bitcoin-cli" $CLI_ARGS "$@"; }
SB=/opt/shz-batcher/bin/shz_batcher

case "${1:-}" in
setup)
  id $U >/dev/null 2>&1 || useradd --system --home-dir $HOME_DIR --shell /usr/sbin/nologin $U
  mkdir -p /opt/shz-batcher/bin /opt/shz-batcher/btc /opt/shz-batcher/receipts /opt/shz-batcher/share /etc/shz-batcher $HOME_DIR/staging $NODE
  install -m 0755 "$STAGE/shz_batcher" $SB
  install -m 0755 "$SRC_BTC/bitcoind" "$SRC_BTC/bitcoin-cli" $BTC/
  install -m 0644 "$STAGE/mock_venue.py" "$STAGE/drill_plan.json" "$STAGE/venue_batches.json" /opt/shz-batcher/share/
  install -m 0644 "$STAGE/shz-batcher.service" /etc/systemd/system/shz-batcher@.service
  chown -R $U:$U $HOME_DIR /opt/shz-batcher/receipts
  systemctl daemon-reload
  systemctl is-active --quiet shz-staging-regtest || systemd-run --unit=shz-staging-regtest --uid=$U \
    "$BTC/bitcoind" -regtest -server=1 -txindex=1 -fallbackfee=0.0001 -rpcuser=shzstage -rpcpassword=shzstage \
    -rpcport=$PORT -port=18544 -listen=0 -dnsseed=0 -dbcache=50 -maxmempool=50 -datadir=$NODE
  for _ in $(seq 100); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 0.5; done
  cli createwallet w >/dev/null 2>&1 || cli loadwallet w >/dev/null 2>&1 || true
  SINK=$(cli getnewaddress "" bech32m); echo "$SINK" > $HOME_DIR/sink
  [ "$(cli getblockcount)" -ge 110 ] || cli generatetoaddress 110 "$SINK" >/dev/null
  # keys generated on this host, never copied: batcher/operator and four drill traders
  K=/etc/shz-batcher/staging-keys.json; T=$HOME_DIR/staging-traders.json
  [ -f $K ] || python3 -c "import json,secrets;print(json.dumps({'batcher_sk':secrets.token_hex(32),'operator_sk':secrets.token_hex(32)}))" > $K
  [ -f $T ] || python3 -c "import json,secrets;print(json.dumps({'accounts':[secrets.token_hex(32) for _ in range(8)]}))" > $T
  chown $U:$U $K $T; chmod 0600 $K $T
  COMMON="--network regtest --cli $BTC/bitcoin-cli --keys $K --state $HOME_DIR/staging --receipts /opt/shz-batcher/receipts"
  sudo -u $U $SB drill-setup $COMMON --cli-args "$CLI_ARGS" --venue "$VENUE_URL" --refund-delta 40 --trader-keys $T \
    --channels /opt/shz-batcher/share/venue_batches.json --collateral 20000 --liquidity 200000 --out $HOME_DIR/registry.json | tee $HOME_DIR/setup.json
  ;;
start)
  K=/etc/shz-batcher/staging-keys.json; T=$HOME_DIR/staging-traders.json
  COMMON="--network regtest --cli $BTC/bitcoin-cli --keys $K --state $HOME_DIR/staging --receipts /opt/shz-batcher/receipts --venue $VENUE_URL"
  BKEY=$(sudo -u $U $SB pubkeys --keys $K | python3 -c "import json,sys;print(json.load(sys.stdin)['batcher'])")
  OPERATOR=$(python3 -c "import json;print(json.load(open('$HOME_DIR/setup.json'))['operator'])")
  NOW=$(date +%s); T0=$(( (NOW + 60 + EPOCH - 1) / EPOCH * EPOCH ))
  if [ "$VENUE_URL" = "http://127.0.0.1:$VPORT" ]; then
    python3 - "$EPOCH" <<'PY'
import json,sys
p=json.load(open('/opt/shz-batcher/share/drill_plan.json')); p['epoch_secs']=int(sys.argv[1])
for b in p['batches']: b['at']=int(b['at']*int(sys.argv[1])/90)
json.dump(p,open('/var/lib/shz-batcher/plan.json','w'))
PY
    systemd-run --unit=shz-staging-venue --uid=$U python3 /opt/shz-batcher/share/mock_venue.py --port $VPORT \
      --source /opt/shz-batcher/share/venue_batches.json --plan $HOME_DIR/plan.json --registry $HOME_DIR/registry.json \
      --batcher-key "$BKEY" --t0 $T0 --log $HOME_DIR/venue.log
    sleep 1
  fi
  rm -f $HOME_DIR/staging/state.json
  sudo -u $U $SB init $COMMON --cli-args "$CLI_ARGS" --epoch-secs $EPOCH --operator "$OPERATOR" --start-seq 0 --t0 $T0
  cat > /etc/shz-batcher/staging.env <<EOF
SHZ_BATCHER_CLI_ARGS="$CLI_ARGS"
SHZ_BATCHER_ARGS=$COMMON --epoch-secs $EPOCH --sign-secs 30 --settle-delay-secs 3 --oracle --attest-wait-secs 20 --refund-delta 40 --fee-rate 1 --bump-rate 5 --bump-after-blocks 0 --bump-after-secs 10
EOF
  systemd-run --unit=shz-staging-traders --uid=$U $SB traders --venue "$VENUE_URL" --trader-keys $T --refuse 2:2 --withdraw 5:2 --for-secs $((EPOCH * 8))
  systemd-run --unit=shz-staging-miner --uid=$U /bin/sh -c "while true; do sleep 30; $BTC/bitcoin-cli $CLI_ARGS generatetoaddress 1 \$(cat $HOME_DIR/sink) >/dev/null; done"
  systemctl start shz-batcher@staging
  echo "t0 $T0; journalctl -u shz-batcher@staging -f"
  ;;
stop)
  systemctl stop shz-batcher@staging shz-staging-traders shz-staging-miner shz-staging-venue 2>/dev/null || true
  ;;
collect)
  OUT=/tmp/shz-batcher-staging-receipts; rm -rf $OUT; mkdir -p $OUT
  cp -r /opt/shz-batcher/receipts/. $OUT/
  journalctl -u shz-batcher@staging --no-pager -o short-unix > $OUT/daemon.log
  journalctl -u shz-staging-traders --no-pager -o short-unix > $OUT/traders.log
  cp $HOME_DIR/venue.log $OUT/ 2>/dev/null || true
  sudo -u $U $SB status --state $HOME_DIR/staging > $OUT/state_after.json
  curl -s "$VENUE_URL/api/explorer/settlements" > $OUT/venue_settlements.json
  cli getblockchaininfo > $OUT/chain.json
  systemctl show shz-batcher@staging -p ActiveState -p NRestarts -p ExecMainStartTimestamp > $OUT/unit.txt
  chmod -R a+rX $OUT; echo $OUT
  ;;
*) echo "usage: $0 setup|start|stop|collect"; exit 2 ;;
esac
