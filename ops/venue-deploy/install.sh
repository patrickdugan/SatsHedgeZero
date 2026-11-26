#!/bin/bash
# Install shz-venue + resident market maker from a Linux checkout of this repo.
# Run from the repo root after `cargo build --release -p shz-venue`.
# Usage: sudo ops/venue-deploy/install.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=${BIN:-target/release/shz-venue}
test -x "$BIN"

id shzvenue >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin shzvenue
id shzvmm   >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin shzvmm

install -d -m 0755 /opt/shz-venue/bin /opt/shz-venue/ui /opt/shz-venue/ops/venue-mm /opt/shz-venue/ops/public-relay
install -m 0755 "$BIN" /opt/shz-venue/bin/shz-venue.new
mv -f /opt/shz-venue/bin/shz-venue.new /opt/shz-venue/bin/shz-venue

# UI: the page, explorer and vendored chart only (no mock server, no tests).
rm -rf /opt/shz-venue/ui.new
install -d -m 0755 /opt/shz-venue/ui.new
cp ui/venue/index.html ui/venue/explorer.html ui/venue/*.js ui/venue/venue.css /opt/shz-venue/ui.new/
rm -f /opt/shz-venue/ui.new/mock_server.mjs
cp -r ui/venue/vendor /opt/shz-venue/ui.new/
chmod -R a+rX /opt/shz-venue/ui.new
rm -rf /opt/shz-venue/ui && mv /opt/shz-venue/ui.new /opt/shz-venue/ui

install -m 0644 ops/venue-mm/mm.py ops/venue-mm/intent.py /opt/shz-venue/ops/venue-mm/
install -m 0644 ops/public-relay/bip340.py /opt/shz-venue/ops/public-relay/
sed -i 's/\r$//' /opt/shz-venue/ops/venue-mm/*.py /opt/shz-venue/ops/public-relay/*.py

install -m 0644 ops/venue-deploy/shz-venue.service ops/venue-deploy/shz-venue-mm.service ops/venue-deploy/shz-venue-mm-utxo.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now shz-venue.service
systemctl restart shz-venue.service
systemctl enable --now shz-venue-mm.service
# The UTXO maker starts only once the operator has placed its key and outpoint:
#   /var/lib/shz-venue-mm-utxo/mm.key (owner shzvmmu, 0600) and /etc/shz-venue/mm-utxo.env (UTXO=txid:vout).
id shzvmmu >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin shzvmmu
systemctl enable shz-venue-mm-utxo.service
if [ -f /var/lib/shz-venue-mm-utxo/mm.key ] && [ -f /etc/shz-venue/mm-utxo.env ]; then
  systemctl restart shz-venue-mm-utxo.service
fi

if ! grep -q 'shz-venue.170-75-168-145.sslip.io' /etc/caddy/Caddyfile; then
  cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date -u +%Y%m%dT%H%M%SZ)"
  { echo; cat ops/venue-deploy/Caddyfile.snippet; } >> /etc/caddy/Caddyfile
  systemctl reload caddy
fi
systemctl --no-pager --lines=0 status shz-venue shz-venue-mm
