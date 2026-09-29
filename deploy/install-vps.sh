#!/bin/bash
# Copy unit files and enable services. Does not start them (tmux still owns 9944).
set -euo pipefail

ROOT=/root/arxon-node
SRC="$ROOT/deploy"
UNIT=/etc/systemd/system

test -x "$ROOT/target/release/arxon-node"
test -x /root/cloudflared
test -f /etc/cloudflared/t.json
test -e /root/nk
test -d /root/arxon-zk

cp "$SRC/run-node.sh" /root/run-node
cp "$SRC/run-tunnel.sh" /root/run-tunnel
cp "$SRC/run-relayer.sh" /root/run-relayer
cp "$SRC/relayer.py" /root/relayer.py
chmod 755 /root/run-node /root/run-tunnel /root/run-relayer /root/relayer.py
cp "$SRC/arxon-node.service" "$UNIT/arxon-node.service"
cp "$SRC/arxon-tunnel.service" "$UNIT/arxon-tunnel.service"
cp "$SRC/arxon-relayer.service" "$UNIT/arxon-relayer.service"
chmod 644 "$UNIT/arxon-node.service" "$UNIT/arxon-tunnel.service" "$UNIT/arxon-relayer.service"
systemctl daemon-reload
systemctl enable arxon-node.service arxon-tunnel.service arxon-relayer.service

echo installed
echo stop tmux windows 0 and 3 then:
echo systemctl start arxon-node
echo systemctl start arxon-tunnel
