#!/bin/bash
set -euo pipefail
SRC=/root/arxon-node/deploy
UNIT=/etc/systemd/system
VENV=/root/relayer-venv

test -f "$SRC/relayer.py"
test -x /root/arxon-node/target/release/arxon-node

if [ ! -x "$VENV/bin/python3" ]; then
	python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q eth-account eth-abi
"$VENV/bin/python3" -c "from eth_account import Account; from eth_abi import decode"

cp "$SRC/relayer.py" /root/relayer.py
cp "$SRC/run-relayer.sh" /root/run-relayer
cp "$SRC/run-tunnel.sh" /root/run-tunnel
chmod 755 /root/run-relayer /root/run-tunnel /root/relayer.py
cp "$SRC/arxon-relayer.service" "$UNIT/arxon-relayer.service"
cp "$SRC/arxon-tunnel.service" "$UNIT/arxon-tunnel.service"
chmod 644 "$UNIT/arxon-relayer.service" "$UNIT/arxon-tunnel.service"
systemctl daemon-reload
systemctl enable arxon-relayer.service
systemctl restart arxon-relayer.service
systemctl restart arxon-tunnel.service
echo relayer
systemctl is-active arxon-relayer
echo tunnel
systemctl is-active arxon-tunnel
