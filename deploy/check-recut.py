#!/usr/bin/env python3
"""Public checks after recut. No seeds."""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

URL = "http://127.0.0.1:9944"
SPEC = Path("/root/arxon-node/template/node/src/chain_spec.rs")
KEEP_TREASURY = "2a022a04e3d0ea66b8157c9b3c0510db52b8a286"
KEEP_RELAYER = "f55260f227cb6a1b5a4cafb4dd365a0531b41fa7"
OLD = "1681a02ba0008469f4380f246622e62fc170437b"
HEX_RE = re.compile(r'hex!\("([0-9a-fA-F]+)"\)')


def rpc(method: str, params: list | None = None) -> object:
	body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
	req = urllib.request.Request(
		URL,
		data=body.encode(),
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	with urllib.request.urlopen(req, timeout=20) as resp:
		payload = json.loads(resp.read().decode())
	if payload.get("error"):
		raise SystemExit("rpc %s %s" % (method, payload["error"]))
	return payload.get("result")


def sudo_hex() -> str:
	text = SPEC.read_text()
	start = text.find("pub fn local_testnet_config")
	end = text.find("\nfn testnet_genesis", start)
	section = text[start:end]
	found = []
	for m in HEX_RE.finditer(section):
		h = m.group(1).lower()
		if len(h) != 40:
			continue
		if h in (KEEP_TREASURY, KEEP_RELAYER):
			continue
		found.append(h)
	if not found:
		raise SystemExit("no sudo hex in local_testnet")
	return found[0]


def main() -> int:
	sudo = sudo_hex()
	print("sudo_hex40", sudo)
	print("sudo_len", len(sudo))
	print("is_typo_e62f", sudo == OLD)
	ver = rpc("state_getRuntimeVersion") or {}
	print("spec_name", ver.get("specName"))
	print("spec_version", ver.get("specVersion"))
	print("block", rpc("chain_getHeader"))
	print("eth_block", rpc("eth_blockNumber"))
	for label, h in (("sudo", sudo), ("treasury", KEEP_TREASURY), ("relayer", KEEP_RELAYER)):
		bal = rpc("eth_getBalance", ["0x" + h, "latest"])
		print("bal_" + label, bal)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
