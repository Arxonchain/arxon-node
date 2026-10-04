#!/usr/bin/env python3
"""Insert Aura/Grandpa into /root/arxon-chain. Does not print seeds. Does not restart."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BIN = "/root/arxon-node/target/release/arxon-node"
CHAIN = "/root/arxon-spec-raw.json"
BASE = "/root/arxon-chain"
NODE_KEY = "/root/nk-test"
RUN = Path("/root/run-node")


def seed_from(path: Path) -> str:
	text = path.read_text(errors="replace")
	for line in text.splitlines():
		low = line.lower()
		if "secret seed" in low:
			tok = line.strip().split()[-1]
			if tok.startswith("0x"):
				return tok
	for line in text.splitlines():
		tok = line.strip()
		if tok.startswith("0x") and len(tok) >= 66:
			return tok
	raise SystemExit("no secret seed in %s" % path)


def run(cmd: list[str]) -> None:
	print("run", " ".join(cmd[:6]), "...", flush=True)
	proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	err = (proc.stderr or b"").decode("utf-8", "replace")
	out = (proc.stdout or b"").decode("utf-8", "replace")
	if proc.returncode != 0:
		print(out[-500:])
		print(err[-1500:])
		raise SystemExit("failed %s" % proc.returncode)
	if out.strip():
		print(out.strip()[-500:])
	if err.strip():
		print(err.strip()[-500:])


def main() -> int:
	aura_file = Path("/tmp/aura.txt")
	gran_file = Path("/tmp/grandpa.txt")
	if not aura_file.is_file():
		raise SystemExit("missing /tmp/aura.txt")
	if not gran_file.is_file():
		print("missing /tmp/grandpa.txt")
		print("put the Grandpa secret seed in that file, one 0x line, then rerun")
		return 2
	if not Path(CHAIN).is_file():
		raise SystemExit("missing %s" % CHAIN)
	aura = seed_from(aura_file)
	gran = seed_from(gran_file)
	print("aura_seed_len", len(aura), "gran_seed_len", len(gran))
	Path(BASE).mkdir(parents=True, exist_ok=True)
	if not Path(NODE_KEY).is_file():
		run([BIN, "key", "generate-node-key", "--file", NODE_KEY])
	else:
		print("keep", NODE_KEY)
	ins = [BIN, "key", "insert", "--base-path", BASE, "--chain", CHAIN]
	run(ins + ["--scheme", "sr25519", "--suri", aura, "--key-type", "aura"])
	print("inserted aura")
	run(ins + ["--scheme", "ed25519", "--suri", gran, "--key-type", "gran"])
	print("inserted gran")
	ks = Path(BASE) / "chains" / "arxon_testnet" / "keystore"
	keys = sorted(p.name for p in ks.glob("*")) if ks.is_dir() else []
	print("keystore", ks, "files", len(keys))
	for name in keys:
		print(" key", name[:8])
	RUN.write_text(
		"exec %s --base-path %s --chain %s --validator --node-key-file %s --rpc-cors all --blocks-pruning archive --state-pruning archive\n"
		% (BIN, BASE, CHAIN, NODE_KEY)
	)
	print("wrote", RUN)
	print("ready")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
