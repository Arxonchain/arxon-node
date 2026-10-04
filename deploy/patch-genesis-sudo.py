#!/usr/bin/env python3
"""Replace mistyped genesis sudo with the EVM address of /tmp/sudo.txt. No seeds."""

from __future__ import annotations

import subprocess
from pathlib import Path

from eth_account import Account

BIN = "/root/arxon-node/target/release/arxon-node"
SUDO_FILE = Path("/tmp/sudo.txt")
SPEC = Path("/root/arxon-node/template/node/src/chain_spec.rs")
OLD = "1681a02ba0008469f4380f246622e62fc170437b"


def uri_from(text: str) -> str:
	for line in text.splitlines():
		low = line.lower()
		if "secret seed" in low:
			tok = line.strip().split()[-1]
			if tok.startswith("0x"):
				return tok
		if "secret phrase" in low:
			phrase = line.split(":", 1)[-1].strip()
			if len(phrase.split()) >= 12:
				return phrase
	for line in text.splitlines():
		tok = line.strip()
		if tok.startswith("0x") and len(tok) in (64, 66):
			return tok
	words = [w for w in text.replace("\n", " ").split() if w.isalpha() and len(w) >= 3]
	if len(words) >= 12:
		return " ".join(words[:24] if len(words) >= 24 else words[:12])
	raise SystemExit("no seed or phrase in %s" % SUDO_FILE)


def inspect_seed(uri: str) -> str:
	proc = subprocess.run(
		[BIN, "key", "inspect", "--scheme", "ecdsa", uri],
		capture_output=True,
		text=True,
		timeout=60,
	)
	if proc.returncode != 0:
		raise SystemExit("key inspect failed")
	for line in (proc.stdout or "").splitlines():
		if "secret seed" in line.lower():
			tok = line.strip().split()[-1]
			if tok.startswith("0x") and len(tok) == 66:
				return tok
	if uri.startswith("0x") and len(uri) in (64, 66):
		return uri if uri.startswith("0x") else "0x" + uri
	raise SystemExit("inspect gave no seed")


def hex40() -> str:
	uri = uri_from(SUDO_FILE.read_text(errors="replace"))
	seed = inspect_seed(uri)
	raw = seed if seed.startswith("0x") else "0x" + seed
	h = Account.from_key(raw).address.lower()[2:]
	if len(h) != 40:
		raise SystemExit("not 40 hex: %s len %s" % (h, len(h)))
	if h == OLD:
		raise SystemExit("derived address is the old typo")
	return h


def main() -> int:
	new = hex40()
	text = SPEC.read_text()
	low = text.lower()
	n_old = low.count(OLD)
	if n_old < 1:
		if new in low:
			print("already patched", new)
			return 0
		raise SystemExit("old sudo hex not in chain_spec.rs")
	if "2a022a04" not in low or "f55260f2" not in low:
		raise SystemExit("refusing to patch: treasury or relayer missing")
	chunks = []
	idx = 0
	lower = text.lower()
	while True:
		j = lower.find(OLD, idx)
		if j < 0:
			chunks.append(text[idx:])
			break
		chunks.append(text[idx:j])
		chunks.append(new)
		idx = j + len(OLD)
	patched = "".join(chunks)
	if OLD in patched.lower():
		raise SystemExit("old typo still present")
	if patched.lower().count(new) < n_old:
		raise SystemExit("new hex not written enough times")
	SPEC.write_text(patched)
	print("replaced", n_old, "old sudo hex")
	print("new_hex40", new)
	print("treasury_ok", "2a022a04" in patched.lower())
	print("relayer_ok", "f55260f2" in patched.lower())
	print("typo_gone", OLD not in patched.lower())
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
