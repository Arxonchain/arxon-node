#!/usr/bin/env python3
"""Print the EVM sudo address for /tmp/sudo.txt. No seeds."""

from __future__ import annotations

import subprocess
from pathlib import Path

from eth_account import Account

BIN = "/root/arxon-node/target/release/arxon-node"
PATH = Path("/tmp/sudo.txt")
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
	raise SystemExit("no seed or phrase in %s" % PATH)


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


def main() -> int:
	uri = uri_from(PATH.read_text(errors="replace"))
	seed = inspect_seed(uri)
	raw = seed if seed.startswith("0x") else "0x" + seed
	addr = Account.from_key(raw).address
	h = addr.lower()[2:]
	print("eth", addr)
	print("hex40", h)
	print("len", len(h))
	print("is_typo_e62f", h == OLD)
	return 0 if len(h) == 40 else 2


if __name__ == "__main__":
	raise SystemExit(main())
