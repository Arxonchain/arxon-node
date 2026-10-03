#!/usr/bin/env python3
"""Find which file on the box is live sudo. Prints paths only. No seeds."""

from __future__ import annotations

import os
from pathlib import Path

from eth_account import Account

LIVE = "1681a02ba0008469f4380f246622e62fc170437b"
BIN = "/root/arxon-node/target/release/arxon-node"


def eth_of_seed(seed: str) -> str:
	raw = seed if seed.startswith("0x") else "0x" + seed
	return Account.from_key(raw).address.lower()[2:]


def seed_from(text: str) -> str | None:
	for line in text.splitlines():
		if "secret seed" in line.lower():
			tok = line.strip().split()[-1]
			if tok.startswith("0x") and len(tok) in (64, 66):
				return tok
	for line in text.splitlines():
		tok = line.strip().split()[-1] if line.strip() else ""
		if tok.startswith("0x") and len(tok) in (64, 66):
			try:
				return tok
			except Exception:
				pass
	return None


def phrase_from(text: str) -> str | None:
	for line in text.splitlines():
		if "secret phrase" in line.lower():
			phrase = line.split(":", 1)[-1].strip()
			if len(phrase.split()) >= 12:
				return phrase
	return None


def inspect_seed(uri: str) -> str | None:
	import subprocess

	proc = subprocess.run(
		[BIN, "key", "inspect", "--scheme", "ecdsa", uri],
		capture_output=True,
		text=True,
		timeout=60,
	)
	if proc.returncode != 0:
		return None
	for line in (proc.stdout or "").splitlines():
		if "secret seed" in line.lower():
			tok = line.strip().split()[-1]
			if tok.startswith("0x") and len(tok) == 66:
				return tok
	return None


def check(path: Path) -> None:
	try:
		text = path.read_text(errors="replace")
	except Exception as exc:
		print("skip", path, type(exc).__name__)
		return
	seed = seed_from(text)
	phrase = phrase_from(text)
	got = None
	kind = None
	if seed:
		try:
			got = eth_of_seed(seed)
			kind = "seed"
		except Exception:
			got = None
	if got != LIVE and phrase:
		ins = inspect_seed(phrase)
		if ins:
			try:
				got = eth_of_seed(ins)
				kind = "phrase"
			except Exception:
				got = None
	print(str(path), "match" if got == LIVE else "no", kind or "empty")


def main() -> None:
	seen = set()
	for folder in (Path("/tmp"), Path("/root")):
		if not folder.is_dir():
			continue
		for path in sorted(folder.glob("*.txt")):
			if path in seen:
				continue
			seen.add(path)
			check(path)
	print("want", LIVE)


if __name__ == "__main__":
	main()
