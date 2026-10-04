#!/usr/bin/env python3
"""Write the EVM address of /tmp/sudo.txt into local_testnet genesis. No seeds."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from eth_account import Account

BIN = "/root/arxon-node/target/release/arxon-node"
SUDO_FILE = Path("/tmp/sudo.txt")
SPEC = Path("/root/arxon-node/template/node/src/chain_spec.rs")
OLD = "1681a02ba0008469f4380f246622e62fc170437b"
KEEP = {
	"2a022a04e3d0ea66b8157c9b3c0510db52b8a286",
	"f55260f227cb6a1b5a4cafb4dd365a0531b41fa7",
}
HEX_RE = re.compile(r'hex!\("([0-9a-fA-F]+)"\)')


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
	if not re.fullmatch(r"[0-9a-f]{40}", h):
		raise SystemExit("derived hex not 40 lowercase")
	return h


def dump_hexes(text: str, label: str) -> None:
	print("scan", label, "bytes", len(text))
	print("has_local", "local_testnet_config" in text)
	print("has_typo_e62f", OLD in text.lower())
	print("has_treasury", "2a022a04" in text.lower())
	print("has_relayer", "f55260f2" in text.lower())
	print("has_d286", "d286bd6b" in text.lower())
	print("has_alith", "f24ff3a9" in text.lower())
	lens = [len(m.group(1)) for m in HEX_RE.finditer(text)]
	print("hex_lens", sorted(set(lens)))


def restore_from_git() -> str:
	env = os.environ.copy()
	env["GIT_PAGER"] = "cat"
	env["PAGER"] = "cat"
	proc = subprocess.run(
		["git", "-c", "core.pager=", "show", "origin/feat/arx-20:template/node/src/chain_spec.rs"],
		cwd="/root/arxon-node",
		capture_output=True,
		text=True,
		timeout=60,
		env=env,
	)
	if proc.returncode != 0:
		err = (proc.stderr or "").strip()[:400]
		raise SystemExit("git show spec failed %s" % err)
	SPEC.parent.mkdir(parents=True, exist_ok=True)
	SPEC.write_text(proc.stdout)
	print("restored spec from origin feat/arx-20")
	return proc.stdout


def patch_local(text: str, new: str) -> str:
	start = text.find("pub fn local_testnet_config")
	if start < 0:
		raise SystemExit("no local_testnet_config")
	end = text.find("\nfn testnet_genesis", start)
	if end < 0:
		raise SystemExit("no testnet_genesis after local")
	section = text[start:end]
	n = 0

	def repl(m: re.Match[str]) -> str:
		nonlocal n
		h = m.group(1)
		if len(h) == 64:
			return m.group(0)
		if h.lower() in KEEP:
			return m.group(0)
		if len(h) in (40, 41):
			n += 1
			return 'hex!("%s")' % new
		return m.group(0)

	new_section = HEX_RE.sub(repl, section)
	print("replaced_slots", n)
	if n < 1:
		raise SystemExit("no sudo hex replaced in local_testnet")
	return text[:start] + new_section + text[end:]


def main() -> int:
	new = hex40()
	print("new_hex40", new)
	print("new_len", len(new))
	text = SPEC.read_text() if SPEC.is_file() else ""
	dump_hexes(text, "before")
	low = text.lower()
	need = (
		"2a022a04" not in low
		or "f55260f2" not in low
		or "local_testnet_config" not in text
	)
	if need:
		print("template missing treasury or relayer, restoring")
		text = restore_from_git()
		dump_hexes(text, "restored")
	patched = patch_local(text, new)
	pl = patched.lower()
	if OLD in pl:
		raise SystemExit("old typo still present")
	if pl.count(new) < 2:
		raise SystemExit("new hex not written enough times")
	if "2a022a04" not in pl or "f55260f2" not in pl:
		raise SystemExit("treasury or relayer missing after patch")
	if any(len(m.group(1)) == 41 for m in HEX_RE.finditer(patched)):
		raise SystemExit("41-char hex still present")
	SPEC.write_text(patched)
	print("new_hex40", new)
	print("new_len", len(new))
	print("contains_new", new in pl)
	print("treasury_ok", True)
	print("relayer_ok", True)
	print("typo_gone", True)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
