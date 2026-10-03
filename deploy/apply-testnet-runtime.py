#!/usr/bin/env python3
"""sudo.set_code for the live testnet. Signs as the recut sudo, never Alith.

Reads the sudo uri from SUDO_URI, /root/sudo.txt, or /tmp/sudo.txt.
Does not print secrets. Does not send unless the signer is the live sudo.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from substrateinterface import Keypair, KeypairType, SubstrateInterface

LIVE_SUDO = "0x1681a02bA0008469F4380f246622E62fC170437b"
ALITH = "0xf24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
WASM = Path("/root/arxon-node/target/release/wbuild/arxon-runtime/arxon_runtime.compact.compressed.wasm")
RUNTIME_SRC = Path("/root/arxon-node/template/runtime/src/lib.rs")
BIN = Path("/root/arxon-node/target/release/arxon-node")
RPC = "ws://127.0.0.1:9944"
CANDIDATES = [Path("/root/sudo.txt"), Path("/tmp/sudo.txt")]
if os.environ.get("SUDO_FILE"):
	CANDIDATES.insert(0, Path(os.environ["SUDO_FILE"]))


def target_spec_version() -> int:
	match = re.search(r"^\s*spec_version:\s*(\d+),", RUNTIME_SRC.read_text(), re.MULTILINE)
	if not match:
		raise SystemExit("no spec_version in %s" % RUNTIME_SRC)
	return int(match.group(1))


def spec_version(substrate: SubstrateInterface) -> int:
	ver = substrate.rpc_request("state_getRuntimeVersion", [])
	if isinstance(ver, dict) and "specVersion" not in ver:
		ver = ver.get("result", ver)
	return int(ver["specVersion"])


def uri_from_file(path: Path) -> str:
	text = path.read_text(errors="replace")
	env_uri = (os.environ.get("SUDO_URI") or "").strip()
	if env_uri:
		return env_uri
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
			return tok if tok.startswith("0x") else "0x" + tok
	words = [w for w in text.replace("\n", " ").split() if w.isalpha() and len(w) >= 3]
	if len(words) >= 12:
		return " ".join(words[:24] if len(words) >= 24 else words[:12])
	raise SystemExit("no secret seed or 12-word phrase in %s" % path)


def inspect_seed(uri: str) -> str:
	if not BIN.is_file():
		raise SystemExit("missing %s" % BIN)
	proc = subprocess.run(
		[str(BIN), "key", "inspect", "--scheme", "ecdsa", uri],
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
	raise SystemExit("key inspect did not yield a 32-byte seed")


def keypair_of(seed: str) -> Keypair:
	raw = seed if seed.startswith("0x") else "0x" + seed
	kp = Keypair.create_from_private_key(raw, crypto_type=KeypairType.ECDSA)
	addr = kp.ss58_address
	print("signer", addr)
	if addr.lower() == ALITH.lower():
		raise SystemExit("refusing Alith; live sudo is %s" % LIVE_SUDO)
	if addr.lower() != LIVE_SUDO.lower():
		raise SystemExit("signer is not live sudo %s" % LIVE_SUDO)
	return kp


def main() -> int:
	if not WASM.is_file():
		print("missing wasm:", WASM)
		return 1
	code = WASM.read_bytes()
	print("wasm bytes:", len(code))

	target = target_spec_version()
	print("spec target:", target)
	substrate = SubstrateInterface(url=RPC)
	before = spec_version(substrate)
	print("spec before:", before)
	if before >= target:
		print("already spec %s; nothing to do" % before)
		return 0

	uri = (os.environ.get("SUDO_URI") or "").strip()
	if not uri:
		path = next((p for p in CANDIDATES if p.is_file()), None)
		if path is None:
			print("missing sudo file; put the live sudo seed or phrase in /root/sudo.txt")
			return 2
		print("sudo_file", path)
		uri = uri_from_file(path)
	print("uri_kind", "hex" if uri.startswith("0x") else "words", "parts", len(uri.split()))
	kp = keypair_of(inspect_seed(uri))

	inner = substrate.compose_call(
		call_module="System",
		call_function="set_code",
		call_params={"code": "0x" + code.hex()},
	)
	call = substrate.compose_call(
		call_module="Sudo",
		call_function="sudo_unchecked_weight",
		call_params={
			"call": inner,
			"weight": {"ref_time": 0, "proof_size": 0},
		},
	)
	extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
	receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
	print("extrinsic", receipt.extrinsic_hash, "finalized", receipt.is_success)
	if not receipt.is_success:
		print("error", receipt.error_message)
		return 1

	substrate = SubstrateInterface(url=RPC)
	after = spec_version(substrate)
	print("spec after:", after)
	return 0 if after == target else 2


if __name__ == "__main__":
	sys.exit(main())
