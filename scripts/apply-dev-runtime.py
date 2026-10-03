#!/usr/bin/env python3
"""Apply the newly built runtime Wasm via sudo.set_code (dev Alith key)."""

from pathlib import Path
import re
import sys

from substrateinterface import Keypair, KeypairType, SubstrateInterface

ALITH_PRIV = "0x5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133"
ALITH = "0xf24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
WASM = Path("/root/arxon-node/target/release/wbuild/arxon-runtime/arxon_runtime.compact.compressed.wasm")
RPC = "ws://127.0.0.1:9944"
RUNTIME_SRC = Path(__file__).resolve().parent.parent / "template/runtime/src/lib.rs"


def target_spec_version() -> int:
	"""spec_version of the runtime being applied, read from the source it was built from."""
	match = re.search(r"^\s*spec_version:\s*(\d+),", RUNTIME_SRC.read_text(), re.MULTILINE)
	if not match:
		raise SystemExit(f"no spec_version in {RUNTIME_SRC}")
	return int(match.group(1))


def spec_version(substrate: SubstrateInterface) -> int:
	ver = substrate.rpc_request("state_getRuntimeVersion", [])
	print("runtime rpc:", ver)
	if isinstance(ver, dict) and "specVersion" not in ver:
		ver = ver.get("result", ver)
	return int(ver["specVersion"])


def main() -> int:
	if not WASM.is_file():
		print("missing wasm:", WASM)
		return 1
	code = WASM.read_bytes()
	print("wasm bytes:", len(code))

	substrate = SubstrateInterface(url=RPC)
	before = spec_version(substrate)
	print("spec before:", before)

	target = target_spec_version()
	print("spec target:", target)
	if before >= target:
		print(f"already spec {before}; nothing to do")
		return 0

	keypair = Keypair.create_from_private_key(ALITH_PRIV, crypto_type=KeypairType.ECDSA)
	print("signer:", keypair.ss58_address, "expected", ALITH)
	if keypair.ss58_address.lower() != ALITH.lower():
		print("refusing to submit: signer is not Alith")
		return 1

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
	extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)
	receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
	print("extrinsic:", receipt.extrinsic_hash, "finalized:", receipt.is_success)
	if not receipt.is_success:
		print("error:", receipt.error_message)
		return 1

	substrate = SubstrateInterface(url=RPC)
	after = spec_version(substrate)
	print("spec after:", after)
	return 0 if after == target else 2


if __name__ == "__main__":
	sys.exit(main())
