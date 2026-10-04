#!/usr/bin/env python3
"""Stop node, park OCR-era DB, keep /root/arxon-zk. Does not print seeds."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

CHAIN = Path("/root/arxon-chain")
PARK = Path("/root/arxon-chain-ocr-d286")
ZK = Path("/root/arxon-zk")
SPEC = Path("/root/arxon-spec-raw.json")


def run(cmd: list[str]) -> None:
	print("run", " ".join(cmd), flush=True)
	proc = subprocess.run(cmd)
	if proc.returncode != 0:
		raise SystemExit("failed %s" % proc.returncode)


def main() -> int:
	if ZK.exists():
		print("keep", ZK)
	else:
		print("no", ZK)
	if not SPEC.is_file():
		print("missing", SPEC)
		return 2
	text = SPEC.read_text(errors="replace")
	print("spec_bytes", SPEC.stat().st_size)
	print("spec_has_typo_e62f", "e62fc170437b" in text.lower())
	print("spec_has_f552", "f55260f2" in text.lower())
	print("spec_has_d286", "d286bd6b" in text.lower())
	print("spec_has_23992", "23992ac0" in text.lower())
	run(["systemctl", "stop", "arxon-node"])
	if CHAIN.exists():
		if PARK.exists():
			print("park already exists", PARK)
			bak = Path("/root/arxon-chain-ocr-d286.bak")
			if bak.exists():
				shutil.rmtree(bak)
			CHAIN.rename(bak)
			print("moved live chain to", bak)
		else:
			CHAIN.rename(PARK)
			print("moved", CHAIN, "to", PARK)
	else:
		print("no live chain dir")
	CHAIN.mkdir(parents=True, exist_ok=True)
	print("empty", CHAIN)
	print("zk_still", ZK.exists())
	print("stopped. next insert keys then systemctl start arxon-node")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
