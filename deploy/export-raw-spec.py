#!/usr/bin/env python3
"""Export --chain local identity, then raw spec. Public fields only."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

BIN = "/root/arxon-node/target/release/arxon-node"
OUT = Path("/root/arxon-spec-raw.json")
ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
LOG_LINE = re.compile(r"^(Script started|Script done|\d{4}-\d{2}-\d{2} )", re.M)


def parse_spec(blob: bytes) -> dict:
	blob = ANSI.sub(b"", blob).replace(b"\r", b"")
	text = blob.decode("utf-8", "replace")
	text = LOG_LINE.sub("", text)
	i, j = text.find("{"), text.rfind("}")
	if i < 0 or j <= i:
		raise SystemExit("no JSON object in build-spec output")
	return json.loads(text[i : j + 1])


def run_spec(*extra: str) -> subprocess.CompletedProcess:
	cmd = [BIN, "build-spec", "--disable-default-bootnode", *extra]
	print("run", " ".join(cmd), flush=True)
	env = os.environ.copy()
	env["RUST_LOG"] = "error"
	return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def find_patch(spec: dict) -> dict:
	gen = spec.get("genesis") or {}
	rg = gen.get("runtimeGenesis") or {}
	for k in ("patch", "config"):
		inner = rg.get(k)
		if isinstance(inner, dict) and ("sudo" in inner or "aura" in inner):
			return inner
	if isinstance(rg, dict) and ("sudo" in rg or "aura" in rg):
		return rg
	rt = gen.get("runtime")
	if isinstance(rt, dict):
		return rt
	raise SystemExit("no patch; genesis keys %s" % list(gen)[:20])


def main() -> int:
	proc = run_spec("--chain", "local")
	if proc.returncode != 0:
		print((proc.stderr or b"").decode("utf-8", "replace")[:4000])
		return 1
	spec = parse_spec(proc.stdout)
	p = find_patch(spec)
	print("name", spec.get("name"))
	print("id", spec.get("id"))
	print("chainType", spec.get("chainType"))
	print("aura", p.get("aura"))
	print("grandpa", p.get("grandpa"))
	print("sudo", p.get("sudo"))
	print("balances", p.get("balances"))
	print("evm_accounts", list(((p.get("evm") or {}).get("accounts") or {})))
	raw_proc = run_spec("--chain", "local", "--raw")
	print("raw_code", raw_proc.returncode, "stdout", len(raw_proc.stdout or b""), "stderr", len(raw_proc.stderr or b""))
	if raw_proc.returncode != 0:
		print((raw_proc.stderr or b"").decode("utf-8", "replace")[:1500])
		print("plain_ok_raw_failed")
		return 0
	raw = parse_spec(raw_proc.stdout)
	top = ((raw.get("genesis") or {}).get("raw") or {}).get("top")
	print("raw_top_keys", len(top) if isinstance(top, dict) else None)
	OUT.write_text(json.dumps(raw, separators=(",", ":")))
	print("wrote", OUT, "bytes", OUT.stat().st_size)
	print("ok")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
