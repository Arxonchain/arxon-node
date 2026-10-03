#!/usr/bin/env python3
"""Local HTTP front: POST /relay submits a shielded bundle as the relayer; other paths proxy RPC.

The relayer pays gas and is paid back from the shielded pool: a `WithFee`
bundle carries a fee `(recipient, amount)` bound into its proofs, and the pool
releases it to `recipient` next to the payment. The relayer only submits
bundles that pay it at least its minimum fee. Bundles without a fee are
accepted while `RELAYER_ACCEPT_FREE` is on (the default, so wallets that do not
attach a fee yet keep working); turn it off once they do.

A native fee must also cover the gas the relayer spends on the bundle
(`eth_estimateGas` times the gas price), whatever the configured minimum.

Native ARX bundles go to the `0x801` precompile. ARX-20 bundles go to the token
contract (`to` in the request), which forwards them to `0x802` and mints the
fee to the relayer; only tokens listed in `RELAYER_TOKENS` are relayed, with
the minimum fee given there in token base units.

Environment:
  RELAYER_KEY            relayer private key (default: Baltathar, dev only)
  RELAYER_MIN_FEE_WEI    minimum native fee in wei (default 10^15, 0.001 ARX)
  RELAYER_ACCEPT_FREE    "1" relays fee-free bundles too, "0" refuses them (default 1)
  RELAYER_TOKENS         "0xToken:minFee,0xOther:minFee" ARX-20 tokens to relay (default none)
"""

from __future__ import annotations

import http.client
import json
import os
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LISTEN = ("127.0.0.1", 8787)
RPC_HOST, RPC_PORT = "127.0.0.1", 9944
SUBMIT = "0x0000000000000000000000000000000000000801"
CHAIN_ID = 7171
GAS = 8_000_000
# Frontier --chain dev well-known account (not sudo). Override with RELAYER_KEY.
BALTATHAR_KEY = "0x8075991ce870b93a8870eca0c0f91913d12f47948ca0fd25b49c6fa7cdbeee8b"
MAX_BODY = 2_000_000
WINDOW = 60.0
MAX_PER_WINDOW = 30

_INPUTS = "(bytes32,bytes32,bytes32)[]"
_OUTPUTS = "(bytes32,bytes32,bytes32,bytes32,bytes)[]"
_PROOFS = "(bytes,bytes,bytes,bytes,bytes)"
_ATTACHMENT = "(bool,uint8,bytes32)"
_FEE = "(address,uint256)"

_UNSHIELD = ["address", "uint256", "bytes32", _INPUTS, _OUTPUTS, "uint8", "uint256"]
_TRANSFER = ["bytes32", _INPUTS, _OUTPUTS, "uint8", "uint256", _ATTACHMENT, _ATTACHMENT]


@dataclass(frozen=True)
class Method:
	"""A relayable method: its argument types and where its fee tuple sits (None if fee-free)."""

	name: str
	args: tuple[str, ...]
	fee_index: int | None

	@property
	def signature(self) -> str:
		return "%s(%s)" % (self.name, ",".join(self.args))


def _methods(transfer_name: str) -> list[Method]:
	return [
		Method(transfer_name, (*_TRANSFER, _PROOFS), None),
		Method("unshield", (*_UNSHIELD, _PROOFS), None),
		Method(transfer_name + "WithFee", (*_TRANSFER, _FEE, _PROOFS), len(_TRANSFER)),
		Method("unshieldWithFee", (*_UNSHIELD, _FEE, _PROOFS), len(_UNSHIELD)),
	]


# 0x801 names the private transfer `submitPrivateTransfer`; the reference ARX-20
# token (which forwards to 0x802) names it `transferPrivate`.
NATIVE_METHODS = _methods("submitPrivateTransfer")
TOKEN_METHODS = _methods("transferPrivate")

_hits: list[float] = []


def selector(method: Method) -> str:
	from eth_utils import function_signature_to_4byte_selector

	return "0x" + function_signature_to_4byte_selector(method.signature).hex()


@dataclass(frozen=True)
class Config:
	payer: str
	min_native_fee: int
	accept_free: bool
	tokens: dict[str, int]


def parse_tokens(spec: str) -> dict[str, int]:
	"""`0xToken:minFee,...` into {lowercase address: min fee in base units}."""
	tokens: dict[str, int] = {}
	for item in filter(None, (part.strip() for part in spec.split(","))):
		address, _, min_fee = item.partition(":")
		address = address.strip().lower()
		if not (address.startswith("0x") and len(address) == 42):
			raise ValueError("RELAYER_TOKENS: %r is not an address" % address)
		int(address, 16)
		tokens[address] = int(min_fee or "0")
	return tokens


def config_from_env() -> Config:
	return Config(
		payer=account().address,
		min_native_fee=int(os.environ.get("RELAYER_MIN_FEE_WEI") or 10**15),
		accept_free=(os.environ.get("RELAYER_ACCEPT_FREE") or "1") != "0",
		tokens=parse_tokens(os.environ.get("RELAYER_TOKENS") or ""),
	)


def check(cfg: Config, to: str, data: str) -> str:
	"""Validates a relay request and returns the address to send it to.

	Raises ValueError when the relayer must not submit it: an unknown target or
	method, a fee paid to someone else, or a fee below the minimum.
	"""
	return checked(cfg, to, data)[0]


def checked(cfg: Config, to: str, data: str) -> tuple[str, int | None]:
	"""`check`, also returning the fee the bundle pays (None when fee-free)."""
	if not isinstance(data, str) or not data.startswith("0x") or len(data) < 10:
		raise ValueError("data must be 0x-prefixed calldata")
	target = (to or SUBMIT).strip().lower()
	if target == SUBMIT:
		methods, min_fee = NATIVE_METHODS, cfg.min_native_fee
	elif target in cfg.tokens:
		methods, min_fee = TOKEN_METHODS, cfg.tokens[target]
	else:
		raise ValueError("relayer only submits to 0x801 and to the ARX-20 tokens it lists")
	sel = data[:10].lower()
	method = next((m for m in methods if selector(m) == sel), None)
	if method is None:
		raise ValueError("relayer only submits private transfers and unshields")
	if method.fee_index is None:
		if not cfg.accept_free:
			raise ValueError("this relayer needs a fee: use the WithFee variant paying %s" % cfg.payer)
		return target, None
	from eth_abi import decode

	try:
		args = decode(list(method.args), bytes.fromhex(data[10:]))
	except Exception as e:
		raise ValueError("calldata does not decode: %s" % e) from e
	recipient, amount = args[method.fee_index]
	if recipient.lower() != cfg.payer.lower():
		raise ValueError("the fee must be paid to this relayer, %s" % cfg.payer)
	if amount < min_fee:
		raise ValueError("fee %d is below this relayer's minimum %d" % (amount, min_fee))
	return target, amount


def covers_gas(fee: int, gas: int, gas_price: int) -> bool:
	"""`True` iff a native fee pays at least what submitting costs the relayer."""
	return fee >= gas * gas_price


def cors(handler: BaseHTTPRequestHandler) -> None:
	handler.send_header("Access-Control-Allow-Origin", "*")
	handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	handler.send_header("Access-Control-Allow-Headers", "content-type")


def rpc(method: str, params: list) -> object:
	body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
	conn = http.client.HTTPConnection(RPC_HOST, RPC_PORT, timeout=60)
	try:
		conn.request("POST", "/", body, {"Host": "127.0.0.1", "Content-Type": "application/json"})
		raw = conn.getresponse().read()
	finally:
		conn.close()
	msg = json.loads(raw)
	if "error" in msg and msg["error"]:
		err = msg["error"]
		if isinstance(err, dict):
			raise RuntimeError(str(err.get("message") or err))
		raise RuntimeError(str(err))
	return msg.get("result")


def limited() -> bool:
	now = time.time()
	_hits[:] = [t for t in _hits if now - t < WINDOW]
	if len(_hits) >= MAX_PER_WINDOW:
		return True
	_hits.append(now)
	return False


def account():
	from eth_account import Account

	key = os.environ.get("RELAYER_KEY") or BALTATHAR_KEY
	return Account.from_key(key)


def submit(cfg: Config, to: str, data: str) -> str:
	target, fee = checked(cfg, to, data)
	acct = account()
	payer = acct.address
	# A bundle that would revert (spent note, flagged recipient, bad proof) costs
	# the relayer gas: the estimate is also the dry run, and fails for those.
	gas = int(rpc("eth_estimateGas", [{"from": payer, "to": target, "data": data, "gas": hex(GAS)}]), 16)
	gas_price = int(rpc("eth_gasPrice", []), 16)
	if fee is not None and target == SUBMIT and not covers_gas(fee, gas, gas_price):
		raise ValueError("fee %d does not cover the gas, %d wei" % (fee, gas * gas_price))
	nonce = int(rpc("eth_getTransactionCount", [payer, "pending"]), 16)
	signed = acct.sign_transaction(
		{
			"nonce": nonce,
			"gasPrice": gas_price,
			"gas": min(GAS, gas * 12 // 10),
			"to": target,
			"value": 0,
			"data": data,
			"chainId": CHAIN_ID,
		}
	)
	raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
	tx_hex = raw.hex()
	if not tx_hex.startswith("0x"):
		tx_hex = "0x" + tx_hex
	h = rpc("eth_sendRawTransaction", [tx_hex])
	if not isinstance(h, str):
		raise RuntimeError("no tx hash")
	return h


def advertised(cfg: Config) -> dict:
	"""What a wallet needs to build a bundle this relayer accepts."""
	return {
		"ok": True,
		"payer": cfg.payer,
		"fee_recipient": cfg.payer,
		"min_fee_wei": str(cfg.min_native_fee),
		"accept_free": cfg.accept_free,
		"tokens": {token: str(fee) for token, fee in cfg.tokens.items()},
		"native_methods": {m.signature: selector(m) for m in NATIVE_METHODS},
		"token_methods": {m.signature: selector(m) for m in TOKEN_METHODS},
	}


class Handler(BaseHTTPRequestHandler):
	config: Config

	def log_message(self, fmt: str, *args) -> None:
		sys_stderr = __import__("sys").stderr
		sys_stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

	def _json(self, code: int, obj: dict) -> None:
		blob = json.dumps(obj).encode()
		self.send_response(code)
		cors(self)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(blob)))
		self.end_headers()
		self.wfile.write(blob)

	def do_OPTIONS(self) -> None:
		self.send_response(204)
		cors(self)
		self.end_headers()

	def do_GET(self) -> None:
		path = urlparse(self.path).path.rstrip("/") or "/"
		if path == "/relay":
			self._json(200, advertised(self.config))
			return
		self._proxy()

	def do_POST(self) -> None:
		path = urlparse(self.path).path.rstrip("/") or "/"
		if path == "/relay":
			self._relay()
			return
		self._proxy()

	def _relay(self) -> None:
		if limited():
			self._json(429, {"error": "relayer busy, try again"})
			return
		n = int(self.headers.get("Content-Length") or 0)
		if n <= 0 or n > MAX_BODY:
			self._json(400, {"error": "bad body"})
			return
		try:
			payload = json.loads(self.rfile.read(n))
			data = payload["data"]
			to = payload.get("to") or SUBMIT
			if not isinstance(data, str) or not isinstance(to, str):
				raise ValueError("data and to must be strings")
			h = submit(self.config, to, data.strip())
		except Exception as e:
			self._json(400, {"error": str(e)})
			return
		self._json(200, {"hash": h})

	def _proxy(self) -> None:
		n = int(self.headers.get("Content-Length") or 0)
		if n > MAX_BODY:
			self.send_error(413)
			return
		body = self.rfile.read(n) if n else b""
		headers = {"Host": "127.0.0.1"}
		ct = self.headers.get("Content-Type")
		if ct:
			headers["Content-Type"] = ct
		conn = http.client.HTTPConnection(RPC_HOST, RPC_PORT, timeout=60)
		try:
			conn.request(self.command, self.path, body, headers)
			resp = conn.getresponse()
			data = resp.read()
		except Exception as e:
			self._json(502, {"error": "rpc proxy: %s" % e})
			return
		finally:
			conn.close()
		self.send_response(resp.status)
		cors(self)
		self.send_header("Content-Type", resp.getheader("Content-Type") or "application/json")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)


def main() -> int:
	try:
		cfg = config_from_env()
	except Exception as e:
		print("relayer config:", e)
		print("pip3 install eth-account eth-abi")
		return 1
	Handler.config = cfg
	print("relayer", cfg.payer, "listen", "%s:%s" % LISTEN)
	print("min fee", cfg.min_native_fee, "wei; fee-free bundles", "accepted" if cfg.accept_free else "refused")
	for token, fee in cfg.tokens.items():
		print("token", token, "min fee", fee)
	ThreadingHTTPServer(LISTEN, Handler).serve_forever()
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
