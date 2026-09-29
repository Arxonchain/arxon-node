#!/usr/bin/env python3
"""Local HTTP front: POST /relay submits 0x801 (private/unshield) as Baltathar; other paths proxy RPC."""

from __future__ import annotations

import http.client
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LISTEN = ("127.0.0.1", 8787)
RPC_HOST, RPC_PORT = "127.0.0.1", 9944
SUBMIT = "0x0000000000000000000000000000000000000801"
CHAIN_ID = 7171
GAS = 8_000_000
# Frontier --chain dev well-known account (not sudo). Override with RELAYER_KEY.
BALTATHAR_KEY = "0x8075991ce870b93a8870eca0c0f91913d12f47948ca0fd25b49c6fa7cdbeee8b"
ALLOW = {"0xcda7b865", "0x6148385b"}  # submitPrivateTransfer, unshield
MAX_BODY = 2_000_000
WINDOW = 60.0
MAX_PER_WINDOW = 30

_hits: list[float] = []


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


def submit(data: str) -> str:
	if not data.startswith("0x") or len(data) < 10:
		raise ValueError("data must be 0x-prefixed calldata")
	sel = data[:10].lower()
	if sel not in ALLOW:
		raise ValueError("relayer only submits private transfer and unshield")
	acct = account()
	payer = acct.address
	rpc(
		"eth_call",
		[{"from": payer, "to": SUBMIT, "data": data, "gas": hex(GAS)}, "latest"],
	)
	nonce = int(rpc("eth_getTransactionCount", [payer, "pending"]), 16)
	gas_price = int(rpc("eth_gasPrice", []), 16)
	signed = acct.sign_transaction(
		{
			"nonce": nonce,
			"gasPrice": gas_price,
			"gas": GAS,
			"to": SUBMIT,
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


class Handler(BaseHTTPRequestHandler):
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
			try:
				payer = account().address
			except Exception as e:
				self._json(500, {"error": str(e)})
				return
			self._json(200, {"ok": True, "payer": payer})
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
			if not isinstance(data, str):
				raise ValueError("data")
			h = submit(data.strip())
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
		acct = account()
	except Exception as e:
		print("need eth-account:", e)
		print("pip3 install eth-account")
		return 1
	print("relayer", acct.address, "listen", "%s:%s" % LISTEN)
	ThreadingHTTPServer(LISTEN, Handler).serve_forever()
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
