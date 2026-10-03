"""Relay request checks: run with `python3 -m unittest deploy/test_relayer.py`."""

from __future__ import annotations

import unittest

from eth_abi import encode

import relayer
from relayer import SUBMIT, Config, check, parse_tokens, selector

PAYER = "0x3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0"
OTHER = "0x798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc"
TOKEN = "0x" + "aa" * 20
MIN_FEE = 10**15

WORD = b"\x11" * 32
PROOFS = (b"", b"\x01" * 64, b"\x02" * 64, b"", b"")
NO_ATTACHMENT = (False, 0, b"\x00" * 32)
UNSHIELD_HEAD = [PAYER, 40 * 10**9, WORD, [(WORD, WORD, WORD)], [], 0, 100]
TRANSFER_HEAD = [WORD, [(WORD, WORD, WORD)], [(WORD, WORD, WORD, WORD, b"note")], 7, 100, NO_ATTACHMENT, NO_ATTACHMENT]


def config(accept_free: bool = True) -> Config:
	return Config(payer=PAYER, min_native_fee=MIN_FEE, accept_free=accept_free, tokens={TOKEN: 5})


def method(methods, name):
	return next(m for m in methods if m.name == name)


def calldata(methods, name: str, args: list) -> str:
	m = method(methods, name)
	return selector(m) + encode(list(m.args), args).hex()


def unshield_with_fee(fee_to: str, fee: int, methods=relayer.NATIVE_METHODS) -> str:
	return calldata(methods, "unshieldWithFee", [*UNSHIELD_HEAD, (fee_to, fee), PROOFS])


class Selectors(unittest.TestCase):
	def test_match_the_precompile_signatures(self):
		expected = {
			"submitPrivateTransfer": "0xcda7b865",
			"unshield": "0x6148385b",
		}
		for m in relayer.NATIVE_METHODS:
			if m.name in expected:
				self.assertEqual(selector(m), expected[m.name], m.signature)
		self.assertEqual(
			method(relayer.NATIVE_METHODS, "unshieldWithFee").signature,
			"unshieldWithFee(address,uint256,bytes32,(bytes32,bytes32,bytes32)[],"
			"(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(address,uint256),"
			"(bytes,bytes,bytes,bytes,bytes))",
		)
		self.assertEqual(
			method(relayer.NATIVE_METHODS, "submitPrivateTransferWithFee").signature,
			"submitPrivateTransferWithFee(bytes32,(bytes32,bytes32,bytes32)[],"
			"(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bool,uint8,bytes32),"
			"(bool,uint8,bytes32),(address,uint256),(bytes,bytes,bytes,bytes,bytes))",
		)

	def test_token_methods_are_the_reference_arx20_names(self):
		names = {m.name for m in relayer.TOKEN_METHODS}
		self.assertEqual(names, {"transferPrivate", "unshield", "transferPrivateWithFee", "unshieldWithFee"})


class NativeRelay(unittest.TestCase):
	def test_a_fee_paid_to_the_relayer_at_the_minimum_is_relayed(self):
		self.assertEqual(check(config(), SUBMIT, unshield_with_fee(PAYER, MIN_FEE)), SUBMIT)

	def test_the_fee_recipient_is_compared_without_case(self):
		self.assertEqual(check(config(), SUBMIT, unshield_with_fee(PAYER.lower(), MIN_FEE)), SUBMIT)

	def test_a_relayed_private_transfer_is_checked_the_same_way(self):
		data = calldata(
			relayer.NATIVE_METHODS, "submitPrivateTransferWithFee", [*TRANSFER_HEAD, (PAYER, MIN_FEE), PROOFS]
		)
		self.assertEqual(check(config(), SUBMIT, data), SUBMIT)

	def test_a_fee_paid_to_someone_else_is_refused(self):
		with self.assertRaisesRegex(ValueError, "paid to this relayer"):
			check(config(), SUBMIT, unshield_with_fee(OTHER, MIN_FEE))

	def test_a_fee_below_the_minimum_is_refused(self):
		with self.assertRaisesRegex(ValueError, "below"):
			check(config(), SUBMIT, unshield_with_fee(PAYER, MIN_FEE - 1))

	def test_a_fee_free_bundle_is_relayed_while_free_relaying_is_on(self):
		data = calldata(relayer.NATIVE_METHODS, "unshield", [*UNSHIELD_HEAD, PROOFS])
		self.assertEqual(check(config(accept_free=True), SUBMIT, data), SUBMIT)

	def test_a_fee_free_bundle_is_refused_once_free_relaying_is_off(self):
		data = calldata(relayer.NATIVE_METHODS, "unshield", [*UNSHIELD_HEAD, PROOFS])
		with self.assertRaisesRegex(ValueError, "needs a fee"):
			check(config(accept_free=False), SUBMIT, data)

	def test_other_precompile_methods_are_refused(self):
		with self.assertRaisesRegex(ValueError, "only submits private transfers"):
			check(config(), SUBMIT, "0x12345678" + "00" * 32)

	def test_calldata_that_does_not_decode_is_refused(self):
		data = selector(method(relayer.NATIVE_METHODS, "unshieldWithFee")) + "00" * 3
		with self.assertRaisesRegex(ValueError, "does not decode"):
			check(config(), SUBMIT, data)

	def test_data_must_be_hex_calldata(self):
		with self.assertRaises(ValueError):
			check(config(), SUBMIT, "deadbeef")


class TokenRelay(unittest.TestCase):
	def test_a_listed_token_is_relayed_with_its_own_minimum(self):
		data = unshield_with_fee(PAYER, 5, relayer.TOKEN_METHODS)
		self.assertEqual(check(config(), TOKEN.upper().replace("0X", "0x"), data), TOKEN)

	def test_a_token_fee_below_its_minimum_is_refused(self):
		with self.assertRaisesRegex(ValueError, "below"):
			check(config(), TOKEN, unshield_with_fee(PAYER, 4, relayer.TOKEN_METHODS))

	def test_an_unlisted_contract_is_never_called(self):
		data = unshield_with_fee(PAYER, MIN_FEE, relayer.TOKEN_METHODS)
		with self.assertRaisesRegex(ValueError, "tokens it lists"):
			check(config(), "0x" + "bb" * 20, data)

	def test_a_token_is_not_sent_the_precompile_transfer_name(self):
		data = calldata(
			relayer.NATIVE_METHODS, "submitPrivateTransferWithFee", [*TRANSFER_HEAD, (PAYER, 5), PROOFS]
		)
		with self.assertRaisesRegex(ValueError, "only submits private transfers"):
			check(config(), TOKEN, data)


class TokenList(unittest.TestCase):
	def test_parses_addresses_and_minimums(self):
		self.assertEqual(
			parse_tokens(" 0x" + "AA" * 20 + ":7, 0x" + "bb" * 20),
			{"0x" + "aa" * 20: 7, "0x" + "bb" * 20: 0},
		)

	def test_refuses_a_non_address(self):
		with self.assertRaises(ValueError):
			parse_tokens("0x1234:5")


if __name__ == "__main__":
	unittest.main()
