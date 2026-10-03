import { expect } from "chai";

import { ARXON_ZK_PRECOMPILE, ARXON_ZK_SUBMIT_PRECOMPILE, GENESIS_ACCOUNT, NOTE_TREE_EMPTY_ROOT } from "./config";
import { customRequest, describeWithFrontier } from "./util";

// Arxon ZK submit precompile at 0x801: state-changing door into pallet-privacy.
// Dummy proofs are rejected by the real Halo2 host verifier; that is the check.
describeWithFrontier("Arxon ZK submit precompile (0x801)", (context) => {
	const ZERO_WORD = "0x" + "00".repeat(32);
	const DUMMY_PROOF = "0x" + "ab".repeat(64);

	const shieldAbi = {
		name: "shield",
		type: "function",
		inputs: [
			{
				type: "tuple[]",
				name: "outputs",
				components: [
					{ type: "bytes32", name: "cm" },
					{ type: "bytes32", name: "cv" },
					{ type: "bytes32", name: "revealedReceiver" },
					{ type: "bytes32", name: "revealedAmount" },
					{ type: "bytes", name: "encryptedNote" },
				],
			},
			{ type: "uint8", name: "maskBits" },
			{ type: "uint256", name: "expiryBlock" },
			{
				type: "tuple",
				name: "proofs",
				components: [
					{ type: "bytes", name: "spend" },
					{ type: "bytes", name: "output" },
					{ type: "bytes", name: "balance" },
					{ type: "bytes", name: "receipt" },
					{ type: "bytes", name: "compliance" },
				],
			},
		],
	};

	function shieldData() {
		return context.web3.eth.abi.encodeFunctionCall(
			shieldAbi as any,
			[
				[[ZERO_WORD, ZERO_WORD, ZERO_WORD, ZERO_WORD, "0x11"]],
				0,
				100,
				["0x", DUMMY_PROOF, DUMMY_PROOF, "0x", "0x"],
			] as any
		);
	}

	async function call(to: string, data: string, value?: string) {
		// A funded caller: shield is payable, and an unfunded call fails in the EVM
		// (OutOfFund) before it ever reaches the precompile.
		const tx: { from: string; to: string; data: string; value?: string } = { from: GENESIS_ACCOUNT, to, data };
		if (value) tx.value = value;
		return customRequest(context.web3, "eth_call", [tx]);
	}

	it("is a precompile: unknown selectors revert", async function () {
		const result = await call(ARXON_ZK_SUBMIT_PRECOMPILE, "0xdeadbeef");
		expect(result.error, JSON.stringify(result.error)).to.not.be.undefined;
	});

	it("shield with a dummy proof reverts and does not insert a note", async function () {
		const result = await call(ARXON_ZK_SUBMIT_PRECOMPILE, shieldData(), "0x9c7652400");
		expect(result.error, JSON.stringify(result.error)).to.not.be.undefined;
		expect(result.error.message).to.include("revert");

		const root = await call(
			ARXON_ZK_PRECOMPILE,
			context.web3.eth.abi.encodeFunctionCall({ name: "getNoteTreeRoot", type: "function", inputs: [] }, [])
		);
		expect(root.result).to.equal(NOTE_TREE_EMPTY_ROOT);
	});

	function isBalanceHiddenData(account: string) {
		return context.web3.eth.abi.encodeFunctionCall(
			{ name: "isBalanceHidden", type: "function", inputs: [{ type: "address", name: "account" }] },
			[account]
		);
	}

	it("isBalanceHidden is false for an account that never set it", async function () {
		const result = await call(ARXON_ZK_SUBMIT_PRECOMPILE, isBalanceHiddenData(GENESIS_ACCOUNT));
		expect(result.error, JSON.stringify(result.error)).to.be.undefined;
		expect(context.web3.eth.abi.decodeParameter("bool", result.result)).to.equal(false);
	});

	it("setBalanceVisibility is accepted from the signing account", async function () {
		const data = context.web3.eth.abi.encodeFunctionCall(
			{ name: "setBalanceVisibility", type: "function", inputs: [{ type: "bool", name: "hidden" }] },
			[true] as any
		);
		const result = await call(ARXON_ZK_SUBMIT_PRECOMPILE, data);
		expect(result.error, JSON.stringify(result.error)).to.be.undefined;
	});
});
