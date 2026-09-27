import { expect } from "chai";

import { ARXON_ZK_PRECOMPILE, MEMBERSHIP_TREE_EMPTY_ROOT, NOTE_TREE_EMPTY_ROOT } from "./config";
import { customRequest, describeWithFrontier } from "./util";

// Arxon ZK precompile at 0x800: view only, backed by the real Halo2 verifier host function.
describeWithFrontier("Arxon ZK precompile (0x800)", (context) => {
	const ZERO_WORD = "0x" + "00".repeat(32);
	const C1_ROWS = 8;
	const C1_PROOF_LEN = 3456;

	const verifyAbi = {
		name: "verifyPrivacyProof",
		type: "function",
		inputs: [
			{ type: "uint8", name: "circuitId" },
			{ type: "bytes", name: "proof" },
			{ type: "bytes32[][]", name: "publicInputs" },
		],
	};

	function encode(name: string, inputs: any[], args: any[]) {
		return context.web3.eth.abi.encodeFunctionCall({ name, type: "function", inputs }, args);
	}

	function encodeVerify(circuitId: number, proofLen: number, rows: number) {
		const proof = "0x" + "ab".repeat(proofLen);
		const instance = Array(rows).fill(ZERO_WORD);
		return context.web3.eth.abi.encodeFunctionCall(verifyAbi as any, [circuitId, proof, [instance]] as any);
	}

	async function call(data: string) {
		return customRequest(context.web3, "eth_call", [{ to: ARXON_ZK_PRECOMPILE, data }]);
	}

	function asBool(result: string): boolean {
		return context.web3.eth.abi.decodeParameter("bool", result) as unknown as boolean;
	}

	it("isNullifierSpent is false for an unseen nullifier", async function () {
		const result = await call(encode("isNullifierSpent", [{ type: "bytes32", name: "nullifier" }], [ZERO_WORD]));
		expect(asBool(result.result)).to.equal(false);
	});

	it("getTrustRegistryRoot returns the empty membership tree root", async function () {
		const result = await call(encode("getTrustRegistryRoot", [], []));
		expect(result.result).to.equal(MEMBERSHIP_TREE_EMPTY_ROOT);
	});

	it("getNoteTreeRoot returns the empty note tree root", async function () {
		const result = await call(encode("getNoteTreeRoot", [], []));
		expect(result.result).to.equal(NOTE_TREE_EMPTY_ROOT);
	});

	// The empty root is deliberately not an anchor: no note can be spent under it. Roots become
	// known once the first commitment is inserted.
	it("isKnownNoteRoot is false for the empty root and for an unknown root", async function () {
		const empty = await call(
			encode("isKnownNoteRoot", [{ type: "bytes32", name: "root" }], [NOTE_TREE_EMPTY_ROOT])
		);
		const unknown = await call(
			encode("isKnownNoteRoot", [{ type: "bytes32", name: "root" }], [MEMBERSHIP_TREE_EMPTY_ROOT])
		);
		expect(asBool(empty.result)).to.equal(false);
		expect(asBool(unknown.result)).to.equal(false);
	});

	it("verifyPrivacyProof returns false for a garbage proof of the right length", async function () {
		const result = await call(encodeVerify(1, C1_PROOF_LEN, C1_ROWS));
		expect(result.error, JSON.stringify(result.error)).to.be.undefined;
		expect(asBool(result.result)).to.equal(false);
	});

	it("verifyPrivacyProof returns false for a proof of the wrong length", async function () {
		const result = await call(encodeVerify(1, C1_PROOF_LEN - 1, C1_ROWS));
		expect(asBool(result.result)).to.equal(false);
	});

	it("verifyPrivacyProof reverts for an unknown circuit id", async function () {
		const result = await call(encodeVerify(7, C1_PROOF_LEN, C1_ROWS));
		expect(result.error).to.not.be.undefined;
		expect(result.error.message).to.include("revert");
	});

	it("verifyPrivacyProof reverts on the wrong number of public input rows", async function () {
		const result = await call(encodeVerify(1, C1_PROOF_LEN, C1_ROWS + 1));
		expect(result.error).to.not.be.undefined;
		expect(result.error.message).to.include("revert");
	});

	it("verifyPrivacyProof reverts for a proof over the 8192 byte cap", async function () {
		const result = await call(encodeVerify(1, 9000, C1_ROWS));
		expect(result.error).to.not.be.undefined;
		expect(result.error.message).to.include("revert");
	});

	it("verifyPrivacyProof costs more gas than a storage getter", async function () {
		const verify = await customRequest(context.web3, "eth_estimateGas", [
			{ to: ARXON_ZK_PRECOMPILE, data: encodeVerify(1, C1_PROOF_LEN, C1_ROWS) },
		]);
		const getter = await customRequest(context.web3, "eth_estimateGas", [
			{ to: ARXON_ZK_PRECOMPILE, data: encode("getNoteTreeRoot", [], []) },
		]);
		expect(parseInt(verify.result, 16)).to.be.greaterThan(parseInt(getter.result, 16));
	});

	it("state changing calls do not exist: unknown selectors revert", async function () {
		const result = await call("0xdeadbeef");
		expect(result.error).to.not.be.undefined;
	});
});
