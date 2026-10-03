import { expect } from "chai";
import { AbiItem } from "web3-utils";

import ARX20 from "../build/contracts/ARX20.json";
import { ARXON_ARX20_PRECOMPILE, GENESIS_ACCOUNT, GENESIS_ACCOUNT_PRIVATE_KEY } from "./config";
import { createAndFinalizeBlock, customRequest, describeWithFrontier } from "./util";

// The reference ARX-20 against the ARX-20 precompile at 0x802: the constructor
// fixes the token's shielded unit from its decimals, and only a contract can
// run a pool (an EOA calling 0x802 directly is refused).
describeWithFrontier("Arxon ARX-20 precompile (0x802)", (context) => {
	const ZERO_WORD = "0x" + "00".repeat(32);
	const DUMMY_PROOF = "0x" + "ab".repeat(64);

	async function deploy(decimals: number): Promise<string> {
		const data = new context.web3.eth.Contract(ARX20.abi as AbiItem[])
			.deploy({ data: ARX20.bytecode, arguments: ["Token", "TKN", decimals, "1000000000000000000000"] })
			.encodeABI();
		const tx = await context.web3.eth.accounts.signTransaction(
			{ from: GENESIS_ACCOUNT, data, value: "0x00", gasPrice: "0x3B9ACA00", gas: "0x300000" },
			GENESIS_ACCOUNT_PRIVATE_KEY
		);
		const sent = await customRequest(context.web3, "eth_sendRawTransaction", [tx.rawTransaction]);
		expect(sent.error, JSON.stringify(sent.error)).to.be.undefined;
		await createAndFinalizeBlock(context.web3);
		const receipt = await context.web3.eth.getTransactionReceipt(sent.result);
		expect(receipt.status, "constructor succeeded").to.equal(true);
		return receipt.contractAddress;
	}

	async function shieldedUnit(token: string): Promise<string> {
		const data = context.web3.eth.abi.encodeFunctionCall(
			{ name: "shieldedUnit", type: "function", inputs: [{ type: "address", name: "token" }] },
			[token]
		);
		const result = await customRequest(context.web3, "eth_call", [{ to: ARXON_ARX20_PRECOMPILE, data }]);
		expect(result.error, JSON.stringify(result.error)).to.be.undefined;
		return context.web3.eth.abi.decodeParameter("uint256", result.result).toString();
	}

	it("a 6-decimal token fixes a shielded unit of one base unit in its constructor", async function () {
		this.timeout(60000);
		const token = await deploy(6);

		expect(await shieldedUnit(token)).to.equal("1");
		const contract = new context.web3.eth.Contract(ARX20.abi as AbiItem[], token);
		expect((await contract.methods.shieldedUnit().call()).toString()).to.equal("1");
		expect((await contract.methods.decimals().call()).toString()).to.equal("6");
	});

	it("an 18-decimal token keeps the 10^9 unit of native ARX", async function () {
		this.timeout(60000);
		const token = await deploy(18);

		expect(await shieldedUnit(token)).to.equal("1000000000");
	});

	it("an account without code cannot shield into a pool of its own", async function () {
		const shieldAbi = {
			name: "shield",
			type: "function",
			inputs: [
				{ type: "uint256", name: "amount" },
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
		const data = context.web3.eth.abi.encodeFunctionCall(
			shieldAbi as any,
			[
				"1000000000",
				[[ZERO_WORD, ZERO_WORD, ZERO_WORD, ZERO_WORD, "0x11"]],
				0,
				100,
				["0x", DUMMY_PROOF, DUMMY_PROOF, "0x", "0x"],
			] as any
		);

		const result = await customRequest(context.web3, "eth_call", [
			{ from: GENESIS_ACCOUNT, to: ARXON_ARX20_PRECOMPILE, data },
		]);

		expect(result.error, JSON.stringify(result.error)).to.not.be.undefined;
		// The revert reason names the pallet error, in the message or in the revert data.
		const reason = context.web3.utils.utf8ToHex("NotATokenContract").slice(2);
		const error = JSON.stringify(result.error);
		expect(error.includes("NotATokenContract") || error.includes(reason), error).to.equal(true);
	});
});
