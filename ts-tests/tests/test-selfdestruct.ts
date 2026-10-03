import { expect, use as chaiUse } from "chai";
import chaiAsPromised from "chai-as-promised";
import { AbiItem } from "web3-utils";

import SelfDestructAfterCreate2 from "../build/contracts/SelfDestructAfterCreate2.json";
import { GENESIS_ACCOUNT, GENESIS_ACCOUNT_PRIVATE_KEY, FIRST_CONTRACT_ADDRESS } from "./config";
import { createAndFinalizeBlock, customRequest, describeWithFrontier, sealUntilMined } from "./util";

chaiUse(chaiAsPromised);

describeWithFrontier("Test self-destruct contract", (context) => {
	const TEST_CONTRACT_BYTECODE = SelfDestructAfterCreate2.bytecode;
	const TEST_CONTRACT_DEPLOYED_BYTECODE = SelfDestructAfterCreate2.deployedBytecode;
	const TEST_CONTRACT_ABI = SelfDestructAfterCreate2.abi as AbiItem[];

	// Those test are ordered. In general this should be avoided, but due to the time it takes
	// to spin up a frontier node, it saves a lot of time.

	it("SELFDESTRUCT must reset contract account", async function () {
		this.timeout(60000);

		const tx = await context.web3.eth.accounts.signTransaction(
			{
				from: GENESIS_ACCOUNT,
				data: TEST_CONTRACT_BYTECODE,
				value: "0x00",
				gasPrice: "0x3B9ACA00",
				gas: "0x100000",
			},
			GENESIS_ACCOUNT_PRIVATE_KEY
		);

		expect(await customRequest(context.web3, "eth_sendRawTransaction", [tx.rawTransaction])).to.include({
			id: 1,
			jsonrpc: "2.0",
		});

		// Verify the contract is not yet stored
		expect(await customRequest(context.web3, "eth_getCode", [FIRST_CONTRACT_ADDRESS])).to.deep.equal({
			id: 1,
			jsonrpc: "2.0",
			result: "0x",
		});

		// Verify the contract is stored after the block is produced
		await createAndFinalizeBlock(context.web3);
		expect(await customRequest(context.web3, "eth_getCode", [FIRST_CONTRACT_ADDRESS])).to.deep.equal({
			id: 1,
			jsonrpc: "2.0",
			result: TEST_CONTRACT_DEPLOYED_BYTECODE,
		});

		// Prepare signer and fetch latest nonce
		await context.web3.eth.accounts.wallet.add(GENESIS_ACCOUNT_PRIVATE_KEY);
		let nonce = await context.web3.eth.getTransactionCount(GENESIS_ACCOUNT);

		const contract = new context.web3.eth.Contract(TEST_CONTRACT_ABI, FIRST_CONTRACT_ADDRESS, {
			from: GENESIS_ACCOUNT,
			gasPrice: "0x3B9ACA00",
		});

		const [{ transactionHash: tx1Hash }, { transactionHash: tx2Hash }, { transactionHash: tx3Hash }]: any[] =
			await sealUntilMined(context.web3, [
				contract.methods.step1().send({ from: GENESIS_ACCOUNT, gas: "0x100000", nonce: nonce++ }),
				contract.methods.step2().send({ from: GENESIS_ACCOUNT, gas: "0x100000", nonce: nonce++ }),
				contract.methods
					.cannotRecreateInTheSameCall()
					.send({ from: GENESIS_ACCOUNT, gas: "0x100000", nonce: nonce++ }),
			]);

		for (let txHash of [tx1Hash, tx2Hash, tx3Hash]) {
			const receipt = await context.web3.eth.getTransactionReceipt(txHash);
			expect(receipt.status).to.be.true;
		}

		const deployedAddress = await contract.methods.deployed1().call();

		// Verify the contract no longer exists
		expect(await customRequest(context.web3, "eth_getCode", [deployedAddress])).to.deep.equal({
			id: 1,
			jsonrpc: "2.0",
			result: "0x",
		});
	});
});
