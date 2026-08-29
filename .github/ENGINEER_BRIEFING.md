# Arxon engineer briefing

Clone branch `stable2512`. Read this once before writing circuits or changing the runtime. The same text is on the GitHub Issues tab of this repository.

Privacy flags exist in storage. Halo2 does not. Post quantum signing exists as an opt in wrapper. Those three facts drive the work.

**Start the six Halo2 circuits now.** Remaining post-quantum work (lock after register, host-function ML-DSA, measured weights, pallet tests, public-network keys) is account-layer and can land later. It does not change Circuit 1 public inputs. Do not wait on it. Do not register an ML-DSA key on the accounts you use to develop the first private-transfer extrinsics; ordinary ECDSA `--dev` accounts (Alith / Alice) are the right test accounts until wrap is needed.

---

## What is live in the chain and in the code

### Node, consensus, EVM

* Sovereign Layer 1, not a parachain. Binary: `arxon-node`.
* Consensus: AURA + GRANDPA, about 6 second slots. Litepaper still says BABE. The code is AURA.
  * Wiring: `template/node/src/service.rs`, `template/runtime/src/lib.rs` (`pallet_aura`, `pallet_grandpa`).
* Polkadot SDK `stable2512`. Rust `1.88.0` in `rust-toolchain.toml`.
* EVM via Frontier. Chain ID **7171** on both the development spec and the local testnet spec. Constant: `ARXON_EVM_CHAIN_ID` in `template/runtime/src/lib.rs`. Specs: `template/node/src/chain_spec.rs`.
* MetaMask RPC: `http://127.0.0.1:9944`. Token symbol `ARX`, 18 decimals (`ARX_DECIMALS`, `ARX_UNIT`).
* Standard Ethereum precompiles at `0x01` through `0x05`, plus Frontier extras at `0x400` through `0x403` (SHA3-FIPS, ECRecover public key, Curve25519 add/mul). File: `template/runtime/src/precompiles.rs`. Address `0x800` (`ARXON_ZK_PRECOMPILE`) is reserved: calls revert until the Halo2 verifier is implemented. Do not deploy a contract there.
* `--dev` genesis sudo and treasury is the well-known **Alith** test account. Aura authority is the well-known `//Alice` seed. Those keys are public. Local machines only. Do not ship this genesis as a public network.

### ARX token and genesis

* Total supply: 1,000,000,000 ARX, 18 decimals.
* Split: 300M treasury, 250M mining, 200M investors, 150M team, 100M staking.
* Same numbers in `template/node/src/chain_spec.rs` and `template/runtime/src/genesis_config_preset.rs`.

### Custom pallets (this is the Arxon product layer)

All of these live under `template/pallets/<name>/` and are registered in `template/runtime/src/lib.rs`.

**Index 12. Mining** (`template/pallets/mining/src/lib.rs`)

* `register_miner`
* `credit_points` (root)
* Storage: `MiningPoints`, `TotalPoints`

**Index 13. Privacy** (`template/pallets/privacy/src/lib.rs`)

* This is **selective privacy**: the user picks which fields to hide or reveal. Any combination of the four flags is valid.
* Struct `PrivacyMask`: `hide_sender`, `hide_receiver`, `hide_amount`, `hide_balance`.
* The same mask is the product model for **native FRAME calls and EVM transactions**. Halo2 will enforce it on both paths. Do not build a public-only EVM and a private-only native chain.
* `set_privacy_default`
* `record_tx_privacy` (does not set hide_balance on the per-tx mask)
* `set_balance_visibility`
* Storage: `AccountPrivacyDefault`, `TxPrivacyMask`, `ShieldedTxCount`, `HideBalanceAccounts`
* **Not hooked into `pallet_balances` or `pallet_ethereum`.** Anyone can call `record_tx_privacy` on any hash. Full nodes still see transparent state. This is application-layer metadata until Halo2 lands.

**Index 14. ARX claim** (`template/pallets/arx-claim/src/lib.rs`)

* `set_snapshot`, `set_arx_per_point`, `set_claiming_status` (root)
* `claim_arx` (signed)
* `Currency` is in the config. **`claim_arx` does not mint or transfer ARX.** It only records the claim.

**Index 15. PTR** (`template/pallets/ptr/src/lib.rs`)

* `create_receipt` (root only)
* `generate_disclosure_code` (sender or receiver)
* `use_disclosure_code` (burns the code)
* Receipts store plaintext sender, receiver, amount, and pre/post balances. `ReceiptCreated` events also include parties.

**Index 16. Trust registry** (`template/pallets/trust-registry/src/lib.rs`)

* Anti-rug project badges: Bronze / Silver / Gold, lock durations, community alerts, sudo revoke.
* `register_project`, `extend_lock`, `upgrade_tier`, `submit_alert`, `trigger_mint_alert`, `revoke_project`
* **This is not** the ZK membership tree for exchanges and merchants. Keep the two ideas separate.

**Index 17. Quantum account** (`template/pallets/quantum-account/src/lib.rs`)

* See the post quantum section below.

Frontier occupies indices 0 through 11 (system, timestamp, aura, grandpa, balances, payment, sudo, ethereum, evm, chain id, base fee, manual seal). Indices 18 (verifier), 19 (nullifier registry), and 20 (note / membership tree) are reserved for ZK. Index 16 stays anti-rug. Index 17 stays quantum accounts.

Root README: `README.md`.

---

## Post quantum resistance

### Already done

* Pallet `pallet-quantum-account` at runtime index 17.
* Algorithm: ML-DSA-65 (NIST FIPS 204 / Dilithium Level 3). Crate: `ml-dsa` `0.1.0-rc.8` in workspace `Cargo.toml`.
* Public key 1952 bytes. Signature 3309 bytes.
* Domain string: `arxon-quantum-dispatch-v1`.
* `verify_mldsa65` in `template/pallets/quantum-account/src/lib.rs`.
* `register_quantum_key`
* `deregister_quantum_key`
* `quantum_dispatch(quantum_signer, nonce, call, signature)`: relayer pays the outer fee. Inner call runs as `Signed(quantum_signer)`. Signed message is `domain || SCALE(nonce) || SCALE(call)`. Nonce is incremented before inner dispatch. If the extrinsic returns `Err` (including a failed inner call), FRAME rolls that increment back, so the same signature can be retried.
* Storage: `QuantumKeys`, `QuantumNonces`, `QuantumAccountCount`.
* Helper: `is_quantum_account`.
* Runtime config: `impl pallet_quantum_account::Config for Runtime` in `template/runtime/src/lib.rs`.
* This layer is independent of Halo2. A future private transfer can be wrapped as `quantum_dispatch(submit_private_transaction(...))`.

### Left to do (not ZK, but not finished)

* Registration is opt in. Accounts are **not** quantum resistant by default.
* ECDSA still authenticates `register_quantum_key` and `deregister_quantum_key`. A stolen classical key can still bind or remove a quantum key.
* Nothing forces a registered account to use only `quantum_dispatch`.
* Verify runs in Wasm, not a host function. Same performance risk as Halo2 verify.
* Weights are hardcoded, not benchmarked.
* No pallet tests.
* Public testnet / mainnet must **not** use Alith / `//Alice`. Generate new sudo, treasury, and validator keys offline.

---

## ZK work still to do (circuits and integration)

Product model to freeze before Circuit 1: **selective privacy**. The user chooses, per transaction, which of the four fields to hide or reveal (`hide_sender`, `hide_receiver`, `hide_amount`, `hide_balance`), matching `PrivacyMask` and the litepaper. Any combination is valid. Do not collapse this into three modes (`PUBLIC` / `SEMI_PRIVATE` / `FULLY_PRIVATE`) unless product signs that change. IARX20 (draft only, not in this repo) uses the same four flags.

Native Substrate extrinsics and EVM (Frontier) transactions share that one model, one note tree, one nullifier set, and the same six circuits. The EVM precompile is a second door into the same shielded pool, not a different privacy design.

Proofs must bind to chain ID **7171**, never 42. SS58 prefix 42 is an address format, not the EVM chain id.

Circuit 1 mask packing is frozen in `PrivacyMask::as_bits` (`template/pallets/privacy/src/lib.rs`): bit 0 hide_sender, bit 1 hide_receiver, bit 2 hide_amount, bit 3 hide_balance.

EVM precompile address `0x800` is reserved in `template/runtime/src/precompiles.rs` (`ARXON_ZK_PRECOMPILE`). Calls revert with `ARXON_ZK_PRECOMPILE_RESERVED` until the verifier is implemented. Do not deploy a contract there.

Runtime pallet indices 18 (verifier), 19 (nullifier registry), and 20 (note / membership tree) are reserved in comments in `template/runtime/src/lib.rs`. Index 16 stays anti-rug. Index 17 stays quantum accounts.

### Circuit 1. PrivacyFlagEnforcement (build this first)

* Prove the four-bit mask is valid and matches what the transaction actually commits or reveals.
* Public: commitment, `PrivacyMask::as_bits` (u8), nullifier, chain id 7171, block window.
* Private: amount, blinding, keys as required by the hide bits.
* Pedersen commitment correctness. Flag validity via lookup.

### Circuit 2. BalanceIntegrity

* Shielded pool conservation: sum(inputs) = sum(outputs) + fee.
* Range proofs `[0, 2^64)` as Halo2 lookups, not a separate circuit.
* This is the inflation backstop.

### Circuit 3. NullifierDerivation

* `nullifier = Poseidon(note_secret, note_commitment)`.
* Merkle inclusion of the note under a recent root.
* Pallet enforces uniqueness. Circuit proves formation.

### Circuit 4. PTR_Generation

* On-chain id: Poseidon of keys, amount commitment, nonce.
* Replaces plaintext receipts in `pallet-ptr`.
* Witness stays off chain or encrypted.

### Circuit 5. DisclosureProof

* Selective reveal of fields that open the PTR hash.
* Replaces “burn a code and read the full receipt from storage”.

### Circuit 6. TrustRegistryMembership

* Merkle membership of a regulated counterparty.
* **New tree.** Do not overload index 16 (anti-rug projects).

### Runtime that ships with the circuits

* `pallet-zk-verifier`: `verify(circuit_id, proof, public_inputs)`.
* `pallet-nullifier-registry`: spent set.
* Note sparse Merkle tree, depth 32, Poseidon, store current root plus a short history of recent roots.
* Host function `verify_halo2_ipa`. Do not verify Halo2 inside Wasm.
* Update `pallet-privacy` so a private transfer without a valid Circuit 1 proof is rejected.
* Rewrite `pallet-ptr` to commitments.
* Hook a real private-transfer extrinsic **and** an EVM path so flags cannot be painted onto unrelated hashes. Both paths verify Circuit 1–6 against the same pool.

### Crypto parameters

* Curves: Pasta (Pallas prove, Vesta recurse).
* Commitment: IPA, no trusted setup.
* Hash: Poseidon over Pallas, width 3, 8 full / 56 partial rounds, alpha 5.
* Target: proof under 5KB, prove under a few seconds on mobile, verify fast via the host function.

### EVM (same selective privacy, second submission path)

* MetaMask / Solidity users pick the same four flags as native users. There is no EVM-only public mode.
* Precompile at `0x800`: `verifyPrivacyProof`, `isNullifierSpent`, `getTrustRegistryRoot`. Address is already reserved; replace the revert stub, do not pick a new address.
* View only. Cap proof size and public input count. Gas model required.
* Register methods in `template/runtime/src/precompiles.rs`.
* Proofs bind to chain ID 7171 and `PrivacyMask::as_bits`. Native and EVM must not fork the mask encoding.

### Security after the circuits exist

* Replay: bind proof to chain id + block window.
* Nullifier mempool front running.
* Proof malleability.
* Constraint-count regression in CI.
* Soundness tests on invalid witnesses.
* Measured weights, not hardcoded guesses.

### Out of ZK scope unless asked

* Mining points, ARX-P conversion payout, anti-rug badges, faucet, explorer, validator expansion, official MetaMask listing.
* ZK voting (litepaper) comes after these six circuits.

### Suggested first steps for the ZK engineer

* Use the frozen four-flag packing (`PrivacyMask::as_bits`) and chain ID 7171 as Circuit 1 public inputs. Do not invent a second mask encoding. Native and EVM share this packing.
* Add a `crates/zk` (or similar) Halo2 + Pasta + Poseidon crate. Prove a dummy circuit. Do not touch the runtime until that works.
* Implement Circuit 1 against the frozen mask.
* Sketch nullifier storage and both submission paths (native private-transfer extrinsic and EVM `0x800`).

---

## Housekeeping already done on this branch

* Duplicate mining crate under `template/pallets/` removed.
* Pallet crate metadata uses the workspace repository `Arxonchain/arxon-node`.
* Dev and local specs share chain ID 7171 and 18 decimal genesis.
* Template README no longer publishes Alith private keys.
* Sprint “Day N” labels stripped from Arxon commit titles.
* EVM precompile `0x800` reserved; `PrivacyMask::as_bits` frozen for Circuit 1.
