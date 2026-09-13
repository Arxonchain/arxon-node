# Arxon engineer briefing

Clone branch `stable2512`. Read this once before writing circuits or changing the runtime. The same text is on the GitHub Issues tab of this repository.

Status on branch `zk/selective-privacy` (September 2026): the six Halo2 circuits, the three ZK pallets, the host function, the privacy and PTR rewrites, the `0x800` precompile and the quantum account tests are implemented and tested. The sections below keep the original requirements and record, per item, what was delivered and where it deviates. The root `README.md` section "Selective privacy with ZK" is the user facing summary.

Remaining after this delivery: EVM submission precompile `0x801` (separate increment), weights re-measured on reference hardware, wallet SDK and mobile prover, public network keys.

---

## What is live in the chain and in the code

### Node, consensus, EVM

* Sovereign Layer 1, not a parachain. Binary: `arxon-node`.
* Consensus: AURA + GRANDPA, about 6 second slots. Litepaper still says BABE. The code is AURA.
  * Wiring: `template/node/src/service.rs`, `template/runtime/src/lib.rs` (`pallet_aura`, `pallet_grandpa`).
* Polkadot SDK `stable2512`. Rust `1.88.0` in `rust-toolchain.toml`.
* EVM via Frontier. Chain ID **7171** on both the development spec and the local testnet spec. Constant: `ARXON_EVM_CHAIN_ID` in `template/runtime/src/lib.rs`. Specs: `template/node/src/chain_spec.rs`.
* MetaMask RPC: `http://127.0.0.1:9944`. Token symbol `ARX`, 18 decimals (`ARX_DECIMALS`, `ARX_UNIT`).
* Standard Ethereum precompiles at `0x01` through `0x05`, plus Frontier extras at `0x400` through `0x403` (SHA3-FIPS, ECRecover public key, Curve25519 add/mul). File: `template/runtime/src/precompiles.rs`. Address `0x800` is the Arxon ZK precompile (`template/precompiles/zk`): `verifyPrivacyProof`, `isNullifierSpent`, `getTrustRegistryRoot`, `getNoteTreeRoot`, `isKnownNoteRoot`, all view.
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
* `set_privacy_default`, `set_balance_visibility`
* `register_shielded_key(pk)`: links the signer to a shielded public key so revealed parties resolve to accounts.
* `shield(amount, outputs, mask_bits, expiry_block, proofs)`: moves ARX into the pool account (`PalletId arx/shld`) and inserts the output commitments. Proofs: Circuit 1 per output, Circuit 2.
* `unshield(recipient, amount, anchor, inputs, outputs, mask_bits, expiry_block, proofs)`: spends notes, pays the recipient from the pool. Proofs: Circuit 3 per input, Circuit 1 per change output, Circuit 2.
* `submit_private_transfer(anchor, inputs, outputs, mask_bits, expiry_block, ptr, compliance, proofs)`: shielded to shielded, optional Circuit 4 receipt and Circuit 6 membership attachments.
* `record_tx_privacy` was removed (call index 1 is burned). Flags can no longer be painted onto arbitrary hashes; `TxPrivacyMask` is keyed by bundle digest and written only by a verified bundle.
* Storage: `AccountPrivacyDefault`, `TxPrivacyMask`, `ShieldedTxCount`, `HideBalanceAccounts`, `ShieldedKeys`, `ShieldedKeyOwners`.
* Every bundle is checked before any write: mask validity, expiry window, unit multiples, known anchor, unspent and unique nullifiers, then every proof in the fixed order C3, C1, C2, C4, C6 against public inputs the pallet builds itself (including the bundle digest that binds recipient, amounts, nullifiers, commitments and mask). Tests in `template/pallets/privacy/src/tests.rs` break every cross circuit link.

**Index 14. ARX claim** (`template/pallets/arx-claim/src/lib.rs`)

* `set_snapshot`, `set_arx_per_point`, `set_claiming_status` (root)
* `claim_arx` (signed)
* `Currency` is in the config. **`claim_arx` does not mint or transfer ARX.** It only records the claim.

**Index 15. PTR** (`template/pallets/ptr/src/lib.rs`)

* Receipts are commitments `ReceiptCommitment { cv, block_number, mask_bits }` keyed by `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`, recorded by `pallet-privacy` when a private transfer attaches a Circuit 4 proof.
* `disclose(ptr_id, disclosure_mask, revealed, expiry_block, proof)`: the signer opens the receipt with a Circuit 5 proof whose `audience` row is the signer's digest, so the proof cannot be replayed to a third party. Revealed parties resolve to accounts through the shielded key registry.
* Plaintext receipts, `create_receipt` and disclosure codes are gone. No migration for previous data (dev and local testnet only).

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
* Pallet tests: done. `template/pallets/quantum-account/src/{mock,tests}.rs`, 20 tests with real ML-DSA-65 keys and signatures (registration, removal, dispatch as the quantum signer, nonce, replay, foreign key, signature over another call, rollback and retry after an inner failure).
* Public testnet / mainnet must **not** use Alith / `//Alice`. Generate new sudo, treasury, and validator keys offline.

---

## ZK work (circuits and integration): requirements and delivery

Delivered layout:

| Path | Crate | Runtime index |
|---|---|---|
| `crates/zk-primitives` | `arxon-zk-primitives` (`no_std`) | shared contract: ids, field encoding, public input layouts, bundle digest, tagged Poseidon, frozen VK hashes |
| `crates/zk` | `arxon-zk` (`std`) | six circuits, prover, verifier, key cache, pins, reference trees, wallet witness builders, `examples/measure.rs` |
| `template/primitives/zk-host` | `arxon-zk-host` | host function `verify_halo2_ipa` |
| `template/primitives/zk-runtime-api` | `arxon-zk-runtime-api` | `ArxonZkApi` |
| `template/pallets/zk-verifier` | `pallet-zk-verifier` | 18 |
| `template/pallets/nullifier-registry` | `pallet-nullifier-registry` | 19 |
| `template/pallets/note-tree` | `pallet-note-tree` | 20 (note tree depth 32 and membership tree depth 16 in one pallet, keyed by `TreeId`) |
| `template/precompiles/zk` | `pallet-evm-precompile-arxon-zk` | `0x800` |

Measured on a 24 core desktop (`make measure-zk`): single instance proofs are 3456 to 3584 bytes (two instance proofs up to 5088), proving 110 to 410 ms, verification 2 to 5 ms. Verifying key hashes are frozen in `arxon-zk-primitives::VK_HASHES` and asserted by tests; proof lengths are pinned per circuit and instance count and checked before the transcript is read.

Deviations agreed with the product owner:

* Value commitments are Poseidon `cv = H_CV(amount, blinding)` instead of Pedersen. Conservation is proven inside Circuit 2 by opening the four commitments; no ECC chip, smaller circuits.
* `0x800` stays view only as listed below. EVM submission goes to a separate `0x801` precompile (not started, separate approval).
* The extrinsic signer is visible and pays the fee in v1; the bundle digest excludes the signer so relayers work. The `fee` public row is fixed at 0.
* `hide_balance` (bit 3) has no in circuit effect; the pallet records it.
* One proof per circuit per bundle with up to 2 instances (2 in / 2 out), so a full private transfer is 3 proofs.

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
* Delivered (`crates/zk/src/circuits/c1_privacy_flags`, K 9): one instance per output. Public rows `cv, cm, mask, revealed_receiver, revealed_amount, bundle_digest, chain_id, expiry_block`. Mask validity by a 16 row lookup table that also yields the four bits; reveal gates force `revealed_receiver = pk_r` and `revealed_amount = amount` unless the matching bit hides them (then 0). The nullifier and the sender reveal live in Circuit 3, since an output only circuit cannot prove who spends.

### Circuit 2. BalanceIntegrity

* Shielded pool conservation: sum(inputs) = sum(outputs) + fee.
* Range proofs `[0, 2^64)` as Halo2 lookups, not a separate circuit.
* This is the inflation backstop.
* Delivered (`c2_balance`, K 9): fixed 2 in / 2 out. Rows `cv_in0, cv_in1, cv_out0, cv_out1, transparent_in, transparent_out, fee, bundle_digest, chain_id, expiry_block`. Opens the four value commitments, 64 bit byte table range checks on every amount, gate `v_in0 + v_in1 + transparent_in = v_out0 + v_out1 + transparent_out + fee`. Unused slots carry the public `H_CV(0, 0)`.

### Circuit 3. NullifierDerivation

* `nullifier = Poseidon(note_secret, note_commitment)`.
* Merkle inclusion of the note under a recent root.
* Pallet enforces uniqueness. Circuit proves formation.
* Delivered (`c3_nullifier`, K 11): one instance per input. Rows `anchor, nullifier, cv, mask, revealed_sender, bundle_digest, chain_id, expiry_block`. Derives `pk`, `nk`, `cm`, a depth 32 Poseidon Merkle path to `anchor`, `nf = H_NF(nk, cm)`, a fresh `cv`, and the sender reveal gate on the proven spend key.

### Circuit 4. PTR_Generation

* On-chain id: Poseidon of keys, amount commitment, nonce.
* Replaces plaintext receipts in `pallet-ptr`.
* Witness stays off chain or encrypted.
* Delivered (`c4_ptr`, K 9): rows `ptr_id, cv, bundle_digest, chain_id, expiry_block`. The pallet forces `cv` to equal the value commitment of the output named by `PtrAttachment.payment_output_index`.

### Circuit 5. DisclosureProof

* Selective reveal of fields that open the PTR hash.
* Replaces “burn a code and read the full receipt from storage”.
* Delivered (`c5_disclosure`, K 9): rows `ptr_id, disclosure_mask, revealed_sender, revealed_receiver, revealed_amount, audience, chain_id, expiry_block`. Same four bit packing with bit 3 forbidden; `audience` is the digest of the verifier account, set by `pallet-ptr::disclose` from the signer.

### Circuit 6. TrustRegistryMembership

* Merkle membership of a regulated counterparty.
* **New tree.** Do not overload index 16 (anti-rug projects).
* Delivered (`c6_membership`, K 10): rows `registry_root, cm, bundle_digest, chain_id, expiry_block`. Depth 16 membership tree in `pallet-note-tree` (`TreeId::Member`, root only `add_member`), leaf `H_MEMBER(pk)`; `cm = H_NOTE(pk_member, amount, rho)` ties the member to an actual output of the bundle.

### Runtime that ships with the circuits

* `pallet-zk-verifier`: `verify(circuit_id, proof, public_inputs)`.
* `pallet-nullifier-registry`: spent set.
* Note sparse Merkle tree, depth 32, Poseidon, store current root plus a short history of recent roots.
* Host function `verify_halo2_ipa`. Do not verify Halo2 inside Wasm.
* Update `pallet-privacy` so a private transfer without a valid Circuit 1 proof is rejected.
* Rewrite `pallet-ptr` to commitments.
* Hook a real private-transfer extrinsic **and** an EVM path so flags cannot be painted onto unrelated hashes. Both paths verify Circuit 1–6 against the same pool.
* Delivered: all of the above except the EVM submission path (`0x801`, pending). The note tree is an append only Poseidon Merkle tree with `KnownLeaves` duplicate rejection and a 1024 root history; Poseidon runs inside the runtime Wasm for inserts, verification runs natively through the host function only. Circuits can be disabled by governance (`set_circuit_enabled`), VK hashes are genesis constants.

### Crypto parameters

* Curves: Pasta (Pallas prove, Vesta recurse).
* Commitment: IPA, no trusted setup.
* Hash: Poseidon over Pallas, width 3, 8 full / 56 partial rounds, alpha 5.
* Target: proof under 5KB, prove under a few seconds on mobile, verify fast via the host function.
* Delivered: Pasta with IPA (`halo2_proofs` 0.3.5, `halo2_gadgets` 0.5.0, `halo2_poseidon` 0.1.0), Poseidon `P128Pow5T3` with domain tags in the capacity element. Single instance proofs 3456 to 3584 bytes. Mobile proving is not measured yet; desktop proving is 110 to 410 ms.

### EVM (same selective privacy, second submission path)

* MetaMask / Solidity users pick the same four flags as native users. There is no EVM-only public mode.
* Precompile at `0x800`: `verifyPrivacyProof`, `isNullifierSpent`, `getTrustRegistryRoot`. Address is already reserved; replace the revert stub, do not pick a new address.
* View only. Cap proof size and public input count. Gas model required.
* Register methods in `template/runtime/src/precompiles.rs`.
* Proofs bind to chain ID 7171 and `PrivacyMask::as_bits`. Native and EVM must not fork the mask encoding.
* Delivered: `0x800` with the three listed methods plus `getNoteTreeRoot` and `isKnownNoteRoot`, all view, proof capped at 8192 bytes and public inputs at 2 instances of 16 rows, gas from the verifier weight. `ts-tests/tests/test-arxon-zk-precompile.ts` exercises it against a running node. Submission from Solidity is the pending `0x801` increment.

### Security after the circuits exist

* Replay: bind proof to chain id + block window.
* Nullifier mempool front running.
* Proof malleability.
* Constraint-count regression in CI.
* Soundness tests on invalid witnesses.
* Measured weights, not hardcoded guesses.
* Delivered: replay (chain id constant in every VK, expiry window, bundle digest), front running (digest binds recipient and nullifiers), malleability (exact proof length pins, canonical field decoding), constraint regression (VK hash and proof length pins asserted in `make test`), soundness (a failing witness test per constraint and a tamper test per public row). Weights: pallets 13, 15, 18, 19, 20 have `#[benchmarks]` modules and weights measured through `arxon-node benchmark pallet` on a developer desktop (verification 3 to 6 ms per proof, note tree insert 5.1 ms); bundle extrinsics compose the measured primitives. Re-run `make benchmark-zk` on the reference hardware before mainnet.

### Out of ZK scope unless asked

* Mining points, ARX-P conversion payout, anti-rug badges, faucet, explorer, validator expansion, official MetaMask listing.
* ZK voting (litepaper) comes after these six circuits.

### Suggested first steps for the ZK engineer

* Use the frozen four-flag packing (`PrivacyMask::as_bits`) and chain ID 7171 as Circuit 1 public inputs. Do not invent a second mask encoding. Native and EVM share this packing.
* Add a `crates/zk` (or similar) Halo2 + Pasta + Poseidon crate. Prove a dummy circuit. Do not touch the runtime until that works.
* Implement Circuit 1 against the frozen mask.
* Sketch nullifier storage and both submission paths (native private-transfer extrinsic and EVM `0x800`).

---

## How to run the delivery

* `make test`: every unit test, including the runtime end to end tests with real proofs (`template/runtime/src/zk_integration.rs`).
* `make test-zk`, `make test-zk-e2e`, `make measure-zk`, `make check-wasm`: see the Makefile.
* `cargo build --release -p arxon-node && ./target/release/arxon-node --dev --tmp`, then `state_call ArxonZkApi_note_tree_root` returns the empty root `0x1ca704bf…` and `eth_call` to `0x800` answers `getTrustRegistryRoot()` with `0xcb7b6048…`.
* `make integration-test` runs the ts-tests, including the `0x800` spec.

## Housekeeping already done on this branch

* Duplicate mining crate under `template/pallets/` removed.
* Pallet crate metadata uses the workspace repository `Arxonchain/arxon-node`.
* Dev and local specs share chain ID 7171 and 18 decimal genesis.
* Template README no longer publishes Alith private keys.
* Sprint “Day N” labels stripped from Arxon commit titles.
* EVM precompile `0x800` reserved; `PrivacyMask::as_bits` frozen for Circuit 1.
