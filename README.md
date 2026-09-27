# Arxon Node

Arxon is a sovereign Layer 1 blockchain built for the unbanked and diaspora communities, starting from Nigeria. It combines selective transaction privacy, full EVM compatibility, and a mobile first mining system on a single chain.

## What Makes Arxon Different

Most blockchains force a choice between full transparency and full privacy. Arxon lets the user choose, per transaction, exactly what to hide:

* Hide sender
* Hide receiver
* Hide amount
* Hide wallet balance

Those four flags are enforced by six Halo2 circuits (Pasta curves, IPA, Poseidon) over a shielded pool. A private transfer is rejected unless its proofs verify against the mask the user chose. See [Selective privacy with ZK](#selective-privacy-with-zk).

This is **selective privacy**: the user picks, per transaction, which of those fields to hide or reveal. The same four flags apply on the native Arxon path and on the EVM (Frontier / MetaMask / Solidity) path: one note tree, one nullifier set, one set of circuits. It is not three modes, and EVM is not left fully public.

This selective disclosure model is meant to protect remittance users from exposure while keeping a path for exchanges and regulators to verify a transaction when a party chooses to disclose it.

## Key Features

* Sovereign L1, independent consensus (AURA + GRANDPA)
* ARX native token, 1,000,000,000 total supply, 18 decimal places
* EVM compatible: Solidity, MetaMask, Ethereum tooling (Frontier)
* Selective privacy enforced by Halo2 proofs: shield, private transfer, unshield over a native shielded pool
* Private transaction receipts as commitments, opened to a chosen verifier with a disclosure proof
* Trust registry membership proofs for regulated counterparties (compliance attachment)
* EVM precompile `0x800` for proof verification and pool state (view only)
* ARX-P mining points and an on chain claim pallet (claim does not yet move balances)
* Anti rug trust registry for projects (Bronze / Silver / Gold)
* Post quantum account layer: ML-DSA-65, opt in
* EVM chain ID 7171

## Token Distribution

| Allocation | Amount | Percentage |
|---|---|---|
| Treasury | 300,000,000 ARX | 30% |
| Community Mining | 250,000,000 ARX | 25% |
| Investors | 200,000,000 ARX | 20% |
| Team (4yr vest) | 150,000,000 ARX | 15% |
| Staking Reserve | 100,000,000 ARX | 10% |

## Network Details

| Parameter | Value |
|---|---|
| Chain ID (EVM) | 7171 |
| Token Symbol | ARX |
| Decimals | 18 |
| Block Time | ~6 seconds |
| Consensus | AURA + GRANDPA |
| SDK | Polkadot SDK stable2512 |
| Rust | 1.88.0 (`rust-toolchain.toml`) |
| Base Fee | 0.1 Gwei |
| Block Size | 10MB |
| Runtime spec_name | arxon |

Dev and local testnet specs both use chain ID 7171. Do not use 42.

## Connect MetaMask

1. Open MetaMask → Add Network → Add manually
2. Network Name: `Arxon`
3. RPC URL: `http://YOUR_NODE_IP:9944`
4. Chain ID: `7171`
5. Currency Symbol: `ARX`
6. Decimals: `18`

## Run a Node

### Prerequisites

* Ubuntu 22.04 or later
* Rust 1.88.0 (the repo pins this in `rust-toolchain.toml`)
* 4GB RAM minimum
* libclang, protobuf-compiler

### Install Dependencies
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
# rust-toolchain.toml selects 1.88.0 and wasm32v1-none
sudo apt-get install -y libclang-dev clang protobuf-compiler
```

### Build
```bash
git clone https://github.com/Arxonchain/arxon-node.git
cd arxon-node
cargo build --release -p arxon-node
```

### Run Development Node
```bash
./target/release/arxon-node --dev
```

`--dev` uses well-known test keys (Alith as sudo and treasury, `//Alice` as the Aura/GRANDPA authority). Those private keys are public. Anyone can control a node that ships this genesis. Use `--dev` on a machine you trust. Do not use this genesis for a public testnet or mainnet. Generate fresh sudo, treasury, and validator keys first.

`--rpc-external --unsafe-rpc-external` opens RPC to other machines and disables origin checks. That is for a local MetaMask session only. Do not expose it on the public internet.

```bash
./target/release/arxon-node --dev --rpc-external --unsafe-rpc-external
```

## Security notes

* Fields hidden by the mask never reach chain state: a full node sees commitments, nullifiers and proofs. Some things are public by design. The account that signs and pays for a shielded extrinsic is visible (v1 limitation, see below). A shield shows its depositor and amount, an unshield its recipient and amount, and an on chain `disclose` shows the fields it reveals.
* PTR receipts store a Poseidon commitment only. See [Disclosures](#disclosures) for how to open one privately.
* `register_shielded_key` takes no proof that the caller holds the key. Someone can register a key they saw revealed before its owner does, and events then name the wrong account. Treat `sender_account` and `receiver_account` in events as advisory and the revealed key as authoritative. A key ownership proof is future work.
* Weights of the ZK pallets are measured on a developer laptop (see below); re-run the benchmarks on the validators' reference hardware before mainnet.
* Quantum accounts are opt in. ECDSA can still register or remove a quantum key.
* Do not commit `.env`, keystores, or mnemonic files. The well-known Alith key in Frontier docs is for local `--dev` only.

## Custom pallets

All Arxon pallets live under `template/pallets/<name>/` and are registered in `template/runtime/src/lib.rs`.

| Index | Crate | What it does |
|---|---|---|
| 12 | pallet-mining | ARX-P points. `register_miner`, sudo `credit_points`. |
| 13 | pallet-privacy | Shielded pool. `register_shielded_key`, `shield`, `unshield`, `submit_private_transfer` with Halo2 proof bundles; `set_privacy_default`, `set_balance_visibility`. Four flag `PrivacyMask`, bit packing `as_bits` (sender, receiver, amount, balance). |
| 14 | pallet-arx-claim | Snapshot and `claim_arx`. Records the claim; it does not yet mint or transfer ARX. |
| 15 | pallet-ptr | Receipt commitments recorded by private transfers (Circuit 4) and `disclose` with a Circuit 5 proof bound to the caller. |
| 16 | pallet-trust-registry | Project anti rug badges and liquidity lock tiers. Not the ZK exchange membership tree. |
| 17 | pallet-quantum-account | ML-DSA-65 register / deregister / `quantum_dispatch`. Opt in. ECDSA still signs the outer extrinsic. |
| 18 | pallet-zk-verifier | Circuit registry (frozen VK hash, enable switch) and the `VerifyProof` service over the `verify_halo2_ipa` host function. |
| 19 | pallet-nullifier-registry | Spent nullifier set. |
| 20 | pallet-note-tree | Depth 32 note commitment tree and depth 16 membership tree, Poseidon, root history of 65536 inserts. `add_member` is root only. |

Frontier EVM pallets occupy indices 7 through 11. EVM precompile `0x800` verifies proofs and reads pool state (view only).

## Selective privacy with ZK

Code map:

| Path | Crate | Role |
|---|---|---|
| `crates/zk-primitives` | `arxon-zk-primitives` | `no_std` contract shared by circuits and runtime: circuit ids, field encoding, public input layouts, bundle digest, tagged Poseidon, frozen VK hashes. |
| `crates/zk` | `arxon-zk` | The six Halo2 circuits, prover, verifier, key cache, pins, reference Merkle trees and a wallet module that builds witnesses. `std` only. |
| `template/primitives/zk-host` | `arxon-zk-host` | Host function `verify_halo2_ipa(circuit_id, vk_hash, proof, public_inputs)`. Verification never runs inside Wasm. |
| `template/primitives/zk-runtime-api` | `arxon-zk-runtime-api` | `ArxonZkApi`: note and membership roots, anchor and nullifier lookups, circuit status. |
| `template/pallets/{zk-verifier,nullifier-registry,note-tree,privacy,ptr}` | pallets 18, 19, 20, 13, 15 | Runtime enforcement. |
| `template/precompiles/zk` | `pallet-evm-precompile-arxon-zk` | Precompile `0x800`. |

### Shielded pool

* Funds shielded with `shield` move from the depositor to the pool account `0x6d6f646c6172782f73686c640000000000000000` (`PalletId(*b"arx/shld")`). `unshield` pays out of that account. The pool never mints.
* Shielded amounts are `u64` multiples of the shielded unit, `10^9` base units (1 gwei of ARX). Transparent amounts must be exact multiples.
* Every proof binds `chain_id = 7171` (a fixed constant inside every verifying key) and an `expiry_block` accepted only in `[now, now + 128]`.
* Every proof also binds the bundle digest `blake2_256("arxon/bundle/v2" ++ SCALE(chain_id, expiry_block, recipient, transparent_in, transparent_out, fee, nullifiers, commitments, cv_inputs, cv_outputs, mask_bits, blake2_256(encrypted_notes), receipt, compliance))[..31] ++ 0x00`, recomputed by the pallet from the extrinsic. `receipt` is `Option<(payment_output_index, ptr_id)>` and `compliance` is `Option<(output_index, registry_root)>`. A proof cannot be lifted onto a different transfer, recipient or mask, and a relayer cannot strip an attached receipt or compliance attestation. The signer is not in the digest, so any relayer may submit a bundle.
* Anchors (note tree roots) stay valid for the last 65536 inserts. A test derives that bound from the measured weights: blocks full of the cheapest inserts cannot evict an anchor within the 128 block proof validity window.
* A bundle carries at most 2 inputs and 2 outputs. Missing slots are the public dummy commitment `H_CV(0, 0)`.
* Nullifiers are rejected if spent or repeated inside a bundle; commitments are rejected if already in the tree.
* Encrypted notes (`BoundedVec<u8, 512>` per output) travel in the event only, hashed into the digest. The wallet encrypts them to the recipient.

Calls of `pallet-privacy`:

| Call | Arguments | Proofs |
|---|---|---|
| `register_shielded_key` | `pk` | none. Links the signer to a shielded key so reveals resolve to an account. |
| `shield` | `amount, outputs, mask_bits, expiry_block, proofs` | C1 (one instance per output), C2 |
| `unshield` | `recipient, amount, anchor, inputs, outputs, mask_bits, expiry_block, proofs` | C3 (one instance per input), C1 for change, C2 |
| `submit_private_transfer` | `anchor, inputs, outputs, mask_bits, expiry_block, ptr, compliance, proofs` | C3, C1, C2, plus C4 when `ptr` is attached and C6 when `compliance` is attached |

`ptr` is `PtrAttachment { payment_output_index, ptr_id }`. `compliance` is `ComplianceAttachment { output_index, registry_root }`, where `registry_root` may be any recent membership root, so an `add_member` does not invalidate proofs in flight.

### Disclosures

A receipt is `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`. Circuit 4 proves at payment time that `pk_s` owns every note the bundle spends and that `pk_r` owns the paid note, so a receipt cannot name anyone else. Circuit 5 later opens the receipt selectively, revealing the fields its mask does not hide, to an `audience` (the digest of the verifier's account).

* **Private disclosure.** The receipt holder builds the Circuit 5 proof and hands it to the auditor off chain. The auditor checks it with an `eth_call` to `verifyPrivacyProof(5, proof, inputs)` at `0x800`, or with the host function. Nothing is written or published.
* **On chain disclosure.** `pallet-ptr::disclose(ptr_id, disclosure_mask, revealed, expiry_block, proof)` records an attestation signed by the auditor. The revealed fields are extrinsic arguments and event data, so they become public. The audience binding only stops another account from reusing the same proof on chain.

### Circuits

Hash: Poseidon over Pallas (`P128Pow5T3`: width 3, 8 full and 56 partial rounds, alpha 5), domain separated by a tag in the capacity element. Keys `pk = H_PK(sk)`, `nk = H_NK(sk)`; note `cm = H_NOTE(pk, amount, rho)`; nullifier `nf = H_NF(nk, cm)`; value commitment `cv = H_CV(amount, blinding)`; receipt `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`.

Public inputs are canonical little endian Pallas base field elements. Amounts are `u64`. Masks use the frozen `PrivacyMask::as_bits` packing: bit 0 hide_sender, bit 1 hide_receiver, bit 2 hide_amount, bit 3 hide_balance.

| Id | Circuit | K | Proof bytes (1 / 2 instances) | Public rows per instance |
|---|---|---|---|---|
| 1 | PrivacyFlagEnforcement | 9 | 3456 / 4960 | `cv, cm, mask, revealed_receiver, revealed_amount, bundle_digest, chain_id, expiry_block` |
| 2 | BalanceIntegrity | 9 | 3456 | `cv_in0, cv_in1, cv_out0, cv_out1, transparent_in, transparent_out, fee, bundle_digest, chain_id, expiry_block` |
| 3 | NullifierDerivation | 11 | 3584 / 5088 | `anchor, nullifier, cv, mask, revealed_sender, bundle_digest, chain_id, expiry_block` |
| 4 | PTR_Generation | 9 | 3456 | `ptr_id, cv, cm, nullifier_0, nullifier_1, bundle_digest, chain_id, expiry_block` |
| 5 | DisclosureProof | 9 | 3456 | `ptr_id, disclosure_mask, revealed_sender, revealed_receiver, revealed_amount, audience, chain_id, expiry_block` |
| 6 | TrustRegistryMembership | 10 | 3520 | `registry_root, cm, bundle_digest, chain_id, expiry_block` |

Every single instance proof is under the 5 KB target. `make measure-zk` on a 24 thread developer laptop proves in 130 to 500 ms per proof with the wallet's multithreaded prover. Nodes verify single threaded; see [Weights](#weights) for those times. Verifying keys are pinned by hash in `arxon-zk-primitives::VK_HASHES`, and a node refuses the proofs of any circuit whose built key does not match its pin. Proof lengths are pinned per circuit and checked before the transcript is read, so trailing bytes are rejected.

The pallet builds every public input itself and enforces the cross circuit links:

* C2 value commitments equal the C3 and C1 instances.
* C1 commitments equal the leaves inserted.
* C4 `cv` and `cm` equal the paid output, and its two nullifier rows equal the bundle's input nullifiers (the first one twice for a one-input bundle).
* C6 `cm` equals an output of the bundle.

### EVM precompile `0x800`

All methods are `view`. Gas for `verifyPrivacyProof` is the verifier weight converted with `GasWeightMapping`.

| Method | Returns |
|---|---|
| `verifyPrivacyProof(uint8 circuitId, bytes proof, bytes32[][] publicInputs)` | `bool`. `false` for an invalid proof; reverts for an unknown or disabled circuit, a wrong row count or a proof over 8192 bytes. |
| `isNullifierSpent(bytes32)` | `bool` |
| `getTrustRegistryRoot()` | `bytes32` membership tree root |
| `getNoteTreeRoot()` | `bytes32` |
| `isKnownNoteRoot(bytes32)` | `bool`. `true` for the roots of the last 65536 inserts, current one included. The empty root is not an anchor: nothing can be spent under it. |

The empty note tree root is `0x1ca704bf814299b9f2b8c2331355744f2f23b9ad33e794590c9153a21fca001f` and the empty membership root is `0xcb7b604832ada5c237d29fb877d9fd8a127cf14c95c1a23d0338aad69d3fe906`.

A verification costs 250k to 800k gas (its weight at 40,000 ps per gas). `eth_call` runs with up to `--execute-gas-limit-multiplier` (default 10) times the 75M block gas limit, so one free call can run about 3000 verifications, around 30 seconds of CPU. Public RPC nodes should lower that multiplier.

### Deviations from the engineer briefing (for product sign-off)

* **Value commitments** are Poseidon hashes `H_CV(amount, blinding)` instead of Pedersen commitments. Conservation is proven inside Circuit 2 by opening the four commitments, so no elliptic curve chip is needed and the circuits stay at K 9 to 11.
* **Circuit 1 public inputs.** The nullifier moved to Circuit 3, since an output only circuit cannot prove what is spent. The "block window" is a single `expiry_block`; the pallet accepts it in `[now, now + 128]`.
* **Note tree.** It is an append only incremental Merkle tree, not a sparse Merkle tree. Duplicate leaves are rejected, and recent roots are kept as anchors.
* **Verifier interface.** `pallet-zk-verifier` exposes no `verify(circuit_id, proof, public_inputs)` extrinsic. It is the `VerifyProof` service that the pallets call, and it is reachable publicly through `0x800`.
* **EVM submission** (shield, unshield and private transfers from Solidity) is not in `0x800`, which stays view only as listed. It is planned as a separate precompile `0x801` dispatching into the same `pallet_privacy::execute` path.
* **Fees.** The extrinsic signer pays the fee and is visible. The bundle digest excludes the signer so relayers can submit on behalf of a user. The in circuit `fee` row exists and is fixed at 0 in v1.
* **`hide_balance`** (bit 3) has no in circuit meaning. It is recorded with the bundle mask. `HideBalanceAccounts` is a separate opt in flag set by `set_balance_visibility`, and transparent balances stay public.
* **Disclosure codes** are replaced by audience bound proofs (see [Disclosures](#disclosures)).

### Upgrading a running chain

The testnet runs spec 1. Spec 2 carries versioned migrations that register the six circuits with their frozen hashes, build the empty subtree chains of both trees, and delete the old plaintext receipts and disclosure codes. They do nothing on a chain created with spec 2.

Roll the new `arxon-node` binary out to every validator and full node **before** `set_code`. The runtime imports the `verify_halo2_ipa` host function, and an old binary stalls at the first block that verifies a proof.

### Testing

| Command | What runs |
|---|---|
| `make test` | Every unit test, including MockProver tests of every constraint, pallet tests with a fake verifier, and the runtime end to end tests with real proofs. |
| `make test-zk` | Circuit, host function and primitives tests in release. |
| `make test-zk-e2e` | Runtime end to end: shield, relayed private transfer, unshield, receipt and disclosure, membership attestation, tampered proof and retargeted recipient rejected. |
| `make measure-zk` | Proof sizes, timings and VK hashes; fails if a proof length or a verifying key hash drifts from its pin. |
| `make check-wasm` | The `no_std` crates the runtime embeds against `wasm32v1-none`. |
| `make integration-test` | ts-tests, including `test-arxon-zk-precompile.ts` against a running node. |

Changing a circuit changes its verifying key hash and proof lengths. To re-pin deliberately:

1. Print the new pins with `cargo test -p arxon-zk print_pins -- --ignored --nocapture`.
2. Update `crates/zk-primitives/src/vk_hashes.rs`, the circuit's `PROOF_LENGTHS` and its pinned test hash.
3. Regenerate the verifier benchmark fixtures with `cargo run --release -p arxon-zk --example gen_verifier_fixtures`. The `arxon-zk-host` test `verifier_benchmark_fixtures_still_verify` fails while they are stale.
4. Re-run the benchmarks. A running chain picks up the new hashes through the zk-verifier migration.

### Weights

The ZK pallets carry benchmarked weights (`benchmark pallet` through `arxon-node`, which registers the verifier host function; `frame-omni-bencher` cannot run them). Verification and tree inserts are measured directly; bundle extrinsics compose those primitives in `pallet-privacy/src/weights.rs` (one Circuit 3 verification per input, one Circuit 1 verification per output, one Circuit 2 verification, one nullifier mark per input, one insert per output, plus the receipt and membership attachments when present).

Nodes verify proofs single threaded: halo2's `multicore` feature is off in the node, so verification is deterministic in time and a panic cannot escape on a worker thread. The weights are measured that way on a developer laptop (Intel Core Ultra 9 275HX). `benchmark machine` passes every CPU and memory check against the Substrate reference hardware on it; only random disk writes fall short.

| Primitive | Ref time |
|---|---|
| Circuit 1 verification, 1 / 2 instances | 10.2 ms / 12.5 ms |
| Circuit 2 verification | 10.2 ms |
| Circuit 3 verification, 1 / 2 instances | 24.2 ms / 30.9 ms |
| Circuit 4, 5, 6 verification | 11.2 ms, 10.4 ms, 15.8 ms |
| Note tree insert (depth 32, Poseidon in Wasm) | 3.6 ms |
| Membership tree insert (depth 16) | 1.8 ms |
| Nullifier mark, receipt record | about 12 µs |

A 2 in / 2 out private transfer therefore costs about 61 ms of ref time, so a block of 3000 ms of normal dispatch weight holds about 49 of them. Regenerate with `make benchmark-zk` after building `arxon-node` with `--features runtime-benchmarks`.

## Roadmap

Done:

* Sovereign L1 with ARX genesis (1B, 18 decimals)
* EVM / Frontier, chain ID 7171
* Mining pallet
* Shielded pool with proof enforced privacy flags
* PTR pallet (commitments and disclosure proofs)
* ARX claim pallet (snapshot path; payout incomplete)
* Trust registry (anti rug)
* Quantum account pallet (ML-DSA-65, opt in) with pallet tests
* Six Halo2 circuits and runtime enforcement of the four privacy flags
* Nullifier set, note and membership trees, ZK verifier host function
* EVM precompile `0x800` for proof verification

Next:

* EVM submission precompile `0x801` (shield, unshield, private transfer from Solidity)
* ZK pallet weights re-measured on reference hardware
* Key ownership proof for `register_shielded_key`
* Removal from the trust registry membership tree
* Wallet SDK and mobile prover
* Public testnet, explorer, faucet, validator set
* Complete ARX claim so it actually pays from the mining allocation
* Mainnet

## Community

* Website: [arxon.io](https://arxon.io)
* Twitter: [@Arxonarx](https://twitter.com/Arxoninfra)
* Mining app: [arxonchain.xyz](https://arxonchain.xyz)

## License

Licensed under the Apache License, Version 2.0 and MIT license.

Built with [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) and [Frontier](https://github.com/polkadot-evm/frontier).
