# Arxon Node

Arxon is a sovereign Layer 1 blockchain built for the unbanked and diaspora communities, starting from Nigeria. It combines selective transaction privacy, full EVM compatibility, and a mobile first mining system on a single chain.

## What Makes Arxon Different

Most blockchains force a choice between full transparency and full privacy. Arxon lets the user choose, per transaction, exactly what to hide:

* Hide sender
* Hide receiver
* Hide amount
* Hide wallet balance

Those four flags are stored in the runtime today. They are not yet cryptographically enforced. Halo2 proofs are the next layer of work.

This is **selective privacy**: the user picks, per transaction, which of those fields to hide or reveal. The same four flags apply on the native Arxon path and on the EVM (Frontier / MetaMask / Solidity) path. ZK will enforce that one model on both. It is not three modes, and EVM is not left fully public.

This selective disclosure model is meant to protect remittance users from exposure while keeping a path for exchanges and regulators to verify a transaction when a party chooses to disclose it.

## Key Features

* Sovereign L1, independent consensus (AURA + GRANDPA)
* ARX native token, 1,000,000,000 total supply, 18 decimal places
* EVM compatible: Solidity, MetaMask, Ethereum tooling (Frontier)
* Selective privacy flags on native and EVM (application layer until ZK lands)
* Private transaction receipts and single use disclosure codes (plaintext on chain until ZK lands)
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

* The privacy pallet does not hide data from a full node. Treat flags as application metadata until Halo2 is live.
* PTR receipts currently store plaintext. Do not treat them as cryptographic privacy.
* Quantum accounts are opt in. ECDSA can still register or remove a quantum key.
* Do not commit `.env`, keystores, or mnemonic files. The well-known Alith key in Frontier docs is for local `--dev` only.

## Custom pallets

All Arxon pallets live under `template/pallets/<name>/` and are registered in `template/runtime/src/lib.rs`.

| Index | Crate | What it does |
|---|---|---|
| 12 | pallet-mining | ARX-P points. `register_miner`, sudo `credit_points`. |
| 13 | pallet-privacy | Four flag `PrivacyMask`. Bit packing: `as_bits` (sender, receiver, amount, balance). Defaults, per tx record, balance visibility. Not hooked into transfers. |
| 14 | pallet-arx-claim | Snapshot and `claim_arx`. Records the claim; it does not yet mint or transfer ARX. |
| 15 | pallet-ptr | Private transaction receipts and disclosure codes. `create_receipt` is root only. Receipts store plaintext. |
| 16 | pallet-trust-registry | Project anti rug badges and liquidity lock tiers. Not the ZK exchange membership tree. |
| 17 | pallet-quantum-account | ML-DSA-65 register / deregister / `quantum_dispatch`. Opt in. ECDSA still signs the outer extrinsic. |

Frontier EVM pallets occupy indices 7 through 11. Indices 18 (verifier), 19 (nullifiers), and 20 (note tree) are reserved for ZK. EVM precompile `0x800` is reserved for proof verification; it reverts until the verifier lands.

## Roadmap

Done:

* Sovereign L1 with ARX genesis (1B, 18 decimals)
* EVM / Frontier, chain ID 7171
* Mining pallet
* Privacy flag pallet (application layer)
* PTR pallet (application layer)
* ARX claim pallet (snapshot path; payout incomplete)
* Trust registry (anti rug)
* Quantum account pallet (ML-DSA-65, opt in)

Next:

* Public testnet, explorer, faucet, validator set
* Complete ARX claim so it actually pays from the mining allocation
* Halo2 circuits and runtime enforcement of the four privacy flags
* Nullifier set, note commitment tree, ZK verifier host function
* EVM precompile for proof verification
* Mainnet

## Community

* Website: [arxon.io](https://arxon.io)
* Twitter: [@Arxonarx](https://twitter.com/Arxonarx)
* Mining app: [arxonchain.xyz](https://arxonchain.xyz)

## License

Licensed under the Apache License, Version 2.0 and MIT license.

Built with [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) and [Frontier](https://github.com/polkadot-evm/frontier).
