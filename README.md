# Arxon Node

Arxon is a sovereign Layer-1 blockchain built for the unbanked and diaspora communities, starting from Nigeria. It combines selective transaction privacy, full EVM compatibility, and a mobile-first mining system,all on a single chain.

## What Makes Arxon Different

Most blockchains force a choice between full transparency and full privacy. Arxon gives users complete control per transaction, you choose exactly what to hide:

- Hide sender
- Hide receiver  
- Hide amount
- Hide wallet balance

This selective disclosure model is unique. It protects remittance users from exposure while keeping the chain auditable for exchanges and regulators.

## Key Features

- **Sovereign L1** — Not a fork, not a sidechain. Arxon is its own independent blockchain with its own consensus (BABE/GRANDPA)
- **ARX Token** — Native token with 1,000,000,000 total supply and 12 decimal places
- **EVM Compatible** — Deploy Solidity smart contracts. Connect MetaMask. Use any Ethereum tooling
- **Selective Privacy** — Per-transaction privacy flags for sender, receiver, amount, and balance
- **Mining System** — Browser and mobile mining via ARX-P points, convertible to ARX at mainnet
- **Chain ID** — 7171

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
| Decimals | 12 |
| Block Time | ~6 seconds |
| Consensus | BABE/GRANDPA (PoS) |
| SDK | Polkadot SDK stable2512 |
| TPS | 2,000-3,000 transparent / 500-800 mixed private |
| Base Fee | 0.1 Gwei (~0.001 ARX per transfer) |
| Block Size | 10MB |

## Connect MetaMask

1. Open MetaMask → Add Network → Add manually
2. Network Name: `Arxon Dev`
3. RPC URL: `http://YOUR_NODE_IP:9944`
4. Chain ID: `7171`
5. Currency Symbol: `ARX`

## Run a Node

### Prerequisites

- Ubuntu 22.04 or later
- Rust (nightly toolchain)
- 4GB RAM minimum
- libclang, protobuf-compiler

### Install Dependencies
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup install nightly
rustup target add wasm32-unknown-unknown --toolchain nightly

# Install system dependencies
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

### Run with External RPC (for MetaMask/dApps)
```bash
./target/release/arxon-node --dev --rpc-external --unsafe-rpc-external
```

## Custom Pallets

### pallet-mining
Tracks ARX-P mining points per account. Foundation for the ARX claim system at mainnet.
- `register_miner()` — Register as a miner
- `credit_points()` — Sudo: credit points to an account

### pallet-privacy
Selective privacy per transaction. Users control exactly what information is visible on-chain.
- `set_privacy_default()` — Set default privacy preferences
- `record_tx_privacy()` — Record privacy mask for a specific transaction
- `set_balance_visibility()` — Toggle wallet balance visibility

## Roadmap

- [x] Sovereign L1 chain with ARX token
- [x] Mining pallet (ARX-P points system)
- [x] Selective privacy pallet
- [x] EVM compatibility (Frontier)
- [x] Real 1B ARX genesis supply
- [ ] Multi-node public testnet
- [ ] ARX claim pallet for miners
- [ ] Halo2 ZK proof integration
- [ ] Mainnet launch (early 2027)

## Community

- Website: [arxon.io](https://arxon.io)
- Twitter: [@Arxonarx](https://twitter.com/Arxonarx)
- Mining App: Join 1M+ miners earning ARX-P points

## License

Licensed under the Apache License, Version 2.0 and MIT license.

Built with [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) and [Frontier](https://github.com/polkadot-evm/frontier).
