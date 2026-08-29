# Arxon node (Frontier template)

This folder is the Frontier-based node and runtime used by Arxon.

Build and run from the **repository root**. See the root `README.md` for chain ID 7171, token decimals, pallets, and how to start `arxon-node`.

```sh
cargo build --release -p arxon-node
./target/release/arxon-node --dev
```

`--dev` genesis uses well-known public test accounts (Alith, Alice). Those private keys are public. They are for local development only. Never reuse this genesis on a public network.

JSON-RPC for a local wallet is `http://127.0.0.1:9944`. Do not publish `--unsafe-rpc-external` to the internet.
