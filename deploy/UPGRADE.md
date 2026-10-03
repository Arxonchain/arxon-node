# Upgrading the testnet to spec 7

The testnet (`rpc-test.arxon.io`) runs node `0.0.0-80ad1e7d` with runtime spec 4. Spec 7 brings
specs 5 and 6 with it: the note tree leaf index, ARX-20 pools on `0x802`, hide balance, relayer
fees from the pool, per-token shielded units, and placeholder code at the precompile addresses.

## Rehearsed

This order was rehearsed on 2026-10-03 with the exact production binary (`80ad1e7d`):

1. A spec 4 chain with two notes shielded through `0x801` with real proofs.
2. `sudo.set_code` with the spec 7 Wasm while the old binary kept running. The migrations ran: the
   note tree moved to storage version 2 and kept its leaves in order and the same root, and
   `0x800`, `0x801` and `0x802` got their placeholder code.
3. Still on the old binary:
   * a relayed `unshieldWithFee` with real proofs went through the new `relayer.py`, which was paid
     its fee from the pool;
   * the relayer refused a fee paid to someone else;
   * `setBalanceVisibility` worked from an account;
   * a reference ARX-20 with 6 decimals deployed and fixed a shielded unit of 1.
4. The node restarted on the new binary over the same database and kept producing and finalizing
   blocks with the same state.

The new runtime adds no host function, so the old binary runs it. The new binary was **not**
rehearsed on spec 4: upgrade the runtime first, then the binary.

## Steps (on the VPS, as root)

```sh
cd /root/arxon-node
git fetch origin && git checkout stable2512 && git pull --ff-only
cargo build --release -p arxon-node      # new node and target/release/wbuild/.../arxon_runtime.compact.compressed.wasm

# 1. Runtime first, while the running node is still the old binary.
python3 scripts/apply-dev-runtime.py     # spec 4 -> 7, signed with the dev Alith sudo key

# 2. Then the node binary.
systemctl restart arxon-node

# 3. Relayer: its settings, then the new relayer.py, eth-abi and service unit (installs and restarts).
cat > /root/relayer.env <<'ENV'
RELAYER_MIN_FEE_WEI=1000000000000000
RELAYER_ACCEPT_FREE=1
RELAYER_TOKENS=
ENV
bash deploy/install-relayer.sh
```

`RELAYER_ACCEPT_FREE=1` keeps relaying the fee-free bundles today's wallets send. Set it to `0`
once the wallets send `unshieldWithFee` / `submitPrivateTransferWithFee` (see
[`crates/zk-prover/WALLET_INTEGRATION.md`](../crates/zk-prover/WALLET_INTEGRATION.md)). List the
ARX-20 tokens to relay in `RELAYER_TOKENS` as `0xToken:minFeeInTokenBaseUnits,...`. After editing
`/root/relayer.env`, `systemctl restart arxon-relayer`.

## Checks

```sh
RPC=https://rpc-test.arxon.io
q() { curl -s -X POST -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" $RPC; echo; }
q state_getRuntimeVersion '[]'                                               # specVersion 7
q eth_getCode '["0x0000000000000000000000000000000000000802","latest"]'     # "0x60006000fd"
q system_version '[]'                                                        # the new commit
curl -s $RPC/relay                                                            # min_fee_wei, accept_free, methods
```

## After the upgrade

* Rebuild the browser prover for the wallets (`scripts/build-prove-wasm.ps1`) and update the local
  `arxon-prove` binary: both accept the new `fee_wei`, `fee_recipient` and `shielded_unit_wei`
  fields.
* Pool and receipt events now carry an `asset` field. Anything that decodes them by position must
  be updated.
* ARX-20 tokens deployed before spec 7 cannot call `setShieldedDecimals` and keep the 10^9 unit. A
  pool that ran at an address without code (an EOA calling `0x802` directly) can no longer be used.
* Accounts that turned hide balance on before spec 7 have it in force immediately.
