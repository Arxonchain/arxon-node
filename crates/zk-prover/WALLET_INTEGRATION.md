# Wallet integration (spec 7)

What `arxon-wallet` and `arxon-mobile` need to change for hide balance, relayer fees and ARX-20
units. The prover is the same in both places: the local `arxon-prove` server
(`POST http://127.0.0.1:17871/v1/*`) and the browser build (`arxon-prove-wasm`, same JSON).

Constants: `0x801` = `0x0000000000000000000000000000000000000801`, `0x802` = `...0802`, chain id
7171. Amounts are base units (wei for ARX) as decimal strings.

## 1. Hide balance

Read the flag in force:

```
0x801.isBalanceHidden(address account) view returns (bool)
```

(or the runtime API `ArxonZkApi_balance_hidden([u8; 20])`). Toggle it with a transaction the
user signs from their own account (a contract cannot call it):

```
0x801.setBalanceVisibility(bool hidden)
```

A change takes effect 129 blocks later (about 13 minutes at 6 second blocks); show it as pending
until `isBalanceHidden` returns the new value. Turning it back before then cancels the change.

While it is on, the wallet should:

* set mask bit 3 (`0b1000`) on every bundle it builds (shield, transfer, unshield are all
  `mask_bits` in the prover requests);
* not offer unshield (the chain refuses any unshield with bit 3, and the prover refuses to build
  one);
* send private payments through the relayer with a fee (section 2), so no public transaction ever
  comes from the user's account.

The chain refuses an unshield to an account with the flag on, and refuses to pay a relayer fee to
it. If the user pastes a recipient for an unshield, check `isBalanceHidden(recipient)` first and
explain instead of failing at submission.

## 2. Relayer fees

The relayer's terms:

```
GET https://rpc-test.arxon.io/relay
{ "payer": "0x…", "fee_recipient": "0x…", "min_fee_wei": "1000000000000000",
  "accept_free": true, "tokens": { "0xtoken": "minFee" }, "native_methods": {…}, "token_methods": {…} }
```

Pick the fee, in wei: at least `min_fee_wei`, and enough to cover the gas (`eth_gasPrice` ×
about 2,000,000 gas for a 2 input bundle), rounded up to a multiple of `10^9`. The fee comes out
of the spent note together with the payment, so `amount + fee` must fit in the note; the change
note gets the rest.

Ask the prover with the fee:

```json
POST /v1/unshield
{ "amount_wei": "990000000000000000", "mask_bits": 0, "expiry_block": 1234,
  "sk_hex": "0x…", "recipient": "0x…",
  "note": { "amount_wei": "1000000000000000000", "rho": "0x…", "leaf_index": 0 },
  "leaves": ["0x…", "…"],
  "fee_wei": "10000000000000000", "fee_recipient": "0x<relayer fee_recipient>" }
```

`POST /v1/transfer` takes the same `fee_wei` and `fee_recipient`. The response repeats them
(`fee_wei`, `fee_recipient`) next to `anchor`, `inputs`, `outputs` and `proofs`. The proofs bind
both, so the call must carry exactly those values.

Encode the call with the fee as one tuple `(address recipient, uint256 amount)`:

```
unshieldWithFee(address recipient, uint256 amount, bytes32 anchor,
                (bytes32,bytes32,bytes32)[] inputs,
                (bytes32,bytes32,bytes32,bytes32,bytes)[] outputs,
                uint8 maskBits, uint256 expiryBlock,
                (address,uint256) fee,
                (bytes,bytes,bytes,bytes,bytes) proofs)

submitPrivateTransferWithFee(bytes32 anchor, (bytes32,bytes32,bytes32)[] inputs,
                (bytes32,bytes32,bytes32,bytes32,bytes)[] outputs,
                uint8 maskBits, uint256 expiryBlock,
                (bool,uint8,bytes32) ptr, (bool,uint8,bytes32) compliance,
                (address,uint256) fee,
                (bytes,bytes,bytes,bytes,bytes) proofs)
```

and post it to the relayer:

```json
POST https://rpc-test.arxon.io/relay
{ "data": "0x<calldata>" }            ->  { "hash": "0x…" }   or   { "error": "…" }
```

The relayer refuses a fee paid to anyone else, a fee under its minimum or under the gas it would
spend, and any bundle that would revert. Fee-free `unshield` / `submitPrivateTransfer` are only
relayed while `accept_free` is `true`, which ends once the wallets send fees.

## 3. ARX-20 tokens

* The token's shielded unit is `0x802.shieldedUnit(address token) view returns (uint256)`. Pass it
  as `"shielded_unit_wei"` in every prover request for that token, with `"token": "0x…"`. Amounts
  and fees are multiples of it. A 6-decimal token has unit 1, so any amount works.
* Token bundles go to the token contract, not to `0x802`: `shield`, `unshield`, `transferPrivate`,
  and the relayed `unshieldWithFee` / `transferPrivateWithFee` (same arguments as on `0x801`). The
  token mints the relayer fee to `fee.recipient`, in the token.
* To relay a token bundle, post `{ "data": "0x…", "to": "0xToken" }`. The relayer only relays
  tokens it lists in `tokens`, with that token's minimum fee in token base units.
* Notes, roots and nullifiers of a token are read from `0x802` (`getNoteLeaves(address,uint256,uint256)`,
  `getNoteTreeRoot(address)`, `isNullifierSpent(address,bytes32)`), never from `0x800`.
* A new token deploys `ARX20(name, symbol, decimals, initialSupply)`; its constructor fixes the unit.

## 4. Events

Every pool event now names its asset first: `Shielded`, `Unshielded`, `BundleExecuted`,
`NoteSpent`, `NoteCreated`, `ComplianceAttested` and the new `FeePaid { asset, recipient, amount,
bundle_digest }` carry `asset: Native | Arx20(token)`. `PTR.ReceiptCreated` carries `asset` and
`PTR.Disclosed` carries `asset: Option<_>`. Code that decodes these with the runtime metadata keeps
working; code that decodes by field position must add the field.
