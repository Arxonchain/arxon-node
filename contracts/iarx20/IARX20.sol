// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title ARX-20 (IARX20)
/// @notice Issued-token selective privacy on Arxon. Same four-bit PrivacyMask as
///         native ARX: bit0 sender, bit1 receiver, bit2 amount, bit3 balance.
///
/// Native ARX is not this interface. It is the chain currency with privacy at
/// `0x800` / `0x801`. Plain ERC-20 on Arxon stays fully public and never gains
/// these methods. Deploy this standard (or the reference `ARX20.sol`) when the
/// issuer wants shield / private transfer / unshield.
///
/// Public `transfer` / `approve` remain ERC-20 (visible). Privacy is the extra
/// door into a per-token tree at precompile `0x802`, which only a deployed
/// contract can open (an EOA or an EIP-7702 delegated account is refused).
///
/// Amounts and fees are multiples of the token's shielded unit,
/// `0x802.shieldedUnit(token)`: `10^(decimals - 9)` base units, or 1 for 9
/// decimals or fewer, once the token calls `0x802.setShieldedDecimals` (the
/// reference does it in its constructor). A token that never does keeps 10^9.
///
/// Hide balance: a bundle with mask bit 3 can pay privately but never
/// unshields, and nothing is unshielded to an account that turned hide balance
/// on at `0x801.setBalanceVisibility(true)`; its money stays in the pool.
///
/// The `WithFee` variants let a relayer submit for a user: the proofs bind
/// the fee `(recipient, amount)`, the pool releases it next to the payment,
/// and the token mints it to the fee recipient.
interface IARX20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);

    struct Output {
        bytes32 cm;
        bytes32 cv;
        bytes32 revealedReceiver;
        bytes32 revealedAmount;
        bytes encryptedNote;
    }

    struct Input {
        bytes32 nullifier;
        bytes32 cv;
        bytes32 revealedSender;
    }

    struct Proofs {
        bytes spend;
        bytes output;
        bytes balance;
        bytes receipt;
        bytes compliance;
    }

    struct RelayFee {
        address recipient;
        uint256 amount;
    }

    struct OptionalAttachment {
        bool present;
        uint8 outputIndex;
        bytes32 id;
    }

    /// Burn `amount` of public balance and insert notes into this token's tree.
    function shield(
        uint256 amount,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        Proofs calldata proofs
    ) external;

    /// Spend notes then mint `amount` to `recipient`.
    function unshield(
        address recipient,
        uint256 amount,
        bytes32 anchor,
        Input[] calldata inputs,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        Proofs calldata proofs
    ) external;

    /// Spend and create notes inside this token's pool. No public mint/burn.
    function transferPrivate(
        bytes32 anchor,
        Input[] calldata inputs,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        OptionalAttachment calldata ptr,
        OptionalAttachment calldata compliance,
        Proofs calldata proofs
    ) external;

    /// `unshield` relayed: also mints `fee.amount` to `fee.recipient`.
    function unshieldWithFee(
        address recipient,
        uint256 amount,
        bytes32 anchor,
        Input[] calldata inputs,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        RelayFee calldata fee,
        Proofs calldata proofs
    ) external;

    /// `transferPrivate` relayed: the fee leaves the pool and is minted to `fee.recipient`.
    function transferPrivateWithFee(
        bytes32 anchor,
        Input[] calldata inputs,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        OptionalAttachment calldata ptr,
        OptionalAttachment calldata compliance,
        RelayFee calldata fee,
        Proofs calldata proofs
    ) external;
}
