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
/// door into a per-token tree at precompile `0x802`. Amounts must be multiples
/// of 10^9 base units (same shielded unit as native ARX). `hide_balance` is
/// recorded with the mask; Circuit 1 does not constrain it yet.
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
}
