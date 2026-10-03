// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IARX20} from "./IARX20.sol";

/// @dev Isolated ARX-20 pool. Never call `0x801` (that door is native ARX only).
interface IARX20Pool {
    function shield(
        uint256 amount,
        IARX20.Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        IARX20.Proofs calldata proofs
    ) external;

    function unshield(
        address recipient,
        uint256 amount,
        bytes32 anchor,
        IARX20.Input[] calldata inputs,
        IARX20.Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        IARX20.Proofs calldata proofs
    ) external;

    function submitPrivateTransfer(
        bytes32 anchor,
        IARX20.Input[] calldata inputs,
        IARX20.Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        IARX20.OptionalAttachment calldata ptr,
        IARX20.OptionalAttachment calldata compliance,
        IARX20.Proofs calldata proofs
    ) external;

    function unshieldWithFee(
        address recipient,
        uint256 amount,
        bytes32 anchor,
        IARX20.Input[] calldata inputs,
        IARX20.Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        IARX20.RelayFee calldata fee,
        IARX20.Proofs calldata proofs
    ) external;

    function submitPrivateTransferWithFee(
        bytes32 anchor,
        IARX20.Input[] calldata inputs,
        IARX20.Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        IARX20.OptionalAttachment calldata ptr,
        IARX20.OptionalAttachment calldata compliance,
        IARX20.RelayFee calldata fee,
        IARX20.Proofs calldata proofs
    ) external;

    /// Fixes the caller's shielded unit from its decimals; once, while its pool is empty.
    function setShieldedDecimals(uint8 decimals) external;

    function shieldedUnit(address token) external view returns (uint256);
}

/// @title Reference ARX-20
/// @notice Minimal ERC-20 + selective privacy via precompile `0x802`.
///         Issuers copy this; do not add these methods to a plain ERC-20.
contract ARX20 is IARX20 {
    IARX20Pool internal constant POOL = IARX20Pool(address(0x802));

    string public name;
    string public symbol;
    uint8 public immutable decimals;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// Fixes the pool's shielded unit from `decimals_` (`10^(decimals - 9)`
    /// base units, 1 at 9 or fewer), so a 6-decimal token can shield cents.
    /// It must happen here: the unit can only be set while the pool is empty.
    constructor(string memory name_, string memory symbol_, uint8 decimals_, uint256 initialSupply) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        POOL.setShieldedDecimals(decimals_);
        _mint(msg.sender, initialSupply);
    }

    /// Base units per shielded unit: amounts and fees must be multiples of it.
    function shieldedUnit() external view returns (uint256) {
        return POOL.shieldedUnit(address(this));
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= value, "allowance");
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    function shield(
        uint256 amount,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        Proofs calldata proofs
    ) external {
        _burn(msg.sender, amount);
        POOL.shield(amount, outputs, maskBits, expiryBlock, proofs);
    }

    function unshield(
        address recipient,
        uint256 amount,
        bytes32 anchor,
        Input[] calldata inputs,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        Proofs calldata proofs
    ) external {
        POOL.unshield(recipient, amount, anchor, inputs, outputs, maskBits, expiryBlock, proofs);
        _mint(recipient, amount);
    }

    function transferPrivate(
        bytes32 anchor,
        Input[] calldata inputs,
        Output[] calldata outputs,
        uint8 maskBits,
        uint256 expiryBlock,
        OptionalAttachment calldata ptr,
        OptionalAttachment calldata compliance,
        Proofs calldata proofs
    ) external {
        POOL.submitPrivateTransfer(
            anchor, inputs, outputs, maskBits, expiryBlock, ptr, compliance, proofs
        );
    }

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
    ) external {
        POOL.unshieldWithFee(
            recipient, amount, anchor, inputs, outputs, maskBits, expiryBlock, fee, proofs
        );
        _mint(recipient, amount);
        _mint(fee.recipient, fee.amount);
    }

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
    ) external {
        POOL.submitPrivateTransferWithFee(
            anchor, inputs, outputs, maskBits, expiryBlock, ptr, compliance, fee, proofs
        );
        _mint(fee.recipient, fee.amount);
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "zero");
        uint256 bal = balanceOf[from];
        require(bal >= value, "balance");
        balanceOf[from] = bal - value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 value) internal {
        require(to != address(0), "zero");
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function _burn(address from, uint256 value) internal {
        uint256 bal = balanceOf[from];
        require(bal >= value, "balance");
        balanceOf[from] = bal - value;
        totalSupply -= value;
        emit Transfer(from, address(0), value);
    }
}
