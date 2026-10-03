//! # Arxon ARX-20 precompile (`0x802`)
//!
//! Isolated shielded pool for issued ARX-20 tokens. Native ARX stays on
//! `0x801` / `TreeId::Note`. Plain ERC-20 has no methods here.
//!
//! State-changing calls take the token from `msg.sender`: only the ARX-20
//! contract can shield, unshield or privately transfer its own asset. The
//! contract burns public balances before `shield` and mints after `unshield`.
//! This precompile never moves native ARX. `msg.value` is rejected.
//!
//! View methods take the token address so wallets can query without
//! impersonating the contract.
//!
//! Only contracts run a pool: the chain refuses a caller without code (an EOA)
//! or whose code is an EIP-7702 delegation. The one exception is
//! `setShieldedDecimals`, which a token calls from its constructor, before its
//! code is stored; it fixes the shielded unit (`10^(decimals - 9)` base units,
//! 1 for 9 decimals or fewer) once, while the pool is empty.
//!
//! The `WithFee` variants bind a relayer fee `(recipient, amount)` in token
//! base units into the proofs. The pool records it; the token mints it to the
//! fee recipient, like the unshielded amount.

use alloc::vec::Vec;
use core::marker::PhantomData;

use arxon_zk_primitives::FieldBytes;
use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
use frame_system::RawOrigin;
use pallet_evm::AddressMapping;
use pallet_note_tree::{MerkleTree, TreeId, MAX_LEAF_PAGE};
use pallet_privacy::Call as PrivacyCall;
use precompile_utils::prelude::*;
use sp_core::{H160, H256, U256};
use sp_runtime::{traits::Dispatchable, SaturatedConversion};

use crate::submit::{
	ensure_direct_call, ensure_no_value, signed_origin, to_balance, to_block_number, to_compliance,
	to_inputs, to_outputs, to_proofs, to_ptr, to_relay_fee, AbiInputs, AbiOptionalAttachment,
	AbiOutputs, AbiProofs, AbiRelayFee,
};
use crate::LEAF_READ_BYTES;

/// Address of this precompile (reserved as `ARXON_ARX20_PRECOMPILE`).
pub const ARX20_ADDRESS: u64 = 0x802;

/// ARX-20 pool door, generic over the runtime.
pub struct ArxonArx20Precompile<R>(PhantomData<R>);

// The Solidity ABI fixes each method's arguments, mirroring the pallet calls.
#[allow(clippy::too_many_arguments)]
#[precompile_utils::precompile]
impl<R> ArxonArx20Precompile<R>
where
	R: pallet_evm::Config
		+ pallet_privacy::Config
		+ pallet_note_tree::Config
		+ pallet_nullifier_registry::Config
		+ frame_system::Config<AccountId = pallet_evm::AccountIdOf<R>>,
	R::RuntimeCall:
		Dispatchable<PostInfo = PostDispatchInfo> + GetDispatchInfo + From<PrivacyCall<R>>,
	<R::RuntimeCall as Dispatchable>::RuntimeOrigin: From<RawOrigin<pallet_evm::AccountIdOf<R>>>,
	pallet_privacy::BalanceOf<R>: TryFrom<u128>,
	frame_system::pallet_prelude::BlockNumberFor<R>: TryFrom<u128>,
{
	/// Burns are the token's job. This inserts notes into the caller's tree.
	#[precompile::public(
		"shield(uint256,(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bytes,bytes,bytes,bytes,bytes))"
	)]
	fn shield(
		handle: &mut impl PrecompileHandle,
		amount: U256,
		outputs: AbiOutputs,
		mask_bits: u8,
		expiry_block: U256,
		proofs: AbiProofs,
	) -> EvmResult {
		ensure_direct_call(handle)?;
		ensure_no_value(handle)?;
		let token = caller_token(handle)?;
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			PrivacyCall::<R>::shield_arx20 {
				token,
				amount: to_balance::<R>(amount)?,
				outputs: to_outputs(outputs)?,
				mask_bits,
				expiry_block: to_block_number::<R>(expiry_block)?,
				proofs: to_proofs(proofs)?,
			},
			0,
		)?;
		Ok(())
	}

	/// Spends notes of the caller token. The token mints after this returns.
	#[precompile::public(
		"unshield(address,uint256,bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bytes,bytes,bytes,bytes,bytes))"
	)]
	fn unshield(
		handle: &mut impl PrecompileHandle,
		recipient: Address,
		amount: U256,
		anchor: H256,
		inputs: AbiInputs,
		outputs: AbiOutputs,
		mask_bits: u8,
		expiry_block: U256,
		proofs: AbiProofs,
	) -> EvmResult {
		ensure_direct_call(handle)?;
		ensure_no_value(handle)?;
		let token = caller_token(handle)?;
		let recipient = R::AddressMapping::into_account_id(recipient.into());
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			PrivacyCall::<R>::unshield_arx20 {
				token,
				recipient,
				amount: to_balance::<R>(amount)?,
				anchor: FieldBytes(anchor.0),
				inputs: to_inputs(inputs)?,
				outputs: to_outputs(outputs)?,
				mask_bits,
				expiry_block: to_block_number::<R>(expiry_block)?,
				proofs: to_proofs(proofs)?,
			},
			0,
		)?;
		Ok(())
	}

	/// Spends and creates notes inside the caller token's pool.
	#[precompile::public(
		"submitPrivateTransfer(bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bool,uint8,bytes32),(bool,uint8,bytes32),(bytes,bytes,bytes,bytes,bytes))"
	)]
	fn submit_private_transfer(
		handle: &mut impl PrecompileHandle,
		anchor: H256,
		inputs: AbiInputs,
		outputs: AbiOutputs,
		mask_bits: u8,
		expiry_block: U256,
		ptr: AbiOptionalAttachment,
		compliance: AbiOptionalAttachment,
		proofs: AbiProofs,
	) -> EvmResult {
		ensure_direct_call(handle)?;
		ensure_no_value(handle)?;
		let token = caller_token(handle)?;
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			PrivacyCall::<R>::submit_private_transfer_arx20 {
				token,
				anchor: FieldBytes(anchor.0),
				inputs: to_inputs(inputs)?,
				outputs: to_outputs(outputs)?,
				mask_bits,
				expiry_block: to_block_number::<R>(expiry_block)?,
				ptr: to_ptr(ptr)?,
				compliance: to_compliance(compliance)?,
				proofs: to_proofs(proofs)?,
			},
			0,
		)?;
		Ok(())
	}

	/// [`Self::unshield`] with a relayer fee the token mints to `fee.recipient`.
	#[precompile::public(
		"unshieldWithFee(address,uint256,bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(address,uint256),(bytes,bytes,bytes,bytes,bytes))"
	)]
	fn unshield_with_fee(
		handle: &mut impl PrecompileHandle,
		recipient: Address,
		amount: U256,
		anchor: H256,
		inputs: AbiInputs,
		outputs: AbiOutputs,
		mask_bits: u8,
		expiry_block: U256,
		fee: AbiRelayFee,
		proofs: AbiProofs,
	) -> EvmResult {
		ensure_direct_call(handle)?;
		ensure_no_value(handle)?;
		let token = caller_token(handle)?;
		let recipient = R::AddressMapping::into_account_id(recipient.into());
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			PrivacyCall::<R>::unshield_arx20_with_fee {
				token,
				recipient,
				amount: to_balance::<R>(amount)?,
				anchor: FieldBytes(anchor.0),
				inputs: to_inputs(inputs)?,
				outputs: to_outputs(outputs)?,
				mask_bits,
				expiry_block: to_block_number::<R>(expiry_block)?,
				fee: to_relay_fee::<R>(fee)?,
				proofs: to_proofs(proofs)?,
			},
			0,
		)?;
		Ok(())
	}

	/// [`Self::submit_private_transfer`] with a relayer fee the token mints to `fee.recipient`.
	#[precompile::public(
		"submitPrivateTransferWithFee(bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bool,uint8,bytes32),(bool,uint8,bytes32),(address,uint256),(bytes,bytes,bytes,bytes,bytes))"
	)]
	fn submit_private_transfer_with_fee(
		handle: &mut impl PrecompileHandle,
		anchor: H256,
		inputs: AbiInputs,
		outputs: AbiOutputs,
		mask_bits: u8,
		expiry_block: U256,
		ptr: AbiOptionalAttachment,
		compliance: AbiOptionalAttachment,
		fee: AbiRelayFee,
		proofs: AbiProofs,
	) -> EvmResult {
		ensure_direct_call(handle)?;
		ensure_no_value(handle)?;
		let token = caller_token(handle)?;
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			PrivacyCall::<R>::submit_private_transfer_arx20_with_fee {
				token,
				anchor: FieldBytes(anchor.0),
				inputs: to_inputs(inputs)?,
				outputs: to_outputs(outputs)?,
				mask_bits,
				expiry_block: to_block_number::<R>(expiry_block)?,
				ptr: to_ptr(ptr)?,
				compliance: to_compliance(compliance)?,
				fee: to_relay_fee::<R>(fee)?,
				proofs: to_proofs(proofs)?,
			},
			0,
		)?;
		Ok(())
	}

	/// Fixes the caller token's shielded unit from its `decimals`. Once, while
	/// its pool is empty; meant for the token's constructor.
	#[precompile::public("setShieldedDecimals(uint8)")]
	fn set_shielded_decimals(handle: &mut impl PrecompileHandle, decimals: u8) -> EvmResult {
		ensure_direct_call(handle)?;
		ensure_no_value(handle)?;
		let token = caller_token(handle)?;
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			PrivacyCall::<R>::set_arx20_unit { token, decimals },
			0,
		)?;
		Ok(())
	}

	/// Base units of `token` per shielded unit (amounts and fees must be multiples).
	#[precompile::public("shieldedUnit(address)")]
	#[precompile::view]
	fn shielded_unit(handle: &mut impl PrecompileHandle, token: Address) -> EvmResult<U256> {
		handle.record_db_read::<R>(36)?;
		let unit =
			pallet_privacy::Pallet::<R>::unit_of(pallet_privacy::PrivacyAsset::Arx20(token.into()));
		Ok(U256::from(unit.saturated_into::<u128>()))
	}

	/// Current root of `token`'s ARX-20 note tree.
	#[precompile::public("getNoteTreeRoot(address)")]
	#[precompile::view]
	fn get_note_tree_root(handle: &mut impl PrecompileHandle, token: Address) -> EvmResult<H256> {
		handle.record_db_read::<R>(32)?;
		handle.record_db_read::<R>(32)?;
		let tree = TreeId::Arx20(token.into());
		Ok(H256(pallet_note_tree::Pallet::<R>::current_root(tree).0))
	}

	/// `true` iff `root` is a live anchor for `token`.
	#[precompile::public("isKnownNoteRoot(address,bytes32)")]
	#[precompile::view]
	fn is_known_note_root(
		handle: &mut impl PrecompileHandle,
		token: Address,
		root: H256,
	) -> EvmResult<bool> {
		handle.record_db_read::<R>(52)?;
		Ok(pallet_note_tree::Pallet::<R>::is_known_root(
			TreeId::Arx20(token.into()),
			&FieldBytes(root.0),
		))
	}

	/// `true` iff `nullifier` was spent for `token` (not the native ARX set).
	#[precompile::public("isNullifierSpent(address,bytes32)")]
	#[precompile::view]
	fn is_nullifier_spent(
		handle: &mut impl PrecompileHandle,
		token: Address,
		nullifier: H256,
	) -> EvmResult<bool> {
		handle.record_db_read::<R>(32)?;
		Ok(pallet_nullifier_registry::Pallet::<R>::is_spent_asset(
			token.into(),
			&FieldBytes(nullifier.0),
		))
	}

	/// Number of commitments in `token`'s tree.
	#[precompile::public("getNoteLeafCount(address)")]
	#[precompile::view]
	fn get_note_leaf_count(handle: &mut impl PrecompileHandle, token: Address) -> EvmResult<U256> {
		handle.record_db_read::<R>(8)?;
		Ok(U256::from(pallet_note_tree::Pallet::<R>::leaf_count(
			TreeId::Arx20(token.into()),
		)))
	}

	/// Note commitment at `index` in `token`'s tree.
	#[precompile::public("getNoteLeaf(address,uint256)")]
	#[precompile::view]
	fn get_note_leaf(
		handle: &mut impl PrecompileHandle,
		token: Address,
		index: U256,
	) -> EvmResult<H256> {
		let index = u64::try_from(index).map_err(|_| revert("unknown leaf"))?;
		// TreeId::Arx20 keys carry the 20-byte token address.
		handle.record_db_read::<R>(LEAF_READ_BYTES + 20)?;
		pallet_note_tree::Pallet::<R>::leaf_at(TreeId::Arx20(token.into()), index)
			.map(|leaf| H256(leaf.0))
			.ok_or_else(|| revert("unknown leaf"))
	}

	/// Up to `count` commitments of `token`'s tree from `start`, capped at
	/// `MAX_LEAF_PAGE` and at the last leaf; one read charged per leaf returned.
	#[precompile::public("getNoteLeaves(address,uint256,uint256)")]
	#[precompile::view]
	fn get_note_leaves(
		handle: &mut impl PrecompileHandle,
		token: Address,
		start: U256,
		count: U256,
	) -> EvmResult<Vec<H256>> {
		let tree = TreeId::Arx20(token.into());
		let Ok(start) = u64::try_from(start) else {
			return Ok(Vec::new());
		};
		let count = u32::try_from(count).unwrap_or(u32::MAX).min(MAX_LEAF_PAGE);
		handle.record_db_read::<R>(8)?;
		let available = pallet_note_tree::Pallet::<R>::leaf_count(tree).saturating_sub(start);
		for _ in 0..available.min(u64::from(count)) {
			handle.record_db_read::<R>(LEAF_READ_BYTES + 20)?;
		}
		Ok(pallet_note_tree::Pallet::<R>::leaves(tree, start, count)
			.into_iter()
			.map(|leaf| H256(leaf.0))
			.collect())
	}
}

fn caller_token(handle: &impl PrecompileHandle) -> EvmResult<H160> {
	let token = handle.context().caller;
	if token.is_zero() {
		return Err(revert("token required"));
	}
	Ok(token)
}
