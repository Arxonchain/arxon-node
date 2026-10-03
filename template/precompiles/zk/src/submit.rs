//! # Arxon ZK submission precompile (`0x801`)
//!
//! State-changing EVM door into the same shielded pool the native extrinsics
//! write. Solidity and MetaMask callers pick the same four-flag `PrivacyMask`
//! and the same `ProofBundle`; this precompile maps the ABI onto
//! `pallet_privacy::{shield, unshield, submit_private_transfer}` and dispatches
//! as the EVM caller. `0x800` stays view only.
//!
//! Empty `bytes` on an optional proof means `None`. The balance proof is
//! required. Optional PTR / compliance attachments are a `(bool,uint8,bytes32)`
//! tuple; `present = false` skips them. `shield` is payable: the deposit is
//! `msg.value` so Hide amount is not a named ABI `uint256`. Unshield and
//! private transfer still take amounts as ABI `uint256` and reject value.
//!
//! The `WithFee` variants are for relayers: the bundle pays a fee
//! `(address recipient, uint256 amount)` from the pool through the Circuit 2
//! `fee` row, and both fields are bound into the proofs, so the relayer that
//! submits cannot change either.
//!
//! `setBalanceVisibility` is the hide-balance switch of the caller, an account
//! signing its own transaction (`msg.sender == tx.origin`). It takes effect
//! `MaxProofValidity + 1` blocks later; `isBalanceHidden` answers with the
//! value in force now.

use alloc::vec::Vec;
use core::marker::PhantomData;

use arxon_zk_primitives::{FieldBytes, Proof, MAX_PROOF_BYTES};
use frame_support::{
	dispatch::{GetDispatchInfo, PostDispatchInfo},
	traits::ConstU32,
};
use frame_system::RawOrigin;
use pallet_evm::AddressMapping;
use pallet_privacy::{
	ComplianceAttachment, EncryptedNote, Input, Inputs, Output, Outputs, ProofBundle,
	PtrAttachment, RelayFee, RelayFeeOf, MAX_ENCRYPTED_NOTE, MAX_NOTES,
};
use precompile_utils::prelude::*;
use sp_core::{H256, U256};
use sp_runtime::traits::Dispatchable;

/// Address of this precompile (reserved by the runtime as `ARXON_ZK_SUBMIT_PRECOMPILE`).
pub const SUBMIT_ADDRESS: u64 = 0x801;

/// One output note as the ABI carries it.
#[derive(Clone, Debug, Eq, PartialEq, solidity::Codec)]
pub struct AbiOutput {
	/// Note commitment.
	pub cm: H256,
	/// Value commitment.
	pub cv: H256,
	/// Receiver key, zeroed when the mask hides the receiver.
	pub revealed_receiver: H256,
	/// Amount, zeroed when the mask hides the amount.
	pub revealed_amount: H256,
	/// Ciphertext for the receiver.
	pub encrypted_note: BoundedBytes<ConstU32<MAX_ENCRYPTED_NOTE>>,
}

/// One spent note as the ABI carries it.
#[derive(Clone, Debug, Eq, PartialEq, solidity::Codec)]
pub struct AbiInput {
	/// Nullifier of the spent note.
	pub nullifier: H256,
	/// Fresh value commitment of the spent amount.
	pub cv: H256,
	/// Sender key, zeroed when the mask hides the sender.
	pub revealed_sender: H256,
}

/// Proofs of a bundle. Empty `bytes` is `None` for every optional circuit.
#[derive(Clone, Debug, Eq, PartialEq, solidity::Codec)]
pub struct AbiProofs {
	/// Circuit 3, one instance per input.
	pub spend: BoundedBytes<ConstU32<MAX_PROOF_BYTES>>,
	/// Circuit 1, one instance per output.
	pub output: BoundedBytes<ConstU32<MAX_PROOF_BYTES>>,
	/// Circuit 2, always required.
	pub balance: BoundedBytes<ConstU32<MAX_PROOF_BYTES>>,
	/// Circuit 4, iff a receipt is attached.
	pub receipt: BoundedBytes<ConstU32<MAX_PROOF_BYTES>>,
	/// Circuit 6, iff a compliance attestation is attached.
	pub compliance: BoundedBytes<ConstU32<MAX_PROOF_BYTES>>,
}

/// Relayer fee of a `WithFee` call: `amount` base units paid from the pool to `recipient`.
#[derive(Clone, Debug, Eq, PartialEq, solidity::Codec)]
pub struct AbiRelayFee {
	/// Account the fee is paid to.
	pub recipient: Address,
	/// Fee in base units (wei for ARX), a multiple of the pool's shielded unit.
	pub amount: U256,
}

/// Optional PTR or compliance attachment. `present = false` means `None`.
#[derive(Clone, Debug, Eq, PartialEq, solidity::Codec)]
pub struct AbiOptionalAttachment {
	/// Whether the attachment is set.
	pub present: bool,
	/// Output index the attachment names.
	pub output_index: u8,
	/// `ptr_id` (Circuit 4) or membership `registry_root` (Circuit 6).
	pub id: H256,
}

/// Outputs, capped at Circuit 2 arity.
pub type AbiOutputs = BoundedVec<AbiOutput, ConstU32<MAX_NOTES>>;
/// Inputs, capped at Circuit 2 arity.
pub type AbiInputs = BoundedVec<AbiInput, ConstU32<MAX_NOTES>>;

/// The submission precompile, generic over the runtime.
pub struct ArxonZkSubmitPrecompile<R>(PhantomData<R>);

// The Solidity ABI fixes each method's arguments, mirroring the pallet calls.
#[allow(clippy::too_many_arguments)]
#[precompile_utils::precompile]
impl<R> ArxonZkSubmitPrecompile<R>
where
	R: pallet_evm::Config
		+ pallet_privacy::Config
		+ frame_system::Config<AccountId = pallet_evm::AccountIdOf<R>>,
	R::RuntimeCall:
		Dispatchable<PostInfo = PostDispatchInfo> + GetDispatchInfo + From<pallet_privacy::Call<R>>,
	<R::RuntimeCall as Dispatchable>::RuntimeOrigin: From<RawOrigin<pallet_evm::AccountIdOf<R>>>,
	pallet_privacy::BalanceOf<R>: TryFrom<u128>,
	frame_system::pallet_prelude::BlockNumberFor<R>: TryFrom<u128>,
{
	/// Moves `msg.value` ARX from the caller into the pool as the given notes.
	#[precompile::public(
		"shield((bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bytes,bytes,bytes,bytes,bytes))"
	)]
	#[precompile::payable]
	fn shield(
		handle: &mut impl PrecompileHandle,
		outputs: AbiOutputs,
		mask_bits: u8,
		expiry_block: U256,
		proofs: AbiProofs,
	) -> EvmResult {
		ensure_direct_call(handle)?;
		let amount = handle.context().apparent_value;
		if amount.is_zero() {
			return Err(revert("amount required"));
		}
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			pallet_privacy::Call::<R>::shield {
				amount: to_balance::<R>(amount)?,
				outputs: to_outputs(outputs)?,
				mask_bits,
				expiry_block: to_block_number::<R>(expiry_block)?,
				proofs: to_proofs(proofs)?,
			},
			0,
		)?;
		// EVM already credited this precompile with `msg.value`. Pallet shield
		// still debits the depositor, so return that credit or the user pays twice.
		refund_call_value::<R>(handle, amount)?;
		Ok(())
	}

	/// Spends notes and pays `amount` ARX from the pool to `recipient`.
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
		let recipient = R::AddressMapping::into_account_id(recipient.into());
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			pallet_privacy::Call::<R>::unshield {
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

	/// Spends notes and creates notes inside the pool.
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
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			pallet_privacy::Call::<R>::submit_private_transfer {
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

	/// [`Self::unshield`] paying `fee.amount` wei from the pool to `fee.recipient`.
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
		let recipient = R::AddressMapping::into_account_id(recipient.into());
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			pallet_privacy::Call::<R>::unshield_with_fee {
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

	/// [`Self::submit_private_transfer`] paying `fee.amount` wei from the pool to `fee.recipient`.
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
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			pallet_privacy::Call::<R>::submit_private_transfer_with_fee {
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

	/// Turns hide-balance on or off for the caller, an account signing its own
	/// transaction. Takes effect `MaxProofValidity + 1` blocks later.
	#[precompile::public("setBalanceVisibility(bool)")]
	fn set_balance_visibility(handle: &mut impl PrecompileHandle, hidden: bool) -> EvmResult {
		ensure_direct_call(handle)?;
		ensure_no_value(handle)?;
		// A contract cannot flag itself: an exchange or a token flagged by its
		// own code would refuse every payout made to it, a surprise for the
		// people paying it rather than a privacy choice of an owner.
		if handle.context().caller != handle.origin() {
			return Err(revert("only the transaction signer"));
		}
		RuntimeHelper::<R>::try_dispatch(
			handle,
			signed_origin::<R>(handle),
			pallet_privacy::Call::<R>::set_balance_visibility { hidden },
			0,
		)?;
		Ok(())
	}

	/// `true` iff hide-balance is in force for `account` now (a change still
	/// maturing reports the previous value).
	#[precompile::public("isBalanceHidden(address)")]
	#[precompile::view]
	fn is_balance_hidden(handle: &mut impl PrecompileHandle, account: Address) -> EvmResult<bool> {
		// The flag and the block it last changed at.
		handle.record_db_read::<R>(1)?;
		handle.record_db_read::<R>(4)?;
		let who = R::AddressMapping::into_account_id(account.into());
		Ok(pallet_privacy::Pallet::<R>::is_balance_hidden(&who))
	}
}

/// The submission precompiles act for `context.caller`. Under DELEGATECALL
/// that is the delegating contract's caller, so a contract a victim (or a
/// token) calls could spend as them. Only direct calls are accepted.
pub(crate) fn ensure_direct_call(handle: &impl PrecompileHandle) -> EvmResult {
	if handle.code_address() != handle.context().address {
		Err(revert("delegatecall not allowed"))
	} else {
		Ok(())
	}
}

pub(crate) fn ensure_no_value(handle: &impl PrecompileHandle) -> EvmResult {
	if handle.context().apparent_value != U256::zero() {
		Err(revert("precompile does not accept value"))
	} else {
		Ok(())
	}
}

fn refund_call_value<R>(handle: &impl PrecompileHandle, amount: U256) -> EvmResult
where
	R: pallet_evm::Config
		+ pallet_privacy::Config
		+ frame_system::Config<AccountId = pallet_evm::AccountIdOf<R>>,
	pallet_privacy::BalanceOf<R>: TryFrom<u128>,
{
	let value = to_balance::<R>(amount)?;
	let precompile = R::AddressMapping::into_account_id(handle.context().address);
	let caller = R::AddressMapping::into_account_id(handle.context().caller);
	pallet_privacy::Pallet::<R>::return_call_value(precompile, caller, value)
		.map_err(|_| revert("value refund failed"))?;
	Ok(())
}

pub(crate) fn signed_origin<R>(
	handle: &impl PrecompileHandle,
) -> <R::RuntimeCall as Dispatchable>::RuntimeOrigin
where
	R: pallet_evm::Config + frame_system::Config<AccountId = pallet_evm::AccountIdOf<R>>,
	<R::RuntimeCall as Dispatchable>::RuntimeOrigin: From<RawOrigin<pallet_evm::AccountIdOf<R>>>,
{
	let who = R::AddressMapping::into_account_id(handle.context().caller);
	RawOrigin::Signed(who).into()
}

pub(crate) fn to_balance<R>(amount: U256) -> EvmResult<pallet_privacy::BalanceOf<R>>
where
	R: pallet_privacy::Config,
	pallet_privacy::BalanceOf<R>: TryFrom<u128>,
{
	let amount: u128 = amount.try_into().map_err(|_| revert("amount overflow"))?;
	amount.try_into().map_err(|_| revert("amount overflow"))
}

pub(crate) fn to_relay_fee<R>(fee: AbiRelayFee) -> EvmResult<RelayFeeOf<R>>
where
	R: pallet_evm::Config
		+ pallet_privacy::Config
		+ frame_system::Config<AccountId = pallet_evm::AccountIdOf<R>>,
	pallet_privacy::BalanceOf<R>: TryFrom<u128>,
{
	Ok(RelayFee {
		amount: to_balance::<R>(fee.amount)?,
		recipient: R::AddressMapping::into_account_id(fee.recipient.into()),
	})
}

pub(crate) fn to_block_number<R>(
	n: U256,
) -> EvmResult<frame_system::pallet_prelude::BlockNumberFor<R>>
where
	R: frame_system::Config,
	frame_system::pallet_prelude::BlockNumberFor<R>: TryFrom<u128>,
{
	let n: u128 = n.try_into().map_err(|_| revert("expiry overflow"))?;
	n.try_into().map_err(|_| revert("expiry overflow"))
}

pub(crate) fn to_outputs(outputs: AbiOutputs) -> EvmResult<Outputs> {
	let items: Vec<AbiOutput> = outputs.into();
	let mut out = Vec::with_capacity(items.len());
	for o in items {
		out.push(Output {
			cm: FieldBytes(o.cm.0),
			cv: FieldBytes(o.cv.0),
			revealed_receiver: FieldBytes(o.revealed_receiver.0),
			revealed_amount: FieldBytes(o.revealed_amount.0),
			encrypted_note: EncryptedNote::try_from(o.encrypted_note.as_bytes().to_vec())
				.map_err(|_| revert("encrypted note too large"))?,
		});
	}
	Outputs::try_from(out).map_err(|_| revert("too many outputs"))
}

pub(crate) fn to_inputs(inputs: AbiInputs) -> EvmResult<Inputs> {
	let items: Vec<AbiInput> = inputs.into();
	let mut out = Vec::with_capacity(items.len());
	for i in items {
		out.push(Input {
			nullifier: FieldBytes(i.nullifier.0),
			cv: FieldBytes(i.cv.0),
			revealed_sender: FieldBytes(i.revealed_sender.0),
		});
	}
	Inputs::try_from(out).map_err(|_| revert("too many inputs"))
}

pub(crate) fn to_proofs(proofs: AbiProofs) -> EvmResult<ProofBundle> {
	Ok(ProofBundle {
		spend: optional_proof(&proofs.spend, "spend proof")?,
		output: optional_proof(&proofs.output, "output proof")?,
		balance: required_proof(&proofs.balance, "balance proof")?,
		receipt: optional_proof(&proofs.receipt, "receipt proof")?,
		compliance: optional_proof(&proofs.compliance, "compliance proof")?,
	})
}

fn optional_proof(
	bytes: &BoundedBytes<ConstU32<MAX_PROOF_BYTES>>,
	field: &str,
) -> EvmResult<Option<Proof>> {
	if bytes.as_bytes().is_empty() {
		Ok(None)
	} else {
		Ok(Some(required_proof(bytes, field)?))
	}
}

fn required_proof(
	bytes: &BoundedBytes<ConstU32<MAX_PROOF_BYTES>>,
	field: &str,
) -> EvmResult<Proof> {
	if bytes.as_bytes().is_empty() {
		return Err(revert(alloc::format!("{field} required")));
	}
	Proof::try_from(bytes.as_bytes().to_vec())
		.map_err(|_| revert(alloc::format!("{field} too large")))
}

pub(crate) fn to_ptr(att: AbiOptionalAttachment) -> EvmResult<Option<PtrAttachment>> {
	if !att.present {
		return Ok(None);
	}
	Ok(Some(PtrAttachment {
		payment_output_index: att.output_index,
		ptr_id: FieldBytes(att.id.0),
	}))
}

pub(crate) fn to_compliance(att: AbiOptionalAttachment) -> EvmResult<Option<ComplianceAttachment>> {
	if !att.present {
		return Ok(None);
	}
	Ok(Some(ComplianceAttachment {
		output_index: att.output_index,
		registry_root: FieldBytes(att.id.0),
	}))
}
