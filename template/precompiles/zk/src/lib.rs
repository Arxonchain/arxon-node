//! # Arxon ZK precompile (`0x800`)
//!
//! The EVM door into the shielded pool's verifier and state, exactly as the
//! engineer briefing lists it: **view only**. Solidity contracts and MetaMask
//! users read the same nullifier set, tree roots and verifier the native path
//! writes to; no method here changes state. Submission is [`submit`] at `0x801`.
//!
//! ABI (`bytes32` values are canonical little-endian Pallas base field
//! elements, the same bytes the native extrinsics use):
//!
//! * `verifyPrivacyProof(uint8 circuitId, bytes proof, bytes32[][] publicInputs) -> bool`
//!   one row vector per instance. `false` for an invalid proof; reverts for an
//!   unknown or disabled circuit or malformed public inputs.
//! * `isNullifierSpent(bytes32) -> bool`
//! * `getTrustRegistryRoot() -> bytes32` (the membership tree, Circuit 6)
//! * `getNoteTreeRoot() -> bytes32`
//! * `isKnownNoteRoot(bytes32) -> bool` (accepted as an anchor right now)
//! * `getNoteLeafCount() -> uint256`
//! * `getNoteLeaf(uint256 index) -> bytes32`
//!
//! Gas: the verification methods charge the verifier weight converted through
//! the runtime's `GasWeightMapping`, plus a storage read; the getters charge a
//! storage read. Proof size and instance count are capped by the ABI types.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use arxon_zk_primitives::{
	CircuitId, FieldBytes, InstanceRows, Proof, PublicInputs, MAX_INSTANCES, MAX_PROOF_BYTES,
	MAX_PUBLIC_INPUTS,
};
use frame_support::traits::ConstU32;
use pallet_evm::GasWeightMapping;
use pallet_note_tree::{MerkleTree, TreeId};
use pallet_zk_verifier::{CircuitConfig, VerifyProof};
use precompile_utils::prelude::*;
use scale_codec::MaxEncodedLen;
use sp_core::{H256, U256};

pub mod submit;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use submit::{ArxonZkSubmitPrecompile, SUBMIT_ADDRESS};

/// Address of this precompile (reserved by the runtime as `ARXON_ZK_PRECOMPILE`).
pub const ADDRESS: u64 = 0x800;

/// One instance's public rows as the ABI carries them.
pub type AbiInstance = BoundedVec<H256, ConstU32<MAX_PUBLIC_INPUTS>>;
/// All instances of one proof.
pub type AbiPublicInputs = BoundedVec<AbiInstance, ConstU32<MAX_INSTANCES>>;
/// A proof, capped at the contract's hard bound.
pub type AbiProof = BoundedBytes<ConstU32<MAX_PROOF_BYTES>>;

/// The precompile, generic over the runtime.
pub struct ArxonZkPrecompile<R>(PhantomData<R>);

#[precompile_utils::precompile]
impl<R> ArxonZkPrecompile<R>
where
	R: pallet_evm::Config
		+ pallet_zk_verifier::Config
		+ pallet_nullifier_registry::Config
		+ pallet_note_tree::Config,
{
	/// `true` iff `proof` verifies for `circuit_id` under `public_inputs`.
	#[precompile::public("verifyPrivacyProof(uint8,bytes,bytes32[][])")]
	#[precompile::view]
	fn verify_privacy_proof(
		handle: &mut impl PrecompileHandle,
		circuit_id: u8,
		proof: AbiProof,
		public_inputs: AbiPublicInputs,
	) -> EvmResult<bool> {
		let id = CircuitId::try_from(circuit_id).map_err(|_| revert("unknown circuit id"))?;
		let instances: Vec<AbiInstance> = public_inputs.into();
		let instance_count = (instances.len() as u32).max(1);
		handle.record_db_read::<R>(CircuitConfig::max_encoded_len())?;
		let weight = pallet_zk_verifier::Pallet::<R>::verify_weight(id, instance_count);
		handle.record_cost(R::GasWeightMapping::weight_to_gas(weight))?;

		let proof =
			Proof::try_from(proof.as_bytes().to_vec()).map_err(|_| revert("proof too large"))?;
		let inputs = Self::to_public_inputs(instances)?;
		match <pallet_zk_verifier::Pallet<R> as VerifyProof>::check_proof(id, &proof, &inputs) {
			Ok(()) => Ok(true),
			Err(e) if e == pallet_zk_verifier::Error::<R>::InvalidProof.into() => Ok(false),
			Err(e) if e == pallet_zk_verifier::Error::<R>::CircuitDisabled.into() => {
				Err(revert("circuit disabled"))
			}
			Err(e) if e == pallet_zk_verifier::Error::<R>::CircuitNotRegistered.into() => {
				Err(revert("circuit not registered"))
			}
			Err(_) => Err(revert("malformed public inputs")),
		}
	}

	/// `true` iff the nullifier was spent.
	#[precompile::public("isNullifierSpent(bytes32)")]
	#[precompile::view]
	fn is_nullifier_spent(handle: &mut impl PrecompileHandle, nullifier: H256) -> EvmResult<bool> {
		handle.record_db_read::<R>(32)?;
		Ok(pallet_nullifier_registry::Pallet::<R>::is_spent(
			&FieldBytes(nullifier.0),
		))
	}

	/// Current root of the trust registry membership tree.
	#[precompile::public("getTrustRegistryRoot()")]
	#[precompile::view]
	fn get_trust_registry_root(handle: &mut impl PrecompileHandle) -> EvmResult<H256> {
		// Current root, or the genesis empty root before the first insert.
		handle.record_db_read::<R>(32)?;
		handle.record_db_read::<R>(32)?;
		Ok(H256(
			pallet_note_tree::Pallet::<R>::current_root(TreeId::Membership).0,
		))
	}

	/// Current root of the note commitment tree.
	#[precompile::public("getNoteTreeRoot()")]
	#[precompile::view]
	fn get_note_tree_root(handle: &mut impl PrecompileHandle) -> EvmResult<H256> {
		// Current root, or the genesis empty root before the first insert.
		handle.record_db_read::<R>(32)?;
		handle.record_db_read::<R>(32)?;
		Ok(H256(
			pallet_note_tree::Pallet::<R>::current_root(TreeId::Note).0,
		))
	}

	/// `true` iff `root` is an anchor the note tree currently accepts.
	#[precompile::public("isKnownNoteRoot(bytes32)")]
	#[precompile::view]
	fn is_known_note_root(handle: &mut impl PrecompileHandle, root: H256) -> EvmResult<bool> {
		// Blake2_128Concat key of the root (16 + 32 bytes) plus the u32 slot.
		handle.record_db_read::<R>(52)?;
		Ok(pallet_note_tree::Pallet::<R>::is_known_root(
			TreeId::Note,
			&FieldBytes(root.0),
		))
	}

	/// Number of commitments in the note tree.
	#[precompile::public("getNoteLeafCount()")]
	#[precompile::view]
	fn get_note_leaf_count(handle: &mut impl PrecompileHandle) -> EvmResult<U256> {
		handle.record_db_read::<R>(8)?;
		Ok(U256::from(pallet_note_tree::Pallet::<R>::leaf_count(
			TreeId::Note,
		)))
	}

	/// Note commitment at `index` (insertion order).
	#[precompile::public("getNoteLeaf(uint256)")]
	#[precompile::view]
	fn get_note_leaf(handle: &mut impl PrecompileHandle, index: U256) -> EvmResult<H256> {
		let want = u64::try_from(index).map_err(|_| revert("leaf index"))?;
		handle.record_db_read::<R>(8)?;
		let count = pallet_note_tree::Pallet::<R>::leaf_count(TreeId::Note);
		if want >= count {
			return Err(revert("unknown leaf"));
		}
		handle.record_db_read::<R>(48usize.saturating_mul(count.max(1) as usize))?;
		match pallet_note_tree::Pallet::<R>::leaf_at(TreeId::Note, want) {
			Some(leaf) => Ok(H256(leaf.0)),
			None => Err(revert("unknown leaf")),
		}
	}
}

impl<R> ArxonZkPrecompile<R> {
	fn to_public_inputs(instances: Vec<AbiInstance>) -> EvmResult<PublicInputs> {
		let mut out = PublicInputs::default();
		for instance in instances {
			let rows: Vec<H256> = instance.into();
			let rows: Vec<FieldBytes> = rows.into_iter().map(|h| FieldBytes(h.0)).collect();
			let rows =
				InstanceRows::try_from(rows).map_err(|_| revert("too many public input rows"))?;
			out.try_push(rows)
				.map_err(|_| revert("too many instances"))?;
		}
		Ok(out)
	}
}
