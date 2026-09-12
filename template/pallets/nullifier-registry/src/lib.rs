//! # Nullifier registry (runtime index 19)
//!
//! The set of spent note nullifiers of the Arxon shielded pool. A nullifier is
//! `H_NF(nk, cm)`, proved well-formed by Circuit 3; this pallet only enforces
//! uniqueness. It exposes no extrinsics: `pallet-privacy` (and later the EVM
//! submission precompile) mark nullifiers through [`NullifierSet`] inside the
//! same transaction that verified the proofs, so the check and the write are
//! atomic.
//!
//! Storage uses `Blake2_128Concat`, not `Identity`: the prover chooses the
//! preimage of a nullifier, so an attacker could otherwise grind key prefixes
//! and unbalance the storage trie.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// The spent set as seen by the pallets that consume it.
pub trait NullifierSet {
	/// `true` iff `nullifier` was already spent.
	fn is_spent(nullifier: &arxon_zk_primitives::FieldBytes) -> bool;

	/// Marks `nullifier` spent. Fails if it already was; the caller's
	/// transaction is expected to roll back.
	fn mark_spent(
		nullifier: &arxon_zk_primitives::FieldBytes,
	) -> frame_support::pallet_prelude::DispatchResult;
}

#[frame_support::pallet]
pub mod pallet {
	use arxon_zk_primitives::FieldBytes;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	use super::NullifierSet;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {}

	/// Spent nullifiers and the block they were spent in.
	#[pallet::storage]
	pub type SpentNullifiers<T: Config> =
		StorageMap<_, Blake2_128Concat, FieldBytes, BlockNumberFor<T>, OptionQuery>;

	/// Number of nullifiers ever spent.
	#[pallet::storage]
	pub type SpentCount<T: Config> = StorageValue<_, u64, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A note was spent.
		NullifierSpent {
			/// The nullifier.
			nullifier: FieldBytes,
			/// Block in which it was spent.
			block_number: BlockNumberFor<T>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The nullifier was already spent: double spend attempt.
		AlreadySpent,
		/// The spent counter overflowed.
		Overflow,
	}

	impl<T: Config> Pallet<T> {
		/// `true` iff `nullifier` was already spent.
		pub fn is_spent(nullifier: &FieldBytes) -> bool {
			SpentNullifiers::<T>::contains_key(nullifier)
		}

		/// Marks `nullifier` spent in the current block.
		pub fn mark_spent(nullifier: &FieldBytes) -> DispatchResult {
			ensure!(!Self::is_spent(nullifier), Error::<T>::AlreadySpent);
			let count = SpentCount::<T>::get()
				.checked_add(1)
				.ok_or(Error::<T>::Overflow)?;
			let block_number = frame_system::Pallet::<T>::block_number();
			SpentNullifiers::<T>::insert(nullifier, block_number);
			SpentCount::<T>::put(count);
			Self::deposit_event(Event::NullifierSpent {
				nullifier: *nullifier,
				block_number,
			});
			Ok(())
		}

		/// Block in which `nullifier` was spent, if any.
		pub fn spent_at(nullifier: &FieldBytes) -> Option<BlockNumberFor<T>> {
			SpentNullifiers::<T>::get(nullifier)
		}
	}

	impl<T: Config> NullifierSet for Pallet<T> {
		fn is_spent(nullifier: &FieldBytes) -> bool {
			Pallet::<T>::is_spent(nullifier)
		}

		fn mark_spent(nullifier: &FieldBytes) -> DispatchResult {
			Pallet::<T>::mark_spent(nullifier)
		}
	}
}
