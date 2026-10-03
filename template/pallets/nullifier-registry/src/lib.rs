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
//!
//! Native ARX uses [`SpentNullifiers`]. Each ARX-20 token has its own spent set
//! so a spend on one asset cannot nullify a note of another (notes share
//! `H_NOTE(pk, amount, rho)` with no asset id).

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// The spent set as seen by the pallets that consume it.
pub trait NullifierSet {
	/// `true` iff `nullifier` was already spent in the native ARX pool.
	fn is_spent(nullifier: &arxon_zk_primitives::FieldBytes) -> bool;

	/// Marks `nullifier` spent in the native ARX pool. Fails if it already was;
	/// the caller's transaction is expected to roll back.
	fn mark_spent(
		nullifier: &arxon_zk_primitives::FieldBytes,
	) -> frame_support::pallet_prelude::DispatchResult;

	/// Weight of one [`Self::mark_spent`], for consumers' weight functions.
	fn mark_spent_weight() -> frame_support::weights::Weight;

	/// `true` iff `nullifier` was spent for `asset` (`None` = native ARX).
	fn is_spent_for(
		asset: Option<sp_core::H160>,
		nullifier: &arxon_zk_primitives::FieldBytes,
	) -> bool;

	/// Marks `nullifier` spent for `asset` (`None` = native ARX).
	fn mark_spent_for(
		asset: Option<sp_core::H160>,
		nullifier: &arxon_zk_primitives::FieldBytes,
	) -> frame_support::pallet_prelude::DispatchResult;
}

#[frame_support::pallet]
pub mod pallet {
	use arxon_zk_primitives::FieldBytes;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_core::H160;

	use super::{weights::WeightInfo, NullifierSet};

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Weights.
		type WeightInfo: WeightInfo;
	}

	/// Spent nullifiers and the block they were spent in.
	#[pallet::storage]
	pub type SpentNullifiers<T: Config> =
		StorageMap<_, Blake2_128Concat, FieldBytes, BlockNumberFor<T>, OptionQuery>;

	/// Number of nullifiers ever spent.
	#[pallet::storage]
	pub type SpentCount<T: Config> = StorageValue<_, u64, ValueQuery>;

	/// Spent ARX-20 nullifiers: `(token, nullifier) → block`.
	#[pallet::storage]
	pub type SpentAssetNullifiers<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		H160,
		Blake2_128Concat,
		FieldBytes,
		BlockNumberFor<T>,
		OptionQuery,
	>;

	/// Number of nullifiers spent per ARX-20 token.
	#[pallet::storage]
	pub type AssetSpentCount<T: Config> = StorageMap<_, Blake2_128Concat, H160, u64, ValueQuery>;

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
		/// An ARX-20 note was spent.
		AssetNullifierSpent {
			/// ARX-20 contract.
			token: H160,
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

		/// `true` iff `nullifier` was spent for ARX-20 `token`.
		pub fn is_spent_asset(token: H160, nullifier: &FieldBytes) -> bool {
			SpentAssetNullifiers::<T>::contains_key(token, nullifier)
		}

		/// Marks `nullifier` spent for ARX-20 `token` in the current block.
		pub fn mark_spent_asset(token: H160, nullifier: &FieldBytes) -> DispatchResult {
			ensure!(
				!Self::is_spent_asset(token, nullifier),
				Error::<T>::AlreadySpent
			);
			let count = AssetSpentCount::<T>::get(token)
				.checked_add(1)
				.ok_or(Error::<T>::Overflow)?;
			let block_number = frame_system::Pallet::<T>::block_number();
			SpentAssetNullifiers::<T>::insert(token, nullifier, block_number);
			AssetSpentCount::<T>::insert(token, count);
			Self::deposit_event(Event::AssetNullifierSpent {
				token,
				nullifier: *nullifier,
				block_number,
			});
			Ok(())
		}

		/// `true` iff `nullifier` was spent for `asset` (`None` = native ARX).
		pub fn is_spent_for(asset: Option<H160>, nullifier: &FieldBytes) -> bool {
			match asset {
				None => Self::is_spent(nullifier),
				Some(token) => Self::is_spent_asset(token, nullifier),
			}
		}

		/// Marks `nullifier` spent for `asset` (`None` = native ARX).
		pub fn mark_spent_for(asset: Option<H160>, nullifier: &FieldBytes) -> DispatchResult {
			match asset {
				None => Self::mark_spent(nullifier),
				Some(token) => Self::mark_spent_asset(token, nullifier),
			}
		}
	}

	impl<T: Config> NullifierSet for Pallet<T> {
		fn is_spent(nullifier: &FieldBytes) -> bool {
			Pallet::<T>::is_spent(nullifier)
		}

		fn mark_spent(nullifier: &FieldBytes) -> DispatchResult {
			Pallet::<T>::mark_spent(nullifier)
		}

		fn mark_spent_weight() -> Weight {
			T::WeightInfo::mark_spent()
		}

		fn is_spent_for(asset: Option<H160>, nullifier: &FieldBytes) -> bool {
			Pallet::<T>::is_spent_for(asset, nullifier)
		}

		fn mark_spent_for(asset: Option<H160>, nullifier: &FieldBytes) -> DispatchResult {
			Pallet::<T>::mark_spent_for(asset, nullifier)
		}
	}
}
