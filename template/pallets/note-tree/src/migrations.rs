//! Storage migrations.

use frame_support::{
	migrations::VersionedMigration, pallet_prelude::*, traits::UncheckedOnRuntimeUpgrade,
};

use crate::{weights::WeightInfo, Config, KnownLeaves, LeafAt, Pallet, TreeId};

/// Builds the empty subtree chains of both trees on a chain that ran before
/// this pallet existed, as genesis does on a new chain.
pub struct BuildZeros<T>(PhantomData<T>);

impl<T: Config> UncheckedOnRuntimeUpgrade for BuildZeros<T> {
	fn on_runtime_upgrade() -> Weight {
		let mut weight = Weight::zero();
		for tree in [TreeId::Note, TreeId::Membership] {
			let _ = Pallet::<T>::empty_root(tree);
			let levels = u64::from(tree.depth()) + 1;
			weight = weight
				.saturating_add(T::DbWeight::get().reads_writes(levels, levels))
				.saturating_add(T::WeightInfo::insert());
		}
		weight
	}
}

/// Version 0 to 1: see [`BuildZeros`].
pub type V0ToV1<T> =
	VersionedMigration<0, 1, BuildZeros<T>, Pallet<T>, <T as frame_system::Config>::DbWeight>;

/// Indexes every existing leaf by position (`LeafAt`), as inserts do from
/// version 2 on. One pass over `KnownLeaves`: a read and a write per leaf.
///
/// It runs in a single block, which suits the testnet's note count. A chain
/// with millions of leaves would need a multi-block migration instead.
pub struct IndexLeavesByPosition<T>(PhantomData<T>);

impl<T: Config> UncheckedOnRuntimeUpgrade for IndexLeavesByPosition<T> {
	fn on_runtime_upgrade() -> Weight {
		let mut indexed = 0u64;
		for (tree, leaf, index) in KnownLeaves::<T>::iter() {
			LeafAt::<T>::insert(tree, index, leaf);
			indexed = indexed.saturating_add(1);
		}
		T::DbWeight::get().reads_writes(indexed, indexed)
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(
		_: alloc::vec::Vec<u8>,
	) -> Result<(), frame_support::sp_runtime::TryRuntimeError> {
		for tree in [TreeId::Note, TreeId::Membership] {
			for index in 0..Pallet::<T>::leaf_count(tree) {
				frame_support::ensure!(
					LeafAt::<T>::contains_key(tree, index),
					"a leaf index has no LeafAt entry"
				);
			}
		}
		Ok(())
	}
}

/// Version 1 to 2: see [`IndexLeavesByPosition`].
pub type V1ToV2<T> = VersionedMigration<
	1,
	2,
	IndexLeavesByPosition<T>,
	Pallet<T>,
	<T as frame_system::Config>::DbWeight,
>;
