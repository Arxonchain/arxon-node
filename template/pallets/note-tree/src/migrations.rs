//! Storage migrations.

use frame_support::{
	migrations::VersionedMigration, pallet_prelude::*, traits::UncheckedOnRuntimeUpgrade,
};

use crate::{weights::WeightInfo, Config, Pallet, TreeId};

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
