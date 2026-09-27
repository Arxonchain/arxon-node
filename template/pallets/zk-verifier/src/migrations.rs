//! Storage migrations.

use arxon_zk_primitives::{vk_hash, CircuitId};
use frame_support::{
	migrations::VersionedMigration, pallet_prelude::*, traits::UncheckedOnRuntimeUpgrade,
};

use crate::{CircuitConfig, Circuits, Config, Pallet};

/// Registers every circuit with its frozen verifying key hash, enabled, on a
/// chain that ran before this pallet existed (genesis never ran for it there).
pub struct RegisterCircuits<T>(PhantomData<T>);

impl<T: Config> UncheckedOnRuntimeUpgrade for RegisterCircuits<T> {
	fn on_runtime_upgrade() -> Weight {
		let mut writes = 0u64;
		for id in CircuitId::ALL {
			if !Circuits::<T>::contains_key(id) {
				Circuits::<T>::insert(
					id,
					CircuitConfig {
						enabled: true,
						vk_hash: vk_hash(id),
					},
				);
				writes += 1;
			}
		}
		T::DbWeight::get().reads_writes(CircuitId::ALL.len() as u64, writes)
	}
}

/// Version 0 to 1: see [`RegisterCircuits`].
pub type V0ToV1<T> =
	VersionedMigration<0, 1, RegisterCircuits<T>, Pallet<T>, <T as frame_system::Config>::DbWeight>;
