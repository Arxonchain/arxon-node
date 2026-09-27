//! Storage migrations.

use arxon_zk_primitives::{vk_hash, CircuitId};
use frame_support::{
	migrations::VersionedMigration, pallet_prelude::*, traits::UncheckedOnRuntimeUpgrade,
};

use crate::{CircuitConfig, Circuits, Config, Pallet};

/// Brings the circuit registry to the verifying keys this runtime was built with.
///
/// On a chain that ran before this pallet existed (genesis never ran for it)
/// every circuit is registered, enabled. On any chain, an entry whose hash
/// differs from the frozen one (a circuit changed in this upgrade) is updated
/// and keeps its enabled flag: the node only verifies against the keys it was
/// built with, so a stale hash would make the circuit unusable.
pub struct RegisterCircuits<T>(PhantomData<T>);

impl<T: Config> UncheckedOnRuntimeUpgrade for RegisterCircuits<T> {
	fn on_runtime_upgrade() -> Weight {
		let mut writes = 0u64;
		for id in CircuitId::ALL {
			let frozen = vk_hash(id);
			let config = match Circuits::<T>::get(id) {
				Some(c) if c.vk_hash == frozen => continue,
				Some(c) => CircuitConfig {
					enabled: c.enabled,
					vk_hash: frozen,
				},
				None => CircuitConfig {
					enabled: true,
					vk_hash: frozen,
				},
			};
			Circuits::<T>::insert(id, config);
			writes += 1;
		}
		T::DbWeight::get().reads_writes(CircuitId::ALL.len() as u64, writes)
	}
}

/// Version 0 to 1: see [`RegisterCircuits`].
pub type V0ToV1<T> =
	VersionedMigration<0, 1, RegisterCircuits<T>, Pallet<T>, <T as frame_system::Config>::DbWeight>;
