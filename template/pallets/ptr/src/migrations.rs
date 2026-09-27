//! Storage migrations.

use frame_support::{
	migration::clear_storage_prefix,
	migrations::VersionedMigration,
	pallet_prelude::*,
	traits::{PalletInfoAccess, UncheckedOnRuntimeUpgrade},
};

use crate::{Config, Pallet, TotalReceipts};

/// Removes the plaintext receipts and disclosure codes of the pre-ZK pallet.
///
/// Version 0 stored `Receipts` with parties and amounts in clear, under the
/// same storage name the commitments now use, plus `DisclosureCodes`,
/// `CodeCountPerTx` and `TotalCodesUsed`. The old receipts cannot decode as
/// commitments and must not survive as readable plaintext, so all of it is
/// deleted and the receipt counter restarts.
pub struct RemovePlaintextReceipts<T>(PhantomData<T>);

/// Storage items of version 0 that version 1 no longer has, or reuses with a new type.
pub const REMOVED_ITEMS: [&[u8]; 4] = [
	b"Receipts",
	b"DisclosureCodes",
	b"CodeCountPerTx",
	b"TotalCodesUsed",
];

impl<T: Config> UncheckedOnRuntimeUpgrade for RemovePlaintextReceipts<T> {
	fn on_runtime_upgrade() -> Weight {
		let pallet = <Pallet<T> as PalletInfoAccess>::name().as_bytes();
		let mut removed = 0u64;
		for item in REMOVED_ITEMS {
			let result = clear_storage_prefix(pallet, item, b"", None, None);
			removed = removed.saturating_add(u64::from(result.unique));
		}
		TotalReceipts::<T>::kill();
		T::DbWeight::get().reads_writes(removed, removed.saturating_add(1))
	}
}

/// Version 0 to 1: see [`RemovePlaintextReceipts`].
pub type V0ToV1<T> = VersionedMigration<
	0,
	1,
	RemovePlaintextReceipts<T>,
	Pallet<T>,
	<T as frame_system::Config>::DbWeight,
>;
