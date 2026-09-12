//! Test runtime with the production Poseidon hasher and a three-root history.

use frame_support::{derive_impl, traits::ConstU32};
use sp_runtime::BuildStorage;

use crate::{self as pallet_note_tree, PoseidonHasher};

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		NoteTree: pallet_note_tree,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = frame_system::mocking::MockBlock<Test>;
}

/// Small on purpose so eviction is testable.
pub const ROOT_HISTORY: u32 = 3;

impl pallet_note_tree::Config for Test {
	type Hasher = PoseidonHasher;
	type RootHistorySize = ConstU32<ROOT_HISTORY>;
	type WeightInfo = ();
}

/// Externalities at block 1 so events are recorded.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap()
		.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
