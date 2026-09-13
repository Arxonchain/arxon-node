//! Test runtime.

use frame_support::derive_impl;
use sp_runtime::BuildStorage;

use crate as pallet_nullifier_registry;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		NullifierRegistry: pallet_nullifier_registry,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = frame_system::mocking::MockBlock<Test>;
}

impl pallet_nullifier_registry::Config for Test {
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
