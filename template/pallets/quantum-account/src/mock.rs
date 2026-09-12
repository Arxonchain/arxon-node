//! Test runtime: System plus the quantum account pallet. Inner calls are
//! `System::remark` (succeeds for any signed origin) and `System::set_code`
//! (root only, so it fails from a signed origin: a deterministic inner failure).

use frame_support::derive_impl;
use sp_runtime::BuildStorage;

use crate as pallet_quantum_account;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		QuantumAccount: pallet_quantum_account,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = frame_system::mocking::MockBlock<Test>;
}

impl pallet_quantum_account::Config for Test {
	type RuntimeCall = RuntimeCall;
}

pub const QUANTUM: u64 = 1;
pub const RELAYER: u64 = 2;

/// Externalities at block 1 so events are recorded.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap()
		.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
