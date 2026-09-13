//! Test runtime: pallet-evm with this precompile at 0x800, verifier with a fake backend.

use std::cell::RefCell;

use arxon_zk_primitives::{CircuitId, PublicInputs};
use frame_support::{derive_impl, parameter_types, traits::ConstU32, weights::Weight};
use frame_system::EnsureRoot;
use pallet_evm::{EnsureAddressNever, EnsureAddressRoot};
use pallet_zk_verifier::ProofVerifier;
use precompile_utils::{precompile_set::*, testing::*};
use sp_core::U256;
use sp_runtime::BuildStorage;

use crate::ArxonZkPrecompile;

pub type AccountId = MockAccount;
pub type Balance = u128;

frame_support::construct_runtime!(
	pub enum Runtime {
		System: frame_system,
		Balances: pallet_balances,
		Timestamp: pallet_timestamp,
		Evm: pallet_evm,
		ZkVerifier: pallet_zk_verifier,
		NullifierRegistry: pallet_nullifier_registry,
		NoteTree: pallet_note_tree,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
	type Block = frame_system::mocking::MockBlock<Self>;
	type AccountId = AccountId;
	type Lookup = sp_runtime::traits::IdentityLookup<AccountId>;
	type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Runtime {
	type Balance = Balance;
	type AccountStore = System;
	type ExistentialDeposit = frame_support::traits::ConstU128<0>;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Runtime {}

pub type Precompiles<R> =
	PrecompileSetBuilder<R, (PrecompileAt<AddressU64<{ crate::ADDRESS }>, ArxonZkPrecompile<R>>,)>;
pub type PCall = crate::ArxonZkPrecompileCall<Runtime>;

const MAX_POV_SIZE: u64 = 5 * 1024 * 1024;

parameter_types! {
	pub BlockGasLimit: U256 = U256::from(u64::MAX);
	pub PrecompilesValue: Precompiles<Runtime> = Precompiles::new();
	pub const WeightPerGas: Weight = Weight::from_parts(1, 0);
	pub GasLimitPovSizeRatio: u64 = {
		let block_gas_limit = BlockGasLimit::get().min(u64::MAX.into()).low_u64();
		block_gas_limit.saturating_div(MAX_POV_SIZE)
	};
}

impl pallet_evm::Config for Runtime {
	type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
	type FeeCalculator = ();
	type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
	type WeightPerGas = WeightPerGas;
	type BlockHashMapping = pallet_evm::SubstrateBlockHashMapping<Self>;
	type CallOrigin = EnsureAddressRoot<AccountId>;
	type WithdrawOrigin = EnsureAddressNever<AccountId>;
	type AddressMapping = AccountId;
	type Currency = Balances;
	type PrecompilesType = Precompiles<Runtime>;
	type PrecompilesValue = PrecompilesValue;
	type ChainId = ();
	type BlockGasLimit = BlockGasLimit;
	type Runner = pallet_evm::runner::stack::Runner<Self>;
	type OnChargeTransaction = ();
	type OnCreate = ();
	type FindAuthor = ();
	type GasLimitPovSizeRatio = GasLimitPovSizeRatio;
	type GasLimitStorageGrowthRatio = ();
	type Timestamp = Timestamp;
	type WeightInfo = pallet_evm::weights::SubstrateWeight<Self>;
	type CreateOriginFilter = ();
	type CreateInnerOriginFilter = ();
}

thread_local! {
	static ACCEPT: RefCell<bool> = const { RefCell::new(true) };
	static LAST_INSTANCES: RefCell<Option<PublicInputs>> = const { RefCell::new(None) };
}

/// Fake backend: accepts or rejects everything, remembers the last public inputs.
pub struct FakeVerifier;

impl FakeVerifier {
	pub fn set_accept(accept: bool) {
		ACCEPT.with(|a| *a.borrow_mut() = accept);
	}

	pub fn last_instances() -> Option<PublicInputs> {
		LAST_INSTANCES.with(|c| c.borrow().clone())
	}

	pub fn reset() {
		Self::set_accept(true);
		LAST_INSTANCES.with(|c| *c.borrow_mut() = None);
	}
}

impl ProofVerifier for FakeVerifier {
	fn verify(_: CircuitId, _: &[u8; 32], _: &[u8], public_inputs: &PublicInputs) -> bool {
		LAST_INSTANCES.with(|c| *c.borrow_mut() = Some(public_inputs.clone()));
		ACCEPT.with(|a| *a.borrow())
	}
}

impl pallet_zk_verifier::Config for Runtime {
	type Verifier = FakeVerifier;
	type AdminOrigin = EnsureRoot<AccountId>;
	type WeightInfo = ();
}

impl pallet_nullifier_registry::Config for Runtime {
	type WeightInfo = ();
}

impl pallet_note_tree::Config for Runtime {
	type Hasher = pallet_note_tree::PoseidonHasher;
	type RootHistorySize = ConstU32<4>;
	type WeightInfo = ();
}

pub fn precompiles() -> Precompiles<Runtime> {
	PrecompilesValue::get()
}

/// Externalities at block 1 with every circuit registered and the fake verifier accepting.
pub fn new_test_ext() -> sp_io::TestExternalities {
	FakeVerifier::reset();
	let genesis = RuntimeGenesisConfig {
		system: Default::default(),
		balances: Default::default(),
		evm: Default::default(),
		zk_verifier: Default::default(),
		note_tree: Default::default(),
	};
	let mut ext: sp_io::TestExternalities = genesis.build_storage().unwrap().into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
