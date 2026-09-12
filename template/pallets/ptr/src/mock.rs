//! Test runtime: real verifier pallet with a fake backend that records its last call.

use std::cell::RefCell;

use arxon_zk_primitives::{CircuitId, PublicInputs};
use frame_support::{derive_impl, traits::ConstU64};
use frame_system::EnsureRoot;
use pallet_zk_verifier::ProofVerifier;
use sp_runtime::BuildStorage;

use crate as pallet_ptr;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		ZkVerifier: pallet_zk_verifier,
		Ptr: pallet_ptr,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = frame_system::mocking::MockBlock<Test>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierCall {
	pub circuit_id: CircuitId,
	pub public_inputs: PublicInputs,
}

thread_local! {
	static ACCEPT: RefCell<bool> = const { RefCell::new(true) };
	static LAST: RefCell<Option<VerifierCall>> = const { RefCell::new(None) };
}

pub struct FakeVerifier;

impl FakeVerifier {
	pub fn set_accept(accept: bool) {
		ACCEPT.with(|a| *a.borrow_mut() = accept);
	}

	pub fn last_call() -> Option<VerifierCall> {
		LAST.with(|c| c.borrow().clone())
	}

	pub fn reset() {
		Self::set_accept(true);
		LAST.with(|c| *c.borrow_mut() = None);
	}
}

impl ProofVerifier for FakeVerifier {
	fn verify(circuit_id: CircuitId, _: &[u8; 32], _: &[u8], public_inputs: &PublicInputs) -> bool {
		LAST.with(|c| {
			*c.borrow_mut() = Some(VerifierCall {
				circuit_id,
				public_inputs: public_inputs.clone(),
			})
		});
		ACCEPT.with(|a| *a.borrow())
	}
}

impl pallet_zk_verifier::Config for Test {
	type Verifier = FakeVerifier;
	type AdminOrigin = EnsureRoot<u64>;
	type WeightInfo = ();
}

pub const MAX_VALIDITY: u64 = 128;

impl pallet_ptr::Config for Test {
	type ZkVerifier = ZkVerifier;
	type MaxProofValidity = ConstU64<MAX_VALIDITY>;
	type WeightInfo = ();
}

pub const AUDITOR: u64 = 7;

/// Externalities at block 1 with every circuit enabled and the fake verifier accepting.
pub fn new_test_ext() -> sp_io::TestExternalities {
	FakeVerifier::reset();
	let genesis = RuntimeGenesisConfig {
		system: Default::default(),
		zk_verifier: Default::default(),
	};
	let mut ext: sp_io::TestExternalities = genesis.build_storage().unwrap().into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
