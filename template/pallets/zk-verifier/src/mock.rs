//! Test runtime with a switchable fake verifier that records its last call.

use std::cell::RefCell;

use arxon_zk_primitives::{CircuitId, PublicInputs};
use frame_support::derive_impl;
use frame_system::EnsureRoot;
use sp_runtime::BuildStorage;

use crate::{self as pallet_zk_verifier, ProofVerifier};

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		ZkVerifier: pallet_zk_verifier,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = frame_system::mocking::MockBlock<Test>;
}

/// What the fake verifier saw last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierCall {
	pub circuit_id: CircuitId,
	pub vk_hash: [u8; 32],
	pub proof: Vec<u8>,
	pub public_inputs: PublicInputs,
}

thread_local! {
	static ACCEPT: RefCell<bool> = const { RefCell::new(true) };
	static LAST_CALL: RefCell<Option<VerifierCall>> = const { RefCell::new(None) };
}

/// Fake backend: accepts or rejects everything, remembers its last call.
pub struct FakeVerifier;

impl FakeVerifier {
	pub fn set_accept(accept: bool) {
		ACCEPT.with(|a| *a.borrow_mut() = accept);
	}

	pub fn last_call() -> Option<VerifierCall> {
		LAST_CALL.with(|c| c.borrow().clone())
	}

	pub fn reset() {
		Self::set_accept(true);
		LAST_CALL.with(|c| *c.borrow_mut() = None);
	}
}

impl ProofVerifier for FakeVerifier {
	fn verify(
		circuit_id: CircuitId,
		vk_hash: &[u8; 32],
		proof: &[u8],
		public_inputs: &PublicInputs,
	) -> bool {
		LAST_CALL.with(|c| {
			*c.borrow_mut() = Some(VerifierCall {
				circuit_id,
				vk_hash: *vk_hash,
				proof: proof.to_vec(),
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

/// Externalities with the default genesis (every circuit enabled) at block 1.
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

/// Externalities with an empty circuit registry.
pub fn new_test_ext_without_circuits() -> sp_io::TestExternalities {
	FakeVerifier::reset();
	let genesis = RuntimeGenesisConfig {
		system: Default::default(),
		zk_verifier: pallet_zk_verifier::GenesisConfig {
			circuits: vec![],
			_phantom: Default::default(),
		},
	};
	let mut ext: sp_io::TestExternalities = genesis.build_storage().unwrap().into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
