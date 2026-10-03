//! Test runtime: real verifier pallet with a fake backend, real nullifier set
//! and real Poseidon note tree, pallet-balances with zero existential deposit.

use std::cell::RefCell;

use arxon_zk_primitives::{CircuitId, PublicInputs};
use frame_support::{
	derive_impl, parameter_types,
	traits::{ConstU128, ConstU32, ConstU64},
	PalletId,
};
use frame_system::EnsureRoot;
use pallet_zk_verifier::ProofVerifier;
use sp_runtime::BuildStorage;

use crate::{self as pallet_privacy, ReceiptSink};
use sp_core::H160;
use sp_runtime::traits::Convert;

pub type Balance = u128;
pub type AccountId = u64;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		ZkVerifier: pallet_zk_verifier,
		NullifierRegistry: pallet_nullifier_registry,
		NoteTree: pallet_note_tree,
		Privacy: pallet_privacy,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = frame_system::mocking::MockBlock<Test>;
	type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type Balance = Balance;
	type AccountStore = System;
	type ExistentialDeposit = ConstU128<0>;
}

/// One backend call as the fake saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierCall {
	pub circuit_id: CircuitId,
	pub proof: Vec<u8>,
	pub public_inputs: PublicInputs,
}

thread_local! {
	static ACCEPT: RefCell<bool> = const { RefCell::new(true) };
	static REJECT_CIRCUIT: RefCell<Option<CircuitId>> = const { RefCell::new(None) };
	static CALLS: RefCell<Vec<VerifierCall>> = const { RefCell::new(Vec::new()) };
}

/// Fake backend: accepts everything, or rejects everything, or rejects one circuit; records every call.
pub struct FakeVerifier;

impl FakeVerifier {
	pub fn set_accept(accept: bool) {
		ACCEPT.with(|a| *a.borrow_mut() = accept);
	}

	pub fn reject_only(circuit: CircuitId) {
		REJECT_CIRCUIT.with(|c| *c.borrow_mut() = Some(circuit));
	}

	pub fn calls() -> Vec<VerifierCall> {
		CALLS.with(|c| c.borrow().clone())
	}

	pub fn reset() {
		Self::set_accept(true);
		REJECT_CIRCUIT.with(|c| *c.borrow_mut() = None);
		CALLS.with(|c| c.borrow_mut().clear());
	}
}

impl ProofVerifier for FakeVerifier {
	fn verify(
		circuit_id: CircuitId,
		_vk_hash: &[u8; 32],
		proof: &[u8],
		public_inputs: &PublicInputs,
	) -> bool {
		CALLS.with(|c| {
			c.borrow_mut().push(VerifierCall {
				circuit_id,
				proof: proof.to_vec(),
				public_inputs: public_inputs.clone(),
			})
		});
		let rejected = REJECT_CIRCUIT.with(|c| *c.borrow() == Some(circuit_id));
		ACCEPT.with(|a| *a.borrow()) && !rejected
	}
}

impl pallet_zk_verifier::Config for Test {
	type Verifier = FakeVerifier;
	type AdminOrigin = EnsureRoot<AccountId>;
	type WeightInfo = ();
}

impl pallet_nullifier_registry::Config for Test {
	type WeightInfo = ();
}

impl pallet_note_tree::Config for Test {
	type Hasher = pallet_note_tree::PoseidonHasher;
	type RootHistorySize = ConstU32<8>;
	type WeightInfo = ();
}

parameter_types! {
	pub const PrivacyPalletId: PalletId = PalletId(*b"arx/shld");
}

/// 1 ARX = 10^9 shielded units in these tests (as in the runtime).
pub const UNIT: Balance = 1_000_000_000;
pub const MAX_VALIDITY: u64 = 128;

/// A recorded receipt: `(ptr_id, cv, mask_bits, asset)`.
pub type RecordedReceipt = (
	arxon_zk_primitives::FieldBytes,
	arxon_zk_primitives::FieldBytes,
	u8,
	pallet_privacy::PrivacyAsset,
);

thread_local! {
	static RECEIPTS: RefCell<Vec<RecordedReceipt>> = const { RefCell::new(Vec::new()) };
}

/// Records every receipt handed over by the privacy pallet.
pub struct RecordingSink;

impl RecordingSink {
	pub fn recorded() -> Vec<RecordedReceipt> {
		RECEIPTS.with(|r| r.borrow().clone())
	}

	pub fn reset() {
		RECEIPTS.with(|r| r.borrow_mut().clear());
	}
}

impl ReceiptSink for RecordingSink {
	fn record(
		ptr_id: arxon_zk_primitives::FieldBytes,
		cv: arxon_zk_primitives::FieldBytes,
		mask_bits: u8,
		asset: pallet_privacy::PrivacyAsset,
	) -> frame_support::dispatch::DispatchResult {
		RECEIPTS.with(|r| r.borrow_mut().push((ptr_id, cv, mask_bits, asset)));
		Ok(())
	}

	fn record_weight() -> frame_support::weights::Weight {
		frame_support::weights::Weight::zero()
	}
}

impl pallet_privacy::Config for Test {
	type Currency = Balances;
	type PalletId = PrivacyPalletId;
	type ShieldedUnit = ConstU128<UNIT>;
	type MaxProofValidity = ConstU64<MAX_VALIDITY>;
	type ZkVerifier = ZkVerifier;
	type Nullifiers = NullifierRegistry;
	type Trees = NoteTree;
	type Receipts = RecordingSink;
	type TokenToAccount = TokenToU64;
	type Arx20Tokens = ContractTokens;
	type WeightInfo = ();
}

/// Every address is a token contract except [`EOA_TOKEN`], which stands for an
/// externally owned (or EIP-7702 delegated) account.
pub struct ContractTokens;

impl frame_support::traits::Contains<H160> for ContractTokens {
	fn contains(token: &H160) -> bool {
		*token != H160::from_low_u64_be(EOA_TOKEN)
	}
}

/// Last 8 bytes of the token address (tests use `H160::from_low_u64_be`).
pub struct TokenToU64;

impl Convert<H160, AccountId> for TokenToU64 {
	fn convert(token: H160) -> AccountId {
		let mut b = [0u8; 8];
		b.copy_from_slice(&token.0[12..20]);
		u64::from_be_bytes(b)
	}
}

pub const ALICE: AccountId = 1;
pub const BOB: AccountId = 2;
pub const RELAYER: AccountId = 3;
pub const TOKEN: AccountId = 99;
/// An account that signs as if it were a token but has no contract code.
pub const EOA_TOKEN: AccountId = 98;
pub const ALICE_BALANCE: Balance = 1_000 * UNIT;

pub fn arx20_token() -> H160 {
	H160::from_low_u64_be(TOKEN)
}

/// Externalities at block 1: Alice funded, every circuit enabled, fake verifier accepting.
pub fn new_test_ext() -> sp_io::TestExternalities {
	FakeVerifier::reset();
	RecordingSink::reset();
	let genesis = RuntimeGenesisConfig {
		system: Default::default(),
		balances: pallet_balances::GenesisConfig {
			balances: vec![(ALICE, ALICE_BALANCE), (RELAYER, UNIT)],
			dev_accounts: None,
		},
		zk_verifier: Default::default(),
		note_tree: Default::default(),
	};
	let mut ext: sp_io::TestExternalities = genesis.build_storage().unwrap().into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
