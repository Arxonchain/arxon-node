//! One behaviour per test, through the precompile set tester.

use arxon_zk_primitives::{CircuitId, FieldBytes, MAX_INSTANCES, MAX_PROOF_BYTES};
use frame_support::{
	assert_ok,
	traits::{
		fungible::Inspect,
		tokens::{fungible::Mutate, Preservation},
		ConstU32,
	},
};
use pallet_evm::GasWeightMapping;
use pallet_note_tree::{MerkleTree, TreeId};
use precompile_utils::{prelude::*, testing::*};
use sp_core::{H160, H256, U256};

use crate::{
	mock::{
		new_test_ext, precompiles, ACall, FakeVerifier, NoteTree, NullifierRegistry, PCall, Privacy,
		Runtime, RuntimeOrigin, SCall, ZkVerifier, ALICE_BALANCE, UNIT,
	},
	submit::{
		AbiInput, AbiInputs, AbiOptionalAttachment, AbiOutput, AbiOutputs, AbiProofs,
		SUBMIT_ADDRESS,
	},
	AbiInstance, AbiProof, AbiPublicInputs, ADDRESS,
};

fn address() -> H160 {
	H160::from_low_u64_be(ADDRESS)
}

fn word(byte: u8) -> H256 {
	H256(FieldBytes::from_u64(0x1000 + byte as u64).0)
}

fn instance(circuit: CircuitId) -> AbiInstance {
	vec![word(1); circuit.public_input_len()].into()
}

fn inputs(circuit: CircuitId, instances: usize) -> AbiPublicInputs {
	vec![instance(circuit); instances].into()
}

fn proof(len: usize) -> AbiProof {
	vec![7u8; len].into()
}

fn verify_call(circuit: CircuitId, instances: usize) -> PCall {
	PCall::verify_privacy_proof {
		circuit_id: circuit.as_u8(),
		proof: proof(100),
		public_inputs: inputs(circuit, instances),
	}
}

// --- verifyPrivacyProof --------------------------------------------------------------------------

#[test]
fn verify_privacy_proof_returns_true_when_verifier_accepts() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::PrivacyFlagEnforcement, 1),
			)
			.execute_returns(true);
	});
}

#[test]
fn verify_privacy_proof_returns_false_when_verifier_rejects() {
	new_test_ext().execute_with(|| {
		FakeVerifier::set_accept(false);

		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::PrivacyFlagEnforcement, 1),
			)
			.execute_returns(false);
	});
}

#[test]
fn verify_privacy_proof_hands_every_instance_row_to_the_verifier() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::NullifierDerivation, 2),
			)
			.execute_returns(true);

		let seen = FakeVerifier::last_instances().expect("verifier called");
		assert_eq!(seen.len(), 2);
		assert_eq!(
			seen[0].len(),
			CircuitId::NullifierDerivation.public_input_len()
		);
		assert_eq!(seen[0][0], FieldBytes(word(1).0));
	});
}

#[test]
fn verify_privacy_proof_works_in_static_call() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::PrivacyFlagEnforcement, 1),
			)
			.with_static_call(true)
			.execute_returns(true);
	});
}

#[test]
fn verify_privacy_proof_does_not_write_state() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::PrivacyFlagEnforcement, 1),
			)
			.execute_returns(true);

		assert_eq!(pallet_zk_verifier::VerificationCount::<Runtime>::get(), 0);
	});
}

#[test]
fn verify_privacy_proof_reverts_for_unknown_circuit_id() {
	new_test_ext().execute_with(|| {
		let call = PCall::verify_privacy_proof {
			circuit_id: 9,
			proof: proof(100),
			public_inputs: inputs(CircuitId::PtrGeneration, 1),
		};

		precompiles()
			.prepare_test(Alice, address(), call)
			.execute_reverts(|out| out == b"unknown circuit id");
	});
}

#[test]
fn verify_privacy_proof_reverts_when_circuit_disabled() {
	new_test_ext().execute_with(|| {
		assert_ok!(ZkVerifier::set_circuit_enabled(
			RuntimeOrigin::root(),
			CircuitId::PrivacyFlagEnforcement,
			false
		));

		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::PrivacyFlagEnforcement, 1),
			)
			.execute_reverts(|out| out == b"circuit disabled");
	});
}

#[test]
fn verify_privacy_proof_reverts_on_wrong_row_count() {
	new_test_ext().execute_with(|| {
		let short: AbiPublicInputs = vec![AbiInstance::from(vec![word(1); 3])].into();
		let call = PCall::verify_privacy_proof {
			circuit_id: 1,
			proof: proof(100),
			public_inputs: short,
		};

		precompiles()
			.prepare_test(Alice, address(), call)
			.execute_reverts(|out| out == b"malformed public inputs");
	});
}

#[test]
fn verify_privacy_proof_reverts_on_too_many_instances_for_the_circuit() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::BalanceIntegrity, 2),
			)
			.execute_reverts(|out| out == b"malformed public inputs");
	});
}

#[test]
fn verify_privacy_proof_rejects_oversized_proof_at_the_abi() {
	new_test_ext().execute_with(|| {
		let call = PCall::verify_privacy_proof {
			circuit_id: 1,
			proof: proof(MAX_PROOF_BYTES as usize + 1),
			public_inputs: inputs(CircuitId::PrivacyFlagEnforcement, 1),
		};

		precompiles()
			.prepare_test(Alice, address(), call)
			.execute_reverts(|out| !out.is_empty());
		assert!(
			FakeVerifier::last_instances().is_none(),
			"verifier never reached"
		);
	});
}

#[test]
fn verify_privacy_proof_rejects_more_instances_than_the_abi_cap() {
	new_test_ext().execute_with(|| {
		let call = PCall::verify_privacy_proof {
			circuit_id: 1,
			proof: proof(100),
			public_inputs: inputs(
				CircuitId::PrivacyFlagEnforcement,
				MAX_INSTANCES as usize + 1,
			),
		};

		precompiles()
			.prepare_test(Alice, address(), call)
			.execute_reverts(|out| !out.is_empty());
	});
}

#[test]
fn verify_privacy_proof_charges_the_verifier_weight_as_gas() {
	new_test_ext().execute_with(|| {
		let weight = ZkVerifier::verify_weight(CircuitId::PrivacyFlagEnforcement, 2);
		let expected = <Runtime as pallet_evm::Config>::GasWeightMapping::weight_to_gas(weight)
			+ RuntimeHelper::<Runtime>::db_read_gas_cost();

		precompiles()
			.prepare_test(
				Alice,
				address(),
				verify_call(CircuitId::PrivacyFlagEnforcement, 2),
			)
			.expect_cost(expected)
			.execute_returns(true);
	});
}

// --- getters --------------------------------------------------------------------------------------

#[test]
fn is_nullifier_spent_false_then_true_after_registry_mark() {
	new_test_ext().execute_with(|| {
		let nullifier = word(5);

		precompiles()
			.prepare_test(Alice, address(), PCall::is_nullifier_spent { nullifier })
			.execute_returns(false);

		assert_ok!(NullifierRegistry::mark_spent(&FieldBytes(nullifier.0)));

		precompiles()
			.prepare_test(Alice, address(), PCall::is_nullifier_spent { nullifier })
			.execute_returns(true);
	});
}

#[test]
fn get_trust_registry_root_returns_the_membership_tree_root() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::add_member(
			RuntimeOrigin::root(),
			FieldBytes::from_u64(77)
		));
		let expected = H256(NoteTree::current_root(TreeId::Membership).0);

		precompiles()
			.prepare_test(Alice, address(), PCall::get_trust_registry_root {})
			.execute_returns(expected);
	});
}

#[test]
fn get_note_tree_root_returns_the_note_tree_root() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &FieldBytes::from_u64(11)));
		let expected = H256(NoteTree::current_root(TreeId::Note).0);

		precompiles()
			.prepare_test(Alice, address(), PCall::get_note_tree_root {})
			.execute_returns(expected);
	});
}

#[test]
fn note_and_registry_roots_differ() {
	new_test_ext().execute_with(|| {
		let note = H256(NoteTree::current_root(TreeId::Note).0);
		let registry = H256(NoteTree::current_root(TreeId::Membership).0);

		assert_ne!(note, registry);
	});
}

#[test]
fn is_known_note_root_tracks_recent_anchors() {
	new_test_ext().execute_with(|| {
		let empty = H256(NoteTree::current_root(TreeId::Note).0);
		assert_ok!(NoteTree::insert(TreeId::Note, &FieldBytes::from_u64(11)));
		let current = H256(NoteTree::current_root(TreeId::Note).0);

		precompiles()
			.prepare_test(
				Alice,
				address(),
				PCall::is_known_note_root { root: current },
			)
			.execute_returns(true);
		precompiles()
			.prepare_test(Alice, address(), PCall::is_known_note_root { root: empty })
			.execute_returns(false);
	});
}

#[test]
fn getters_work_in_static_calls() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				address(),
				PCall::is_nullifier_spent { nullifier: word(1) },
			)
			.with_static_call(true)
			.execute_returns(false);
	});
}

// --- ABI -------------------------------------------------------------------------------------------

#[test]
fn selectors_match_the_documented_signatures() {
	assert_eq!(
		PCall::verify_privacy_proof_selectors(),
		&[compute_selector(
			"verifyPrivacyProof(uint8,bytes,bytes32[][])"
		)]
	);
	assert_eq!(
		PCall::is_nullifier_spent_selectors(),
		&[compute_selector("isNullifierSpent(bytes32)")]
	);
	assert_eq!(
		PCall::get_trust_registry_root_selectors(),
		&[compute_selector("getTrustRegistryRoot()")]
	);
	assert_eq!(
		PCall::get_note_tree_root_selectors(),
		&[compute_selector("getNoteTreeRoot()")]
	);
	assert_eq!(
		PCall::is_known_note_root_selectors(),
		&[compute_selector("isKnownNoteRoot(bytes32)")]
	);
	assert_eq!(
		PCall::get_note_leaf_count_selectors(),
		&[compute_selector("getNoteLeafCount()")]
	);
	assert_eq!(
		PCall::get_note_leaf_selectors(),
		&[compute_selector("getNoteLeaf(uint256)")]
	);
}

#[test]
fn unknown_selector_reverts() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(Alice, address(), vec![0xde, 0xad, 0xbe, 0xef])
			.execute_reverts(|out| out.starts_with(b"Unknown selector") || !out.is_empty());
	});
}

#[test]
fn get_note_leaf_returns_inserted_commitment() {
	new_test_ext().execute_with(|| {
		let leaf = FieldBytes::from_u64(7);
		assert_ok!(<NoteTree as MerkleTree>::insert(TreeId::Note, &leaf));
		precompiles()
			.prepare_test(Alice, address(), PCall::get_note_leaf_count {})
			.execute_returns(U256::from(1u64));
		precompiles()
			.prepare_test(
				Alice,
				address(),
				PCall::get_note_leaf {
					index: U256::zero(),
				},
			)
			.execute_returns(H256(leaf.0));
	});
}

// --- 0x801 submit ---------------------------------------------------------------------------------

fn submit_address() -> H160 {
	H160::from_low_u64_be(SUBMIT_ADDRESS)
}

fn h(byte: u8) -> H256 {
	H256(FieldBytes::from_u64(0x1000 + byte as u64).0)
}

fn abi_output(cm: u8, cv: u8) -> AbiOutput {
	AbiOutput {
		cm: h(cm),
		cv: h(cv),
		revealed_receiver: h(0xb0),
		revealed_amount: H256(FieldBytes::from_u64(42).0),
		encrypted_note: vec![cm; 16].into(),
	}
}

fn abi_input(nullifier: u8, cv: u8) -> AbiInput {
	AbiInput {
		nullifier: h(nullifier),
		cv: h(cv),
		revealed_sender: h(0xa0),
	}
}

fn abi_outputs(items: Vec<AbiOutput>) -> AbiOutputs {
	items.into()
}

fn abi_inputs(items: Vec<AbiInput>) -> AbiInputs {
	items.into()
}

fn abi_proofs(spend: bool, output: bool) -> AbiProofs {
	fn p(byte: u8) -> BoundedBytes<ConstU32<MAX_PROOF_BYTES>> {
		vec![byte; 64].into()
	}
	fn empty() -> BoundedBytes<ConstU32<MAX_PROOF_BYTES>> {
		Vec::<u8>::new().into()
	}
	AbiProofs {
		spend: if spend { p(3) } else { empty() },
		output: if output { p(1) } else { empty() },
		balance: p(2),
		receipt: empty(),
		compliance: empty(),
	}
}

fn none_attachment() -> AbiOptionalAttachment {
	AbiOptionalAttachment {
		present: false,
		output_index: 0,
		id: H256::zero(),
	}
}

const EXPIRY: u64 = 100;

fn shield_call(outs: AbiOutputs, mask: u8) -> SCall {
	SCall::shield {
		outputs: outs,
		mask_bits: mask,
		expiry_block: U256::from(EXPIRY),
		proofs: abi_proofs(false, true),
	}
}

fn revert_contains(out: &[u8], needle: &str) -> bool {
	core::str::from_utf8(out)
		.map(|s| s.contains(needle))
		.unwrap_or(false)
}

#[test]
fn submit_shield_moves_funds_into_the_pool_and_inserts_the_commitment() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0),
			)
			.with_value(42 * UNIT)
			.execute_returns(());

		let alice: crate::mock::AccountId = Alice.into();
		assert_eq!(
			pallet_balances::Pallet::<Runtime>::balance(&alice),
			ALICE_BALANCE - 42 * UNIT
		);
		assert_eq!(Privacy::pool_balance(), 42 * UNIT);
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 1);
		assert!(NoteTree::contains_leaf(TreeId::Note, &FieldBytes(h(1).0)));
	});
}

#[test]
fn submit_shield_reverts_when_msg_value_is_zero() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0),
			)
			.execute_reverts(|out| revert_contains(out, "amount required"));
	});
}

#[test]
fn submit_shield_refunds_msg_value_so_the_depositor_is_not_charged_twice() {
	new_test_ext().execute_with(|| {
		let alice: crate::mock::AccountId = Alice.into();
		let submit: crate::mock::AccountId = submit_address().into();
		assert_ok!(<pallet_balances::Pallet<Runtime> as Mutate<_>>::transfer(
			&alice,
			&submit,
			42 * UNIT,
			Preservation::Expendable,
		));

		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0),
			)
			.with_value(42 * UNIT)
			.execute_returns(());

		assert_eq!(
			pallet_balances::Pallet::<Runtime>::balance(&alice),
			ALICE_BALANCE - 42 * UNIT
		);
		assert_eq!(pallet_balances::Pallet::<Runtime>::balance(&submit), 0);
		assert_eq!(Privacy::pool_balance(), 42 * UNIT);
	});
}

#[test]
fn submit_shield_reverts_on_an_invalid_mask_and_does_not_write() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0x10),
			)
			.with_value(42 * UNIT)
			.execute_reverts(|out| revert_contains(out, "InvalidMask"));

		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
		assert_eq!(Privacy::pool_balance(), 0);
	});
}

#[test]
fn submit_shield_reverts_when_the_verifier_rejects() {
	new_test_ext().execute_with(|| {
		FakeVerifier::set_accept(false);

		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0),
			)
			.with_value(42 * UNIT)
			.execute_reverts(|out| revert_contains(out, "InvalidProof"));

		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
	});
}

#[test]
fn submit_shield_reverts_in_a_static_call() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0),
			)
			.with_static_call(true)
			.execute_reverts(|out| !out.is_empty());
	});
}

#[test]
fn submit_unshield_pays_the_recipient_from_the_pool() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0),
			)
			.with_value(42 * UNIT)
			.execute_returns(());
		let anchor = H256(NoteTree::current_root(TreeId::Note).0);
		let bob: crate::mock::AccountId = Bob.into();

		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				SCall::unshield {
					recipient: Address(Bob.into()),
					amount: U256::from(42 * UNIT),
					anchor,
					inputs: abi_inputs(vec![abi_input(10, 11)]),
					outputs: abi_outputs(vec![]),
					mask_bits: 0,
					expiry_block: U256::from(EXPIRY),
					proofs: abi_proofs(true, false),
				},
			)
			.execute_returns(());

		assert_eq!(pallet_balances::Pallet::<Runtime>::balance(&bob), 42 * UNIT);
		assert_eq!(Privacy::pool_balance(), 0);
		assert!(NullifierRegistry::is_spent(&FieldBytes(h(10).0)));
	});
}

#[test]
fn submit_private_transfer_spends_and_creates_notes() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				shield_call(abi_outputs(vec![abi_output(1, 2)]), 0),
			)
			.with_value(42 * UNIT)
			.execute_returns(());
		let anchor = H256(NoteTree::current_root(TreeId::Note).0);

		precompiles()
			.prepare_test(
				Alice,
				submit_address(),
				SCall::submit_private_transfer {
					anchor,
					inputs: abi_inputs(vec![abi_input(10, 11)]),
					outputs: abi_outputs(vec![abi_output(3, 4)]),
					mask_bits: 0b0111,
					expiry_block: U256::from(EXPIRY),
					ptr: none_attachment(),
					compliance: none_attachment(),
					proofs: abi_proofs(true, true),
				},
			)
			.execute_returns(());

		assert!(NullifierRegistry::is_spent(&FieldBytes(h(10).0)));
		assert!(NoteTree::contains_leaf(TreeId::Note, &FieldBytes(h(3).0)));
		assert_eq!(Privacy::pool_balance(), 42 * UNIT);
	});
}

#[test]
fn submit_selectors_match_the_documented_signatures() {
	assert_eq!(
		SCall::shield_selectors(),
		&[compute_selector(
			"shield((bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bytes,bytes,bytes,bytes,bytes))"
		)]
	);
	assert_eq!(
		SCall::unshield_selectors(),
		&[compute_selector(
			"unshield(address,uint256,bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bytes,bytes,bytes,bytes,bytes))"
		)]
	);
	assert_eq!(
		SCall::submit_private_transfer_selectors(),
		&[compute_selector(
			"submitPrivateTransfer(bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bool,uint8,bytes32),(bool,uint8,bytes32),(bytes,bytes,bytes,bytes,bytes))"
		)]
	);
}

// --- 0x802 ARX-20 --------------------------------------------------------------------------------

fn arx20_address() -> H160 {
	H160::from_low_u64_be(crate::ARX20_ADDRESS)
}

fn token() -> H160 {
	H160::from_low_u64_be(0xA20)
}

#[test]
fn arx20_shield_writes_the_token_tree_not_native_arx() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				token(),
				arx20_address(),
				ACall::shield {
					amount: U256::from(42 * UNIT),
					outputs: abi_outputs(vec![abi_output(1, 2)]),
					mask_bits: 0,
					expiry_block: U256::from(EXPIRY),
					proofs: abi_proofs(false, true),
				},
			)
			.execute_returns(());

		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
		assert!(NoteTree::contains_leaf(
			TreeId::Arx20(token()),
			&FieldBytes(h(1).0)
		));
		assert_eq!(Privacy::pool_balance(), 0);
	});
}

#[test]
fn arx20_get_note_tree_root_is_empty_until_shield() {
	new_test_ext().execute_with(|| {
		let empty = NoteTree::current_root(TreeId::Arx20(token()));
		precompiles()
			.prepare_test(
				Alice,
				arx20_address(),
				ACall::get_note_tree_root {
					token: Address(token()),
				},
			)
			.execute_returns(H256(empty.0));
	});
}

#[test]
fn arx20_selectors_match_the_documented_signatures() {
	assert_eq!(
		ACall::shield_selectors(),
		&[compute_selector(
			"shield(uint256,(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bytes,bytes,bytes,bytes,bytes))"
		)]
	);
	assert_eq!(
		ACall::unshield_selectors(),
		&[compute_selector(
			"unshield(address,uint256,bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bytes,bytes,bytes,bytes,bytes))"
		)]
	);
	assert_eq!(
		ACall::submit_private_transfer_selectors(),
		&[compute_selector(
			"submitPrivateTransfer(bytes32,(bytes32,bytes32,bytes32)[],(bytes32,bytes32,bytes32,bytes32,bytes)[],uint8,uint256,(bool,uint8,bytes32),(bool,uint8,bytes32),(bytes,bytes,bytes,bytes,bytes))"
		)]
	);
	assert_eq!(
		ACall::get_note_leaf_count_selectors(),
		&[compute_selector("getNoteLeafCount(address)")]
	);
	assert_eq!(
		ACall::get_note_leaf_selectors(),
		&[compute_selector("getNoteLeaf(address,uint256)")]
	);
}

#[test]
fn arx20_get_note_leaf_returns_inserted_commitment() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(
				token(),
				arx20_address(),
				ACall::shield {
					amount: U256::from(42 * UNIT),
					outputs: abi_outputs(vec![abi_output(1, 2)]),
					mask_bits: 0,
					expiry_block: U256::from(EXPIRY),
					proofs: abi_proofs(false, true),
				},
			)
			.execute_returns(());

		precompiles()
			.prepare_test(
				Alice,
				arx20_address(),
				ACall::get_note_leaf_count {
					token: Address(token()),
				},
			)
			.execute_returns(U256::from(1u64));
		precompiles()
			.prepare_test(
				Alice,
				arx20_address(),
				ACall::get_note_leaf {
					token: Address(token()),
					index: U256::zero(),
				},
			)
			.execute_returns(h(1));
	});
}
