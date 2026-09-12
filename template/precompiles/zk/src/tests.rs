//! One behaviour per test, through the precompile set tester.

use arxon_zk_primitives::{CircuitId, FieldBytes, MAX_INSTANCES, MAX_PROOF_BYTES};
use frame_support::assert_ok;
use pallet_evm::GasWeightMapping;
use pallet_note_tree::{MerkleTree, TreeId};
use precompile_utils::{prelude::*, testing::*};
use sp_core::{H160, H256};

use crate::{
	mock::{
		new_test_ext, precompiles, FakeVerifier, NoteTree, NullifierRegistry, PCall, Runtime,
		RuntimeOrigin, ZkVerifier,
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
}

#[test]
fn unknown_selector_reverts() {
	new_test_ext().execute_with(|| {
		precompiles()
			.prepare_test(Alice, address(), vec![0xde, 0xad, 0xbe, 0xef])
			.execute_reverts(|out| out.starts_with(b"Unknown selector") || !out.is_empty());
	});
}
