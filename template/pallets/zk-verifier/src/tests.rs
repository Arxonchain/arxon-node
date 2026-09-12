//! One behaviour per test. Arrange / Act / Assert.

use arxon_zk_primitives::{vk_hash, CircuitId, FieldBytes, InstanceRows, Proof, PublicInputs};
use frame_support::{assert_noop, assert_ok, BoundedVec};
use sp_runtime::DispatchError;

use crate::{
	mock::{
		new_test_ext, new_test_ext_without_circuits, FakeVerifier, RuntimeEvent, RuntimeOrigin,
		System, Test, ZkVerifier,
	},
	CircuitConfig, Error, Event, VerificationCount, VerifyProof,
};

fn c1() -> CircuitId {
	CircuitId::PrivacyFlagEnforcement
}

fn proof() -> Proof {
	BoundedVec::truncate_from(vec![7u8; 100])
}

fn rows(n: usize) -> InstanceRows {
	BoundedVec::truncate_from(vec![FieldBytes::ZERO; n])
}

fn inputs(circuit: CircuitId, instances: usize) -> PublicInputs {
	BoundedVec::truncate_from(vec![rows(circuit.public_input_len()); instances])
}

// --- genesis -----------------------------------------------------------------------------------

#[test]
fn default_genesis_registers_every_circuit_enabled_with_its_frozen_vk_hash() {
	new_test_ext().execute_with(|| {
		for id in CircuitId::ALL {
			assert_eq!(
				ZkVerifier::circuit(id),
				Some(CircuitConfig {
					enabled: true,
					vk_hash: vk_hash(id)
				})
			);
		}
	});
}

// --- set_circuit_enabled -----------------------------------------------------------------------

#[test]
fn set_circuit_enabled_requires_admin_origin() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::set_circuit_enabled(RuntimeOrigin::signed(1), c1(), false),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn set_circuit_enabled_disables_and_emits_event() {
	new_test_ext().execute_with(|| {
		assert_ok!(ZkVerifier::set_circuit_enabled(
			RuntimeOrigin::root(),
			c1(),
			false
		));

		assert!(!ZkVerifier::circuit(c1()).unwrap().enabled);
		System::assert_last_event(RuntimeEvent::ZkVerifier(Event::CircuitEnabledSet {
			circuit_id: c1(),
			enabled: false,
		}));
	});
}

#[test]
fn set_circuit_enabled_keeps_the_vk_hash() {
	new_test_ext().execute_with(|| {
		assert_ok!(ZkVerifier::set_circuit_enabled(
			RuntimeOrigin::root(),
			c1(),
			false
		));

		assert_eq!(ZkVerifier::circuit(c1()).unwrap().vk_hash, vk_hash(c1()));
	});
}

#[test]
fn set_circuit_enabled_fails_for_unregistered_circuit() {
	new_test_ext_without_circuits().execute_with(|| {
		assert_noop!(
			ZkVerifier::set_circuit_enabled(RuntimeOrigin::root(), c1(), true),
			Error::<Test>::CircuitNotRegistered
		);
	});
}

// --- verify_proof ------------------------------------------------------------------------------

#[test]
fn verify_proof_fails_when_circuit_not_registered() {
	new_test_ext_without_circuits().execute_with(|| {
		assert_noop!(
			ZkVerifier::verify_proof(c1(), &proof(), &inputs(c1(), 1)),
			Error::<Test>::CircuitNotRegistered
		);
		assert_eq!(
			FakeVerifier::last_call(),
			None,
			"backend must not be called"
		);
	});
}

#[test]
fn verify_proof_fails_when_circuit_disabled() {
	new_test_ext().execute_with(|| {
		assert_ok!(ZkVerifier::set_circuit_enabled(
			RuntimeOrigin::root(),
			c1(),
			false
		));

		assert_noop!(
			ZkVerifier::verify_proof(c1(), &proof(), &inputs(c1(), 1)),
			Error::<Test>::CircuitDisabled
		);
		assert_eq!(
			FakeVerifier::last_call(),
			None,
			"backend must not be called"
		);
	});
}

#[test]
fn verify_proof_fails_with_no_instances() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::verify_proof(c1(), &proof(), &inputs(c1(), 0)),
			Error::<Test>::NoInstances
		);
	});
}

#[test]
fn verify_proof_fails_when_too_many_instances_for_the_circuit() {
	new_test_ext().execute_with(|| {
		let c2 = CircuitId::BalanceIntegrity;

		assert_noop!(
			ZkVerifier::verify_proof(c2, &proof(), &inputs(c2, 2)),
			Error::<Test>::TooManyInstances
		);
	});
}

#[test]
fn verify_proof_accepts_max_instances_for_multi_instance_circuits() {
	new_test_ext().execute_with(|| {
		assert_ok!(ZkVerifier::verify_proof(
			c1(),
			&proof(),
			&inputs(c1(), c1().max_instances() as usize)
		));
	});
}

#[test]
fn verify_proof_fails_when_an_instance_has_wrong_row_count() {
	new_test_ext().execute_with(|| {
		let bad: PublicInputs =
			BoundedVec::truncate_from(vec![rows(c1().public_input_len()), rows(3)]);

		assert_noop!(
			ZkVerifier::verify_proof(c1(), &proof(), &bad),
			Error::<Test>::WrongRowCount
		);
		assert_eq!(
			FakeVerifier::last_call(),
			None,
			"backend must not be called"
		);
	});
}

#[test]
fn verify_proof_returns_invalid_proof_when_backend_rejects() {
	new_test_ext().execute_with(|| {
		FakeVerifier::set_accept(false);

		assert_noop!(
			ZkVerifier::verify_proof(c1(), &proof(), &inputs(c1(), 1)),
			Error::<Test>::InvalidProof
		);
		assert_eq!(VerificationCount::<Test>::get(), 0);
	});
}

#[test]
fn verify_proof_succeeds_and_increments_count_when_backend_accepts() {
	new_test_ext().execute_with(|| {
		assert_ok!(ZkVerifier::verify_proof(c1(), &proof(), &inputs(c1(), 1)));
		assert_ok!(ZkVerifier::verify_proof(c1(), &proof(), &inputs(c1(), 1)));

		assert_eq!(VerificationCount::<Test>::get(), 2);
	});
}

#[test]
fn verify_proof_passes_pinned_vk_hash_proof_and_inputs_to_the_backend() {
	new_test_ext().execute_with(|| {
		let inputs = inputs(c1(), 2);

		assert_ok!(ZkVerifier::verify_proof(c1(), &proof(), &inputs));

		let call = FakeVerifier::last_call().expect("backend called");
		assert_eq!(call.circuit_id, c1());
		assert_eq!(call.vk_hash, vk_hash(c1()));
		assert_eq!(call.proof, proof().into_inner());
		assert_eq!(call.public_inputs, inputs);
	});
}

#[test]
fn verify_proof_fails_with_overflow_when_count_is_saturated() {
	new_test_ext().execute_with(|| {
		VerificationCount::<Test>::put(u64::MAX);

		assert_noop!(
			ZkVerifier::verify_proof(c1(), &proof(), &inputs(c1(), 1)),
			Error::<Test>::Overflow
		);
	});
}

#[test]
fn check_proof_verifies_without_counting() {
	new_test_ext().execute_with(|| {
		assert_ok!(ZkVerifier::check_proof(c1(), &proof(), &inputs(c1(), 1)));

		assert_eq!(VerificationCount::<Test>::get(), 0);
		assert!(FakeVerifier::last_call().is_some(), "backend was consulted");
	});
}

#[test]
fn check_proof_rejects_like_verify_proof() {
	new_test_ext().execute_with(|| {
		FakeVerifier::set_accept(false);

		assert_noop!(
			ZkVerifier::check_proof(c1(), &proof(), &inputs(c1(), 1)),
			Error::<Test>::InvalidProof
		);
	});
}

#[test]
fn verify_weight_grows_with_instances() {
	new_test_ext().execute_with(|| {
		let one = ZkVerifier::verify_weight(c1(), 1);
		let two = ZkVerifier::verify_weight(c1(), 2);

		assert!(two.ref_time() > one.ref_time());
	});
}
