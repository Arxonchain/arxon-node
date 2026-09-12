//! The host function must never panic and must fail closed.

use arxon_zk_primitives::{vk_hash, CircuitId, FieldBytes, MAX_PROOF_BYTES};
use scale_codec::Encode;

use crate::native::{guarded, verify, verify_guarded, Rejection};

fn c1() -> CircuitId {
	CircuitId::PrivacyFlagEnforcement
}

fn one_instance() -> Vec<u8> {
	vec![vec![FieldBytes::ZERO; c1().public_input_len()]].encode()
}

#[test]
fn verify_rejects_unknown_circuit_id() {
	assert_eq!(
		verify(0, &[0; 32], &[], &one_instance()),
		Err(Rejection::UnknownCircuit(0))
	);
	assert_eq!(
		verify(7, &[0; 32], &[], &one_instance()),
		Err(Rejection::UnknownCircuit(7))
	);
}

#[test]
fn verify_rejects_vk_hash_mismatch_before_anything_else() {
	let mut wrong = vk_hash(c1());
	wrong[0] ^= 1;

	assert_eq!(
		verify(c1().as_u8(), &wrong, &[], &one_instance()),
		Err(Rejection::VkHashMismatch)
	);
}

#[test]
fn verify_rejects_oversized_proof_without_calling_backend() {
	let oversized = vec![0u8; MAX_PROOF_BYTES as usize + 1];

	let result = verify(c1().as_u8(), &vk_hash(c1()), &oversized, &one_instance());

	assert_eq!(
		result,
		Err(Rejection::ProofTooLarge(MAX_PROOF_BYTES as usize + 1))
	);
}

#[test]
fn verify_rejects_undecodable_public_inputs() {
	let result = verify(c1().as_u8(), &vk_hash(c1()), &[], &[0xff, 0xff, 0xff]);

	assert_eq!(result, Err(Rejection::MalformedPublicInputs));
}

#[test]
fn verify_rejects_public_inputs_with_trailing_bytes() {
	let mut encoded = one_instance();
	encoded.push(0);

	let result = verify(c1().as_u8(), &vk_hash(c1()), &[], &encoded);

	assert_eq!(result, Err(Rejection::MalformedPublicInputs));
}

#[test]
fn verify_rejects_more_instances_than_the_circuit_allows() {
	let rows = vec![FieldBytes::ZERO; CircuitId::BalanceIntegrity.public_input_len()];
	let two = vec![rows.clone(), rows].encode();

	let result = verify(
		CircuitId::BalanceIntegrity.as_u8(),
		&vk_hash(CircuitId::BalanceIntegrity),
		&[],
		&two,
	);

	assert_eq!(result, Err(Rejection::MalformedPublicInputs));
}

#[test]
fn verify_hands_well_formed_input_to_the_backend() {
	// No chain circuit is wired yet, so the backend answers UnknownCircuit; what matters
	// here is that every cheap check passed and the backend was reached.
	let result = verify(c1().as_u8(), &vk_hash(c1()), &[], &one_instance());

	assert!(matches!(result, Err(Rejection::Invalid(_))));
}

#[test]
fn verify_guarded_returns_false_for_any_rejection() {
	assert!(!verify_guarded(0, &[0; 32], &[], &one_instance()));
	assert!(!verify_guarded(
		c1().as_u8(),
		&vk_hash(c1()),
		&[1, 2, 3],
		&one_instance()
	));
}

#[test]
fn guarded_turns_a_panic_into_false() {
	assert!(!guarded(|| panic!("verifier exploded")));
}

#[test]
fn guarded_passes_through_a_normal_result() {
	assert!(guarded(|| true));
	assert!(!guarded(|| false));
}
