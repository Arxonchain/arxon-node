use arxon_zk_primitives::{CircuitId, FieldBytes, CHAIN_ID, MAX_PROOF_BYTES};

use super::{DummyCircuit, DummyWitness, ROW_C, ROW_CHAIN_ID};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::VerifyError,
	field::Fp,
	pins::{expected_proof_len, measure},
	prover::prove,
	test_support::*,
	verifier::{verify, verify_by_id, verify_by_wire_id},
};

fn witness() -> DummyWitness {
	DummyWitness {
		a: Fp::from(6),
		b: Fp::from(7),
	}
}

fn honest_rows() -> Vec<Fp> {
	DummyCircuit::public_from_witness(&witness()).to_rows()
}

// --- MockProver -------------------------------------------------------------------------------

#[test]
fn dummy_honest_witness_is_satisfied() {
	let prover = mock_honest::<DummyCircuit>(&witness());

	assert_satisfied(&prover);
}

#[test]
fn dummy_public_rows_are_product_then_chain_id() {
	let rows = honest_rows();

	assert_eq!(rows.len(), 2);
	assert_eq!(rows[ROW_C], Fp::from(42));
	assert_eq!(rows[ROW_CHAIN_ID], Fp::from(CHAIN_ID));
}

#[test]
fn dummy_wrong_product_row_fails() {
	let mut rows = honest_rows();
	rows[ROW_C] = Fp::from(43);

	let failures = assert_unsatisfied(&mock::<DummyCircuit>(&witness(), rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn dummy_chain_id_42_fails() {
	let mut rows = honest_rows();
	rows[ROW_CHAIN_ID] = Fp::from(42);

	let failures = assert_unsatisfied(&mock::<DummyCircuit>(&witness(), rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn dummy_every_public_row_is_bound() {
	assert_every_public_row_is_bound::<DummyCircuit>(&witness());
}

#[test]
fn dummy_metadata_is_consistent() {
	assert_circuit_metadata_consistent::<DummyCircuit>();
}

// --- Real proofs -------------------------------------------------------------------------------

#[test]
fn dummy_prove_then_verify_succeeds() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();

	let result = verify::<DummyCircuit>(&proof, &[honest_rows()]);

	assert_eq!(result, Ok(()));
}

#[test]
fn dummy_proof_len_matches_circuit_cost_estimate_and_cap() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();

	assert_eq!(proof.len(), expected_proof_len::<DummyCircuit>(1));
	assert!(proof.len() <= MAX_PROOF_BYTES as usize);
}

#[test]
fn dummy_two_instances_in_one_proof_verify() {
	let w2 = DummyWitness {
		a: Fp::from(2),
		b: Fp::from(3),
	};
	let proof = prove::<DummyCircuit>(&[witness(), w2], deterministic_rng(2)).unwrap();
	let rows2 = DummyCircuit::public_from_witness(&w2).to_rows();

	assert_eq!(
		verify::<DummyCircuit>(&proof, &[honest_rows(), rows2]),
		Ok(())
	);
	assert_eq!(proof.len(), expected_proof_len::<DummyCircuit>(2));
}

#[test]
fn dummy_two_instance_proof_costs_less_than_two_proofs() {
	let one = expected_proof_len::<DummyCircuit>(1);
	let two = expected_proof_len::<DummyCircuit>(2);

	assert!(
		two < 2 * one,
		"marginal instance must be cheaper than a new proof: {one} vs {two}"
	);
}

#[test]
fn dummy_prove_rejects_zero_instances() {
	let err = prove::<DummyCircuit>(&[], deterministic_rng(1)).unwrap_err();

	assert!(matches!(err, crate::error::ProveError::NoInstances));
}

#[test]
fn dummy_prove_rejects_more_than_max_instances() {
	let err = prove::<DummyCircuit>(&[witness(); 3], deterministic_rng(1)).unwrap_err();

	assert!(matches!(
		err,
		crate::error::ProveError::TooManyInstances { max: 2, got: 3 }
	));
}

#[test]
fn dummy_verify_rejects_flipped_byte_at_every_position() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();

	for index in 0..proof.len() {
		let tampered = with_flipped_byte(&proof, index);

		assert_eq!(
			verify::<DummyCircuit>(&tampered, &[honest_rows()]),
			Err(VerifyError::InvalidProof),
			"byte {index}"
		);
	}
}

#[test]
fn dummy_verify_rejects_truncated_proof_before_reading_it() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();
	let expected = proof.len();

	let result = verify::<DummyCircuit>(&proof[..expected - 1], &[honest_rows()]);

	assert_eq!(
		result,
		Err(VerifyError::WrongProofLength {
			expected,
			got: expected - 1
		})
	);
}

#[test]
fn dummy_verify_rejects_proof_with_appended_byte() {
	let mut proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();
	let expected = proof.len();
	proof.push(0);

	let result = verify::<DummyCircuit>(&proof, &[honest_rows()]);

	assert_eq!(
		result,
		Err(VerifyError::WrongProofLength {
			expected,
			got: expected + 1
		})
	);
}

#[test]
fn dummy_verify_rejects_wrong_public_input() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();
	let mut rows = honest_rows();
	rows[ROW_C] = Fp::from(43);

	assert_eq!(
		verify::<DummyCircuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}

#[test]
fn dummy_verify_rejects_wrong_chain_id_public_input() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();
	let mut rows = honest_rows();
	rows[ROW_CHAIN_ID] = Fp::from(42);

	assert_eq!(
		verify::<DummyCircuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}

#[test]
fn dummy_verify_rejects_wrong_row_count() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();

	let result = verify::<DummyCircuit>(&proof, &[vec![Fp::from(42)]]);

	assert_eq!(
		result,
		Err(VerifyError::WrongRowCount {
			instance: 0,
			expected: 2,
			got: 1
		})
	);
}

#[test]
fn dummy_verify_rejects_zero_and_excess_instances() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();

	assert_eq!(
		verify::<DummyCircuit>(&proof, &[]),
		Err(VerifyError::NoInstances)
	);
	assert_eq!(
		verify::<DummyCircuit>(&proof, &[honest_rows(), honest_rows(), honest_rows()]),
		Err(VerifyError::TooManyInstances { max: 2, got: 3 })
	);
}

#[test]
fn dummy_verify_rejects_single_instance_proof_presented_as_two_instances() {
	let proof = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();

	let result = verify::<DummyCircuit>(&proof, &[honest_rows(), honest_rows()]);

	assert!(matches!(result, Err(VerifyError::WrongProofLength { .. })));
}

#[test]
fn dummy_two_proofs_of_same_witness_differ_but_both_verify() {
	let p1 = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();
	let p2 = prove::<DummyCircuit>(&[witness()], deterministic_rng(2)).unwrap();

	assert_ne!(p1, p2, "blinding must make proofs unlinkable");
	assert_eq!(verify::<DummyCircuit>(&p1, &[honest_rows()]), Ok(()));
	assert_eq!(verify::<DummyCircuit>(&p2, &[honest_rows()]), Ok(()));
}

#[test]
fn dummy_proving_is_deterministic_for_a_fixed_rng() {
	let p1 = prove::<DummyCircuit>(&[witness()], deterministic_rng(7)).unwrap();
	let p2 = prove::<DummyCircuit>(&[witness()], deterministic_rng(7)).unwrap();

	assert_eq!(p1, p2);
}

// --- Pins --------------------------------------------------------------------------------------

#[test]
fn dummy_k_is_5_and_pins_are_stable() {
	let pins = measure::<DummyCircuit>();

	assert_eq!(pins.k, 5);
	assert_eq!(pins.name, "C0 Dummy");
	assert_eq!(pins.proof_lengths, DummyCircuit::PROOF_LENGTHS);
	assert_eq!(
		hex::encode(pins.vk_hash),
		PINNED_VK_HASH,
		"vk changed: re-pin deliberately"
	);
}

#[test]
fn dummy_pinned_proof_lengths_match_real_proofs_for_every_instance_count() {
	let w2 = DummyWitness {
		a: Fp::from(2),
		b: Fp::from(3),
	};
	let one = prove::<DummyCircuit>(&[witness()], deterministic_rng(1)).unwrap();
	let two = prove::<DummyCircuit>(&[witness(), w2], deterministic_rng(1)).unwrap();

	assert_eq!(
		DummyCircuit::PROOF_LENGTHS.len(),
		DummyCircuit::max_instances() as usize
	);
	assert_eq!(
		one.len(),
		DummyCircuit::PROOF_LENGTHS[0],
		"re-pin PROOF_LENGTHS[0]"
	);
	assert_eq!(
		two.len(),
		DummyCircuit::PROOF_LENGTHS[1],
		"re-pin PROOF_LENGTHS[1]"
	);
}

#[test]
fn expected_proof_len_fails_closed_for_unpinned_instance_counts() {
	assert_eq!(expected_proof_len::<DummyCircuit>(0), usize::MAX);
	assert_eq!(expected_proof_len::<DummyCircuit>(3), usize::MAX);
}

/// Run with `cargo test -p arxon-zk print_pins -- --ignored --nocapture` to re-pin after a circuit change.
#[test]
#[ignore = "prints current pins for a deliberate re-pin"]
fn print_pins_for_update() {
	let pins = measure::<DummyCircuit>();
	println!("{pins:#?}");
	println!("vk_hash hex = {}", hex::encode(pins.vk_hash));
	let w2 = DummyWitness {
		a: Fp::from(2),
		b: Fp::from(3),
	};
	for (n, ws) in [(1, vec![witness()]), (2, vec![witness(), w2])] {
		let proof = prove::<DummyCircuit>(&ws, deterministic_rng(1)).unwrap();
		println!(
			"measured proof length for {n} instance(s) = {}",
			proof.len()
		);
	}
}

const PINNED_VK_HASH: &str = "c6a00d58c7f43c08389cb0649711649496f6ba03b5a77cebdefa8e6129208c73";

// --- Dispatch ----------------------------------------------------------------------------------

#[test]
fn verify_by_wire_id_rejects_zero_and_seven() {
	assert_eq!(
		verify_by_wire_id(0, &[], &[]),
		Err(VerifyError::UnknownCircuit(0))
	);
	assert_eq!(
		verify_by_wire_id(7, &[], &[]),
		Err(VerifyError::UnknownCircuit(7))
	);
}

#[test]
fn verify_by_id_rejects_oversized_proof_before_dispatch() {
	let oversized = vec![0u8; MAX_PROOF_BYTES as usize + 1];

	let result = verify_by_id(
		CircuitId::PrivacyFlagEnforcement,
		&oversized,
		&[vec![FieldBytes::ZERO]],
	);

	assert!(matches!(result, Err(VerifyError::WrongProofLength { .. })));
}
