use ff::Field;

use super::{rows, C5Circuit, C5Witness};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::VerifyError,
	field::Fp,
	pins::measure,
	prover::prove,
	test_support::{fixtures::*, *},
	verifier::verify,
};

fn rows_of(w: &C5Witness) -> Vec<Fp> {
	C5Circuit::public_from_witness(w).to_rows()
}

#[test]
fn c5_valid_witness_for_each_disclosure_mask_without_balance_bit_is_satisfied() {
	for mask in 0..8u8 {
		assert_satisfied(&mock_honest::<C5Circuit>(&c5(mask)));
	}
}

#[test]
fn c5_ptr_id_equals_the_receipt_of_circuit_4() {
	assert_eq!(rows_of(&c5(0))[rows::PTR_ID], c4().ptr_id());
}

#[test]
fn c5_full_disclosure_publishes_all_three_fields() {
	let w = c5(0);
	let rows = rows_of(&w);

	assert_eq!(rows[rows::REVEALED_SENDER], w.pk_s);
	assert_eq!(rows[rows::REVEALED_RECEIVER], w.pk_r);
	assert_eq!(rows[rows::REVEALED_AMOUNT], Fp::from(42));
	assert_eq!(rows[rows::AUDIENCE], w.audience);
}

#[test]
fn c5_amount_only_disclosure_hides_the_parties() {
	let rows = rows_of(&c5(0b0011));

	assert_eq!(rows[rows::REVEALED_SENDER], Fp::ZERO);
	assert_eq!(rows[rows::REVEALED_RECEIVER], Fp::ZERO);
	assert_eq!(rows[rows::REVEALED_AMOUNT], Fp::from(42));
}

#[test]
fn c5_bit3_set_fails() {
	let w = c5(0b1000);

	let failures = assert_unsatisfied(&mock_honest::<C5Circuit>(&w));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c5_reveal_amount_with_wrong_blinding_fails() {
	let mut w = c5(0);
	let honest = rows_of(&w);
	w.blinding += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C5Circuit>(&w, honest));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c5_reveal_sender_of_unrelated_receipt_fails() {
	let w = c5(0);
	let mut rows = rows_of(&w);
	rows[rows::PTR_ID] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C5Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c5_leaking_hidden_sender_fails() {
	let w = c5(0b0001);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_SENDER] = w.pk_s;

	let failures = assert_unsatisfied(&mock::<C5Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c5_wrong_revealed_amount_fails() {
	let w = c5(0);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_AMOUNT] = Fp::from(43);

	let failures = assert_unsatisfied(&mock::<C5Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c5_audience_row_is_bound() {
	let w = c5(0);
	let mut rows = rows_of(&w);
	rows[rows::AUDIENCE] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C5Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c5_every_public_row_is_bound() {
	assert_every_public_row_is_bound::<C5Circuit>(&c5(0b0101));
}

#[test]
fn c5_metadata_is_consistent() {
	assert_circuit_metadata_consistent::<C5Circuit>();
}

#[test]
fn c5_vk_hash_is_pinned() {
	let pins = measure::<C5Circuit>();

	assert_eq!(pins.k, 9);
	assert_eq!(
		hex::encode(pins.vk_hash),
		PINNED_VK_HASH,
		"vk changed: re-pin deliberately. cost: {}",
		pins.cost
	);
}

const PINNED_VK_HASH: &str = "68fe69f4ad847c48452dd4e3ed31f135c7326192c9898d15557e8d20b60c4a50";

#[test]
#[ignore = "prints current pins for a deliberate re-pin"]
fn c5_print_pins_for_update() {
	let pins = measure::<C5Circuit>();
	println!("{pins:#?}");
	println!("vk_hash hex = {}", hex::encode(pins.vk_hash));
	let proof = prove::<C5Circuit>(&[c5(0)], deterministic_rng(1)).unwrap();
	println!("measured proof length for 1 instance(s) = {}", proof.len());
}

#[test]
fn c5_prove_then_verify_succeeds_and_length_is_pinned() {
	let w = c5(0b0010);

	let proof = prove::<C5Circuit>(&[w], deterministic_rng(1)).unwrap();

	assert_eq!(verify::<C5Circuit>(&proof, &[rows_of(&w)]), Ok(()));
	assert_eq!(
		proof.len(),
		C5Circuit::PROOF_LENGTHS[0],
		"re-pin PROOF_LENGTHS[0]"
	);
	assert!(proof.len() < 5120);
}

#[test]
fn c5_proof_for_one_audience_does_not_verify_for_another() {
	let w = c5(0);
	let proof = prove::<C5Circuit>(&[w], deterministic_rng(1)).unwrap();
	let mut rows = rows_of(&w);
	rows[rows::AUDIENCE] = fe(61);

	assert_eq!(
		verify::<C5Circuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}
