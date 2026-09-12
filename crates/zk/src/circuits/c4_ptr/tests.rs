use arxon_zk_primitives::poseidon::hash_ptr;
use ff::Field;

use super::{rows, C4Circuit, C4Witness};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::VerifyError,
	field::Fp,
	pins::measure,
	prover::prove,
	test_support::{fixtures::*, *},
	verifier::verify,
};

fn rows_of(w: &C4Witness) -> Vec<Fp> {
	C4Circuit::public_from_witness(w).to_rows()
}

#[test]
fn c4_honest_witness_is_satisfied() {
	assert_satisfied(&mock_honest::<C4Circuit>(&c4()));
}

#[test]
fn c4_ptr_id_matches_native_hash() {
	let w = c4();

	assert_eq!(
		rows_of(&w)[rows::PTR_ID],
		hash_ptr(w.pk_s, w.pk_r, w.cv, w.nonce)
	);
}

#[test]
fn c4_wrong_nonce_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::PTR_ID] = hash_ptr(w.pk_s, w.pk_r, w.cv, w.nonce + Fp::ONE);

	let failures = assert_unsatisfied(&mock::<C4Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c4_swapped_sender_receiver_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::PTR_ID] = hash_ptr(w.pk_r, w.pk_s, w.cv, w.nonce);

	let failures = assert_unsatisfied(&mock::<C4Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c4_cv_row_must_be_the_one_hashed() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::CV] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C4Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c4_chain_id_42_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::CHAIN_ID] = Fp::from(42);

	let failures = assert_unsatisfied(&mock::<C4Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c4_every_public_row_is_bound() {
	assert_every_public_row_is_bound::<C4Circuit>(&c4());
}

#[test]
fn c4_metadata_is_consistent() {
	assert_circuit_metadata_consistent::<C4Circuit>();
}

#[test]
fn c4_vk_hash_is_pinned() {
	let pins = measure::<C4Circuit>();

	assert_eq!(pins.k, 9);
	assert_eq!(
		hex::encode(pins.vk_hash),
		PINNED_VK_HASH,
		"vk changed: re-pin deliberately. cost: {}",
		pins.cost
	);
}

const PINNED_VK_HASH: &str = "1cb2ba13232989084598bd6460756b092e297f96e03bd32f85f65f233eb9ac23";

#[test]
#[ignore = "prints current pins for a deliberate re-pin"]
fn c4_print_pins_for_update() {
	let pins = measure::<C4Circuit>();
	println!("{pins:#?}");
	println!("vk_hash hex = {}", hex::encode(pins.vk_hash));
	let proof = prove::<C4Circuit>(&[c4()], deterministic_rng(1)).unwrap();
	println!("measured proof length for 1 instance(s) = {}", proof.len());
}

#[test]
fn c4_prove_then_verify_succeeds_and_length_is_pinned() {
	let w = c4();

	let proof = prove::<C4Circuit>(&[w], deterministic_rng(1)).unwrap();

	assert_eq!(verify::<C4Circuit>(&proof, &[rows_of(&w)]), Ok(()));
	assert_eq!(
		proof.len(),
		C4Circuit::PROOF_LENGTHS[0],
		"re-pin PROOF_LENGTHS[0]"
	);
	assert!(proof.len() < 5120);
}

#[test]
fn c4_verify_rejects_wrong_ptr_id() {
	let w = c4();
	let proof = prove::<C4Circuit>(&[w], deterministic_rng(1)).unwrap();
	let mut rows = rows_of(&w);
	rows[rows::PTR_ID] += Fp::ONE;

	assert_eq!(
		verify::<C4Circuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}
