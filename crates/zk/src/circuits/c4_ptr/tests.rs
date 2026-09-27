use arxon_zk_primitives::poseidon::{hash_nk, hash_note, hash_nullifier, hash_pk, hash_ptr};
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

fn assert_rows_rejected(w: &C4Witness, rows: Vec<Fp>) {
	let failures = assert_unsatisfied(&mock::<C4Circuit>(w, rows));
	assert_has_permutation_failure(&failures);
}

#[test]
fn c4_honest_witness_is_satisfied() {
	assert_satisfied(&mock_honest::<C4Circuit>(&c4()));
}

#[test]
fn c4_one_input_bundle_repeats_the_nullifier_and_is_satisfied() {
	let mut w = c4();
	w.spent[1] = w.spent[0];

	assert_eq!(w.nullifiers()[0], w.nullifiers()[1]);
	assert_satisfied(&mock_honest::<C4Circuit>(&w));
}

#[test]
fn c4_rows_match_native_hashes() {
	let w = c4();
	let rows = rows_of(&w);

	assert_eq!(rows[rows::PTR_ID], hash_ptr(w.pk_s, w.pk_r, w.cv, w.nonce));
	assert_eq!(rows[rows::CM], hash_note(w.pk_r, w.amount, w.rho_out));
	let spent_cm = hash_note(hash_pk(sender_sk()), w.spent[1].amount, w.spent[1].rho);
	assert_eq!(
		rows[rows::NULLIFIER_1],
		hash_nullifier(hash_nk(sender_sk()), spent_cm)
	);
}

#[test]
fn c4_wrong_nonce_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::PTR_ID] = hash_ptr(w.pk_s, w.pk_r, w.cv, w.nonce + Fp::ONE);

	assert_rows_rejected(&w, rows);
}

#[test]
fn c4_swapped_sender_receiver_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::PTR_ID] = hash_ptr(w.pk_r, w.pk_s, w.cv, w.nonce);

	assert_rows_rejected(&w, rows);
}

#[test]
fn c4_cv_row_must_be_the_one_hashed() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::CV] += Fp::ONE;

	assert_rows_rejected(&w, rows);
}

/// The original attack: a receipt naming a victim as sender. The victim's key
/// cannot produce the nullifiers of notes the victim does not own.
#[test]
fn c4_receipt_naming_a_victim_as_sender_fails() {
	let honest = c4();
	let framed = C4Witness {
		pk_s: hash_pk(fe(0xbad)),
		..honest
	};
	let mut rows = rows_of(&framed);
	rows[rows::NULLIFIER_0] = rows_of(&honest)[rows::NULLIFIER_0];
	rows[rows::NULLIFIER_1] = rows_of(&honest)[rows::NULLIFIER_1];

	assert_rows_rejected(&framed, rows);
}

/// A sender paying with two keys cannot attribute the payment to one of them:
/// both nullifier rows must derive from the same `pk_s` and `nk`.
#[test]
fn c4_nullifier_of_a_note_owned_by_another_key_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	let other_cm = hash_note(hash_pk(fe(0xc1ea)), w.spent[1].amount, w.spent[1].rho);
	rows[rows::NULLIFIER_1] = hash_nullifier(hash_nk(fe(0xc1ea)), other_cm);

	assert_rows_rejected(&w, rows);
}

#[test]
fn c4_nullifier_under_another_nullifier_key_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	let cm = hash_note(w.pk_s, w.spent[0].amount, w.spent[0].rho);
	rows[rows::NULLIFIER_0] = hash_nullifier(hash_nk(fe(0xc1ea)), cm);

	assert_rows_rejected(&w, rows);
}

/// A receipt naming a receiver other than the paid note's owner.
#[test]
fn c4_payment_cm_of_another_receiver_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::CM] = hash_note(fe(0xfeed), w.amount, w.rho_out);

	assert_rows_rejected(&w, rows);
}

#[test]
fn c4_chain_id_42_fails() {
	let w = c4();
	let mut rows = rows_of(&w);
	rows[rows::CHAIN_ID] = Fp::from(42);

	assert_rows_rejected(&w, rows);
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

const PINNED_VK_HASH: &str = "1cfefe2151af9a08c72fd38430a2a5d42586fef4d6a4225039be744ca507f7e6";

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
