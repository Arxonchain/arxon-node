use arxon_zk_primitives::{mask::MASK_ALL, poseidon::hash_cv, CHAIN_ID};
use ff::Field;
use halo2_proofs::dev::MockProver;

use super::{rows, C1Circuit, C1Witness};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	circuits::C2Circuit,
	error::VerifyError,
	field::Fp,
	pins::measure,
	prover::prove,
	test_support::{fixtures::*, *},
	verifier::verify,
};

fn rows_of(w: &C1Witness) -> Vec<Fp> {
	C1Circuit::public_from_witness(w).to_rows()
}

// --- satisfiability -----------------------------------------------------------------------------

#[test]
fn c1_valid_witness_for_each_of_16_masks_is_satisfied() {
	for mask in 0..=MASK_ALL {
		assert_satisfied(&mock_honest::<C1Circuit>(&c1(mask)));
	}
}

#[test]
fn c1_zero_amount_is_satisfied() {
	let mut w = c1(0);
	w.amount = 0;

	assert_satisfied(&mock_honest::<C1Circuit>(&w));
}

#[test]
fn c1_max_u64_amount_is_satisfied() {
	let mut w = c1(0);
	w.amount = u64::MAX;

	assert_satisfied(&mock_honest::<C1Circuit>(&w));
}

#[test]
fn c1_public_rows_follow_the_frozen_layout() {
	let w = c1(0b0100);
	let rows = rows_of(&w);

	assert_eq!(rows.len(), rows::LEN);
	assert_eq!(rows[rows::CV], hash_cv(42, w.blinding));
	assert_eq!(rows[rows::MASK], Fp::from(0b0100));
	assert_eq!(rows[rows::REVEALED_RECEIVER], w.pk_r, "receiver shown");
	assert_eq!(rows[rows::REVEALED_AMOUNT], Fp::ZERO, "amount hidden");
	assert_eq!(rows[rows::BUNDLE_DIGEST], digest());
	assert_eq!(rows[rows::CHAIN_ID], Fp::from(CHAIN_ID));
	assert_eq!(rows[rows::EXPIRY_BLOCK], Fp::from(EXPIRY as u64));
}

// --- soundness (one per constraint) -------------------------------------------------------------

#[test]
fn c1_mask_16_fails_mask_lookup() {
	let mut w = c1(0);
	w.mask = 16;

	let failures = assert_unsatisfied(&mock_honest::<C1Circuit>(&w));

	assert_has_lookup_failure(&failures);
}

#[test]
fn c1_revealed_amount_when_hidden_fails() {
	let w = c1(0b0100);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_AMOUNT] = Fp::from(42);

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_wrong_revealed_amount_when_shown_fails() {
	let w = c1(0);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_AMOUNT] = Fp::from(43);

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_revealed_receiver_when_hidden_fails() {
	let w = c1(0b0010);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_RECEIVER] = w.pk_r;

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_wrong_revealed_receiver_when_shown_fails() {
	let w = c1(0);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_RECEIVER] = fe(99);

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_mask_row_claiming_hidden_while_witness_reveals_fails() {
	// Prover proves mask 0 (all shown) but publishes mask 0b0111 with the shown values.
	let w = c1(0);
	let mut rows = rows_of(&w);
	rows[rows::MASK] = Fp::from(0b0111);

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_wrong_cv_fails() {
	let w = c1(0);
	let mut rows = rows_of(&w);
	rows[rows::CV] = hash_cv(43, w.blinding);

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_wrong_cm_fails() {
	let w = c1(0);
	let mut rows = rows_of(&w);
	rows[rows::CM] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_cv_and_cm_must_open_to_the_same_amount() {
	// Rows built from a note of 42 but a cv of 43: no single amount witness satisfies both hashes.
	let w = c1(0b0100);
	let mut rows = rows_of(&w);
	rows[rows::CV] = hash_cv(43, w.blinding);

	assert!(mock::<C1Circuit>(&w, rows).verify().is_err());
}

#[test]
fn c1_chain_id_42_fails() {
	let w = c1(0);
	let mut rows = rows_of(&w);
	rows[rows::CHAIN_ID] = Fp::from(42);

	let failures = assert_unsatisfied(&mock::<C1Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c1_every_public_row_is_bound() {
	assert_every_public_row_is_bound::<C1Circuit>(&c1(0b0101));
}

#[test]
fn c1_metadata_is_consistent() {
	assert_circuit_metadata_consistent::<C1Circuit>();
}

#[test]
fn c1_fits_its_k() {
	let w = c1(0);

	let prover = MockProver::run(
		C1Circuit::K,
		&C1Circuit::from_witness(&w),
		vec![rows_of(&w)],
	);

	assert!(prover.is_ok(), "C1 does not fit K={}", C1Circuit::K);
}

// --- pins -------------------------------------------------------------------------------------------

#[test]
fn c1_vk_hash_is_pinned() {
	let pins = measure::<C1Circuit>();

	assert_eq!(pins.k, 9);
	assert_eq!(
		hex::encode(pins.vk_hash),
		PINNED_VK_HASH,
		"vk changed: re-pin deliberately. cost: {}",
		pins.cost
	);
}

const PINNED_VK_HASH: &str = "9546beb0398d78f120977d51bc2fa85d91583e4c5df407b95050c408530d5dc3";

/// `cargo test -p arxon-zk c1_print_pins -- --ignored --nocapture`
#[test]
#[ignore = "prints current pins for a deliberate re-pin"]
fn c1_print_pins_for_update() {
	let pins = measure::<C1Circuit>();
	println!("{pins:#?}");
	println!("vk_hash hex = {}", hex::encode(pins.vk_hash));
	for n in 1..=2 {
		let proof = prove::<C1Circuit>(&vec![c1(0); n], deterministic_rng(1)).unwrap();
		println!(
			"measured proof length for {n} instance(s) = {}",
			proof.len()
		);
	}
}

// --- real proofs ------------------------------------------------------------------------------------

#[test]
fn c1_prove_then_verify_succeeds_for_one_and_two_instances() {
	let (a, b) = (c1(0), c1(0b0111));

	let one = prove::<C1Circuit>(&[a], deterministic_rng(1)).unwrap();
	let two = prove::<C1Circuit>(&[a, b], deterministic_rng(2)).unwrap();

	assert_eq!(verify::<C1Circuit>(&one, &[rows_of(&a)]), Ok(()));
	assert_eq!(
		verify::<C1Circuit>(&two, &[rows_of(&a), rows_of(&b)]),
		Ok(())
	);
	assert_eq!(
		one.len(),
		C1Circuit::PROOF_LENGTHS[0],
		"re-pin PROOF_LENGTHS[0]"
	);
	assert_eq!(
		two.len(),
		C1Circuit::PROOF_LENGTHS[1],
		"re-pin PROOF_LENGTHS[1]"
	);
	assert!(
		one.len() < 5120,
		"single-instance proof must stay under 5 KB"
	);
}

#[test]
fn c1_verify_rejects_flipped_bytes_at_sampled_positions() {
	let w = c1(0);
	let proof = prove::<C1Circuit>(&[w], deterministic_rng(1)).unwrap();

	for index in (0..proof.len()).step_by(97) {
		let tampered = with_flipped_byte(&proof, index);
		assert_eq!(
			verify::<C1Circuit>(&tampered, &[rows_of(&w)]),
			Err(VerifyError::InvalidProof),
			"byte {index}"
		);
	}
}

#[test]
fn c1_verify_rejects_wrong_public_inputs() {
	let w = c1(0);
	let proof = prove::<C1Circuit>(&[w], deterministic_rng(1)).unwrap();
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_AMOUNT] = Fp::from(43);

	assert_eq!(
		verify::<C1Circuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}

#[test]
fn c1_proof_is_rejected_by_circuit_2_verifier() {
	let w = c1(0);
	let proof = prove::<C1Circuit>(&[w], deterministic_rng(1)).unwrap();
	let c2 = C2Circuit::public_from_witness(&c2_shield()).to_rows();

	assert!(verify::<C2Circuit>(&proof, &[c2]).is_err());
}

#[test]
fn c1_two_proofs_of_same_witness_differ_but_both_verify() {
	let w = c1(0);

	let p1 = prove::<C1Circuit>(&[w], deterministic_rng(1)).unwrap();
	let p2 = prove::<C1Circuit>(&[w], deterministic_rng(2)).unwrap();

	assert_ne!(p1, p2);
	assert_eq!(verify::<C1Circuit>(&p1, &[rows_of(&w)]), Ok(()));
	assert_eq!(verify::<C1Circuit>(&p2, &[rows_of(&w)]), Ok(()));
}
