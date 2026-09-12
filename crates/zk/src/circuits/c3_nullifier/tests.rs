use arxon_zk_primitives::{
	mask::MASK_ALL,
	poseidon::{hash_cv, hash_nullifier},
	NOTE_TREE_DEPTH,
};
use ff::Field;
use halo2_proofs::dev::MockProver;

use super::{rows, C3Circuit, C3Witness};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::VerifyError,
	field::Fp,
	gadgets::merkle::PathWitness,
	merkle::{MemberTree, TreeKind},
	pins::measure,
	prover::prove,
	test_support::{fixtures::*, *},
	verifier::verify,
};

fn rows_of(w: &C3Witness) -> Vec<Fp> {
	C3Circuit::public_from_witness(w).to_rows()
}

// --- satisfiability -----------------------------------------------------------------------------

#[test]
fn c3_valid_witness_for_each_of_16_masks_is_satisfied() {
	for mask in 0..=MASK_ALL {
		assert_satisfied(&mock_honest::<C3Circuit>(&c3(mask)));
	}
}

#[test]
fn c3_anchor_equals_the_tree_root() {
	let (tree, w) = c3_tree();

	assert_eq!(rows_of(&w)[rows::ANCHOR], tree.root());
}

#[test]
fn c3_public_rows_follow_the_frozen_layout() {
	let w = c3(0b0001);
	let rows = rows_of(&w);

	assert_eq!(rows.len(), rows::LEN);
	assert_eq!(rows[rows::NULLIFIER], w.nullifier());
	assert_eq!(rows[rows::CV], hash_cv(42, w.blinding));
	assert_eq!(rows[rows::MASK], Fp::ONE);
	assert_eq!(rows[rows::REVEALED_SENDER], Fp::ZERO, "sender hidden");
	assert_eq!(
		rows_of(&c3(0))[rows::REVEALED_SENDER],
		w.pk(),
		"sender shown"
	);
}

#[test]
fn c3_fits_its_k() {
	let w = c3(0);

	let prover = MockProver::run(
		C3Circuit::K,
		&C3Circuit::from_witness(&w),
		vec![rows_of(&w)],
	);

	assert!(prover.is_ok(), "C3 does not fit K={}", C3Circuit::K);
}

// --- soundness ----------------------------------------------------------------------------------

#[test]
fn c3_wrong_anchor_fails() {
	let w = c3(0);
	let mut rows = rows_of(&w);
	rows[rows::ANCHOR] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_wrong_sibling_at_leaf_level_fails() {
	let mut w = c3(0);
	let honest = rows_of(&w);
	w.path.siblings[0] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, honest));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_wrong_sibling_at_root_level_fails() {
	let mut w = c3(0);
	let honest = rows_of(&w);
	w.path.siblings[NOTE_TREE_DEPTH - 1] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, honest));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_note_of_another_tree_position_fails() {
	// Claim the note sits at index 0 (path of the decoy) while its commitment is at index 2.
	let (tree, mut w) = c3_tree();
	let honest = rows_of(&w);
	w.path = tree.path(0);

	assert!(mock::<C3Circuit>(&w, honest).verify().is_err());
}

#[test]
fn c3_position_bit_two_fails_boolean_gate() {
	let w = c3(0);
	let mut path = PathWitness::from(&w.path);
	path.bits[5] = Fp::from(2);

	let failures = assert_unsatisfied(
		&MockProver::run(
			C3Circuit::K,
			&C3Circuit::with_raw_path(&w, path),
			vec![rows_of(&w)],
		)
		.unwrap(),
	);

	assert_has_gate_failure(&failures, "bit is boolean");
}

#[test]
fn c3_nullifier_from_wrong_sk_fails() {
	let w = c3(0);
	let mut rows = rows_of(&w);
	let other = C3Witness {
		sk: fe(99),
		..w.clone()
	};
	rows[rows::NULLIFIER] = other.nullifier();

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_nullifier_computed_with_rho_instead_of_nk_fails() {
	let w = c3(0);
	let mut rows = rows_of(&w);
	rows[rows::NULLIFIER] = hash_nullifier(w.rho, w.cm());

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_revealed_sender_when_hidden_fails() {
	let w = c3(0b0001);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_SENDER] = w.pk();

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_revealed_sender_of_another_key_fails() {
	let w = c3(0);
	let mut rows = rows_of(&w);
	rows[rows::REVEALED_SENDER] = fe(99);

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_cv_of_wrong_amount_fails() {
	let w = c3(0);
	let mut rows = rows_of(&w);
	rows[rows::CV] = hash_cv(43, w.blinding);

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_amount_2_pow_64_fails_range_lookup() {
	let w = c3(0);
	let circuit = C3Circuit::with_raw_amount(&w, Fp::from(u64::MAX) + Fp::ONE);

	let prover = MockProver::run(C3Circuit::K, &circuit, vec![rows_of(&w)]).unwrap();

	assert!(prover.verify().is_err());
}

#[test]
fn c3_member_tree_root_is_not_a_note_anchor() {
	let w = c3(0);
	let mut rows = rows_of(&w);
	let mut member = MemberTree::new(TreeKind::Member);
	member.insert(w.cm());
	rows[rows::ANCHOR] = member.root();

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_chain_id_42_fails() {
	let w = c3(0);
	let mut rows = rows_of(&w);
	rows[rows::CHAIN_ID] = Fp::from(42);

	let failures = assert_unsatisfied(&mock::<C3Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c3_every_public_row_is_bound() {
	assert_every_public_row_is_bound::<C3Circuit>(&c3(0b1110));
}

#[test]
fn c3_metadata_is_consistent() {
	assert_circuit_metadata_consistent::<C3Circuit>();
}

// --- pins -------------------------------------------------------------------------------------------

#[test]
fn c3_vk_hash_is_pinned() {
	let pins = measure::<C3Circuit>();

	assert_eq!(pins.k, 11);
	assert_eq!(
		hex::encode(pins.vk_hash),
		PINNED_VK_HASH,
		"vk changed: re-pin deliberately. cost: {}",
		pins.cost
	);
}

const PINNED_VK_HASH: &str = "aa29c3035a33e25f644249be23cb76cbafb6da94e550e85fdd417b78e6a182a4";

/// `cargo test -p arxon-zk c3_print_pins -- --ignored --nocapture`
#[test]
#[ignore = "prints current pins for a deliberate re-pin"]
fn c3_print_pins_for_update() {
	let pins = measure::<C3Circuit>();
	println!("{pins:#?}");
	println!("vk_hash hex = {}", hex::encode(pins.vk_hash));
	for n in 1..=2 {
		let proof = prove::<C3Circuit>(&vec![c3(0); n], deterministic_rng(1)).unwrap();
		println!(
			"measured proof length for {n} instance(s) = {}",
			proof.len()
		);
	}
}

// --- real proofs ------------------------------------------------------------------------------------

#[test]
fn c3_prove_then_verify_succeeds_for_one_and_two_instances() {
	let (a, b) = (c3(0), c3(0b0001));

	let one = prove::<C3Circuit>(&[a.clone()], deterministic_rng(1)).unwrap();
	let two = prove::<C3Circuit>(&[a.clone(), b.clone()], deterministic_rng(2)).unwrap();

	assert_eq!(verify::<C3Circuit>(&one, &[rows_of(&a)]), Ok(()));
	assert_eq!(
		verify::<C3Circuit>(&two, &[rows_of(&a), rows_of(&b)]),
		Ok(())
	);
	assert_eq!(
		one.len(),
		C3Circuit::PROOF_LENGTHS[0],
		"re-pin PROOF_LENGTHS[0]"
	);
	assert_eq!(
		two.len(),
		C3Circuit::PROOF_LENGTHS[1],
		"re-pin PROOF_LENGTHS[1]"
	);
	assert!(
		one.len() < 5120,
		"single-instance proof must stay under 5 KB"
	);
}

#[test]
fn c3_verify_rejects_flipped_bytes_at_sampled_positions() {
	let w = c3(0);
	let proof = prove::<C3Circuit>(&[w.clone()], deterministic_rng(1)).unwrap();

	for index in (0..proof.len()).step_by(97) {
		let tampered = with_flipped_byte(&proof, index);
		assert_eq!(
			verify::<C3Circuit>(&tampered, &[rows_of(&w)]),
			Err(VerifyError::InvalidProof),
			"byte {index}"
		);
	}
}

#[test]
fn c3_verify_rejects_wrong_nullifier_public_input() {
	let w = c3(0);
	let proof = prove::<C3Circuit>(&[w.clone()], deterministic_rng(1)).unwrap();
	let mut rows = rows_of(&w);
	rows[rows::NULLIFIER] += Fp::ONE;

	assert_eq!(
		verify::<C3Circuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}
