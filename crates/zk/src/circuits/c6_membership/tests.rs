use arxon_zk_primitives::{poseidon::hash_note, MEMBER_TREE_DEPTH};
use ff::Field;
use halo2_proofs::dev::MockProver;

use super::{rows, C6Circuit, C6Witness};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::VerifyError,
	field::Fp,
	merkle::{NoteTree, TreeKind},
	pins::measure,
	prover::prove,
	test_support::{fixtures::*, *},
	verifier::verify,
};

fn rows_of(w: &C6Witness) -> Vec<Fp> {
	C6Circuit::public_from_witness(w).to_rows()
}

#[test]
fn c6_honest_witness_is_satisfied() {
	assert_satisfied(&mock_honest::<C6Circuit>(&c6()));
}

#[test]
fn c6_registry_root_equals_the_tree_root_and_cm_the_note() {
	let (tree, w) = c6_tree();
	let rows = rows_of(&w);

	assert_eq!(rows[rows::REGISTRY_ROOT], tree.root());
	assert_eq!(rows[rows::CM], hash_note(w.pk_member, 42, w.rho));
}

#[test]
fn c6_fits_its_k() {
	let w = c6();

	assert!(MockProver::run(
		C6Circuit::K,
		&C6Circuit::from_witness(&w),
		vec![rows_of(&w)]
	)
	.is_ok());
}

#[test]
fn c6_leaf_from_unregistered_pk_fails() {
	let mut w = c6();
	let honest = rows_of(&w);
	w.pk_member = fe(99);

	assert!(mock::<C6Circuit>(&w, honest).verify().is_err());
}

#[test]
fn c6_note_commitment_to_other_recipient_fails() {
	let w = c6();
	let mut rows = rows_of(&w);
	rows[rows::CM] = hash_note(fe(99), 42, w.rho);

	let failures = assert_unsatisfied(&mock::<C6Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c6_wrong_sibling_at_root_level_fails() {
	let mut w = c6();
	let honest = rows_of(&w);
	w.path.siblings[MEMBER_TREE_DEPTH - 1] += Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C6Circuit>(&w, honest));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c6_registry_root_of_note_tree_fails() {
	let w = c6();
	let mut rows = rows_of(&w);
	let mut note_tree = NoteTree::new(TreeKind::Note);
	note_tree.insert(w.leaf());
	rows[rows::REGISTRY_ROOT] = note_tree.root();

	let failures = assert_unsatisfied(&mock::<C6Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c6_chain_id_42_fails() {
	let w = c6();
	let mut rows = rows_of(&w);
	rows[rows::CHAIN_ID] = Fp::from(42);

	let failures = assert_unsatisfied(&mock::<C6Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c6_every_public_row_is_bound() {
	assert_every_public_row_is_bound::<C6Circuit>(&c6());
}

#[test]
fn c6_metadata_is_consistent() {
	assert_circuit_metadata_consistent::<C6Circuit>();
}

#[test]
fn c6_vk_hash_is_pinned() {
	let pins = measure::<C6Circuit>();

	assert_eq!(pins.k, 10);
	assert_eq!(
		hex::encode(pins.vk_hash),
		PINNED_VK_HASH,
		"vk changed: re-pin deliberately. cost: {}",
		pins.cost
	);
}

const PINNED_VK_HASH: &str = "44dd00715d7f6e3026fac700d85f7146af19ee5ff3f0c91fd8ff44ed63ca96ce";

#[test]
#[ignore = "prints current pins for a deliberate re-pin"]
fn c6_print_pins_for_update() {
	let pins = measure::<C6Circuit>();
	println!("{pins:#?}");
	println!("vk_hash hex = {}", hex::encode(pins.vk_hash));
	let proof = prove::<C6Circuit>(&[c6()], deterministic_rng(1)).unwrap();
	println!("measured proof length for 1 instance(s) = {}", proof.len());
}

#[test]
fn c6_prove_then_verify_succeeds_and_length_is_pinned() {
	let w = c6();

	let proof = prove::<C6Circuit>(&[w.clone()], deterministic_rng(1)).unwrap();

	assert_eq!(verify::<C6Circuit>(&proof, &[rows_of(&w)]), Ok(()));
	assert_eq!(
		proof.len(),
		C6Circuit::PROOF_LENGTHS[0],
		"re-pin PROOF_LENGTHS[0]"
	);
	assert!(proof.len() < 5120);
}

#[test]
fn c6_verify_rejects_wrong_registry_root() {
	let w = c6();
	let proof = prove::<C6Circuit>(&[w.clone()], deterministic_rng(1)).unwrap();
	let mut rows = rows_of(&w);
	rows[rows::REGISTRY_ROOT] += Fp::ONE;

	assert_eq!(
		verify::<C6Circuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}
