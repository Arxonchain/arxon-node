use arxon_zk_primitives::poseidon::hash_cv;
use ff::Field;
use halo2_proofs::dev::MockProver;

use super::{rows, C2Circuit, C2Witness};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::VerifyError,
	field::Fp,
	pins::measure,
	prover::prove,
	test_support::{fixtures::*, *},
	verifier::verify,
};

fn rows_of(w: &C2Witness) -> Vec<Fp> {
	C2Circuit::public_from_witness(w).to_rows()
}

fn raw(w: &C2Witness, v_in: [u64; 2], v_out: [u64; 2], tin: u64, tout: u64, fee: u64) -> C2Circuit {
	C2Circuit::with_raw_amounts(
		w,
		v_in.map(Fp::from),
		v_out.map(Fp::from),
		Fp::from(tin),
		Fp::from(tout),
		Fp::from(fee),
	)
}

// --- satisfiability -----------------------------------------------------------------------------

#[test]
fn c2_balanced_transfer_is_satisfied() {
	assert_satisfied(&mock_honest::<C2Circuit>(&c2_transfer()));
}

#[test]
fn c2_shield_with_dummy_input_slots_is_satisfied() {
	assert_satisfied(&mock_honest::<C2Circuit>(&c2_shield()));
}

#[test]
fn c2_unshield_with_change_is_satisfied() {
	assert_satisfied(&mock_honest::<C2Circuit>(&c2_unshield()));
}

#[test]
fn c2_non_zero_fee_is_accounted() {
	let mut w = c2_transfer();
	w.v_out = [39, 2];
	w.fee = 1;

	assert_satisfied(&mock_honest::<C2Circuit>(&w));
}

#[test]
fn c2_unused_slots_expose_the_dummy_commitment() {
	let rows = rows_of(&c2_shield());

	assert_eq!(rows[rows::CV_IN[0]], dummy_cv());
	assert_eq!(rows[rows::CV_IN[1]], dummy_cv());
	assert_eq!(rows[rows::CV_OUT[1]], dummy_cv());
	assert_eq!(rows[rows::TRANSPARENT_IN], Fp::from(42));
}

// --- soundness ----------------------------------------------------------------------------------

#[test]
fn c2_sum_mismatch_by_one_fails_conservation_gate() {
	let w = c2_transfer();
	let circuit = raw(&w, [30, 12], [41, 2], 0, 0, 0);

	let failures =
		assert_unsatisfied(&MockProver::run(C2Circuit::K, &circuit, vec![rows_of(&w)]).unwrap());

	assert_has_gate_failure(&failures, "inputs equal outputs plus fee");
}

#[test]
fn c2_dummy_slot_only_opens_to_zero() {
	// Public cv_in1 = dummy, witness claims it holds 1 unit (and balances the sum with it).
	let w = c2_shield();
	let circuit = raw(&w, [0, 1], [43, 0], 42, 0, 0);

	let failures =
		assert_unsatisfied(&MockProver::run(C2Circuit::K, &circuit, vec![rows_of(&w)]).unwrap());

	assert_has_permutation_failure(&failures);
}

#[test]
fn c2_output_2_pow_64_fails_range_lookup() {
	let w = c2_transfer();
	let two_pow_64 = Fp::from(u64::MAX) + Fp::ONE;
	// in: 2^64 + 12, out: 2^64 + 2 + 40 keeps the field equation true; the range check must reject.
	let circuit = C2Circuit::with_raw_amounts(
		&w,
		[two_pow_64 + Fp::from(30), Fp::from(12)],
		[two_pow_64 + Fp::from(40), Fp::from(2)],
		Fp::ZERO,
		Fp::ZERO,
		Fp::ZERO,
	);
	let mut rows = rows_of(&w);
	rows[rows::CV_IN[0]] = arxon_zk_primitives::poseidon::sponge_hash::<
		arxon_zk_primitives::poseidon::ArxonDomain<{ arxon_zk_primitives::constants::tags::CV }, 2>,
	>(&[two_pow_64 + Fp::from(30), w.r_in[0]]);
	rows[rows::CV_OUT[0]] = arxon_zk_primitives::poseidon::sponge_hash::<
		arxon_zk_primitives::poseidon::ArxonDomain<{ arxon_zk_primitives::constants::tags::CV }, 2>,
	>(&[two_pow_64 + Fp::from(40), w.r_out[0]]);

	let failures =
		assert_unsatisfied(&MockProver::run(C2Circuit::K, &circuit, vec![rows]).unwrap());

	assert_has_lookup_failure(&failures);
}

#[test]
fn c2_wraparound_attempt_with_negative_input_fails() {
	// v_in0 = -1 (p - 1) and v_out0 = 11 makes the field sum balance: -1 + 12 = 11. Range check rejects.
	let w = c2_transfer();
	let circuit = C2Circuit::with_raw_amounts(
		&w,
		[-Fp::ONE, Fp::from(12)],
		[Fp::from(11), Fp::ZERO],
		Fp::ZERO,
		Fp::ZERO,
		Fp::ZERO,
	);
	let mut rows = rows_of(&w);
	rows[rows::CV_IN[0]] = arxon_zk_primitives::poseidon::sponge_hash::<
		arxon_zk_primitives::poseidon::ArxonDomain<{ arxon_zk_primitives::constants::tags::CV }, 2>,
	>(&[-Fp::ONE, w.r_in[0]]);
	rows[rows::CV_OUT[0]] = hash_cv(11, w.r_out[0]);
	rows[rows::CV_OUT[1]] = hash_cv(0, w.r_out[1]);

	assert!(MockProver::run(C2Circuit::K, &circuit, vec![rows])
		.unwrap()
		.verify()
		.is_err());
}

#[test]
fn c2_transparent_out_row_must_match_witness() {
	let w = c2_unshield();
	let mut rows = rows_of(&w);
	rows[rows::TRANSPARENT_OUT] = Fp::from(41);

	let failures = assert_unsatisfied(&mock::<C2Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c2_fee_row_must_match_witness() {
	let w = c2_transfer();
	let mut rows = rows_of(&w);
	rows[rows::FEE] = Fp::ONE;

	let failures = assert_unsatisfied(&mock::<C2Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c2_chain_id_42_fails() {
	let w = c2_transfer();
	let mut rows = rows_of(&w);
	rows[rows::CHAIN_ID] = Fp::from(42);

	let failures = assert_unsatisfied(&mock::<C2Circuit>(&w, rows));

	assert_has_permutation_failure(&failures);
}

#[test]
fn c2_every_public_row_is_bound() {
	assert_every_public_row_is_bound::<C2Circuit>(&c2_transfer());
}

#[test]
fn c2_metadata_is_consistent() {
	assert_circuit_metadata_consistent::<C2Circuit>();
}

// --- pins -------------------------------------------------------------------------------------------

#[test]
fn c2_vk_hash_is_pinned() {
	let pins = measure::<C2Circuit>();

	assert_eq!(pins.k, 9);
	assert_eq!(
		hex::encode(pins.vk_hash),
		PINNED_VK_HASH,
		"vk changed: re-pin deliberately. cost: {}",
		pins.cost
	);
}

const PINNED_VK_HASH: &str = "ef1f8c9c8f31eebba74ea7f2126a818ea0938cb04c88ce23b2b06127ddb3504c";

/// `cargo test -p arxon-zk c2_print_pins -- --ignored --nocapture`
#[test]
#[ignore = "prints current pins for a deliberate re-pin"]
fn c2_print_pins_for_update() {
	let pins = measure::<C2Circuit>();
	println!("{pins:#?}");
	println!("vk_hash hex = {}", hex::encode(pins.vk_hash));
	let proof = prove::<C2Circuit>(&[c2_transfer()], deterministic_rng(1)).unwrap();
	println!("measured proof length for 1 instance(s) = {}", proof.len());
}

// --- real proofs ------------------------------------------------------------------------------------

#[test]
fn c2_prove_then_verify_succeeds_and_length_is_pinned() {
	let w = c2_transfer();

	let proof = prove::<C2Circuit>(&[w], deterministic_rng(1)).unwrap();

	assert_eq!(verify::<C2Circuit>(&proof, &[rows_of(&w)]), Ok(()));
	assert_eq!(
		proof.len(),
		C2Circuit::PROOF_LENGTHS[0],
		"re-pin PROOF_LENGTHS[0]"
	);
	assert!(proof.len() < 5120);
}

#[test]
fn c2_verify_rejects_flipped_bytes_at_sampled_positions() {
	let w = c2_transfer();
	let proof = prove::<C2Circuit>(&[w], deterministic_rng(1)).unwrap();

	for index in (0..proof.len()).step_by(97) {
		let tampered = with_flipped_byte(&proof, index);
		assert_eq!(
			verify::<C2Circuit>(&tampered, &[rows_of(&w)]),
			Err(VerifyError::InvalidProof),
			"byte {index}"
		);
	}
}

#[test]
fn c2_verify_rejects_wrong_transparent_amount() {
	let w = c2_shield();
	let proof = prove::<C2Circuit>(&[w], deterministic_rng(1)).unwrap();
	let mut rows = rows_of(&w);
	rows[rows::TRANSPARENT_IN] = Fp::from(41);

	assert_eq!(
		verify::<C2Circuit>(&proof, &[rows]),
		Err(VerifyError::InvalidProof)
	);
}

/// The transparent and fee rows are public, so an attacker picks them freely:
/// each one must be range-checked, or a field wraparound could mint value.
fn raw_public_values_are_rejected(t_in: Fp, t_out: Fp, fee: Fp, v_out0: Fp) {
	let w = c2_shield();
	let circuit = C2Circuit::with_raw_amounts(
		&w,
		[Fp::ZERO, Fp::ZERO],
		[v_out0, Fp::ZERO],
		t_in,
		t_out,
		fee,
	);
	let mut rows = rows_of(&w);
	rows[rows::CV_OUT[0]] = arxon_zk_primitives::poseidon::sponge_hash::<
		arxon_zk_primitives::poseidon::ArxonDomain<{ arxon_zk_primitives::constants::tags::CV }, 2>,
	>(&[v_out0, w.r_out[0]]);
	rows[rows::TRANSPARENT_IN] = t_in;
	rows[rows::TRANSPARENT_OUT] = t_out;
	rows[rows::FEE] = fee;

	let failures =
		assert_unsatisfied(&MockProver::run(C2Circuit::K, &circuit, vec![rows]).unwrap());

	assert_has_lookup_failure(&failures);
}

#[test]
fn c2_transparent_in_of_2_pow_64_fails_range_lookup() {
	let two_pow_64 = Fp::from(u64::MAX) + Fp::ONE;
	raw_public_values_are_rejected(
		two_pow_64 + Fp::from(42),
		Fp::ZERO,
		Fp::ZERO,
		two_pow_64 + Fp::from(42),
	);
}

#[test]
fn c2_negative_transparent_out_fails_range_lookup() {
	// 42 in = 43 out + (-1): balances in the field, mints one unit.
	raw_public_values_are_rejected(Fp::from(42), -Fp::ONE, Fp::ZERO, Fp::from(43));
}

#[test]
fn c2_negative_fee_fails_range_lookup() {
	raw_public_values_are_rejected(Fp::from(42), Fp::ZERO, -Fp::ONE, Fp::from(43));
}
