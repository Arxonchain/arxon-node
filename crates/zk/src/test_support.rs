//! Shared test helpers: deterministic randomness, MockProver assertions, byte tampering.
#![allow(dead_code)] // helpers are consumed progressively as circuits land

use ff::Field;
use halo2_proofs::dev::{MockProver, VerifyFailure};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use crate::{
	circuit::{ArxonCircuit, PublicRows},
	field::Fp,
};

/// A seeded RNG so proofs in tests are reproducible.
pub fn deterministic_rng(seed: u64) -> ChaCha20Rng {
	ChaCha20Rng::seed_from_u64(seed)
}

/// Runs the MockProver on one instance of `C`.
pub fn mock<C: ArxonCircuit>(witness: &C::Witness, rows: Vec<Fp>) -> MockProver<Fp> {
	MockProver::run(C::K, &C::from_witness(witness), vec![rows]).expect("synthesis must succeed")
}

/// Runs the MockProver on `witness` with the public rows the prover would derive.
pub fn mock_honest<C: ArxonCircuit>(witness: &C::Witness) -> MockProver<Fp> {
	mock::<C>(witness, C::public_from_witness(witness).to_rows())
}

/// Asserts the mock prover accepts.
pub fn assert_satisfied(prover: &MockProver<Fp>) {
	if let Err(failures) = prover.verify() {
		panic!(
			"expected a satisfied circuit, got {} failure(s): {failures:#?}",
			failures.len()
		);
	}
}

/// Asserts the mock prover rejects, returning the failures for finer checks.
pub fn assert_unsatisfied(prover: &MockProver<Fp>) -> Vec<VerifyFailure> {
	prover
		.verify()
		.expect_err("expected an unsatisfied circuit")
}

/// Asserts at least one failure is a permutation (copy constraint) failure.
pub fn assert_has_permutation_failure(failures: &[VerifyFailure]) {
	assert!(
		failures
			.iter()
			.any(|f| matches!(f, VerifyFailure::Permutation { .. })),
		"expected a permutation failure, got {failures:#?}"
	);
}

/// Asserts at least one failure is an unsatisfied gate whose name contains `gate`.
pub fn assert_has_gate_failure(failures: &[VerifyFailure], gate: &str) {
	assert!(
		failures.iter().any(|f| matches!(f, VerifyFailure::ConstraintNotSatisfied { constraint, .. } if format!("{constraint:?}").contains(gate))),
		"expected gate '{gate}' to fail, got {failures:#?}"
	);
}

/// Asserts at least one failure is a lookup failure.
pub fn assert_has_lookup_failure(failures: &[VerifyFailure]) {
	assert!(
		failures
			.iter()
			.any(|f| matches!(f, VerifyFailure::Lookup { .. })),
		"expected a lookup failure, got {failures:#?}"
	);
}

/// Returns `proof` with the byte at `index` flipped.
pub fn with_flipped_byte(proof: &[u8], index: usize) -> Vec<u8> {
	let mut out = proof.to_vec();
	out[index] ^= 0x01;
	out
}

/// Asserts that perturbing any single public row makes the MockProver reject
/// with a permutation failure: every row is copy-constrained to an advice cell,
/// none is a free instance cell. (It cannot see whether the row is bound to the
/// *right* cell; per-circuit semantic negative tests cover that.)
pub fn assert_every_public_row_is_bound<C: ArxonCircuit>(witness: &C::Witness) {
	let honest = C::public_from_witness(witness).to_rows();
	assert_eq!(
		honest.len(),
		C::Public::LEN,
		"row count must match the layout"
	);
	for row in 0..honest.len() {
		let mut tampered = honest.clone();
		tampered[row] += Fp::ONE;
		let prover = mock::<C>(witness, tampered);
		let failures = match prover.verify() {
			Ok(()) => panic!(
				"public row {row} of {} is not bound by any constraint",
				C::NAME
			),
			Err(failures) => failures,
		};
		assert!(
			failures.iter().any(|f| matches!(f, VerifyFailure::Permutation { .. })),
			"public row {row} of {} failed for a reason other than its copy constraint: {failures:#?}",
			C::NAME
		);
	}
}

/// Asserts the static metadata of `C` agrees with the shared contract: row
/// count equals the wire layout, one pinned proof length per instance count.
pub fn assert_circuit_metadata_consistent<C: ArxonCircuit>() {
	if let Some(id) = C::ID {
		assert_eq!(
			C::Public::LEN,
			id.public_input_len(),
			"{}: LEN differs from CircuitId::public_input_len",
			C::NAME
		);
		assert_eq!(
			C::max_instances(),
			id.max_instances(),
			"{}: max_instances differs from CircuitId",
			C::NAME
		);
	}
	assert_eq!(
		C::PROOF_LENGTHS.len(),
		C::max_instances() as usize,
		"{}: one pinned proof length per instance count",
		C::NAME
	);
	assert!(
		C::PROOF_LENGTHS.iter().all(|l| *l > 0),
		"{}: every proof length must be pinned",
		C::NAME
	);
}
