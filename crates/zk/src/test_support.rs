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

/// Deterministic witnesses for the chain circuits.
pub mod fixtures {
	use arxon_zk_primitives::poseidon::cv_dummy;
	use ff::Field;

	use crate::{
		circuits::{C1Witness, C2Witness, C3Witness, C4Witness, C5Witness, C6Witness},
		field::Fp,
		merkle::{MemberTree, NoteTree, TreeKind},
	};

	/// A non-trivial field element derived from `n`.
	pub fn fe(n: u64) -> Fp {
		Fp::from(n) * Fp::from(0x9e37_79b9_7f4a_7c15) + Fp::from(11)
	}

	/// Bundle digest used by every fixture.
	pub fn digest() -> Fp {
		fe(777)
	}

	/// Expiry block used by every fixture.
	pub const EXPIRY: u32 = 1_000;

	/// An output note of 42 units under `mask`.
	pub fn c1(mask: u8) -> C1Witness {
		C1Witness {
			amount: 42,
			blinding: fe(1),
			pk_r: fe(2),
			rho: fe(3),
			mask,
			bundle_digest: digest(),
			expiry_block: EXPIRY,
		}
	}

	/// The tree the C3 fixture spends from: three decoy notes and the real one at index 2.
	pub fn c3_tree() -> (NoteTree, C3Witness) {
		let sk = fe(10);
		let amount = 42;
		let rho = fe(12);
		let cm = arxon_zk_primitives::poseidon::hash_note(
			arxon_zk_primitives::poseidon::hash_pk(sk),
			amount,
			rho,
		);
		let mut tree = NoteTree::new(TreeKind::Note);
		tree.insert(fe(100));
		tree.insert(fe(101));
		let index = tree.insert(cm);
		tree.insert(fe(103));
		let witness = C3Witness {
			sk,
			amount,
			rho,
			blinding: fe(13),
			mask: 0,
			path: tree.path(index),
			bundle_digest: digest(),
			expiry_block: EXPIRY,
		};
		(tree, witness)
	}

	/// A spend of the note in [`c3_tree`] under `mask`.
	pub fn c3(mask: u8) -> C3Witness {
		let (_, mut w) = c3_tree();
		w.mask = mask;
		w
	}

	/// A balanced 2-in / 2-out transfer: 30 + 12 = 40 + 2.
	pub fn c2_transfer() -> C2Witness {
		C2Witness {
			v_in: [30, 12],
			r_in: [fe(21), fe(22)],
			v_out: [40, 2],
			r_out: [fe(23), fe(24)],
			transparent_in: 0,
			transparent_out: 0,
			fee: 0,
			bundle_digest: digest(),
			expiry_block: EXPIRY,
		}
	}

	/// A shield of 42 units into one note; unused slots are the dummy commitment.
	pub fn c2_shield() -> C2Witness {
		C2Witness {
			v_in: [0, 0],
			r_in: [Fp::ZERO, Fp::ZERO],
			v_out: [42, 0],
			r_out: [fe(1), Fp::ZERO],
			transparent_in: 42,
			transparent_out: 0,
			fee: 0,
			bundle_digest: digest(),
			expiry_block: EXPIRY,
		}
	}

	/// An unshield of 40 units from one 42-unit note with 2 units of change.
	pub fn c2_unshield() -> C2Witness {
		C2Witness {
			v_in: [42, 0],
			r_in: [fe(13), Fp::ZERO],
			v_out: [2, 0],
			r_out: [fe(31), Fp::ZERO],
			transparent_in: 0,
			transparent_out: 40,
			fee: 0,
			bundle_digest: digest(),
			expiry_block: EXPIRY,
		}
	}

	/// The dummy value commitment as a field element.
	pub fn dummy_cv() -> Fp {
		cv_dummy()
	}

	/// Spending key of the receipt sender in [`c4`] and [`c5`].
	pub fn sender_sk() -> Fp {
		fe(50)
	}

	/// A receipt for the 42-unit payment of [`c1`], in a bundle spending two of the
	/// sender's notes (30 and 12 units).
	pub fn c4() -> C4Witness {
		use arxon_zk_primitives::poseidon::{hash_cv, hash_nk, hash_pk};

		use crate::circuits::SpentNote;

		let payment = c1(0);
		C4Witness {
			pk_s: hash_pk(sender_sk()),
			nk: hash_nk(sender_sk()),
			spent: [
				SpentNote {
					amount: 30,
					rho: fe(52),
				},
				SpentNote {
					amount: 12,
					rho: fe(53),
				},
			],
			pk_r: payment.pk_r,
			amount: payment.amount,
			rho_out: payment.rho,
			cv: hash_cv(payment.amount, payment.blinding),
			nonce: fe(51),
			bundle_digest: digest(),
			expiry_block: EXPIRY,
		}
	}

	/// A disclosure of the receipt in [`c4`] under `disclosure_mask` to audience `fe(60)`.
	pub fn c5(disclosure_mask: u8) -> C5Witness {
		let payment = c1(0);
		C5Witness {
			pk_s: arxon_zk_primitives::poseidon::hash_pk(sender_sk()),
			pk_r: payment.pk_r,
			amount: payment.amount,
			blinding: payment.blinding,
			nonce: fe(51),
			disclosure_mask,
			audience: fe(60),
			expiry_block: EXPIRY,
		}
	}

	/// A registry with two decoys and the member at index 1, plus the membership witness for a note to that member.
	pub fn c6_tree() -> (MemberTree, C6Witness) {
		let pk_member = fe(70);
		let mut tree = MemberTree::new(TreeKind::Member);
		tree.insert(arxon_zk_primitives::poseidon::hash_member_leaf(fe(71)));
		let index = tree.insert(arxon_zk_primitives::poseidon::hash_member_leaf(pk_member));
		tree.insert(arxon_zk_primitives::poseidon::hash_member_leaf(fe(72)));
		let witness = C6Witness {
			pk_member,
			amount: 42,
			rho: fe(73),
			path: tree.path(index),
			bundle_digest: digest(),
			expiry_block: EXPIRY,
		};
		(tree, witness)
	}

	/// The membership witness of [`c6_tree`].
	pub fn c6() -> C6Witness {
		c6_tree().1
	}
}
