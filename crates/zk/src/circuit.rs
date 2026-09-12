//! The trait every Arxon circuit implements.

use arxon_zk_primitives::CircuitId;
use halo2_proofs::plonk::Circuit;

use crate::field::Fp;

/// Public input rows of one instance, as field elements in constraint order.
pub trait PublicRows {
	/// Number of rows.
	const LEN: usize;

	/// Rows in constraint order.
	fn to_rows(&self) -> Vec<Fp>;
}

/// An Arxon circuit: a halo2 [`Circuit`] plus the metadata the prover,
/// verifier and pin tests need.
///
/// `Default` must produce the witness-less circuit used for key generation
/// (every private value `Value::unknown()`).
pub trait ArxonCircuit: Circuit<Fp> + Default + Clone + std::fmt::Debug {
	/// Wire id, or `None` for harness circuits that never reach the chain.
	const ID: Option<CircuitId>;
	/// `log2` of the number of rows.
	const K: u32;
	/// Human name used in pins and diagnostics.
	const NAME: &'static str;
	/// Exact serialized proof length for 1, 2, ... `max_instances()` instances,
	/// measured from real proofs and pinned. The verifier rejects any other
	/// length before reading the transcript (halo2 ignores trailing bytes).
	/// `CircuitCost` is not exact (it counts instance evaluations the zcash
	/// verifier computes locally), so these are measured, not estimated.
	const PROOF_LENGTHS: &'static [usize];
	/// Everything the prover knows.
	type Witness: Clone;
	/// Public rows derived from a witness.
	type Public: PublicRows;

	/// Maximum number of instances folded into one proof.
	fn max_instances() -> u32 {
		Self::ID.map(CircuitId::max_instances).unwrap_or(1)
	}

	/// Builds the circuit with every private value known.
	fn from_witness(witness: &Self::Witness) -> Self;

	/// Derives the public rows the prover commits to for `witness`.
	fn public_from_witness(witness: &Self::Witness) -> Self::Public;
}
