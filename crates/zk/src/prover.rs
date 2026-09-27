//! Multi-instance proof creation.

use arxon_zk_primitives::MAX_PROOF_BYTES;
use halo2_proofs::{
	plonk::create_proof,
	transcript::{Blake2bWrite, Challenge255},
};
use rand_core::RngCore;

use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::ProveError,
	field::{Curve, Fp},
	key_cache::proving_key,
	params::params,
};

/// Rows of every instance, as the verifier will see them.
pub fn public_rows<C: ArxonCircuit>(witnesses: &[C::Witness]) -> Vec<Vec<Fp>> {
	witnesses
		.iter()
		.map(|w| C::public_from_witness(w).to_rows())
		.collect()
}

/// Proves one instance of `C` per witness, all folded into a single proof.
///
/// Returns the serialized proof. Its length is deterministic for a given
/// circuit and instance count (see [`crate::pins`]).
pub fn prove<C: ArxonCircuit + 'static>(
	witnesses: &[C::Witness],
	rng: impl RngCore,
) -> Result<Vec<u8>, ProveError> {
	let n = witnesses.len();
	if n == 0 {
		return Err(ProveError::NoInstances);
	}
	let max = C::max_instances();
	if n > max as usize {
		return Err(ProveError::TooManyInstances { max, got: n });
	}

	let circuits: Vec<C> = witnesses.iter().map(C::from_witness).collect();
	let rows = public_rows::<C>(witnesses);
	// halo2 wants, per circuit, a slice of instance columns, each a slice of rows.
	let columns: Vec<[&[Fp]; 1]> = rows.iter().map(|r| [r.as_slice()]).collect();
	let instances: Vec<&[&[Fp]]> = columns.iter().map(|c| c.as_slice()).collect();

	let pk = proving_key::<C>();
	let mut transcript = Blake2bWrite::<Vec<u8>, Curve, Challenge255<Curve>>::init(Vec::new());
	create_proof(
		params(C::K),
		&*pk,
		&circuits,
		&instances,
		rng,
		&mut transcript,
	)?;
	let proof = transcript.finalize();

	if proof.len() > MAX_PROOF_BYTES as usize {
		return Err(ProveError::ProofTooLarge {
			len: proof.len(),
			max: MAX_PROOF_BYTES,
		});
	}
	Ok(proof)
}
