//! Proof verification.
//!
//! Order of checks, cheapest first and all before the transcript is touched:
//! circuit id, instance count, row count per instance, canonical field bytes,
//! exact proof length (halo2's transcript ignores trailing bytes, so a length
//! pin is what makes proofs non-malleable at the byte level), then the IPA
//! verification itself.

use arxon_zk_primitives::{CircuitId, FieldBytes, MAX_PROOF_BYTES};
use halo2_proofs::{
	plonk::{verify_proof, SingleVerifier},
	transcript::{Blake2bRead, Challenge255},
};

use crate::{
	circuit::{ArxonCircuit, PublicRows},
	error::VerifyError,
	field::{rows_from_bytes, Curve, Fp},
	key_cache::verifier_key,
	params::params,
	pins::expected_proof_len,
};

/// Verifies `proof` against `instances` (one row vector per instance).
pub fn verify<C: ArxonCircuit + 'static>(
	proof: &[u8],
	instances: &[Vec<Fp>],
) -> Result<(), VerifyError> {
	check_instance_shape::<C>(instances.len(), instances.iter().map(Vec::len))?;
	check_proof_len::<C>(proof.len(), instances.len())?;

	let columns: Vec<[&[Fp]; 1]> = instances.iter().map(|r| [r.as_slice()]).collect();
	let halo2_instances: Vec<&[&[Fp]]> = columns.iter().map(|c| c.as_slice()).collect();

	let params = params(C::K);
	let key = verifier_key::<C>();
	if !key.matches_pin {
		return Err(VerifyError::KeyMismatch);
	}
	let mut transcript = Blake2bRead::<&[u8], Curve, Challenge255<Curve>>::init(proof);
	verify_proof(
		params,
		&key.vk,
		SingleVerifier::new(params),
		&halo2_instances,
		&mut transcript,
	)
	.map_err(|_| VerifyError::InvalidProof)
}

/// Verifies a proof for the circuit identified by `id`, with byte-encoded public inputs.
/// This is the entry point of the `verify_halo2_ipa` host function.
pub fn verify_by_id(
	id: CircuitId,
	proof: &[u8],
	instances: &[Vec<FieldBytes>],
) -> Result<(), VerifyError> {
	if proof.len() > MAX_PROOF_BYTES as usize {
		return Err(VerifyError::WrongProofLength {
			expected: MAX_PROOF_BYTES as usize,
			got: proof.len(),
		});
	}
	crate::circuits::dispatch_chain_circuit!(id, |C| verify_bytes::<C>(proof, instances))
}

/// Like [`verify_by_id`] but from a wire byte.
pub fn verify_by_wire_id(
	id: u8,
	proof: &[u8],
	instances: &[Vec<FieldBytes>],
) -> Result<(), VerifyError> {
	let id = CircuitId::try_from(id).map_err(|_| VerifyError::UnknownCircuit(id))?;
	verify_by_id(id, proof, instances)
}

fn verify_bytes<C: ArxonCircuit + 'static>(
	proof: &[u8],
	instances: &[Vec<FieldBytes>],
) -> Result<(), VerifyError> {
	check_instance_shape::<C>(instances.len(), instances.iter().map(Vec::len))?;
	let decoded = instances
		.iter()
		.enumerate()
		.map(|(i, rows)| rows_from_bytes(i, rows))
		.collect::<Result<Vec<_>, _>>()?;
	verify::<C>(proof, &decoded)
}

fn check_instance_shape<C: ArxonCircuit>(
	count: usize,
	row_counts: impl Iterator<Item = usize>,
) -> Result<(), VerifyError> {
	if count == 0 {
		return Err(VerifyError::NoInstances);
	}
	let max = C::max_instances();
	if count > max as usize {
		return Err(VerifyError::TooManyInstances { max, got: count });
	}
	for (instance, got) in row_counts.enumerate() {
		if got != C::Public::LEN {
			return Err(VerifyError::WrongRowCount {
				instance,
				expected: C::Public::LEN,
				got,
			});
		}
	}
	Ok(())
}

fn check_proof_len<C: ArxonCircuit + 'static>(
	got: usize,
	instances: usize,
) -> Result<(), VerifyError> {
	let expected = expected_proof_len::<C>(instances);
	if got != expected {
		return Err(VerifyError::WrongProofLength { expected, got });
	}
	Ok(())
}
