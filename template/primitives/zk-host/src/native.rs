//! Native implementation.

use std::panic::{catch_unwind, AssertUnwindSafe};

use arxon_zk_primitives::{
	vk_hash, CircuitId, FieldBytes, MAX_INSTANCES, MAX_PROOF_BYTES, MAX_PUBLIC_INPUTS,
};
use scale_codec::Decode;

/// Why a verification returned `false` (logged, never surfaced to the runtime).
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
	/// Wire id outside 1..=6.
	UnknownCircuit(u8),
	/// The runtime's pinned hash differs from this node's frozen hash.
	VkHashMismatch,
	/// Longer than `MAX_PROOF_BYTES`.
	ProofTooLarge(usize),
	/// Public inputs are not `Vec<Vec<[u8; 32]>>` within bounds.
	MalformedPublicInputs,
	/// `arxon_zk` rejected the proof.
	Invalid(arxon_zk::VerifyError),
}

/// Runs the verification, turning any panic into `false`.
pub fn verify_guarded(
	circuit_id: u8,
	vk_hash: &[u8; 32],
	proof: &[u8],
	public_inputs: &[u8],
) -> bool {
	guarded(|| match verify(circuit_id, vk_hash, proof, public_inputs) {
		Ok(()) => true,
		Err(rejection) => {
			log::debug!(target: "arxon-zk-host", "proof rejected: {rejection:?}");
			false
		}
	})
}

/// `f()` or `false` if it panics.
pub fn guarded(f: impl FnOnce() -> bool) -> bool {
	catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
		log::error!(target: "arxon-zk-host", "verifier panicked; rejecting proof");
		false
	})
}

/// Cheap checks first, then the IPA verifier.
pub fn verify(
	circuit_id: u8,
	provided_vk_hash: &[u8; 32],
	proof: &[u8],
	public_inputs: &[u8],
) -> Result<(), Rejection> {
	let id = CircuitId::try_from(circuit_id).map_err(|_| Rejection::UnknownCircuit(circuit_id))?;
	if *provided_vk_hash != vk_hash(id) {
		return Err(Rejection::VkHashMismatch);
	}
	if proof.len() > MAX_PROOF_BYTES as usize {
		return Err(Rejection::ProofTooLarge(proof.len()));
	}
	let instances = decode_public_inputs(id, public_inputs)?;
	arxon_zk::verify_by_id(id, proof, &instances).map_err(Rejection::Invalid)
}

fn decode_public_inputs(id: CircuitId, bytes: &[u8]) -> Result<Vec<Vec<FieldBytes>>, Rejection> {
	let mut input = bytes;
	let instances =
		Vec::<Vec<FieldBytes>>::decode(&mut input).map_err(|_| Rejection::MalformedPublicInputs)?;
	if !input.is_empty() {
		return Err(Rejection::MalformedPublicInputs);
	}
	let bounded = instances.len() <= MAX_INSTANCES as usize
		&& instances.len() <= id.max_instances() as usize
		&& instances
			.iter()
			.all(|rows| rows.len() <= MAX_PUBLIC_INPUTS as usize);
	if !bounded {
		return Err(Rejection::MalformedPublicInputs);
	}
	Ok(instances)
}
