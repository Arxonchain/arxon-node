//! Regression pins: verifying key hash and proof sizes per circuit.
//!
//! * The VK hash is `blake2_256` of the `Debug` rendering of
//!   `VerifyingKey::pinned()`, which covers the whole constraint system, fixed
//!   columns and permutation. Any circuit change moves it. The frozen values
//!   live in `arxon_zk_primitives::VK_HASHES`; a test asserts they match.
//! * Proof lengths are measured from real proofs and pinned on each circuit
//!   (`ArxonCircuit::PROOF_LENGTHS`); the verifier enforces them exactly.
//!   `CircuitCost` is kept as a diagnostic (rows, columns, queries) because
//!   its size estimate is off by the instance evaluations.

use halo2_proofs::dev::CircuitCost;
use sp_crypto_hashing::blake2_256;

use crate::{circuit::ArxonCircuit, key_cache::keys};

/// Everything pinned for one circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitPins {
	/// `ArxonCircuit::NAME`.
	pub name: &'static str,
	/// `ArxonCircuit::K`.
	pub k: u32,
	/// Verifying key hash.
	pub vk_hash: [u8; 32],
	/// Pinned proof lengths per instance count.
	pub proof_lengths: &'static [usize],
	/// `Debug` rendering of `CircuitCost` (rows used, columns, queries, lookups).
	pub cost: String,
}

/// Hash of the verifying key of `C`.
pub fn vk_hash<C: ArxonCircuit + 'static>() -> [u8; 32] {
	let keys = keys::<C>();
	blake2_256(format!("{:?}", keys.vk.pinned()).as_bytes())
}

/// halo2's structural cost report for `C` (diagnostic; not used for verification).
pub fn cost<C: ArxonCircuit>() -> CircuitCost<pasta_curves::vesta::Point, C> {
	CircuitCost::measure(C::K, &C::default())
}

/// Exact serialized length of a proof of `C` with `instances` instances.
///
/// Fails closed: an instance count without a pinned length yields `usize::MAX`,
/// so no real proof can ever match it.
pub fn expected_proof_len<C: ArxonCircuit>(instances: usize) -> usize {
	instances
		.checked_sub(1)
		.and_then(|i| C::PROOF_LENGTHS.get(i))
		.copied()
		.unwrap_or(usize::MAX)
}

/// Measures every pin of `C`.
pub fn measure<C: ArxonCircuit + 'static>() -> CircuitPins {
	CircuitPins {
		name: C::NAME,
		k: C::K,
		vk_hash: vk_hash::<C>(),
		proof_lengths: C::PROOF_LENGTHS,
		cost: format!("{:?}", cost::<C>()),
	}
}
