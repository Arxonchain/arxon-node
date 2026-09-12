//! Weights. Placeholders until `benchmark pallet` runs through the node (plan Phase G1);
//! `frame-omni-bencher` cannot be used because verification needs the custom host function.

use arxon_zk_primitives::CircuitId;
use frame_support::weights::Weight;

/// Weight functions of the pallet.
pub trait WeightInfo {
	/// `set_circuit_enabled` extrinsic.
	fn set_circuit_enabled() -> Weight;
	/// Verifying one proof of `circuit_id` carrying `instances` instances.
	fn verify_proof(circuit_id: CircuitId, instances: u32) -> Weight;
}

/// Placeholder: 20 ms of ref time per instance, which caps a 4000 ms block at
/// roughly 200 single-instance verifications until measured weights land.
impl WeightInfo for () {
	fn set_circuit_enabled() -> Weight {
		Weight::from_parts(10_000_000, 1_000)
	}

	fn verify_proof(_circuit_id: CircuitId, instances: u32) -> Weight {
		Weight::from_parts(20_000_000_000, 4_000).saturating_mul(instances.max(1) as u64)
	}
}
