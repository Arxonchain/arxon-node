//! Frozen verifying key hashes.
//!
//! `arxon-zk` asserts that `blake2_256(format!("{:?}", vk.pinned()))` of every
//! circuit equals the entry below. A change here is a deliberate, reviewed
//! re-pin after a circuit change (constraint-count regression check).
//! The runtime stores these at genesis and the host function refuses to verify
//! against anything else.

use crate::circuit_id::CircuitId;

/// Placeholder until the circuits exist: all zero. Replaced when each circuit is pinned.
pub const VK_HASHES: [[u8; 32]; 6] = [[0u8; 32]; 6];

/// Frozen verifying key hash of `id`.
pub const fn vk_hash(id: CircuitId) -> [u8; 32] {
	VK_HASHES[id.index()]
}
