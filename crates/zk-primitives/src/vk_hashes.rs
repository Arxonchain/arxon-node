//! Frozen verifying key hashes.
//!
//! `arxon-zk` asserts that `blake2_256(format!("{:?}", vk.pinned()))` of every
//! wired circuit equals the entry below. A change here is a deliberate,
//! reviewed re-pin after a circuit change (constraint-count regression check).
//! The runtime stores these at genesis and the host function refuses to verify
//! against anything else.

use crate::circuit_id::CircuitId;

/// Frozen verifying key hash per circuit, indexed by `CircuitId::index()`.
pub const VK_HASHES: [[u8; 32]; 6] = [
	// 1 PrivacyFlagEnforcement
	hex_literal("9546beb0398d78f120977d51bc2fa85d91583e4c5df407b95050c408530d5dc3"),
	// 2 BalanceIntegrity
	hex_literal("ef1f8c9c8f31eebba74ea7f2126a818ea0938cb04c88ce23b2b06127ddb3504c"),
	// 3 NullifierDerivation
	hex_literal("aa29c3035a33e25f644249be23cb76cbafb6da94e550e85fdd417b78e6a182a4"),
	// 4 PtrGeneration
	hex_literal("1cb2ba13232989084598bd6460756b092e297f96e03bd32f85f65f233eb9ac23"),
	// 5 DisclosureProof
	hex_literal("68fe69f4ad847c48452dd4e3ed31f135c7326192c9898d15557e8d20b60c4a50"),
	// 6 TrustRegistryMembership
	hex_literal("44dd00715d7f6e3026fac700d85f7146af19ee5ff3f0c91fd8ff44ed63ca96ce"),
];

/// Frozen verifying key hash of `id`.
pub const fn vk_hash(id: CircuitId) -> [u8; 32] {
	VK_HASHES[id.index()]
}

/// `true` iff `id` has a pinned (non-zero) verifying key hash.
pub const fn has_vk_hash(id: CircuitId) -> bool {
	let h = vk_hash(id);
	let mut i = 0;
	while i < 32 {
		if h[i] != 0 {
			return true;
		}
		i += 1;
	}
	false
}

/// Parses 64 hex characters into 32 bytes at compile time.
const fn hex_literal(s: &str) -> [u8; 32] {
	let bytes = s.as_bytes();
	assert!(bytes.len() == 64, "vk hash literal must be 64 hex chars");
	let mut out = [0u8; 32];
	let mut i = 0;
	while i < 32 {
		out[i] = (hex_nibble(bytes[2 * i]) << 4) | hex_nibble(bytes[2 * i + 1]);
		i += 1;
	}
	out
}

const fn hex_nibble(c: u8) -> u8 {
	match c {
		b'0'..=b'9' => c - b'0',
		b'a'..=b'f' => c - b'a' + 10,
		b'A'..=b'F' => c - b'A' + 10,
		_ => panic!("invalid hex digit in vk hash literal"),
	}
}
