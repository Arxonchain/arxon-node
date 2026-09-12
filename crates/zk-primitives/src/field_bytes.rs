//! Canonical byte encoding of a Pallas base field element.

use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::constants::PALLAS_BASE_MODULUS_LE;

/// A Pallas base field element as 32 little-endian bytes (`Fp::to_repr`).
///
/// The runtime never does field arithmetic; it only needs to build elements that
/// are guaranteed canonical (`< p`) and to reject non-canonical ones coming from
/// the outside. Both are byte comparisons against [`PALLAS_BASE_MODULUS_LE`].
#[derive(
	Clone,
	Copy,
	Debug,
	Default,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Hash,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen
)]
pub struct FieldBytes(pub [u8; 32]);

impl FieldBytes {
	/// The zero element.
	pub const ZERO: FieldBytes = FieldBytes([0u8; 32]);

	/// Number of low bytes that are always canonical (`2^248 < p`).
	pub const SAFE_PREFIX_LEN: usize = 31;

	/// `Fp::from(v)`.
	pub const fn from_u64(v: u64) -> Self {
		let le = v.to_le_bytes();
		let mut out = [0u8; 32];
		let mut i = 0;
		while i < 8 {
			out[i] = le[i];
			i += 1;
		}
		FieldBytes(out)
	}

	/// `Fp::from(v as u64)`.
	pub const fn from_u8(v: u8) -> Self {
		Self::from_u64(v as u64)
	}

	/// `Fp::from(v)` for a `u32` block number.
	pub const fn from_u32(v: u32) -> Self {
		Self::from_u64(v as u64)
	}

	/// Embeds a 32-byte digest by keeping its first 31 bytes and zeroing the top byte.
	/// The result is always canonical.
	pub const fn from_digest(digest: [u8; 32]) -> Self {
		let mut out = [0u8; 32];
		let mut i = 0;
		while i < Self::SAFE_PREFIX_LEN {
			out[i] = digest[i];
			i += 1;
		}
		FieldBytes(out)
	}

	/// Embeds up to 31 arbitrary bytes (an `AccountId20`, for instance) as the
	/// low bytes of a canonical element. Returns `None` if `bytes` is longer than 31.
	pub fn from_short_bytes(bytes: &[u8]) -> Option<Self> {
		if bytes.len() > Self::SAFE_PREFIX_LEN {
			return None;
		}
		let mut out = [0u8; 32];
		out[..bytes.len()].copy_from_slice(bytes);
		Some(FieldBytes(out))
	}

	/// `true` iff the little-endian integer is strictly below the Pallas base modulus.
	pub fn is_canonical(&self) -> bool {
		// Compare as big integers: walk from the most significant byte down.
		for i in (0..32).rev() {
			if self.0[i] < PALLAS_BASE_MODULUS_LE[i] {
				return true;
			}
			if self.0[i] > PALLAS_BASE_MODULUS_LE[i] {
				return false;
			}
		}
		// Equal to the modulus: not canonical.
		false
	}

	/// Borrow the raw bytes.
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<[u8; 32]> for FieldBytes {
	fn from(bytes: [u8; 32]) -> Self {
		FieldBytes(bytes)
	}
}

impl From<FieldBytes> for [u8; 32] {
	fn from(f: FieldBytes) -> Self {
		f.0
	}
}

impl AsRef<[u8]> for FieldBytes {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}
