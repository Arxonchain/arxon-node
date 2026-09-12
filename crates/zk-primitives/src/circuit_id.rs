//! Identifiers of the six Arxon circuits.

use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::constants::MAX_INSTANCES;

/// The six circuits of the Arxon selective privacy design, numbered as in the
/// engineer briefing. The discriminant is the wire value (SCALE and EVM `uint8`).
#[derive(
	Clone,
	Copy,
	Debug,
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
#[repr(u8)]
pub enum CircuitId {
	/// Circuit 1: the four-bit mask is valid and matches what the output note commits or reveals.
	#[codec(index = 1)]
	PrivacyFlagEnforcement = 1,
	/// Circuit 2: shielded pool conservation with 64-bit range proofs.
	#[codec(index = 2)]
	BalanceIntegrity = 2,
	/// Circuit 3: nullifier formation and Merkle inclusion of the spent note.
	#[codec(index = 3)]
	NullifierDerivation = 3,
	/// Circuit 4: private transaction receipt identifier.
	#[codec(index = 4)]
	PtrGeneration = 4,
	/// Circuit 5: selective disclosure of a receipt to a bound audience.
	#[codec(index = 5)]
	DisclosureProof = 5,
	/// Circuit 6: membership of a regulated counterparty in the trust registry tree.
	#[codec(index = 6)]
	TrustRegistryMembership = 6,
}

impl CircuitId {
	/// Every circuit, in wire order.
	pub const ALL: [CircuitId; 6] = [
		CircuitId::PrivacyFlagEnforcement,
		CircuitId::BalanceIntegrity,
		CircuitId::NullifierDerivation,
		CircuitId::PtrGeneration,
		CircuitId::DisclosureProof,
		CircuitId::TrustRegistryMembership,
	];

	/// Wire value.
	pub const fn as_u8(self) -> u8 {
		self as u8
	}

	/// Zero-based position, for fixed-size tables indexed by circuit.
	pub const fn index(self) -> usize {
		(self as u8 - 1) as usize
	}

	/// Number of public input rows per instance (frozen contract v2).
	pub const fn public_input_len(self) -> usize {
		match self {
			CircuitId::PrivacyFlagEnforcement => 8,
			CircuitId::BalanceIntegrity => 10,
			CircuitId::NullifierDerivation => 8,
			CircuitId::PtrGeneration => 5,
			CircuitId::DisclosureProof => 8,
			CircuitId::TrustRegistryMembership => 5,
		}
	}

	/// Maximum number of instances folded into one proof of this circuit.
	pub const fn max_instances(self) -> u32 {
		match self {
			CircuitId::PrivacyFlagEnforcement | CircuitId::NullifierDerivation => MAX_INSTANCES,
			_ => 1,
		}
	}
}

impl TryFrom<u8> for CircuitId {
	type Error = ();

	fn try_from(value: u8) -> Result<Self, ()> {
		match value {
			1 => Ok(CircuitId::PrivacyFlagEnforcement),
			2 => Ok(CircuitId::BalanceIntegrity),
			3 => Ok(CircuitId::NullifierDerivation),
			4 => Ok(CircuitId::PtrGeneration),
			5 => Ok(CircuitId::DisclosureProof),
			6 => Ok(CircuitId::TrustRegistryMembership),
			_ => Err(()),
		}
	}
}

impl From<CircuitId> for u8 {
	fn from(id: CircuitId) -> u8 {
		id.as_u8()
	}
}
