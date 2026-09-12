//! Frozen public input layouts (contract v2).
//!
//! One struct per circuit. `to_elements` yields the instance column rows in the
//! order the circuit constrains them; `from_elements` is the inverse and rejects
//! wrong lengths. The runtime builds these itself from extrinsic arguments; it
//! never accepts a caller-supplied instance vector on a state-changing path.

use alloc::vec::Vec;

use crate::{
	circuit_id::CircuitId,
	constants::{C2_INPUTS, C2_OUTPUTS, CHAIN_ID},
	field_bytes::FieldBytes,
	mask::{hides_amount, hides_receiver, hides_sender},
};

/// Common shape of every public input layout.
pub trait PublicInputLayout: Sized {
	/// Circuit this layout belongs to.
	const CIRCUIT: CircuitId;
	/// Number of rows per instance.
	const LEN: usize;

	/// Rows in constraint order.
	fn to_elements(&self) -> Vec<FieldBytes>;

	/// Inverse of [`Self::to_elements`]; `None` on wrong length.
	fn from_elements(rows: &[FieldBytes]) -> Option<Self>;
}

/// The chain id row shared by every circuit.
pub const fn chain_id_row() -> FieldBytes {
	FieldBytes::from_u64(CHAIN_ID)
}

/// Fields a Circuit 1 or Circuit 5 instance reveals. A hidden field is `FieldBytes::ZERO`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevealedFields {
	/// Sender shielded public key, or zero when hidden.
	pub sender: FieldBytes,
	/// Receiver shielded public key, or zero when hidden.
	pub receiver: FieldBytes,
	/// Amount in shielded units, or zero when hidden.
	pub amount: FieldBytes,
}

impl RevealedFields {
	/// Zeroes every field the mask hides, so a caller cannot smuggle a value into a hidden slot.
	pub fn masked(self, mask_bits: u8) -> Self {
		RevealedFields {
			sender: if hides_sender(mask_bits) {
				FieldBytes::ZERO
			} else {
				self.sender
			},
			receiver: if hides_receiver(mask_bits) {
				FieldBytes::ZERO
			} else {
				self.receiver
			},
			amount: if hides_amount(mask_bits) {
				FieldBytes::ZERO
			} else {
				self.amount
			},
		}
	}
}

/// Circuit 1, one instance per output note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C1PublicInputs {
	/// Value commitment `H_CV(amount, blinding)`.
	pub cv: FieldBytes,
	/// Note commitment `H_NOTE(pk_r, amount, rho)`.
	pub cm: FieldBytes,
	/// Four-flag mask as a field element.
	pub mask: FieldBytes,
	/// Revealed fields (zero where hidden).
	pub revealed: RevealedFields,
	/// Bundle digest.
	pub bundle_digest: FieldBytes,
	/// Chain id (7171).
	pub chain_id: FieldBytes,
	/// Expiry block.
	pub expiry_block: FieldBytes,
}

impl C1PublicInputs {
	/// Builds the instance for `mask_bits`, zeroing revealed fields the mask hides.
	pub fn new(
		cv: FieldBytes,
		cm: FieldBytes,
		mask_bits: u8,
		revealed: RevealedFields,
		bundle_digest: FieldBytes,
		expiry_block: u32,
	) -> Self {
		C1PublicInputs {
			cv,
			cm,
			mask: FieldBytes::from_u8(mask_bits),
			revealed: revealed.masked(mask_bits),
			bundle_digest,
			chain_id: chain_id_row(),
			expiry_block: FieldBytes::from_u32(expiry_block),
		}
	}
}

impl PublicInputLayout for C1PublicInputs {
	const CIRCUIT: CircuitId = CircuitId::PrivacyFlagEnforcement;
	const LEN: usize = 9;

	fn to_elements(&self) -> Vec<FieldBytes> {
		alloc::vec![
			self.cv,
			self.cm,
			self.mask,
			self.revealed.sender,
			self.revealed.receiver,
			self.revealed.amount,
			self.bundle_digest,
			self.chain_id,
			self.expiry_block,
		]
	}

	fn from_elements(r: &[FieldBytes]) -> Option<Self> {
		if r.len() != Self::LEN {
			return None;
		}
		Some(C1PublicInputs {
			cv: r[0],
			cm: r[1],
			mask: r[2],
			revealed: RevealedFields {
				sender: r[3],
				receiver: r[4],
				amount: r[5],
			},
			bundle_digest: r[6],
			chain_id: r[7],
			expiry_block: r[8],
		})
	}
}

/// Circuit 2, single instance per bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C2PublicInputs {
	/// Input value commitments (unused slots hold `CV_DUMMY`).
	pub cv_inputs: [FieldBytes; C2_INPUTS],
	/// Output value commitments (unused slots hold `CV_DUMMY`).
	pub cv_outputs: [FieldBytes; C2_OUTPUTS],
	/// Transparent value entering the pool, shielded units.
	pub transparent_in: FieldBytes,
	/// Transparent value leaving the pool, shielded units.
	pub transparent_out: FieldBytes,
	/// In-circuit fee (0 in v1).
	pub fee: FieldBytes,
	/// Bundle digest.
	pub bundle_digest: FieldBytes,
	/// Chain id (7171).
	pub chain_id: FieldBytes,
	/// Expiry block.
	pub expiry_block: FieldBytes,
}

impl C2PublicInputs {
	/// Builds the instance from integer amounts.
	pub fn new(
		cv_inputs: [FieldBytes; C2_INPUTS],
		cv_outputs: [FieldBytes; C2_OUTPUTS],
		transparent_in: u64,
		transparent_out: u64,
		fee: u64,
		bundle_digest: FieldBytes,
		expiry_block: u32,
	) -> Self {
		C2PublicInputs {
			cv_inputs,
			cv_outputs,
			transparent_in: FieldBytes::from_u64(transparent_in),
			transparent_out: FieldBytes::from_u64(transparent_out),
			fee: FieldBytes::from_u64(fee),
			bundle_digest,
			chain_id: chain_id_row(),
			expiry_block: FieldBytes::from_u32(expiry_block),
		}
	}
}

impl PublicInputLayout for C2PublicInputs {
	const CIRCUIT: CircuitId = CircuitId::BalanceIntegrity;
	const LEN: usize = 10;

	fn to_elements(&self) -> Vec<FieldBytes> {
		alloc::vec![
			self.cv_inputs[0],
			self.cv_inputs[1],
			self.cv_outputs[0],
			self.cv_outputs[1],
			self.transparent_in,
			self.transparent_out,
			self.fee,
			self.bundle_digest,
			self.chain_id,
			self.expiry_block,
		]
	}

	fn from_elements(r: &[FieldBytes]) -> Option<Self> {
		if r.len() != Self::LEN {
			return None;
		}
		Some(C2PublicInputs {
			cv_inputs: [r[0], r[1]],
			cv_outputs: [r[2], r[3]],
			transparent_in: r[4],
			transparent_out: r[5],
			fee: r[6],
			bundle_digest: r[7],
			chain_id: r[8],
			expiry_block: r[9],
		})
	}
}

/// Circuit 3, one instance per spent note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C3PublicInputs {
	/// Recent note tree root the inclusion path opens to.
	pub anchor: FieldBytes,
	/// `H_NF(nk, cm)` of the spent note.
	pub nullifier: FieldBytes,
	/// Fresh value commitment of the spent amount, consumed by Circuit 2.
	pub cv: FieldBytes,
	/// Bundle digest.
	pub bundle_digest: FieldBytes,
	/// Chain id (7171).
	pub chain_id: FieldBytes,
	/// Expiry block.
	pub expiry_block: FieldBytes,
}

impl C3PublicInputs {
	/// Builds the instance.
	pub fn new(
		anchor: FieldBytes,
		nullifier: FieldBytes,
		cv: FieldBytes,
		bundle_digest: FieldBytes,
		expiry_block: u32,
	) -> Self {
		C3PublicInputs {
			anchor,
			nullifier,
			cv,
			bundle_digest,
			chain_id: chain_id_row(),
			expiry_block: FieldBytes::from_u32(expiry_block),
		}
	}
}

impl PublicInputLayout for C3PublicInputs {
	const CIRCUIT: CircuitId = CircuitId::NullifierDerivation;
	const LEN: usize = 6;

	fn to_elements(&self) -> Vec<FieldBytes> {
		alloc::vec![
			self.anchor,
			self.nullifier,
			self.cv,
			self.bundle_digest,
			self.chain_id,
			self.expiry_block
		]
	}

	fn from_elements(r: &[FieldBytes]) -> Option<Self> {
		if r.len() != Self::LEN {
			return None;
		}
		Some(C3PublicInputs {
			anchor: r[0],
			nullifier: r[1],
			cv: r[2],
			bundle_digest: r[3],
			chain_id: r[4],
			expiry_block: r[5],
		})
	}
}

/// Circuit 4, single instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C4PublicInputs {
	/// `H_PTR(pk_s, pk_r, cv, nonce)`.
	pub ptr_id: FieldBytes,
	/// Value commitment of the payment output (Circuit 1 instance chosen by the extrinsic).
	pub cv: FieldBytes,
	/// Bundle digest.
	pub bundle_digest: FieldBytes,
	/// Chain id (7171).
	pub chain_id: FieldBytes,
	/// Expiry block.
	pub expiry_block: FieldBytes,
}

impl C4PublicInputs {
	/// Builds the instance.
	pub fn new(
		ptr_id: FieldBytes,
		cv: FieldBytes,
		bundle_digest: FieldBytes,
		expiry_block: u32,
	) -> Self {
		C4PublicInputs {
			ptr_id,
			cv,
			bundle_digest,
			chain_id: chain_id_row(),
			expiry_block: FieldBytes::from_u32(expiry_block),
		}
	}
}

impl PublicInputLayout for C4PublicInputs {
	const CIRCUIT: CircuitId = CircuitId::PtrGeneration;
	const LEN: usize = 5;

	fn to_elements(&self) -> Vec<FieldBytes> {
		alloc::vec![
			self.ptr_id,
			self.cv,
			self.bundle_digest,
			self.chain_id,
			self.expiry_block
		]
	}

	fn from_elements(r: &[FieldBytes]) -> Option<Self> {
		if r.len() != Self::LEN {
			return None;
		}
		Some(C4PublicInputs {
			ptr_id: r[0],
			cv: r[1],
			bundle_digest: r[2],
			chain_id: r[3],
			expiry_block: r[4],
		})
	}
}

/// Circuit 5, single instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C5PublicInputs {
	/// Receipt identifier being opened.
	pub ptr_id: FieldBytes,
	/// Disclosure mask: same four-flag packing, "hide" semantics, bit 3 must be clear.
	pub disclosure_mask: FieldBytes,
	/// Revealed fields (zero where still hidden).
	pub revealed: RevealedFields,
	/// Verifier account digest the disclosure is bound to.
	pub audience: FieldBytes,
	/// Chain id (7171).
	pub chain_id: FieldBytes,
	/// Expiry block.
	pub expiry_block: FieldBytes,
}

impl C5PublicInputs {
	/// Builds the instance, zeroing revealed fields the disclosure mask keeps hidden.
	pub fn new(
		ptr_id: FieldBytes,
		disclosure_mask: u8,
		revealed: RevealedFields,
		audience: FieldBytes,
		expiry_block: u32,
	) -> Self {
		C5PublicInputs {
			ptr_id,
			disclosure_mask: FieldBytes::from_u8(disclosure_mask),
			revealed: revealed.masked(disclosure_mask),
			audience,
			chain_id: chain_id_row(),
			expiry_block: FieldBytes::from_u32(expiry_block),
		}
	}
}

impl PublicInputLayout for C5PublicInputs {
	const CIRCUIT: CircuitId = CircuitId::DisclosureProof;
	const LEN: usize = 8;

	fn to_elements(&self) -> Vec<FieldBytes> {
		alloc::vec![
			self.ptr_id,
			self.disclosure_mask,
			self.revealed.sender,
			self.revealed.receiver,
			self.revealed.amount,
			self.audience,
			self.chain_id,
			self.expiry_block,
		]
	}

	fn from_elements(r: &[FieldBytes]) -> Option<Self> {
		if r.len() != Self::LEN {
			return None;
		}
		Some(C5PublicInputs {
			ptr_id: r[0],
			disclosure_mask: r[1],
			revealed: RevealedFields {
				sender: r[2],
				receiver: r[3],
				amount: r[4],
			},
			audience: r[5],
			chain_id: r[6],
			expiry_block: r[7],
		})
	}
}

/// Circuit 6, single instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6PublicInputs {
	/// Current membership tree root.
	pub registry_root: FieldBytes,
	/// Output note commitment paid to the member.
	pub cm: FieldBytes,
	/// Bundle digest.
	pub bundle_digest: FieldBytes,
	/// Chain id (7171).
	pub chain_id: FieldBytes,
	/// Expiry block.
	pub expiry_block: FieldBytes,
}

impl C6PublicInputs {
	/// Builds the instance.
	pub fn new(
		registry_root: FieldBytes,
		cm: FieldBytes,
		bundle_digest: FieldBytes,
		expiry_block: u32,
	) -> Self {
		C6PublicInputs {
			registry_root,
			cm,
			bundle_digest,
			chain_id: chain_id_row(),
			expiry_block: FieldBytes::from_u32(expiry_block),
		}
	}
}

impl PublicInputLayout for C6PublicInputs {
	const CIRCUIT: CircuitId = CircuitId::TrustRegistryMembership;
	const LEN: usize = 5;

	fn to_elements(&self) -> Vec<FieldBytes> {
		alloc::vec![
			self.registry_root,
			self.cm,
			self.bundle_digest,
			self.chain_id,
			self.expiry_block
		]
	}

	fn from_elements(r: &[FieldBytes]) -> Option<Self> {
		if r.len() != Self::LEN {
			return None;
		}
		Some(C6PublicInputs {
			registry_root: r[0],
			cm: r[1],
			bundle_digest: r[2],
			chain_id: r[3],
			expiry_block: r[4],
		})
	}
}
