//! Transaction binding digest carried by every proof.
//!
//! The pallet recomputes this digest from the extrinsic arguments and places it
//! in the public inputs of every circuit of the bundle. A proof therefore only
//! verifies for the exact set of nullifiers, commitments, value commitments,
//! transparent amounts, recipient, mask and encrypted notes it was created for:
//! a mempool observer cannot re-target an unshield or replay a shield.
//!
//! The extrinsic signer is deliberately excluded so that any relayer may submit
//! (and pay the fee for) a bundle on behalf of the shielded sender.

use alloc::vec::Vec;

use scale_codec::Encode;
use sp_crypto_hashing::blake2_256;

use crate::{constants::BUNDLE_DOMAIN, field_bytes::FieldBytes};

/// Everything that goes into the bundle digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleFields<'a> {
	/// [`crate::constants::CHAIN_ID`] (kept explicit so the digest is self-describing).
	pub chain_id: u64,
	/// Last block at which the bundle may execute.
	pub expiry_block: u32,
	/// SCALE-encoded transparent payout account of an unshield, `None` otherwise.
	pub recipient: Option<&'a [u8]>,
	/// Transparent value entering the pool (shield), in shielded units.
	pub transparent_in: u64,
	/// Transparent value leaving the pool (unshield), in shielded units.
	pub transparent_out: u64,
	/// Nullifiers of the spent notes, in bundle order.
	pub nullifiers: &'a [FieldBytes],
	/// Commitments of the created notes, in bundle order.
	pub commitments: &'a [FieldBytes],
	/// Value commitments of the spent notes (Circuit 3 instances), in bundle order.
	pub cv_inputs: &'a [FieldBytes],
	/// Value commitments of the created notes (Circuit 1 instances), in bundle order.
	pub cv_outputs: &'a [FieldBytes],
	/// Four-flag privacy mask of the bundle.
	pub mask_bits: u8,
	/// [`encrypted_notes_hash`] of the encrypted note payloads, in bundle order.
	pub encrypted_notes_hash: [u8; 32],
}

impl BundleFields<'_> {
	/// Canonical preimage: domain prefix followed by the SCALE encoding of every field.
	pub fn preimage(&self) -> Vec<u8> {
		let mut out = BUNDLE_DOMAIN.to_vec();
		self.chain_id.encode_to(&mut out);
		self.expiry_block.encode_to(&mut out);
		self.recipient.encode_to(&mut out);
		self.transparent_in.encode_to(&mut out);
		self.transparent_out.encode_to(&mut out);
		self.nullifiers.encode_to(&mut out);
		self.commitments.encode_to(&mut out);
		self.cv_inputs.encode_to(&mut out);
		self.cv_outputs.encode_to(&mut out);
		self.mask_bits.encode_to(&mut out);
		self.encrypted_notes_hash.encode_to(&mut out);
		out
	}
}

/// `blake2_256(preimage)` embedded as a canonical field element (31 bytes + zero).
pub fn bundle_digest(fields: &BundleFields<'_>) -> FieldBytes {
	FieldBytes::from_digest(blake2_256(&fields.preimage()))
}

/// Digest of the encrypted note payloads: `blake2_256(SCALE(Vec<Vec<u8>>))`.
pub fn encrypted_notes_hash(notes: &[&[u8]]) -> [u8; 32] {
	blake2_256(&notes.encode())
}
