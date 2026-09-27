//! Prover-side helpers: keys, notes and the witnesses of a bundle.
//!
//! A wallet holds spending keys and notes, decides what to spend and create,
//! asks the chain (or recomputes) the bundle digest, and turns all that into
//! circuit witnesses. Nothing here touches the chain; it is what the runtime
//! integration test and a future CLI use to build extrinsics.

use arxon_zk_primitives::poseidon::{
	fp_to_bytes, hash_cv, hash_member_leaf, hash_nk, hash_note, hash_nullifier, hash_pk, hash_ptr,
};
use arxon_zk_primitives::{FieldBytes, C2_INPUTS, C2_OUTPUTS, MEMBER_TREE_DEPTH, NOTE_TREE_DEPTH};
use ff::Field;
use rand_core::RngCore;

use crate::{
	circuits::{C1Witness, C2Witness, C3Witness, C4Witness, C5Witness, C6Witness, SpentNote},
	field::Fp,
	gadgets::merkle::MerklePath,
};

#[cfg(test)]
mod tests;

/// A shielded spending key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendingKey(pub Fp);

impl SpendingKey {
	/// A fresh random key.
	pub fn random(rng: &mut impl RngCore) -> Self {
		SpendingKey(Fp::random(rng))
	}

	/// `pk = H_PK(sk)`: the public key registered on chain and revealed as sender or receiver.
	pub fn pk(&self) -> Fp {
		hash_pk(self.0)
	}

	/// `nk = H_NK(sk)`.
	pub fn nk(&self) -> Fp {
		hash_nk(self.0)
	}
}

/// A note: who owns how much, with the randomness that makes its commitment unique.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
	/// Owner public key.
	pub pk: Fp,
	/// Amount in shielded units.
	pub amount: u64,
	/// Randomness.
	pub rho: Fp,
}

impl Note {
	/// A note to `pk` with fresh randomness.
	pub fn new(pk: Fp, amount: u64, rng: &mut impl RngCore) -> Self {
		Note {
			pk,
			amount,
			rho: Fp::random(rng),
		}
	}

	/// `cm = H_NOTE(pk, amount, rho)`.
	pub fn commitment(&self) -> Fp {
		hash_note(self.pk, self.amount, self.rho)
	}

	/// Nullifier under the owner's spending key.
	pub fn nullifier(&self, sk: &SpendingKey) -> Fp {
		hash_nullifier(sk.nk(), self.commitment())
	}
}

/// An output note being created, with the blinding of its value commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputNote {
	/// The note.
	pub note: Note,
	/// Value commitment blinding.
	pub blinding: Fp,
}

impl OutputNote {
	/// A note to `pk` with fresh randomness and blinding.
	pub fn new(pk: Fp, amount: u64, rng: &mut impl RngCore) -> Self {
		OutputNote {
			note: Note::new(pk, amount, rng),
			blinding: Fp::random(rng),
		}
	}

	/// `cv = H_CV(amount, blinding)`.
	pub fn cv(&self) -> Fp {
		hash_cv(self.note.amount, self.blinding)
	}

	/// Commitment as bytes.
	pub fn cm_bytes(&self) -> FieldBytes {
		fp_to_bytes(&self.note.commitment())
	}

	/// Value commitment as bytes.
	pub fn cv_bytes(&self) -> FieldBytes {
		fp_to_bytes(&self.cv())
	}
}

/// A note being spent: the owner's key, the note, its tree path and a fresh blinding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendNote {
	/// Owner.
	pub sk: SpendingKey,
	/// The note.
	pub note: Note,
	/// Authentication path in the note tree.
	pub path: MerklePath<NOTE_TREE_DEPTH>,
	/// Fresh blinding for the exposed value commitment.
	pub blinding: Fp,
}

impl SpendNote {
	/// Prepares a spend with a fresh blinding.
	pub fn new(
		sk: SpendingKey,
		note: Note,
		path: MerklePath<NOTE_TREE_DEPTH>,
		rng: &mut impl RngCore,
	) -> Self {
		SpendNote {
			sk,
			note,
			path,
			blinding: Fp::random(rng),
		}
	}

	/// `cv = H_CV(amount, blinding)`.
	pub fn cv(&self) -> Fp {
		hash_cv(self.note.amount, self.blinding)
	}

	/// Nullifier as bytes.
	pub fn nullifier_bytes(&self) -> FieldBytes {
		fp_to_bytes(&self.note.nullifier(&self.sk))
	}

	/// Value commitment as bytes.
	pub fn cv_bytes(&self) -> FieldBytes {
		fp_to_bytes(&self.cv())
	}
}

/// Everything a bundle's circuits need beyond the notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleContext {
	/// Four-flag mask.
	pub mask: u8,
	/// Bundle digest computed by (or exactly as) the pallet.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
	/// Transparent value entering the pool, in shielded units.
	pub transparent_in: u64,
	/// Transparent value leaving the pool, in shielded units.
	pub transparent_out: u64,
}

/// Circuit 3 witnesses, one per spend.
pub fn spend_witnesses(spends: &[SpendNote], ctx: &BundleContext) -> Vec<C3Witness> {
	spends
		.iter()
		.map(|s| C3Witness {
			sk: s.sk.0,
			amount: s.note.amount,
			rho: s.note.rho,
			blinding: s.blinding,
			mask: ctx.mask,
			path: s.path.clone(),
			bundle_digest: ctx.bundle_digest,
			expiry_block: ctx.expiry_block,
		})
		.collect()
}

/// Circuit 1 witnesses, one per output.
pub fn output_witnesses(outputs: &[OutputNote], ctx: &BundleContext) -> Vec<C1Witness> {
	outputs
		.iter()
		.map(|o| C1Witness {
			amount: o.note.amount,
			blinding: o.blinding,
			pk_r: o.note.pk,
			rho: o.note.rho,
			mask: ctx.mask,
			bundle_digest: ctx.bundle_digest,
			expiry_block: ctx.expiry_block,
		})
		.collect()
}

/// Circuit 2 witness. Unused slots are zero amount with zero blinding (`CV_DUMMY`).
///
/// # Panics
/// If more than `C2_INPUTS` spends or `C2_OUTPUTS` outputs are given.
pub fn balance_witness(
	spends: &[SpendNote],
	outputs: &[OutputNote],
	ctx: &BundleContext,
) -> C2Witness {
	assert!(
		spends.len() <= C2_INPUTS,
		"at most {C2_INPUTS} spends per bundle"
	);
	assert!(
		outputs.len() <= C2_OUTPUTS,
		"at most {C2_OUTPUTS} outputs per bundle"
	);
	let mut v_in = [0u64; C2_INPUTS];
	let mut r_in = [Fp::ZERO; C2_INPUTS];
	for (i, s) in spends.iter().enumerate() {
		v_in[i] = s.note.amount;
		r_in[i] = s.blinding;
	}
	let mut v_out = [0u64; C2_OUTPUTS];
	let mut r_out = [Fp::ZERO; C2_OUTPUTS];
	for (i, o) in outputs.iter().enumerate() {
		v_out[i] = o.note.amount;
		r_out[i] = o.blinding;
	}
	C2Witness {
		v_in,
		r_in,
		v_out,
		r_out,
		transparent_in: ctx.transparent_in,
		transparent_out: ctx.transparent_out,
		fee: 0,
		bundle_digest: ctx.bundle_digest,
		expiry_block: ctx.expiry_block,
	}
}

/// `true` iff the bundle conserves value (what Circuit 2 will prove).
pub fn is_balanced(spends: &[SpendNote], outputs: &[OutputNote], ctx: &BundleContext) -> bool {
	let inputs: u128 =
		spends.iter().map(|s| s.note.amount as u128).sum::<u128>() + ctx.transparent_in as u128;
	let outputs: u128 =
		outputs.iter().map(|o| o.note.amount as u128).sum::<u128>() + ctx.transparent_out as u128;
	inputs == outputs
}

/// A receipt the sender keeps for a payment output: everything Circuit 5 needs later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
	/// Sender shielded public key.
	pub pk_s: Fp,
	/// The paid output.
	pub payment: OutputNote,
	/// Receipt nonce.
	pub nonce: Fp,
}

impl Receipt {
	/// A receipt for `payment` from `sender` with a fresh nonce.
	pub fn new(sender: &SpendingKey, payment: OutputNote, rng: &mut impl RngCore) -> Self {
		Receipt {
			pk_s: sender.pk(),
			payment,
			nonce: Fp::random(rng),
		}
	}

	/// `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`.
	pub fn ptr_id(&self) -> Fp {
		hash_ptr(
			self.pk_s,
			self.payment.note.pk,
			self.payment.cv(),
			self.nonce,
		)
	}

	/// Identifier as bytes.
	pub fn ptr_id_bytes(&self) -> FieldBytes {
		fp_to_bytes(&self.ptr_id())
	}

	/// Circuit 4 witness for the bundle that pays this receipt, which spends `spends`.
	///
	/// # Panics
	/// If `spends` is empty, holds more than `C2_INPUTS` notes, or any of them is
	/// not the sender's: Circuit 4 proves the sender owns every spent note.
	pub fn generation_witness(&self, spends: &[SpendNote], ctx: &BundleContext) -> C4Witness {
		assert!(
			(1..=C2_INPUTS).contains(&spends.len()),
			"a receipt needs 1 to {C2_INPUTS} spends"
		);
		assert!(
			spends.iter().all(|s| s.sk.pk() == self.pk_s),
			"the receipt's sender must own every spent note"
		);
		let slot = |i: usize| {
			let note = spends.get(i).unwrap_or(&spends[0]).note;
			SpentNote {
				amount: note.amount,
				rho: note.rho,
			}
		};
		C4Witness {
			pk_s: self.pk_s,
			nk: spends[0].sk.nk(),
			spent: [slot(0), slot(1)],
			pk_r: self.payment.note.pk,
			amount: self.payment.note.amount,
			rho_out: self.payment.note.rho,
			cv: self.payment.cv(),
			nonce: self.nonce,
			bundle_digest: ctx.bundle_digest,
			expiry_block: ctx.expiry_block,
		}
	}

	/// Circuit 5 witness disclosing the fields `disclosure_mask` does not hide to `audience`.
	pub fn disclosure_witness(
		&self,
		disclosure_mask: u8,
		audience: Fp,
		expiry_block: u32,
	) -> C5Witness {
		C5Witness {
			pk_s: self.pk_s,
			pk_r: self.payment.note.pk,
			amount: self.payment.note.amount,
			blinding: self.payment.blinding,
			nonce: self.nonce,
			disclosure_mask,
			audience,
			expiry_block,
		}
	}
}

/// Membership tree leaf of a shielded public key.
pub fn member_leaf(pk: Fp) -> Fp {
	hash_member_leaf(pk)
}

/// Circuit 6 witness: `output` pays the member whose leaf sits at `path` in the registry.
pub fn membership_witness(
	output: &OutputNote,
	path: MerklePath<MEMBER_TREE_DEPTH>,
	ctx: &BundleContext,
) -> C6Witness {
	C6Witness {
		pk_member: output.note.pk,
		amount: output.note.amount,
		rho: output.note.rho,
		path,
		bundle_digest: ctx.bundle_digest,
		expiry_block: ctx.expiry_block,
	}
}
