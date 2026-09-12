//! Circuit 1: PrivacyFlagEnforcement, one instance per output note.
//!
//! Proves that the four-flag mask is valid and that the note being created
//! commits or reveals exactly what the mask says:
//!
//! * `mask < 16`, bits boolean and consistent (lookup);
//! * `cv = H_CV(amount, blinding)` and `cm = H_NOTE(pk_r, amount, rho)` open to
//!   the same `amount`, which is a `u64`;
//! * `revealed_receiver` is `pk_r` or zero and `revealed_amount` is `amount` or
//!   zero, driven by the looked-up mask bits;
//! * `bundle_digest`, `chain_id` (fixed constant) and `expiry_block` are bound.
//!
//! The sender is not part of this circuit: an output cannot prove who spends,
//! so `revealed_sender` lives in Circuit 3.

use arxon_zk_primitives::{
	mask::{hides_amount, hides_receiver},
	poseidon::{hash_cv, hash_note},
	CircuitId,
};
use halo2_proofs::{
	circuit::{Layouter, SimpleFloorPlanner, Value},
	plonk::{Circuit, ConstraintSystem, Error},
};

use super::common::{binding_rows, CircuitConfig};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	field::Fp,
};

#[cfg(test)]
mod tests;

/// Instance rows.
pub mod rows {
	/// `cv`.
	pub const CV: usize = 0;
	/// `cm`.
	pub const CM: usize = 1;
	/// `mask`.
	pub const MASK: usize = 2;
	/// `revealed_receiver`.
	pub const REVEALED_RECEIVER: usize = 3;
	/// `revealed_amount`.
	pub const REVEALED_AMOUNT: usize = 4;
	/// `bundle_digest`.
	pub const BUNDLE_DIGEST: usize = 5;
	/// `chain_id`.
	pub const CHAIN_ID: usize = 6;
	/// `expiry_block`.
	pub const EXPIRY_BLOCK: usize = 7;
	/// Row count.
	pub const LEN: usize = 8;
}

/// Everything the prover knows about one output note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C1Witness {
	/// Note amount in shielded units.
	pub amount: u64,
	/// Value commitment blinding.
	pub blinding: Fp,
	/// Receiver shielded public key.
	pub pk_r: Fp,
	/// Note randomness.
	pub rho: Fp,
	/// Four-flag mask.
	pub mask: u8,
	/// Bundle digest (from the pallet's `BundleFields`).
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

/// Public rows of one instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C1Public {
	/// `H_CV(amount, blinding)`.
	pub cv: Fp,
	/// `H_NOTE(pk_r, amount, rho)`.
	pub cm: Fp,
	/// Mask.
	pub mask: Fp,
	/// `pk_r` or zero.
	pub revealed_receiver: Fp,
	/// `amount` or zero.
	pub revealed_amount: Fp,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl PublicRows for C1Public {
	const LEN: usize = rows::LEN;

	fn to_rows(&self) -> Vec<Fp> {
		let [digest, chain, expiry] = binding_rows(self.bundle_digest, self.expiry_block);
		vec![
			self.cv,
			self.cm,
			self.mask,
			self.revealed_receiver,
			self.revealed_amount,
			digest,
			chain,
			expiry,
		]
	}
}

/// The circuit.
#[derive(Clone, Debug, Default)]
pub struct C1Circuit {
	amount: Value<u64>,
	blinding: Value<Fp>,
	pk_r: Value<Fp>,
	rho: Value<Fp>,
	mask: Value<u8>,
	bundle_digest: Value<Fp>,
	expiry_block: Value<u64>,
}

impl Circuit<Fp> for C1Circuit {
	type Config = CircuitConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		CircuitConfig::configure(meta)
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		cfg.load_tables(&mut layouter)?;

		let bits = cfg.mask.assign(&mut layouter, self.mask)?;
		let amount = cfg.witness_u64(&mut layouter, "amount", self.amount)?;
		let blinding = cfg.witness(&mut layouter, "blinding", self.blinding)?;
		let pk_r = cfg.witness(&mut layouter, "pk_r", self.pk_r)?;
		let rho = cfg.witness(&mut layouter, "rho", self.rho)?;

		cfg.range.check(&mut layouter, &amount)?;
		let cv = cfg
			.poseidon
			.hash_domain::<{ arxon_zk_primitives::constants::tags::CV }, 2>(
				layouter.namespace(|| "cv"),
				[amount.clone(), blinding],
			)?;
		let cm = cfg
			.poseidon
			.hash_domain::<{ arxon_zk_primitives::constants::tags::NOTE }, 3>(
				layouter.namespace(|| "cm"),
				[pk_r.clone(), amount.clone(), rho],
			)?;
		let revealed_receiver = cfg
			.reveal
			.reveal(&mut layouter, bits.hide_receiver(), &pk_r)?;
		let revealed_amount = cfg
			.reveal
			.reveal(&mut layouter, bits.hide_amount(), &amount)?;

		cfg.expose(&mut layouter, &cv, rows::CV)?;
		cfg.expose(&mut layouter, &cm, rows::CM)?;
		cfg.expose(&mut layouter, &bits.mask, rows::MASK)?;
		cfg.expose(&mut layouter, &revealed_receiver, rows::REVEALED_RECEIVER)?;
		cfg.expose(&mut layouter, &revealed_amount, rows::REVEALED_AMOUNT)?;
		cfg.expose_binding_rows(
			&mut layouter,
			rows::BUNDLE_DIGEST,
			self.bundle_digest,
			self.expiry_block,
		)
	}
}

impl ArxonCircuit for C1Circuit {
	const ID: Option<CircuitId> = Some(CircuitId::PrivacyFlagEnforcement);
	const K: u32 = 9;
	const NAME: &'static str = "C1 PrivacyFlagEnforcement";
	const PROOF_LENGTHS: &'static [usize] = &[3456, 4960];
	type Witness = C1Witness;
	type Public = C1Public;

	fn from_witness(w: &C1Witness) -> Self {
		C1Circuit {
			amount: Value::known(w.amount),
			blinding: Value::known(w.blinding),
			pk_r: Value::known(w.pk_r),
			rho: Value::known(w.rho),
			mask: Value::known(w.mask),
			bundle_digest: Value::known(w.bundle_digest),
			expiry_block: Value::known(w.expiry_block as u64),
		}
	}

	fn public_from_witness(w: &C1Witness) -> C1Public {
		C1Public {
			cv: hash_cv(w.amount, w.blinding),
			cm: hash_note(w.pk_r, w.amount, w.rho),
			mask: Fp::from(w.mask as u64),
			revealed_receiver: if hides_receiver(w.mask) {
				Fp::from(0)
			} else {
				w.pk_r
			},
			revealed_amount: if hides_amount(w.mask) {
				Fp::from(0)
			} else {
				Fp::from(w.amount)
			},
			bundle_digest: w.bundle_digest,
			expiry_block: w.expiry_block,
		}
	}
}
