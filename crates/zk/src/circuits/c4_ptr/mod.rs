//! Circuit 4: PTR_Generation, one instance per bundle that attaches a receipt.
//!
//! Proves the receipt identifier `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)` names
//! the real parties of the payment:
//!
//! * the sender `pk_s` owns every note the bundle spends: for both input slots
//!   `nf_i = H_NF(nk, H_NOTE(pk_s, amount_i, rho_i))`, and the pallet sets the two
//!   nullifier rows to the bundle's input nullifiers (the first one twice for a
//!   one-input bundle). Circuit 3 proved those nullifiers from notes in the tree,
//!   so by collision resistance `pk_s` and `nk` are the spender's own keys. A
//!   sender cannot name another key, nor split a payment across two of its keys
//!   and attribute it to the cleaner one;
//! * the receiver `pk_r` owns the paid note: `cm = H_NOTE(pk_r, amount, rho_out)`
//!   is public and the pallet sets it to the payment output's commitment.
//!
//! `cv` is the payment output's value commitment, also set by the pallet; Circuit 1
//! proves it opens to the same amount as `cm`. The prover needs `nk`, not the
//! spending key. Parties, amounts and nonce stay private; Circuit 5 later opens
//! them selectively.

use arxon_zk_primitives::{
	constants::tags,
	poseidon::{hash_note, hash_nullifier, hash_ptr},
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
	/// `ptr_id`.
	pub const PTR_ID: usize = 0;
	/// `cv` of the payment output.
	pub const CV: usize = 1;
	/// `cm` of the payment output.
	pub const CM: usize = 2;
	/// Nullifier of input slot 0.
	pub const NULLIFIER_0: usize = 3;
	/// Nullifier of input slot 1 (slot 0 again for a one-input bundle).
	pub const NULLIFIER_1: usize = 4;
	/// `bundle_digest`.
	pub const BUNDLE_DIGEST: usize = 5;
	/// `chain_id`.
	pub const CHAIN_ID: usize = 6;
	/// `expiry_block`.
	pub const EXPIRY_BLOCK: usize = 7;
	/// Row count.
	pub const LEN: usize = 8;
}

/// A note the sender spends in the bundle: amount and randomness (its owner is `pk_s`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentNote {
	/// Amount in shielded units.
	pub amount: u64,
	/// Note randomness.
	pub rho: Fp,
}

/// Everything the prover knows about the receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C4Witness {
	/// Sender shielded public key.
	pub pk_s: Fp,
	/// Sender nullifier key.
	pub nk: Fp,
	/// The bundle's spent notes; slot 1 repeats slot 0 in a one-input bundle.
	pub spent: [SpentNote; 2],
	/// Receiver shielded public key.
	pub pk_r: Fp,
	/// Amount of the payment output.
	pub amount: u64,
	/// Randomness of the payment output.
	pub rho_out: Fp,
	/// Value commitment of the payment output.
	pub cv: Fp,
	/// Receipt nonce.
	pub nonce: Fp,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl C4Witness {
	/// `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`.
	pub fn ptr_id(&self) -> Fp {
		hash_ptr(self.pk_s, self.pk_r, self.cv, self.nonce)
	}

	/// `cm = H_NOTE(pk_r, amount, rho_out)` of the payment output.
	pub fn cm(&self) -> Fp {
		hash_note(self.pk_r, self.amount, self.rho_out)
	}

	/// Nullifiers of the two input slots.
	pub fn nullifiers(&self) -> [Fp; 2] {
		self.spent
			.map(|n| hash_nullifier(self.nk, hash_note(self.pk_s, n.amount, n.rho)))
	}
}

/// Public rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C4Public {
	/// Receipt identifier.
	pub ptr_id: Fp,
	/// Payment value commitment.
	pub cv: Fp,
	/// Payment note commitment.
	pub cm: Fp,
	/// Input nullifiers.
	pub nullifiers: [Fp; 2],
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl PublicRows for C4Public {
	const LEN: usize = rows::LEN;

	fn to_rows(&self) -> Vec<Fp> {
		let [digest, chain, expiry] = binding_rows(self.bundle_digest, self.expiry_block);
		vec![
			self.ptr_id,
			self.cv,
			self.cm,
			self.nullifiers[0],
			self.nullifiers[1],
			digest,
			chain,
			expiry,
		]
	}
}

/// The circuit.
#[derive(Clone, Debug, Default)]
pub struct C4Circuit {
	pk_s: Value<Fp>,
	nk: Value<Fp>,
	spent: [(Value<Fp>, Value<Fp>); 2],
	pk_r: Value<Fp>,
	amount: Value<Fp>,
	rho_out: Value<Fp>,
	cv: Value<Fp>,
	nonce: Value<Fp>,
	bundle_digest: Value<Fp>,
	expiry_block: Value<u64>,
}

impl Circuit<Fp> for C4Circuit {
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

		let pk_s = cfg.witness(&mut layouter, "pk_s", self.pk_s)?;
		let nk = cfg.witness(&mut layouter, "nk", self.nk)?;
		let pk_r = cfg.witness(&mut layouter, "pk_r", self.pk_r)?;
		let amount = cfg.witness(&mut layouter, "amount", self.amount)?;
		let rho_out = cfg.witness(&mut layouter, "rho_out", self.rho_out)?;
		let cv = cfg.witness(&mut layouter, "cv", self.cv)?;
		let nonce = cfg.witness(&mut layouter, "nonce", self.nonce)?;

		let mut nullifiers = Vec::with_capacity(2);
		for (i, (spent_amount, rho)) in self.spent.iter().enumerate() {
			let spent_amount = cfg.witness(&mut layouter, "spent amount", *spent_amount)?;
			let rho = cfg.witness(&mut layouter, "spent rho", *rho)?;
			let cm_in = cfg.poseidon.hash_domain::<{ tags::NOTE }, 3>(
				layouter.namespace(|| format!("spent cm {i}")),
				[pk_s.clone(), spent_amount, rho],
			)?;
			nullifiers.push(cfg.poseidon.hash_domain::<{ tags::NULLIFIER }, 2>(
				layouter.namespace(|| format!("nf {i}")),
				[nk.clone(), cm_in],
			)?);
		}
		let cm = cfg.poseidon.hash_domain::<{ tags::NOTE }, 3>(
			layouter.namespace(|| "payment cm"),
			[pk_r.clone(), amount, rho_out],
		)?;
		let ptr_id = cfg.poseidon.hash_domain::<{ tags::PTR }, 4>(
			layouter.namespace(|| "ptr id"),
			[pk_s, pk_r, cv.clone(), nonce],
		)?;

		cfg.expose(&mut layouter, &ptr_id, rows::PTR_ID)?;
		cfg.expose(&mut layouter, &cv, rows::CV)?;
		cfg.expose(&mut layouter, &cm, rows::CM)?;
		cfg.expose(&mut layouter, &nullifiers[0], rows::NULLIFIER_0)?;
		cfg.expose(&mut layouter, &nullifiers[1], rows::NULLIFIER_1)?;
		cfg.expose_binding_rows(
			&mut layouter,
			rows::BUNDLE_DIGEST,
			self.bundle_digest,
			self.expiry_block,
		)
	}
}

impl ArxonCircuit for C4Circuit {
	const ID: Option<CircuitId> = Some(CircuitId::PtrGeneration);
	const K: u32 = 9;
	const NAME: &'static str = "C4 PtrGeneration";
	const PROOF_LENGTHS: &'static [usize] = &[3456];
	type Witness = C4Witness;
	type Public = C4Public;

	fn from_witness(w: &C4Witness) -> Self {
		C4Circuit {
			pk_s: Value::known(w.pk_s),
			nk: Value::known(w.nk),
			spent: w
				.spent
				.map(|n| (Value::known(Fp::from(n.amount)), Value::known(n.rho))),
			pk_r: Value::known(w.pk_r),
			amount: Value::known(Fp::from(w.amount)),
			rho_out: Value::known(w.rho_out),
			cv: Value::known(w.cv),
			nonce: Value::known(w.nonce),
			bundle_digest: Value::known(w.bundle_digest),
			expiry_block: Value::known(w.expiry_block as u64),
		}
	}

	fn public_from_witness(w: &C4Witness) -> C4Public {
		C4Public {
			ptr_id: w.ptr_id(),
			cv: w.cv,
			cm: w.cm(),
			nullifiers: w.nullifiers(),
			bundle_digest: w.bundle_digest,
			expiry_block: w.expiry_block,
		}
	}
}
