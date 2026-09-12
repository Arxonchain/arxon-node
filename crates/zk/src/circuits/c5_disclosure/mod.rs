//! Circuit 5: DisclosureProof, opens a receipt selectively to one audience.
//!
//! Given a receipt `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)` with `cv = H_CV(amount, blinding)`,
//! reveals any subset of `{sender, receiver, amount}` chosen by `disclosure_mask`
//! (same four-flag packing, "hide" semantics; bit 3 must be clear because a
//! receipt has no balance). `audience` is bound so the proof cannot be replayed
//! to anyone else; `chain_id` and `expiry_block` bound as everywhere.

use arxon_zk_primitives::{
	constants::tags,
	mask::{hides_amount, hides_receiver, hides_sender},
	poseidon::{hash_cv, hash_ptr},
	CircuitId,
};
use ff::Field;
use halo2_proofs::{
	circuit::{Layouter, SimpleFloorPlanner, Value},
	plonk::{Circuit, ConstraintSystem, Error},
};

use super::common::CircuitConfig;
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	field::Fp,
	gadgets::binding,
};

#[cfg(test)]
mod tests;

/// Instance rows.
pub mod rows {
	/// `ptr_id`.
	pub const PTR_ID: usize = 0;
	/// `disclosure_mask`.
	pub const DISCLOSURE_MASK: usize = 1;
	/// `revealed_sender`.
	pub const REVEALED_SENDER: usize = 2;
	/// `revealed_receiver`.
	pub const REVEALED_RECEIVER: usize = 3;
	/// `revealed_amount`.
	pub const REVEALED_AMOUNT: usize = 4;
	/// `audience`.
	pub const AUDIENCE: usize = 5;
	/// `chain_id`.
	pub const CHAIN_ID: usize = 6;
	/// `expiry_block`.
	pub const EXPIRY_BLOCK: usize = 7;
	/// Row count.
	pub const LEN: usize = 8;
}

/// Everything the receipt holder knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C5Witness {
	/// Sender shielded public key.
	pub pk_s: Fp,
	/// Receiver shielded public key.
	pub pk_r: Fp,
	/// Payment amount in shielded units.
	pub amount: u64,
	/// Value commitment blinding.
	pub blinding: Fp,
	/// Receipt nonce.
	pub nonce: Fp,
	/// Which fields stay hidden (bit 3 must be clear).
	pub disclosure_mask: u8,
	/// Verifier account digest the disclosure is for.
	pub audience: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl C5Witness {
	/// `cv = H_CV(amount, blinding)`.
	pub fn cv(&self) -> Fp {
		hash_cv(self.amount, self.blinding)
	}

	/// `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`.
	pub fn ptr_id(&self) -> Fp {
		hash_ptr(self.pk_s, self.pk_r, self.cv(), self.nonce)
	}
}

/// Public rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C5Public {
	/// Receipt identifier.
	pub ptr_id: Fp,
	/// Disclosure mask.
	pub disclosure_mask: Fp,
	/// `pk_s` or zero.
	pub revealed_sender: Fp,
	/// `pk_r` or zero.
	pub revealed_receiver: Fp,
	/// `amount` or zero.
	pub revealed_amount: Fp,
	/// Audience.
	pub audience: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl PublicRows for C5Public {
	const LEN: usize = rows::LEN;

	fn to_rows(&self) -> Vec<Fp> {
		vec![
			self.ptr_id,
			self.disclosure_mask,
			self.revealed_sender,
			self.revealed_receiver,
			self.revealed_amount,
			self.audience,
			Fp::from(arxon_zk_primitives::CHAIN_ID),
			Fp::from(self.expiry_block as u64),
		]
	}
}

/// The circuit.
#[derive(Clone, Debug, Default)]
pub struct C5Circuit {
	pk_s: Value<Fp>,
	pk_r: Value<Fp>,
	amount: Value<Fp>,
	blinding: Value<Fp>,
	nonce: Value<Fp>,
	disclosure_mask: Value<u8>,
	audience: Value<Fp>,
	expiry_block: Value<u64>,
}

impl Circuit<Fp> for C5Circuit {
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

		let bits = cfg.mask.assign(&mut layouter, self.disclosure_mask)?;
		// A receipt has no balance: the balance bit must be zero.
		layouter.assign_region(
			|| "no balance bit",
			|mut region| region.constrain_constant(bits.hide_balance().cell().cell(), Fp::ZERO),
		)?;

		let pk_s = cfg.witness(&mut layouter, "pk_s", self.pk_s)?;
		let pk_r = cfg.witness(&mut layouter, "pk_r", self.pk_r)?;
		let amount = cfg.witness(&mut layouter, "amount", self.amount)?;
		let blinding = cfg.witness(&mut layouter, "blinding", self.blinding)?;
		let nonce = cfg.witness(&mut layouter, "nonce", self.nonce)?;

		cfg.range.check(&mut layouter, &amount)?;
		let cv = cfg.poseidon.hash_domain::<{ tags::CV }, 2>(
			layouter.namespace(|| "cv"),
			[amount.clone(), blinding],
		)?;
		let ptr_id = cfg.poseidon.hash_domain::<{ tags::PTR }, 4>(
			layouter.namespace(|| "ptr id"),
			[pk_s.clone(), pk_r.clone(), cv, nonce],
		)?;
		let revealed_sender = cfg
			.reveal
			.reveal(&mut layouter, bits.hide_sender(), &pk_s)?;
		let revealed_receiver = cfg
			.reveal
			.reveal(&mut layouter, bits.hide_receiver(), &pk_r)?;
		let revealed_amount = cfg
			.reveal
			.reveal(&mut layouter, bits.hide_amount(), &amount)?;

		cfg.expose(&mut layouter, &ptr_id, rows::PTR_ID)?;
		cfg.expose(&mut layouter, &bits.mask, rows::DISCLOSURE_MASK)?;
		cfg.expose(&mut layouter, &revealed_sender, rows::REVEALED_SENDER)?;
		cfg.expose(&mut layouter, &revealed_receiver, rows::REVEALED_RECEIVER)?;
		cfg.expose(&mut layouter, &revealed_amount, rows::REVEALED_AMOUNT)?;
		let column = cfg.shared.advices[5];
		binding::expose_witness(
			&mut layouter,
			column,
			cfg.shared.instance,
			rows::AUDIENCE,
			"audience",
			self.audience,
		)?;
		binding::expose_constant(
			&mut layouter,
			column,
			cfg.shared.instance,
			rows::CHAIN_ID,
			"chain id",
			Fp::from(arxon_zk_primitives::CHAIN_ID),
		)?;
		binding::expose_witness(
			&mut layouter,
			column,
			cfg.shared.instance,
			rows::EXPIRY_BLOCK,
			"expiry block",
			self.expiry_block.map(Fp::from),
		)?;
		Ok(())
	}
}

impl ArxonCircuit for C5Circuit {
	const ID: Option<CircuitId> = Some(CircuitId::DisclosureProof);
	const K: u32 = 9;
	const NAME: &'static str = "C5 DisclosureProof";
	const PROOF_LENGTHS: &'static [usize] = &[3456];
	type Witness = C5Witness;
	type Public = C5Public;

	fn from_witness(w: &C5Witness) -> Self {
		C5Circuit {
			pk_s: Value::known(w.pk_s),
			pk_r: Value::known(w.pk_r),
			amount: Value::known(Fp::from(w.amount)),
			blinding: Value::known(w.blinding),
			nonce: Value::known(w.nonce),
			disclosure_mask: Value::known(w.disclosure_mask),
			audience: Value::known(w.audience),
			expiry_block: Value::known(w.expiry_block as u64),
		}
	}

	fn public_from_witness(w: &C5Witness) -> C5Public {
		let m = w.disclosure_mask;
		C5Public {
			ptr_id: w.ptr_id(),
			disclosure_mask: Fp::from(m as u64),
			revealed_sender: if hides_sender(m) { Fp::ZERO } else { w.pk_s },
			revealed_receiver: if hides_receiver(m) { Fp::ZERO } else { w.pk_r },
			revealed_amount: if hides_amount(m) {
				Fp::ZERO
			} else {
				Fp::from(w.amount)
			},
			audience: w.audience,
			expiry_block: w.expiry_block,
		}
	}
}
