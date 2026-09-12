//! Circuit 4: PTR_Generation, one instance per bundle that attaches a receipt.
//!
//! Proves the receipt identifier is well formed: `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`
//! where `cv` is the value commitment of the payment output (the pallet forces
//! it to equal the chosen Circuit 1 instance's `cv`). Parties and nonce stay
//! private; Circuit 5 later opens them selectively.

use arxon_zk_primitives::{constants::tags, poseidon::hash_ptr, CircuitId};
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
	/// `cv`.
	pub const CV: usize = 1;
	/// `bundle_digest`.
	pub const BUNDLE_DIGEST: usize = 2;
	/// `chain_id`.
	pub const CHAIN_ID: usize = 3;
	/// `expiry_block`.
	pub const EXPIRY_BLOCK: usize = 4;
	/// Row count.
	pub const LEN: usize = 5;
}

/// Everything the prover knows about the receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C4Witness {
	/// Sender shielded public key.
	pub pk_s: Fp,
	/// Receiver shielded public key.
	pub pk_r: Fp,
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
}

/// Public rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C4Public {
	/// Receipt identifier.
	pub ptr_id: Fp,
	/// Payment value commitment.
	pub cv: Fp,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl PublicRows for C4Public {
	const LEN: usize = rows::LEN;

	fn to_rows(&self) -> Vec<Fp> {
		let [digest, chain, expiry] = binding_rows(self.bundle_digest, self.expiry_block);
		vec![self.ptr_id, self.cv, digest, chain, expiry]
	}
}

/// The circuit.
#[derive(Clone, Debug, Default)]
pub struct C4Circuit {
	pk_s: Value<Fp>,
	pk_r: Value<Fp>,
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
		let pk_r = cfg.witness(&mut layouter, "pk_r", self.pk_r)?;
		let cv = cfg.witness(&mut layouter, "cv", self.cv)?;
		let nonce = cfg.witness(&mut layouter, "nonce", self.nonce)?;
		let ptr_id = cfg.poseidon.hash_domain::<{ tags::PTR }, 4>(
			layouter.namespace(|| "ptr id"),
			[pk_s, pk_r, cv.clone(), nonce],
		)?;

		cfg.expose(&mut layouter, &ptr_id, rows::PTR_ID)?;
		cfg.expose(&mut layouter, &cv, rows::CV)?;
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
			pk_r: Value::known(w.pk_r),
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
			bundle_digest: w.bundle_digest,
			expiry_block: w.expiry_block,
		}
	}
}
