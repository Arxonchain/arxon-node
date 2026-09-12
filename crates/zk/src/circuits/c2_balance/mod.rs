//! Circuit 2: BalanceIntegrity, one instance per bundle.
//!
//! Opens the two input and two output value commitments and proves
//! `v_in0 + v_in1 + transparent_in = v_out0 + v_out1 + transparent_out + fee`
//! with every term in `[0, 2^64)`. This is the shielded pool's inflation
//! backstop. Unused slots carry `CV_DUMMY = H_CV(0, 0)`, which can only be
//! opened to zero.

use arxon_zk_primitives::{constants::tags, poseidon::hash_cv, CircuitId, C2_INPUTS, C2_OUTPUTS};
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
	/// `cv_in0`, `cv_in1`.
	pub const CV_IN: [usize; 2] = [0, 1];
	/// `cv_out0`, `cv_out1`.
	pub const CV_OUT: [usize; 2] = [2, 3];
	/// `transparent_in`.
	pub const TRANSPARENT_IN: usize = 4;
	/// `transparent_out`.
	pub const TRANSPARENT_OUT: usize = 5;
	/// `fee`.
	pub const FEE: usize = 6;
	/// `bundle_digest`.
	pub const BUNDLE_DIGEST: usize = 7;
	/// `chain_id`.
	pub const CHAIN_ID: usize = 8;
	/// `expiry_block`.
	pub const EXPIRY_BLOCK: usize = 9;
	/// Row count.
	pub const LEN: usize = 10;
}

/// Everything the prover knows about the bundle's values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C2Witness {
	/// Input amounts (zero for unused slots).
	pub v_in: [u64; C2_INPUTS],
	/// Input blindings (zero for unused slots).
	pub r_in: [Fp; C2_INPUTS],
	/// Output amounts (zero for unused slots).
	pub v_out: [u64; C2_OUTPUTS],
	/// Output blindings (zero for unused slots).
	pub r_out: [Fp; C2_OUTPUTS],
	/// Transparent value entering the pool.
	pub transparent_in: u64,
	/// Transparent value leaving the pool.
	pub transparent_out: u64,
	/// In-circuit fee (zero in v1).
	pub fee: u64,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

/// Public rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C2Public {
	/// Input value commitments.
	pub cv_in: [Fp; C2_INPUTS],
	/// Output value commitments.
	pub cv_out: [Fp; C2_OUTPUTS],
	/// Transparent value in.
	pub transparent_in: u64,
	/// Transparent value out.
	pub transparent_out: u64,
	/// Fee.
	pub fee: u64,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl PublicRows for C2Public {
	const LEN: usize = rows::LEN;

	fn to_rows(&self) -> Vec<Fp> {
		let [digest, chain, expiry] = binding_rows(self.bundle_digest, self.expiry_block);
		vec![
			self.cv_in[0],
			self.cv_in[1],
			self.cv_out[0],
			self.cv_out[1],
			Fp::from(self.transparent_in),
			Fp::from(self.transparent_out),
			Fp::from(self.fee),
			digest,
			chain,
			expiry,
		]
	}
}

/// The circuit.
#[derive(Clone, Debug, Default)]
pub struct C2Circuit {
	v_in: [Value<Fp>; C2_INPUTS],
	r_in: [Value<Fp>; C2_INPUTS],
	v_out: [Value<Fp>; C2_OUTPUTS],
	r_out: [Value<Fp>; C2_OUTPUTS],
	transparent_in: Value<Fp>,
	transparent_out: Value<Fp>,
	fee: Value<Fp>,
	bundle_digest: Value<Fp>,
	expiry_block: Value<u64>,
}

impl C2Circuit {
	/// A circuit with raw field-element amounts, so tests can exercise the range
	/// checks with values a `u64` witness cannot express.
	#[cfg(test)]
	pub fn with_raw_amounts(
		w: &C2Witness,
		v_in: [Fp; 2],
		v_out: [Fp; 2],
		transparent_in: Fp,
		transparent_out: Fp,
		fee: Fp,
	) -> Self {
		C2Circuit {
			v_in: v_in.map(Value::known),
			r_in: w.r_in.map(Value::known),
			v_out: v_out.map(Value::known),
			r_out: w.r_out.map(Value::known),
			transparent_in: Value::known(transparent_in),
			transparent_out: Value::known(transparent_out),
			fee: Value::known(fee),
			bundle_digest: Value::known(w.bundle_digest),
			expiry_block: Value::known(w.expiry_block as u64),
		}
	}
}

impl Circuit<Fp> for C2Circuit {
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

		let mut cv_rows = Vec::with_capacity(4);
		let mut values = Vec::with_capacity(4);
		for (i, (v, r)) in self
			.v_in
			.iter()
			.zip(self.r_in.iter())
			.chain(self.v_out.iter().zip(self.r_out.iter()))
			.enumerate()
		{
			let value = cfg.witness(&mut layouter, "value", *v)?;
			let blinding = cfg.witness(&mut layouter, "blinding", *r)?;
			cfg.range.check(&mut layouter, &value)?;
			let cv = cfg.poseidon.hash_domain::<{ tags::CV }, 2>(
				layouter.namespace(|| format!("cv {i}")),
				[value.clone(), blinding],
			)?;
			cv_rows.push(cv);
			values.push(value);
		}
		let transparent_in = cfg.witness(&mut layouter, "transparent in", self.transparent_in)?;
		let transparent_out =
			cfg.witness(&mut layouter, "transparent out", self.transparent_out)?;
		let fee = cfg.witness(&mut layouter, "fee", self.fee)?;
		for public_amount in [&transparent_in, &transparent_out, &fee] {
			cfg.range.check(&mut layouter, public_amount)?;
		}

		cfg.balance.check(
			&mut layouter,
			[&values[0], &values[1], &transparent_in],
			[&values[2], &values[3], &transparent_out],
			&fee,
		)?;

		for (cv, row) in cv_rows
			.iter()
			.zip(rows::CV_IN.iter().chain(rows::CV_OUT.iter()))
		{
			cfg.expose(&mut layouter, cv, *row)?;
		}
		cfg.expose(&mut layouter, &transparent_in, rows::TRANSPARENT_IN)?;
		cfg.expose(&mut layouter, &transparent_out, rows::TRANSPARENT_OUT)?;
		cfg.expose(&mut layouter, &fee, rows::FEE)?;
		cfg.expose_binding_rows(
			&mut layouter,
			rows::BUNDLE_DIGEST,
			self.bundle_digest,
			self.expiry_block,
		)
	}
}

impl ArxonCircuit for C2Circuit {
	const ID: Option<CircuitId> = Some(CircuitId::BalanceIntegrity);
	const K: u32 = 9;
	const NAME: &'static str = "C2 BalanceIntegrity";
	const PROOF_LENGTHS: &'static [usize] = &[3456];
	type Witness = C2Witness;
	type Public = C2Public;

	fn from_witness(w: &C2Witness) -> Self {
		C2Circuit {
			v_in: w.v_in.map(|v| Value::known(Fp::from(v))),
			r_in: w.r_in.map(Value::known),
			v_out: w.v_out.map(|v| Value::known(Fp::from(v))),
			r_out: w.r_out.map(Value::known),
			transparent_in: Value::known(Fp::from(w.transparent_in)),
			transparent_out: Value::known(Fp::from(w.transparent_out)),
			fee: Value::known(Fp::from(w.fee)),
			bundle_digest: Value::known(w.bundle_digest),
			expiry_block: Value::known(w.expiry_block as u64),
		}
	}

	fn public_from_witness(w: &C2Witness) -> C2Public {
		C2Public {
			cv_in: [hash_cv(w.v_in[0], w.r_in[0]), hash_cv(w.v_in[1], w.r_in[1])],
			cv_out: [
				hash_cv(w.v_out[0], w.r_out[0]),
				hash_cv(w.v_out[1], w.r_out[1]),
			],
			transparent_in: w.transparent_in,
			transparent_out: w.transparent_out,
			fee: w.fee,
			bundle_digest: w.bundle_digest,
			expiry_block: w.expiry_block,
		}
	}
}
