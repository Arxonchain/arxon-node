//! Circuit 0: the harness circuit.
//!
//! Proves `a * b = c` with `c` public and the chain id bound as a fixed
//! constant. It never reaches the chain; it exists to validate the whole
//! prove / verify / exact-length / pin pipeline before any real gadget, and it
//! stays as the regression test of that pipeline.

use arxon_zk_primitives::{CircuitId, CHAIN_ID};
use halo2_proofs::{
	circuit::{Layouter, SimpleFloorPlanner, Value},
	plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
	poly::Rotation,
};

use crate::{
	circuit::{ArxonCircuit, PublicRows},
	field::Fp,
};

#[cfg(test)]
mod tests;

/// Instance row of `c`.
pub const ROW_C: usize = 0;
/// Instance row of the chain id.
pub const ROW_CHAIN_ID: usize = 1;

/// Private inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DummyWitness {
	/// Left factor.
	pub a: Fp,
	/// Right factor.
	pub b: Fp,
}

/// Public rows: `[c, chain_id]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DummyPublic {
	/// `a * b`.
	pub c: Fp,
	/// Always [`CHAIN_ID`].
	pub chain_id: Fp,
}

impl PublicRows for DummyPublic {
	const LEN: usize = 2;

	fn to_rows(&self) -> Vec<Fp> {
		vec![self.c, self.chain_id]
	}
}

/// Column layout.
#[derive(Clone, Debug)]
pub struct DummyConfig {
	a: Column<Advice>,
	b: Column<Advice>,
	c: Column<Advice>,
	instance: Column<Instance>,
	s_mul: Selector,
}

/// The harness circuit.
#[derive(Clone, Debug, Default)]
pub struct DummyCircuit {
	a: Value<Fp>,
	b: Value<Fp>,
}

impl Circuit<Fp> for DummyCircuit {
	type Config = DummyConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		let a = meta.advice_column();
		let b = meta.advice_column();
		let c = meta.advice_column();
		let constants = meta.fixed_column();
		let instance = meta.instance_column();
		let s_mul = meta.selector();

		meta.enable_equality(a);
		meta.enable_equality(c);
		meta.enable_equality(instance);
		meta.enable_constant(constants);

		meta.create_gate("a * b = c", |meta| {
			let s = meta.query_selector(s_mul);
			let a = meta.query_advice(a, Rotation::cur());
			let b = meta.query_advice(b, Rotation::cur());
			let c = meta.query_advice(c, Rotation::cur());
			vec![s * (a * b - c)]
		});

		DummyConfig {
			a,
			b,
			c,
			instance,
			s_mul,
		}
	}

	fn synthesize(
		&self,
		config: Self::Config,
		mut layouter: impl Layouter<Fp>,
	) -> Result<(), Error> {
		let c = layouter.assign_region(
			|| "multiply",
			|mut region| {
				config.s_mul.enable(&mut region, 0)?;
				region.assign_advice(|| "a", config.a, 0, || self.a)?;
				region.assign_advice(|| "b", config.b, 0, || self.b)?;
				region.assign_advice(|| "c", config.c, 0, || self.a * self.b)
			},
		)?;
		layouter.constrain_instance(c.cell(), config.instance, ROW_C)?;

		let chain_id = layouter.assign_region(
			|| "chain id",
			|mut region| {
				region.assign_advice_from_constant(|| "chain id", config.a, 0, Fp::from(CHAIN_ID))
			},
		)?;
		layouter.constrain_instance(chain_id.cell(), config.instance, ROW_CHAIN_ID)?;

		Ok(())
	}
}

impl ArxonCircuit for DummyCircuit {
	const ID: Option<CircuitId> = None;
	const K: u32 = 5;
	const NAME: &'static str = "C0 Dummy";
	const PROOF_LENGTHS: &'static [usize] = &[1568, 2272];
	type Witness = DummyWitness;
	type Public = DummyPublic;

	/// The harness folds two instances so multi-instance proving is exercised without a chain circuit.
	fn max_instances() -> u32 {
		2
	}

	fn from_witness(w: &DummyWitness) -> Self {
		DummyCircuit {
			a: Value::known(w.a),
			b: Value::known(w.b),
		}
	}

	fn public_from_witness(w: &DummyWitness) -> DummyPublic {
		DummyPublic {
			c: w.a * w.b,
			chain_id: Fp::from(CHAIN_ID),
		}
	}
}
