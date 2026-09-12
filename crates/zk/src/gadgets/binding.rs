//! Binding public rows to the instance column.
//!
//! An instance cell that no advice cell is copy-constrained to is a free
//! variable: the proof verifies for any value in it. Every public row of every
//! Arxon circuit therefore goes through one of these helpers, and a shared test
//! (`assert_every_public_row_is_bound`) perturbs each row to prove it.

use halo2_proofs::{
	circuit::{AssignedCell, Layouter, Value},
	plonk::{Advice, Column, Error, Instance},
};

use crate::field::Fp;

/// Assigns `value` to a fresh advice cell.
pub fn witness(
	layouter: &mut impl Layouter<Fp>,
	column: Column<Advice>,
	name: &'static str,
	value: Value<Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
	layouter.assign_region(
		|| name,
		|mut region| region.assign_advice(|| name, column, 0, || value),
	)
}

/// Assigns the fixed constant `value` to a fresh advice cell (needs an
/// `enable_constant` fixed column in the circuit).
pub fn constant(
	layouter: &mut impl Layouter<Fp>,
	column: Column<Advice>,
	name: &'static str,
	value: Fp,
) -> Result<AssignedCell<Fp, Fp>, Error> {
	layouter.assign_region(
		|| name,
		|mut region| region.assign_advice_from_constant(|| name, column, 0, value),
	)
}

/// Copy-constrains `cell` to instance `row`.
pub fn expose(
	layouter: &mut impl Layouter<Fp>,
	cell: &AssignedCell<Fp, Fp>,
	instance: Column<Instance>,
	row: usize,
) -> Result<(), Error> {
	layouter.constrain_instance(cell.cell(), instance, row)
}

/// Witnesses `value` and exposes it at instance `row` (a bind-only public input).
pub fn expose_witness(
	layouter: &mut impl Layouter<Fp>,
	column: Column<Advice>,
	instance: Column<Instance>,
	row: usize,
	name: &'static str,
	value: Value<Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
	let cell = witness(layouter, column, name, value)?;
	expose(layouter, &cell, instance, row)?;
	Ok(cell)
}

/// Bakes `value` into the verifying key and exposes it at instance `row`
/// (used for the chain id: a proof for any other value is unverifiable).
pub fn expose_constant(
	layouter: &mut impl Layouter<Fp>,
	column: Column<Advice>,
	instance: Column<Instance>,
	row: usize,
	name: &'static str,
	value: Fp,
) -> Result<AssignedCell<Fp, Fp>, Error> {
	let cell = constant(layouter, column, name, value)?;
	expose(layouter, &cell, instance, row)?;
	Ok(cell)
}
