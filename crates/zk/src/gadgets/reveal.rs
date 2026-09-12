//! Selective reveal gate.
//!
//! For a boolean `hide` bit, a private `value` and a public `revealed` cell:
//! `(1 - hide) * (value - revealed) = 0` and `hide * revealed = 0`.
//! Shown fields must equal the value; hidden fields must be exposed as zero,
//! so a prover cannot leak a value into a "hidden" slot either.
//!
//! The production entry point takes a [`MaskBit`], a cell only the mask lookup
//! can produce, so the bit driving the gate is the bit of the published mask.

use halo2_proofs::{
	circuit::{AssignedCell, Layouter, Value},
	plonk::{ConstraintSystem, Constraints, Error, Expression, Selector},
	poly::Rotation,
};

use super::{mask::MaskBit, SharedColumns};
use crate::field::Fp;

/// Reveal gate configuration.
#[derive(Clone, Debug)]
pub struct RevealConfig {
	q_reveal: Selector,
	shared: SharedColumns,
}

impl RevealConfig {
	/// Uses `advices[0..3]` for `(hide, value, revealed)`.
	pub fn configure(meta: &mut ConstraintSystem<Fp>, shared: &SharedColumns) -> Self {
		let q_reveal = meta.selector();
		meta.create_gate("reveal", |meta| {
			let q = meta.query_selector(q_reveal);
			let hide = meta.query_advice(shared.advices[0], Rotation::cur());
			let value = meta.query_advice(shared.advices[1], Rotation::cur());
			let revealed = meta.query_advice(shared.advices[2], Rotation::cur());
			let one = Expression::Constant(Fp::from(1));
			Constraints::with_selector(
				q,
				[
					(
						"shown field equals value",
						(one - hide.clone()) * (value - revealed.clone()),
					),
					("hidden field is zero", hide * revealed),
				],
			)
		});
		RevealConfig {
			q_reveal,
			shared: shared.clone(),
		}
	}

	/// Returns the `revealed` cell for `value` under `hide`; the caller exposes
	/// it as a public row.
	pub fn reveal(
		&self,
		layouter: &mut impl Layouter<Fp>,
		hide: &MaskBit,
		value: &AssignedCell<Fp, Fp>,
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		let hide = hide.cell();
		let revealed =
			hide.value()
				.zip(value.value())
				.map(|(h, v)| if *h == Fp::from(1) { Fp::from(0) } else { *v });
		self.reveal_cells(layouter, hide, value, revealed)
	}

	/// Gate-level access with an arbitrary `hide` cell and a caller-chosen
	/// `revealed` witness. Tests only: production circuits go through [`Self::reveal`].
	#[cfg(test)]
	pub fn reveal_raw(
		&self,
		layouter: &mut impl Layouter<Fp>,
		hide: &AssignedCell<Fp, Fp>,
		value: &AssignedCell<Fp, Fp>,
		revealed: Value<Fp>,
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		self.reveal_cells(layouter, hide, value, revealed)
	}

	fn reveal_cells(
		&self,
		layouter: &mut impl Layouter<Fp>,
		hide: &AssignedCell<Fp, Fp>,
		value: &AssignedCell<Fp, Fp>,
		revealed: Value<Fp>,
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		layouter.assign_region(
			|| "reveal",
			|mut region| {
				self.q_reveal.enable(&mut region, 0)?;
				hide.copy_advice(|| "hide", &mut region, self.shared.advices[0], 0)?;
				value.copy_advice(|| "value", &mut region, self.shared.advices[1], 0)?;
				region.assign_advice(|| "revealed", self.shared.advices[2], 0, || revealed)
			},
		)
	}
}
