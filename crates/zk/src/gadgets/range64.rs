//! 64-bit range check as a byte-table lookup with a running sum.
//!
//! `z_0 = value`, `z_{i+1} = (z_i - byte_i) / 256`, every `byte_i = z_i - 256 z_{i+1}`
//! is looked up in a 256-row table, and `z_8` is constrained to zero. Hence
//! `value = sum byte_i 256^i < 2^64`. One advice column, two rotations.

use ff::Field;
use halo2_proofs::{
	circuit::{AssignedCell, Layouter, Value},
	plonk::{ConstraintSystem, Error, Selector, TableColumn},
	poly::Rotation,
};

use super::SharedColumns;
use crate::field::Fp;

/// Number of 8-bit words in a `u64`.
pub const NUM_BYTES: usize = 8;

/// Range check configuration.
#[derive(Clone, Debug)]
pub struct Range64Config {
	q_range: Selector,
	byte_table: TableColumn,
	shared: SharedColumns,
}

impl Range64Config {
	/// Uses `advices[5]` as the running-sum column.
	pub fn configure(meta: &mut ConstraintSystem<Fp>, shared: &SharedColumns) -> Self {
		let q_range = meta.complex_selector();
		let byte_table = meta.lookup_table_column();
		let z = shared.advices[5];
		meta.lookup(|meta| {
			let q = meta.query_selector(q_range);
			let z_cur = meta.query_advice(z, Rotation::cur());
			let z_next = meta.query_advice(z, Rotation::next());
			let byte = z_cur - z_next * Fp::from(256);
			vec![(q * byte, byte_table)]
		});
		Range64Config {
			q_range,
			byte_table,
			shared: shared.clone(),
		}
	}

	/// Loads the byte table. Call once per synthesis.
	pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
		layouter.assign_table(
			|| "byte table",
			|mut table| {
				for b in 0..256u64 {
					table.assign_cell(
						|| "byte",
						self.byte_table,
						b as usize,
						|| Value::known(Fp::from(b)),
					)?;
				}
				Ok(())
			},
		)
	}

	/// Constrains the copied `value` cell to `[0, 2^64)`.
	pub fn check(
		&self,
		layouter: &mut impl Layouter<Fp>,
		value: &AssignedCell<Fp, Fp>,
	) -> Result<(), Error> {
		let z = self.shared.advices[5];
		layouter.assign_region(
			|| "range64",
			|mut region| {
				value.copy_advice(|| "z_0", &mut region, z, 0)?;
				let mut running = value.value().copied();
				for i in 0..NUM_BYTES {
					self.q_range.enable(&mut region, i)?;
					running = running.map(shift_right_byte);
					if i + 1 < NUM_BYTES {
						region.assign_advice(|| "z_next", z, i + 1, || running)?;
					}
				}
				// z_8 is the fixed constant zero, so the eight looked-up bytes reconstruct the value exactly.
				region.assign_advice_from_constant(|| "z_8 = 0", z, NUM_BYTES, Fp::ZERO)?;
				Ok(())
			},
		)
	}
}

/// `(v - (v mod 256)) / 256` on the integer representation of `v`.
fn shift_right_byte(v: Fp) -> Fp {
	use ff::PrimeField;
	let mut repr = v.to_repr();
	repr.copy_within(1.., 0);
	repr[31] = 0;
	Fp::from_repr(repr).expect("shifting right keeps the value canonical")
}
