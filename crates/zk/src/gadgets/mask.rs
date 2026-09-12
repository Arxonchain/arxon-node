//! The four-flag privacy mask as a single lookup.
//!
//! A 16-row table holds every valid mask next to its four bits. Looking up the
//! tuple `(mask, b0, b1, b2, b3)` proves at once that `mask < 16`, that every
//! bit is boolean and that `mask = b0 + 2 b1 + 4 b2 + 8 b3`. When the selector
//! is off the tuple is all zeros, which is the row of mask 0.

use arxon_zk_primitives::mask::MASK_TABLE_ROWS;
use halo2_proofs::{
	circuit::{AssignedCell, Layouter, Value},
	plonk::{ConstraintSystem, Error, Selector, TableColumn},
	poly::Rotation,
};

use super::SharedColumns;
use crate::field::Fp;

/// A mask and its four bits as assigned cells.
#[derive(Clone, Debug)]
pub struct MaskBits {
	/// The mask as a field element.
	pub mask: AssignedCell<Fp, Fp>,
	/// `[hide_sender, hide_receiver, hide_amount, hide_balance]`.
	pub bits: [AssignedCell<Fp, Fp>; 4],
}

/// Mask lookup configuration.
#[derive(Clone, Debug)]
pub struct MaskConfig {
	q_mask: Selector,
	table: [TableColumn; 5],
	shared: SharedColumns,
}

impl MaskConfig {
	/// Uses `advices[0..5]` for `(mask, b0, b1, b2, b3)`.
	pub fn configure(meta: &mut ConstraintSystem<Fp>, shared: &SharedColumns) -> Self {
		let q_mask = meta.complex_selector();
		let table = [(); 5].map(|_| meta.lookup_table_column());
		meta.lookup(|meta| {
			let q = meta.query_selector(q_mask);
			(0..5)
				.map(|i| {
					(
						q.clone() * meta.query_advice(shared.advices[i], Rotation::cur()),
						table[i],
					)
				})
				.collect()
		});
		MaskConfig {
			q_mask,
			table,
			shared: shared.clone(),
		}
	}

	/// Loads the 16-row table. Call once per synthesis.
	pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
		layouter.assign_table(
			|| "mask table",
			|mut table| {
				for mask in 0..MASK_TABLE_ROWS {
					table.assign_cell(
						|| "mask",
						self.table[0],
						mask,
						|| Value::known(Fp::from(mask as u64)),
					)?;
					for bit in 0..4 {
						let b = ((mask >> bit) & 1) as u64;
						table.assign_cell(
							|| "bit",
							self.table[bit + 1],
							mask,
							|| Value::known(Fp::from(b)),
						)?;
					}
				}
				Ok(())
			},
		)
	}

	/// Witnesses `mask` and its bits and constrains them through the lookup.
	pub fn assign(
		&self,
		layouter: &mut impl Layouter<Fp>,
		mask: Value<u8>,
	) -> Result<MaskBits, Error> {
		let mask_fe = mask.map(|m| Fp::from(m as u64));
		let bits = [0, 1, 2, 3].map(|bit| mask.map(|m| Fp::from(((m >> bit) & 1) as u64)));
		self.assign_raw(layouter, mask_fe, bits)
	}

	/// Witnesses an arbitrary `(mask, bits)` tuple; only the lookup keeps it honest.
	pub fn assign_raw(
		&self,
		layouter: &mut impl Layouter<Fp>,
		mask: Value<Fp>,
		bits: [Value<Fp>; 4],
	) -> Result<MaskBits, Error> {
		layouter.assign_region(
			|| "mask bits",
			|mut region| {
				self.q_mask.enable(&mut region, 0)?;
				let mask_cell =
					region.assign_advice(|| "mask", self.shared.advices[0], 0, || mask)?;
				let mut cells = Vec::with_capacity(4);
				for (i, value) in bits.iter().enumerate() {
					cells.push(region.assign_advice(
						|| "bit",
						self.shared.advices[i + 1],
						0,
						|| *value,
					)?);
				}
				let bits: [AssignedCell<Fp, Fp>; 4] = cells.try_into().expect("four bits");
				Ok(MaskBits {
					mask: mask_cell,
					bits,
				})
			},
		)
	}
}
