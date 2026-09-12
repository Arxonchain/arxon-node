//! Conservation gate of Circuit 2:
//! `v_in0 + v_in1 + transparent_in = v_out0 + v_out1 + transparent_out + fee`.
//!
//! Every term is separately range-checked to 64 bits, so the field sum equals
//! the integer sum (seven terms below `2^64` cannot wrap around a 255-bit field).

use halo2_proofs::{
	circuit::{AssignedCell, Layouter},
	plonk::{ConstraintSystem, Error, Selector},
	poly::Rotation,
};

use super::SharedColumns;
use crate::field::Fp;

/// Conservation gate configuration.
#[derive(Clone, Debug)]
pub struct BalanceConfig {
	q_balance: Selector,
	shared: SharedColumns,
}

impl BalanceConfig {
	/// Row 0: `advices[0..6] = (v_in0, v_in1, transparent_in, v_out0, v_out1, transparent_out)`; row 1: `advices[0] = fee`.
	pub fn configure(meta: &mut ConstraintSystem<Fp>, shared: &SharedColumns) -> Self {
		let q_balance = meta.selector();
		meta.create_gate("balance", |meta| {
			let q = meta.query_selector(q_balance);
			let [in0, in1, tin, out0, out1, tout] =
				[0, 1, 2, 3, 4, 5].map(|i| meta.query_advice(shared.advices[i], Rotation::cur()));
			let fee = meta.query_advice(shared.advices[0], Rotation::next());
			let inputs = in0 + in1 + tin;
			let outputs = out0 + out1 + tout + fee;
			vec![("inputs equal outputs plus fee", q * (inputs - outputs))]
		});
		BalanceConfig {
			q_balance,
			shared: shared.clone(),
		}
	}

	/// Constrains `inputs[0] + inputs[1] + inputs[2] = outputs[0] + outputs[1] + outputs[2] + fee`.
	pub fn check(
		&self,
		layouter: &mut impl Layouter<Fp>,
		inputs: [&AssignedCell<Fp, Fp>; 3],
		outputs: [&AssignedCell<Fp, Fp>; 3],
		fee: &AssignedCell<Fp, Fp>,
	) -> Result<(), Error> {
		layouter.assign_region(
			|| "balance",
			|mut region| {
				self.q_balance.enable(&mut region, 0)?;
				for (i, cell) in inputs.iter().chain(outputs.iter()).enumerate() {
					cell.copy_advice(|| "term", &mut region, self.shared.advices[i], 0)?;
				}
				fee.copy_advice(|| "fee", &mut region, self.shared.advices[0], 1)?;
				Ok(())
			},
		)
	}
}
