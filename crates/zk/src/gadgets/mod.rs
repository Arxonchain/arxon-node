//! Reusable in-circuit gadgets shared by the Arxon circuits.
//!
//! Every gadget owns its selectors and lookup tables but borrows advice and
//! fixed columns from a [`SharedColumns`] pool, so circuits stay narrow (proof
//! size grows with columns, not with rows).
//!
//! Invariant: the layout of every gadget (which rows get which selectors) must
//! not depend on witness values. halo2 compresses selectors from the
//! witness-less circuit used at key generation; a circuit that branched on a
//! `Value` would prove against a layout its verifying key never saw.
//! Prover-side computations must therefore live inside `Value::map`, never in
//! control flow.

pub mod balance;
pub mod binding;
pub mod mask;
pub mod merkle;
pub mod poseidon;
pub mod range64;
pub mod reveal;

#[cfg(test)]
mod tests;

use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed, Instance};

use crate::field::Fp;

/// Number of advice columns in the shared pool. Pow5 needs 4 (3 state + partial
/// s-box); the widest other gadget (Merkle level) needs 5.
pub const NUM_ADVICE: usize = 6;
/// Fixed columns: 3 `rc_a` + 3 `rc_b` for Pow5; `rc_b[0]` also carries constants.
pub const NUM_FIXED: usize = 6;

/// Columns shared by every gadget of a circuit.
#[derive(Clone, Debug)]
pub struct SharedColumns {
	/// Advice pool.
	pub advices: [Column<Advice>; NUM_ADVICE],
	/// Fixed pool (Poseidon round constants; `fixed[3]` is the constants column).
	pub fixed: [Column<Fixed>; NUM_FIXED],
	/// The single instance column.
	pub instance: Column<Instance>,
}

impl SharedColumns {
	/// Allocates the pool, enabling equality on every advice column and the
	/// instance column, and constants on `fixed[3]` (Pow5's `rc_b[0]`).
	pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
		let advices = [(); NUM_ADVICE].map(|_| meta.advice_column());
		let fixed = [(); NUM_FIXED].map(|_| meta.fixed_column());
		let instance = meta.instance_column();
		for a in advices {
			meta.enable_equality(a);
		}
		meta.enable_equality(instance);
		meta.enable_constant(fixed[3]);
		SharedColumns {
			advices,
			fixed,
			instance,
		}
	}

	/// The fixed column that carries constants.
	pub fn constants(&self) -> Column<Fixed> {
		self.fixed[3]
	}
}
