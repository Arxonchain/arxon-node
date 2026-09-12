//! Tagged Poseidon hashing in-circuit, mirroring `arxon_zk_primitives::poseidon`.
//!
//! `hash_tagged_N(tag, m_1..m_N)` absorbs `[tag, m_1, ..., m_N]` through a
//! `ConstantLength<N + 1>` sponge on `Pow5Chip<Fp, 3, 2>` with `P128Pow5T3`,
//! exactly what the native side does, so digests agree by construction.

use halo2_gadgets::poseidon::{
	primitives::{ConstantLength, P128Pow5T3},
	Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
	circuit::{AssignedCell, Layouter},
	plonk::{ConstraintSystem, Error},
};

use super::{binding, SharedColumns};
use crate::field::Fp;

/// Poseidon configuration over the shared column pool.
#[derive(Clone, Debug)]
pub struct PoseidonConfig {
	pow5: Pow5Config<Fp, 3, 2>,
	shared: SharedColumns,
}

type Chip = Pow5Chip<Fp, 3, 2>;

impl PoseidonConfig {
	/// Uses `advices[0..3]` as state, `advices[3]` as partial s-box,
	/// `fixed[0..3]` as `rc_a` and `fixed[3..6]` as `rc_b`.
	pub fn configure(meta: &mut ConstraintSystem<Fp>, shared: &SharedColumns) -> Self {
		let state = [shared.advices[0], shared.advices[1], shared.advices[2]];
		let partial_sbox = shared.advices[3];
		let rc_a = [shared.fixed[0], shared.fixed[1], shared.fixed[2]];
		let rc_b = [shared.fixed[3], shared.fixed[4], shared.fixed[5]];
		let pow5 = Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);
		PoseidonConfig {
			pow5,
			shared: shared.clone(),
		}
	}

	fn tag_cell(
		&self,
		layouter: &mut impl Layouter<Fp>,
		tag: u64,
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		binding::constant(
			layouter,
			self.shared.advices[4],
			"poseidon tag",
			Fp::from(tag),
		)
	}
}

macro_rules! tagged_hash {
	($name:ident, $len:literal, $($m:ident),+) => {
		impl PoseidonConfig {
			/// Tagged Poseidon hash of the given message cells.
			pub fn $name(
				&self,
				mut layouter: impl Layouter<Fp>,
				tag: u64,
				$($m: AssignedCell<Fp, Fp>,)+
			) -> Result<AssignedCell<Fp, Fp>, Error> {
				let tag = self.tag_cell(&mut layouter, tag)?;
				let hasher = Hash::<Fp, Chip, P128Pow5T3, ConstantLength<$len>, 3, 2>::init(
					Chip::construct(self.pow5.clone()),
					layouter.namespace(|| "poseidon init"),
				)?;
				hasher.hash(layouter.namespace(|| "poseidon hash"), [tag, $($m),+])
			}
		}
	};
}

tagged_hash!(hash_tagged_1, 2, a);
tagged_hash!(hash_tagged_2, 3, a, b);
tagged_hash!(hash_tagged_3, 4, a, b, c);
tagged_hash!(hash_tagged_4, 5, a, b, c, d);
