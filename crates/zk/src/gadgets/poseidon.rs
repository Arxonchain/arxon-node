//! Arxon-domain Poseidon hashing in-circuit, mirroring `arxon_zk_primitives::poseidon`.
//!
//! `hash_domain::<TAG, L>(message)` runs the `Pow5Chip<Fp, 3, 2>` sponge with
//! `P128Pow5T3` under `ArxonDomain<TAG, L>` (initial capacity `(L << 64) | TAG`),
//! absorbing the message then the domain's zero padding, exactly like the
//! native `sponge_hash`, so digests agree by construction. The tag never
//! enters the message, so a two-word hash is one permutation.

use arxon_zk_primitives::poseidon::ArxonDomain;
use halo2_gadgets::poseidon::{
	primitives::{Absorbing, Domain, P128Pow5T3},
	PaddedWord, Pow5Chip, Pow5Config, Sponge,
};
use halo2_proofs::{
	circuit::{AssignedCell, Layouter},
	plonk::{ConstraintSystem, Error},
};

use super::SharedColumns;
use crate::field::Fp;

/// Poseidon configuration over the shared column pool.
#[derive(Clone, Debug)]
pub struct PoseidonConfig {
	pow5: Pow5Config<Fp, 3, 2>,
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
		PoseidonConfig { pow5 }
	}

	/// `H_TAG(message)` for an `L`-word message.
	pub fn hash_domain<const TAG: u64, const L: usize>(
		&self,
		mut layouter: impl Layouter<Fp>,
		message: [AssignedCell<Fp, Fp>; L],
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		type Absorb = Absorbing<PaddedWord<Fp>, 2>;
		let chip = Chip::construct(self.pow5.clone());
		let mut sponge = Sponge::<Fp, Chip, P128Pow5T3, Absorb, ArxonDomain<TAG, L>, 3, 2>::new(
			chip,
			layouter.namespace(|| "poseidon init"),
		)?;
		let padding = <ArxonDomain<TAG, L> as Domain<Fp, 2>>::padding(L).map(PaddedWord::Padding);
		for (i, word) in message
			.into_iter()
			.map(PaddedWord::Message)
			.chain(padding)
			.enumerate()
		{
			sponge.absorb(layouter.namespace(|| format!("absorb {i}")), word)?;
		}
		let mut squeezing = sponge.finish_absorbing(layouter.namespace(|| "finish absorbing"))?;
		squeezing.squeeze(layouter.namespace(|| "squeeze"))
	}
}
