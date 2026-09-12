//! Depth-32 Merkle inclusion path over tagged Poseidon.
//!
//! Per level, with `bit` the position bit (0: current node is the left child):
//! `bit * (bit - 1) = 0`, `left = cur + bit * (sib - cur)`, `right = sib + bit * (cur - sib)`,
//! then `next = H_tag(left, right)`.

use arxon_zk_primitives::TREE_DEPTH;
use halo2_proofs::{
	circuit::{AssignedCell, Layouter, Value},
	plonk::{ConstraintSystem, Constraints, Error, Expression, Selector},
	poly::Rotation,
};

use super::{poseidon::PoseidonConfig, SharedColumns};
use crate::field::Fp;

/// A Merkle authentication path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
	/// Sibling at each level, leaf level first.
	pub siblings: [Fp; TREE_DEPTH],
	/// Position bit at each level, leaf level first (`true` = current node is the right child).
	pub bits: [bool; TREE_DEPTH],
}

impl MerklePath {
	/// Leaf index encoded by the position bits.
	pub fn leaf_index(&self) -> u64 {
		self.bits
			.iter()
			.rev()
			.fold(0u64, |acc, b| (acc << 1) | u64::from(*b))
	}
}

/// The path as the circuit witnesses it: position bits are field elements, so
/// tests can feed a non-boolean bit and watch the boolean gate reject it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathWitness {
	/// Sibling at each level, leaf level first.
	pub siblings: [Fp; TREE_DEPTH],
	/// Position bit at each level as `0` or `1`.
	pub bits: [Fp; TREE_DEPTH],
}

impl From<&MerklePath> for PathWitness {
	fn from(path: &MerklePath) -> Self {
		PathWitness {
			siblings: path.siblings,
			bits: path.bits.map(Fp::from),
		}
	}
}

/// Merkle path configuration (swap gate plus a Poseidon config).
#[derive(Clone, Debug)]
pub struct MerkleConfig {
	q_swap: Selector,
	poseidon: PoseidonConfig,
	shared: SharedColumns,
}

impl MerkleConfig {
	/// Uses `advices[0..5]` for `(cur, sib, bit, left, right)`.
	pub fn configure(
		meta: &mut ConstraintSystem<Fp>,
		shared: &SharedColumns,
		poseidon: &PoseidonConfig,
	) -> Self {
		let q_swap = meta.selector();
		meta.create_gate("merkle swap", |meta| {
			let q = meta.query_selector(q_swap);
			let cur = meta.query_advice(shared.advices[0], Rotation::cur());
			let sib = meta.query_advice(shared.advices[1], Rotation::cur());
			let bit = meta.query_advice(shared.advices[2], Rotation::cur());
			let left = meta.query_advice(shared.advices[3], Rotation::cur());
			let right = meta.query_advice(shared.advices[4], Rotation::cur());
			let one = Expression::Constant(Fp::from(1));
			Constraints::with_selector(
				q,
				[
					("bit is boolean", bit.clone() * (bit.clone() - one)),
					(
						"left child",
						cur.clone() + bit.clone() * (sib.clone() - cur.clone()) - left,
					),
					("right child", sib.clone() + bit * (cur - sib) - right),
				],
			)
		});
		MerkleConfig {
			q_swap,
			poseidon: poseidon.clone(),
			shared: shared.clone(),
		}
	}

	/// Computes the root from `leaf` along `path`, hashing nodes with `tag`.
	pub fn root(
		&self,
		layouter: &mut impl Layouter<Fp>,
		tag: u64,
		leaf: AssignedCell<Fp, Fp>,
		path: Value<&PathWitness>,
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		let mut cur = leaf;
		for level in 0..TREE_DEPTH {
			let sib = path.map(|p| p.siblings[level]);
			let bit = path.map(|p| p.bits[level]);
			let (left, right) = layouter.assign_region(
				|| format!("merkle level {level}"),
				|mut region| {
					self.q_swap.enable(&mut region, 0)?;
					cur.copy_advice(|| "cur", &mut region, self.shared.advices[0], 0)?;
					region.assign_advice(|| "sib", self.shared.advices[1], 0, || sib)?;
					region.assign_advice(|| "bit", self.shared.advices[2], 0, || bit)?;
					let swap = cur.value().zip(sib).zip(bit).map(|((c, s), b)| {
						if b == Fp::from(1) {
							(s, *c)
						} else {
							(*c, s)
						}
					});
					let left = region.assign_advice(
						|| "left",
						self.shared.advices[3],
						0,
						|| swap.map(|(l, _)| l),
					)?;
					let right = region.assign_advice(
						|| "right",
						self.shared.advices[4],
						0,
						|| swap.map(|(_, r)| r),
					)?;
					Ok((left, right))
				},
			)?;
			cur = self.poseidon.hash_tagged_2(
				layouter.namespace(|| format!("merkle hash {level}")),
				tag,
				left,
				right,
			)?;
		}
		Ok(cur)
	}
}
