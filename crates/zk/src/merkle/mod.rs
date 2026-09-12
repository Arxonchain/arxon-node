//! Native reference Merkle tree (append-only, depth 32, tagged Poseidon).
//!
//! Used by tests as the oracle for the in-circuit path gadget and by the
//! runtime tests as the reference for the incremental on-chain tree.

use arxon_zk_primitives::{
	constants::tags,
	poseidon::{hash_merkle_member, hash_merkle_note},
	TREE_DEPTH,
};
use ff::Field;

use crate::{field::Fp, gadgets::merkle::MerklePath};

#[cfg(test)]
mod tests;

/// Which tagged hash a tree uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeKind {
	/// Note commitment tree.
	Note,
	/// Trust registry membership tree.
	Member,
}

impl TreeKind {
	/// Poseidon tag of this tree's node hash.
	pub const fn tag(self) -> u64 {
		match self {
			TreeKind::Note => tags::MERKLE_NOTE,
			TreeKind::Member => tags::MERKLE_MEMBER,
		}
	}

	/// Node hash.
	pub fn hash(self, left: Fp, right: Fp) -> Fp {
		match self {
			TreeKind::Note => hash_merkle_note(left, right),
			TreeKind::Member => hash_merkle_member(left, right),
		}
	}

	/// Hash of the empty subtree at each height (`0` = empty leaf).
	pub fn empty_hashes(self) -> [Fp; TREE_DEPTH + 1] {
		let mut out = [Fp::ZERO; TREE_DEPTH + 1];
		for h in 1..=TREE_DEPTH {
			out[h] = self.hash(out[h - 1], out[h - 1]);
		}
		out
	}

	/// Root of the empty tree.
	pub fn empty_root(self) -> Fp {
		self.empty_hashes()[TREE_DEPTH]
	}
}

/// Append-only Merkle tree that recomputes roots and paths naively (test oracle).
#[derive(Clone, Debug)]
pub struct ReferenceTree {
	kind: TreeKind,
	leaves: Vec<Fp>,
	empty: [Fp; TREE_DEPTH + 1],
}

impl ReferenceTree {
	/// An empty tree.
	pub fn new(kind: TreeKind) -> Self {
		ReferenceTree {
			kind,
			leaves: Vec::new(),
			empty: kind.empty_hashes(),
		}
	}

	/// Which tree this is.
	pub fn kind(&self) -> TreeKind {
		self.kind
	}

	/// Appends a leaf and returns its index.
	pub fn insert(&mut self, leaf: Fp) -> u64 {
		self.leaves.push(leaf);
		(self.leaves.len() - 1) as u64
	}

	/// Number of leaves.
	pub fn len(&self) -> usize {
		self.leaves.len()
	}

	/// `true` iff no leaf was inserted.
	pub fn is_empty(&self) -> bool {
		self.leaves.is_empty()
	}

	/// Node at `height` covering leaves `[index * 2^height, (index + 1) * 2^height)`.
	fn node(&self, height: usize, index: u64) -> Fp {
		let first_leaf = index << height;
		if first_leaf as usize >= self.leaves.len() {
			return self.empty[height];
		}
		if height == 0 {
			return self.leaves[first_leaf as usize];
		}
		self.kind.hash(
			self.node(height - 1, index * 2),
			self.node(height - 1, index * 2 + 1),
		)
	}

	/// Current root.
	pub fn root(&self) -> Fp {
		self.node(TREE_DEPTH, 0)
	}

	/// Authentication path of leaf `index`.
	pub fn path(&self, index: u64) -> MerklePath {
		let mut siblings = [Fp::ZERO; TREE_DEPTH];
		let mut bits = [false; TREE_DEPTH];
		let mut idx = index;
		for (level, (sib, bit)) in siblings.iter_mut().zip(bits.iter_mut()).enumerate() {
			*bit = idx & 1 == 1;
			*sib = self.node(level, idx ^ 1);
			idx >>= 1;
		}
		MerklePath { siblings, bits }
	}

	/// Recomputes the root from a leaf and a path (native check of the gadget's algorithm).
	pub fn root_from_path(kind: TreeKind, leaf: Fp, path: &MerklePath) -> Fp {
		let mut cur = leaf;
		for level in 0..TREE_DEPTH {
			let sib = path.siblings[level];
			cur = if path.bits[level] {
				kind.hash(sib, cur)
			} else {
				kind.hash(cur, sib)
			};
		}
		cur
	}
}
