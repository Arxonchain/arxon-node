//! Circuit 6: TrustRegistryMembership.
//!
//! Proves that the recipient of an output note is a regulated counterparty:
//! `leaf = H_MEMBER(pk_member)` is in the membership tree under `registry_root`
//! (depth 16, its own Poseidon tag, a different tree from the anti-rug registry
//! at pallet index 16) and `cm = H_NOTE(pk_member, amount, rho)` is one of the
//! bundle's output commitments (the pallet checks that). The member's identity
//! stays private.

use arxon_zk_primitives::{
	constants::tags,
	poseidon::{hash_member_leaf, hash_note},
	CircuitId, MEMBER_TREE_DEPTH,
};
use halo2_proofs::{
	circuit::{Layouter, SimpleFloorPlanner, Value},
	plonk::{Circuit, ConstraintSystem, Error},
};

use super::common::{binding_rows, CircuitConfig};
use crate::{
	circuit::{ArxonCircuit, PublicRows},
	field::Fp,
	gadgets::merkle::{MerklePath, PathWitness},
	merkle::{MemberTree, TreeKind},
};

#[cfg(test)]
mod tests;

/// Instance rows.
pub mod rows {
	/// `registry_root`.
	pub const REGISTRY_ROOT: usize = 0;
	/// `cm`.
	pub const CM: usize = 1;
	/// `bundle_digest`.
	pub const BUNDLE_DIGEST: usize = 2;
	/// `chain_id`.
	pub const CHAIN_ID: usize = 3;
	/// `expiry_block`.
	pub const EXPIRY_BLOCK: usize = 4;
	/// Row count.
	pub const LEN: usize = 5;
}

/// Everything the prover knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6Witness {
	/// The regulated counterparty's shielded public key.
	pub pk_member: Fp,
	/// Amount of the output note paid to the member.
	pub amount: u64,
	/// Randomness of that note.
	pub rho: Fp,
	/// Path of `H_MEMBER(pk_member)` in the membership tree.
	pub path: MerklePath<MEMBER_TREE_DEPTH>,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl C6Witness {
	/// `leaf = H_MEMBER(pk_member)`.
	pub fn leaf(&self) -> Fp {
		hash_member_leaf(self.pk_member)
	}

	/// Root the path opens to.
	pub fn registry_root(&self) -> Fp {
		MemberTree::root_from_path(TreeKind::Member, self.leaf(), &self.path)
	}

	/// `cm = H_NOTE(pk_member, amount, rho)`.
	pub fn cm(&self) -> Fp {
		hash_note(self.pk_member, self.amount, self.rho)
	}
}

/// Public rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6Public {
	/// Membership tree root.
	pub registry_root: Fp,
	/// Output note commitment.
	pub cm: Fp,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl PublicRows for C6Public {
	const LEN: usize = rows::LEN;

	fn to_rows(&self) -> Vec<Fp> {
		let [digest, chain, expiry] = binding_rows(self.bundle_digest, self.expiry_block);
		vec![self.registry_root, self.cm, digest, chain, expiry]
	}
}

/// The circuit.
#[derive(Clone, Debug)]
pub struct C6Circuit {
	pk_member: Value<Fp>,
	amount: Value<Fp>,
	rho: Value<Fp>,
	path: Value<PathWitness<MEMBER_TREE_DEPTH>>,
	bundle_digest: Value<Fp>,
	expiry_block: Value<u64>,
}

impl Default for C6Circuit {
	fn default() -> Self {
		C6Circuit {
			pk_member: Value::unknown(),
			amount: Value::unknown(),
			rho: Value::unknown(),
			path: Value::unknown(),
			bundle_digest: Value::unknown(),
			expiry_block: Value::unknown(),
		}
	}
}

impl Circuit<Fp> for C6Circuit {
	type Config = CircuitConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		CircuitConfig::configure(meta)
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		cfg.load_tables(&mut layouter)?;

		let pk_member = cfg.witness(&mut layouter, "pk_member", self.pk_member)?;
		let amount = cfg.witness(&mut layouter, "amount", self.amount)?;
		let rho = cfg.witness(&mut layouter, "rho", self.rho)?;

		let leaf = cfg.poseidon.hash_domain::<{ tags::MEMBER_LEAF }, 1>(
			layouter.namespace(|| "leaf"),
			[pk_member.clone()],
		)?;
		let root = cfg
			.merkle
			.root::<{ tags::MERKLE_MEMBER }, MEMBER_TREE_DEPTH>(
				&mut layouter,
				leaf,
				self.path.as_ref(),
			)?;
		let cm = cfg.poseidon.hash_domain::<{ tags::NOTE }, 3>(
			layouter.namespace(|| "cm"),
			[pk_member, amount, rho],
		)?;

		cfg.expose(&mut layouter, &root, rows::REGISTRY_ROOT)?;
		cfg.expose(&mut layouter, &cm, rows::CM)?;
		cfg.expose_binding_rows(
			&mut layouter,
			rows::BUNDLE_DIGEST,
			self.bundle_digest,
			self.expiry_block,
		)
	}
}

impl ArxonCircuit for C6Circuit {
	const ID: Option<CircuitId> = Some(CircuitId::TrustRegistryMembership);
	const K: u32 = 10;
	const NAME: &'static str = "C6 TrustRegistryMembership";
	const PROOF_LENGTHS: &'static [usize] = &[3520];
	type Witness = C6Witness;
	type Public = C6Public;

	fn from_witness(w: &C6Witness) -> Self {
		C6Circuit {
			pk_member: Value::known(w.pk_member),
			amount: Value::known(Fp::from(w.amount)),
			rho: Value::known(w.rho),
			path: Value::known(PathWitness::from(&w.path)),
			bundle_digest: Value::known(w.bundle_digest),
			expiry_block: Value::known(w.expiry_block as u64),
		}
	}

	fn public_from_witness(w: &C6Witness) -> C6Public {
		C6Public {
			registry_root: w.registry_root(),
			cm: w.cm(),
			bundle_digest: w.bundle_digest,
			expiry_block: w.expiry_block,
		}
	}
}
