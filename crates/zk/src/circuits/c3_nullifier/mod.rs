//! Circuit 3: NullifierDerivation, one instance per spent note.
//!
//! Proves the spender owns a note in the tree and derives its nullifier:
//!
//! * `pk = H_PK(sk)`, `nk = H_NK(sk)`, `cm = H_NOTE(pk, amount, rho)`, `amount < 2^64`;
//! * `cm` is a leaf of the note tree under `anchor` (depth-32 Poseidon path);
//! * `nullifier = H_NF(nk, cm)`;
//! * `cv = H_CV(amount, blinding)` with a fresh blinding, so Circuit 2 can
//!   consume the spent amount without learning which note was spent;
//! * `revealed_sender` is `pk` or zero according to the bundle mask (the
//!   proven spend key is the only honest "sender");
//! * `bundle_digest`, `chain_id` (fixed constant) and `expiry_block` are bound.

use arxon_zk_primitives::{
	constants::tags,
	mask::hides_sender,
	poseidon::{hash_cv, hash_nk, hash_note, hash_nullifier, hash_pk},
	CircuitId, NOTE_TREE_DEPTH,
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
	merkle::{NoteTree, TreeKind},
};

#[cfg(test)]
mod tests;

/// Instance rows.
pub mod rows {
	/// `anchor`.
	pub const ANCHOR: usize = 0;
	/// `nullifier`.
	pub const NULLIFIER: usize = 1;
	/// `cv`.
	pub const CV: usize = 2;
	/// `mask`.
	pub const MASK: usize = 3;
	/// `revealed_sender`.
	pub const REVEALED_SENDER: usize = 4;
	/// `bundle_digest`.
	pub const BUNDLE_DIGEST: usize = 5;
	/// `chain_id`.
	pub const CHAIN_ID: usize = 6;
	/// `expiry_block`.
	pub const EXPIRY_BLOCK: usize = 7;
	/// Row count.
	pub const LEN: usize = 8;
}

/// Everything the prover knows about one spent note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C3Witness {
	/// Spending key.
	pub sk: Fp,
	/// Note amount in shielded units.
	pub amount: u64,
	/// Note randomness.
	pub rho: Fp,
	/// Fresh blinding for the exposed value commitment.
	pub blinding: Fp,
	/// Four-flag mask of the bundle.
	pub mask: u8,
	/// Authentication path of `cm` in the note tree.
	pub path: MerklePath<NOTE_TREE_DEPTH>,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl C3Witness {
	/// `pk = H_PK(sk)`.
	pub fn pk(&self) -> Fp {
		hash_pk(self.sk)
	}

	/// `cm = H_NOTE(pk, amount, rho)`.
	pub fn cm(&self) -> Fp {
		hash_note(self.pk(), self.amount, self.rho)
	}

	/// `nf = H_NF(nk, cm)`.
	pub fn nullifier(&self) -> Fp {
		hash_nullifier(hash_nk(self.sk), self.cm())
	}

	/// Root the path opens to.
	pub fn anchor(&self) -> Fp {
		NoteTree::root_from_path(TreeKind::Note, self.cm(), &self.path)
	}
}

/// Public rows of one instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C3Public {
	/// Note tree root.
	pub anchor: Fp,
	/// Nullifier.
	pub nullifier: Fp,
	/// Fresh value commitment.
	pub cv: Fp,
	/// Mask.
	pub mask: Fp,
	/// `pk` or zero.
	pub revealed_sender: Fp,
	/// Bundle digest.
	pub bundle_digest: Fp,
	/// Expiry block.
	pub expiry_block: u32,
}

impl PublicRows for C3Public {
	const LEN: usize = rows::LEN;

	fn to_rows(&self) -> Vec<Fp> {
		let [digest, chain, expiry] = binding_rows(self.bundle_digest, self.expiry_block);
		vec![
			self.anchor,
			self.nullifier,
			self.cv,
			self.mask,
			self.revealed_sender,
			digest,
			chain,
			expiry,
		]
	}
}

/// The circuit.
#[derive(Clone, Debug)]
pub struct C3Circuit {
	sk: Value<Fp>,
	amount: Value<Fp>,
	rho: Value<Fp>,
	blinding: Value<Fp>,
	mask: Value<u8>,
	path: Value<PathWitness<NOTE_TREE_DEPTH>>,
	bundle_digest: Value<Fp>,
	expiry_block: Value<u64>,
}

impl Default for C3Circuit {
	fn default() -> Self {
		C3Circuit {
			sk: Value::unknown(),
			amount: Value::unknown(),
			rho: Value::unknown(),
			blinding: Value::unknown(),
			mask: Value::unknown(),
			path: Value::unknown(),
			bundle_digest: Value::unknown(),
			expiry_block: Value::unknown(),
		}
	}
}

impl C3Circuit {
	/// A circuit with a raw path witness (non-boolean bits allowed), for tests.
	#[cfg(test)]
	pub fn with_raw_path(w: &C3Witness, path: PathWitness<NOTE_TREE_DEPTH>) -> Self {
		let mut circuit = Self::from_witness(w);
		circuit.path = Value::known(path);
		circuit
	}

	/// A circuit with a raw field-element amount, for range tests.
	#[cfg(test)]
	pub fn with_raw_amount(w: &C3Witness, amount: Fp) -> Self {
		let mut circuit = Self::from_witness(w);
		circuit.amount = Value::known(amount);
		circuit
	}
}

impl Circuit<Fp> for C3Circuit {
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

		let bits = cfg.mask.assign(&mut layouter, self.mask)?;
		let sk = cfg.witness(&mut layouter, "sk", self.sk)?;
		let amount = cfg.witness(&mut layouter, "amount", self.amount)?;
		let rho = cfg.witness(&mut layouter, "rho", self.rho)?;
		let blinding = cfg.witness(&mut layouter, "blinding", self.blinding)?;

		cfg.range.check(&mut layouter, &amount)?;
		let pk = cfg
			.poseidon
			.hash_domain::<{ tags::PK }, 1>(layouter.namespace(|| "pk"), [sk.clone()])?;
		let nk = cfg
			.poseidon
			.hash_domain::<{ tags::NK }, 1>(layouter.namespace(|| "nk"), [sk])?;
		let cm = cfg.poseidon.hash_domain::<{ tags::NOTE }, 3>(
			layouter.namespace(|| "cm"),
			[pk.clone(), amount.clone(), rho],
		)?;
		let anchor = cfg.merkle.root::<{ tags::MERKLE_NOTE }, NOTE_TREE_DEPTH>(
			&mut layouter,
			cm.clone(),
			self.path.as_ref(),
		)?;
		let nullifier = cfg
			.poseidon
			.hash_domain::<{ tags::NULLIFIER }, 2>(layouter.namespace(|| "nf"), [nk, cm])?;
		let cv = cfg
			.poseidon
			.hash_domain::<{ tags::CV }, 2>(layouter.namespace(|| "cv"), [amount, blinding])?;
		let revealed_sender = cfg.reveal.reveal(&mut layouter, bits.hide_sender(), &pk)?;

		cfg.expose(&mut layouter, &anchor, rows::ANCHOR)?;
		cfg.expose(&mut layouter, &nullifier, rows::NULLIFIER)?;
		cfg.expose(&mut layouter, &cv, rows::CV)?;
		cfg.expose(&mut layouter, &bits.mask, rows::MASK)?;
		cfg.expose(&mut layouter, &revealed_sender, rows::REVEALED_SENDER)?;
		cfg.expose_binding_rows(
			&mut layouter,
			rows::BUNDLE_DIGEST,
			self.bundle_digest,
			self.expiry_block,
		)
	}
}

impl ArxonCircuit for C3Circuit {
	const ID: Option<CircuitId> = Some(CircuitId::NullifierDerivation);
	const K: u32 = 11;
	const NAME: &'static str = "C3 NullifierDerivation";
	const PROOF_LENGTHS: &'static [usize] = &[3584, 5088];
	type Witness = C3Witness;
	type Public = C3Public;

	fn from_witness(w: &C3Witness) -> Self {
		C3Circuit {
			sk: Value::known(w.sk),
			amount: Value::known(Fp::from(w.amount)),
			rho: Value::known(w.rho),
			blinding: Value::known(w.blinding),
			mask: Value::known(w.mask),
			path: Value::known(PathWitness::from(&w.path)),
			bundle_digest: Value::known(w.bundle_digest),
			expiry_block: Value::known(w.expiry_block as u64),
		}
	}

	fn public_from_witness(w: &C3Witness) -> C3Public {
		C3Public {
			anchor: w.anchor(),
			nullifier: w.nullifier(),
			cv: hash_cv(w.amount, w.blinding),
			mask: Fp::from(w.mask as u64),
			revealed_sender: if hides_sender(w.mask) {
				Fp::from(0)
			} else {
				w.pk()
			},
			bundle_digest: w.bundle_digest,
			expiry_block: w.expiry_block,
		}
	}
}
