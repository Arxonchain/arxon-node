//! Configuration and synthesis helpers shared by the chain circuits.

use arxon_zk_primitives::CHAIN_ID;
use halo2_proofs::{
	circuit::{AssignedCell, Layouter, Value},
	plonk::{ConstraintSystem, Error},
};

use crate::{
	field::Fp,
	gadgets::{
		balance::BalanceConfig, binding, mask::MaskConfig, merkle::MerkleConfig,
		poseidon::PoseidonConfig, range64::Range64Config, reveal::RevealConfig, SharedColumns,
	},
};

/// Every gadget a chain circuit may use, over one shared column pool.
#[derive(Clone, Debug)]
pub struct CircuitConfig {
	/// Column pool.
	pub shared: SharedColumns,
	/// Poseidon sponge.
	pub poseidon: PoseidonConfig,
	/// Four-flag mask lookup.
	pub mask: MaskConfig,
	/// 64-bit range check.
	pub range: Range64Config,
	/// Selective reveal gate.
	pub reveal: RevealConfig,
	/// Merkle path (unused by circuits without a tree; costs no rows then).
	pub merkle: MerkleConfig,
	/// Circuit 2 conservation gate.
	pub balance: BalanceConfig,
}

impl CircuitConfig {
	/// Configures every gadget.
	pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
		let shared = SharedColumns::configure(meta);
		let poseidon = PoseidonConfig::configure(meta, &shared);
		let mask = MaskConfig::configure(meta, &shared);
		let range = Range64Config::configure(meta, &shared);
		let reveal = RevealConfig::configure(meta, &shared);
		let merkle = MerkleConfig::configure(meta, &shared, &poseidon);
		let balance = BalanceConfig::configure(meta, &shared);
		CircuitConfig {
			shared,
			poseidon,
			mask,
			range,
			reveal,
			merkle,
			balance,
		}
	}

	/// Loads the lookup tables. Must run once per synthesis, before any lookup.
	pub fn load_tables(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
		self.mask.load(layouter)?;
		self.range.load(layouter)
	}

	/// Witnesses a private field element.
	pub fn witness(
		&self,
		layouter: &mut impl Layouter<Fp>,
		name: &'static str,
		value: Value<Fp>,
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		binding::witness(layouter, self.shared.advices[5], name, value)
	}

	/// Witnesses a `u64` as a field element.
	pub fn witness_u64(
		&self,
		layouter: &mut impl Layouter<Fp>,
		name: &'static str,
		value: Value<u64>,
	) -> Result<AssignedCell<Fp, Fp>, Error> {
		self.witness(layouter, name, value.map(Fp::from))
	}

	/// Copy-constrains `cell` to instance `row`.
	pub fn expose(
		&self,
		layouter: &mut impl Layouter<Fp>,
		cell: &AssignedCell<Fp, Fp>,
		row: usize,
	) -> Result<(), Error> {
		binding::expose(layouter, cell, self.shared.instance, row)
	}

	/// Exposes the three trailing binding rows every chain circuit ends with:
	/// `bundle_digest` (witness), `chain_id` (fixed constant), `expiry_block` (witness).
	pub fn expose_binding_rows(
		&self,
		layouter: &mut impl Layouter<Fp>,
		first_row: usize,
		bundle_digest: Value<Fp>,
		expiry_block: Value<u64>,
	) -> Result<(), Error> {
		let column = self.shared.advices[5];
		let instance = self.shared.instance;
		binding::expose_witness(
			layouter,
			column,
			instance,
			first_row,
			"bundle digest",
			bundle_digest,
		)?;
		binding::expose_constant(
			layouter,
			column,
			instance,
			first_row + 1,
			"chain id",
			Fp::from(CHAIN_ID),
		)?;
		binding::expose_witness(
			layouter,
			column,
			instance,
			first_row + 2,
			"expiry block",
			expiry_block.map(Fp::from),
		)?;
		Ok(())
	}
}

/// The three trailing rows as field elements, for `PublicRows` implementations.
pub fn binding_rows(bundle_digest: Fp, expiry_block: u32) -> [Fp; 3] {
	[
		bundle_digest,
		Fp::from(CHAIN_ID),
		Fp::from(expiry_block as u64),
	]
}
