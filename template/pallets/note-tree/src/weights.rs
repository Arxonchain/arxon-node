//! Weights. Placeholders until `benchmark pallet` runs (plan Phase G1).

use frame_support::weights::Weight;

/// Weight functions of the pallet.
pub trait WeightInfo {
	/// `add_member` extrinsic: one insert.
	fn add_member() -> Weight;
	/// One tree insert (32 Poseidon permutations in Wasm plus about 70 storage ops).
	fn insert() -> Weight;
}

/// Placeholder: 20 ms of ref time per insert, generous proof size. Measured weights replace this.
impl WeightInfo for () {
	fn add_member() -> Weight {
		Self::insert()
	}

	fn insert() -> Weight {
		Weight::from_parts(20_000_000_000, 8_192)
	}
}
