//! Weights. Placeholders until `benchmark pallet` runs through the node (plan Phase G1).

use frame_support::weights::Weight;

/// Weight functions of the pallet.
pub trait WeightInfo {
	/// Recording one receipt commitment.
	fn record() -> Weight;
	/// `disclose`: one Circuit 5 verification plus bookkeeping.
	fn disclose() -> Weight;
}

impl WeightInfo for () {
	fn record() -> Weight {
		Weight::from_parts(50_000_000, 2_048)
	}

	fn disclose() -> Weight {
		Weight::from_parts(20_050_000_000, 8_192)
	}
}
