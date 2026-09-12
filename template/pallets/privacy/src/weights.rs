//! Weights. Placeholders until `benchmark pallet` runs through the node (plan Phase G1).

use frame_support::weights::Weight;

/// Weight functions of the pallet.
pub trait WeightInfo {
	/// `set_privacy_default`.
	fn set_privacy_default() -> Weight;
	/// `set_balance_visibility`.
	fn set_balance_visibility() -> Weight;
	/// `register_shielded_key`.
	fn register_shielded_key() -> Weight;
	/// `shield` with `outputs` notes.
	fn shield(outputs: u32) -> Weight;
	/// `unshield` with `inputs` spent notes and `outputs` change notes.
	fn unshield(inputs: u32, outputs: u32) -> Weight;
	/// `submit_private_transfer` with `inputs` spent and `outputs` created notes.
	fn submit_private_transfer(inputs: u32, outputs: u32) -> Weight;
}

/// One proof verification (host function, per instance): 20 ms of ref time.
const VERIFY: u64 = 20_000_000_000;
/// One note tree insert (32 Poseidon permutations in Wasm): 20 ms of ref time.
const INSERT: u64 = 20_000_000_000;
/// Storage and bookkeeping per call.
const BASE: u64 = 50_000_000;

fn bundle(inputs: u32, outputs: u32) -> Weight {
	// C3 per input, C1 per output, C2 once, one insert per output.
	let verifications = (inputs + outputs + 1) as u64;
	Weight::from_parts(
		BASE + VERIFY * verifications + INSERT * outputs as u64,
		16_384 + 4_096 * (inputs + outputs) as u64,
	)
}

impl WeightInfo for () {
	fn set_privacy_default() -> Weight {
		Weight::from_parts(BASE, 1_024)
	}

	fn set_balance_visibility() -> Weight {
		Weight::from_parts(BASE, 1_024)
	}

	fn register_shielded_key() -> Weight {
		Weight::from_parts(BASE, 2_048)
	}

	fn shield(outputs: u32) -> Weight {
		bundle(0, outputs)
	}

	fn unshield(inputs: u32, outputs: u32) -> Weight {
		bundle(inputs, outputs)
	}

	fn submit_private_transfer(inputs: u32, outputs: u32) -> Weight {
		bundle(inputs, outputs)
	}
}
