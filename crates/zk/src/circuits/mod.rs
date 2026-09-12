//! The Arxon circuits.
//!
//! [`WIRED`] lists the chain circuits that are implemented; the two macros
//! below iterate or dispatch over exactly that list. A test asserts the list
//! matches what the macros do, and the final test of Phase A asserts it
//! covers all six circuit ids, so a circuit cannot be half-wired silently.

pub mod c0_dummy;

use arxon_zk_primitives::CircuitId;

/// Chain circuits implemented so far (plan Phase A5 grows this list).
pub const WIRED: &[CircuitId] = &[];

/// Runs `$body` once per wired chain circuit type, binding it to `$c`.
#[macro_export]
macro_rules! for_each_chain_circuit {
	(|$c:ident| $body:block) => {{
		// No chain circuit is wired yet. Each wired circuit adds a block:
		// { type $c = c1_privacy_flags::Circuit; $body }
	}};
}

/// Evaluates `$body` with `$c` bound to the circuit type of `$id`; errors with
/// `UnknownCircuit` for ids that are not wired.
#[macro_export]
macro_rules! dispatch_chain_circuit {
	($id:expr, |$c:ident| $body:expr) => {{
		let id: ::arxon_zk_primitives::CircuitId = $id;
		#[allow(unreachable_patterns)]
		match id {
			// Each wired circuit adds an arm:
			// CircuitId::PrivacyFlagEnforcement => { type $c = c1_privacy_flags::Circuit; $body }
			_ => Err($crate::error::VerifyError::UnknownCircuit(id.as_u8())),
		}
	}};
}

pub use dispatch_chain_circuit;
pub use for_each_chain_circuit;

#[cfg(test)]
mod tests {
	use arxon_zk_primitives::{CircuitId, FieldBytes};

	use super::WIRED;
	use crate::{error::VerifyError, verifier::verify_by_id};

	#[test]
	fn dispatch_reaches_every_wired_circuit_and_rejects_the_rest() {
		for id in CircuitId::ALL {
			let result = verify_by_id(id, &[], &[vec![FieldBytes::ZERO; id.public_input_len()]]);
			if WIRED.contains(&id) {
				assert_ne!(
					result,
					Err(VerifyError::UnknownCircuit(id.as_u8())),
					"{id:?} is wired but not dispatched"
				);
			} else {
				assert_eq!(
					result,
					Err(VerifyError::UnknownCircuit(id.as_u8())),
					"{id:?} is dispatched but not listed"
				);
			}
		}
	}

	#[test]
	fn warm_up_builds_keys_for_every_wired_circuit() {
		crate::key_cache::warm_up();

		assert_eq!(crate::key_cache::cached_count(), WIRED.len());
	}
}
