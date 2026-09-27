//! The Arxon circuits.
//!
//! [`WIRED`] lists the chain circuits that are implemented; the two macros
//! below iterate or dispatch over exactly that list. A test asserts the list
//! matches what the macros do, and the final test of Phase A asserts it
//! covers all six circuit ids, so a circuit cannot be half-wired silently.

pub mod c0_dummy;
pub mod c1_privacy_flags;
pub mod c2_balance;
pub mod c3_nullifier;
pub mod c4_ptr;
pub mod c5_disclosure;
pub mod c6_membership;
pub mod common;

use arxon_zk_primitives::CircuitId;

pub use c1_privacy_flags::{C1Circuit, C1Public, C1Witness};
pub use c2_balance::{C2Circuit, C2Public, C2Witness};
pub use c3_nullifier::{C3Circuit, C3Public, C3Witness};
pub use c4_ptr::{C4Circuit, C4Public, C4Witness, SpentNote};
pub use c5_disclosure::{C5Circuit, C5Public, C5Witness};
pub use c6_membership::{C6Circuit, C6Public, C6Witness};

/// Every chain circuit is implemented.
pub const WIRED: &[CircuitId] = &CircuitId::ALL;

/// Runs `$body` once per wired chain circuit type, binding it to `$c`.
#[macro_export]
macro_rules! for_each_chain_circuit {
	(|$c:ident| $body:block) => {{
		{
			type $c = $crate::circuits::C1Circuit;
			$body
		}
		{
			type $c = $crate::circuits::C2Circuit;
			$body
		}
		{
			type $c = $crate::circuits::C3Circuit;
			$body
		}
		{
			type $c = $crate::circuits::C4Circuit;
			$body
		}
		{
			type $c = $crate::circuits::C5Circuit;
			$body
		}
		{
			type $c = $crate::circuits::C6Circuit;
			$body
		}
	}};
}

/// Evaluates `$body` with `$c` bound to the circuit type of `$id`; errors with
/// `UnknownCircuit` for ids that are not wired.
#[macro_export]
macro_rules! dispatch_chain_circuit {
	($id:expr, |$c:ident| $body:expr) => {{
		let id: ::arxon_zk_primitives::CircuitId = $id;
		match id {
			::arxon_zk_primitives::CircuitId::PrivacyFlagEnforcement => {
				type $c = $crate::circuits::C1Circuit;
				$body
			}
			::arxon_zk_primitives::CircuitId::BalanceIntegrity => {
				type $c = $crate::circuits::C2Circuit;
				$body
			}
			::arxon_zk_primitives::CircuitId::NullifierDerivation => {
				type $c = $crate::circuits::C3Circuit;
				$body
			}
			::arxon_zk_primitives::CircuitId::PtrGeneration => {
				type $c = $crate::circuits::C4Circuit;
				$body
			}
			::arxon_zk_primitives::CircuitId::DisclosureProof => {
				type $c = $crate::circuits::C5Circuit;
				$body
			}
			::arxon_zk_primitives::CircuitId::TrustRegistryMembership => {
				type $c = $crate::circuits::C6Circuit;
				$body
			}
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
	fn frozen_vk_hashes_match_the_wired_circuits() {
		use crate::{circuit::ArxonCircuit, pins::vk_hash};
		crate::circuits::for_each_chain_circuit!(|C| {
			let id = <C as ArxonCircuit>::ID.expect("chain circuit");
			assert!(WIRED.contains(&id), "{id:?} wired by macro but not listed");
			assert_eq!(
				vk_hash::<C>(),
				arxon_zk_primitives::vk_hash(id),
				"frozen VK hash of {id:?} is stale"
			);
		});
		for id in CircuitId::ALL {
			assert_eq!(
				arxon_zk_primitives::vk_hashes::has_vk_hash(id),
				WIRED.contains(&id),
				"{id:?}"
			);
		}
	}

	#[test]
	fn warm_up_builds_keys_for_every_wired_circuit() {
		assert_eq!(crate::key_cache::warm_up(), Ok(()));

		assert!(crate::key_cache::cached_count() >= WIRED.len());
	}

	#[test]
	fn all_six_circuits_are_wired() {
		assert_eq!(WIRED, &CircuitId::ALL);
	}
}
