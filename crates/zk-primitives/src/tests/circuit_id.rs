use scale_codec::{Decode, Encode};

use crate::{CircuitId, MAX_INSTANCES};

#[test]
fn circuit_id_roundtrips_through_u8_for_all_variants() {
	for id in CircuitId::ALL {
		let wire = id.as_u8();

		let back = CircuitId::try_from(wire);

		assert_eq!(back, Ok(id));
	}
}

#[test]
fn circuit_id_wire_values_are_one_to_six_in_order() {
	let wire: alloc::vec::Vec<u8> = CircuitId::ALL.iter().map(|id| id.as_u8()).collect();

	assert_eq!(wire, alloc::vec![1, 2, 3, 4, 5, 6]);
}

#[test]
fn circuit_id_rejects_zero() {
	assert_eq!(CircuitId::try_from(0u8), Err(()));
}

#[test]
fn circuit_id_rejects_seven_and_above() {
	assert_eq!(CircuitId::try_from(7u8), Err(()));
	assert_eq!(CircuitId::try_from(255u8), Err(()));
}

#[test]
fn circuit_id_scale_encoding_is_the_single_wire_byte() {
	for id in CircuitId::ALL {
		let encoded = id.encode();

		assert_eq!(encoded, alloc::vec![id.as_u8()]);
		assert_eq!(CircuitId::decode(&mut &encoded[..]), Ok(id));
	}
}

#[test]
fn circuit_id_index_is_zero_based_and_dense() {
	let indices: alloc::vec::Vec<usize> = CircuitId::ALL.iter().map(|id| id.index()).collect();

	assert_eq!(indices, alloc::vec![0, 1, 2, 3, 4, 5]);
}

#[test]
fn only_circuits_one_and_three_fold_multiple_instances() {
	assert_eq!(
		CircuitId::PrivacyFlagEnforcement.max_instances(),
		MAX_INSTANCES
	);
	assert_eq!(
		CircuitId::NullifierDerivation.max_instances(),
		MAX_INSTANCES
	);
	assert_eq!(CircuitId::BalanceIntegrity.max_instances(), 1);
	assert_eq!(CircuitId::PtrGeneration.max_instances(), 1);
	assert_eq!(CircuitId::DisclosureProof.max_instances(), 1);
	assert_eq!(CircuitId::TrustRegistryMembership.max_instances(), 1);
}
