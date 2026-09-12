use alloc::vec::Vec;

use crate::{
	public_inputs::chain_id_row, C1PublicInputs, C2PublicInputs, C3PublicInputs, C4PublicInputs,
	C5PublicInputs, C6PublicInputs, CircuitId, FieldBytes, PublicInputLayout, RevealedFields,
	CHAIN_ID,
};

fn fb(byte: u8) -> FieldBytes {
	FieldBytes([byte; 32])
}

fn revealed() -> RevealedFields {
	RevealedFields {
		sender: fb(0xa1),
		receiver: fb(0xa2),
		amount: FieldBytes::from_u64(42),
	}
}

#[test]
fn chain_id_row_is_7171() {
	assert_eq!(chain_id_row(), FieldBytes::from_u64(7171));
	assert_eq!(CHAIN_ID, 7171);
}

#[test]
fn c1_public_inputs_to_elements_has_len_9_in_documented_order() {
	let c1 = C1PublicInputs::new(fb(1), fb(2), 0b1000, revealed(), fb(7), 100);

	let rows = c1.to_elements();

	assert_eq!(rows.len(), 9);
	assert_eq!(
		rows.len(),
		CircuitId::PrivacyFlagEnforcement.public_input_len()
	);
	assert_eq!(rows[0], fb(1), "cv");
	assert_eq!(rows[1], fb(2), "cm");
	assert_eq!(rows[2], FieldBytes::from_u8(0b1000), "mask");
	assert_eq!(rows[3], fb(0xa1), "revealed sender");
	assert_eq!(rows[4], fb(0xa2), "revealed receiver");
	assert_eq!(rows[5], FieldBytes::from_u64(42), "revealed amount");
	assert_eq!(rows[6], fb(7), "bundle digest");
	assert_eq!(rows[7], chain_id_row(), "chain id");
	assert_eq!(rows[8], FieldBytes::from_u32(100), "expiry block");
}

#[test]
fn c1_new_zeroes_revealed_fields_the_mask_hides() {
	let c1 = C1PublicInputs::new(fb(1), fb(2), 0b0101, revealed(), fb(7), 100);

	assert_eq!(
		c1.revealed.sender,
		FieldBytes::ZERO,
		"hidden sender must be zero"
	);
	assert_eq!(c1.revealed.receiver, fb(0xa2), "shown receiver kept");
	assert_eq!(
		c1.revealed.amount,
		FieldBytes::ZERO,
		"hidden amount must be zero"
	);
}

#[test]
fn c2_public_inputs_to_elements_has_len_10_in_documented_order() {
	let c2 = C2PublicInputs::new([fb(1), fb(2)], [fb(3), fb(4)], 10, 20, 0, fb(7), 100);

	let rows = c2.to_elements();

	assert_eq!(rows.len(), CircuitId::BalanceIntegrity.public_input_len());
	assert_eq!(&rows[..4], &[fb(1), fb(2), fb(3), fb(4)]);
	assert_eq!(rows[4], FieldBytes::from_u64(10), "transparent in");
	assert_eq!(rows[5], FieldBytes::from_u64(20), "transparent out");
	assert_eq!(rows[6], FieldBytes::ZERO, "fee");
	assert_eq!(rows[7], fb(7), "bundle digest");
	assert_eq!(rows[8], chain_id_row());
	assert_eq!(rows[9], FieldBytes::from_u32(100));
}

#[test]
fn c3_public_inputs_to_elements_has_len_6_in_documented_order() {
	let c3 = C3PublicInputs::new(fb(1), fb(2), fb(3), fb(7), 100);

	let rows = c3.to_elements();

	assert_eq!(
		rows.len(),
		CircuitId::NullifierDerivation.public_input_len()
	);
	assert_eq!(&rows[..4], &[fb(1), fb(2), fb(3), fb(7)]);
	assert_eq!(rows[4], chain_id_row());
	assert_eq!(rows[5], FieldBytes::from_u32(100));
}

#[test]
fn c4_public_inputs_to_elements_has_len_5_in_documented_order() {
	let c4 = C4PublicInputs::new(fb(1), fb(2), fb(7), 100);

	let rows = c4.to_elements();

	assert_eq!(rows.len(), CircuitId::PtrGeneration.public_input_len());
	assert_eq!(&rows[..3], &[fb(1), fb(2), fb(7)]);
	assert_eq!(rows[3], chain_id_row());
	assert_eq!(rows[4], FieldBytes::from_u32(100));
}

#[test]
fn c5_public_inputs_to_elements_has_len_8_in_documented_order() {
	let c5 = C5PublicInputs::new(fb(1), 0b0010, revealed(), fb(9), 100);

	let rows = c5.to_elements();

	assert_eq!(rows.len(), CircuitId::DisclosureProof.public_input_len());
	assert_eq!(rows[0], fb(1), "ptr id");
	assert_eq!(rows[1], FieldBytes::from_u8(0b0010), "disclosure mask");
	assert_eq!(rows[2], fb(0xa1), "sender shown");
	assert_eq!(rows[3], FieldBytes::ZERO, "receiver hidden");
	assert_eq!(rows[4], FieldBytes::from_u64(42), "amount shown");
	assert_eq!(rows[5], fb(9), "audience");
	assert_eq!(rows[6], chain_id_row());
	assert_eq!(rows[7], FieldBytes::from_u32(100));
}

#[test]
fn c6_public_inputs_to_elements_has_len_5_in_documented_order() {
	let c6 = C6PublicInputs::new(fb(1), fb(2), fb(7), 100);

	let rows = c6.to_elements();

	assert_eq!(
		rows.len(),
		CircuitId::TrustRegistryMembership.public_input_len()
	);
	assert_eq!(&rows[..3], &[fb(1), fb(2), fb(7)]);
	assert_eq!(rows[3], chain_id_row());
	assert_eq!(rows[4], FieldBytes::from_u32(100));
}

#[test]
fn every_layout_roundtrips_through_from_elements() {
	let c1 = C1PublicInputs::new(fb(1), fb(2), 0, revealed(), fb(7), 1);
	let c2 = C2PublicInputs::new([fb(1), fb(2)], [fb(3), fb(4)], 1, 2, 3, fb(7), 1);
	let c3 = C3PublicInputs::new(fb(1), fb(2), fb(3), fb(7), 1);
	let c4 = C4PublicInputs::new(fb(1), fb(2), fb(7), 1);
	let c5 = C5PublicInputs::new(fb(1), 0, revealed(), fb(9), 1);
	let c6 = C6PublicInputs::new(fb(1), fb(2), fb(7), 1);

	assert_eq!(C1PublicInputs::from_elements(&c1.to_elements()), Some(c1));
	assert_eq!(C2PublicInputs::from_elements(&c2.to_elements()), Some(c2));
	assert_eq!(C3PublicInputs::from_elements(&c3.to_elements()), Some(c3));
	assert_eq!(C4PublicInputs::from_elements(&c4.to_elements()), Some(c4));
	assert_eq!(C5PublicInputs::from_elements(&c5.to_elements()), Some(c5));
	assert_eq!(C6PublicInputs::from_elements(&c6.to_elements()), Some(c6));
}

#[test]
fn from_elements_rejects_wrong_length() {
	let too_short: Vec<FieldBytes> = alloc::vec![fb(1); 4];
	let too_long: Vec<FieldBytes> = alloc::vec![fb(1); 11];

	assert_eq!(C1PublicInputs::from_elements(&too_short), None);
	assert_eq!(C1PublicInputs::from_elements(&too_long), None);
	assert_eq!(C2PublicInputs::from_elements(&too_short), None);
	assert_eq!(C3PublicInputs::from_elements(&too_short), None);
	assert_eq!(C4PublicInputs::from_elements(&too_short), None);
	assert_eq!(C5PublicInputs::from_elements(&too_short), None);
	assert_eq!(C6PublicInputs::from_elements(&too_short), None);
}

#[test]
fn layout_len_constants_match_circuit_id_table() {
	assert_eq!(
		C1PublicInputs::LEN,
		CircuitId::PrivacyFlagEnforcement.public_input_len()
	);
	assert_eq!(
		C2PublicInputs::LEN,
		CircuitId::BalanceIntegrity.public_input_len()
	);
	assert_eq!(
		C3PublicInputs::LEN,
		CircuitId::NullifierDerivation.public_input_len()
	);
	assert_eq!(
		C4PublicInputs::LEN,
		CircuitId::PtrGeneration.public_input_len()
	);
	assert_eq!(
		C5PublicInputs::LEN,
		CircuitId::DisclosureProof.public_input_len()
	);
	assert_eq!(
		C6PublicInputs::LEN,
		CircuitId::TrustRegistryMembership.public_input_len()
	);
}
