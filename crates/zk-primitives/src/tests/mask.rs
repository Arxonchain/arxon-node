use crate::mask::*;

#[test]
fn mask_constants_match_frozen_packing() {
	assert_eq!(MASK_HIDE_SENDER, 1);
	assert_eq!(MASK_HIDE_RECEIVER, 2);
	assert_eq!(MASK_HIDE_AMOUNT, 4);
	assert_eq!(MASK_HIDE_BALANCE, 8);
}

#[test]
fn is_valid_mask_accepts_zero_through_fifteen() {
	for mask in 0u8..16 {
		assert!(is_valid_mask(mask), "mask {mask} must be valid");
	}
}

#[test]
fn is_valid_mask_rejects_sixteen_and_two_fifty_five() {
	assert!(!is_valid_mask(16));
	assert!(!is_valid_mask(255));
}

#[test]
fn mask_to_field_is_the_small_integer() {
	assert_eq!(mask_to_field(0b1010).0[0], 0b1010);
	assert!(mask_to_field(0b1010).0[1..].iter().all(|b| *b == 0));
}

#[test]
fn hide_predicates_read_their_own_bit_only() {
	assert!(hides_sender(0b0001) && !hides_sender(0b1110));
	assert!(hides_receiver(0b0010) && !hides_receiver(0b1101));
	assert!(hides_amount(0b0100) && !hides_amount(0b1011));
	assert!(hides_balance(0b1000) && !hides_balance(0b0111));
}

#[test]
fn revealed_count_ignores_the_balance_bit() {
	assert_eq!(revealed_count(0b0000), 3);
	assert_eq!(revealed_count(0b1000), 3);
	assert_eq!(revealed_count(0b0111), 0);
	assert_eq!(revealed_count(0b0101), 1);
}
