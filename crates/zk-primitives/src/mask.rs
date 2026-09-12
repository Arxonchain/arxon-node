//! The frozen four-flag privacy mask packing.
//!
//! This restates `PrivacyMask::as_bits` from `pallet-privacy`; a test in that
//! pallet asserts both agree. Do not reorder.

use crate::field_bytes::FieldBytes;

/// bit 0: hide the sender.
pub const MASK_HIDE_SENDER: u8 = 1 << 0;
/// bit 1: hide the receiver.
pub const MASK_HIDE_RECEIVER: u8 = 1 << 1;
/// bit 2: hide the amount.
pub const MASK_HIDE_AMOUNT: u8 = 1 << 2;
/// bit 3: hide the balance.
pub const MASK_HIDE_BALANCE: u8 = 1 << 3;
/// Every valid mask is `<= MASK_ALL`.
pub const MASK_ALL: u8 = 0b1111;
/// Number of valid masks (rows of the in-circuit lookup table).
pub const MASK_TABLE_ROWS: usize = 16;

/// `true` iff only the four defined bits are set.
pub const fn is_valid_mask(mask: u8) -> bool {
	mask & !MASK_ALL == 0
}

/// `Fp::from(mask)`.
pub const fn mask_to_field(mask: u8) -> FieldBytes {
	FieldBytes::from_u8(mask)
}

/// `true` iff bit 0 is set.
pub const fn hides_sender(mask: u8) -> bool {
	mask & MASK_HIDE_SENDER != 0
}

/// `true` iff bit 1 is set.
pub const fn hides_receiver(mask: u8) -> bool {
	mask & MASK_HIDE_RECEIVER != 0
}

/// `true` iff bit 2 is set.
pub const fn hides_amount(mask: u8) -> bool {
	mask & MASK_HIDE_AMOUNT != 0
}

/// `true` iff bit 3 is set.
pub const fn hides_balance(mask: u8) -> bool {
	mask & MASK_HIDE_BALANCE != 0
}

/// Number of revealed fields among sender, receiver and amount (bits 0 to 2 clear).
pub const fn revealed_count(mask: u8) -> usize {
	let hidden =
		(mask & (MASK_HIDE_SENDER | MASK_HIDE_RECEIVER | MASK_HIDE_AMOUNT)).count_ones() as usize;
	3 - hidden
}
