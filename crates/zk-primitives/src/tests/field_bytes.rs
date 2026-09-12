use crate::{FieldBytes, PALLAS_BASE_MODULUS_LE};

#[test]
fn field_bytes_from_u64_is_little_endian() {
	let f = FieldBytes::from_u64(0x0102_0304_0506_0708);

	assert_eq!(&f.0[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
	assert!(f.0[8..].iter().all(|b| *b == 0));
}

#[test]
fn field_bytes_zero_is_canonical() {
	assert!(FieldBytes::ZERO.is_canonical());
}

#[test]
fn field_bytes_modulus_minus_one_is_canonical() {
	let mut p_minus_one = PALLAS_BASE_MODULUS_LE;
	p_minus_one[0] -= 1;

	assert!(FieldBytes(p_minus_one).is_canonical());
}

#[test]
fn field_bytes_modulus_is_not_canonical() {
	assert!(!FieldBytes(PALLAS_BASE_MODULUS_LE).is_canonical());
}

#[test]
fn field_bytes_modulus_plus_one_is_not_canonical() {
	let mut p_plus_one = PALLAS_BASE_MODULUS_LE;
	p_plus_one[0] += 1;

	assert!(!FieldBytes(p_plus_one).is_canonical());
}

#[test]
fn field_bytes_all_ff_is_not_canonical() {
	assert!(!FieldBytes([0xff; 32]).is_canonical());
}

#[test]
fn field_bytes_from_digest_keeps_31_bytes_and_zeroes_the_top_byte() {
	let digest = [0xffu8; 32];

	let f = FieldBytes::from_digest(digest);

	assert_eq!(&f.0[..31], &[0xff; 31]);
	assert_eq!(f.0[31], 0);
	assert!(f.is_canonical());
}

#[test]
fn field_bytes_from_short_bytes_embeds_an_account_id20() {
	let account = [0xabu8; 20];

	let f = FieldBytes::from_short_bytes(&account).expect("20 bytes fit");

	assert_eq!(&f.0[..20], &account);
	assert!(f.0[20..].iter().all(|b| *b == 0));
	assert!(f.is_canonical());
}

#[test]
fn field_bytes_from_short_bytes_rejects_32_bytes() {
	assert_eq!(FieldBytes::from_short_bytes(&[1u8; 32]), None);
}

#[test]
fn field_bytes_modulus_constant_matches_pallas_base_field() {
	// p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
	let be =
		hex::decode("40000000000000000000000000000000224698fc094cf91b992d30ed00000001").unwrap();
	let mut le = be.clone();
	le.reverse();

	assert_eq!(&le[..], &PALLAS_BASE_MODULUS_LE[..]);
}
