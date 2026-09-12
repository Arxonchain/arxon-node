use ff::{Field, PrimeField};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};

use crate::{
	constants::tags,
	poseidon::{
		cv_dummy, fp_from_bytes, fp_to_bytes, hash_cv, hash_member_leaf, hash_merkle_member,
		hash_merkle_note, hash_nk, hash_note, hash_nullifier, hash_pk, hash_ptr, hash_two_bytes,
		Fp, MerkleDomain,
	},
	FieldBytes, PALLAS_BASE_MODULUS_LE,
};

fn untagged2(a: Fp, b: Fp) -> Fp {
	Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

#[test]
fn tagged_hash_is_plain_poseidon_with_the_tag_prepended() {
	let sk = Fp::from(7);

	assert_eq!(hash_pk(sk), untagged2(Fp::from(tags::PK), sk));
	assert_eq!(hash_nk(sk), untagged2(Fp::from(tags::NK), sk));
}

#[test]
fn pk_and_nk_of_the_same_secret_differ() {
	let sk = Fp::from(7);

	assert_ne!(hash_pk(sk), hash_nk(sk));
}

#[test]
fn note_and_member_merkle_domains_differ_on_the_same_children() {
	let (l, r) = (Fp::from(1), Fp::from(2));

	assert_ne!(hash_merkle_note(l, r), hash_merkle_member(l, r));
}

#[test]
fn merkle_hash_is_not_symmetric() {
	let (l, r) = (Fp::from(1), Fp::from(2));

	assert_ne!(hash_merkle_note(l, r), hash_merkle_note(r, l));
}

#[test]
fn cv_dummy_is_h_cv_of_zero_zero() {
	assert_eq!(cv_dummy(), hash_cv(0, Fp::ZERO));
}

#[test]
fn cv_hides_amount_behind_blinding() {
	assert_ne!(hash_cv(5, Fp::from(1)), hash_cv(5, Fp::from(2)));
	assert_ne!(hash_cv(5, Fp::from(1)), hash_cv(6, Fp::from(1)));
}

#[test]
fn note_commitment_depends_on_every_field() {
	let base = hash_note(Fp::from(1), 10, Fp::from(3));

	assert_ne!(base, hash_note(Fp::from(2), 10, Fp::from(3)));
	assert_ne!(base, hash_note(Fp::from(1), 11, Fp::from(3)));
	assert_ne!(base, hash_note(Fp::from(1), 10, Fp::from(4)));
}

#[test]
fn nullifier_depends_on_nk_and_cm() {
	let base = hash_nullifier(Fp::from(1), Fp::from(2));

	assert_ne!(base, hash_nullifier(Fp::from(3), Fp::from(2)));
	assert_ne!(base, hash_nullifier(Fp::from(1), Fp::from(3)));
}

#[test]
fn ptr_id_depends_on_every_field_and_on_party_order() {
	let base = hash_ptr(Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4));

	assert_ne!(
		base,
		hash_ptr(Fp::from(2), Fp::from(1), Fp::from(3), Fp::from(4)),
		"swapped parties"
	);
	assert_ne!(
		base,
		hash_ptr(Fp::from(1), Fp::from(2), Fp::from(9), Fp::from(4)),
		"cv"
	);
	assert_ne!(
		base,
		hash_ptr(Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(9)),
		"nonce"
	);
}

#[test]
fn member_leaf_differs_from_pk_hash_of_the_same_key() {
	let pk = Fp::from(11);

	assert_ne!(hash_member_leaf(pk), hash_pk(pk));
}

#[test]
fn fp_bytes_roundtrip_is_canonical_little_endian() {
	let f = Fp::from(0x0102_0304);

	let bytes = fp_to_bytes(&f);

	assert_eq!(bytes, FieldBytes::from_u64(0x0102_0304));
	assert_eq!(fp_from_bytes(&bytes), Some(f));
}

#[test]
fn fp_from_bytes_rejects_the_modulus() {
	assert_eq!(fp_from_bytes(&FieldBytes(PALLAS_BASE_MODULUS_LE)), None);
}

#[test]
fn is_canonical_agrees_with_field_decoding_on_boundary_values() {
	let mut p_minus_one = PALLAS_BASE_MODULUS_LE;
	p_minus_one[0] -= 1;
	let samples = [
		FieldBytes::ZERO,
		FieldBytes(p_minus_one),
		FieldBytes(PALLAS_BASE_MODULUS_LE),
		FieldBytes([0xff; 32]),
	];

	for s in samples {
		assert_eq!(s.is_canonical(), fp_from_bytes(&s).is_some(), "{s:?}");
	}
}

#[test]
fn hash_two_bytes_matches_field_level_hash() {
	let (l, r) = (Fp::from(1), Fp::from(2));

	let out = hash_two_bytes(MerkleDomain::Note, &fp_to_bytes(&l), &fp_to_bytes(&r));

	assert_eq!(out, Some(fp_to_bytes(&hash_merkle_note(l, r))));
}

#[test]
fn hash_two_bytes_returns_none_for_non_canonical_input() {
	let bad = FieldBytes([0xff; 32]);

	assert_eq!(
		hash_two_bytes(MerkleDomain::Note, &bad, &FieldBytes::ZERO),
		None
	);
	assert_eq!(
		hash_two_bytes(MerkleDomain::Member, &FieldBytes::ZERO, &bad),
		None
	);
}

#[test]
fn poseidon_spec_is_width3_rate2_8_full_56_partial() {
	use halo2_poseidon::Spec;

	assert_eq!(<P128Pow5T3 as Spec<Fp, 3, 2>>::full_rounds(), 8);
	assert_eq!(<P128Pow5T3 as Spec<Fp, 3, 2>>::partial_rounds(), 56);
	assert_eq!(
		<P128Pow5T3 as Spec<Fp, 3, 2>>::sbox(Fp::from(2)),
		Fp::from(32),
		"alpha 5"
	);
}

#[test]
fn poseidon_upstream_kat_h_zero_one_is_reproduced() {
	// First vector of halo2_poseidon `test_vectors::fp` (zcash-test-vectors orchard_poseidon/hash/fp.py):
	// ConstantLength<2> hash of [0, 1].
	let expected: [u8; 32] = [
		0x83, 0x58, 0xd7, 0x11, 0xa0, 0x32, 0x9d, 0x38, 0xbe, 0xcd, 0x54, 0xfb, 0xa7, 0xc2, 0x83,
		0xed, 0x3e, 0x08, 0x9a, 0x39, 0xc9, 0x1b, 0x6a, 0x9d, 0x10, 0xef, 0xb0, 0x2b, 0xc3, 0xf1,
		0x2f, 0x06,
	];

	let digest = untagged2(Fp::ZERO, Fp::ONE);

	assert_eq!(digest.to_repr(), expected);
}

#[test]
fn tagged_hash_with_tag_zero_and_one_message_equals_upstream_kat() {
	// A tagged L=1 hash is exactly the upstream ConstantLength<2> hash of [tag, m]:
	// with tag 0 and m = 1 it must reproduce the first upstream vector.
	let expected = untagged2(Fp::ZERO, Fp::ONE);

	let digest =
		Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([Fp::from(0u64), Fp::ONE]);

	assert_eq!(digest, expected);
}
