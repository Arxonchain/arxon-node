use ff::{Field, PrimeField};
use halo2_poseidon::{ConstantLength, Domain, Hash, P128Pow5T3};

use crate::{
	constants::tags,
	poseidon::{
		cv_dummy, fp_from_bytes, fp_to_bytes, hash_cv, hash_domain, hash_member_leaf,
		hash_merkle_member, hash_merkle_note, hash_nk, hash_note, hash_nullifier, hash_pk,
		hash_ptr, hash_two_bytes, sponge_hash, ArxonDomain, Fp, MerkleDomain, RATE,
	},
	FieldBytes, PALLAS_BASE_MODULUS_LE,
};

fn upstream<const L: usize>(msg: [Fp; L]) -> Fp {
	Hash::<Fp, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(msg)
}

fn sample(n: u64) -> Fp {
	// Deterministic, non-trivial field elements.
	Fp::from(n) * Fp::from(0x9e37_79b9_7f4a_7c15) + Fp::from(7)
}

// --- the native port equals upstream on the plain domain ---------------------------------------

#[test]
fn ported_sponge_equals_upstream_constant_length_hash_for_lengths_1_to_5() {
	assert_eq!(
		sponge_hash::<ConstantLength<1>>(&[sample(1)]),
		upstream([sample(1)])
	);
	assert_eq!(
		sponge_hash::<ConstantLength<2>>(&[sample(1), sample(2)]),
		upstream([sample(1), sample(2)])
	);
	assert_eq!(
		sponge_hash::<ConstantLength<3>>(&[sample(1), sample(2), sample(3)]),
		upstream([sample(1), sample(2), sample(3)])
	);
	assert_eq!(
		sponge_hash::<ConstantLength<4>>(&[sample(1), sample(2), sample(3), sample(4)]),
		upstream([sample(1), sample(2), sample(3), sample(4)])
	);
	assert_eq!(
		sponge_hash::<ConstantLength<5>>(&[sample(1), sample(2), sample(3), sample(4), sample(5)]),
		upstream([sample(1), sample(2), sample(3), sample(4), sample(5)])
	);
}

#[test]
fn arxon_domain_with_tag_zero_is_exactly_constant_length() {
	// Tag 0 is never used by Arxon; it shows the domain differs from upstream only by the tag bits.
	assert_eq!(
		hash_domain::<0, 2>([sample(1), sample(2)]),
		upstream([sample(1), sample(2)])
	);
	assert_eq!(
		<ArxonDomain<0, 2> as Domain<Fp, RATE>>::initial_capacity_element(),
		<ConstantLength<2> as Domain<Fp, RATE>>::initial_capacity_element()
	);
}

#[test]
fn poseidon_upstream_kat_h_zero_one_is_reproduced_by_the_port() {
	// First vector of halo2_poseidon `test_vectors::fp` (zcash-test-vectors orchard_poseidon/hash/fp.py).
	let expected: [u8; 32] = [
		0x83, 0x58, 0xd7, 0x11, 0xa0, 0x32, 0x9d, 0x38, 0xbe, 0xcd, 0x54, 0xfb, 0xa7, 0xc2, 0x83,
		0xed, 0x3e, 0x08, 0x9a, 0x39, 0xc9, 0x1b, 0x6a, 0x9d, 0x10, 0xef, 0xb0, 0x2b, 0xc3, 0xf1,
		0x2f, 0x06,
	];

	let digest = sponge_hash::<ConstantLength<2>>(&[Fp::ZERO, Fp::ONE]);

	assert_eq!(digest.to_repr(), expected);
}

// --- domain separation ----------------------------------------------------------------------------

#[test]
fn arxon_domain_capacity_encodes_length_and_tag() {
	let cap = <ArxonDomain<{ tags::CV }, 2> as Domain<Fp, RATE>>::initial_capacity_element();

	assert_eq!(cap, Fp::from_u128((2u128 << 64) | tags::CV as u128));
}

#[test]
fn every_arxon_tag_is_non_zero_and_distinct() {
	let all = [
		tags::PK,
		tags::NK,
		tags::NOTE,
		tags::NULLIFIER,
		tags::PTR,
		tags::MERKLE_NOTE,
		tags::MERKLE_MEMBER,
		tags::MEMBER_LEAF,
		tags::CV,
	];

	for (i, a) in all.iter().enumerate() {
		assert_ne!(*a, 0);
		for b in &all[i + 1..] {
			assert_ne!(a, b);
		}
	}
}

#[test]
fn arxon_hash_never_equals_upstream_hash_of_the_same_message() {
	let msg = [sample(1), sample(2)];

	assert_ne!(hash_merkle_note(msg[0], msg[1]), upstream(msg));
	assert_ne!(hash_cv(5, sample(2)), upstream([Fp::from(5), sample(2)]));
}

#[test]
fn pk_and_nk_of_the_same_secret_differ() {
	assert_ne!(hash_pk(sample(1)), hash_nk(sample(1)));
}

#[test]
fn note_and_member_merkle_domains_differ_on_the_same_children() {
	assert_ne!(
		hash_merkle_note(sample(1), sample(2)),
		hash_merkle_member(sample(1), sample(2))
	);
}

#[test]
fn merkle_hash_is_not_symmetric() {
	assert_ne!(
		hash_merkle_note(sample(1), sample(2)),
		hash_merkle_note(sample(2), sample(1))
	);
}

#[test]
fn member_leaf_differs_from_pk_hash_of_the_same_key() {
	assert_ne!(hash_member_leaf(sample(3)), hash_pk(sample(3)));
}

// --- Arxon hash functions -------------------------------------------------------------------------

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
fn named_hashes_are_the_generic_domain_hash_with_their_tag() {
	assert_eq!(
		hash_pk(sample(1)),
		hash_domain::<{ tags::PK }, 1>([sample(1)])
	);
	assert_eq!(
		hash_nullifier(sample(1), sample(2)),
		hash_domain::<{ tags::NULLIFIER }, 2>([sample(1), sample(2)])
	);
	assert_eq!(
		hash_note(sample(1), 9, sample(3)),
		hash_domain::<{ tags::NOTE }, 3>([sample(1), Fp::from(9), sample(3)])
	);
}

// --- bytes ----------------------------------------------------------------------------------------

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
	let (l, r) = (sample(1), sample(2));

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
