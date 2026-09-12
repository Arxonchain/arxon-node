use crate::{bundle_digest, encrypted_notes_hash, BundleFields, FieldBytes, CHAIN_ID};

fn fb(byte: u8) -> FieldBytes {
	FieldBytes([byte; 32])
}

fn base<'a>(nullifiers: &'a [FieldBytes], commitments: &'a [FieldBytes]) -> BundleFields<'a> {
	BundleFields {
		chain_id: CHAIN_ID,
		expiry_block: 100,
		recipient: None,
		transparent_in: 10,
		transparent_out: 0,
		fee: 0,
		nullifiers,
		commitments,
		cv_inputs: &[],
		cv_outputs: &[],
		mask_bits: 0b0011,
		encrypted_notes_hash: [0u8; 32],
	}
}

#[test]
fn bundle_digest_is_deterministic() {
	let nfs = [fb(1)];
	let cms = [fb(2)];
	let fields = base(&nfs, &cms);

	assert_eq!(bundle_digest(&fields), bundle_digest(&fields));
}

#[test]
fn bundle_digest_is_a_canonical_field_element_with_zero_top_byte() {
	let fields = base(&[], &[]);

	let digest = bundle_digest(&fields);

	assert!(digest.is_canonical());
	assert_eq!(digest.0[31], 0);
}

#[test]
fn bundle_digest_changes_when_recipient_changes() {
	let alice = [0xaau8; 20];
	let bob = [0xbbu8; 20];
	let mut to_alice = base(&[], &[]);
	to_alice.recipient = Some(&alice);
	let mut to_bob = to_alice.clone();
	to_bob.recipient = Some(&bob);

	assert_ne!(bundle_digest(&to_alice), bundle_digest(&to_bob));
}

#[test]
fn bundle_digest_changes_when_transparent_out_changes() {
	let a = base(&[], &[]);
	let mut b = a.clone();
	b.transparent_out = 1;

	assert_ne!(bundle_digest(&a), bundle_digest(&b));
}

#[test]
fn bundle_digest_changes_when_fee_changes() {
	let a = base(&[], &[]);
	let mut b = a.clone();
	b.fee = 1;

	assert_ne!(bundle_digest(&a), bundle_digest(&b));
}

#[test]
fn bundle_digest_distinguishes_no_recipient_from_empty_recipient() {
	let a = base(&[], &[]);
	let mut b = a.clone();
	b.recipient = Some(&[]);

	assert_ne!(bundle_digest(&a), bundle_digest(&b));
}

#[test]
fn bundle_digest_distinguishes_cv_input_from_cv_output_position() {
	let x = [fb(4)];
	let mut a = base(&[], &[]);
	a.cv_inputs = &x;
	let mut b = base(&[], &[]);
	b.cv_outputs = &x;

	assert_ne!(bundle_digest(&a), bundle_digest(&b));
}

#[test]
fn bundle_digest_changes_when_a_nullifier_changes() {
	let nfs_a = [fb(1)];
	let nfs_b = [fb(2)];

	assert_ne!(
		bundle_digest(&base(&nfs_a, &[])),
		bundle_digest(&base(&nfs_b, &[]))
	);
}

#[test]
fn bundle_digest_changes_when_a_commitment_changes() {
	let cms_a = [fb(1)];
	let cms_b = [fb(2)];

	assert_ne!(
		bundle_digest(&base(&[], &cms_a)),
		bundle_digest(&base(&[], &cms_b))
	);
}

#[test]
fn bundle_digest_changes_when_mask_changes() {
	let a = base(&[], &[]);
	let mut b = a.clone();
	b.mask_bits = 0b0100;

	assert_ne!(bundle_digest(&a), bundle_digest(&b));
}

#[test]
fn bundle_digest_changes_when_expiry_changes() {
	let a = base(&[], &[]);
	let mut b = a.clone();
	b.expiry_block = 101;

	assert_ne!(bundle_digest(&a), bundle_digest(&b));
}

#[test]
fn bundle_digest_changes_when_encrypted_notes_change() {
	let a = base(&[], &[]);
	let mut b = a.clone();
	b.encrypted_notes_hash = encrypted_notes_hash(&[b"ciphertext"]);

	assert_ne!(bundle_digest(&a), bundle_digest(&b));
}

#[test]
fn bundle_digest_distinguishes_nullifier_from_commitment_position() {
	// Same bytes as a nullifier vs as a commitment must not collide (field-wise SCALE framing).
	let x = [fb(9)];

	assert_ne!(bundle_digest(&base(&x, &[])), bundle_digest(&base(&[], &x)));
}

#[test]
fn bundle_preimage_starts_with_the_domain_prefix() {
	let fields = base(&[], &[]);

	let preimage = fields.preimage();

	assert!(preimage.starts_with(b"arxon/bundle/v1"));
}

#[test]
fn encrypted_notes_hash_depends_on_order() {
	let ab = encrypted_notes_hash(&[b"a", b"b"]);
	let ba = encrypted_notes_hash(&[b"b", b"a"]);

	assert_ne!(ab, ba);
}
