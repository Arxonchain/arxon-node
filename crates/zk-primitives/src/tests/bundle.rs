use crate::{
	arx20_bundle_digest, bundle_digest, digest_to_field, encrypted_notes_hash, BundleFields,
	FieldBytes, CHAIN_ID,
};

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
		fee_recipient: None,
		nullifiers,
		commitments,
		cv_inputs: &[],
		cv_outputs: &[],
		mask_bits: 0b0011,
		encrypted_notes_hash: [0u8; 32],
		receipt: None,
		compliance: None,
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

	assert!(preimage.starts_with(b"arxon/bundle/v2"));
}

#[test]
fn encrypted_notes_hash_depends_on_order() {
	let ab = encrypted_notes_hash(&[b"a", b"b"]);
	let ba = encrypted_notes_hash(&[b"b", b"a"]);

	assert_ne!(ab, ba);
}

#[test]
fn digest_to_field_is_canonical_and_injective_on_samples() {
	let a = digest_to_field(b"alice");
	let b = digest_to_field(b"bob");

	assert!(a.is_canonical());
	assert_eq!(a.0[31], 0);
	assert_ne!(a, b);
}

#[test]
fn bundle_digest_changes_when_a_receipt_is_attached_or_retargeted() {
	let nfs = [fb(1)];
	let bare = base(&nfs, &[]);
	let mut with_receipt = bare.clone();
	with_receipt.receipt = Some((0, fb(0x20)));
	let mut other_output = with_receipt.clone();
	other_output.receipt = Some((1, fb(0x20)));

	assert_ne!(bundle_digest(&bare), bundle_digest(&with_receipt));
	assert_ne!(bundle_digest(&with_receipt), bundle_digest(&other_output));
}

#[test]
fn bundle_digest_changes_when_a_compliance_attestation_is_attached_or_rerooted() {
	let nfs = [fb(1)];
	let bare = base(&nfs, &[]);
	let mut with_compliance = bare.clone();
	with_compliance.compliance = Some((0, fb(0x30)));
	let mut other_root = with_compliance.clone();
	other_root.compliance = Some((0, fb(0x31)));

	assert_ne!(bundle_digest(&bare), bundle_digest(&with_compliance));
	assert_ne!(bundle_digest(&with_compliance), bundle_digest(&other_root));
}

#[test]
fn arx20_bundle_digest_differs_from_native_and_binds_the_token() {
	let fields = base(&[], &[]);
	let token_a = [0x11u8; 20];
	let token_b = [0x22u8; 20];

	let native = bundle_digest(&fields);
	let a = arx20_bundle_digest(&token_a, &fields);
	let b = arx20_bundle_digest(&token_b, &fields);

	assert_ne!(native, a);
	assert_ne!(a, b);
	assert!(a.is_canonical());
	assert_eq!(a.0[31], 0);
	assert_eq!(
		arx20_bundle_digest(&token_a, &fields),
		arx20_bundle_digest(&token_a, &fields)
	);
}

/// A fully populated fee-free bundle: every field set, so a change to the
/// encoding of any of them moves the pinned digest.
fn pinned_fields<'a>(
	nullifiers: &'a [FieldBytes],
	commitments: &'a [FieldBytes],
	recipient: &'a [u8],
) -> BundleFields<'a> {
	BundleFields {
		chain_id: CHAIN_ID,
		expiry_block: 4242,
		recipient: Some(recipient),
		transparent_in: 0,
		transparent_out: 7,
		fee: 0,
		fee_recipient: None,
		nullifiers,
		commitments,
		cv_inputs: nullifiers,
		cv_outputs: commitments,
		mask_bits: 0b0101,
		encrypted_notes_hash: [9u8; 32],
		receipt: Some((0, fb(0x31))),
		compliance: Some((1, fb(0x32))),
	}
}

/// Digests of fee-free bundles are frozen: wallets already deployed compute
/// them, so adding the relayer fee must not move them.
#[test]
fn fee_free_bundle_digests_are_pinned() {
	let nfs = [fb(1), fb(2)];
	let cms = [fb(3), fb(4)];
	let fields = pinned_fields(&nfs, &cms, &[0x11; 20]);

	assert_eq!(hex::encode(bundle_digest(&fields).0), PINNED_NATIVE_DIGEST);
	assert_eq!(
		hex::encode(arx20_bundle_digest(&[0x22; 20], &fields).0),
		PINNED_ARX20_DIGEST
	);
}

const PINNED_NATIVE_DIGEST: &str =
	"9c697da09611a1f90cbfa9f33377bd8edc26d690da374101ee1f2cfcd898e100";
const PINNED_ARX20_DIGEST: &str =
	"370f7b48a0bc04e2bd3305923e212de35b81127984ab81d9074f4d9ac77b0d00";

#[test]
fn a_relayed_bundle_binds_its_fee_and_fee_recipient() {
	let nfs = [fb(1), fb(2)];
	let cms = [fb(3), fb(4)];
	let free = pinned_fields(&nfs, &cms, &[0x11; 20]);
	let relayed = BundleFields {
		fee: 5,
		fee_recipient: Some(&[0x77; 20]),
		..free.clone()
	};
	let other_recipient = BundleFields {
		fee_recipient: Some(&[0x78; 20]),
		..relayed.clone()
	};
	let other_fee = BundleFields {
		fee: 6,
		..relayed.clone()
	};

	let digests = [
		bundle_digest(&free),
		bundle_digest(&relayed),
		bundle_digest(&other_recipient),
		bundle_digest(&other_fee),
	];
	for i in 0..digests.len() {
		for j in i + 1..digests.len() {
			assert_ne!(digests[i], digests[j], "digests {i} and {j} collide");
		}
	}
}

/// A fee recipient without a fee is not silently dropped: it still changes the
/// preimage, so it can never be confused with a fee-free bundle.
#[test]
fn a_fee_recipient_without_a_fee_is_still_bound() {
	let nfs = [fb(1)];
	let free = pinned_fields(&nfs, &[], &[0x11; 20]);
	let stray = BundleFields {
		fee_recipient: Some(&[0x77; 20]),
		..free.clone()
	};

	assert_ne!(bundle_digest(&free), bundle_digest(&stray));
}
