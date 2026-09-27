//! One behaviour per test. Arrange / Act / Assert.

use arxon_zk_primitives::{CircuitId, FieldBytes, Proof, CHAIN_ID};
use frame_support::{assert_noop, assert_ok, BoundedVec};
use pallet_privacy::ReceiptSink;

use crate::{
	mock::{new_test_ext, FakeVerifier, Ptr, RuntimeEvent, RuntimeOrigin, System, Test, AUDITOR},
	DisclosureCount, Error, Event, ReceiptCommitment, Receipts, RevealedValues, TotalReceipts,
};

fn fb(byte: u8) -> FieldBytes {
	FieldBytes::from_u64(0x1000 + byte as u64)
}

fn proof() -> Proof {
	BoundedVec::truncate_from(vec![5u8; 64])
}

fn revealed() -> RevealedValues {
	RevealedValues {
		sender: fb(0xa0),
		receiver: fb(0xb0),
		amount: FieldBytes::from_u64(42),
	}
}

const EXPIRY: u64 = 100;

fn recorded_receipt() -> FieldBytes {
	assert_ok!(Ptr::record(fb(1), fb(2), 0b0111));
	fb(1)
}

fn disclose(ptr_id: FieldBytes, mask: u8) -> sp_runtime::DispatchResult {
	Ptr::disclose(
		RuntimeOrigin::signed(AUDITOR),
		ptr_id,
		mask,
		revealed(),
		EXPIRY,
		proof(),
	)
}

// --- record -----------------------------------------------------------------------------------------

#[test]
fn record_stores_commitment_with_current_block_and_mask() {
	new_test_ext().execute_with(|| {
		System::set_block_number(9);

		assert_ok!(Ptr::record(fb(1), fb(2), 0b0101));

		assert_eq!(
			Receipts::<Test>::get(fb(1)),
			Some(ReceiptCommitment {
				cv: fb(2),
				block_number: 9,
				mask_bits: 0b0101
			})
		);
		assert_eq!(TotalReceipts::<Test>::get(), 1);
	});
}

#[test]
fn record_emits_receipt_created_without_parties() {
	new_test_ext().execute_with(|| {
		assert_ok!(Ptr::record(fb(1), fb(2), 0b0101));

		System::assert_last_event(RuntimeEvent::Ptr(Event::ReceiptCreated {
			ptr_id: fb(1),
			block_number: 1,
			mask_bits: 0b0101,
		}));
	});
}

#[test]
fn record_fails_when_receipt_already_exists() {
	new_test_ext().execute_with(|| {
		assert_ok!(Ptr::record(fb(1), fb(2), 0));

		assert_noop!(
			Ptr::record(fb(1), fb(3), 0),
			Error::<Test>::ReceiptAlreadyExists
		);
	});
}

// --- disclose ---------------------------------------------------------------------------------------

#[test]
fn disclose_verifies_circuit_5_with_audience_bound_to_caller() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();

		assert_ok!(disclose(ptr_id, 0b0011));

		let call = FakeVerifier::last_call().expect("verifier called");
		assert_eq!(call.circuit_id, CircuitId::DisclosureProof);
		let rows = &call.public_inputs[0];
		assert_eq!(rows[0], ptr_id);
		assert_eq!(rows[1], FieldBytes::from_u8(0b0011), "disclosure mask");
		assert_eq!(rows[2], FieldBytes::ZERO, "sender hidden");
		assert_eq!(rows[3], FieldBytes::ZERO, "receiver hidden");
		assert_eq!(rows[4], FieldBytes::from_u64(42), "amount shown");
		assert_eq!(
			rows[5],
			Ptr::audience_of(&AUDITOR),
			"audience is the caller"
		);
		assert_eq!(rows[6], FieldBytes::from_u64(CHAIN_ID));
		assert_eq!(rows[7], FieldBytes::from_u32(EXPIRY as u32));
	});
}

#[test]
fn audience_differs_per_account_and_is_canonical() {
	new_test_ext().execute_with(|| {
		assert_ne!(Ptr::audience_of(&AUDITOR), Ptr::audience_of(&8));
		assert!(Ptr::audience_of(&AUDITOR).is_canonical());
	});
}

#[test]
fn disclose_emits_disclosed_with_only_the_revealed_fields() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();

		assert_ok!(disclose(ptr_id, 0b0010));

		System::assert_last_event(RuntimeEvent::Ptr(Event::Disclosed {
			ptr_id,
			verifier: AUDITOR,
			disclosure_mask: 0b0010,
			sender: Some(fb(0xa0)),
			receiver: None,
			amount: Some(42),
		}));
	});
}

#[test]
fn disclose_increments_disclosure_count() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();

		assert_ok!(disclose(ptr_id, 0));
		assert_ok!(disclose(ptr_id, 0b0111));

		assert_eq!(DisclosureCount::<Test>::get(ptr_id), 2);
	});
}

#[test]
fn disclose_fails_for_unknown_receipt() {
	new_test_ext().execute_with(|| {
		assert_noop!(disclose(fb(9), 0), Error::<Test>::ReceiptNotFound);
	});
}

#[test]
fn disclose_fails_when_mask_sets_the_balance_bit_or_is_invalid() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();

		assert_noop!(
			disclose(ptr_id, 0b1000),
			Error::<Test>::InvalidDisclosureMask
		);
		assert_noop!(disclose(ptr_id, 16), Error::<Test>::InvalidDisclosureMask);
	});
}

#[test]
fn disclose_fails_when_verifier_rejects_and_counts_nothing() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();
		FakeVerifier::set_accept(false);

		assert_noop!(
			disclose(ptr_id, 0),
			pallet_zk_verifier::Error::<Test>::InvalidProof
		);
		assert_eq!(DisclosureCount::<Test>::get(ptr_id), 0);
	});
}

#[test]
fn disclose_fails_when_expired_or_too_far() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();

		assert_noop!(
			Ptr::disclose(
				RuntimeOrigin::signed(AUDITOR),
				ptr_id,
				0,
				revealed(),
				1 + 129,
				proof()
			),
			Error::<Test>::ExpiryTooFar
		);
		System::set_block_number(EXPIRY + 1);
		assert_noop!(disclose(ptr_id, 0), Error::<Test>::ProofExpired);
	});
}

#[test]
fn disclose_fails_with_non_canonical_revealed_value() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();
		let bad = RevealedValues {
			sender: FieldBytes([0xff; 32]),
			..revealed()
		};

		assert_noop!(
			Ptr::disclose(
				RuntimeOrigin::signed(AUDITOR),
				ptr_id,
				0,
				bad,
				EXPIRY,
				proof()
			),
			Error::<Test>::InvalidFieldElement
		);
	});
}

#[test]
fn disclose_requires_signed_origin() {
	new_test_ext().execute_with(|| {
		let ptr_id = recorded_receipt();

		assert_noop!(
			Ptr::disclose(
				RuntimeOrigin::none(),
				ptr_id,
				0,
				revealed(),
				EXPIRY,
				proof()
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

// --- migration ---------------------------------------------------------------------------------

#[test]
fn migration_deletes_the_plaintext_receipts_and_codes_of_version_0() {
	use frame_support::{
		storage::{storage_prefix, unhashed},
		traits::{GetStorageVersion, OnRuntimeUpgrade, PalletInfoAccess, StorageVersion},
	};

	new_test_ext().execute_with(|| {
		let pallet = <Ptr as PalletInfoAccess>::name().as_bytes();
		let old_key = |item: &[u8]| {
			let mut key = storage_prefix(pallet, item).to_vec();
			key.extend_from_slice(&[7u8; 48]);
			key
		};
		for item in crate::migrations::REMOVED_ITEMS {
			unhashed::put_raw(&old_key(item), b"plaintext party and amount");
		}
		crate::TotalReceipts::<Test>::put(9);
		StorageVersion::new(0).put::<Ptr>();

		crate::migrations::V0ToV1::<Test>::on_runtime_upgrade();

		for item in crate::migrations::REMOVED_ITEMS {
			assert_eq!(
				unhashed::get_raw(&old_key(item)),
				None,
				"{item:?} left behind"
			);
		}
		assert_eq!(crate::TotalReceipts::<Test>::get(), 0);
		assert_eq!(Ptr::on_chain_storage_version(), 1);
	});
}
