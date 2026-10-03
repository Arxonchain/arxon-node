//! One behaviour per test. Arrange / Act / Assert.

use arxon_zk_primitives::FieldBytes;
use frame_support::{assert_noop, assert_ok};

use crate::{
	mock::{new_test_ext, NullifierRegistry, RuntimeEvent, System, Test},
	Error, Event, NullifierSet, SpentCount, SpentNullifiers,
};

fn nf(byte: u8) -> FieldBytes {
	FieldBytes([byte; 32])
}

#[test]
fn is_spent_is_false_for_unknown_nullifier() {
	new_test_ext().execute_with(|| {
		assert!(!NullifierRegistry::is_spent(&nf(1)));
	});
}

#[test]
fn mark_spent_records_current_block_number() {
	new_test_ext().execute_with(|| {
		System::set_block_number(7);

		assert_ok!(NullifierRegistry::mark_spent(&nf(1)));

		assert_eq!(SpentNullifiers::<Test>::get(nf(1)), Some(7));
		assert_eq!(NullifierRegistry::spent_at(&nf(1)), Some(7));
	});
}

#[test]
fn is_spent_is_true_after_mark_spent() {
	new_test_ext().execute_with(|| {
		assert_ok!(NullifierRegistry::mark_spent(&nf(1)));

		assert!(NullifierRegistry::is_spent(&nf(1)));
	});
}

#[test]
fn mark_spent_emits_nullifier_spent_event() {
	new_test_ext().execute_with(|| {
		assert_ok!(NullifierRegistry::mark_spent(&nf(1)));

		System::assert_last_event(RuntimeEvent::NullifierRegistry(Event::NullifierSpent {
			nullifier: nf(1),
			block_number: 1,
		}));
	});
}

#[test]
fn mark_spent_increments_spent_count() {
	new_test_ext().execute_with(|| {
		assert_ok!(NullifierRegistry::mark_spent(&nf(1)));
		assert_ok!(NullifierRegistry::mark_spent(&nf(2)));

		assert_eq!(SpentCount::<Test>::get(), 2);
	});
}

#[test]
fn mark_spent_twice_fails_with_already_spent() {
	new_test_ext().execute_with(|| {
		assert_ok!(NullifierRegistry::mark_spent(&nf(1)));

		assert_noop!(
			NullifierRegistry::mark_spent(&nf(1)),
			Error::<Test>::AlreadySpent
		);
	});
}

#[test]
fn failed_mark_spent_leaves_count_and_block_unchanged() {
	new_test_ext().execute_with(|| {
		assert_ok!(NullifierRegistry::mark_spent(&nf(1)));
		System::set_block_number(9);

		let _ = NullifierRegistry::mark_spent(&nf(1));

		assert_eq!(SpentCount::<Test>::get(), 1);
		assert_eq!(SpentNullifiers::<Test>::get(nf(1)), Some(1));
	});
}

#[test]
fn distinct_nullifiers_are_independent() {
	new_test_ext().execute_with(|| {
		assert_ok!(NullifierRegistry::mark_spent(&nf(1)));

		assert!(!NullifierRegistry::is_spent(&nf(2)));
		assert_ok!(NullifierRegistry::mark_spent(&nf(2)));
	});
}

#[test]
fn mark_spent_fails_with_overflow_when_count_is_saturated() {
	new_test_ext().execute_with(|| {
		SpentCount::<Test>::put(u64::MAX);

		assert_noop!(
			NullifierRegistry::mark_spent(&nf(1)),
			Error::<Test>::Overflow
		);
	});
}

#[test]
fn nullifier_set_trait_delegates_to_the_pallet() {
	new_test_ext().execute_with(|| {
		assert!(!<NullifierRegistry as NullifierSet>::is_spent(&nf(3)));

		assert_ok!(<NullifierRegistry as NullifierSet>::mark_spent(&nf(3)));

		assert!(<NullifierRegistry as NullifierSet>::is_spent(&nf(3)));
	});
}

#[test]
fn an_arx20_spend_does_not_mark_the_native_nullifier() {
	new_test_ext().execute_with(|| {
		let token = sp_core::H160::from_low_u64_be(0xA20);
		assert_ok!(NullifierRegistry::mark_spent_asset(token, &nf(1)));

		assert!(NullifierRegistry::is_spent_asset(token, &nf(1)));
		assert!(!NullifierRegistry::is_spent(&nf(1)));
		assert!(!NullifierRegistry::is_spent_asset(
			sp_core::H160::from_low_u64_be(0xB20),
			&nf(1)
		));
	});
}

#[test]
fn native_and_arx20_can_share_the_same_nullifier_bytes() {
	new_test_ext().execute_with(|| {
		let token = sp_core::H160::from_low_u64_be(0xA20);
		assert_ok!(NullifierRegistry::mark_spent(&nf(7)));
		assert_ok!(NullifierRegistry::mark_spent_asset(token, &nf(7)));

		assert!(NullifierRegistry::is_spent(&nf(7)));
		assert!(NullifierRegistry::is_spent_asset(token, &nf(7)));
	});
}
