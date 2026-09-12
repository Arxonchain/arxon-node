//! One behaviour per test. Arrange / Act / Assert.

use arxon_zk_primitives::{poseidon::cv_dummy_bytes, CircuitId, FieldBytes, Proof, CHAIN_ID};
use frame_support::{assert_noop, assert_ok, traits::fungible::Inspect, BoundedVec};
use pallet_note_tree::{MerkleTree, TreeId};
use sp_runtime::traits::Dispatchable;
use sp_runtime::DispatchError;

use crate::{
	mock::{
		new_test_ext, Balances, FakeVerifier, NoteTree, NullifierRegistry, Privacy, RuntimeCall,
		RuntimeEvent, RuntimeOrigin, System, Test, ALICE, ALICE_BALANCE, BOB, RELAYER, UNIT,
	},
	pallet::{Intent, ValueFlow},
	Error, Event, Input, Inputs, Output, Outputs, PrivacyMask, ProofBundle, ShieldedTxCount,
	TxPrivacyMask,
};

// --- builders -----------------------------------------------------------------------------------

/// A distinct canonical field element per tag byte (never zero).
fn fb(byte: u8) -> FieldBytes {
	FieldBytes::from_u64(0x1000 + byte as u64)
}

fn proof(byte: u8) -> Proof {
	BoundedVec::truncate_from(vec![byte; 64])
}

fn output(cm: u8, cv: u8) -> Output {
	Output {
		cm: fb(cm),
		cv: fb(cv),
		revealed_receiver: fb(0xb0),
		revealed_amount: FieldBytes::from_u64(42),
		encrypted_note: BoundedVec::truncate_from(vec![cm; 16]),
	}
}

fn input(nullifier: u8, cv: u8) -> Input {
	Input {
		nullifier: fb(nullifier),
		cv: fb(cv),
		revealed_sender: fb(0xa0),
	}
}

fn outputs(items: Vec<Output>) -> Outputs {
	BoundedVec::truncate_from(items)
}

fn inputs(items: Vec<Input>) -> Inputs {
	BoundedVec::truncate_from(items)
}

fn bundle(spend: bool, output: bool) -> ProofBundle {
	ProofBundle {
		spend: spend.then(|| proof(3)),
		output: output.then(|| proof(1)),
		balance: proof(2),
	}
}

const EXPIRY: u64 = 100;

fn shield(amount: u128, outs: Outputs, mask: u8) -> Result<(), DispatchError> {
	Privacy::shield(
		RuntimeOrigin::signed(ALICE),
		amount,
		outs,
		mask,
		EXPIRY,
		bundle(false, true),
	)
}

/// Shields 42 units into note `cm` and returns the anchor.
fn shielded_note(cm: u8, cv: u8) -> FieldBytes {
	assert_ok!(shield(42 * UNIT, outputs(vec![output(cm, cv)]), 0));
	NoteTree::current_root(TreeId::Note)
}

fn transfer(anchor: FieldBytes, ins: Inputs, outs: Outputs, mask: u8) -> Result<(), DispatchError> {
	Privacy::submit_private_transfer(
		RuntimeOrigin::signed(RELAYER),
		anchor,
		ins,
		outs,
		mask,
		EXPIRY,
		bundle(true, true),
	)
}

fn unshield(
	recipient: u64,
	amount: u128,
	anchor: FieldBytes,
	ins: Inputs,
	outs: Outputs,
) -> Result<(), DispatchError> {
	let proofs = ProofBundle {
		spend: Some(proof(3)),
		output: (!outs.is_empty()).then(|| proof(1)),
		balance: proof(2),
	};
	Privacy::unshield(
		RuntimeOrigin::signed(RELAYER),
		recipient,
		amount,
		anchor,
		ins,
		outs,
		0,
		EXPIRY,
		proofs,
	)
}

fn last_digest() -> FieldBytes {
	System::events()
		.into_iter()
		.rev()
		.find_map(|r| match r.event {
			RuntimeEvent::Privacy(Event::BundleExecuted { bundle_digest, .. }) => {
				Some(bundle_digest)
			}
			_ => None,
		})
		.expect("a bundle executed")
}

// --- mask helpers -------------------------------------------------------------------------------

#[test]
fn as_bits_matches_zk_primitives_mask_constants() {
	use arxon_zk_primitives::mask::*;

	assert_eq!(
		PrivacyMask::from_bits(MASK_HIDE_SENDER).as_bits(),
		MASK_HIDE_SENDER
	);
	assert_eq!(
		PrivacyMask::from_bits(MASK_HIDE_RECEIVER).as_bits(),
		MASK_HIDE_RECEIVER
	);
	assert_eq!(
		PrivacyMask::from_bits(MASK_HIDE_AMOUNT).as_bits(),
		MASK_HIDE_AMOUNT
	);
	assert_eq!(
		PrivacyMask::from_bits(MASK_HIDE_BALANCE).as_bits(),
		MASK_HIDE_BALANCE
	);
	assert_eq!(PrivacyMask::from_bits(MASK_ALL).as_bits(), MASK_ALL);
}

#[test]
fn four_flag_packing_is_stable() {
	let all = PrivacyMask {
		hide_sender: true,
		hide_receiver: true,
		hide_amount: true,
		hide_balance: true,
	};

	assert_eq!(all.as_bits(), 0b1111);
	assert_eq!(
		PrivacyMask::from_bits(0b0101),
		PrivacyMask {
			hide_sender: true,
			hide_receiver: false,
			hide_amount: true,
			hide_balance: false
		}
	);
	assert!(!PrivacyMask::from_bits(0).is_any_private());
}

// --- simple calls --------------------------------------------------------------------------------

#[test]
fn set_privacy_default_stores_mask_and_emits_event() {
	new_test_ext().execute_with(|| {
		let mask = PrivacyMask::from_bits(0b0110);

		assert_ok!(Privacy::set_privacy_default(
			RuntimeOrigin::signed(ALICE),
			mask
		));

		assert_eq!(crate::AccountPrivacyDefault::<Test>::get(ALICE), Some(mask));
		System::assert_last_event(RuntimeEvent::Privacy(Event::PrivacyDefaultSet {
			who: ALICE,
			mask,
		}));
	});
}

#[test]
fn set_balance_visibility_stores_flag() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::set_balance_visibility(
			RuntimeOrigin::signed(ALICE),
			true
		));

		assert!(crate::HideBalanceAccounts::<Test>::get(ALICE));
	});
}

#[test]
fn register_shielded_key_links_both_directions() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(ALICE),
			fb(0xa0)
		));

		assert_eq!(Privacy::shielded_key(&ALICE), Some(fb(0xa0)));
		assert_eq!(Privacy::shielded_key_owner(&fb(0xa0)), Some(ALICE));
	});
}

#[test]
fn register_shielded_key_rejects_key_owned_by_another_account() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(ALICE),
			fb(0xa0)
		));

		assert_noop!(
			Privacy::register_shielded_key(RuntimeOrigin::signed(BOB), fb(0xa0)),
			Error::<Test>::ShieldedKeyTaken
		);
	});
}

#[test]
fn register_shielded_key_replaces_previous_key_of_the_same_account() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(ALICE),
			fb(0xa0)
		));

		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(ALICE),
			fb(0xa1)
		));

		assert_eq!(Privacy::shielded_key_owner(&fb(0xa0)), None);
		assert_eq!(Privacy::shielded_key_owner(&fb(0xa1)), Some(ALICE));
	});
}

#[test]
fn register_shielded_key_rejects_non_canonical_key() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Privacy::register_shielded_key(RuntimeOrigin::signed(ALICE), FieldBytes([0xff; 32])),
			Error::<Test>::InvalidFieldElement
		);
	});
}

// --- shield ---------------------------------------------------------------------------------------

#[test]
fn shield_moves_funds_into_pool_account_and_inserts_commitment() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		assert_eq!(Balances::balance(&ALICE), ALICE_BALANCE - 42 * UNIT);
		assert_eq!(Privacy::pool_balance(), 42 * UNIT);
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 1);
		assert!(NoteTree::contains_leaf(TreeId::Note, &fb(1)));
	});
}

#[test]
fn shield_verifies_circuit_1_then_circuit_2_and_nothing_else() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		let circuits: Vec<CircuitId> = FakeVerifier::calls().iter().map(|c| c.circuit_id).collect();
		assert_eq!(
			circuits,
			vec![
				CircuitId::PrivacyFlagEnforcement,
				CircuitId::BalanceIntegrity
			]
		);
	});
}

#[test]
fn shield_passes_bundle_digest_chain_id_and_expiry_in_every_public_input() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0));
		let digest = last_digest();

		for call in FakeVerifier::calls() {
			for instance in call.public_inputs.iter() {
				let n = instance.len();
				assert_eq!(
					instance[n - 3],
					digest,
					"{:?} bundle digest row",
					call.circuit_id
				);
				assert_eq!(
					instance[n - 2],
					FieldBytes::from_u64(CHAIN_ID),
					"{:?} chain id row",
					call.circuit_id
				);
				assert_eq!(
					instance[n - 1],
					FieldBytes::from_u32(EXPIRY as u32),
					"{:?} expiry row",
					call.circuit_id
				);
			}
		}
	});
}

#[test]
fn shield_builds_circuit_2_inputs_with_dummy_slots_and_transparent_in() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		let c2 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::BalanceIntegrity)
			.unwrap();
		let rows = &c2.public_inputs[0];
		assert_eq!(rows[0], cv_dummy_bytes(), "cv_in0 dummy");
		assert_eq!(rows[1], cv_dummy_bytes(), "cv_in1 dummy");
		assert_eq!(rows[2], fb(2), "cv_out0");
		assert_eq!(rows[3], cv_dummy_bytes(), "cv_out1 dummy");
		assert_eq!(
			rows[4],
			FieldBytes::from_u64(42),
			"transparent in, shielded units"
		);
		assert_eq!(rows[5], FieldBytes::ZERO, "transparent out");
		assert_eq!(rows[6], FieldBytes::ZERO, "fee");
	});
}

#[test]
fn shield_zeroes_revealed_fields_the_mask_hides_in_circuit_1_inputs() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0b0110));

		let c1 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::PrivacyFlagEnforcement)
			.unwrap();
		let rows = &c1.public_inputs[0];
		assert_eq!(rows[2], FieldBytes::from_u8(0b0110), "mask");
		assert_eq!(rows[3], FieldBytes::ZERO, "receiver hidden");
		assert_eq!(rows[4], FieldBytes::ZERO, "amount hidden");
	});
}

#[test]
fn shield_records_mask_under_the_bundle_digest_and_counts_private_bundles() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0b0001));

		assert_eq!(
			TxPrivacyMask::<Test>::get(last_digest()),
			Some(PrivacyMask::from_bits(0b0001))
		);
		assert_eq!(ShieldedTxCount::<Test>::get(), 1);
	});
}

#[test]
fn shield_with_all_public_mask_does_not_count_as_private() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		assert_eq!(ShieldedTxCount::<Test>::get(), 0);
	});
}

#[test]
fn shield_emits_note_created_with_ciphertext_and_resolved_receiver() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(BOB),
			fb(0xb0)
		));

		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		let created = System::events().into_iter().find_map(|r| match r.event {
			RuntimeEvent::Privacy(e @ Event::NoteCreated { .. }) => Some(e),
			_ => None,
		});
		assert_eq!(
			created,
			Some(Event::NoteCreated {
				bundle_digest: last_digest(),
				leaf_index: 0,
				cm: fb(1),
				revealed_receiver: Some(fb(0xb0)),
				receiver_account: Some(BOB),
				revealed_amount: Some(42),
				encrypted_note: BoundedVec::truncate_from(vec![1; 16]),
			})
		);
	});
}

#[test]
fn shield_fails_when_verifier_rejects_and_leaves_state_untouched() {
	new_test_ext().execute_with(|| {
		FakeVerifier::set_accept(false);

		assert_noop!(
			shield(42 * UNIT, outputs(vec![output(1, 2)]), 0),
			pallet_zk_verifier::Error::<Test>::InvalidProof
		);
		assert_eq!(Balances::balance(&ALICE), ALICE_BALANCE);
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
	});
}

#[test]
fn shield_fails_when_amount_not_multiple_of_shielded_unit() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			shield(42 * UNIT + 1, outputs(vec![output(1, 2)]), 0),
			Error::<Test>::AmountNotMultipleOfUnit
		);
	});
}

#[test]
fn shield_fails_with_zero_amount() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			shield(0, outputs(vec![output(1, 2)]), 0),
			Error::<Test>::ZeroAmount
		);
	});
}

#[test]
fn shield_fails_with_invalid_mask() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			shield(42 * UNIT, outputs(vec![output(1, 2)]), 16),
			Error::<Test>::InvalidMask
		);
	});
}

#[test]
fn shield_fails_when_expiry_is_in_the_past() {
	new_test_ext().execute_with(|| {
		System::set_block_number(EXPIRY + 1);

		assert_noop!(
			shield(42 * UNIT, outputs(vec![output(1, 2)]), 0),
			Error::<Test>::ProofExpired
		);
	});
}

#[test]
fn shield_fails_when_expiry_exceeds_max_validity() {
	new_test_ext().execute_with(|| {
		let result = Privacy::shield(
			RuntimeOrigin::signed(ALICE),
			42 * UNIT,
			outputs(vec![output(1, 2)]),
			0,
			1 + 129,
			bundle(false, true),
		);

		assert_noop!(result, Error::<Test>::ExpiryTooFar);
	});
}

#[test]
fn shield_fails_without_outputs() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			shield(42 * UNIT, outputs(vec![]), 0),
			Error::<Test>::NoOutputs
		);
	});
}

#[test]
fn shield_fails_when_proof_bundle_carries_an_unexpected_spend_proof() {
	new_test_ext().execute_with(|| {
		let result = Privacy::shield(
			RuntimeOrigin::signed(ALICE),
			42 * UNIT,
			outputs(vec![output(1, 2)]),
			0,
			EXPIRY,
			bundle(true, true),
		);

		assert_noop!(result, Error::<Test>::ProofBundleMismatch);
	});
}

#[test]
fn shield_fails_when_output_proof_is_missing() {
	new_test_ext().execute_with(|| {
		let result = Privacy::shield(
			RuntimeOrigin::signed(ALICE),
			42 * UNIT,
			outputs(vec![output(1, 2)]),
			0,
			EXPIRY,
			bundle(false, false),
		);

		assert_noop!(result, Error::<Test>::ProofBundleMismatch);
	});
}

#[test]
fn shield_fails_with_duplicate_commitment_in_the_tree() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		assert_noop!(
			shield(42 * UNIT, outputs(vec![output(1, 9)]), 0),
			Error::<Test>::DuplicateCommitment
		);
	});
}

#[test]
fn shield_fails_with_duplicate_commitment_inside_the_bundle() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			shield(42 * UNIT, outputs(vec![output(1, 2), output(1, 3)]), 0),
			Error::<Test>::DuplicateCommitment
		);
	});
}

#[test]
fn shield_fails_with_non_canonical_commitment() {
	new_test_ext().execute_with(|| {
		let mut bad = output(1, 2);
		bad.cm = FieldBytes([0xff; 32]);

		assert_noop!(
			shield(42 * UNIT, outputs(vec![bad]), 0),
			Error::<Test>::InvalidFieldElement
		);
	});
}

#[test]
fn shield_fails_when_depositor_cannot_pay() {
	new_test_ext().execute_with(|| {
		let result = Privacy::shield(
			RuntimeOrigin::signed(BOB),
			42 * UNIT,
			outputs(vec![output(1, 2)]),
			0,
			EXPIRY,
			bundle(false, true),
		);

		assert!(result.is_err());
		assert_eq!(
			NoteTree::leaf_count(TreeId::Note),
			0,
			"insert rolled back with the failed transfer"
		);
	});
}

// --- private transfer ---------------------------------------------------------------------------

#[test]
fn private_transfer_marks_nullifiers_spent_and_inserts_commitments() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0
		));

		assert!(NullifierRegistry::is_spent(&fb(10)));
		assert!(NoteTree::contains_leaf(TreeId::Note, &fb(20)));
		assert_eq!(Privacy::pool_balance(), 42 * UNIT, "pool balance unchanged");
	});
}

#[test]
fn private_transfer_verifies_circuits_3_1_2_in_order() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::reset();

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0
		));

		let circuits: Vec<CircuitId> = FakeVerifier::calls().iter().map(|c| c.circuit_id).collect();
		assert_eq!(
			circuits,
			vec![
				CircuitId::NullifierDerivation,
				CircuitId::PrivacyFlagEnforcement,
				CircuitId::BalanceIntegrity
			]
		);
	});
}

#[test]
fn private_transfer_builds_one_circuit_3_instance_per_input_with_anchor_and_cv() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::reset();

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11), input(12, 13)]),
			outputs(vec![output(20, 21)]),
			0b0001
		));

		let c3 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::NullifierDerivation)
			.unwrap();
		assert_eq!(c3.public_inputs.len(), 2);
		assert_eq!(c3.public_inputs[1][0], anchor);
		assert_eq!(c3.public_inputs[1][1], fb(12), "nullifier");
		assert_eq!(c3.public_inputs[1][2], fb(13), "cv");
		assert_eq!(c3.public_inputs[1][3], FieldBytes::from_u8(0b0001), "mask");
		assert_eq!(c3.public_inputs[1][4], FieldBytes::ZERO, "sender hidden");
	});
}

#[test]
fn private_transfer_fills_circuit_2_input_slots_from_inputs_and_dummy() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::reset();

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21), output(22, 23)]),
			0
		));

		let c2 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::BalanceIntegrity)
			.unwrap();
		let rows = &c2.public_inputs[0];
		assert_eq!(rows[0], fb(11));
		assert_eq!(rows[1], cv_dummy_bytes());
		assert_eq!(rows[2], fb(21));
		assert_eq!(rows[3], fb(23));
		assert_eq!(rows[4], FieldBytes::ZERO, "no transparent in");
		assert_eq!(rows[5], FieldBytes::ZERO, "no transparent out");
	});
}

#[test]
fn private_transfer_fails_with_unknown_anchor() {
	new_test_ext().execute_with(|| {
		shielded_note(1, 2);

		assert_noop!(
			transfer(
				fb(0x77),
				inputs(vec![input(10, 11)]),
				outputs(vec![output(20, 21)]),
				0
			),
			Error::<Test>::UnknownAnchor
		);
	});
}

#[test]
fn private_transfer_fails_with_nullifier_already_spent() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0
		));
		let anchor = NoteTree::current_root(TreeId::Note);

		assert_noop!(
			transfer(
				anchor,
				inputs(vec![input(10, 11)]),
				outputs(vec![output(30, 31)]),
				0
			),
			Error::<Test>::NullifierAlreadySpent
		);
	});
}

#[test]
fn private_transfer_fails_with_duplicate_nullifier_in_bundle() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_noop!(
			transfer(
				anchor,
				inputs(vec![input(10, 11), input(10, 12)]),
				outputs(vec![output(20, 21)]),
				0
			),
			Error::<Test>::DuplicateNullifier
		);
	});
}

#[test]
fn private_transfer_fails_when_one_circuit_rejects_and_nothing_is_written() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::reject_only(CircuitId::BalanceIntegrity);

		assert_noop!(
			transfer(
				anchor,
				inputs(vec![input(10, 11)]),
				outputs(vec![output(20, 21)]),
				0
			),
			pallet_zk_verifier::Error::<Test>::InvalidProof
		);
		assert!(!NullifierRegistry::is_spent(&fb(10)));
		assert!(!NoteTree::contains_leaf(TreeId::Note, &fb(20)));
	});
}

#[test]
fn private_transfer_fails_without_inputs_or_outputs() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_noop!(
			transfer(anchor, inputs(vec![]), outputs(vec![output(20, 21)]), 0),
			Error::<Test>::NoInputs
		);
		assert_noop!(
			transfer(anchor, inputs(vec![input(10, 11)]), outputs(vec![]), 0),
			Error::<Test>::NoOutputs
		);
	});
}

#[test]
fn private_transfer_emits_note_spent_with_resolved_sender_when_revealed() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(ALICE),
			fb(0xa0)
		));

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0
		));

		let spent = System::events().into_iter().find_map(|r| match r.event {
			RuntimeEvent::Privacy(e @ Event::NoteSpent { .. }) => Some(e),
			_ => None,
		});
		assert_eq!(
			spent,
			Some(Event::NoteSpent {
				bundle_digest: last_digest(),
				nullifier: fb(10),
				revealed_sender: Some(fb(0xa0)),
				sender_account: Some(ALICE),
			})
		);
	});
}

#[test]
fn private_transfer_hides_sender_in_event_when_mask_says_so() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0b0001
		));

		let spent = System::events().into_iter().find_map(|r| match r.event {
			RuntimeEvent::Privacy(Event::NoteSpent {
				revealed_sender,
				sender_account,
				..
			}) => Some((revealed_sender, sender_account)),
			_ => None,
		});
		assert_eq!(spent, Some((None, None)));
	});
}

#[test]
fn identical_bundle_cannot_execute_twice() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0
		));

		let again = transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0,
		);

		assert!(again.is_err());
	});
}

// --- unshield -------------------------------------------------------------------------------------

#[test]
fn unshield_pays_recipient_from_pool() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_ok!(unshield(
			BOB,
			40 * UNIT,
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)])
		));

		assert_eq!(Balances::balance(&BOB), 40 * UNIT);
		assert_eq!(Privacy::pool_balance(), 2 * UNIT);
		assert!(NullifierRegistry::is_spent(&fb(10)));
	});
}

#[test]
fn unshield_without_change_needs_no_output_proof() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_ok!(unshield(
			BOB,
			42 * UNIT,
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![])
		));

		let circuits: Vec<CircuitId> = FakeVerifier::calls().iter().map(|c| c.circuit_id).collect();
		assert!(circuits.ends_with(&[CircuitId::NullifierDerivation, CircuitId::BalanceIntegrity]));
	});
}

#[test]
fn unshield_binds_recipient_and_transparent_out_into_the_digest() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let to_bob = Intent::<Test> {
			anchor: Some(anchor),
			inputs: inputs(vec![input(10, 11)]),
			outputs: outputs(vec![]),
			mask_bits: 0,
			expiry_block: EXPIRY,
			proofs: bundle(true, false),
			value: ValueFlow::Unshield {
				recipient: BOB,
				amount: 42 * UNIT,
			},
		};
		let to_alice = Intent::<Test> {
			value: ValueFlow::Unshield {
				recipient: ALICE,
				amount: 42 * UNIT,
			},
			..to_bob_clone(&to_bob)
		};
		let less = Intent::<Test> {
			value: ValueFlow::Unshield {
				recipient: BOB,
				amount: 41 * UNIT,
			},
			..to_bob_clone(&to_bob)
		};

		let transparent = crate::pallet::Pallet::<Test>::transparent_for_tests(&to_bob);
		let d_bob = Privacy::digest_of(&to_bob, &transparent);
		let d_alice = Privacy::digest_of(&to_alice, &transparent);
		let d_less = Privacy::digest_of(
			&less,
			&crate::pallet::Pallet::<Test>::transparent_for_tests(&less),
		);

		assert_ne!(d_bob, d_alice, "recipient must be bound");
		assert_ne!(d_bob, d_less, "amount must be bound");
	});
}

fn to_bob_clone(i: &Intent<Test>) -> Intent<Test> {
	Intent {
		anchor: i.anchor,
		inputs: i.inputs.clone(),
		outputs: i.outputs.clone(),
		mask_bits: i.mask_bits,
		expiry_block: i.expiry_block,
		proofs: i.proofs.clone(),
		value: ValueFlow::Transfer,
	}
}

#[test]
fn unshield_fails_with_pool_insufficient_even_if_proofs_accepted() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_noop!(
			unshield(
				BOB,
				43 * UNIT,
				anchor,
				inputs(vec![input(10, 11)]),
				outputs(vec![])
			),
			Error::<Test>::PoolInsufficient
		);
	});
}

#[test]
fn unshield_fails_when_verifier_rejects_and_does_not_mark_nullifier() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::set_accept(false);

		assert_noop!(
			unshield(
				BOB,
				42 * UNIT,
				anchor,
				inputs(vec![input(10, 11)]),
				outputs(vec![])
			),
			pallet_zk_verifier::Error::<Test>::InvalidProof
		);
		assert!(!NullifierRegistry::is_spent(&fb(10)));
		assert_eq!(Balances::balance(&BOB), 0);
	});
}

#[test]
fn unshield_fails_without_inputs() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_noop!(
			unshield(BOB, 42 * UNIT, anchor, inputs(vec![]), outputs(vec![])),
			Error::<Test>::NoInputs
		);
	});
}

// --- dispatch through the runtime ---------------------------------------------------------------

#[test]
fn dispatch_through_runtime_call_rolls_back_partial_writes_on_error() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		// Circuit 2 is verified last; everything before it must be undone.
		FakeVerifier::reject_only(CircuitId::BalanceIntegrity);
		let call = RuntimeCall::Privacy(crate::Call::submit_private_transfer {
			anchor,
			inputs: inputs(vec![input(10, 11)]),
			outputs: outputs(vec![output(20, 21)]),
			mask_bits: 0,
			expiry_block: EXPIRY,
			proofs: bundle(true, true),
		});

		let result = call.dispatch(RuntimeOrigin::signed(RELAYER));

		assert!(result.is_err());
		assert!(!NullifierRegistry::is_spent(&fb(10)));
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 1);
		assert_eq!(TxPrivacyMask::<Test>::iter().count(), 1);
	});
}

#[test]
fn any_signer_can_relay_a_bundle() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		let relayed = Privacy::submit_private_transfer(
			RuntimeOrigin::signed(BOB),
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0,
			EXPIRY,
			bundle(true, true),
		);

		assert_ok!(relayed);
	});
}
