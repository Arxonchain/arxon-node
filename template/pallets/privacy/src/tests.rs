//! One behaviour per test. Arrange / Act / Assert.

use arxon_zk_primitives::{poseidon::cv_dummy_bytes, CircuitId, FieldBytes, Proof, CHAIN_ID};
use frame_support::{assert_noop, assert_ok, traits::fungible::Inspect, BoundedVec};
use pallet_note_tree::{MerkleTree, TreeId};
use sp_runtime::traits::Dispatchable;
use sp_runtime::DispatchError;

use crate::{
	mock::{
		arx20_token, new_test_ext, Balances, FakeVerifier, NoteTree, NullifierRegistry, Privacy,
		RecordingSink, RuntimeCall, RuntimeEvent, RuntimeOrigin, System, Test, ALICE,
		ALICE_BALANCE, BOB, RELAYER, TOKEN, UNIT,
	},
	pallet::{Intent, ValueFlow},
	ComplianceAttachment, Error, Event, Input, Inputs, Output, Outputs, PrivacyAsset, PrivacyMask,
	ProofBundle, PtrAttachment, ShieldedTxCount, TxPrivacyMask,
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
		receipt: None,
		compliance: None,
	}
}

fn full_bundle(receipt: bool, compliance: bool) -> ProofBundle {
	ProofBundle {
		receipt: receipt.then(|| proof(4)),
		compliance: compliance.then(|| proof(6)),
		..bundle(true, true)
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
		None,
		None,
		bundle(true, true),
	)
}

fn transfer_with(
	anchor: FieldBytes,
	outs: Outputs,
	ptr: Option<PtrAttachment>,
	compliance: Option<ComplianceAttachment>,
	proofs: ProofBundle,
) -> Result<(), DispatchError> {
	Privacy::submit_private_transfer(
		RuntimeOrigin::signed(RELAYER),
		anchor,
		inputs(vec![input(10, 11)]),
		outs,
		0,
		EXPIRY,
		ptr,
		compliance,
		proofs,
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
		output: (!outs.is_empty()).then(|| proof(1)),
		..bundle(true, false)
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

/// Adds one registry member and returns the new membership root.
fn member_root(member: u8) -> FieldBytes {
	assert_ok!(NoteTree::add_member(RuntimeOrigin::root(), fb(member)));
	NoteTree::current_root(TreeId::Membership)
}

fn compliance(output_index: u8, registry_root: FieldBytes) -> Option<ComplianceAttachment> {
	Some(ComplianceAttachment {
		output_index,
		registry_root,
	})
}

/// The bundle digest every public input of the last verified Circuit 2 carried.
fn verified_digest() -> FieldBytes {
	FakeVerifier::calls()
		.into_iter()
		.find(|c| c.circuit_id == CircuitId::BalanceIntegrity)
		.expect("C2 verified")
		.public_inputs[0][7]
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
			RuntimeEvent::Privacy(
				e @ Event::NoteCreated {
					asset: crate::PrivacyAsset::Native,
					..
				},
			) => Some(e),
			_ => None,
		});
		assert_eq!(
			created,
			Some(Event::NoteCreated {
				asset: crate::PrivacyAsset::Native,
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
			RuntimeEvent::Privacy(
				e @ Event::NoteSpent {
					asset: crate::PrivacyAsset::Native,
					..
				},
			) => Some(e),
			_ => None,
		});
		assert_eq!(
			spent,
			Some(Event::NoteSpent {
				asset: crate::PrivacyAsset::Native,
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
				asset: crate::PrivacyAsset::Native,
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
			asset: PrivacyAsset::Native,
			anchor: Some(anchor),
			inputs: inputs(vec![input(10, 11)]),
			outputs: outputs(vec![]),
			mask_bits: 0,
			expiry_block: EXPIRY,
			proofs: bundle(true, false),
			ptr: None,
			compliance: None,
			value: ValueFlow::Unshield {
				recipient: BOB,
				amount: 42 * UNIT,
			},
			fee: None,
			signer: None,
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
		asset: i.asset,
		anchor: i.anchor,
		inputs: i.inputs.clone(),
		outputs: i.outputs.clone(),
		mask_bits: i.mask_bits,
		expiry_block: i.expiry_block,
		proofs: i.proofs.clone(),
		ptr: None,
		compliance: None,
		value: ValueFlow::Transfer,
		fee: None,
		signer: None,
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
			ptr: None,
			compliance: None,
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
			None,
			None,
			bundle(true, true),
		);

		assert_ok!(relayed);
	});
}

// --- receipts and compliance -------------------------------------------------------------------

#[test]
fn private_transfer_with_receipt_binds_circuit_4_to_the_payment_output_and_the_spends() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::reset();
		let ptr = PtrAttachment {
			payment_output_index: 1,
			ptr_id: fb(0x50),
		};

		assert_ok!(transfer_with(
			anchor,
			outputs(vec![output(20, 21), output(22, 23)]),
			Some(ptr),
			None,
			full_bundle(true, false)
		));

		let c4 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::PtrGeneration)
			.expect("C4 verified");
		let rows = &c4.public_inputs[0];
		assert_eq!(rows[0], fb(0x50), "ptr id");
		assert_eq!(rows[1], fb(23), "cv of output 1");
		assert_eq!(rows[2], fb(22), "cm of output 1");
		assert_eq!(
			[rows[3], rows[4]],
			[fb(10), fb(10)],
			"a one-input bundle repeats its nullifier"
		);
	});
}

#[test]
fn receipt_of_a_two_input_transfer_carries_both_nullifiers_to_circuit_4() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::reset();

		assert_ok!(Privacy::submit_private_transfer(
			RuntimeOrigin::signed(RELAYER),
			anchor,
			inputs(vec![input(10, 11), input(12, 13)]),
			outputs(vec![output(20, 21)]),
			0,
			EXPIRY,
			Some(PtrAttachment {
				payment_output_index: 0,
				ptr_id: fb(0x50),
			}),
			None,
			full_bundle(true, false),
		));

		let c4 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::PtrGeneration)
			.expect("C4 verified");
		assert_eq!(
			[c4.public_inputs[0][3], c4.public_inputs[0][4]],
			[fb(10), fb(12)]
		);
	});
}

#[test]
fn private_transfer_with_receipt_records_it_in_the_sink() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let ptr = PtrAttachment {
			payment_output_index: 0,
			ptr_id: fb(0x50),
		};

		assert_ok!(transfer_with(
			anchor,
			outputs(vec![output(20, 21)]),
			Some(ptr),
			None,
			full_bundle(true, false)
		));

		assert_eq!(
			RecordingSink::recorded(),
			vec![(fb(0x50), fb(21), 0, crate::PrivacyAsset::Native)]
		);
	});
}

#[test]
fn private_transfer_fails_when_receipt_proof_is_missing_or_unexpected() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let ptr = PtrAttachment {
			payment_output_index: 0,
			ptr_id: fb(0x50),
		};

		assert_noop!(
			transfer_with(
				anchor,
				outputs(vec![output(20, 21)]),
				Some(ptr),
				None,
				full_bundle(false, false)
			),
			Error::<Test>::ProofBundleMismatch
		);
		assert_noop!(
			transfer_with(
				anchor,
				outputs(vec![output(20, 21)]),
				None,
				None,
				full_bundle(true, false)
			),
			Error::<Test>::ProofBundleMismatch
		);
	});
}

#[test]
fn private_transfer_fails_with_receipt_index_past_the_outputs() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let ptr = PtrAttachment {
			payment_output_index: 1,
			ptr_id: fb(0x50),
		};

		assert_noop!(
			transfer_with(
				anchor,
				outputs(vec![output(20, 21)]),
				Some(ptr),
				None,
				full_bundle(true, false)
			),
			Error::<Test>::InvalidOutputIndex
		);
	});
}

#[test]
fn private_transfer_with_compliance_verifies_circuit_6_against_the_membership_root() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let root = member_root(0x70);
		FakeVerifier::reset();

		assert_ok!(transfer_with(
			anchor,
			outputs(vec![output(20, 21)]),
			None,
			compliance(0, root),
			full_bundle(false, true)
		));

		let c6 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::TrustRegistryMembership)
			.expect("C6 verified");
		assert_eq!(c6.public_inputs[0][0], root, "membership root");
		assert_eq!(c6.public_inputs[0][1], fb(20), "cm of output 0");
		System::assert_has_event(RuntimeEvent::Privacy(Event::ComplianceAttested {
			asset: crate::PrivacyAsset::Native,
			bundle_digest: last_digest(),
			output_index: 0,
			membership_root: root,
		}));
	});
}

#[test]
fn private_transfer_fails_when_compliance_proof_rejected_and_writes_nothing() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let root = member_root(0x70);
		FakeVerifier::reject_only(CircuitId::TrustRegistryMembership);

		assert_noop!(
			transfer_with(
				anchor,
				outputs(vec![output(20, 21)]),
				None,
				compliance(0, root),
				full_bundle(false, true)
			),
			pallet_zk_verifier::Error::<Test>::InvalidProof
		);
		assert!(!NullifierRegistry::is_spent(&fb(10)));
	});
}

#[test]
fn circuits_are_verified_in_the_fixed_bundle_order() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let root = member_root(0x70);
		FakeVerifier::reset();
		let ptr = PtrAttachment {
			payment_output_index: 0,
			ptr_id: fb(0x50),
		};

		assert_ok!(transfer_with(
			anchor,
			outputs(vec![output(20, 21)]),
			Some(ptr),
			compliance(0, root),
			full_bundle(true, true)
		));

		let order: Vec<CircuitId> = FakeVerifier::calls().iter().map(|c| c.circuit_id).collect();
		assert_eq!(
			order,
			vec![
				CircuitId::NullifierDerivation,
				CircuitId::PrivacyFlagEnforcement,
				CircuitId::BalanceIntegrity,
				CircuitId::PtrGeneration,
				CircuitId::TrustRegistryMembership,
			]
		);
	});
}

// --- attachments are bound to the bundle -------------------------------------------------------

#[test]
fn compliance_accepts_a_superseded_but_recent_registry_root() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let old_root = member_root(0x70);
		let new_root = member_root(0x71);
		assert_ne!(old_root, new_root);
		FakeVerifier::reset();

		assert_ok!(transfer_with(
			anchor,
			outputs(vec![output(20, 21)]),
			None,
			compliance(0, old_root),
			full_bundle(false, true)
		));

		let c6 = FakeVerifier::calls()
			.into_iter()
			.find(|c| c.circuit_id == CircuitId::TrustRegistryMembership)
			.expect("C6 verified");
		assert_eq!(c6.public_inputs[0][0], old_root);
	});
}

#[test]
fn compliance_fails_with_an_unknown_registry_root() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		member_root(0x70);

		assert_noop!(
			transfer_with(
				anchor,
				outputs(vec![output(20, 21)]),
				None,
				compliance(0, fb(0x7f)),
				full_bundle(false, true)
			),
			Error::<Test>::UnknownRegistryRoot
		);
	});
}

#[test]
fn compliance_fails_with_a_non_canonical_registry_root() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_noop!(
			transfer_with(
				anchor,
				outputs(vec![output(20, 21)]),
				None,
				compliance(0, FieldBytes([0xff; 32])),
				full_bundle(false, true)
			),
			Error::<Test>::InvalidFieldElement
		);
	});
}

#[test]
fn compliance_fails_when_its_output_index_points_past_the_outputs() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let root = member_root(0x70);

		assert_noop!(
			transfer_with(
				anchor,
				outputs(vec![output(20, 21)]),
				None,
				compliance(1, root),
				full_bundle(false, true)
			),
			Error::<Test>::InvalidOutputIndex
		);
	});
}

fn digest_of_transfer_with(ptr: Option<PtrAttachment>, compliance_root: Option<u8>) -> FieldBytes {
	let mut digest = FieldBytes::ZERO;
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let attachment = compliance_root.map(|member| ComplianceAttachment {
			output_index: 0,
			registry_root: member_root(member),
		});
		FakeVerifier::reset();
		assert_ok!(transfer_with(
			anchor,
			outputs(vec![output(20, 21)]),
			ptr,
			attachment,
			full_bundle(ptr.is_some(), attachment.is_some())
		));
		digest = verified_digest();
	});
	digest
}

#[test]
fn stripping_the_receipt_changes_the_digest_the_proofs_must_carry() {
	let ptr = PtrAttachment {
		payment_output_index: 0,
		ptr_id: fb(0x50),
	};

	assert_ne!(
		digest_of_transfer_with(Some(ptr), None),
		digest_of_transfer_with(None, None)
	);
}

#[test]
fn stripping_the_compliance_attestation_changes_the_digest_the_proofs_must_carry() {
	assert_ne!(
		digest_of_transfer_with(None, Some(0x70)),
		digest_of_transfer_with(None, None)
	);
}

#[test]
fn retargeting_the_receipt_id_changes_the_digest_the_proofs_must_carry() {
	let ptr = |id| PtrAttachment {
		payment_output_index: 0,
		ptr_id: fb(id),
	};

	assert_ne!(
		digest_of_transfer_with(Some(ptr(0x50)), None),
		digest_of_transfer_with(Some(ptr(0x51)), None)
	);
}

fn shield_arx20(amount: u128, outs: Outputs, mask: u8) -> Result<(), DispatchError> {
	Privacy::shield_arx20(
		RuntimeOrigin::signed(TOKEN),
		arx20_token(),
		amount,
		outs,
		mask,
		EXPIRY,
		bundle(false, true),
	)
}

#[test]
fn shield_arx20_does_not_move_native_arx_or_the_native_tree() {
	new_test_ext().execute_with(|| {
		let pool_before = Privacy::pool_balance();
		assert_ok!(shield_arx20(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		assert_eq!(Balances::balance(&ALICE), ALICE_BALANCE);
		assert_eq!(Privacy::pool_balance(), pool_before);
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
		assert!(NoteTree::contains_leaf(
			TreeId::Arx20(arx20_token()),
			&fb(1)
		));
	});
}

#[test]
fn shield_arx20_rejects_a_signer_that_is_not_the_token() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Privacy::shield_arx20(
				RuntimeOrigin::signed(ALICE),
				arx20_token(),
				42 * UNIT,
				outputs(vec![output(1, 2)]),
				0,
				EXPIRY,
				bundle(false, true),
			),
			Error::<Test>::OnlyArx20Token
		);
		assert_eq!(NoteTree::leaf_count(TreeId::Arx20(arx20_token())), 0);
	});
}

#[test]
fn a_native_anchor_is_unknown_on_an_arx20_unshield() {
	new_test_ext().execute_with(|| {
		let native_anchor = shielded_note(1, 2);

		assert_noop!(
			Privacy::unshield_arx20(
				RuntimeOrigin::signed(TOKEN),
				arx20_token(),
				BOB,
				42 * UNIT,
				native_anchor,
				inputs(vec![input(10, 11)]),
				outputs(vec![]),
				0,
				EXPIRY,
				bundle(true, false),
			),
			Error::<Test>::UnknownAnchor
		);
	});
}

#[test]
fn arx20_unshield_does_not_pay_native_arx() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield_arx20(42 * UNIT, outputs(vec![output(1, 2)]), 0));
		let tree = TreeId::Arx20(arx20_token());
		let anchor = NoteTree::current_root(tree);
		let bob_before = Balances::balance(&BOB);

		assert_ok!(Privacy::unshield_arx20(
			RuntimeOrigin::signed(TOKEN),
			arx20_token(),
			BOB,
			42 * UNIT,
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![]),
			0,
			EXPIRY,
			bundle(true, false),
		));

		assert_eq!(Balances::balance(&BOB), bob_before);
		assert!(NullifierRegistry::is_spent_asset(arx20_token(), &fb(10)));
		assert!(!NullifierRegistry::is_spent(&fb(10)));
	});
}

#[test]
fn arx20_digest_differs_from_native_for_the_same_notes() {
	new_test_ext().execute_with(|| {
		let native = crate::pallet::Intent::<Test> {
			asset: PrivacyAsset::Native,
			anchor: None,
			inputs: Inputs::default(),
			outputs: outputs(vec![output(1, 2)]),
			mask_bits: 0,
			expiry_block: EXPIRY,
			proofs: bundle(false, true),
			ptr: None,
			compliance: None,
			value: ValueFlow::Shield {
				depositor: TOKEN,
				amount: 42 * UNIT,
			},
			fee: None,
			signer: None,
		};
		let token = crate::pallet::Intent::<Test> {
			asset: PrivacyAsset::Arx20(arx20_token()),
			anchor: None,
			inputs: Inputs::default(),
			outputs: outputs(vec![output(1, 2)]),
			mask_bits: 0,
			expiry_block: EXPIRY,
			proofs: bundle(false, true),
			ptr: None,
			compliance: None,
			value: ValueFlow::Shield {
				depositor: TOKEN,
				amount: 42 * UNIT,
			},
			fee: None,
			signer: None,
		};
		let n = Privacy::digest_of(&native, &Privacy::transparent_for_tests(&native));
		let t = Privacy::digest_of(&token, &Privacy::transparent_for_tests(&token));
		assert_ne!(n, t);
	});
}

// --- relayer fee paid from the pool ---------------------------------------------------------------

use crate::{mock::MAX_VALIDITY, HideBalanceAccounts, RelayFee};

fn relay_fee(units: u128) -> RelayFee<u64, u128> {
	RelayFee {
		amount: units * UNIT,
		recipient: RELAYER,
	}
}

/// Public rows of the last verified Circuit 2 instance.
fn c2_rows() -> Vec<FieldBytes> {
	FakeVerifier::calls()
		.into_iter()
		.find(|c| c.circuit_id == CircuitId::BalanceIntegrity)
		.expect("C2 verified")
		.public_inputs[0]
		.to_vec()
}

const C2_FEE_ROW: usize = 6;

fn transfer_with_fee(anchor: FieldBytes, fee: RelayFee<u64, u128>) -> Result<(), DispatchError> {
	Privacy::submit_private_transfer_with_fee(
		RuntimeOrigin::signed(RELAYER),
		anchor,
		inputs(vec![input(10, 11)]),
		outputs(vec![output(20, 21)]),
		0,
		EXPIRY,
		None,
		None,
		fee,
		bundle(true, true),
	)
}

fn unshield_with_fee(
	recipient: u64,
	amount: u128,
	anchor: FieldBytes,
	fee: RelayFee<u64, u128>,
) -> Result<(), DispatchError> {
	Privacy::unshield_with_fee(
		RuntimeOrigin::signed(RELAYER),
		recipient,
		amount,
		anchor,
		inputs(vec![input(10, 11)]),
		outputs(vec![]),
		0,
		EXPIRY,
		fee,
		bundle(true, false),
	)
}

#[test]
fn a_relayed_private_transfer_pays_the_relayer_from_the_pool() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let relayer_before = Balances::balance(&RELAYER);
		let pool_before = Privacy::pool_balance();
		FakeVerifier::reset();

		assert_ok!(transfer_with_fee(anchor, relay_fee(2)));

		assert_eq!(Balances::balance(&RELAYER), relayer_before + 2 * UNIT);
		assert_eq!(Privacy::pool_balance(), pool_before - 2 * UNIT);
		assert_eq!(c2_rows()[C2_FEE_ROW], FieldBytes::from_u64(2));
		System::assert_has_event(RuntimeEvent::Privacy(Event::FeePaid {
			asset: PrivacyAsset::Native,
			recipient: RELAYER,
			amount: 2 * UNIT,
			bundle_digest: last_digest(),
		}));
	});
}

#[test]
fn a_relayed_unshield_pays_the_recipient_and_the_relayer() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let relayer_before = Balances::balance(&RELAYER);

		assert_ok!(unshield_with_fee(BOB, 40 * UNIT, anchor, relay_fee(2)));

		assert_eq!(Balances::balance(&BOB), 40 * UNIT);
		assert_eq!(Balances::balance(&RELAYER), relayer_before + 2 * UNIT);
		assert_eq!(Privacy::pool_balance(), 0);
	});
}

#[test]
fn a_relayed_unshield_fails_when_the_pool_cannot_cover_amount_and_fee() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_noop!(
			unshield_with_fee(BOB, 41 * UNIT, anchor, relay_fee(2)),
			Error::<Test>::PoolInsufficient
		);
	});
}

#[test]
fn a_fee_must_be_a_positive_multiple_of_the_unit() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		let odd = RelayFee {
			amount: UNIT + 1,
			recipient: RELAYER,
		};
		let zero = RelayFee {
			amount: 0,
			recipient: RELAYER,
		};

		assert_noop!(
			transfer_with_fee(anchor, odd),
			Error::<Test>::AmountNotMultipleOfUnit
		);
		assert_noop!(transfer_with_fee(anchor, zero), Error::<Test>::ZeroAmount);
	});
}

#[test]
fn the_fee_and_its_recipient_are_bound_into_the_digest() {
	let digest_with = |recipient: u64, units: u128| {
		let mut digest = FieldBytes::ZERO;
		new_test_ext().execute_with(|| {
			let anchor = shielded_note(1, 2);
			FakeVerifier::reset();
			assert_ok!(transfer_with_fee(
				anchor,
				RelayFee {
					amount: units * UNIT,
					recipient
				}
			));
			digest = verified_digest();
		});
		digest
	};

	assert_ne!(digest_with(RELAYER, 2), digest_with(BOB, 2));
	assert_ne!(digest_with(RELAYER, 2), digest_with(RELAYER, 3));
}

#[test]
fn a_fee_free_bundle_keeps_a_zero_fee_row() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		FakeVerifier::reset();

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0
		));

		assert_eq!(c2_rows()[C2_FEE_ROW], FieldBytes::ZERO);
	});
}

// --- hide-balance ---------------------------------------------------------------------------------

/// A flag set long ago (no pending change): in force at once.
fn flag(who: u64) {
	HideBalanceAccounts::<Test>::insert(who, true);
}

fn unshield_masked(
	signer: u64,
	recipient: u64,
	anchor: FieldBytes,
	mask: u8,
) -> Result<(), DispatchError> {
	Privacy::unshield(
		RuntimeOrigin::signed(signer),
		recipient,
		40 * UNIT,
		anchor,
		inputs(vec![input(10, 11)]),
		outputs(vec![output(30, 31)]),
		mask,
		EXPIRY,
		bundle(true, true),
	)
}

#[test]
fn turning_hide_balance_on_takes_effect_after_the_proof_validity_window() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::set_balance_visibility(
			RuntimeOrigin::signed(ALICE),
			true
		));
		let effective_from = 1 + MAX_VALIDITY + 1;

		System::assert_last_event(RuntimeEvent::Privacy(Event::BalanceVisibilitySet {
			who: ALICE,
			hidden: true,
			effective_from,
		}));
		assert!(!Privacy::is_balance_hidden(&ALICE));
		System::set_block_number(effective_from - 1);
		assert!(!Privacy::is_balance_hidden(&ALICE));
		System::set_block_number(effective_from);
		assert!(Privacy::is_balance_hidden(&ALICE));
	});
}

#[test]
fn turning_hide_balance_off_also_waits_for_the_window() {
	new_test_ext().execute_with(|| {
		flag(ALICE);
		System::set_block_number(10);

		assert_ok!(Privacy::set_balance_visibility(
			RuntimeOrigin::signed(ALICE),
			false
		));

		assert!(Privacy::is_balance_hidden(&ALICE));
		System::set_block_number(10 + MAX_VALIDITY + 1);
		assert!(!Privacy::is_balance_hidden(&ALICE));
	});
}

#[test]
fn repeating_the_current_flag_does_not_restart_the_window() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::set_balance_visibility(
			RuntimeOrigin::signed(ALICE),
			true
		));
		System::set_block_number(1 + MAX_VALIDITY + 1);
		assert!(Privacy::is_balance_hidden(&ALICE));

		assert_ok!(Privacy::set_balance_visibility(
			RuntimeOrigin::signed(ALICE),
			true
		));

		assert!(Privacy::is_balance_hidden(&ALICE));
	});
}

#[test]
fn a_bundle_marked_hide_balance_cannot_unshield() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_noop!(
			unshield_masked(RELAYER, BOB, anchor, 0b1000),
			Error::<Test>::HideBalanceForbidsUnshield
		);
	});
}

#[test]
fn a_bundle_marked_hide_balance_can_still_pay_privately() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);

		assert_ok!(transfer(
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0b1000
		));
	});
}

#[test]
fn pool_value_cannot_be_unshielded_to_an_account_that_hides_its_balance() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		flag(BOB);

		assert_noop!(
			unshield_masked(RELAYER, BOB, anchor, 0),
			Error::<Test>::RecipientHidesBalance
		);
	});
}

/// A recipient that turns the flag on while a relayer is submitting its unshield
/// cannot make the relayer pay for a rejected bundle.
#[test]
fn a_flag_still_maturing_does_not_reject_an_unshield_in_flight() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		assert_ok!(Privacy::set_balance_visibility(
			RuntimeOrigin::signed(BOB),
			true
		));

		assert_ok!(unshield_masked(RELAYER, BOB, anchor, 0));
	});
}

#[test]
fn an_account_that_hides_its_balance_cannot_sign_an_unshield() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		flag(ALICE);

		assert_noop!(
			unshield_masked(ALICE, BOB, anchor, 0),
			Error::<Test>::SenderHidesBalance
		);
	});
}

/// Circuit 3 forces a revealed sender to be the spent note's owner, so a
/// revealed sender registered to a flagged account is that account spending.
#[test]
fn a_revealed_sender_that_hides_its_balance_cannot_unshield() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(ALICE),
			fb(0xa0)
		));
		flag(ALICE);

		assert_noop!(
			unshield_masked(RELAYER, BOB, anchor, 0),
			Error::<Test>::SenderHidesBalance
		);
	});
}

/// The documented limit: with the sender hidden the chain cannot tell whose
/// notes are spent, so only the owner's wallet (which sets bit 3) applies the rule.
#[test]
fn a_hidden_sender_is_not_checked_against_the_flag() {
	new_test_ext().execute_with(|| {
		let anchor = shielded_note(1, 2);
		assert_ok!(Privacy::register_shielded_key(
			RuntimeOrigin::signed(ALICE),
			fb(0xa0)
		));
		flag(ALICE);

		assert_ok!(unshield_masked(RELAYER, BOB, anchor, 0b0001));
	});
}

// --- ARX-20: contracts only, per-token unit, asset everywhere -------------------------------------

use crate::{mock::EOA_TOKEN, Arx20Unit};

fn eoa_token() -> sp_core::H160 {
	sp_core::H160::from_low_u64_be(EOA_TOKEN)
}

#[test]
fn an_account_without_contract_code_cannot_run_an_arx20_pool() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Privacy::shield_arx20(
				RuntimeOrigin::signed(EOA_TOKEN),
				eoa_token(),
				42 * UNIT,
				outputs(vec![output(1, 2)]),
				0,
				EXPIRY,
				bundle(false, true),
			),
			Error::<Test>::NotATokenContract
		);
	});
}

#[test]
fn arx20_events_and_receipts_name_the_token() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield_arx20(42 * UNIT, outputs(vec![output(1, 2)]), 0));

		System::assert_has_event(RuntimeEvent::Privacy(Event::Shielded {
			asset: PrivacyAsset::Arx20(arx20_token()),
			depositor: TOKEN,
			amount: 42 * UNIT,
			bundle_digest: last_digest(),
		}));
		let anchor = NoteTree::current_root(TreeId::Arx20(arx20_token()));
		assert_ok!(Privacy::submit_private_transfer_arx20(
			RuntimeOrigin::signed(TOKEN),
			arx20_token(),
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0,
			EXPIRY,
			Some(PtrAttachment {
				payment_output_index: 0,
				ptr_id: fb(0x50)
			}),
			None,
			full_bundle(true, false),
		));
		assert_eq!(
			RecordingSink::recorded(),
			vec![(fb(0x50), fb(21), 0, PrivacyAsset::Arx20(arx20_token()))]
		);
	});
}

#[test]
fn a_relayed_arx20_transfer_moves_no_native_arx_and_reports_the_token_fee() {
	new_test_ext().execute_with(|| {
		assert_ok!(shield_arx20(42 * UNIT, outputs(vec![output(1, 2)]), 0));
		let anchor = NoteTree::current_root(TreeId::Arx20(arx20_token()));
		let relayer_before = Balances::balance(&RELAYER);

		assert_ok!(Privacy::submit_private_transfer_arx20_with_fee(
			RuntimeOrigin::signed(TOKEN),
			arx20_token(),
			anchor,
			inputs(vec![input(10, 11)]),
			outputs(vec![output(20, 21)]),
			0,
			EXPIRY,
			None,
			None,
			relay_fee(2),
			bundle(true, true),
		));

		assert_eq!(Balances::balance(&RELAYER), relayer_before);
		System::assert_has_event(RuntimeEvent::Privacy(Event::FeePaid {
			asset: PrivacyAsset::Arx20(arx20_token()),
			recipient: RELAYER,
			amount: 2 * UNIT,
			bundle_digest: last_digest(),
		}));
	});
}

fn set_unit(decimals: u8) -> Result<(), DispatchError> {
	Privacy::set_arx20_unit(RuntimeOrigin::signed(TOKEN), arx20_token(), decimals)
}

#[test]
fn a_token_unit_follows_its_decimals() {
	for (decimals, unit) in [
		(6u8, 1u128),
		(9, 1),
		(18, 1_000_000_000),
		(24, 10u128.pow(15)),
	] {
		new_test_ext().execute_with(|| {
			assert_ok!(set_unit(decimals));

			assert_eq!(Arx20Unit::<Test>::get(arx20_token()), Some(unit));
			System::assert_last_event(RuntimeEvent::Privacy(Event::Arx20UnitSet {
				token: arx20_token(),
				unit,
			}));
		});
	}
}

#[test]
fn a_six_decimal_token_shields_amounts_below_the_native_unit() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			shield_arx20(5, outputs(vec![output(1, 2)]), 0),
			Error::<Test>::AmountNotMultipleOfUnit
		);
		assert_ok!(set_unit(6));
		FakeVerifier::reset();

		assert_ok!(shield_arx20(5, outputs(vec![output(1, 2)]), 0));

		assert_eq!(
			c2_rows()[4],
			FieldBytes::from_u64(5),
			"transparent_in in token units"
		);
	});
}

#[test]
fn a_token_unit_is_set_once_and_only_while_the_pool_is_empty() {
	new_test_ext().execute_with(|| {
		assert_ok!(set_unit(18));
		assert_noop!(set_unit(6), Error::<Test>::Arx20UnitAlreadySet);
	});
	new_test_ext().execute_with(|| {
		assert_ok!(shield_arx20(42 * UNIT, outputs(vec![output(1, 2)]), 0));
		assert_noop!(set_unit(6), Error::<Test>::Arx20PoolNotEmpty);
	});
}

#[test]
fn a_token_unit_rejects_absurd_decimals_and_other_signers() {
	new_test_ext().execute_with(|| {
		assert_noop!(set_unit(37), Error::<Test>::InvalidDecimals);
		assert_noop!(
			Privacy::set_arx20_unit(RuntimeOrigin::signed(ALICE), arx20_token(), 6),
			Error::<Test>::OnlyArx20Token
		);
	});
}

/// The constructor of a token calls this before its code is stored, so the
/// contract-code requirement does not apply here.
#[test]
fn an_account_without_code_may_still_fix_its_unit() {
	new_test_ext().execute_with(|| {
		assert_ok!(Privacy::set_arx20_unit(
			RuntimeOrigin::signed(EOA_TOKEN),
			eoa_token(),
			6
		));
	});
}
