//! End to end: real Halo2 proofs through the real runtime, natively.
//!
//! The dev genesis funds Alith. Alice (a shielded key) shields 42 ARX,
//! transfers 40 to Bob's shielded key with 2 of change while hiding sender,
//! receiver and amount, and Bob unshields his 40 to Baltathar's transparent
//! account. Then two proofs that must fail: a flipped byte, and a bundle
//! re-targeted to another recipient.

use arxon_zk::{
	circuits::{C1Circuit, C2Circuit, C3Circuit, C4Circuit, C5Circuit, C6Circuit},
	merkle::{MemberTree as ReferenceMemberTree, NoteTree as ReferenceNoteTree, TreeKind},
	primitives::{
		poseidon::{fp_from_bytes, fp_to_bytes},
		FieldBytes, Proof, SHIELDED_UNIT,
	},
	prove,
	wallet::{
		balance_witness, member_leaf, membership_witness, output_witnesses, spend_witnesses,
		BundleContext, OutputNote, Receipt, SpendNote, SpendingKey,
	},
	Fp,
};
use frame_support::{assert_ok, traits::fungible::Inspect, BoundedVec};
use hex_literal::hex;
use pallet_note_tree::{MerkleTree, TreeId};
use pallet_privacy::{
	pallet::{Intent, ValueFlow},
	ComplianceAttachment, Input, Inputs, Output, Outputs, ProofBundle, PtrAttachment,
};
use rand_core::OsRng;
use sp_runtime::BuildStorage;

use crate::{
	AccountId, Balance, Balances, NoteTree, NullifierRegistry, Privacy, Runtime,
	RuntimeGenesisConfig, RuntimeOrigin, System, PTR,
};

const EXPIRY: u32 = 100;
const MASK_ALL_HIDDEN: u8 = 0b0111;

fn alith() -> AccountId {
	AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"))
}

fn baltathar() -> AccountId {
	AccountId::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0"))
}

fn units(n: u64) -> Balance {
	n as Balance * SHIELDED_UNIT
}

fn dev_ext() -> sp_io::TestExternalities {
	let genesis: RuntimeGenesisConfig =
		serde_json::from_value(crate::genesis_config_preset::development())
			.expect("dev preset is a full genesis config");
	let mut ext: sp_io::TestExternalities = genesis.build_storage().unwrap().into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}

fn empty_proofs() -> ProofBundle {
	ProofBundle {
		spend: None,
		output: None,
		balance: BoundedVec::default(),
		receipt: None,
		compliance: None,
	}
}

fn proof_of(bytes: Vec<u8>) -> Proof {
	Proof::try_from(bytes).expect("proof within cap")
}

fn output_arg(o: &OutputNote) -> Output {
	Output {
		cm: o.cm_bytes(),
		cv: o.cv_bytes(),
		revealed_receiver: fp_to_bytes(&o.note.pk),
		revealed_amount: FieldBytes::from_u64(o.note.amount),
		encrypted_note: BoundedVec::truncate_from(b"ciphertext for the receiver".to_vec()),
	}
}

fn input_arg(s: &SpendNote) -> Input {
	Input {
		nullifier: s.nullifier_bytes(),
		cv: s.cv_bytes(),
		revealed_sender: fp_to_bytes(&s.sk.pk()),
	}
}

/// Optional attachments of a bundle: a receipt for one output, a membership proof for one output.
#[derive(Default)]
struct Attachments {
	receipt: Option<(u8, Receipt)>,
	membership: Option<(
		u8,
		arxon_zk::gadgets::merkle::MerklePath<{ arxon_zk::primitives::MEMBER_TREE_DEPTH }>,
	)>,
}

impl Attachments {
	fn ptr(&self) -> Option<PtrAttachment> {
		self.receipt.as_ref().map(|(i, r)| PtrAttachment {
			payment_output_index: *i,
			ptr_id: r.ptr_id_bytes(),
		})
	}

	fn compliance(&self) -> Option<ComplianceAttachment> {
		self.membership.as_ref().map(|(i, _)| ComplianceAttachment {
			output_index: *i,
			registry_root: NoteTree::current_root(TreeId::Membership),
		})
	}
}

/// Builds the bundle context the pallet will expect and proves every circuit of it.
fn prove_bundle(
	spends: &[SpendNote],
	outputs: &[OutputNote],
	anchor: Option<FieldBytes>,
	mask: u8,
	value: ValueFlow<Runtime>,
) -> ProofBundle {
	prove_bundle_with(
		spends,
		outputs,
		anchor,
		mask,
		value,
		&Attachments::default(),
	)
}

fn prove_bundle_with(
	spends: &[SpendNote],
	outputs: &[OutputNote],
	anchor: Option<FieldBytes>,
	mask: u8,
	value: ValueFlow<Runtime>,
	attachments: &Attachments,
) -> ProofBundle {
	let intent = Intent::<Runtime> {
		anchor,
		inputs: Inputs::truncate_from(spends.iter().map(input_arg).collect()),
		outputs: Outputs::truncate_from(outputs.iter().map(output_arg).collect()),
		mask_bits: mask,
		expiry_block: EXPIRY,
		proofs: empty_proofs(),
		ptr: attachments.ptr(),
		compliance: attachments.compliance(),
		value,
	};
	let (transparent_in, transparent_out) = match &intent.value {
		ValueFlow::Shield { amount, .. } => ((*amount / SHIELDED_UNIT) as u64, 0),
		ValueFlow::Unshield { amount, .. } => (0, (*amount / SHIELDED_UNIT) as u64),
		ValueFlow::Transfer => (0, 0),
	};
	let digest = Privacy::bundle_digest_for(&intent).expect("valid intent");
	let ctx = BundleContext {
		mask,
		bundle_digest: fp_from_bytes(&digest).expect("digest is canonical"),
		expiry_block: EXPIRY,
		transparent_in,
		transparent_out,
	};
	let spend = (!spends.is_empty())
		.then(|| proof_of(prove::<C3Circuit>(&spend_witnesses(spends, &ctx), OsRng).unwrap()));
	let output = (!outputs.is_empty())
		.then(|| proof_of(prove::<C1Circuit>(&output_witnesses(outputs, &ctx), OsRng).unwrap()));
	let balance =
		proof_of(prove::<C2Circuit>(&[balance_witness(spends, outputs, &ctx)], OsRng).unwrap());
	let receipt = attachments
		.receipt
		.as_ref()
		.map(|(_, r)| proof_of(prove::<C4Circuit>(&[r.generation_witness(&ctx)], OsRng).unwrap()));
	let compliance = attachments.membership.as_ref().map(|(i, path)| {
		proof_of(
			prove::<C6Circuit>(
				&[membership_witness(
					&outputs[*i as usize],
					path.clone(),
					&ctx,
				)],
				OsRng,
			)
			.unwrap(),
		)
	});
	ProofBundle {
		spend,
		output,
		balance,
		receipt,
		compliance,
	}
}

fn outputs_arg(outputs: &[OutputNote]) -> Outputs {
	Outputs::truncate_from(outputs.iter().map(output_arg).collect())
}

fn inputs_arg(spends: &[SpendNote]) -> Inputs {
	Inputs::truncate_from(spends.iter().map(input_arg).collect())
}

fn note_root() -> Fp {
	fp_from_bytes(&NoteTree::current_root(TreeId::Note)).unwrap()
}

#[test]
fn shield_transfer_and_unshield_with_real_proofs() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let bob = SpendingKey::random(&mut rng);
		let mut reference = ReferenceNoteTree::new(TreeKind::Note);
		let alith_before = Balances::balance(&alith());

		// 1. Alith shields 42 ARX into a note owned by Alice's shielded key.
		let shielded = OutputNote::new(alice.pk(), 42, &mut rng);
		let proofs = prove_bundle(
			&[],
			&[shielded],
			None,
			0,
			ValueFlow::Shield {
				depositor: alith(),
				amount: units(42),
			},
		);
		assert_ok!(Privacy::shield(
			RuntimeOrigin::signed(alith()),
			units(42),
			outputs_arg(&[shielded]),
			0,
			EXPIRY,
			proofs
		));
		reference.insert(shielded.note.commitment());

		assert_eq!(Balances::balance(&alith()), alith_before - units(42));
		assert_eq!(Privacy::pool_balance(), units(42));
		assert_eq!(
			note_root(),
			reference.root(),
			"on-chain incremental tree matches the reference tree"
		);
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 1);

		// 2. Alice privately pays Bob 40 with 2 of change, hiding sender, receiver and amount.
		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let to_bob = OutputNote::new(bob.pk(), 40, &mut rng);
		let change = OutputNote::new(alice.pk(), 2, &mut rng);
		let anchor = fp_to_bytes(&reference.root());
		let proofs = prove_bundle(
			std::slice::from_ref(&spend),
			&[to_bob, change],
			Some(anchor),
			MASK_ALL_HIDDEN,
			ValueFlow::Transfer,
		);
		assert_ok!(Privacy::submit_private_transfer(
			RuntimeOrigin::signed(baltathar()),
			anchor,
			inputs_arg(std::slice::from_ref(&spend)),
			outputs_arg(&[to_bob, change]),
			MASK_ALL_HIDDEN,
			EXPIRY,
			None,
			None,
			proofs,
		));
		reference.insert(to_bob.note.commitment());
		reference.insert(change.note.commitment());

		assert!(NullifierRegistry::is_spent(&spend.nullifier_bytes()));
		assert_eq!(note_root(), reference.root());
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 3);
		assert_eq!(
			Privacy::pool_balance(),
			units(42),
			"a private transfer moves no transparent value"
		);

		// 3. Bob unshields his 40 to Baltathar's transparent account.
		let bob_spend = SpendNote::new(bob, to_bob.note, reference.path(1), &mut rng);
		let anchor = fp_to_bytes(&reference.root());
		let baltathar_before = Balances::balance(&baltathar());
		let proofs = prove_bundle(
			std::slice::from_ref(&bob_spend),
			&[],
			Some(anchor),
			0,
			ValueFlow::Unshield {
				recipient: baltathar(),
				amount: units(40),
			},
		);
		assert_ok!(Privacy::unshield(
			RuntimeOrigin::signed(baltathar()),
			baltathar(),
			units(40),
			anchor,
			inputs_arg(std::slice::from_ref(&bob_spend)),
			outputs_arg(&[]),
			0,
			EXPIRY,
			proofs,
		));

		assert_eq!(
			Balances::balance(&baltathar()),
			baltathar_before + units(40)
		);
		assert_eq!(Privacy::pool_balance(), units(2));
		assert!(NullifierRegistry::is_spent(&bob_spend.nullifier_bytes()));
	});
}

#[test]
fn tampered_proof_is_rejected_natively() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let shielded = OutputNote::new(alice.pk(), 42, &mut rng);
		let mut proofs = prove_bundle(
			&[],
			&[shielded],
			None,
			0,
			ValueFlow::Shield {
				depositor: alith(),
				amount: units(42),
			},
		);
		let mut balance = proofs.balance.into_inner();
		balance[100] ^= 1;
		proofs.balance = proof_of(balance);

		let result = Privacy::shield(
			RuntimeOrigin::signed(alith()),
			units(42),
			outputs_arg(&[shielded]),
			0,
			EXPIRY,
			proofs,
		);

		assert_eq!(
			result,
			Err(pallet_zk_verifier::Error::<Runtime>::InvalidProof.into())
		);
		assert_eq!(Privacy::pool_balance(), 0);
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
	});
}

#[test]
fn unshield_retargeted_to_another_recipient_is_rejected() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let mut reference = ReferenceNoteTree::new(TreeKind::Note);
		let shielded = OutputNote::new(alice.pk(), 42, &mut rng);
		let proofs = prove_bundle(
			&[],
			&[shielded],
			None,
			0,
			ValueFlow::Shield {
				depositor: alith(),
				amount: units(42),
			},
		);
		assert_ok!(Privacy::shield(
			RuntimeOrigin::signed(alith()),
			units(42),
			outputs_arg(&[shielded]),
			0,
			EXPIRY,
			proofs
		));
		reference.insert(shielded.note.commitment());
		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let anchor = fp_to_bytes(&reference.root());
		// Proofs bound to Baltathar as recipient...
		let proofs = prove_bundle(
			std::slice::from_ref(&spend),
			&[],
			Some(anchor),
			0,
			ValueFlow::Unshield {
				recipient: baltathar(),
				amount: units(42),
			},
		);

		// ...submitted with Alith as recipient instead.
		let result = Privacy::unshield(
			RuntimeOrigin::signed(baltathar()),
			alith(),
			units(42),
			anchor,
			inputs_arg(std::slice::from_ref(&spend)),
			outputs_arg(&[]),
			0,
			EXPIRY,
			proofs,
		);

		assert_eq!(
			result,
			Err(pallet_zk_verifier::Error::<Runtime>::InvalidProof.into())
		);
		assert!(!NullifierRegistry::is_spent(&spend.nullifier_bytes()));
		assert_eq!(Privacy::pool_balance(), units(42));
	});
}

#[test]
fn runtime_api_reports_the_shielded_pool_state() {
	use arxon_zk_runtime_api::runtime_decl_for_arxon_zk_api::ArxonZkApiV1;

	dev_ext().execute_with(|| {
		assert_eq!(Runtime::note_tree_root(), NoteTree::root(TreeId::Note).0);
		assert_eq!(
			Runtime::membership_root(),
			NoteTree::root(TreeId::Membership).0
		);
		assert_eq!(Runtime::leaf_count(0), 0);
		assert!(!Runtime::is_nullifier_spent([7u8; 32]));
		assert!(Runtime::circuit_enabled(1));
		assert!(Runtime::circuit_enabled(3));
		assert!(!Runtime::circuit_enabled(7));
	});
}

#[test]
fn receipt_attached_to_a_private_payment_can_be_disclosed_to_an_auditor() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let bob = SpendingKey::random(&mut rng);
		let mut reference = ReferenceNoteTree::new(TreeKind::Note);
		let shielded = OutputNote::new(alice.pk(), 42, &mut rng);
		let proofs = prove_bundle(
			&[],
			&[shielded],
			None,
			0,
			ValueFlow::Shield {
				depositor: alith(),
				amount: units(42),
			},
		);
		assert_ok!(Privacy::shield(
			RuntimeOrigin::signed(alith()),
			units(42),
			outputs_arg(&[shielded]),
			0,
			EXPIRY,
			proofs
		));
		reference.insert(shielded.note.commitment());

		// Alice pays Bob 40 with a receipt attached to that output, hiding everything.
		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let to_bob = OutputNote::new(bob.pk(), 40, &mut rng);
		let change = OutputNote::new(alice.pk(), 2, &mut rng);
		let receipt = Receipt::new(&alice, to_bob, &mut rng);
		let attachments = Attachments {
			receipt: Some((0, receipt)),
			membership: None,
		};
		let anchor = fp_to_bytes(&reference.root());
		let proofs = prove_bundle_with(
			std::slice::from_ref(&spend),
			&[to_bob, change],
			Some(anchor),
			MASK_ALL_HIDDEN,
			ValueFlow::Transfer,
			&attachments,
		);
		// A relayer that strips the receipt cannot reuse the proofs: they carry the digest
		// of the bundle with the receipt attached.
		let stripped = Privacy::submit_private_transfer(
			RuntimeOrigin::signed(baltathar()),
			anchor,
			inputs_arg(std::slice::from_ref(&spend)),
			outputs_arg(&[to_bob, change]),
			MASK_ALL_HIDDEN,
			EXPIRY,
			None,
			None,
			ProofBundle {
				receipt: None,
				..proofs.clone()
			},
		);
		assert_eq!(
			stripped,
			Err(pallet_zk_verifier::Error::<Runtime>::InvalidProof.into())
		);
		assert_ok!(Privacy::submit_private_transfer(
			RuntimeOrigin::signed(baltathar()),
			anchor,
			inputs_arg(std::slice::from_ref(&spend)),
			outputs_arg(&[to_bob, change]),
			MASK_ALL_HIDDEN,
			EXPIRY,
			attachments.ptr(),
			None,
			proofs,
		));
		let stored = PTR::receipt(&receipt.ptr_id_bytes()).expect("receipt recorded");
		assert_eq!(stored.cv, to_bob.cv_bytes());
		assert_eq!(stored.mask_bits, MASK_ALL_HIDDEN);

		// Alice discloses only the amount to Baltathar, the auditor.
		let audience = fp_from_bytes(&PTR::audience_of(&baltathar())).unwrap();
		let disclosure = receipt.disclosure_witness(0b0011, audience, EXPIRY);
		let proof = proof_of(prove::<C5Circuit>(&[disclosure], OsRng).unwrap());
		let revealed = pallet_ptr::RevealedValues {
			sender: fp_to_bytes(&alice.pk()),
			receiver: fp_to_bytes(&bob.pk()),
			amount: FieldBytes::from_u64(40),
		};
		assert_ok!(PTR::disclose(
			RuntimeOrigin::signed(baltathar()),
			receipt.ptr_id_bytes(),
			0b0011,
			revealed,
			EXPIRY,
			proof.clone()
		));
		System::assert_has_event(
			pallet_ptr::Event::<Runtime>::Disclosed {
				ptr_id: receipt.ptr_id_bytes(),
				verifier: baltathar(),
				disclosure_mask: 0b0011,
				sender: None,
				receiver: None,
				amount: Some(40),
			}
			.into(),
		);

		// The same disclosure proof does not work for another auditor.
		let replay = PTR::disclose(
			RuntimeOrigin::signed(alith()),
			receipt.ptr_id_bytes(),
			0b0011,
			revealed,
			EXPIRY,
			proof,
		);
		assert_eq!(
			replay,
			Err(pallet_zk_verifier::Error::<Runtime>::InvalidProof.into())
		);
	});
}

#[test]
fn payment_to_a_registered_counterparty_carries_a_membership_attestation() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let exchange = SpendingKey::random(&mut rng);
		let mut reference = ReferenceNoteTree::new(TreeKind::Note);
		let mut registry = ReferenceMemberTree::new(TreeKind::Member);

		// Root registers the exchange's shielded key in the trust registry.
		let leaf = fp_to_bytes(&member_leaf(exchange.pk()));
		assert_ok!(NoteTree::add_member(RuntimeOrigin::root(), leaf));
		let index = registry.insert(member_leaf(exchange.pk()));
		assert_eq!(
			fp_from_bytes(&NoteTree::current_root(TreeId::Membership)).unwrap(),
			registry.root()
		);

		let shielded = OutputNote::new(alice.pk(), 42, &mut rng);
		let proofs = prove_bundle(
			&[],
			&[shielded],
			None,
			0,
			ValueFlow::Shield {
				depositor: alith(),
				amount: units(42),
			},
		);
		assert_ok!(Privacy::shield(
			RuntimeOrigin::signed(alith()),
			units(42),
			outputs_arg(&[shielded]),
			0,
			EXPIRY,
			proofs
		));
		reference.insert(shielded.note.commitment());

		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let to_exchange = OutputNote::new(exchange.pk(), 42, &mut rng);
		let attachments = Attachments {
			receipt: None,
			membership: Some((0, registry.path(index))),
		};
		let anchor = fp_to_bytes(&reference.root());
		let proofs = prove_bundle_with(
			std::slice::from_ref(&spend),
			&[to_exchange],
			Some(anchor),
			MASK_ALL_HIDDEN,
			ValueFlow::Transfer,
			&attachments,
		);
		assert_ok!(Privacy::submit_private_transfer(
			RuntimeOrigin::signed(baltathar()),
			anchor,
			inputs_arg(std::slice::from_ref(&spend)),
			outputs_arg(&[to_exchange]),
			MASK_ALL_HIDDEN,
			EXPIRY,
			None,
			attachments.compliance(),
			proofs,
		));

		let attested = System::events().into_iter().any(|r| {
			matches!(
				r.event,
				crate::RuntimeEvent::Privacy(pallet_privacy::Event::ComplianceAttested { output_index: 0, membership_root, .. })
					if membership_root == NoteTree::current_root(TreeId::Membership)
			)
		});
		assert!(attested, "compliance attestation event emitted");
	});
}
