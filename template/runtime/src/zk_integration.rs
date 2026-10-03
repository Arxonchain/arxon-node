//! End to end: real Halo2 proofs through the real runtime, natively.
//!
//! The dev genesis funds Alith. Alice (a shielded key) shields 42 ARX,
//! transfers 40 to Bob's shielded key with 2 of change while hiding sender,
//! receiver and amount, and Bob unshields his 40 to Baltathar's transparent
//! account. Then two proofs that must fail: a flipped byte, and a bundle
//! re-targeted to another recipient. Relayed bundles pay their relayer from
//! the pool, hide-balance blocks unshields, and a 6-decimal ARX-20 token
//! shields amounts in its own unit.

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
	ComplianceAttachment, HideBalanceAccounts, Input, Inputs, Output, Outputs, PrivacyAsset,
	ProofBundle, PtrAttachment, RelayFee, RelayFeeOf,
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

/// The relayer of the relayed bundles.
fn charleth() -> AccountId {
	AccountId::from(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc"))
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

/// Optional parts of a bundle: a receipt for one output, a membership proof
/// for one output, a relayer fee, and the pool (native ARX when `None`).
#[derive(Default)]
struct Attachments {
	receipt: Option<(u8, Receipt)>,
	membership: Option<(
		u8,
		arxon_zk::gadgets::merkle::MerklePath<{ arxon_zk::primitives::MEMBER_TREE_DEPTH }>,
	)>,
	fee: Option<RelayFeeOf<Runtime>>,
	asset: Option<PrivacyAsset>,
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
	let asset = attachments.asset.unwrap_or(PrivacyAsset::Native);
	let unit = Privacy::unit_of(asset);
	let intent = Intent::<Runtime> {
		asset,
		anchor,
		inputs: Inputs::truncate_from(spends.iter().map(input_arg).collect()),
		outputs: Outputs::truncate_from(outputs.iter().map(output_arg).collect()),
		mask_bits: mask,
		expiry_block: EXPIRY,
		proofs: empty_proofs(),
		ptr: attachments.ptr(),
		compliance: attachments.compliance(),
		value,
		fee: attachments.fee.clone(),
		signer: None,
	};
	let (transparent_in, transparent_out) = match &intent.value {
		ValueFlow::Shield { amount, .. } => ((*amount / unit) as u64, 0),
		ValueFlow::Unshield { amount, .. } => (0, (*amount / unit) as u64),
		ValueFlow::Transfer => (0, 0),
	};
	let fee = attachments
		.fee
		.as_ref()
		.map_or(0, |f| (f.amount / unit) as u64);
	let digest = Privacy::bundle_digest_for(&intent).expect("valid intent");
	let ctx = BundleContext {
		mask,
		bundle_digest: fp_from_bytes(&digest).expect("digest is canonical"),
		expiry_block: EXPIRY,
		transparent_in,
		transparent_out,
		fee,
	};
	let spend = (!spends.is_empty())
		.then(|| proof_of(prove::<C3Circuit>(&spend_witnesses(spends, &ctx), OsRng).unwrap()));
	let output = (!outputs.is_empty())
		.then(|| proof_of(prove::<C1Circuit>(&output_witnesses(outputs, &ctx), OsRng).unwrap()));
	let balance =
		proof_of(prove::<C2Circuit>(&[balance_witness(spends, outputs, &ctx)], OsRng).unwrap());
	let receipt = attachments.receipt.as_ref().map(|(_, r)| {
		proof_of(prove::<C4Circuit>(&[r.generation_witness(spends, &ctx)], OsRng).unwrap())
	});
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
		assert_eq!(
			NoteTree::leaves(TreeId::Note, 0, 10),
			vec![NoteTree::leaf_at(TreeId::Note, 0).expect("indexed")]
		);

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
	use arxon_zk_runtime_api::runtime_decl_for_arxon_zk_api::ArxonZkApiV3;

	dev_ext().execute_with(|| {
		assert_eq!(Runtime::note_tree_root(), NoteTree::root(TreeId::Note).0);
		assert_eq!(
			Runtime::membership_root(),
			NoteTree::root(TreeId::Membership).0
		);
		assert_eq!(Runtime::leaf_count(0), Some(0));
		assert_eq!(Runtime::leaf_count(1), Some(0));
		assert_eq!(Runtime::leaf_count(2), None);
		assert_eq!(Runtime::leaves(0, 0, 10), Some(vec![]));
		assert_eq!(Runtime::leaves(2, 0, 10), None);
		assert!(!Runtime::is_nullifier_spent([7u8; 32]));
		assert!(Runtime::circuit_enabled(1));
		assert!(Runtime::circuit_enabled(3));
		assert!(!Runtime::circuit_enabled(7));
		assert!(!Runtime::balance_hidden(baltathar().into()));
		assert_eq!(Runtime::arx20_shielded_unit([0x20; 20]), SHIELDED_UNIT);
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
			..Default::default()
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
				asset: Some(PrivacyAsset::Native),
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
			membership: Some((0, registry.path(index))),
			..Default::default()
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

/// Shields `amount` ARX from Alith into one note of `owner` and returns it with
/// the reference tree that now holds it.
fn shield_one(owner: &SpendingKey, amount: u64) -> (OutputNote, ReferenceNoteTree) {
	let mut rng = OsRng;
	let mut reference = ReferenceNoteTree::new(TreeKind::Note);
	let shielded = OutputNote::new(owner.pk(), amount, &mut rng);
	let proofs = prove_bundle(
		&[],
		&[shielded],
		None,
		0,
		ValueFlow::Shield {
			depositor: alith(),
			amount: units(amount),
		},
	);
	assert_ok!(Privacy::shield(
		RuntimeOrigin::signed(alith()),
		units(amount),
		outputs_arg(&[shielded]),
		0,
		EXPIRY,
		proofs
	));
	reference.insert(shielded.note.commitment());
	(shielded, reference)
}

fn relay_fee(n: u64, recipient: AccountId) -> RelayFeeOf<Runtime> {
	RelayFee {
		amount: units(n),
		recipient,
	}
}

#[test]
fn relayed_unshield_pays_the_relayer_from_the_pool() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let (shielded, reference) = shield_one(&alice, 42);
		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let anchor = fp_to_bytes(&reference.root());
		let attachments = Attachments {
			fee: Some(relay_fee(2, charleth())),
			..Default::default()
		};
		let proofs = prove_bundle_with(
			std::slice::from_ref(&spend),
			&[],
			Some(anchor),
			0,
			ValueFlow::Unshield {
				recipient: baltathar(),
				amount: units(40),
			},
			&attachments,
		);
		let baltathar_before = Balances::balance(&baltathar());
		let charleth_before = Balances::balance(&charleth());

		assert_ok!(Privacy::unshield_with_fee(
			RuntimeOrigin::signed(charleth()),
			baltathar(),
			units(40),
			anchor,
			inputs_arg(std::slice::from_ref(&spend)),
			outputs_arg(&[]),
			0,
			EXPIRY,
			relay_fee(2, charleth()),
			proofs,
		));

		assert_eq!(
			Balances::balance(&baltathar()),
			baltathar_before + units(40)
		);
		assert_eq!(
			Balances::balance(&charleth()),
			charleth_before + units(2),
			"the relayer is paid from the pool and paid nothing for the extrinsic in this test"
		);
		assert_eq!(Privacy::pool_balance(), 0);
	});
}

#[test]
fn a_relayer_cannot_redirect_or_raise_its_fee() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let bob = SpendingKey::random(&mut rng);
		let (shielded, reference) = shield_one(&alice, 42);
		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let to_bob = OutputNote::new(bob.pk(), 40, &mut rng);
		let anchor = fp_to_bytes(&reference.root());
		let attachments = Attachments {
			fee: Some(relay_fee(2, charleth())),
			..Default::default()
		};
		let proofs = prove_bundle_with(
			std::slice::from_ref(&spend),
			&[to_bob],
			Some(anchor),
			MASK_ALL_HIDDEN,
			ValueFlow::Transfer,
			&attachments,
		);
		let submit = |fee: RelayFeeOf<Runtime>| {
			Privacy::submit_private_transfer_with_fee(
				RuntimeOrigin::signed(baltathar()),
				anchor,
				inputs_arg(std::slice::from_ref(&spend)),
				outputs_arg(&[to_bob]),
				MASK_ALL_HIDDEN,
				EXPIRY,
				None,
				None,
				fee,
				proofs.clone(),
			)
		};

		assert_eq!(
			submit(relay_fee(2, baltathar())),
			Err(pallet_zk_verifier::Error::<Runtime>::InvalidProof.into())
		);
		assert_eq!(
			submit(relay_fee(3, charleth())),
			Err(pallet_zk_verifier::Error::<Runtime>::InvalidProof.into())
		);
		assert_ok!(submit(relay_fee(2, charleth())));
		assert_eq!(Privacy::pool_balance(), units(40));
	});
}

#[test]
fn a_bundle_marked_hide_balance_pays_privately_but_cannot_unshield() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let bob = SpendingKey::random(&mut rng);
		let (shielded, mut reference) = shield_one(&alice, 42);
		let hide_balance = 0b1000;

		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let to_bob = OutputNote::new(bob.pk(), 40, &mut rng);
		let change = OutputNote::new(alice.pk(), 2, &mut rng);
		let anchor = fp_to_bytes(&reference.root());
		let proofs = prove_bundle(
			std::slice::from_ref(&spend),
			&[to_bob, change],
			Some(anchor),
			hide_balance,
			ValueFlow::Transfer,
		);
		assert_ok!(Privacy::submit_private_transfer(
			RuntimeOrigin::signed(baltathar()),
			anchor,
			inputs_arg(std::slice::from_ref(&spend)),
			outputs_arg(&[to_bob, change]),
			hide_balance,
			EXPIRY,
			None,
			None,
			proofs,
		));
		reference.insert(to_bob.note.commitment());
		reference.insert(change.note.commitment());

		let bob_spend = SpendNote::new(bob, to_bob.note, reference.path(1), &mut rng);
		let anchor = fp_to_bytes(&reference.root());
		let proofs = prove_bundle(
			std::slice::from_ref(&bob_spend),
			&[],
			Some(anchor),
			hide_balance,
			ValueFlow::Unshield {
				recipient: baltathar(),
				amount: units(40),
			},
		);

		assert_eq!(
			Privacy::unshield(
				RuntimeOrigin::signed(baltathar()),
				baltathar(),
				units(40),
				anchor,
				inputs_arg(std::slice::from_ref(&bob_spend)),
				outputs_arg(&[]),
				hide_balance,
				EXPIRY,
				proofs,
			),
			Err(pallet_privacy::Error::<Runtime>::HideBalanceForbidsUnshield.into())
		);
		assert_eq!(Privacy::pool_balance(), units(42));
	});
}

#[test]
fn pool_value_is_not_unshielded_to_an_account_that_hides_its_balance() {
	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let alice = SpendingKey::random(&mut rng);
		let (shielded, reference) = shield_one(&alice, 42);
		// A flag set long ago, so already in force (the delay is a pallet test).
		HideBalanceAccounts::<Runtime>::insert(baltathar(), true);
		let spend = SpendNote::new(alice, shielded.note, reference.path(0), &mut rng);
		let anchor = fp_to_bytes(&reference.root());
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

		assert_eq!(
			Privacy::unshield(
				RuntimeOrigin::signed(charleth()),
				baltathar(),
				units(42),
				anchor,
				inputs_arg(std::slice::from_ref(&spend)),
				outputs_arg(&[]),
				0,
				EXPIRY,
				proofs,
			),
			Err(pallet_privacy::Error::<Runtime>::RecipientHidesBalance.into())
		);
		assert!(!NullifierRegistry::is_spent(&spend.nullifier_bytes()));
	});
}

/// A token contract (any code that is not an EIP-7702 delegation) at `token`.
fn deploy_token(token: sp_core::H160) {
	pallet_evm::Pallet::<Runtime>::create_account(token, vec![0x60, 0x00, 0x60, 0x00, 0xf3], None)
		.expect("code stored");
}

#[test]
fn a_six_decimal_token_shields_in_its_own_unit() {
	use arxon_zk_runtime_api::runtime_decl_for_arxon_zk_api::ArxonZkApiV3;

	dev_ext().execute_with(|| {
		let mut rng = OsRng;
		let token = sp_core::H160::repeat_byte(0x66);
		let token_account = AccountId::from(token);
		deploy_token(token);
		assert_ok!(Privacy::set_arx20_unit(
			RuntimeOrigin::signed(token_account),
			token,
			6
		));
		assert_eq!(Runtime::arx20_shielded_unit(token.0), 1);
		let alice = SpendingKey::random(&mut rng);
		// 0.000005 of the token: five base units, below what a 10^9 unit could carry.
		let shielded = OutputNote::new(alice.pk(), 5, &mut rng);
		let attachments = Attachments {
			asset: Some(PrivacyAsset::Arx20(token)),
			..Default::default()
		};
		let proofs = prove_bundle_with(
			&[],
			&[shielded],
			None,
			0,
			ValueFlow::Shield {
				depositor: token_account,
				amount: 5,
			},
			&attachments,
		);

		assert_ok!(Privacy::shield_arx20(
			RuntimeOrigin::signed(token_account),
			token,
			5,
			outputs_arg(&[shielded]),
			0,
			EXPIRY,
			proofs,
		));

		assert_eq!(NoteTree::leaf_count(TreeId::Arx20(token)), 1);
		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
	});
}

// --- the wallet prover against the chain -----------------------------------------------------------

fn json_bytes(v: &serde_json::Value) -> Vec<u8> {
	hex::decode(v.as_str().expect("hex string").trim_start_matches("0x")).expect("hex")
}

fn json_field(v: &serde_json::Value) -> FieldBytes {
	FieldBytes(json_bytes(v).try_into().expect("32 bytes"))
}

fn json_proof(v: &serde_json::Value) -> Option<Proof> {
	let bytes = json_bytes(v);
	(!bytes.is_empty()).then(|| proof_of(bytes))
}

fn json_bundle(res: &serde_json::Value) -> (Inputs, Outputs, ProofBundle) {
	let empty = Vec::new();
	let inputs = res["inputs"]
		.as_array()
		.unwrap_or(&empty)
		.iter()
		.map(|i| Input {
			nullifier: json_field(&i["nullifier"]),
			cv: json_field(&i["cv"]),
			revealed_sender: json_field(&i["revealed_sender"]),
		});
	let outputs = res["outputs"]
		.as_array()
		.expect("outputs")
		.iter()
		.map(|o| Output {
			cm: json_field(&o["cm"]),
			cv: json_field(&o["cv"]),
			revealed_receiver: json_field(&o["revealed_receiver"]),
			revealed_amount: json_field(&o["revealed_amount"]),
			encrypted_note: BoundedVec::truncate_from(json_bytes(&o["encrypted_note"])),
		});
	let p = &res["proofs"];
	(
		Inputs::truncate_from(inputs.collect()),
		Outputs::truncate_from(outputs.collect()),
		ProofBundle {
			spend: json_proof(&p["spend"]),
			output: json_proof(&p["output"]),
			balance: json_proof(&p["balance"]).expect("balance proof"),
			receipt: json_proof(&p["receipt"]),
			compliance: json_proof(&p["compliance"]),
		},
	)
}

/// The local prover and the browser prover share `arxon_prove`: what it builds
/// for a relayed unshield must verify on chain, fee row and fee recipient included.
#[test]
fn the_wallet_prover_builds_a_relayed_unshield_the_chain_accepts() {
	dev_ext().execute_with(|| {
		let shield: serde_json::Value = serde_json::to_value(
			arxon_prove::shield(
				serde_json::from_value(serde_json::json!({
					"amount_wei": units(42).to_string(),
					"mask_bits": 0,
					"expiry_block": EXPIRY,
				}))
				.unwrap(),
			)
			.expect("shield proved"),
		)
		.unwrap();
		let (_, outputs, proofs) = json_bundle(&shield);
		assert_ok!(Privacy::shield(
			RuntimeOrigin::signed(alith()),
			units(42),
			outputs,
			0,
			EXPIRY,
			proofs
		));

		let unshield: serde_json::Value = serde_json::to_value(
			arxon_prove::unshield(
				serde_json::from_value(serde_json::json!({
					"amount_wei": units(40).to_string(),
					"mask_bits": 0,
					"expiry_block": EXPIRY,
					"sk_hex": shield["sk_hex"],
					"recipient": format!("0x{}", hex::encode(sp_core::H160::from(baltathar()).0)),
					"note": {
						"amount_wei": shield["note"]["amount_wei"],
						"rho": shield["note"]["rho"],
						"leaf_index": 0,
					},
					"leaves": [shield["note"]["cm"]],
					"fee_wei": units(2).to_string(),
					"fee_recipient": format!("0x{}", hex::encode(sp_core::H160::from(charleth()).0)),
				}))
				.unwrap(),
			)
			.expect("unshield proved"),
		)
		.unwrap();
		assert_eq!(unshield["fee_wei"], units(2).to_string());
		let (inputs, outputs, proofs) = json_bundle(&unshield);
		let charleth_before = Balances::balance(&charleth());

		assert_ok!(Privacy::unshield_with_fee(
			RuntimeOrigin::signed(charleth()),
			baltathar(),
			units(40),
			json_field(&unshield["anchor"]),
			inputs,
			outputs,
			0,
			EXPIRY,
			relay_fee(2, charleth()),
			proofs,
		));

		assert_eq!(Balances::balance(&charleth()), charleth_before + units(2));
		assert_eq!(Privacy::pool_balance(), 0);
	});
}
