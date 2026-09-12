use arxon_zk_primitives::poseidon::cv_dummy;

use super::*;
use crate::{
	circuit::ArxonCircuit,
	circuits::{C1Circuit, C2Circuit, C3Circuit},
	merkle::{NoteTree, TreeKind},
	test_support::{assert_satisfied, deterministic_rng, mock_honest},
};

fn ctx(mask: u8, transparent_in: u64, transparent_out: u64) -> BundleContext {
	BundleContext {
		mask,
		bundle_digest: Fp::from(777),
		expiry_block: 50,
		transparent_in,
		transparent_out,
	}
}

#[test]
fn spending_key_derives_distinct_pk_and_nk() {
	let sk = SpendingKey::random(&mut deterministic_rng(1));

	assert_ne!(sk.pk(), sk.nk());
	assert_eq!(sk.pk(), hash_pk(sk.0));
}

#[test]
fn note_commitment_and_nullifier_follow_the_contract() {
	let sk = SpendingKey::random(&mut deterministic_rng(1));
	let note = Note::new(sk.pk(), 42, &mut deterministic_rng(2));

	assert_eq!(note.commitment(), hash_note(sk.pk(), 42, note.rho));
	assert_eq!(
		note.nullifier(&sk),
		hash_nullifier(sk.nk(), note.commitment())
	);
}

#[test]
fn shield_witnesses_satisfy_circuits_1_and_2() {
	let mut rng = deterministic_rng(3);
	let receiver = SpendingKey::random(&mut rng);
	let out = OutputNote::new(receiver.pk(), 42, &mut rng);
	let ctx = ctx(0b0010, 42, 0);

	let c1 = output_witnesses(&[out], &ctx);
	let c2 = balance_witness(&[], &[out], &ctx);

	assert!(is_balanced(&[], &[out], &ctx));
	assert_satisfied(&mock_honest::<C1Circuit>(&c1[0]));
	assert_satisfied(&mock_honest::<C2Circuit>(&c2));
	assert_eq!(
		C2Circuit::public_from_witness(&c2).cv_in,
		[cv_dummy(), cv_dummy()]
	);
}

#[test]
fn transfer_witnesses_satisfy_circuits_3_1_and_2() {
	let mut rng = deterministic_rng(4);
	let alice = SpendingKey::random(&mut rng);
	let bob = SpendingKey::random(&mut rng);
	let funded = Note::new(alice.pk(), 42, &mut rng);
	let mut tree = NoteTree::new(TreeKind::Note);
	let index = tree.insert(funded.commitment());
	let spend = SpendNote::new(alice, funded, tree.path(index), &mut rng);
	let to_bob = OutputNote::new(bob.pk(), 40, &mut rng);
	let change = OutputNote::new(alice.pk(), 2, &mut rng);
	let ctx = ctx(0b0111, 0, 0);

	let c3 = spend_witnesses(std::slice::from_ref(&spend), &ctx);
	let c1 = output_witnesses(&[to_bob, change], &ctx);
	let c2 = balance_witness(std::slice::from_ref(&spend), &[to_bob, change], &ctx);

	assert!(is_balanced(
		std::slice::from_ref(&spend),
		&[to_bob, change],
		&ctx
	));
	assert_eq!(c3[0].anchor(), tree.root());
	assert_satisfied(&mock_honest::<C3Circuit>(&c3[0]));
	assert_satisfied(&mock_honest::<C1Circuit>(&c1[0]));
	assert_satisfied(&mock_honest::<C1Circuit>(&c1[1]));
	assert_satisfied(&mock_honest::<C2Circuit>(&c2));
}

#[test]
fn unshield_witnesses_balance_against_transparent_out() {
	let mut rng = deterministic_rng(5);
	let alice = SpendingKey::random(&mut rng);
	let funded = Note::new(alice.pk(), 42, &mut rng);
	let mut tree = NoteTree::new(TreeKind::Note);
	let index = tree.insert(funded.commitment());
	let spend = SpendNote::new(alice, funded, tree.path(index), &mut rng);
	let ctx = ctx(0, 0, 42);

	let c2 = balance_witness(std::slice::from_ref(&spend), &[], &ctx);

	assert!(is_balanced(std::slice::from_ref(&spend), &[], &ctx));
	assert_satisfied(&mock_honest::<C2Circuit>(&c2));
}

#[test]
fn is_balanced_detects_inflation() {
	let mut rng = deterministic_rng(6);
	let k = SpendingKey::random(&mut rng);
	let out = OutputNote::new(k.pk(), 43, &mut rng);

	assert!(!is_balanced(&[], &[out], &ctx(0, 42, 0)));
}

#[test]
fn spend_cv_bytes_and_c3_public_cv_agree() {
	let mut rng = deterministic_rng(7);
	let alice = SpendingKey::random(&mut rng);
	let funded = Note::new(alice.pk(), 5, &mut rng);
	let mut tree = NoteTree::new(TreeKind::Note);
	let index = tree.insert(funded.commitment());
	let spend = SpendNote::new(alice, funded, tree.path(index), &mut rng);
	let ctx = ctx(0, 0, 5);

	let c3 = &spend_witnesses(std::slice::from_ref(&spend), &ctx)[0];

	assert_eq!(
		fp_to_bytes(&C3Circuit::public_from_witness(c3).cv),
		spend.cv_bytes()
	);
	assert_eq!(
		fp_to_bytes(&C3Circuit::public_from_witness(c3).nullifier),
		spend.nullifier_bytes()
	);
}

#[test]
fn receipt_witnesses_satisfy_circuits_4_and_5_and_agree_on_ptr_id() {
	let mut rng = deterministic_rng(8);
	let alice = SpendingKey::random(&mut rng);
	let bob = SpendingKey::random(&mut rng);
	let payment = OutputNote::new(bob.pk(), 40, &mut rng);
	let receipt = Receipt::new(&alice, payment, &mut rng);
	let ctx = ctx(0, 0, 0);

	let c4 = receipt.generation_witness(&ctx);
	let c5 = receipt.disclosure_witness(0b0011, Fp::from(99), 60);

	assert_satisfied(&mock_honest::<crate::circuits::C4Circuit>(&c4));
	assert_satisfied(&mock_honest::<crate::circuits::C5Circuit>(&c5));
	assert_eq!(c4.ptr_id(), c5.ptr_id());
	assert_eq!(c4.ptr_id(), receipt.ptr_id());
	assert_eq!(c4.cv, payment.cv());
}

#[test]
fn membership_witness_satisfies_circuit_6() {
	let mut rng = deterministic_rng(9);
	let member = SpendingKey::random(&mut rng);
	let mut registry = crate::merkle::MemberTree::new(TreeKind::Member);
	let index = registry.insert(member_leaf(member.pk()));
	let paid = OutputNote::new(member.pk(), 5, &mut rng);
	let ctx = ctx(0, 0, 0);

	let c6 = membership_witness(&paid, registry.path(index), &ctx);

	assert_eq!(c6.registry_root(), registry.root());
	assert_eq!(c6.cm(), paid.note.commitment());
	assert_satisfied(&mock_honest::<crate::circuits::C6Circuit>(&c6));
}
