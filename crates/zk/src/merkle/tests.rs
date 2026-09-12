use ff::{Field, PrimeField};

use super::{ReferenceTree, TreeKind};
use crate::field::Fp;

#[test]
fn empty_roots_are_pinned() {
	assert_eq!(
		hex::encode(TreeKind::Note.empty_root().to_repr()),
		NOTE_EMPTY_ROOT,
		"note empty root moved"
	);
	assert_eq!(
		hex::encode(TreeKind::Member.empty_root().to_repr()),
		MEMBER_EMPTY_ROOT,
		"member empty root moved"
	);
}

/// Frozen: the runtime genesis must produce exactly these roots.
const NOTE_EMPTY_ROOT: &str = "b8a0934bd1708c4a147bf33ee7da4dc521f7c9b16d638e09269d33c4dd3c6f16";
const MEMBER_EMPTY_ROOT: &str = "05b80f0172db899364a4c79fd9803a93eb3adb9cc418966de2e73614238df215";

#[test]
fn empty_subtree_hashes_chain_from_the_zero_leaf() {
	let hashes = TreeKind::Note.empty_hashes();

	assert_eq!(hashes[0], Fp::ZERO);
	assert_eq!(hashes[1], TreeKind::Note.hash(Fp::ZERO, Fp::ZERO));
	assert_eq!(hashes[2], TreeKind::Note.hash(hashes[1], hashes[1]));
}

#[test]
fn note_and_member_trees_have_different_empty_roots() {
	assert_ne!(TreeKind::Note.empty_root(), TreeKind::Member.empty_root());
}

#[test]
fn empty_tree_root_equals_empty_root_constant() {
	let tree = ReferenceTree::new(TreeKind::Note);

	assert!(tree.is_empty());
	assert_eq!(tree.root(), TreeKind::Note.empty_root());
}

#[test]
fn insert_returns_sequential_indices() {
	let mut tree = ReferenceTree::new(TreeKind::Note);

	assert_eq!(tree.insert(Fp::from(1)), 0);
	assert_eq!(tree.insert(Fp::from(2)), 1);
	assert_eq!(tree.len(), 2);
}

#[test]
fn inserting_a_leaf_changes_the_root() {
	let mut tree = ReferenceTree::new(TreeKind::Note);
	let before = tree.root();

	tree.insert(Fp::from(1));

	assert_ne!(tree.root(), before);
}

#[test]
fn path_of_every_leaf_recomputes_the_root() {
	let mut tree = ReferenceTree::new(TreeKind::Member);
	let leaves: Vec<Fp> = (1..=6u64).map(Fp::from).collect();
	for l in &leaves {
		tree.insert(*l);
	}

	for (i, leaf) in leaves.iter().enumerate() {
		let path = tree.path(i as u64);
		assert_eq!(path.leaf_index(), i as u64);
		assert_eq!(
			ReferenceTree::root_from_path(TreeKind::Member, *leaf, &path),
			tree.root(),
			"leaf {i}"
		);
	}
}

#[test]
fn path_with_wrong_leaf_does_not_recompute_the_root() {
	let mut tree = ReferenceTree::new(TreeKind::Note);
	tree.insert(Fp::from(1));
	let path = tree.path(0);

	assert_ne!(
		ReferenceTree::root_from_path(TreeKind::Note, Fp::from(2), &path),
		tree.root()
	);
}

#[test]
fn two_leaf_root_is_hash_of_leaves_then_empty_siblings() {
	let mut tree = ReferenceTree::new(TreeKind::Note);
	tree.insert(Fp::from(1));
	tree.insert(Fp::from(2));
	let empty = TreeKind::Note.empty_hashes();
	let mut expected = TreeKind::Note.hash(Fp::from(1), Fp::from(2));
	for sibling in &empty[1..32] {
		expected = TreeKind::Note.hash(expected, *sibling);
	}

	assert_eq!(tree.root(), expected);
}
