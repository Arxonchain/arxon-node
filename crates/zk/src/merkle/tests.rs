use arxon_zk_primitives::{MEMBER_TREE_DEPTH, NOTE_TREE_DEPTH};
use ff::{Field, PrimeField};

use super::{MemberTree, NoteTree, ReferenceTree, TreeKind};
use crate::field::Fp;

/// Frozen: the runtime genesis must produce exactly these roots.
const NOTE_EMPTY_ROOT: &str = "1ca704bf814299b9f2b8c2331355744f2f23b9ad33e794590c9153a21fca001f";
const MEMBER_EMPTY_ROOT: &str = "cb7b604832ada5c237d29fb877d9fd8a127cf14c95c1a23d0338aad69d3fe906";

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

#[test]
fn tree_depths_are_32_and_16() {
	assert_eq!(TreeKind::Note.depth(), NOTE_TREE_DEPTH);
	assert_eq!(TreeKind::Member.depth(), MEMBER_TREE_DEPTH);
	assert_eq!(NOTE_TREE_DEPTH, 32);
	assert_eq!(MEMBER_TREE_DEPTH, 16);
}

#[test]
fn empty_subtree_hashes_chain_from_the_zero_leaf() {
	let hashes = TreeKind::Note.empty_hashes();

	assert_eq!(hashes.len(), NOTE_TREE_DEPTH + 1);
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
	let tree = NoteTree::new(TreeKind::Note);

	assert!(tree.is_empty());
	assert_eq!(tree.root(), TreeKind::Note.empty_root());
}

#[test]
#[should_panic(expected = "tree kind depth must match")]
fn reference_tree_rejects_mismatched_depth() {
	let _ = ReferenceTree::<NOTE_TREE_DEPTH>::new(TreeKind::Member);
}

#[test]
fn insert_returns_sequential_indices() {
	let mut tree = NoteTree::new(TreeKind::Note);

	assert_eq!(tree.insert(Fp::from(1)), 0);
	assert_eq!(tree.insert(Fp::from(2)), 1);
	assert_eq!(tree.len(), 2);
}

#[test]
fn inserting_a_leaf_changes_the_root() {
	let mut tree = NoteTree::new(TreeKind::Note);
	let before = tree.root();

	tree.insert(Fp::from(1));

	assert_ne!(tree.root(), before);
}

#[test]
fn path_of_every_leaf_recomputes_the_root() {
	let mut tree = MemberTree::new(TreeKind::Member);
	let leaves: Vec<Fp> = (1..=6u64).map(Fp::from).collect();
	for l in &leaves {
		tree.insert(*l);
	}

	for (i, leaf) in leaves.iter().enumerate() {
		let path = tree.path(i as u64);
		assert_eq!(path.leaf_index(), i as u64);
		assert_eq!(
			MemberTree::root_from_path(TreeKind::Member, *leaf, &path),
			tree.root(),
			"leaf {i}"
		);
	}
}

#[test]
fn path_with_wrong_leaf_does_not_recompute_the_root() {
	let mut tree = NoteTree::new(TreeKind::Note);
	tree.insert(Fp::from(1));
	let path = tree.path(0);

	assert_ne!(
		NoteTree::root_from_path(TreeKind::Note, Fp::from(2), &path),
		tree.root()
	);
}

#[test]
fn two_leaf_root_is_hash_of_leaves_then_empty_siblings() {
	let mut tree = NoteTree::new(TreeKind::Note);
	tree.insert(Fp::from(1));
	tree.insert(Fp::from(2));
	let empty = TreeKind::Note.empty_hashes();
	let mut expected = TreeKind::Note.hash(Fp::from(1), Fp::from(2));
	for sibling in &empty[1..NOTE_TREE_DEPTH] {
		expected = TreeKind::Note.hash(expected, *sibling);
	}

	assert_eq!(tree.root(), expected);
}
