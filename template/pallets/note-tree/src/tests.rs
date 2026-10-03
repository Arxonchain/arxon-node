//! One behaviour per test. The oracle is a naive full recomputation with the
//! same tagged Poseidon the pallet uses.

use arxon_zk_primitives::{
	poseidon::{fp_from_bytes, fp_to_bytes, hash_merkle_member, hash_merkle_note, Fp},
	FieldBytes, MEMBER_TREE_DEPTH, NOTE_TREE_DEPTH,
};
use frame_support::{assert_noop, assert_ok};

use crate::{
	mock::{new_test_ext, NoteTree, RuntimeEvent, RuntimeOrigin, System, Test, ROOT_HISTORY},
	Error, Event, KnownRoots, MerkleTree, NextLeafIndex, TreeId,
};

/// Frozen empty roots (also pinned in `arxon-zk`'s reference tree tests).
const NOTE_EMPTY_ROOT: &str = "1ca704bf814299b9f2b8c2331355744f2f23b9ad33e794590c9153a21fca001f";
const MEMBER_EMPTY_ROOT: &str = "cb7b604832ada5c237d29fb877d9fd8a127cf14c95c1a23d0338aad69d3fe906";

fn leaf(v: u64) -> FieldBytes {
	fp_to_bytes(&Fp::from(v))
}

fn hex_root(root: FieldBytes) -> String {
	hex::encode(root.0)
}

/// Naive oracle: root of `leaves` padded with empty leaves to the tree's depth.
fn reference_root(tree: TreeId, leaves: &[FieldBytes]) -> FieldBytes {
	let (hash, depth): (fn(Fp, Fp) -> Fp, usize) = match tree {
		TreeId::Note | TreeId::Arx20(_) => (hash_merkle_note, NOTE_TREE_DEPTH),
		TreeId::Membership => (hash_merkle_member, MEMBER_TREE_DEPTH),
	};
	let mut empty = Fp::from(0);
	let mut level: Vec<Fp> = leaves.iter().map(|l| fp_from_bytes(l).unwrap()).collect();
	for _ in 0..depth {
		let mut next = Vec::with_capacity(level.len().div_ceil(2) + 1);
		for pair in level.chunks(2) {
			let l = pair[0];
			let r = if pair.len() == 2 { pair[1] } else { empty };
			next.push(hash(l, r));
		}
		empty = hash(empty, empty);
		level = next;
	}
	fp_to_bytes(&level.first().copied().unwrap_or(empty))
}

// --- empty tree ---------------------------------------------------------------------------------

#[test]
fn empty_note_root_matches_frozen_constant() {
	new_test_ext().execute_with(|| {
		assert_eq!(hex_root(NoteTree::root(TreeId::Note)), NOTE_EMPTY_ROOT);
	});
}

#[test]
fn empty_membership_root_matches_frozen_constant() {
	new_test_ext().execute_with(|| {
		assert_eq!(
			hex_root(NoteTree::root(TreeId::Membership)),
			MEMBER_EMPTY_ROOT
		);
	});
}

#[test]
fn empty_root_equals_reference_of_no_leaves() {
	new_test_ext().execute_with(|| {
		assert_eq!(
			NoteTree::root(TreeId::Note),
			reference_root(TreeId::Note, &[])
		);
	});
}

#[test]
fn empty_root_is_not_a_known_anchor() {
	new_test_ext().execute_with(|| {
		let root = NoteTree::root(TreeId::Note);

		assert!(!NoteTree::is_known_root(TreeId::Note, &root));
	});
}

#[test]
fn tree_depths_are_32_for_notes_and_16_for_members() {
	assert_eq!(TreeId::Note.depth(), 32);
	assert_eq!(TreeId::Membership.depth(), 16);
	assert_eq!(TreeId::Membership.capacity(), 1 << 16);
}

// --- inserts ------------------------------------------------------------------------------------

#[test]
fn inserting_one_leaf_matches_reference_root() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(11)));

		assert_eq!(
			NoteTree::root(TreeId::Note),
			reference_root(TreeId::Note, &[leaf(11)])
		);
	});
}

#[test]
fn inserting_five_leaves_matches_reference_root_after_each() {
	new_test_ext().execute_with(|| {
		let leaves: Vec<FieldBytes> = (1..=5).map(leaf).collect();

		for i in 0..leaves.len() {
			assert_ok!(NoteTree::insert(TreeId::Note, &leaves[i]));
			assert_eq!(
				NoteTree::root(TreeId::Note),
				reference_root(TreeId::Note, &leaves[..=i]),
				"after leaf {i}"
			);
		}
	});
}

#[test]
fn insert_returns_sequential_indices_and_records_them() {
	new_test_ext().execute_with(|| {
		assert_eq!(NoteTree::insert(TreeId::Note, &leaf(1)), Ok(0));
		assert_eq!(NoteTree::insert(TreeId::Note, &leaf(2)), Ok(1));

		assert_eq!(NoteTree::leaf_count(TreeId::Note), 2);
		assert_eq!(NoteTree::leaf_index(TreeId::Note, &leaf(2)), Some(1));
		assert_eq!(NoteTree::leaf_index(TreeId::Note, &leaf(3)), None);
	});
}

#[test]
fn insert_emits_leaf_inserted_with_new_root() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));

		System::assert_last_event(RuntimeEvent::NoteTree(Event::LeafInserted {
			tree: TreeId::Note,
			index: 0,
			leaf: leaf(1),
			root: NoteTree::root(TreeId::Note),
		}));
	});
}

#[test]
fn insert_rejects_duplicate_leaf() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));

		assert_noop!(
			NoteTree::insert(TreeId::Note, &leaf(1)),
			Error::<Test>::DuplicateLeaf
		);
	});
}

#[test]
fn insert_rejects_non_canonical_leaf() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			NoteTree::insert(TreeId::Note, &FieldBytes([0xff; 32])),
			Error::<Test>::InvalidFieldElement
		);
	});
}

#[test]
fn insert_fails_with_tree_full_when_capacity_is_reached() {
	new_test_ext().execute_with(|| {
		NextLeafIndex::<Test>::insert(TreeId::Note, TreeId::Note.capacity());

		assert_noop!(
			NoteTree::insert(TreeId::Note, &leaf(1)),
			Error::<Test>::TreeFull
		);
	});
}

#[test]
fn the_two_trees_are_independent() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));

		assert_eq!(NoteTree::leaf_count(TreeId::Membership), 0);
		assert_eq!(
			hex_root(NoteTree::root(TreeId::Membership)),
			MEMBER_EMPTY_ROOT
		);
		assert_ok!(NoteTree::insert(TreeId::Membership, &leaf(1)), 0);
	});
}

#[test]
fn an_arx20_tree_does_not_touch_the_native_note_tree() {
	new_test_ext().execute_with(|| {
		let token = TreeId::Arx20(sp_core::H160::from_low_u64_be(0xA20));
		assert_ok!(NoteTree::insert(token, &leaf(1)));

		assert_eq!(NoteTree::leaf_count(TreeId::Note), 0);
		assert_eq!(hex_root(NoteTree::root(TreeId::Note)), NOTE_EMPTY_ROOT);
		assert!(NoteTree::contains_leaf(token, &leaf(1)));
		assert!(!NoteTree::contains_leaf(TreeId::Note, &leaf(1)));
		assert_eq!(NoteTree::root(token), reference_root(token, &[leaf(1)]));
	});
}

#[test]
fn same_leaves_give_different_roots_in_each_tree() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));
		assert_ok!(NoteTree::insert(TreeId::Membership, &leaf(1)));

		assert_ne!(
			NoteTree::root(TreeId::Note),
			NoteTree::root(TreeId::Membership)
		);
		assert_eq!(
			NoteTree::root(TreeId::Membership),
			reference_root(TreeId::Membership, &[leaf(1)])
		);
	});
}

// --- root history -------------------------------------------------------------------------------

#[test]
fn is_known_root_true_for_current_and_recent_roots() {
	new_test_ext().execute_with(|| {
		let mut roots = Vec::new();
		for i in 1..=ROOT_HISTORY as u64 {
			assert_ok!(NoteTree::insert(TreeId::Note, &leaf(i)));
			roots.push(NoteTree::root(TreeId::Note));
		}

		for r in &roots {
			assert!(NoteTree::is_known_root(TreeId::Note, r));
		}
	});
}

#[test]
fn root_history_evicts_oldest_root_after_capacity() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));
		let oldest = NoteTree::root(TreeId::Note);
		for i in 2..=(ROOT_HISTORY as u64 + 1) {
			assert_ok!(NoteTree::insert(TreeId::Note, &leaf(i)));
		}

		assert!(!NoteTree::is_known_root(TreeId::Note, &oldest));
		assert_eq!(
			KnownRoots::<Test>::iter_prefix(TreeId::Note).count(),
			ROOT_HISTORY as usize
		);
	});
}

#[test]
fn is_known_root_false_for_unknown_root() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));

		assert!(!NoteTree::is_known_root(TreeId::Note, &leaf(99)));
	});
}

// --- add_member extrinsic -----------------------------------------------------------------------

#[test]
fn add_member_requires_root_origin() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			NoteTree::add_member(RuntimeOrigin::signed(1), leaf(1)),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn add_member_updates_membership_root_only() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::add_member(RuntimeOrigin::root(), leaf(1)));

		assert_eq!(
			NoteTree::root(TreeId::Membership),
			reference_root(TreeId::Membership, &[leaf(1)])
		);
		assert_eq!(hex_root(NoteTree::root(TreeId::Note)), NOTE_EMPTY_ROOT);
	});
}

#[test]
fn add_member_rejects_duplicate_member() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::add_member(RuntimeOrigin::root(), leaf(1)));

		assert_noop!(
			NoteTree::add_member(RuntimeOrigin::root(), leaf(1)),
			Error::<Test>::DuplicateLeaf
		);
	});
}

// --- views and migration -----------------------------------------------------------------------

#[test]
fn root_of_an_empty_tree_does_not_write_storage() {
	new_test_ext().execute_with(|| {
		assert!(crate::Zeros::<Test>::get(TreeId::Note, 0).is_none());

		let root = NoteTree::root(TreeId::Note);

		assert_eq!(hex::encode(root.0), NOTE_EMPTY_ROOT);
		assert!(
			crate::Zeros::<Test>::get(TreeId::Note, 0).is_none(),
			"a view must not cache anything"
		);
	});
}

#[test]
fn migration_builds_the_empty_subtree_chains_of_both_trees() {
	use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};

	new_test_ext().execute_with(|| {
		StorageVersion::new(0).put::<NoteTree>();

		crate::migrations::V0ToV1::<Test>::on_runtime_upgrade();

		let note = crate::Zeros::<Test>::get(TreeId::Note, 32).expect("built");
		let member = crate::Zeros::<Test>::get(TreeId::Membership, 16).expect("built");
		assert_eq!(hex::encode(note.0), NOTE_EMPTY_ROOT);
		assert_eq!(hex::encode(member.0), MEMBER_EMPTY_ROOT);
		assert_eq!(NoteTree::on_chain_storage_version(), 1);
	});
}

// --- position index --------------------------------------------------------------------------

#[test]
fn leaf_at_returns_each_leaf_by_insertion_index() {
	new_test_ext().execute_with(|| {
		for i in 1..=5 {
			assert_ok!(NoteTree::insert(TreeId::Note, &leaf(i)));
		}

		for i in 0..5u64 {
			assert_eq!(NoteTree::leaf_at(TreeId::Note, i), Some(leaf(i + 1)));
		}
		assert_eq!(NoteTree::leaf_at(TreeId::Note, 5), None);
	});
}

#[test]
fn leaf_at_keeps_the_two_trees_apart() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));
		assert_ok!(NoteTree::insert(TreeId::Membership, &leaf(2)));

		assert_eq!(NoteTree::leaf_at(TreeId::Note, 0), Some(leaf(1)));
		assert_eq!(NoteTree::leaf_at(TreeId::Membership, 0), Some(leaf(2)));
	});
}

#[test]
fn leaf_at_is_unchanged_by_a_rejected_insert() {
	new_test_ext().execute_with(|| {
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));

		assert!(NoteTree::insert(TreeId::Note, &leaf(1)).is_err());

		assert_eq!(NoteTree::leaf_at(TreeId::Note, 1), None);
	});
}

#[test]
fn leaves_returns_a_page_in_order() {
	new_test_ext().execute_with(|| {
		for i in 1..=6 {
			assert_ok!(NoteTree::insert(TreeId::Note, &leaf(i)));
		}

		assert_eq!(
			NoteTree::leaves(TreeId::Note, 2, 3),
			vec![leaf(3), leaf(4), leaf(5)]
		);
	});
}

#[test]
fn leaves_stops_at_the_last_leaf() {
	new_test_ext().execute_with(|| {
		for i in 1..=3 {
			assert_ok!(NoteTree::insert(TreeId::Note, &leaf(i)));
		}

		assert_eq!(
			NoteTree::leaves(TreeId::Note, 1, 100),
			vec![leaf(2), leaf(3)]
		);
		assert!(NoteTree::leaves(TreeId::Note, 3, 100).is_empty());
		assert!(NoteTree::leaves(TreeId::Note, u64::MAX, u32::MAX).is_empty());
	});
}

#[test]
fn leaves_caps_a_page_at_max_leaf_page() {
	new_test_ext().execute_with(|| {
		crate::NextLeafIndex::<Test>::insert(TreeId::Note, u64::from(crate::MAX_LEAF_PAGE) + 10);
		for i in 0..u64::from(crate::MAX_LEAF_PAGE) + 10 {
			crate::LeafAt::<Test>::insert(TreeId::Note, i, FieldBytes::from_u64(i + 1));
		}

		let page = NoteTree::leaves(TreeId::Note, 0, u32::MAX);

		assert_eq!(page.len(), crate::MAX_LEAF_PAGE as usize);
		assert_eq!(page[0], FieldBytes::from_u64(1));
	});
}

#[test]
fn migration_indexes_existing_leaves_by_position() {
	use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};

	new_test_ext().execute_with(|| {
		for i in 1..=4 {
			assert_ok!(NoteTree::insert(TreeId::Note, &leaf(i)));
		}
		assert_ok!(NoteTree::insert(TreeId::Membership, &leaf(9)));
		let _ = crate::LeafAt::<Test>::clear(u32::MAX, None);
		StorageVersion::new(1).put::<NoteTree>();

		crate::migrations::V1ToV2::<Test>::on_runtime_upgrade();

		assert_eq!(
			NoteTree::leaves(TreeId::Note, 0, 10),
			vec![leaf(1), leaf(2), leaf(3), leaf(4)]
		);
		assert_eq!(NoteTree::leaf_at(TreeId::Membership, 0), Some(leaf(9)));
		assert_eq!(NoteTree::on_chain_storage_version(), 2);
	});
}

// --- ARX-20 trees share the note tree's empty subtrees -----------------------------------------

fn token_tree() -> TreeId {
	TreeId::Arx20(sp_core::H160::from_low_u64_be(0xA20))
}

#[test]
fn an_untouched_token_tree_has_the_note_empty_root_and_reading_it_writes_nothing() {
	new_test_ext().execute_with(|| {
		NoteTree::empty_root(TreeId::Note).expect("note zeros");

		assert_eq!(NoteTree::root(token_tree()), NoteTree::root(TreeId::Note));
		assert!(crate::Zeros::<Test>::iter_prefix(token_tree())
			.next()
			.is_none());
	});
}

#[test]
fn the_first_token_insert_builds_no_zeros_of_its_own() {
	new_test_ext().execute_with(|| {
		NoteTree::empty_root(TreeId::Note).expect("note zeros");

		assert_ok!(NoteTree::insert(token_tree(), &leaf(1)));
		assert_ok!(NoteTree::insert(TreeId::Note, &leaf(1)));

		assert!(crate::Zeros::<Test>::iter_prefix(token_tree())
			.next()
			.is_none());
		assert_eq!(
			NoteTree::root(token_tree()),
			NoteTree::root(TreeId::Note),
			"same leaves, same domain: same root"
		);
	});
}
