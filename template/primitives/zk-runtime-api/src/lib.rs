//! Runtime API of the Arxon shielded pool.
//!
//! Wallets and explorers need the current anchors and nullifier state to build
//! proofs and to display shielded activity. Everything is exposed as plain
//! bytes so any client can call it through `state_call` without SCALE types
//! beyond the primitives.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

sp_api::decl_runtime_apis! {
	/// Read-only view of the shielded pool.
	///
	/// Version 2 adds [`ArxonZkApi::leaves`].
	#[api_version(2)]
	pub trait ArxonZkApi {
		/// Current root of the note commitment tree.
		fn note_tree_root() -> [u8; 32];
		/// Current root of the trust registry membership tree.
		fn membership_root() -> [u8; 32];
		/// `true` iff `root` is an anchor the note tree still accepts.
		fn is_known_note_root(root: [u8; 32]) -> bool;
		/// `true` iff `nullifier` was spent.
		fn is_nullifier_spent(nullifier: [u8; 32]) -> bool;
		/// Leaves in tree `tree` (`0` note, `1` membership); `None` for any other id.
		fn leaf_count(tree: u8) -> Option<u64>;
		/// `true` iff proofs of `circuit_id` (wire id 1..=6) are currently accepted.
		fn circuit_enabled(circuit_id: u8) -> bool;
		/// Up to `count` leaves of tree `tree` from index `start`, in insertion
		/// order, capped at 1024 and at the last leaf; `None` for an unknown tree id.
		/// Wallets sync a tree page by page instead of leaf by leaf.
		#[api_version(2)]
		fn leaves(tree: u8, start: u64, count: u32) -> Option<alloc::vec::Vec<[u8; 32]>>;
	}
}
