//! # Note tree (runtime index 20)
//!
//! Two append-only Merkle trees over Arxon-domain Poseidon on Pallas,
//! identified by [`TreeId`] (depth 32 for notes, 16 for the registry):
//!
//! * `Note`: every shielded note commitment `cm`. Filled only by
//!   `pallet-privacy` through [`MerkleTree::insert`] after the proofs verified.
//!   No extrinsic can add a note leaf, so not even root can conjure a note.
//! * `Membership`: leaves `H_MEMBER(pk)` of regulated counterparties (Circuit 6).
//!   Root adds leaves with [`Pallet::add_member`].
//!
//! The tree is the classic incremental construction (filled subtrees per
//! level plus precomputed empty-subtree hashes), so an insert costs 32 hashes.
//! A ring buffer keeps the last `RootHistorySize` roots so a proof built
//! against a slightly stale anchor still verifies. Duplicate leaves are
//! rejected: a duplicated note commitment would share its nullifier with the
//! original and become unspendable ("Faerie Gold").
//!
//! Hashing runs inside the runtime (`halo2_poseidon` is `no_std`), so the hash
//! can change through a runtime upgrade. It sits behind [`MerkleHasher`] in
//! case measured weights ever justify a host function instead.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod weights;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use arxon_zk_primitives::{
	poseidon::{hash_two_bytes, MerkleDomain},
	FieldBytes, MEMBER_TREE_DEPTH, NOTE_TREE_DEPTH,
};
use frame_support::pallet_prelude::*;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Which of the two trees.
#[derive(
	Clone,
	Copy,
	Debug,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen
)]
pub enum TreeId {
	/// Shielded note commitments.
	#[codec(index = 0)]
	Note,
	/// Trust registry membership leaves.
	#[codec(index = 1)]
	Membership,
}

impl TreeId {
	/// Both trees.
	pub const ALL: [TreeId; 2] = [TreeId::Note, TreeId::Membership];

	/// Poseidon domain of this tree's node hash.
	pub const fn domain(self) -> MerkleDomain {
		match self {
			TreeId::Note => MerkleDomain::Note,
			TreeId::Membership => MerkleDomain::Member,
		}
	}

	/// Depth of this tree.
	pub const fn depth(self) -> u8 {
		match self {
			TreeId::Note => NOTE_TREE_DEPTH as u8,
			TreeId::Membership => MEMBER_TREE_DEPTH as u8,
		}
	}

	/// Maximum number of leaves.
	pub const fn capacity(self) -> u64 {
		1u64 << self.depth()
	}
}

/// Node hash of a tree. `None` iff an input is not a canonical field element.
pub trait MerkleHasher {
	/// `H_tree(left, right)`.
	fn hash_two(tree: TreeId, left: &FieldBytes, right: &FieldBytes) -> Option<FieldBytes>;
}

/// The production hasher: tagged Poseidon over Pallas, in Wasm.
pub struct PoseidonHasher;

impl MerkleHasher for PoseidonHasher {
	fn hash_two(tree: TreeId, left: &FieldBytes, right: &FieldBytes) -> Option<FieldBytes> {
		hash_two_bytes(tree.domain(), left, right)
	}
}

/// The trees as seen by the pallets that consume them.
pub trait MerkleTree {
	/// Appends `leaf` and returns its index.
	fn insert(tree: TreeId, leaf: &FieldBytes) -> Result<u64, DispatchError>;

	/// `true` iff `root` is the current root or one of the recent roots.
	fn is_known_root(tree: TreeId, root: &FieldBytes) -> bool;

	/// Current root.
	fn current_root(tree: TreeId) -> FieldBytes;
}

#[frame_support::pallet]
pub mod pallet {
	use arxon_zk_primitives::FieldBytes;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	use super::{weights::WeightInfo, MerkleHasher, MerkleTree, TreeId};

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Node hash.
		type Hasher: MerkleHasher;
		/// Number of recent roots kept as valid anchors, per tree. Size it from
		/// the expected insert rate, not from blocks: under load a root is
		/// evicted after this many inserts.
		#[pallet::constant]
		type RootHistorySize: Get<u32>;
		/// Weights.
		type WeightInfo: WeightInfo;
	}

	/// Rightmost filled subtree hash per level (incremental Merkle tree state).
	#[pallet::storage]
	pub type FilledSubtrees<T: Config> =
		StorageDoubleMap<_, Twox64Concat, TreeId, Twox64Concat, u8, FieldBytes, OptionQuery>;

	/// Empty subtree hash per height and tree; `0` is the empty leaf. Built lazily once.
	#[pallet::storage]
	pub type Zeros<T: Config> =
		StorageDoubleMap<_, Twox64Concat, TreeId, Twox64Concat, u8, FieldBytes, OptionQuery>;

	/// Index the next leaf will take.
	#[pallet::storage]
	pub type NextLeafIndex<T: Config> = StorageMap<_, Twox64Concat, TreeId, u64, ValueQuery>;

	/// Current root, once at least one leaf was inserted.
	#[pallet::storage]
	pub type CurrentRoot<T: Config> = StorageMap<_, Twox64Concat, TreeId, FieldBytes, OptionQuery>;

	/// Ring buffer of recent roots by slot.
	#[pallet::storage]
	pub type RootHistory<T: Config> =
		StorageDoubleMap<_, Twox64Concat, TreeId, Twox64Concat, u32, FieldBytes, OptionQuery>;

	/// Slot the next root will be written to.
	#[pallet::storage]
	pub type RootCursor<T: Config> = StorageMap<_, Twox64Concat, TreeId, u32, ValueQuery>;

	/// Recent roots by value, for O(1) anchor checks. Value: the slot holding it.
	#[pallet::storage]
	pub type KnownRoots<T: Config> =
		StorageDoubleMap<_, Twox64Concat, TreeId, Blake2_128Concat, FieldBytes, u32, OptionQuery>;

	/// Every inserted leaf and its index (duplicate rejection).
	#[pallet::storage]
	pub type KnownLeaves<T: Config> =
		StorageDoubleMap<_, Twox64Concat, TreeId, Blake2_128Concat, FieldBytes, u64, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A leaf was appended.
		LeafInserted {
			/// Which tree.
			tree: TreeId,
			/// Leaf index.
			index: u64,
			/// Leaf value.
			leaf: FieldBytes,
			/// New root.
			root: FieldBytes,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The tree reached its capacity (`2^depth` leaves).
		TreeFull,
		/// The leaf was already inserted.
		DuplicateLeaf,
		/// The leaf is not a canonical Pallas base field element.
		InvalidFieldElement,
		/// Root history size is zero.
		NoRootHistory,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Adds a regulated counterparty leaf `H_MEMBER(pk)` to the membership tree.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::add_member())]
		pub fn add_member(origin: OriginFor<T>, leaf: FieldBytes) -> DispatchResult {
			ensure_root(origin)?;
			Self::do_insert(TreeId::Membership, &leaf)?;
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Empty subtree hash at `height` (`0` = empty leaf), computing and caching the chain on first use.
		pub fn zero_at(tree: TreeId, height: u8) -> Result<FieldBytes, DispatchError> {
			if let Some(z) = Zeros::<T>::get(tree, height) {
				return Ok(z);
			}
			let mut current = FieldBytes::ZERO;
			Zeros::<T>::insert(tree, 0, current);
			for h in 1..=tree.depth() {
				current = T::Hasher::hash_two(tree, &current, &current)
					.ok_or(Error::<T>::InvalidFieldElement)?;
				Zeros::<T>::insert(tree, h, current);
			}
			Zeros::<T>::get(tree, height).ok_or_else(|| Error::<T>::InvalidFieldElement.into())
		}

		/// Root of the empty tree.
		pub fn empty_root(tree: TreeId) -> Result<FieldBytes, DispatchError> {
			Self::zero_at(tree, tree.depth())
		}

		/// Current root (the empty root before the first insert).
		pub fn root(tree: TreeId) -> FieldBytes {
			CurrentRoot::<T>::get(tree)
				.unwrap_or_else(|| Self::empty_root(tree).unwrap_or(FieldBytes::ZERO))
		}

		/// Number of leaves.
		pub fn leaf_count(tree: TreeId) -> u64 {
			NextLeafIndex::<T>::get(tree)
		}

		/// Index of `leaf` if it was inserted.
		pub fn leaf_index(tree: TreeId, leaf: &FieldBytes) -> Option<u64> {
			KnownLeaves::<T>::get(tree, leaf)
		}

		/// Appends `leaf`, updates the root and the root history, emits an event.
		pub fn do_insert(tree: TreeId, leaf: &FieldBytes) -> Result<u64, DispatchError> {
			ensure!(leaf.is_canonical(), Error::<T>::InvalidFieldElement);
			ensure!(
				!KnownLeaves::<T>::contains_key(tree, leaf),
				Error::<T>::DuplicateLeaf
			);
			let index = NextLeafIndex::<T>::get(tree);
			ensure!(index < tree.capacity(), Error::<T>::TreeFull);

			let mut current = *leaf;
			let mut position = index;
			for level in 0..tree.depth() {
				let (left, right) = if position & 1 == 0 {
					FilledSubtrees::<T>::insert(tree, level, current);
					(current, Self::zero_at(tree, level)?)
				} else {
					let filled = FilledSubtrees::<T>::get(tree, level)
						.ok_or(Error::<T>::InvalidFieldElement)?;
					(filled, current)
				};
				current = T::Hasher::hash_two(tree, &left, &right)
					.ok_or(Error::<T>::InvalidFieldElement)?;
				position >>= 1;
			}
			let root = current;

			Self::record_root(tree, root)?;
			KnownLeaves::<T>::insert(tree, leaf, index);
			NextLeafIndex::<T>::insert(tree, index + 1);
			CurrentRoot::<T>::insert(tree, root);
			Self::deposit_event(Event::LeafInserted {
				tree,
				index,
				leaf: *leaf,
				root,
			});
			Ok(index)
		}

		fn record_root(tree: TreeId, root: FieldBytes) -> DispatchResult {
			let size = T::RootHistorySize::get();
			ensure!(size > 0, Error::<T>::NoRootHistory);
			let slot = RootCursor::<T>::get(tree);
			if let Some(evicted) = RootHistory::<T>::get(tree, slot) {
				KnownRoots::<T>::remove(tree, evicted);
			}
			RootHistory::<T>::insert(tree, slot, root);
			KnownRoots::<T>::insert(tree, root, slot);
			RootCursor::<T>::insert(tree, (slot + 1) % size);
			Ok(())
		}

		/// `true` iff `root` is among the recent roots.
		pub fn known_root(tree: TreeId, root: &FieldBytes) -> bool {
			KnownRoots::<T>::contains_key(tree, root)
		}
	}

	impl<T: Config> MerkleTree for Pallet<T> {
		fn insert(tree: TreeId, leaf: &FieldBytes) -> Result<u64, DispatchError> {
			Pallet::<T>::do_insert(tree, leaf)
		}

		fn is_known_root(tree: TreeId, root: &FieldBytes) -> bool {
			Pallet::<T>::known_root(tree, root)
		}

		fn current_root(tree: TreeId) -> FieldBytes {
			Pallet::<T>::root(tree)
		}
	}
}
