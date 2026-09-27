//! Benchmarks. Inserts hash `depth` times whatever the index; the empty subtree
//! chain (`Zeros`) is built at genesis, and the setup warms it anyway so a mock
//! without genesis measures the same steady state. The root ring's next slot is
//! occupied, so every insert also pays the eviction of the oldest root (the
//! steady state of a chain with more inserts than `RootHistorySize`).

use arxon_zk_primitives::FieldBytes;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

use super::*;

/// Occupies the root ring slot the next insert into `tree` will use.
fn fill_next_root_slot<T: Config>(tree: TreeId) {
	let slot = RootCursor::<T>::get(tree);
	let old_root = FieldBytes::from_u64(0x01d_2007);
	RootHistory::<T>::insert(tree, slot, old_root);
	KnownRoots::<T>::insert(tree, old_root, slot);
}

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn add_member() {
		Pallet::<T>::empty_root(TreeId::Membership).expect("zeros");
		fill_next_root_slot::<T>(TreeId::Membership);
		let leaf = FieldBytes::from_u64(0x3e3b);

		#[extrinsic_call]
		_(RawOrigin::Root, leaf);

		assert_eq!(Pallet::<T>::leaf_index(TreeId::Membership, &leaf), Some(0));
	}

	#[benchmark]
	fn insert() {
		Pallet::<T>::empty_root(TreeId::Note).expect("zeros");
		fill_next_root_slot::<T>(TreeId::Note);
		let leaf = FieldBytes::from_u64(0x707e);

		#[block]
		{
			Pallet::<T>::do_insert(TreeId::Note, &leaf).expect("fresh leaf");
		}

		assert_eq!(Pallet::<T>::leaf_index(TreeId::Note, &leaf), Some(0));
		assert!(Pallet::<T>::known_root(
			TreeId::Note,
			&Pallet::<T>::root(TreeId::Note)
		));
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
