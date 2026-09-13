//! Benchmarks. Inserts hash `depth` times whatever the index; the empty subtree
//! chain (`Zeros`) is built at genesis, and the setup warms it anyway so a mock
//! without genesis measures the same steady state.

use arxon_zk_primitives::FieldBytes;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

use super::*;

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn add_member() {
		Pallet::<T>::empty_root(TreeId::Membership).expect("zeros");
		let leaf = FieldBytes::from_u64(0x3e3b);

		#[extrinsic_call]
		_(RawOrigin::Root, leaf);

		assert_eq!(Pallet::<T>::leaf_index(TreeId::Membership, &leaf), Some(0));
	}

	#[benchmark]
	fn insert() {
		Pallet::<T>::empty_root(TreeId::Note).expect("zeros");
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
