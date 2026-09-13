//! Benchmarks. The pallet has no extrinsics; `mark_spent` is what `pallet-privacy`
//! pays per spent input.

use arxon_zk_primitives::FieldBytes;
use frame_benchmarking::v2::*;

use super::*;

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn mark_spent() {
		let nullifier = FieldBytes::from_u64(0xa11ce);
		assert!(!Pallet::<T>::is_spent(&nullifier));

		#[block]
		{
			Pallet::<T>::mark_spent(&nullifier).expect("fresh nullifier");
		}

		assert!(Pallet::<T>::is_spent(&nullifier));
		assert_eq!(SpentCount::<T>::get(), 1);
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
