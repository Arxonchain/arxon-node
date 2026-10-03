//! Benchmarks. `record` is what a private transfer with a receipt attachment pays
//! on top of its proofs; `disclose` is composed in `weights.rs`.

use arxon_zk_primitives::FieldBytes;
use frame_benchmarking::v2::*;
use pallet_privacy::{PrivacyAsset, ReceiptSink};

use super::*;

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn record() {
		let ptr_id = FieldBytes::from_u64(0x9717);
		let cv = FieldBytes::from_u64(0xc0de);
		let token = PrivacyAsset::Arx20([0x20; 20].into());

		#[block]
		{
			<Pallet<T> as ReceiptSink>::record(ptr_id, cv, 0b0111, token).expect("fresh receipt");
		}

		assert_eq!(Pallet::<T>::receipt(&ptr_id).map(|r| r.cv), Some(cv));
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
