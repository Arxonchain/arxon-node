//! Benchmarks of the light extrinsics. Bundles are not benchmarked end to end:
//! their weight is composed in `weights.rs` from the measured primitives of the
//! verifier, note tree, nullifier registry and receipt pallets.

use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

use super::*;

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn set_privacy_default() {
		let caller: T::AccountId = whitelisted_caller();
		let mask = PrivacyMask::from_bits(0b1111);

		#[extrinsic_call]
		_(RawOrigin::Signed(caller.clone()), mask);

		assert_eq!(AccountPrivacyDefault::<T>::get(&caller), Some(mask));
	}

	#[benchmark]
	fn set_balance_visibility() {
		let caller: T::AccountId = whitelisted_caller();

		#[extrinsic_call]
		_(RawOrigin::Signed(caller.clone()), true);

		assert!(HideBalanceAccounts::<T>::get(&caller));
	}

	#[benchmark]
	fn register_shielded_key() {
		let caller: T::AccountId = whitelisted_caller();
		let pk = FieldBytes::from_u64(0x5e1f);

		#[extrinsic_call]
		_(RawOrigin::Signed(caller.clone()), pk);

		assert_eq!(Pallet::<T>::shielded_key(&caller), Some(pk));
		assert_eq!(Pallet::<T>::shielded_key_owner(&pk), Some(caller));
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
