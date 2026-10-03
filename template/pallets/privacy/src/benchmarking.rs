//! Benchmarks of the light extrinsics. Bundles are not benchmarked end to end:
//! their weight is composed in `weights.rs` from the measured primitives of the
//! verifier, note tree, nullifier registry and receipt pallets.

use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use sp_core::H160;
use sp_runtime::traits::Convert;

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
		assert!(HideBalancePending::<T>::get(&caller).is_some());
	}

	/// Worst case: the largest decimals (the longest power) on an empty pool.
	#[benchmark]
	fn set_arx20_unit() {
		let token = H160::repeat_byte(0x20);
		let signer = T::TokenToAccount::convert(token);

		#[extrinsic_call]
		_(RawOrigin::Signed(signer), token, MAX_ARX20_DECIMALS);

		assert!(Arx20Unit::<T>::get(token).is_some());
	}

	/// Worst case: the caller replaces a key it registered before, which also
	/// frees the old key's owner entry.
	#[benchmark]
	fn register_shielded_key() {
		let caller: T::AccountId = whitelisted_caller();
		let old = FieldBytes::from_u64(0x01d);
		Pallet::<T>::register_shielded_key(RawOrigin::Signed(caller.clone()).into(), old)
			.expect("fresh key");
		let pk = FieldBytes::from_u64(0x5e1f);

		#[extrinsic_call]
		_(RawOrigin::Signed(caller.clone()), pk);

		assert_eq!(Pallet::<T>::shielded_key(&caller), Some(pk));
		assert_eq!(Pallet::<T>::shielded_key_owner(&pk), Some(caller));
		assert_eq!(Pallet::<T>::shielded_key_owner(&old), None);
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
