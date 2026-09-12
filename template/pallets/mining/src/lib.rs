#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;
#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
    }
    #[pallet::storage]
    pub type MiningPoints<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;
    #[pallet::storage]
    pub type TotalPoints<T: Config> = StorageValue<_, u64, ValueQuery>;
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        MinerRegistered { who: T::AccountId },
        PointsCredited { who: T::AccountId, points: u64, new_total: u64 },
    }
    #[pallet::error]
    pub enum Error<T> { Overflow, AlreadyRegistered }
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(5_000, 0))]
        pub fn register_miner(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!MiningPoints::<T>::contains_key(&who), Error::<T>::AlreadyRegistered);
            MiningPoints::<T>::insert(&who, 0u64);
            Self::deposit_event(Event::MinerRegistered { who });
            Ok(())
        }
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn credit_points(origin: OriginFor<T>, who: T::AccountId, points: u64) -> DispatchResult {
            ensure_root(origin)?;
            let current = MiningPoints::<T>::get(&who);
            let new_total = current.checked_add(points).ok_or(Error::<T>::Overflow)?;
            let global = TotalPoints::<T>::get().checked_add(points).ok_or(Error::<T>::Overflow)?;
            MiningPoints::<T>::insert(&who, new_total);
            TotalPoints::<T>::put(global);
            Self::deposit_event(Event::PointsCredited { who, points, new_total });
            Ok(())
        }
    }
}
