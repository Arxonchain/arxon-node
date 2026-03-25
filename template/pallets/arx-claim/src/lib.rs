#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;
#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Currency;
    use frame_system::pallet_prelude::*;

    type BalanceOf<T> = <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: Currency<Self::AccountId>;
        type WeightInfo: WeightInfo;
    }

    pub trait WeightInfo {
        fn register_claim() -> Weight;
        fn claim_arx() -> Weight;
        fn set_arx_per_point() -> Weight;
    }

    impl WeightInfo for () {
        fn register_claim() -> Weight { Weight::from_parts(10_000, 0) }
        fn claim_arx() -> Weight { Weight::from_parts(20_000, 0) }
        fn set_arx_per_point() -> Weight { Weight::from_parts(5_000, 0) }
    }

    /// ARX-P points snapshot per account (set by sudo before mainnet)
    #[pallet::storage]
    pub type ArxPointsSnapshot<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    /// Whether an account has already claimed their ARX
    #[pallet::storage]
    pub type HasClaimed<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, bool, ValueQuery>;

    /// How many ARX units per 1 ARX-P point (set by sudo)
    /// Default: 1 ARX-P = 1_000_000_000_000 units (1 ARX)
    #[pallet::storage]
    pub type ArxPerPoint<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Total ARX-P points registered in snapshot
    #[pallet::storage]
    pub type TotalSnapshotPoints<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Total ARX claimed so far
    #[pallet::storage]
    pub type TotalArxClaimed<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Is claiming open?
    #[pallet::storage]
    pub type ClaimingOpen<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Snapshot set for account [account, points]
        SnapshotSet { who: T::AccountId, points: u64 },
        /// ARX claimed successfully [account, points, arx_amount]
        ArxClaimed { who: T::AccountId, points: u64, arx_amount: u64 },
        /// Claiming opened/closed
        ClaimingStatusChanged { open: bool },
        /// ARX per point ratio updated
        ArxPerPointUpdated { new_ratio: u64 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Account has no points in snapshot
        NoPointsInSnapshot,
        /// Account has already claimed
        AlreadyClaimed,
        /// Claiming is not open yet
        ClaimingNotOpen,
        /// Arithmetic overflow
        Overflow,
        /// Zero points — nothing to claim
        ZeroPoints,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sudo: Set ARX-P snapshot for a single account
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_claim())]
        pub fn set_snapshot(
            origin: OriginFor<T>,
            who: T::AccountId,
            points: u64,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(points > 0, Error::<T>::ZeroPoints);
            let total = TotalSnapshotPoints::<T>::get()
                .checked_add(points)
                .ok_or(Error::<T>::Overflow)?;
            ArxPointsSnapshot::<T>::insert(&who, points);
            TotalSnapshotPoints::<T>::put(total);
            Self::deposit_event(Event::SnapshotSet { who, points });
            Ok(())
        }

        /// Sudo: Set ARX per point conversion ratio
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_arx_per_point())]
        pub fn set_arx_per_point(
            origin: OriginFor<T>,
            ratio: u64,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ArxPerPoint::<T>::put(ratio);
            Self::deposit_event(Event::ArxPerPointUpdated { new_ratio: ratio });
            Ok(())
        }

        /// Sudo: Open or close claiming
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(5_000, 0))]
        pub fn set_claiming_status(
            origin: OriginFor<T>,
            open: bool,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ClaimingOpen::<T>::put(open);
            Self::deposit_event(Event::ClaimingStatusChanged { open });
            Ok(())
        }

        /// Any miner: Claim your ARX based on ARX-P snapshot
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::claim_arx())]
        pub fn claim_arx(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(ClaimingOpen::<T>::get(), Error::<T>::ClaimingNotOpen);
            ensure!(!HasClaimed::<T>::get(&who), Error::<T>::AlreadyClaimed);
            let points = ArxPointsSnapshot::<T>::get(&who);
            ensure!(points > 0, Error::<T>::NoPointsInSnapshot);
            let ratio = ArxPerPoint::<T>::get().max(1);
            let arx_amount = points.checked_mul(ratio).ok_or(Error::<T>::Overflow)?;
            let total_claimed = TotalArxClaimed::<T>::get()
                .checked_add(arx_amount)
                .ok_or(Error::<T>::Overflow)?;
            HasClaimed::<T>::insert(&who, true);
            TotalArxClaimed::<T>::put(total_claimed);
            Self::deposit_event(Event::ArxClaimed { who, points, arx_amount });
            Ok(())
        }
    }
}
