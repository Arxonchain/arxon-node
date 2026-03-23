#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;
#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct PrivacyMask {
        pub hide_sender: bool,
        pub hide_receiver: bool,
        pub hide_amount: bool,
        pub hide_balance: bool,
    }
    impl PrivacyMask {
        pub fn is_any_private(&self) -> bool {
            self.hide_sender || self.hide_receiver || self.hide_amount || self.hide_balance
        }
    }
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }
    #[pallet::storage]
    pub type AccountPrivacyDefault<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, PrivacyMask>;
    #[pallet::storage]
    pub type TxPrivacyMask<T: Config> = StorageMap<_, Blake2_128Concat, T::Hash, PrivacyMask>;
    #[pallet::storage]
    pub type ShieldedTxCount<T: Config> = StorageValue<_, u64, ValueQuery>;
    #[pallet::storage]
    pub type HideBalanceAccounts<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, bool, ValueQuery>;
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        PrivacyDefaultSet { who: T::AccountId, hide_sender: bool, hide_receiver: bool, hide_amount: bool, hide_balance: bool },
        TxPrivacyRecorded { tx_hash: T::Hash, hide_sender: bool, hide_receiver: bool, hide_amount: bool },
        BalanceVisibilitySet { who: T::AccountId, hidden: bool },
    }
    #[pallet::error]
    pub enum Error<T> { Overflow }
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn set_privacy_default(origin: OriginFor<T>, hide_sender: bool, hide_receiver: bool, hide_amount: bool, hide_balance: bool) -> DispatchResult {
            let who = ensure_signed(origin)?;
            AccountPrivacyDefault::<T>::insert(&who, PrivacyMask { hide_sender, hide_receiver, hide_amount, hide_balance });
            Self::deposit_event(Event::PrivacyDefaultSet { who, hide_sender, hide_receiver, hide_amount, hide_balance });
            Ok(())
        }
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(15_000, 0))]
        pub fn record_tx_privacy(origin: OriginFor<T>, tx_hash: T::Hash, hide_sender: bool, hide_receiver: bool, hide_amount: bool) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            let mask = PrivacyMask { hide_sender, hide_receiver, hide_amount, hide_balance: false };
            if mask.is_any_private() {
                let count = ShieldedTxCount::<T>::get().checked_add(1).ok_or(Error::<T>::Overflow)?;
                ShieldedTxCount::<T>::put(count);
            }
            TxPrivacyMask::<T>::insert(&tx_hash, &mask);
            Self::deposit_event(Event::TxPrivacyRecorded { tx_hash, hide_sender, hide_receiver, hide_amount });
            Ok(())
        }
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn set_balance_visibility(origin: OriginFor<T>, hidden: bool) -> DispatchResult {
            let who = ensure_signed(origin)?;
            HideBalanceAccounts::<T>::insert(&who, hidden);
            Self::deposit_event(Event::BalanceVisibilitySet { who, hidden });
            Ok(())
        }
    }
}
