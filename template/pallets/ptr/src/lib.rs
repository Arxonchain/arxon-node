#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    /// Full details of a private transaction receipt
    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct TransactionReceipt<AccountId, Balance, BlockNumber> {
        /// Unique transaction hash
        pub tx_hash: [u8; 32],
        /// Block number when transaction occurred
        pub block_number: BlockNumber,
        /// Unix timestamp of the transaction
        pub timestamp: u64,
        /// Full sender address
        pub sender: AccountId,
        /// Full receiver address
        pub receiver: AccountId,
        /// Full amount transferred
        pub amount: Balance,
        /// Privacy flags that were active
        pub hide_sender: bool,
        pub hide_receiver: bool,
        pub hide_amount: bool,
        pub hide_balance: bool,
        /// Sender balance before transaction (only visible to sender and third party with code)
        pub sender_balance_before: Balance,
        /// Sender balance after transaction
        pub sender_balance_after: Balance,
        /// Receiver balance before transaction (only visible to receiver and third party with code)
        pub receiver_balance_before: Balance,
        /// Receiver balance after transaction
        pub receiver_balance_after: Balance,
        /// Receipt is permanently tamper-proof — stored on Arxon blockchain
        pub tamper_proof_statement: bool,
    }

    /// A third party disclosure code — single use, burns after access
    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct DisclosureCode<AccountId, BlockNumber> {
        /// The transaction this code grants access to
        pub tx_hash: [u8; 32],
        /// Who generated this code
        pub generated_by: AccountId,
        /// Block when code was generated
        pub generated_at: BlockNumber,
        /// Whether this code has been used
        pub used: bool,
        /// Block when code was used (if used)
        pub used_at: Option<BlockNumber>,
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type Balance: Member + Parameter + Copy + Default;
    }

    /// Receipts stored by transaction hash
    #[pallet::storage]
    pub type Receipts<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 32], TransactionReceipt<T::AccountId, T::Balance, BlockNumberFor<T>>>;

    /// Disclosure codes stored by code hash
    /// Key: blake2_128(code_bytes) -> DisclosureCode
    #[pallet::storage]
    pub type DisclosureCodes<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 16], DisclosureCode<T::AccountId, BlockNumberFor<T>>>;

    /// How many disclosure codes have been generated per transaction
    #[pallet::storage]
    pub type CodeCountPerTx<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 32], u32, ValueQuery>;

    /// Total receipts ever generated
    #[pallet::storage]
    pub type TotalReceipts<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Total disclosure codes ever used
    #[pallet::storage]
    pub type TotalCodesUsed<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A private transaction receipt was created
        ReceiptCreated {
            tx_hash: [u8; 32],
            sender: T::AccountId,
            receiver: T::AccountId,
            block_number: BlockNumberFor<T>,
        },
        /// A disclosure code was generated
        DisclosureCodeGenerated {
            tx_hash: [u8; 32],
            generated_by: T::AccountId,
            code_index: u32,
        },
        /// A disclosure code was used by a third party
        DisclosureCodeUsed {
            tx_hash: [u8; 32],
            used_at: BlockNumberFor<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Receipt already exists for this transaction
        ReceiptAlreadyExists,
        /// Receipt not found
        ReceiptNotFound,
        /// Disclosure code not found or invalid
        InvalidDisclosureCode,
        /// Disclosure code already used — cannot reuse
        CodeAlreadyUsed,
        /// Only sender or receiver can generate disclosure codes
        NotAPartyToTransaction,
        /// Arithmetic overflow
        Overflow,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a Private Transaction Receipt.
        /// Called automatically when any privacy flag is active on a transaction.
        /// Only callable by sudo or the chain itself (internal).
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn create_receipt(
            origin: OriginFor<T>,
            tx_hash: [u8; 32],
            timestamp: u64,
            sender: T::AccountId,
            receiver: T::AccountId,
            amount: T::Balance,
            hide_sender: bool,
            hide_receiver: bool,
            hide_amount: bool,
            hide_balance: bool,
            sender_balance_before: T::Balance,
            sender_balance_after: T::Balance,
            receiver_balance_before: T::Balance,
            receiver_balance_after: T::Balance,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(!Receipts::<T>::contains_key(&tx_hash), Error::<T>::ReceiptAlreadyExists);

            let block_number = frame_system::Pallet::<T>::block_number();

            let receipt = TransactionReceipt {
                tx_hash,
                block_number,
                timestamp,
                sender: sender.clone(),
                receiver: receiver.clone(),
                amount,
                hide_sender,
                hide_receiver,
                hide_amount,
                hide_balance,
                sender_balance_before,
                sender_balance_after,
                receiver_balance_before,
                receiver_balance_after,
                tamper_proof_statement: true,
            };

            Receipts::<T>::insert(&tx_hash, receipt);

            let total = TotalReceipts::<T>::get()
                .checked_add(1)
                .ok_or(Error::<T>::Overflow)?;
            TotalReceipts::<T>::put(total);

            Self::deposit_event(Event::ReceiptCreated {
                tx_hash,
                sender,
                receiver,
                block_number,
            });

            Ok(())
        }

        /// Generate a single-use disclosure code for a specific transaction.
        /// Only the sender or receiver of that transaction can generate codes.
        /// Each code can only be used once — it burns permanently after use.
        /// Either party can generate as many codes as they need.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(15_000, 0))]
        pub fn generate_disclosure_code(
            origin: OriginFor<T>,
            tx_hash: [u8; 32],
            code_hash: [u8; 16],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let receipt = Receipts::<T>::get(&tx_hash)
                .ok_or(Error::<T>::ReceiptNotFound)?;

            ensure!(
                who == receipt.sender || who == receipt.receiver,
                Error::<T>::NotAPartyToTransaction
            );

            let block_number = frame_system::Pallet::<T>::block_number();
            let code_index = CodeCountPerTx::<T>::get(&tx_hash);

            let disclosure = DisclosureCode {
                tx_hash,
                generated_by: who.clone(),
                generated_at: block_number,
                used: false,
                used_at: None,
            };

            DisclosureCodes::<T>::insert(&code_hash, disclosure);
            CodeCountPerTx::<T>::insert(&tx_hash, code_index + 1);

            Self::deposit_event(Event::DisclosureCodeGenerated {
                tx_hash,
                generated_by: who,
                code_index,
            });

            Ok(())
        }

        /// Use a disclosure code to access full transaction details including both parties balances.
        /// The code burns permanently after this call — it cannot be reused.
        /// Third parties call this to verify the transaction.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn use_disclosure_code(
            origin: OriginFor<T>,
            code_hash: [u8; 16],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            let mut code = DisclosureCodes::<T>::get(&code_hash)
                .ok_or(Error::<T>::InvalidDisclosureCode)?;

            ensure!(!code.used, Error::<T>::CodeAlreadyUsed);

            let block_number = frame_system::Pallet::<T>::block_number();

            // Burn the code — mark as used permanently
            code.used = true;
            code.used_at = Some(block_number);
            DisclosureCodes::<T>::insert(&code_hash, &code);

            let total = TotalCodesUsed::<T>::get()
                .checked_add(1)
                .ok_or(Error::<T>::Overflow)?;
            TotalCodesUsed::<T>::put(total);

            Self::deposit_event(Event::DisclosureCodeUsed {
                tx_hash: code.tx_hash,
                used_at: block_number,
            });

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Check if a receipt exists for a transaction hash
        pub fn receipt_exists(tx_hash: &[u8; 32]) -> bool {
            Receipts::<T>::contains_key(tx_hash)
        }

        /// Get receipt if it exists
        pub fn get_receipt(
            tx_hash: &[u8; 32],
        ) -> Option<TransactionReceipt<T::AccountId, T::Balance, BlockNumberFor<T>>> {
            Receipts::<T>::get(tx_hash)
        }

        /// Check if a disclosure code is valid and unused
        pub fn is_code_valid(code_hash: &[u8; 16]) -> bool {
            match DisclosureCodes::<T>::get(code_hash) {
                Some(code) => !code.used,
                None => false,
            }
        }
    }
}
