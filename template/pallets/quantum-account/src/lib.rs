#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

pub const MLDSA65_PK_LEN: u32 = 1952;
pub const MLDSA65_SIG_LEN: u32 = 3309;
pub const ARXON_QUANTUM_DOMAIN: &[u8] = b"arxon-quantum-dispatch-v1";

/// Verify an ML-DSA-65 signature — runs in native and Wasm.
pub fn verify_mldsa65(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, VerifyingKey};
    use ml_dsa::signature::Verifier;

    if public_key.len() != MLDSA65_PK_LEN as usize
        || signature.len() != MLDSA65_SIG_LEN as usize
    {
        return false;
    }

    let encoded_pk = match EncodedVerifyingKey::<MlDsa65>::try_from(public_key) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let encoded_sig = match EncodedSignature::<MlDsa65>::try_from(signature) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let verifying_key: VerifyingKey<MlDsa65> = VerifyingKey::decode(&encoded_pk);

    let ml_sig = match ml_dsa::Signature::<MlDsa65>::decode(&encoded_sig) {
        Some(s) => s,
        None => return false,
    };

    verifying_key.verify(message, &ml_sig).is_ok()
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use codec::Encode;
    use frame_support::{
        dispatch::{GetDispatchInfo, PostDispatchInfo},
        pallet_prelude::*,
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Dispatchable;

    pub type QuantumPublicKey = BoundedVec<u8, ConstU32<MLDSA65_PK_LEN>>;
    pub type QuantumSignature = BoundedVec<u8, ConstU32<MLDSA65_SIG_LEN>>;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type RuntimeCall: Parameter
            + Dispatchable<RuntimeOrigin = Self::RuntimeOrigin, PostInfo = PostDispatchInfo>
            + GetDispatchInfo
            + From<frame_system::Call<Self>>;
    }

    /// AccountId -> registered ML-DSA-65 public key
    #[pallet::storage]
    #[pallet::getter(fn quantum_key)]
    pub type QuantumKeys<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, QuantumPublicKey, OptionQuery>;

    /// AccountId -> quantum nonce (replay protection)
    #[pallet::storage]
    #[pallet::getter(fn quantum_nonce)]
    pub type QuantumNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    /// Total quantum accounts registered on Arxon
    #[pallet::storage]
    #[pallet::getter(fn quantum_account_count)]
    pub type QuantumAccountCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        QuantumKeyRegistered { who: T::AccountId },
        QuantumKeyDeregistered { who: T::AccountId },
        QuantumDispatchSuccess { who: T::AccountId, nonce: u64 },
        QuantumDispatchFailed { who: T::AccountId, nonce: u64 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// No quantum key registered for this account
        NoQuantumKey,
        /// Account already has a quantum key — deregister first
        KeyAlreadyRegistered,
        /// Public key is not valid ML-DSA-65 (must be exactly 1952 bytes)
        InvalidPublicKey,
        /// Signature is invalid or wrong (must be exactly 3309 bytes)
        InvalidSignature,
        /// Nonce does not match current quantum nonce for this account
        InvalidNonce,
        /// Nonce overflow
        NonceOverflow,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register an ML-DSA-65 public key for the caller's account.
        /// After this, `quantum_dispatch` can authenticate inner calls with that key.
        /// Ordinary signed extrinsics still work unless a later policy disables them.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(150_000_000, 2048))]
        pub fn register_quantum_key(
            origin: OriginFor<T>,
            public_key_bytes: BoundedVec<u8, ConstU32<MLDSA65_PK_LEN>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !QuantumKeys::<T>::contains_key(&who),
                Error::<T>::KeyAlreadyRegistered
            );
            ensure!(
                public_key_bytes.len() == MLDSA65_PK_LEN as usize,
                Error::<T>::InvalidPublicKey
            );
            Self::validate_public_key(&public_key_bytes)?;
            QuantumKeys::<T>::insert(&who, public_key_bytes);
            QuantumAccountCount::<T>::mutate(|c| *c = c.saturating_add(1));
            Self::deposit_event(Event::QuantumKeyRegistered { who });
            Ok(())
        }

        /// Remove the ML-DSA key for the caller's account.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(20_000_000, 0))]
        pub fn deregister_quantum_key(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                QuantumKeys::<T>::contains_key(&who),
                Error::<T>::NoQuantumKey
            );
            QuantumKeys::<T>::remove(&who);
            QuantumAccountCount::<T>::mutate(|c| *c = c.saturating_sub(1));
            Self::deposit_event(Event::QuantumKeyDeregistered { who });
            Ok(())
        }

        /// Submit a call authenticated by an ML-DSA-65 signature.
        ///
        /// Anyone can relay this — the ML-DSA signature is the real authentication.
        /// Signed message: ARXON_QUANTUM_DOMAIN || SCALE(nonce) || SCALE(call)
        #[pallet::call_index(2)]
        #[pallet::weight({
            let call_weight = call.get_dispatch_info().call_weight;
            Weight::from_parts(300_000_000, 65536).saturating_add(call_weight)
        })]
        pub fn quantum_dispatch(
            origin: OriginFor<T>,
            quantum_signer: T::AccountId,
            nonce: u64,
            call: Box<<T as Config>::RuntimeCall>,
            signature: BoundedVec<u8, ConstU32<MLDSA65_SIG_LEN>>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;

            // 1. Fetch registered key
            let pub_key = QuantumKeys::<T>::get(&quantum_signer)
                .ok_or(Error::<T>::NoQuantumKey)?;

            // 2. Nonce check
            let expected_nonce = QuantumNonces::<T>::get(&quantum_signer);
            ensure!(nonce == expected_nonce, Error::<T>::InvalidNonce);

            // 3. Build signed message
            let mut message: Vec<u8> = ARXON_QUANTUM_DOMAIN.to_vec();
            message.extend_from_slice(&nonce.encode());
            message.extend_from_slice(&call.encode());

            // 4. Verify ML-DSA-65 signature
            ensure!(
                signature.len() == MLDSA65_SIG_LEN as usize,
                Error::<T>::InvalidSignature
            );
            ensure!(
                verify_mldsa65(&pub_key, &message, &signature),
                Error::<T>::InvalidSignature
            );

            // 5. Advance nonce before inner dispatch so a reentrant inner call sees the new value.
            // If this extrinsic returns Err, FRAME rolls the nonce change back. A failed inner
            // call can be retried with the same ML-DSA signature.
            let new_nonce = nonce.checked_add(1).ok_or(Error::<T>::NonceOverflow)?;
            QuantumNonces::<T>::insert(&quantum_signer, new_nonce);

            // 6. Dispatch inner call as quantum_signer
            let dispatch_origin =
                frame_system::RawOrigin::Signed(quantum_signer.clone()).into();
            let result = call.dispatch(dispatch_origin);

            match &result {
                Ok(_) => Self::deposit_event(Event::QuantumDispatchSuccess {
                    who: quantum_signer,
                    nonce,
                }),
                Err(_) => Self::deposit_event(Event::QuantumDispatchFailed {
                    who: quantum_signer,
                    nonce,
                }),
            }

            result.map_err(|e| e.error.into())
        }
    }

    impl<T: Config> Pallet<T> {
        fn validate_public_key(bytes: &[u8]) -> Result<(), DispatchError> {
            use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey};
            ensure!(
                bytes.len() == MLDSA65_PK_LEN as usize,
                Error::<T>::InvalidPublicKey
            );
            let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
                .map_err(|_| Error::<T>::InvalidPublicKey)?;
            let _key: VerifyingKey<MlDsa65> = VerifyingKey::decode(&encoded);
            Ok(())
        }

        /// Returns true if this account has a registered ML-DSA key
        pub fn is_quantum_account(account: &T::AccountId) -> bool {
            QuantumKeys::<T>::contains_key(account)
        }
    }
}
