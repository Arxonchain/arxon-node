//! # Private transaction receipts (runtime index 15)
//!
//! A receipt is no longer a plaintext record of both parties, the amount and
//! four balances. It is a commitment `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`
//! proved well formed by Circuit 4 when the private transfer that pays it
//! executes; `pallet-privacy` hands it over through [`pallet_privacy::ReceiptSink`].
//! Storage keeps the identifier, the payment value commitment, the block and
//! the bundle mask: nothing a chain observer can read parties or amounts from.
//!
//! A receipt holder opens it selectively with [`Pallet::disclose`]: a Circuit 5
//! proof reveals any subset of sender, receiver and amount, bound to the
//! *account that submits the disclosure* (`audience`), so a disclosure made for
//! one auditor cannot be replayed to anyone else. This replaces the single-use
//! disclosure codes: the holder can produce as many audience-bound proofs as
//! it wants, off chain, and none of them leaks beyond its audience.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod migrations;
pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
	use arxon_zk_primitives::{
		mask::{hides_amount, hides_balance, hides_receiver, hides_sender, is_valid_mask},
		C5PublicInputs, CircuitId, FieldBytes, InstanceRows, Proof, PublicInputLayout,
		PublicInputs, RevealedFields,
	};
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use pallet_privacy::ReceiptSink;
	use pallet_zk_verifier::VerifyProof;
	use sp_runtime::traits::SaturatedConversion;

	use super::weights::WeightInfo;

	/// What the chain stores about a receipt.
	#[derive(
		Clone,
		Copy,
		Encode,
		Decode,
		DecodeWithMemTracking,
		Eq,
		PartialEq,
		RuntimeDebug,
		TypeInfo,
		MaxEncodedLen
	)]
	pub struct ReceiptCommitment<BlockNumber> {
		/// Value commitment of the payment output the receipt covers.
		pub cv: FieldBytes,
		/// Block of the bundle that created it.
		pub block_number: BlockNumber,
		/// Four-flag mask of that bundle.
		pub mask_bits: u8,
	}

	/// Values a discloser publishes; ignored (zeroed) where the disclosure mask hides them.
	#[derive(
		Clone,
		Copy,
		Encode,
		Decode,
		DecodeWithMemTracking,
		Eq,
		PartialEq,
		RuntimeDebug,
		TypeInfo,
		MaxEncodedLen
	)]
	pub struct RevealedValues {
		/// Sender shielded public key.
		pub sender: FieldBytes,
		/// Receiver shielded public key.
		pub receiver: FieldBytes,
		/// Amount in shielded units.
		pub amount: FieldBytes,
	}

	/// Version 1: the zero-knowledge layout of this pallet (version 0 is the chain before it).
	pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Proof verification.
		type ZkVerifier: VerifyProof;
		/// How far ahead a disclosure's expiry block may lie.
		#[pallet::constant]
		type MaxProofValidity: Get<BlockNumberFor<Self>>;
		/// Weights.
		type WeightInfo: WeightInfo;
	}

	/// Receipts by identifier.
	#[pallet::storage]
	pub type Receipts<T: Config> =
		StorageMap<_, Blake2_128Concat, FieldBytes, ReceiptCommitment<BlockNumberFor<T>>>;

	/// Disclosures made per receipt.
	#[pallet::storage]
	pub type DisclosureCount<T: Config> =
		StorageMap<_, Blake2_128Concat, FieldBytes, u32, ValueQuery>;

	/// Receipts ever recorded.
	#[pallet::storage]
	pub type TotalReceipts<T: Config> = StorageValue<_, u64, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A private transfer attached a receipt.
		ReceiptCreated {
			/// Receipt identifier.
			ptr_id: FieldBytes,
			/// Block.
			block_number: BlockNumberFor<T>,
			/// Mask of the bundle.
			mask_bits: u8,
		},
		/// A receipt was opened to `verifier`.
		Disclosed {
			/// Receipt identifier.
			ptr_id: FieldBytes,
			/// Who the disclosure was made to (and who submitted it).
			verifier: T::AccountId,
			/// Fields kept hidden.
			disclosure_mask: u8,
			/// Sender key if disclosed.
			sender: Option<FieldBytes>,
			/// Receiver key if disclosed.
			receiver: Option<FieldBytes>,
			/// Amount in shielded units if disclosed.
			amount: Option<u64>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// A receipt with this identifier exists.
		ReceiptAlreadyExists,
		/// No receipt with this identifier.
		ReceiptNotFound,
		/// Mask has bits above the four flags, or sets the balance bit.
		InvalidDisclosureMask,
		/// A field element is not canonical.
		InvalidFieldElement,
		/// The expiry block is in the past.
		ProofExpired,
		/// The expiry block is further ahead than `MaxProofValidity`.
		ExpiryTooFar,
		/// Arithmetic overflow.
		Overflow,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Opens receipt `ptr_id` to the signer, revealing the fields `disclosure_mask` does not hide.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::disclose())]
		pub fn disclose(
			origin: OriginFor<T>,
			ptr_id: FieldBytes,
			disclosure_mask: u8,
			revealed: RevealedValues,
			expiry_block: BlockNumberFor<T>,
			proof: Proof,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(
				Receipts::<T>::contains_key(ptr_id),
				Error::<T>::ReceiptNotFound
			);
			ensure!(
				is_valid_mask(disclosure_mask) && !hides_balance(disclosure_mask),
				Error::<T>::InvalidDisclosureMask
			);
			ensure!(
				[revealed.sender, revealed.receiver, revealed.amount]
					.iter()
					.all(FieldBytes::is_canonical),
				Error::<T>::InvalidFieldElement
			);
			Self::check_expiry(expiry_block)?;

			let audience = Self::audience_of(&who);
			let fields = RevealedFields {
				sender: revealed.sender,
				receiver: revealed.receiver,
				amount: revealed.amount,
			};
			let instance = C5PublicInputs::new(
				ptr_id,
				disclosure_mask,
				fields,
				audience,
				expiry_block.saturated_into(),
			)
			.ok_or(Error::<T>::InvalidDisclosureMask)?;
			let rows =
				InstanceRows::try_from(instance.to_elements()).map_err(|_| Error::<T>::Overflow)?;
			let mut inputs = PublicInputs::default();
			inputs.try_push(rows).map_err(|_| Error::<T>::Overflow)?;
			T::ZkVerifier::verify_proof(CircuitId::DisclosureProof, &proof, &inputs)?;

			DisclosureCount::<T>::try_mutate(ptr_id, |c| -> DispatchResult {
				*c = c.checked_add(1).ok_or(Error::<T>::Overflow)?;
				Ok(())
			})?;
			Self::deposit_event(Event::Disclosed {
				ptr_id,
				verifier: who,
				disclosure_mask,
				sender: (!hides_sender(disclosure_mask)).then_some(revealed.sender),
				receiver: (!hides_receiver(disclosure_mask)).then_some(revealed.receiver),
				amount: (!hides_amount(disclosure_mask))
					.then(|| Self::field_to_u64(&revealed.amount)),
			});
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// The audience field element a disclosure to `who` must be bound to.
		pub fn audience_of(who: &T::AccountId) -> FieldBytes {
			arxon_zk_primitives::digest_to_field(&who.encode())
		}

		/// Receipt by identifier.
		pub fn receipt(ptr_id: &FieldBytes) -> Option<ReceiptCommitment<BlockNumberFor<T>>> {
			Receipts::<T>::get(ptr_id)
		}

		fn check_expiry(expiry_block: BlockNumberFor<T>) -> DispatchResult {
			let now = frame_system::Pallet::<T>::block_number();
			ensure!(expiry_block >= now, Error::<T>::ProofExpired);
			ensure!(
				expiry_block - now <= T::MaxProofValidity::get(),
				Error::<T>::ExpiryTooFar
			);
			Ok(())
		}

		fn field_to_u64(f: &FieldBytes) -> u64 {
			let mut le = [0u8; 8];
			le.copy_from_slice(&f.0[..8]);
			u64::from_le_bytes(le)
		}
	}

	impl<T: Config> ReceiptSink for Pallet<T> {
		fn record(ptr_id: FieldBytes, cv: FieldBytes, mask_bits: u8) -> DispatchResult {
			ensure!(
				!Receipts::<T>::contains_key(ptr_id),
				Error::<T>::ReceiptAlreadyExists
			);
			let block_number = frame_system::Pallet::<T>::block_number();
			Receipts::<T>::insert(
				ptr_id,
				ReceiptCommitment {
					cv,
					block_number,
					mask_bits,
				},
			);
			TotalReceipts::<T>::mutate(|t| *t = t.saturating_add(1));
			Self::deposit_event(Event::ReceiptCreated {
				ptr_id,
				block_number,
				mask_bits,
			});
			Ok(())
		}

		fn record_weight() -> Weight {
			T::WeightInfo::record()
		}
	}
}
