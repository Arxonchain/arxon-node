//! # Selective privacy (runtime index 13)
//!
//! The Arxon shielded pool. Users pick, per bundle, which of the four fields to
//! hide or reveal (`PrivacyMask`: sender, receiver, amount, balance). The same
//! mask drives the Halo2 circuits, so a flag is never metadata painted onto an
//! unrelated transaction: every private operation carries proofs that the
//! runtime verifies before it touches state.
//!
//! Three operations move value:
//! * [`Pallet::shield`]: transparent ARX from the signer into the pool, creating notes.
//! * [`Pallet::unshield`]: notes are spent and ARX leaves the pool to a recipient.
//! * [`Pallet::submit_private_transfer`]: notes are spent and new notes created.
//!
//! All three funnel into one execution path that checks everything (mask,
//! expiry window, amounts, anchor, nullifiers, proof shapes, then the proofs
//! themselves) before writing anything. The public inputs of every proof are
//! built by the pallet from the extrinsic arguments, never accepted from the
//! caller, and every proof carries the bundle digest of those arguments, so a
//! proof cannot be re-targeted or replayed.
//!
//! The extrinsic signer only pays the fee; it is deliberately absent from the
//! bundle digest so any relayer can submit a bundle. Shielded amounts are `u64`
//! multiples of `ShieldedUnit` base units. `hide_balance` is enforced here
//! (`HideBalanceAccounts`), not in the circuits.
//!
//! Wire ids: call index 1 (`record_tx_privacy`) is burned; it let anyone paint
//! flags on any hash and is gone.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod weights;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use arxon_zk_primitives::FieldBytes;
use frame_support::pallet_prelude::*;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Receives a receipt attachment from a private transfer (`pallet-ptr` implements it).
pub trait ReceiptSink {
	/// Records a receipt commitment for the payment output with value commitment `cv`.
	fn record(ptr_id: FieldBytes, cv: FieldBytes, mask_bits: u8) -> DispatchResult;
}

impl ReceiptSink for () {
	fn record(_: FieldBytes, _: FieldBytes, _: u8) -> DispatchResult {
		Ok(())
	}
}

/// The four selective privacy flags.
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
pub struct PrivacyMask {
	/// Hide who spends.
	pub hide_sender: bool,
	/// Hide who receives.
	pub hide_receiver: bool,
	/// Hide how much.
	pub hide_amount: bool,
	/// Hide the account balance (application layer).
	pub hide_balance: bool,
}

impl PrivacyMask {
	/// `true` iff any flag is set.
	pub fn is_any_private(&self) -> bool {
		self.hide_sender || self.hide_receiver || self.hide_amount || self.hide_balance
	}

	/// Circuit public-input packing. Do not reorder these bits.
	/// bit 0 = hide_sender, bit 1 = hide_receiver, bit 2 = hide_amount, bit 3 = hide_balance.
	pub const fn as_bits(&self) -> u8 {
		let mut bits = 0u8;
		if self.hide_sender {
			bits |= 1;
		}
		if self.hide_receiver {
			bits |= 2;
		}
		if self.hide_amount {
			bits |= 4;
		}
		if self.hide_balance {
			bits |= 8;
		}
		bits
	}

	/// Inverse of `as_bits`. Higher bits are ignored.
	pub const fn from_bits(bits: u8) -> Self {
		Self {
			hide_sender: bits & 1 != 0,
			hide_receiver: bits & 2 != 0,
			hide_amount: bits & 4 != 0,
			hide_balance: bits & 8 != 0,
		}
	}
}

/// Maximum encrypted note payload per output.
pub const MAX_ENCRYPTED_NOTE: u32 = 512;
/// Maximum notes spent or created per bundle (Circuit 2 arity).
pub const MAX_NOTES: u32 = arxon_zk_primitives::MAX_INSTANCES;

/// Opaque wallet-encrypted `(pk_r, amount, rho, blinding)` for the receiver.
pub type EncryptedNote = BoundedVec<u8, ConstU32<MAX_ENCRYPTED_NOTE>>;

/// A note being created.
#[derive(
	Clone,
	Encode,
	Decode,
	DecodeWithMemTracking,
	Eq,
	PartialEq,
	RuntimeDebug,
	TypeInfo,
	MaxEncodedLen
)]
pub struct Output {
	/// Note commitment `H_NOTE(pk_r, amount, rho)`; the tree leaf.
	pub cm: FieldBytes,
	/// Value commitment `H_CV(amount, blinding)`.
	pub cv: FieldBytes,
	/// Receiver key to publish, ignored (zeroed) when the mask hides the receiver.
	pub revealed_receiver: FieldBytes,
	/// Amount to publish, ignored (zeroed) when the mask hides the amount.
	pub revealed_amount: FieldBytes,
	/// Ciphertext for the receiver; stored in the event only, hashed into the bundle digest.
	pub encrypted_note: EncryptedNote,
}

/// A note being spent.
#[derive(
	Clone,
	Encode,
	Decode,
	DecodeWithMemTracking,
	Eq,
	PartialEq,
	RuntimeDebug,
	TypeInfo,
	MaxEncodedLen
)]
pub struct Input {
	/// `H_NF(nk, cm)` of the spent note.
	pub nullifier: FieldBytes,
	/// Fresh value commitment of the spent amount (Circuit 3 output, Circuit 2 input).
	pub cv: FieldBytes,
	/// Sender key to publish, ignored (zeroed) when the mask hides the sender.
	pub revealed_sender: FieldBytes,
}

/// The proofs of a bundle, in the order the pallet verifies them.
#[derive(
	Clone,
	Encode,
	Decode,
	DecodeWithMemTracking,
	Eq,
	PartialEq,
	RuntimeDebug,
	TypeInfo,
	MaxEncodedLen
)]
pub struct ProofBundle {
	/// Circuit 3, one instance per input. `None` iff there are no inputs.
	pub spend: Option<arxon_zk_primitives::Proof>,
	/// Circuit 1, one instance per output. `None` iff there are no outputs.
	pub output: Option<arxon_zk_primitives::Proof>,
	/// Circuit 2, always present.
	pub balance: arxon_zk_primitives::Proof,
}

/// Spent and created notes of a bundle.
pub type Inputs = BoundedVec<Input, ConstU32<MAX_NOTES>>;
/// Created notes of a bundle.
pub type Outputs = BoundedVec<Output, ConstU32<MAX_NOTES>>;

// Extrinsic arguments stay flat for the wire format; the call macro generates 8-argument constructors.
#[allow(clippy::too_many_arguments)]
#[frame_support::pallet]
pub mod pallet {
	use alloc::vec::Vec;

	use arxon_zk_primitives::{
		bundle_digest, encrypted_notes_hash,
		mask::{hides_amount, hides_receiver, hides_sender, is_valid_mask},
		poseidon::cv_dummy_bytes,
		BundleFields, C1PublicInputs, C2PublicInputs, C3PublicInputs, CircuitId, FieldBytes,
		InstanceRows, PublicInputLayout, PublicInputs, RevealedFields, C2_INPUTS, C2_OUTPUTS,
		CHAIN_ID,
	};
	use frame_support::{
		pallet_prelude::*,
		traits::{
			fungible::{Inspect, Mutate},
			tokens::Preservation,
		},
		PalletId,
	};
	use frame_system::pallet_prelude::*;
	use pallet_note_tree::{MerkleTree, TreeId};
	use pallet_nullifier_registry::NullifierSet;
	use pallet_zk_verifier::VerifyProof;
	use sp_runtime::traits::{AccountIdConversion, SaturatedConversion, Zero};

	use super::{weights::WeightInfo, Inputs, Outputs, PrivacyMask, ProofBundle, ReceiptSink};

	/// Balance type of the configured currency.
	pub type BalanceOf<T> =
		<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// The ARX token.
		type Currency: Inspect<Self::AccountId> + Mutate<Self::AccountId>;
		/// Derives the pool account that custodies shielded ARX.
		#[pallet::constant]
		type PalletId: Get<PalletId>;
		/// Base units per shielded unit (`10^9`: 1 ARX = `10^9` units).
		#[pallet::constant]
		type ShieldedUnit: Get<BalanceOf<Self>>;
		/// How far ahead a bundle's expiry block may lie.
		#[pallet::constant]
		type MaxProofValidity: Get<BlockNumberFor<Self>>;
		/// Proof verification.
		type ZkVerifier: VerifyProof;
		/// Spent nullifier set.
		type Nullifiers: NullifierSet;
		/// Note and membership trees.
		type Trees: MerkleTree;
		/// Receipt attachments (`()` until `pallet-ptr` is rewritten).
		type Receipts: ReceiptSink;
		/// Weights.
		type WeightInfo: WeightInfo;
	}

	/// Default mask an account wants applied by its wallet.
	#[pallet::storage]
	pub type AccountPrivacyDefault<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, PrivacyMask>;

	/// Mask of every executed bundle, keyed by bundle digest.
	#[pallet::storage]
	pub type TxPrivacyMask<T: Config> = StorageMap<_, Blake2_128Concat, FieldBytes, PrivacyMask>;

	/// Number of executed bundles with at least one flag set.
	#[pallet::storage]
	pub type ShieldedTxCount<T: Config> = StorageValue<_, u64, ValueQuery>;

	/// Accounts that asked for their balance to be hidden by front ends.
	#[pallet::storage]
	pub type HideBalanceAccounts<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, bool, ValueQuery>;

	/// Shielded public key registered by an account.
	#[pallet::storage]
	pub type ShieldedKeys<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, FieldBytes>;

	/// Account that registered a shielded public key.
	#[pallet::storage]
	pub type ShieldedKeyOwners<T: Config> =
		StorageMap<_, Blake2_128Concat, FieldBytes, T::AccountId>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An account set its default mask.
		PrivacyDefaultSet {
			/// The account.
			who: T::AccountId,
			/// The mask.
			mask: PrivacyMask,
		},
		/// An account asked front ends to hide or show its balance.
		BalanceVisibilitySet {
			/// The account.
			who: T::AccountId,
			/// `true` = hidden.
			hidden: bool,
		},
		/// An account linked a shielded public key.
		ShieldedKeyRegistered {
			/// The account.
			who: T::AccountId,
			/// The key.
			pk: FieldBytes,
		},
		/// ARX entered the pool.
		Shielded {
			/// Depositor.
			depositor: T::AccountId,
			/// Amount in base units.
			amount: BalanceOf<T>,
			/// Bundle digest.
			bundle_digest: FieldBytes,
		},
		/// ARX left the pool.
		Unshielded {
			/// Recipient.
			recipient: T::AccountId,
			/// Amount in base units.
			amount: BalanceOf<T>,
			/// Bundle digest.
			bundle_digest: FieldBytes,
		},
		/// A bundle executed (any of the three operations).
		BundleExecuted {
			/// Bundle digest (also the key of `TxPrivacyMask`).
			bundle_digest: FieldBytes,
			/// Mask.
			mask: PrivacyMask,
			/// Expiry block the proofs were bound to.
			expiry_block: BlockNumberFor<T>,
		},
		/// A note was spent.
		NoteSpent {
			/// Bundle digest.
			bundle_digest: FieldBytes,
			/// Nullifier.
			nullifier: FieldBytes,
			/// Sender key, if the mask reveals it.
			revealed_sender: Option<FieldBytes>,
			/// Registered owner of that key, if any.
			sender_account: Option<T::AccountId>,
		},
		/// A note was created.
		NoteCreated {
			/// Bundle digest.
			bundle_digest: FieldBytes,
			/// Leaf index in the note tree.
			leaf_index: u64,
			/// Commitment.
			cm: FieldBytes,
			/// Receiver key, if the mask reveals it.
			revealed_receiver: Option<FieldBytes>,
			/// Registered owner of that key, if any.
			receiver_account: Option<T::AccountId>,
			/// Amount in shielded units, if the mask reveals it.
			revealed_amount: Option<u64>,
			/// Ciphertext for the receiver.
			encrypted_note: super::EncryptedNote,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Arithmetic overflow.
		Overflow,
		/// Mask has bits above the four flags.
		InvalidMask,
		/// A field element is not canonical.
		InvalidFieldElement,
		/// The expiry block is in the past.
		ProofExpired,
		/// The expiry block is further ahead than `MaxProofValidity`.
		ExpiryTooFar,
		/// Amount is not a multiple of `ShieldedUnit`.
		AmountNotMultipleOfUnit,
		/// Amount in shielded units does not fit `u64`.
		AmountTooLarge,
		/// Amount is zero.
		ZeroAmount,
		/// The bundle spends no note but must.
		NoInputs,
		/// The bundle creates no note but must.
		NoOutputs,
		/// Proofs present do not match inputs and outputs present.
		ProofBundleMismatch,
		/// Anchor is not a recent note tree root.
		UnknownAnchor,
		/// A nullifier was already spent.
		NullifierAlreadySpent,
		/// The same nullifier appears twice in the bundle.
		DuplicateNullifier,
		/// A commitment is already in the tree or appears twice in the bundle.
		DuplicateCommitment,
		/// The pool holds less than the unshield amount.
		PoolInsufficient,
		/// The shielded key is registered to another account.
		ShieldedKeyTaken,
		/// A bundle with this exact digest already executed.
		DuplicateBundle,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Sets the mask the account's wallet should apply by default.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_privacy_default())]
		pub fn set_privacy_default(origin: OriginFor<T>, mask: PrivacyMask) -> DispatchResult {
			let who = ensure_signed(origin)?;
			AccountPrivacyDefault::<T>::insert(&who, mask);
			Self::deposit_event(Event::PrivacyDefaultSet { who, mask });
			Ok(())
		}

		// Call index 1 was `record_tx_privacy`: removed, never reuse.

		/// Asks front ends to hide or show the account balance.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::set_balance_visibility())]
		pub fn set_balance_visibility(origin: OriginFor<T>, hidden: bool) -> DispatchResult {
			let who = ensure_signed(origin)?;
			HideBalanceAccounts::<T>::insert(&who, hidden);
			Self::deposit_event(Event::BalanceVisibilitySet { who, hidden });
			Ok(())
		}

		/// Links the signer to a shielded public key so revealed senders and
		/// receivers resolve to accounts. Re-registering replaces the previous key.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::register_shielded_key())]
		pub fn register_shielded_key(origin: OriginFor<T>, pk: FieldBytes) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(pk.is_canonical(), Error::<T>::InvalidFieldElement);
			if let Some(owner) = ShieldedKeyOwners::<T>::get(pk) {
				ensure!(owner == who, Error::<T>::ShieldedKeyTaken);
			}
			if let Some(previous) = ShieldedKeys::<T>::get(&who) {
				ShieldedKeyOwners::<T>::remove(previous);
			}
			ShieldedKeys::<T>::insert(&who, pk);
			ShieldedKeyOwners::<T>::insert(pk, &who);
			Self::deposit_event(Event::ShieldedKeyRegistered { who, pk });
			Ok(())
		}

		/// Moves `amount` ARX from the signer into the pool as the given notes.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::shield(outputs.len() as u32))]
		pub fn shield(
			origin: OriginFor<T>,
			amount: BalanceOf<T>,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			let depositor = ensure_signed(origin)?;
			let intent = Intent {
				anchor: None,
				inputs: Inputs::default(),
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				value: ValueFlow::Shield { depositor, amount },
			};
			Self::execute(intent)
		}

		/// Spends notes and pays `amount` ARX from the pool to `recipient`; `outputs` is change.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::unshield(inputs.len() as u32, outputs.len() as u32))]
		pub fn unshield(
			origin: OriginFor<T>,
			recipient: T::AccountId,
			amount: BalanceOf<T>,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			ensure_signed(origin)?;
			let intent = Intent {
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				value: ValueFlow::Unshield { recipient, amount },
			};
			Self::execute(intent)
		}

		/// Spends notes and creates notes inside the pool.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::submit_private_transfer(inputs.len() as u32, outputs.len() as u32))]
		pub fn submit_private_transfer(
			origin: OriginFor<T>,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			ensure_signed(origin)?;
			let intent = Intent {
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				value: ValueFlow::Transfer,
			};
			Self::execute(intent)
		}
	}

	/// Where transparent value goes.
	pub enum ValueFlow<T: Config> {
		/// ARX enters the pool.
		Shield {
			/// Who pays.
			depositor: T::AccountId,
			/// How much, in base units.
			amount: BalanceOf<T>,
		},
		/// ARX leaves the pool.
		Unshield {
			/// Who is paid.
			recipient: T::AccountId,
			/// How much, in base units.
			amount: BalanceOf<T>,
		},
		/// Value stays shielded.
		Transfer,
	}

	/// One bundle, whatever extrinsic produced it.
	pub struct Intent<T: Config> {
		/// Note tree root the spend proofs open to (`None` when nothing is spent).
		pub anchor: Option<FieldBytes>,
		/// Spent notes.
		pub inputs: Inputs,
		/// Created notes.
		pub outputs: Outputs,
		/// Mask.
		pub mask_bits: u8,
		/// Expiry block.
		pub expiry_block: BlockNumberFor<T>,
		/// Proofs.
		pub proofs: ProofBundle,
		/// Transparent value flow.
		pub value: ValueFlow<T>,
	}

	/// Amounts already converted to shielded units.
	pub struct Transparent {
		into_pool: u64,
		out_of_pool: u64,
	}

	impl<T: Config> Pallet<T> {
		/// The pool account.
		pub fn pool_account() -> T::AccountId {
			T::PalletId::get().into_account_truncating()
		}

		/// ARX custodied by the pool, in base units.
		pub fn pool_balance() -> BalanceOf<T> {
			T::Currency::balance(&Self::pool_account())
		}

		/// Registered shielded key of `who`.
		pub fn shielded_key(who: &T::AccountId) -> Option<FieldBytes> {
			ShieldedKeys::<T>::get(who)
		}

		/// Account that registered `pk`.
		pub fn shielded_key_owner(pk: &FieldBytes) -> Option<T::AccountId> {
			ShieldedKeyOwners::<T>::get(pk)
		}

		/// Converts a base-unit amount into shielded units.
		fn to_units(amount: BalanceOf<T>) -> Result<u64, DispatchError> {
			ensure!(!amount.is_zero(), Error::<T>::ZeroAmount);
			let unit = T::ShieldedUnit::get();
			ensure!(!unit.is_zero(), Error::<T>::Overflow);
			ensure!(
				(amount % unit).is_zero(),
				Error::<T>::AmountNotMultipleOfUnit
			);
			let units: u128 = (amount / unit).saturated_into();
			u64::try_from(units).map_err(|_| Error::<T>::AmountTooLarge.into())
		}

		/// Checks the expiry window: `now <= expiry <= now + MaxProofValidity`.
		fn check_expiry(expiry_block: BlockNumberFor<T>) -> DispatchResult {
			let now = frame_system::Pallet::<T>::block_number();
			ensure!(expiry_block >= now, Error::<T>::ProofExpired);
			ensure!(
				expiry_block - now <= T::MaxProofValidity::get(),
				Error::<T>::ExpiryTooFar
			);
			Ok(())
		}

		/// Everything must be a canonical field element.
		fn check_field_elements(intent: &Intent<T>) -> DispatchResult {
			let mut all: Vec<&FieldBytes> = Vec::new();
			if let Some(anchor) = &intent.anchor {
				all.push(anchor);
			}
			for i in intent.inputs.iter() {
				all.extend([&i.nullifier, &i.cv, &i.revealed_sender]);
			}
			for o in intent.outputs.iter() {
				all.extend([&o.cm, &o.cv, &o.revealed_receiver, &o.revealed_amount]);
			}
			ensure!(
				all.into_iter().all(FieldBytes::is_canonical),
				Error::<T>::InvalidFieldElement
			);
			Ok(())
		}

		fn check_shape(intent: &Intent<T>) -> DispatchResult {
			match intent.value {
				ValueFlow::Shield { .. } => {
					ensure!(intent.inputs.is_empty(), Error::<T>::ProofBundleMismatch);
					ensure!(!intent.outputs.is_empty(), Error::<T>::NoOutputs);
				}
				ValueFlow::Unshield { .. } => {
					ensure!(!intent.inputs.is_empty(), Error::<T>::NoInputs)
				}
				ValueFlow::Transfer => {
					ensure!(!intent.inputs.is_empty(), Error::<T>::NoInputs);
					ensure!(!intent.outputs.is_empty(), Error::<T>::NoOutputs);
				}
			}
			let has_inputs = !intent.inputs.is_empty();
			let has_outputs = !intent.outputs.is_empty();
			let has_spend_proof = intent.proofs.spend.is_some();
			let has_output_proof = intent.proofs.output.is_some();
			let has_anchor = intent.anchor.is_some();
			ensure!(
				has_spend_proof == has_inputs,
				Error::<T>::ProofBundleMismatch
			);
			ensure!(
				has_output_proof == has_outputs,
				Error::<T>::ProofBundleMismatch
			);
			ensure!(has_anchor == has_inputs, Error::<T>::ProofBundleMismatch);
			Ok(())
		}

		fn check_notes(intent: &Intent<T>) -> DispatchResult {
			if let Some(anchor) = &intent.anchor {
				ensure!(
					T::Trees::is_known_root(TreeId::Note, anchor),
					Error::<T>::UnknownAnchor
				);
			}
			for (i, input) in intent.inputs.iter().enumerate() {
				ensure!(
					!T::Nullifiers::is_spent(&input.nullifier),
					Error::<T>::NullifierAlreadySpent
				);
				ensure!(
					intent
						.inputs
						.iter()
						.skip(i + 1)
						.all(|other| other.nullifier != input.nullifier),
					Error::<T>::DuplicateNullifier
				);
			}
			for (i, output) in intent.outputs.iter().enumerate() {
				ensure!(
					!T::Trees::contains_leaf(TreeId::Note, &output.cm),
					Error::<T>::DuplicateCommitment
				);
				ensure!(
					intent
						.outputs
						.iter()
						.skip(i + 1)
						.all(|other| other.cm != output.cm),
					Error::<T>::DuplicateCommitment
				);
			}
			Ok(())
		}

		fn transparent(intent: &Intent<T>) -> Result<Transparent, DispatchError> {
			Ok(match &intent.value {
				ValueFlow::Shield { amount, .. } => Transparent {
					into_pool: Self::to_units(*amount)?,
					out_of_pool: 0,
				},
				ValueFlow::Unshield { amount, .. } => Transparent {
					into_pool: 0,
					out_of_pool: Self::to_units(*amount)?,
				},
				ValueFlow::Transfer => Transparent {
					into_pool: 0,
					out_of_pool: 0,
				},
			})
		}

		/// Test-only access to the unit conversion.
		#[cfg(test)]
		pub fn transparent_for_tests(intent: &Intent<T>) -> Transparent {
			Self::transparent(intent).expect("valid amounts")
		}

		/// The digest every proof of the bundle must carry.
		pub fn digest_of(intent: &Intent<T>, transparent: &Transparent) -> FieldBytes {
			let recipient = match &intent.value {
				ValueFlow::Unshield { recipient, .. } => Some(recipient.encode()),
				_ => None,
			};
			let nullifiers: Vec<FieldBytes> = intent.inputs.iter().map(|i| i.nullifier).collect();
			let commitments: Vec<FieldBytes> = intent.outputs.iter().map(|o| o.cm).collect();
			let cv_inputs: Vec<FieldBytes> = intent.inputs.iter().map(|i| i.cv).collect();
			let cv_outputs: Vec<FieldBytes> = intent.outputs.iter().map(|o| o.cv).collect();
			let notes: Vec<&[u8]> = intent
				.outputs
				.iter()
				.map(|o| o.encrypted_note.as_slice())
				.collect();
			bundle_digest(&BundleFields {
				chain_id: CHAIN_ID,
				expiry_block: intent.expiry_block.saturated_into(),
				recipient: recipient.as_deref(),
				transparent_in: transparent.into_pool,
				transparent_out: transparent.out_of_pool,
				fee: 0,
				nullifiers: &nullifiers,
				commitments: &commitments,
				cv_inputs: &cv_inputs,
				cv_outputs: &cv_outputs,
				mask_bits: intent.mask_bits,
				encrypted_notes_hash: encrypted_notes_hash(&notes),
			})
		}

		fn instances<L: PublicInputLayout>(
			layouts: impl Iterator<Item = L>,
		) -> Result<PublicInputs, DispatchError> {
			let mut out = PublicInputs::default();
			for layout in layouts {
				let rows = InstanceRows::try_from(layout.to_elements())
					.map_err(|_| Error::<T>::Overflow)?;
				out.try_push(rows).map_err(|_| Error::<T>::Overflow)?;
			}
			Ok(out)
		}

		fn verify_bundle(
			intent: &Intent<T>,
			transparent: &Transparent,
			digest: FieldBytes,
		) -> DispatchResult {
			let expiry: u32 = intent.expiry_block.saturated_into();
			let mask = intent.mask_bits;

			if let Some(spend) = &intent.proofs.spend {
				let anchor = intent.anchor.ok_or(Error::<T>::ProofBundleMismatch)?;
				let rows = intent.inputs.iter().map(|i| {
					C3PublicInputs::new(
						anchor,
						i.nullifier,
						i.cv,
						mask,
						i.revealed_sender,
						digest,
						expiry,
					)
					.expect("mask validated")
				});
				T::ZkVerifier::verify_proof(
					CircuitId::NullifierDerivation,
					spend,
					&Self::instances(rows)?,
				)?;
			}
			if let Some(output) = &intent.proofs.output {
				let rows = intent.outputs.iter().map(|o| {
					let revealed = RevealedFields {
						sender: FieldBytes::ZERO,
						receiver: o.revealed_receiver,
						amount: o.revealed_amount,
					};
					C1PublicInputs::new(o.cv, o.cm, mask, revealed, digest, expiry)
						.expect("mask validated")
				});
				T::ZkVerifier::verify_proof(
					CircuitId::PrivacyFlagEnforcement,
					output,
					&Self::instances(rows)?,
				)?;
			}
			let dummy = cv_dummy_bytes();
			let mut cv_in = [dummy; C2_INPUTS];
			for (slot, input) in cv_in.iter_mut().zip(intent.inputs.iter()) {
				*slot = input.cv;
			}
			let mut cv_out = [dummy; C2_OUTPUTS];
			for (slot, output) in cv_out.iter_mut().zip(intent.outputs.iter()) {
				*slot = output.cv;
			}
			let balance = C2PublicInputs::new(
				cv_in,
				cv_out,
				transparent.into_pool,
				transparent.out_of_pool,
				0,
				digest,
				expiry,
			);
			T::ZkVerifier::verify_proof(
				CircuitId::BalanceIntegrity,
				&intent.proofs.balance,
				&Self::instances([balance].into_iter())?,
			)
		}

		/// Runs a bundle: every check, then every write.
		pub fn execute(intent: Intent<T>) -> DispatchResult {
			ensure!(is_valid_mask(intent.mask_bits), Error::<T>::InvalidMask);
			Self::check_expiry(intent.expiry_block)?;
			Self::check_field_elements(&intent)?;
			Self::check_shape(&intent)?;
			Self::check_notes(&intent)?;
			let transparent = Self::transparent(&intent)?;
			if let ValueFlow::Unshield { amount, .. } = &intent.value {
				ensure!(
					Self::pool_balance() >= *amount,
					Error::<T>::PoolInsufficient
				);
			}
			let digest = Self::digest_of(&intent, &transparent);
			ensure!(
				!TxPrivacyMask::<T>::contains_key(digest),
				Error::<T>::DuplicateBundle
			);
			Self::verify_bundle(&intent, &transparent, digest)?;

			// Writes. FRAME dispatch is transactional, so an error below still rolls back.
			let mask = PrivacyMask::from_bits(intent.mask_bits);
			for input in intent.inputs.iter() {
				T::Nullifiers::mark_spent(&input.nullifier)?;
				let revealed_sender =
					(!hides_sender(intent.mask_bits)).then_some(input.revealed_sender);
				let sender_account = revealed_sender.and_then(ShieldedKeyOwners::<T>::get);
				Self::deposit_event(Event::NoteSpent {
					bundle_digest: digest,
					nullifier: input.nullifier,
					revealed_sender,
					sender_account,
				});
			}
			for output in intent.outputs.iter() {
				let leaf_index = T::Trees::insert(TreeId::Note, &output.cm)?;
				let revealed_receiver =
					(!hides_receiver(intent.mask_bits)).then_some(output.revealed_receiver);
				let receiver_account = revealed_receiver.and_then(ShieldedKeyOwners::<T>::get);
				let revealed_amount = (!hides_amount(intent.mask_bits))
					.then(|| Self::field_to_u64(&output.revealed_amount));
				Self::deposit_event(Event::NoteCreated {
					bundle_digest: digest,
					leaf_index,
					cm: output.cm,
					revealed_receiver,
					receiver_account,
					revealed_amount,
					encrypted_note: output.encrypted_note.clone(),
				});
			}
			match &intent.value {
				ValueFlow::Shield { depositor, amount } => {
					T::Currency::transfer(
						depositor,
						&Self::pool_account(),
						*amount,
						Preservation::Expendable,
					)?;
					Self::deposit_event(Event::Shielded {
						depositor: depositor.clone(),
						amount: *amount,
						bundle_digest: digest,
					});
				}
				ValueFlow::Unshield { recipient, amount } => {
					T::Currency::transfer(
						&Self::pool_account(),
						recipient,
						*amount,
						Preservation::Expendable,
					)?;
					Self::deposit_event(Event::Unshielded {
						recipient: recipient.clone(),
						amount: *amount,
						bundle_digest: digest,
					});
				}
				ValueFlow::Transfer => {}
			}
			if mask.is_any_private() {
				let count = ShieldedTxCount::<T>::get()
					.checked_add(1)
					.ok_or(Error::<T>::Overflow)?;
				ShieldedTxCount::<T>::put(count);
			}
			TxPrivacyMask::<T>::insert(digest, mask);
			Self::deposit_event(Event::BundleExecuted {
				bundle_digest: digest,
				mask,
				expiry_block: intent.expiry_block,
			});
			Ok(())
		}

		/// Low 8 bytes of a small field element (the circuits range-check revealed amounts to `u64`).
		fn field_to_u64(f: &FieldBytes) -> u64 {
			let mut le = [0u8; 8];
			le.copy_from_slice(&f.0[..8]);
			u64::from_le_bytes(le)
		}
	}
}
