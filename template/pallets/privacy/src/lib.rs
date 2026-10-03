//! # Selective privacy (runtime index 13)
//!
//! The Arxon shielded pool. Users pick, per bundle, which of the four fields to
//! hide or reveal (`PrivacyMask`: sender, receiver, amount, balance). The same
//! mask drives the Halo2 circuits, so a flag is never metadata painted onto an
//! unrelated transaction: every private operation carries proofs that the
//! runtime verifies before it touches state.
//!
//! Three operations move native ARX:
//! * [`Pallet::shield`]: transparent ARX from the signer into the pool, creating notes.
//! * [`Pallet::unshield`]: notes are spent and ARX leaves the pool to a recipient.
//! * [`Pallet::submit_private_transfer`]: notes are spent and new notes created.
//!
//! ARX-20 issued tokens use the same three operations on a **separate** tree and
//! nullifier set per contract ([`Pallet::shield_arx20`], [`Pallet::unshield_arx20`],
//! [`Pallet::submit_private_transfer_arx20`]). Native ARX never moves. Plain
//! ERC-20 has no door here.
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
//! multiples of `ShieldedUnit` base units. `hide_balance` (bit 3) has no
//! meaning in the circuits: it is recorded with the bundle mask, and
//! `HideBalanceAccounts` is a separate opt-in flag set by `set_balance_visibility`.
//!
//! Wire ids: call index 1 (`record_tx_privacy`) is burned; it let anyone paint
//! flags on any hash and is gone.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

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
	/// Records a receipt commitment for the payment output with value commitment
	/// `cv`, paid in `asset` (the pool the bundle ran in).
	fn record(
		ptr_id: FieldBytes,
		cv: FieldBytes,
		mask_bits: u8,
		asset: PrivacyAsset,
	) -> DispatchResult;

	/// Weight of one [`Self::record`], for the bundle weight.
	fn record_weight() -> frame_support::weights::Weight;
}

impl ReceiptSink for () {
	fn record(_: FieldBytes, _: FieldBytes, _: u8, _: PrivacyAsset) -> DispatchResult {
		Ok(())
	}

	fn record_weight() -> frame_support::weights::Weight {
		frame_support::weights::Weight::zero()
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

/// Which pool a bundle writes. Native ARX keeps `TreeId::Note` and the original
/// nullifier map. Each ARX-20 token is isolated.
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
pub enum PrivacyAsset {
	/// Native ARX (`0x801` / existing extrinsics).
	#[codec(index = 0)]
	Native,
	/// Issued ARX-20 contract.
	#[codec(index = 1)]
	Arx20(sp_core::H160),
}

impl PrivacyAsset {
	/// Note tree this asset writes.
	pub const fn tree(self) -> pallet_note_tree::TreeId {
		match self {
			Self::Native => pallet_note_tree::TreeId::Note,
			Self::Arx20(token) => pallet_note_tree::TreeId::Arx20(token),
		}
	}

	/// `None` for native ARX.
	pub const fn token(self) -> Option<sp_core::H160> {
		match self {
			Self::Native => None,
			Self::Arx20(token) => Some(token),
		}
	}

	/// Native ARX pool.
	pub const fn is_native(self) -> bool {
		matches!(self, Self::Native)
	}
}

/// `H160` → runtime `AccountId` via `From` (Arxon `AccountId20`, EVM mock accounts).
pub struct FromH160;

impl<AccountId: From<sp_core::H160>> sp_runtime::traits::Convert<sp_core::H160, AccountId>
	for FromH160
{
	fn convert(token: sp_core::H160) -> AccountId {
		AccountId::from(token)
	}
}

/// Maximum encrypted note payload per output.
pub const MAX_ENCRYPTED_NOTE: u32 = 512;
/// Maximum notes spent or created per bundle (Circuit 2 arity).
pub const MAX_NOTES: u32 = arxon_zk_primitives::MAX_INSTANCES;

// Circuit 2 has exactly `C2_INPUTS` and `C2_OUTPUTS` slots and the pallet fills them from the
// bundle's notes. More notes than slots would drop value commitments from the balance check.
const _: () = assert!(
	MAX_NOTES as usize == arxon_zk_primitives::C2_INPUTS
		&& MAX_NOTES as usize == arxon_zk_primitives::C2_OUTPUTS
);

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
	/// Circuit 4. `Some` iff a receipt is attached.
	pub receipt: Option<arxon_zk_primitives::Proof>,
	/// Circuit 6. `Some` iff a compliance attestation is attached.
	pub compliance: Option<arxon_zk_primitives::Proof>,
}

/// A private transaction receipt attached to one output of the bundle.
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
pub struct PtrAttachment {
	/// Which output is the payment the receipt covers.
	pub payment_output_index: u8,
	/// `H_PTR(pk_s, pk_r, cv, nonce)`, proved by Circuit 4.
	pub ptr_id: FieldBytes,
}

/// A proof that one output pays a regulated counterparty of the trust registry.
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
pub struct ComplianceAttachment {
	/// Which output is paid to the registry member.
	pub output_index: u8,
	/// Membership tree root the Circuit 6 proof was built against. Any recent
	/// root is accepted, so an `add_member` does not invalidate proofs in flight.
	pub registry_root: FieldBytes,
}

/// Fee a relayer earns for submitting a bundle, paid from the pool it spends.
///
/// The amount sits in Circuit 2's `fee` row and both fields are in the bundle
/// digest, so the relayer cannot raise it and nobody can redirect it. Native
/// ARX is paid by the pool account; an ARX-20 fee is minted to `recipient` by
/// the token contract, like any other value leaving that token's pool.
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
pub struct RelayFee<AccountId, Balance> {
	/// Base units; a multiple of the asset's shielded unit.
	pub amount: Balance,
	/// Who is paid, usually the relayer that submits the bundle.
	pub recipient: AccountId,
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
		arx20_bundle_digest, bundle_digest, encrypted_notes_hash,
		mask::{hides_amount, hides_balance, hides_receiver, hides_sender, is_valid_mask},
		poseidon::cv_dummy_bytes,
		BundleFields, C1PublicInputs, C2PublicInputs, C3PublicInputs, C4PublicInputs,
		C6PublicInputs, CircuitId, FieldBytes, InstanceRows, PublicInputLayout, PublicInputs,
		RevealedFields, C2_INPUTS, C2_OUTPUTS, CHAIN_ID,
	};
	use frame_support::{
		pallet_prelude::*,
		traits::{
			fungible::{Inspect, Mutate},
			tokens::Preservation,
			Contains,
		},
		PalletId,
	};
	use frame_system::pallet_prelude::*;
	use pallet_note_tree::{MerkleTree, TreeId};
	use pallet_nullifier_registry::NullifierSet;
	use pallet_zk_verifier::VerifyProof;
	use sp_core::H160;
	use sp_runtime::traits::{AccountIdConversion, Convert, SaturatedConversion, Saturating, Zero};

	use super::{
		weights::WeightInfo, ComplianceAttachment, Inputs, Outputs, PrivacyAsset, PrivacyMask,
		ProofBundle, PtrAttachment, ReceiptSink, RelayFee,
	};

	/// A relayer fee as the calls take it.
	pub type RelayFeeOf<T> = RelayFee<<T as frame_system::Config>::AccountId, BalanceOf<T>>;

	/// Largest token `decimals` accepted by [`Pallet::set_arx20_unit`]: the unit
	/// `10^(decimals - 9)` must fit comfortably in the balance type.
	pub const MAX_ARX20_DECIMALS: u8 = 36;

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
		/// Maps an ARX-20 contract to the account that must sign `*_arx20` calls.
		/// On Arxon this is identity (`AccountId20`); it must match the EVM address mapping.
		type TokenToAccount: Convert<H160, Self::AccountId>;
		/// Addresses that may run an ARX-20 pool: contracts, never an externally
		/// owned account or an EIP-7702 delegated account, whose key holder could
		/// mint notes by signing the pool calls directly.
		type Arx20Tokens: Contains<H160>;
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

	/// Hide-balance flag each account last asked for. It takes effect
	/// `MaxProofValidity` blocks after it changes ([`Pallet::is_balance_hidden`]).
	#[pallet::storage]
	pub type HideBalanceAccounts<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, bool, ValueQuery>;

	/// Block at which an account last changed its hide-balance flag. Until
	/// `MaxProofValidity` blocks have passed the previous value still applies, so
	/// flipping the flag cannot invalidate a bundle a relayer is already submitting.
	#[pallet::storage]
	pub type HideBalanceChangedAt<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, BlockNumberFor<T>>;

	/// Base units per shielded unit of an ARX-20 token, when it set one. Unset
	/// tokens use the native `ShieldedUnit`.
	#[pallet::storage]
	pub type Arx20Unit<T: Config> = StorageMap<_, Blake2_128Concat, H160, BalanceOf<T>>;

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
		/// An account turned hide-balance on or off.
		BalanceVisibilitySet {
			/// The account.
			who: T::AccountId,
			/// `true` = hidden.
			hidden: bool,
			/// First block at which the new value is enforced.
			effective_from: BlockNumberFor<T>,
		},
		/// An account linked a shielded public key.
		ShieldedKeyRegistered {
			/// The account.
			who: T::AccountId,
			/// The key.
			pk: FieldBytes,
		},
		/// Value entered a pool.
		Shielded {
			/// Native ARX or the ARX-20 token.
			asset: PrivacyAsset,
			/// Depositor.
			depositor: T::AccountId,
			/// Amount in base units.
			amount: BalanceOf<T>,
			/// Bundle digest.
			bundle_digest: FieldBytes,
		},
		/// Value left a pool.
		Unshielded {
			/// Native ARX or the ARX-20 token.
			asset: PrivacyAsset,
			/// Recipient.
			recipient: T::AccountId,
			/// Amount in base units.
			amount: BalanceOf<T>,
			/// Bundle digest.
			bundle_digest: FieldBytes,
		},
		/// A bundle executed (any of the three operations).
		BundleExecuted {
			/// Native ARX or the ARX-20 token.
			asset: PrivacyAsset,
			/// Bundle digest (also the key of `TxPrivacyMask`).
			bundle_digest: FieldBytes,
			/// Mask.
			mask: PrivacyMask,
			/// Expiry block the proofs were bound to.
			expiry_block: BlockNumberFor<T>,
		},
		/// One output was proven to pay a trust registry member.
		ComplianceAttested {
			/// Native ARX or the ARX-20 token.
			asset: PrivacyAsset,
			/// Bundle digest.
			bundle_digest: FieldBytes,
			/// Output index.
			output_index: u8,
			/// Membership root the proof opened to.
			membership_root: FieldBytes,
		},
		/// A note was spent.
		NoteSpent {
			/// Native ARX or the ARX-20 token (whose nullifier set it is).
			asset: PrivacyAsset,
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
			/// Native ARX or the ARX-20 token (whose note tree it is).
			asset: PrivacyAsset,
			/// Bundle digest.
			bundle_digest: FieldBytes,
			/// Leaf index in that asset's note tree.
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
		/// A relayer fee left the pool. For native ARX the pool paid it; for an
		/// ARX-20 the token contract mints it to `recipient` after this call.
		FeePaid {
			/// Native ARX or the ARX-20 token.
			asset: PrivacyAsset,
			/// Who is paid.
			recipient: T::AccountId,
			/// Amount in base units.
			amount: BalanceOf<T>,
			/// Bundle digest.
			bundle_digest: FieldBytes,
		},
		/// An ARX-20 token fixed its shielded unit.
		Arx20UnitSet {
			/// The token.
			token: H160,
			/// Base units per shielded unit.
			unit: BalanceOf<T>,
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
		/// A receipt or compliance attachment points past the outputs.
		InvalidOutputIndex,
		/// The compliance attachment's registry root is not a recent membership tree root.
		UnknownRegistryRoot,
		/// Only the ARX-20 contract may submit into its own pool.
		OnlyArx20Token,
		/// Token address is zero.
		ZeroTokenAddress,
		/// A bundle marked hide-balance (mask bit 3) cannot unshield: its value stays notes.
		HideBalanceForbidsUnshield,
		/// The unshield recipient hides its balance: pool value cannot land in its public pocket.
		RecipientHidesBalance,
		/// The account spending (the signer, or the revealed sender) hides its balance.
		SenderHidesBalance,
		/// ARX-20 pools only run at contract addresses (not EOAs or EIP-7702 accounts).
		NotATokenContract,
		/// The token's shielded unit is already set.
		Arx20UnitAlreadySet,
		/// The token's pool already holds notes, so its unit can no longer change.
		Arx20PoolNotEmpty,
		/// `decimals` is above [`MAX_ARX20_DECIMALS`].
		InvalidDecimals,
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

		/// Turns hide-balance on or off for the signer. While on, pool value
		/// cannot be unshielded to the account nor spent by it (as signer or as
		/// revealed sender) into a public pocket. The change is enforced only
		/// `MaxProofValidity` blocks later, so it cannot invalidate a bundle that is
		/// already being relayed.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::set_balance_visibility())]
		pub fn set_balance_visibility(origin: OriginFor<T>, hidden: bool) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let now = frame_system::Pallet::<T>::block_number();
			if HideBalanceAccounts::<T>::get(&who) != hidden {
				HideBalanceAccounts::<T>::insert(&who, hidden);
				HideBalanceChangedAt::<T>::insert(&who, now);
			}
			let effective_from = HideBalanceChangedAt::<T>::get(&who)
				.map(Self::visibility_effective_from)
				.unwrap_or(now);
			Self::deposit_event(Event::BalanceVisibilitySet {
				who,
				hidden,
				effective_from,
			});
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
				asset: PrivacyAsset::Native,
				anchor: None,
				inputs: Inputs::default(),
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr: None,
				compliance: None,
				value: ValueFlow::Shield { depositor, amount },
				fee: None,
				signer: None,
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
			let signer = ensure_signed(origin)?;
			let intent = Intent {
				asset: PrivacyAsset::Native,
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr: None,
				compliance: None,
				value: ValueFlow::Unshield { recipient, amount },
				fee: None,
				signer: Some(signer),
			};
			Self::execute(intent)
		}

		/// Spends notes and creates notes inside the pool, optionally attaching a
		/// receipt (Circuit 4) and a trust registry attestation (Circuit 6).
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::submit_private_transfer(
			inputs.len() as u32,
			outputs.len() as u32,
			ptr.is_some(),
			compliance.is_some()
		))]
		pub fn submit_private_transfer(
			origin: OriginFor<T>,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			ptr: Option<PtrAttachment>,
			compliance: Option<ComplianceAttachment>,
			proofs: ProofBundle,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			let intent = Intent {
				asset: PrivacyAsset::Native,
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr,
				compliance,
				value: ValueFlow::Transfer,
				fee: None,
				signer: Some(signer),
			};
			Self::execute(intent)
		}

		/// Shields `amount` of ARX-20 `token` into that token's tree. Does not
		/// move native ARX; the token contract must burn public balance first.
		/// Signer must be the token account.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::shield(outputs.len() as u32))]
		pub fn shield_arx20(
			origin: OriginFor<T>,
			token: H160,
			amount: BalanceOf<T>,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			let depositor = Self::ensure_arx20_token(origin, token)?;
			let intent = Intent {
				asset: PrivacyAsset::Arx20(token),
				anchor: None,
				inputs: Inputs::default(),
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr: None,
				compliance: None,
				value: ValueFlow::Shield { depositor, amount },
				fee: None,
				signer: None,
			};
			Self::execute(intent)
		}

		/// Unshields ARX-20 `token` notes. Does not pay native ARX; the token
		/// contract must mint after this call succeeds.
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::unshield(inputs.len() as u32, outputs.len() as u32))]
		pub fn unshield_arx20(
			origin: OriginFor<T>,
			token: H160,
			recipient: T::AccountId,
			amount: BalanceOf<T>,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			Self::ensure_arx20_token(origin, token)?;
			let intent = Intent {
				asset: PrivacyAsset::Arx20(token),
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr: None,
				compliance: None,
				value: ValueFlow::Unshield { recipient, amount },
				fee: None,
				signer: None,
			};
			Self::execute(intent)
		}

		/// Private transfer inside one ARX-20 token's pool.
		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::submit_private_transfer(
			inputs.len() as u32,
			outputs.len() as u32,
			ptr.is_some(),
			compliance.is_some()
		))]
		pub fn submit_private_transfer_arx20(
			origin: OriginFor<T>,
			token: H160,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			ptr: Option<PtrAttachment>,
			compliance: Option<ComplianceAttachment>,
			proofs: ProofBundle,
		) -> DispatchResult {
			Self::ensure_arx20_token(origin, token)?;
			let intent = Intent {
				asset: PrivacyAsset::Arx20(token),
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr,
				compliance,
				value: ValueFlow::Transfer,
				fee: None,
				signer: None,
			};
			Self::execute(intent)
		}

		/// [`Pallet::unshield`] submitted by a relayer that is paid `fee` from the pool.
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::unshield(inputs.len() as u32, outputs.len() as u32))]
		pub fn unshield_with_fee(
			origin: OriginFor<T>,
			recipient: T::AccountId,
			amount: BalanceOf<T>,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			fee: RelayFeeOf<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			Self::execute(Intent {
				asset: PrivacyAsset::Native,
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr: None,
				compliance: None,
				value: ValueFlow::Unshield { recipient, amount },
				fee: Some(fee),
				signer: Some(signer),
			})
		}

		/// [`Pallet::submit_private_transfer`] submitted by a relayer that is paid
		/// `fee` from the pool. The sender needs no public balance at all.
		#[pallet::call_index(11)]
		#[pallet::weight(T::WeightInfo::submit_private_transfer(
			inputs.len() as u32,
			outputs.len() as u32,
			ptr.is_some(),
			compliance.is_some()
		))]
		pub fn submit_private_transfer_with_fee(
			origin: OriginFor<T>,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			ptr: Option<PtrAttachment>,
			compliance: Option<ComplianceAttachment>,
			fee: RelayFeeOf<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			let signer = ensure_signed(origin)?;
			Self::execute(Intent {
				asset: PrivacyAsset::Native,
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr,
				compliance,
				value: ValueFlow::Transfer,
				fee: Some(fee),
				signer: Some(signer),
			})
		}

		/// [`Pallet::unshield_arx20`] with a relayer fee the token mints to its recipient.
		#[pallet::call_index(12)]
		#[pallet::weight(T::WeightInfo::unshield(inputs.len() as u32, outputs.len() as u32))]
		pub fn unshield_arx20_with_fee(
			origin: OriginFor<T>,
			token: H160,
			recipient: T::AccountId,
			amount: BalanceOf<T>,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			fee: RelayFeeOf<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			Self::ensure_arx20_token(origin, token)?;
			Self::execute(Intent {
				asset: PrivacyAsset::Arx20(token),
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr: None,
				compliance: None,
				value: ValueFlow::Unshield { recipient, amount },
				fee: Some(fee),
				signer: None,
			})
		}

		/// [`Pallet::submit_private_transfer_arx20`] with a relayer fee the token
		/// mints to its recipient.
		#[pallet::call_index(13)]
		#[pallet::weight(T::WeightInfo::submit_private_transfer(
			inputs.len() as u32,
			outputs.len() as u32,
			ptr.is_some(),
			compliance.is_some()
		))]
		pub fn submit_private_transfer_arx20_with_fee(
			origin: OriginFor<T>,
			token: H160,
			anchor: FieldBytes,
			inputs: Inputs,
			outputs: Outputs,
			mask_bits: u8,
			expiry_block: BlockNumberFor<T>,
			ptr: Option<PtrAttachment>,
			compliance: Option<ComplianceAttachment>,
			fee: RelayFeeOf<T>,
			proofs: ProofBundle,
		) -> DispatchResult {
			Self::ensure_arx20_token(origin, token)?;
			Self::execute(Intent {
				asset: PrivacyAsset::Arx20(token),
				anchor: Some(anchor),
				inputs,
				outputs,
				mask_bits,
				expiry_block,
				proofs,
				ptr,
				compliance,
				value: ValueFlow::Transfer,
				fee: Some(fee),
				signer: None,
			})
		}

		/// Fixes the shielded unit of the signer's ARX-20 pool from its `decimals`:
		/// `10^(decimals - 9)` base units, or 1 for tokens with 9 decimals or
		/// fewer, so amounts up to about 1.8e10 tokens fit the circuits' `u64`.
		/// Allowed once, and only while the pool is empty: notes already in it were
		/// valued with the previous unit. The reference ARX-20 calls it from its
		/// constructor (when its code is not stored yet), so this call does not
		/// require contract code.
		#[pallet::call_index(14)]
		#[pallet::weight(T::WeightInfo::set_arx20_unit())]
		pub fn set_arx20_unit(origin: OriginFor<T>, token: H160, decimals: u8) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!token.is_zero(), Error::<T>::ZeroTokenAddress);
			ensure!(
				who == T::TokenToAccount::convert(token),
				Error::<T>::OnlyArx20Token
			);
			ensure!(decimals <= MAX_ARX20_DECIMALS, Error::<T>::InvalidDecimals);
			ensure!(
				!Arx20Unit::<T>::contains_key(token),
				Error::<T>::Arx20UnitAlreadySet
			);
			ensure!(
				T::Trees::leaf_count(TreeId::Arx20(token)) == 0,
				Error::<T>::Arx20PoolNotEmpty
			);
			let unit: BalanceOf<T> = 10u128
				.checked_pow(u32::from(decimals.saturating_sub(9)))
				.ok_or(Error::<T>::InvalidDecimals)?
				.saturated_into();
			Arx20Unit::<T>::insert(token, unit);
			Self::deposit_event(Event::Arx20UnitSet { token, unit });
			Ok(())
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
		/// Native ARX or one ARX-20 token.
		pub asset: super::PrivacyAsset,
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
		/// Receipt attachment.
		pub ptr: Option<PtrAttachment>,
		/// Trust registry attestation.
		pub compliance: Option<ComplianceAttachment>,
		/// Transparent value flow.
		pub value: ValueFlow<T>,
		/// Relayer fee paid from the pool (unshield and private transfer only).
		pub fee: Option<RelayFeeOf<T>>,
		/// Account that signed a native extrinsic (`None` on the ARX-20 path,
		/// where the signer is the token contract).
		pub signer: Option<T::AccountId>,
	}

	/// Amounts already converted to shielded units.
	pub struct Transparent {
		into_pool: u64,
		out_of_pool: u64,
		fee: u64,
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

		/// Moves `amount` from `from` to `to` when `from` holds at least that much.
		///
		/// `0x801` shield is payable: the EVM credits the precompile, then this
		/// pallet still debits the depositor. Returning the credit avoids a double charge.
		/// Unit tests that only set `apparent_value` skip this because `from` is empty.
		pub fn return_call_value(
			from: T::AccountId,
			to: T::AccountId,
			amount: BalanceOf<T>,
		) -> DispatchResult {
			if T::Currency::balance(&from) < amount {
				return Ok(());
			}
			T::Currency::transfer(&from, &to, amount, Preservation::Expendable).map(|_| ())
		}

		/// Registered shielded key of `who`.
		pub fn shielded_key(who: &T::AccountId) -> Option<FieldBytes> {
			ShieldedKeys::<T>::get(who)
		}

		/// Account that registered `pk`.
		pub fn shielded_key_owner(pk: &FieldBytes) -> Option<T::AccountId> {
			ShieldedKeyOwners::<T>::get(pk)
		}

		/// Signer must be the ARX-20 contract `token`.
		fn ensure_arx20_token(
			origin: OriginFor<T>,
			token: H160,
		) -> Result<T::AccountId, DispatchError> {
			let who = ensure_signed(origin)?;
			ensure!(!token.is_zero(), Error::<T>::ZeroTokenAddress);
			ensure!(
				who == T::TokenToAccount::convert(token),
				Error::<T>::OnlyArx20Token
			);
			ensure!(
				T::Arx20Tokens::contains(&token),
				Error::<T>::NotATokenContract
			);
			Ok(who)
		}

		/// First block at which a hide-balance change made at `changed_at` applies.
		fn visibility_effective_from(changed_at: BlockNumberFor<T>) -> BlockNumberFor<T> {
			changed_at
				.saturating_add(T::MaxProofValidity::get())
				.saturating_add(1u32.into())
		}

		/// `true` iff hide-balance is in force for `who` at the current block: the
		/// value it asked for, or the previous one while a change is still maturing.
		pub fn is_balance_hidden(who: &T::AccountId) -> bool {
			let requested = HideBalanceAccounts::<T>::get(who);
			match HideBalanceChangedAt::<T>::get(who) {
				Some(at)
					if frame_system::Pallet::<T>::block_number()
						< Self::visibility_effective_from(at) =>
				{
					!requested
				}
				_ => requested,
			}
		}

		/// Base units per shielded unit of `asset`.
		pub fn unit_of(asset: PrivacyAsset) -> BalanceOf<T> {
			match asset {
				PrivacyAsset::Native => T::ShieldedUnit::get(),
				PrivacyAsset::Arx20(token) => {
					Arx20Unit::<T>::get(token).unwrap_or_else(T::ShieldedUnit::get)
				}
			}
		}

		/// Hide-balance rules. The spender of a bundle is hidden, so a flag cannot
		/// be tied to it cryptographically; what is enforced is every link the
		/// chain can see: a bundle marked hide-balance never unshields, pool value
		/// never lands in a flagged account, and a flagged account never unshields
		/// as the signer or as a revealed sender (Circuit 3 forces a revealed sender
		/// to be the note owner's key).
		fn check_hide_balance(intent: &Intent<T>) -> DispatchResult {
			let ValueFlow::Unshield { recipient, .. } = &intent.value else {
				return Ok(());
			};
			ensure!(
				!hides_balance(intent.mask_bits),
				Error::<T>::HideBalanceForbidsUnshield
			);
			ensure!(
				!Self::is_balance_hidden(recipient),
				Error::<T>::RecipientHidesBalance
			);
			if let Some(signer) = &intent.signer {
				ensure!(
					!Self::is_balance_hidden(signer),
					Error::<T>::SenderHidesBalance
				);
			}
			if !hides_sender(intent.mask_bits) {
				for input in intent.inputs.iter() {
					if let Some(owner) = ShieldedKeyOwners::<T>::get(input.revealed_sender) {
						ensure!(
							!Self::is_balance_hidden(&owner),
							Error::<T>::SenderHidesBalance
						);
					}
				}
			}
			Ok(())
		}

		/// Converts a base-unit amount of `asset` into shielded units.
		fn to_units(asset: PrivacyAsset, amount: BalanceOf<T>) -> Result<u64, DispatchError> {
			ensure!(!amount.is_zero(), Error::<T>::ZeroAmount);
			let unit = Self::unit_of(asset);
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
			ensure!(
				intent.proofs.receipt.is_some() == intent.ptr.is_some(),
				Error::<T>::ProofBundleMismatch
			);
			ensure!(
				intent.proofs.compliance.is_some() == intent.compliance.is_some(),
				Error::<T>::ProofBundleMismatch
			);
			if let Some(ptr) = &intent.ptr {
				ensure!(
					(ptr.payment_output_index as usize) < intent.outputs.len(),
					Error::<T>::InvalidOutputIndex
				);
				ensure!(ptr.ptr_id.is_canonical(), Error::<T>::InvalidFieldElement);
			}
			if let Some(c) = &intent.compliance {
				ensure!(
					(c.output_index as usize) < intent.outputs.len(),
					Error::<T>::InvalidOutputIndex
				);
				ensure!(
					c.registry_root.is_canonical(),
					Error::<T>::InvalidFieldElement
				);
			}
			Ok(())
		}

		fn check_notes(intent: &Intent<T>) -> DispatchResult {
			let tree = intent.asset.tree();
			if let Some(anchor) = &intent.anchor {
				ensure!(
					T::Trees::is_known_root(tree, anchor),
					Error::<T>::UnknownAnchor
				);
			}
			if let Some(c) = &intent.compliance {
				ensure!(
					T::Trees::is_known_root(TreeId::Membership, &c.registry_root),
					Error::<T>::UnknownRegistryRoot
				);
			}
			let asset = intent.asset.token();
			for (i, input) in intent.inputs.iter().enumerate() {
				ensure!(
					!T::Nullifiers::is_spent_for(asset, &input.nullifier),
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
					!T::Trees::contains_leaf(tree, &output.cm),
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
			let asset = intent.asset;
			let fee = match &intent.fee {
				// A shield is signed by the depositor, who pays its own gas.
				Some(_) if matches!(intent.value, ValueFlow::Shield { .. }) => {
					return Err(Error::<T>::ProofBundleMismatch.into())
				}
				Some(fee) => Self::to_units(asset, fee.amount)?,
				None => 0,
			};
			Ok(match &intent.value {
				ValueFlow::Shield { amount, .. } => Transparent {
					into_pool: Self::to_units(asset, *amount)?,
					out_of_pool: 0,
					fee,
				},
				ValueFlow::Unshield { amount, .. } => Transparent {
					into_pool: 0,
					out_of_pool: Self::to_units(asset, *amount)?,
					fee,
				},
				ValueFlow::Transfer => Transparent {
					into_pool: 0,
					out_of_pool: 0,
					fee,
				},
			})
		}

		/// Test-only access to the unit conversion.
		#[cfg(test)]
		pub fn transparent_for_tests(intent: &Intent<T>) -> Transparent {
			Self::transparent(intent).expect("valid amounts")
		}

		/// The bundle digest a wallet must put into every proof of `intent`.
		/// Same computation `execute` performs; exposed so provers and RPCs agree with the pallet.
		pub fn bundle_digest_for(intent: &Intent<T>) -> Result<FieldBytes, DispatchError> {
			let transparent = Self::transparent(intent)?;
			Ok(Self::digest_of(intent, &transparent))
		}

		/// The digest every proof of the bundle must carry.
		pub fn digest_of(intent: &Intent<T>, transparent: &Transparent) -> FieldBytes {
			let recipient = match &intent.value {
				ValueFlow::Unshield { recipient, .. } => Some(recipient.encode()),
				_ => None,
			};
			let fee_recipient = intent.fee.as_ref().map(|f| f.recipient.encode());
			let nullifiers: Vec<FieldBytes> = intent.inputs.iter().map(|i| i.nullifier).collect();
			let commitments: Vec<FieldBytes> = intent.outputs.iter().map(|o| o.cm).collect();
			let cv_inputs: Vec<FieldBytes> = intent.inputs.iter().map(|i| i.cv).collect();
			let cv_outputs: Vec<FieldBytes> = intent.outputs.iter().map(|o| o.cv).collect();
			let notes: Vec<&[u8]> = intent
				.outputs
				.iter()
				.map(|o| o.encrypted_note.as_slice())
				.collect();
			let fields = BundleFields {
				chain_id: CHAIN_ID,
				expiry_block: intent.expiry_block.saturated_into(),
				recipient: recipient.as_deref(),
				transparent_in: transparent.into_pool,
				transparent_out: transparent.out_of_pool,
				fee: transparent.fee,
				fee_recipient: fee_recipient.as_deref(),
				nullifiers: &nullifiers,
				commitments: &commitments,
				cv_inputs: &cv_inputs,
				cv_outputs: &cv_outputs,
				mask_bits: intent.mask_bits,
				encrypted_notes_hash: encrypted_notes_hash(&notes),
				receipt: intent.ptr.map(|p| (p.payment_output_index, p.ptr_id)),
				compliance: intent.compliance.map(|c| (c.output_index, c.registry_root)),
			};
			match intent.asset.token() {
				None => bundle_digest(&fields),
				Some(token) => arx20_bundle_digest(&token.0, &fields),
			}
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
				transparent.fee,
				digest,
				expiry,
			);
			T::ZkVerifier::verify_proof(
				CircuitId::BalanceIntegrity,
				&intent.proofs.balance,
				&Self::instances([balance].into_iter())?,
			)?;
			if let (Some(ptr), Some(proof)) = (&intent.ptr, &intent.proofs.receipt) {
				// The receipt's sender must own every spent note (both nullifier slots,
				// the first one twice in a one-input bundle) and its receiver the paid note.
				let payment = &intent.outputs[ptr.payment_output_index as usize];
				let first = intent
					.inputs
					.first()
					.ok_or(Error::<T>::ProofBundleMismatch)?;
				let second = intent.inputs.get(1).unwrap_or(first);
				let receipt = C4PublicInputs::new(
					ptr.ptr_id,
					payment.cv,
					payment.cm,
					[first.nullifier, second.nullifier],
					digest,
					expiry,
				);
				T::ZkVerifier::verify_proof(
					CircuitId::PtrGeneration,
					proof,
					&Self::instances([receipt].into_iter())?,
				)?;
			}
			if let (Some(c), Some(proof)) = (&intent.compliance, &intent.proofs.compliance) {
				let paid = &intent.outputs[c.output_index as usize];
				let membership = C6PublicInputs::new(c.registry_root, paid.cm, digest, expiry);
				T::ZkVerifier::verify_proof(
					CircuitId::TrustRegistryMembership,
					proof,
					&Self::instances([membership].into_iter())?,
				)?;
			}
			Ok(())
		}

		/// Runs a bundle: every check, then every write.
		pub fn execute(intent: Intent<T>) -> DispatchResult {
			ensure!(is_valid_mask(intent.mask_bits), Error::<T>::InvalidMask);
			Self::check_expiry(intent.expiry_block)?;
			Self::check_field_elements(&intent)?;
			Self::check_shape(&intent)?;
			Self::check_notes(&intent)?;
			Self::check_hide_balance(&intent)?;
			let transparent = Self::transparent(&intent)?;
			if intent.asset.is_native() {
				let out = match &intent.value {
					ValueFlow::Unshield { amount, .. } => *amount,
					_ => Zero::zero(),
				};
				let fee = intent
					.fee
					.as_ref()
					.map(|f| f.amount)
					.unwrap_or_else(Zero::zero);
				let leaving = out.checked_add(&fee).ok_or(Error::<T>::Overflow)?;
				ensure!(
					Self::pool_balance() >= leaving,
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
			let tree = intent.asset.tree();
			let asset = intent.asset.token();
			for input in intent.inputs.iter() {
				T::Nullifiers::mark_spent_for(asset, &input.nullifier)?;
				let revealed_sender =
					(!hides_sender(intent.mask_bits)).then_some(input.revealed_sender);
				let sender_account = revealed_sender.and_then(ShieldedKeyOwners::<T>::get);
				Self::deposit_event(Event::NoteSpent {
					asset: intent.asset,
					bundle_digest: digest,
					nullifier: input.nullifier,
					revealed_sender,
					sender_account,
				});
			}
			for output in intent.outputs.iter() {
				let leaf_index = T::Trees::insert(tree, &output.cm)?;
				let revealed_receiver =
					(!hides_receiver(intent.mask_bits)).then_some(output.revealed_receiver);
				let receiver_account = revealed_receiver.and_then(ShieldedKeyOwners::<T>::get);
				let revealed_amount = (!hides_amount(intent.mask_bits))
					.then(|| Self::field_to_u64(&output.revealed_amount));
				Self::deposit_event(Event::NoteCreated {
					asset: intent.asset,
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
					if intent.asset.is_native() {
						T::Currency::transfer(
							depositor,
							&Self::pool_account(),
							*amount,
							Preservation::Expendable,
						)?;
					}
					Self::deposit_event(Event::Shielded {
						asset: intent.asset,
						depositor: depositor.clone(),
						amount: *amount,
						bundle_digest: digest,
					});
				}
				ValueFlow::Unshield { recipient, amount } => {
					if intent.asset.is_native() {
						T::Currency::transfer(
							&Self::pool_account(),
							recipient,
							*amount,
							Preservation::Expendable,
						)?;
					}
					Self::deposit_event(Event::Unshielded {
						asset: intent.asset,
						recipient: recipient.clone(),
						amount: *amount,
						bundle_digest: digest,
					});
				}
				ValueFlow::Transfer => {}
			}
			if let Some(fee) = &intent.fee {
				if intent.asset.is_native() {
					T::Currency::transfer(
						&Self::pool_account(),
						&fee.recipient,
						fee.amount,
						Preservation::Expendable,
					)?;
				}
				Self::deposit_event(Event::FeePaid {
					asset: intent.asset,
					recipient: fee.recipient.clone(),
					amount: fee.amount,
					bundle_digest: digest,
				});
			}
			if let Some(ptr) = &intent.ptr {
				let payment = &intent.outputs[ptr.payment_output_index as usize];
				T::Receipts::record(ptr.ptr_id, payment.cv, intent.mask_bits, intent.asset)?;
			}
			if let Some(c) = &intent.compliance {
				Self::deposit_event(Event::ComplianceAttested {
					asset: intent.asset,
					bundle_digest: digest,
					output_index: c.output_index,
					membership_root: c.registry_root,
				});
			}
			if mask.is_any_private() {
				let count = ShieldedTxCount::<T>::get()
					.checked_add(1)
					.ok_or(Error::<T>::Overflow)?;
				ShieldedTxCount::<T>::put(count);
			}
			TxPrivacyMask::<T>::insert(digest, mask);
			Self::deposit_event(Event::BundleExecuted {
				asset: intent.asset,
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
