//! # ZK verifier (runtime index 18)
//!
//! Registry of the six Arxon circuits (enabled flag and pinned verifying key
//! hash) and the [`VerifyProof`] service the privacy pallets and the EVM
//! precompile call. Verification itself happens natively through the
//! `verify_halo2_ipa` host function ([`HostVerifier`]); tests inject a
//! [`ProofVerifier`] fake so no pallet test needs halo2.
//!
//! Verifying key hashes are set at genesis from the frozen constants and are
//! not mutable by any call: the node can only verify against the circuits it
//! was built with, so a changed hash could only make a circuit unverifiable.
//! Governance can disable a circuit (kill switch) and re-enable it.

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

use arxon_zk_primitives::{CircuitId, Proof, PublicInputs};
use frame_support::pallet_prelude::*;
use scale_codec::Encode;

/// Backend that verifies proofs. The runtime wires [`HostVerifier`].
pub trait ProofVerifier {
	/// `true` iff `proof` verifies for `circuit_id` under the verifying key hashed as `vk_hash`.
	fn verify(
		circuit_id: CircuitId,
		vk_hash: &[u8; 32],
		proof: &[u8],
		public_inputs: &PublicInputs,
	) -> bool;
}

/// Production backend: the `verify_halo2_ipa` host function.
pub struct HostVerifier;

impl ProofVerifier for HostVerifier {
	fn verify(
		circuit_id: CircuitId,
		vk_hash: &[u8; 32],
		proof: &[u8],
		public_inputs: &PublicInputs,
	) -> bool {
		arxon_zk_host::zk_verify::verify_halo2_ipa(
			circuit_id.as_u8(),
			*vk_hash,
			proof,
			&public_inputs.encode(),
		)
	}
}

/// Backend that rejects everything (safe default for mocks).
pub struct AlwaysReject;

impl ProofVerifier for AlwaysReject {
	fn verify(_: CircuitId, _: &[u8; 32], _: &[u8], _: &PublicInputs) -> bool {
		false
	}
}

/// Proof verification as seen by the consuming pallets.
pub trait VerifyProof {
	/// Verifies one proof (one or more instances) of `circuit_id` and counts it.
	fn verify_proof(
		circuit_id: CircuitId,
		proof: &Proof,
		public_inputs: &PublicInputs,
	) -> DispatchResult;

	/// Same checks as [`Self::verify_proof`] without writing anything (for `view` callers).
	fn check_proof(
		circuit_id: CircuitId,
		proof: &Proof,
		public_inputs: &PublicInputs,
	) -> DispatchResult;

	/// Weight of verifying `instances` instances of `circuit_id`, for consumers' weight functions.
	fn verify_weight(circuit_id: CircuitId, instances: u32) -> Weight;
}

#[frame_support::pallet]
pub mod pallet {
	use alloc::vec::Vec;

	use arxon_zk_primitives::{vk_hash, CircuitId, Proof, PublicInputs};
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	use super::{weights::WeightInfo, ProofVerifier, VerifyProof};

	/// Registry entry of one circuit.
	#[derive(
		Clone,
		Copy,
		Debug,
		PartialEq,
		Eq,
		Encode,
		Decode,
		DecodeWithMemTracking,
		TypeInfo,
		MaxEncodedLen
	)]
	pub struct CircuitConfig {
		/// Whether proofs of this circuit are accepted.
		pub enabled: bool,
		/// Pinned verifying key hash handed to the verifier backend.
		pub vk_hash: [u8; 32],
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Verification backend.
		type Verifier: ProofVerifier;
		/// Origin allowed to enable and disable circuits.
		type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
		/// Weights.
		type WeightInfo: WeightInfo;
	}

	/// Registered circuits.
	#[pallet::storage]
	pub type Circuits<T: Config> =
		StorageMap<_, Twox64Concat, CircuitId, CircuitConfig, OptionQuery>;

	/// Number of proofs verified successfully.
	#[pallet::storage]
	pub type VerificationCount<T: Config> = StorageValue<_, u64, ValueQuery>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		/// Circuits to register: `(wire id, vk_hash, enabled)`. Unknown ids are ignored.
		pub circuits: Vec<(u8, [u8; 32], bool)>,
		#[serde(skip)]
		pub _phantom: PhantomData<T>,
	}

	impl<T: Config> Default for GenesisConfig<T> {
		/// Every circuit, with its frozen verifying key hash, enabled.
		fn default() -> Self {
			GenesisConfig {
				circuits: CircuitId::ALL
					.iter()
					.map(|id| (id.as_u8(), vk_hash(*id), true))
					.collect(),
				_phantom: PhantomData,
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			for (wire_id, hash, enabled) in &self.circuits {
				if let Ok(id) = CircuitId::try_from(*wire_id) {
					Circuits::<T>::insert(
						id,
						CircuitConfig {
							enabled: *enabled,
							vk_hash: *hash,
						},
					);
				}
			}
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A circuit was enabled or disabled.
		CircuitEnabledSet {
			/// The circuit.
			circuit_id: CircuitId,
			/// New state.
			enabled: bool,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The circuit is not in the registry.
		CircuitNotRegistered,
		/// The circuit is disabled.
		CircuitDisabled,
		/// A proof needs at least one instance.
		NoInstances,
		/// More instances than the circuit folds into one proof.
		TooManyInstances,
		/// An instance has the wrong number of public input rows.
		WrongRowCount,
		/// The backend rejected the proof.
		InvalidProof,
		/// The success counter overflowed.
		Overflow,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Enables or disables a registered circuit (kill switch).
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_circuit_enabled())]
		pub fn set_circuit_enabled(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			enabled: bool,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			Circuits::<T>::try_mutate(circuit_id, |entry| -> DispatchResult {
				let config = entry.as_mut().ok_or(Error::<T>::CircuitNotRegistered)?;
				config.enabled = enabled;
				Ok(())
			})?;
			Self::deposit_event(Event::CircuitEnabledSet {
				circuit_id,
				enabled,
			});
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Registry entry of `circuit_id`.
		pub fn circuit(circuit_id: CircuitId) -> Option<CircuitConfig> {
			Circuits::<T>::get(circuit_id)
		}

		/// Weight of verifying `instances` instances of `circuit_id` (for consumers' weight functions).
		pub fn verify_weight(circuit_id: CircuitId, instances: u32) -> Weight {
			match circuit_id {
				CircuitId::PrivacyFlagEnforcement => {
					T::WeightInfo::verify_privacy_flag_enforcement(instances)
				}
				CircuitId::BalanceIntegrity => T::WeightInfo::verify_balance_integrity(),
				CircuitId::NullifierDerivation => {
					T::WeightInfo::verify_nullifier_derivation(instances)
				}
				CircuitId::PtrGeneration => T::WeightInfo::verify_ptr_generation(),
				CircuitId::DisclosureProof => T::WeightInfo::verify_disclosure_proof(),
				CircuitId::TrustRegistryMembership => {
					T::WeightInfo::verify_trust_registry_membership()
				}
			}
		}

		fn check_shape(circuit_id: CircuitId, public_inputs: &PublicInputs) -> DispatchResult {
			ensure!(!public_inputs.is_empty(), Error::<T>::NoInstances);
			ensure!(
				public_inputs.len() <= circuit_id.max_instances() as usize,
				Error::<T>::TooManyInstances
			);
			let rows = circuit_id.public_input_len();
			ensure!(
				public_inputs.iter().all(|instance| instance.len() == rows),
				Error::<T>::WrongRowCount
			);
			Ok(())
		}
	}

	impl<T: Config> VerifyProof for Pallet<T> {
		fn verify_proof(
			circuit_id: CircuitId,
			proof: &Proof,
			public_inputs: &PublicInputs,
		) -> DispatchResult {
			Self::check_proof(circuit_id, proof, public_inputs)?;
			let count = VerificationCount::<T>::get()
				.checked_add(1)
				.ok_or(Error::<T>::Overflow)?;
			VerificationCount::<T>::put(count);
			Ok(())
		}

		fn verify_weight(circuit_id: CircuitId, instances: u32) -> Weight {
			Pallet::<T>::verify_weight(circuit_id, instances)
		}

		fn check_proof(
			circuit_id: CircuitId,
			proof: &Proof,
			public_inputs: &PublicInputs,
		) -> DispatchResult {
			let config = Circuits::<T>::get(circuit_id).ok_or(Error::<T>::CircuitNotRegistered)?;
			ensure!(config.enabled, Error::<T>::CircuitDisabled);
			Self::check_shape(circuit_id, public_inputs)?;
			ensure!(
				T::Verifier::verify(circuit_id, &config.vk_hash, proof.as_slice(), public_inputs),
				Error::<T>::InvalidProof
			);
			Ok(())
		}
	}
}
