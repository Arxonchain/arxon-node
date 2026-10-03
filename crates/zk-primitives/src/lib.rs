//! Arxon ZK primitives.
//!
//! This crate is the single source of truth for everything the Halo2 circuits
//! (`arxon-zk`, std) and the runtime (`no_std`, Wasm) must agree on:
//!
//! * [`CircuitId`]: the six circuits of the Arxon selective privacy design.
//! * [`FieldBytes`]: canonical little-endian encoding of a Pallas base field element.
//! * [`public_inputs`]: the frozen public input layout of every circuit.
//! * [`bundle`]: the transaction binding digest carried by every proof.
//! * [`mask`]: the frozen four-flag packing shared with `pallet-privacy`.
//! * [`poseidon`] (feature `poseidon`): tagged Poseidon hashing over Pallas.
//!
//! Nothing here depends on `halo2_proofs`, so the crate builds for `wasm32v1-none`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bundle;
pub mod circuit_id;
pub mod constants;
pub mod field_bytes;
pub mod mask;
#[cfg(feature = "poseidon")]
pub mod poseidon;
pub mod proof;
pub mod public_inputs;
pub mod vk_hashes;

pub use bundle::{
	arx20_bundle_digest, bundle_digest, digest_to_field, encrypted_notes_hash, BundleFields,
};
pub use circuit_id::CircuitId;
pub use constants::*;
pub use field_bytes::FieldBytes;
pub use proof::{InstanceRows, Proof, PublicInputs};
pub use public_inputs::{
	C1PublicInputs, C2PublicInputs, C3PublicInputs, C4PublicInputs, C5PublicInputs, C6PublicInputs,
	PublicInputLayout, RevealedFields,
};
pub use vk_hashes::{vk_hash, VK_HASHES};

#[cfg(test)]
mod tests;
