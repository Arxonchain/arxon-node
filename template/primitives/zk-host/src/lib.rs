//! # `verify_halo2_ipa` host function
//!
//! `halo2_proofs` is `std` only and IPA verification is linear in the circuit
//! size, so the runtime never verifies in Wasm: it calls this host function,
//! which the node registers in its executor (`template/node/src/service.rs`).
//!
//! Contract (frozen, versioned `#[version(1)]`):
//! * `circuit_id`: wire id, see `arxon_zk_primitives::CircuitId`.
//! * `vk_hash`: the verifying key hash the runtime pinned at genesis. It must
//!   equal the frozen `arxon_zk_primitives::vk_hash(id)`; a node built with a
//!   different circuit refuses to verify rather than silently accepting.
//! * `proof`: raw proof bytes, at most `MAX_PROOF_BYTES`.
//! * `public_inputs`: SCALE `Vec<Vec<[u8; 32]>>`, one row vector per instance.
//! * returns `true` iff the proof verifies. Every failure, malformed input,
//!   or internal panic yields `false`: a panic in a host function would abort
//!   the node, so the std body is wrapped in `catch_unwind`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// The `runtime_interface` macro refers to `Vec` in the code it generates.
#[allow(unused_imports)]
use alloc::vec::Vec;

// Host side. The `runtime_interface` macro emits the function bodies only when
// `substrate_runtime` is not set (the wasm-builder sets it for runtime builds),
// so this module follows the same cfg, exactly as `sp-io` does.
#[cfg(not(substrate_runtime))]
mod native;

#[cfg(all(not(substrate_runtime), not(feature = "std")))]
compile_error!("arxon-zk-host: host-side builds need the `std` feature; runtime builds set `--cfg substrate_runtime`");

#[cfg(test)]
mod tests;

use sp_runtime_interface::{
	pass_by::{PassFatPointerAndRead, PassPointerAndReadCopy},
	runtime_interface,
};

/// The host interface.
#[runtime_interface]
pub trait ZkVerify {
	/// Verifies a Halo2 IPA proof for `circuit_id`. See the crate docs for the contract.
	#[version(1)]
	fn verify_halo2_ipa(
		circuit_id: u8,
		vk_hash: PassPointerAndReadCopy<[u8; 32], 32>,
		proof: PassFatPointerAndRead<&[u8]>,
		public_inputs: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		native::verify_guarded(circuit_id, &vk_hash, proof, public_inputs)
	}
}

/// Host functions the node executor must register.
#[cfg(not(substrate_runtime))]
pub type HostFunctions = zk_verify::HostFunctions;
