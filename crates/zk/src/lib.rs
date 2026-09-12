//! Arxon Halo2 circuits over the Pasta curves with the IPA commitment scheme.
//!
//! This crate is `std` only: proving and verification happen natively (the
//! runtime reaches [`verifier::verify_by_id`] through the `verify_halo2_ipa`
//! host function). Everything the runtime must agree on (circuit ids, public
//! input layouts, field encoding, tagged Poseidon) lives in `arxon-zk-primitives`.
//!
//! Layout:
//! * [`circuit`]: the [`circuit::ArxonCircuit`] trait every circuit implements.
//! * [`circuits`]: the six Arxon circuits plus the dummy harness circuit.
//! * [`prover`] / [`verifier`]: multi-instance proof creation and verification.
//! * [`key_cache`]: lazily built, process-wide proving and verifying keys.
//! * [`pins`]: verifying key hashes and proof sizes pinned for regression.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod circuit;
pub mod circuits;
pub mod error;
pub mod field;
pub mod gadgets;
pub mod key_cache;
pub mod merkle;
pub mod params;
pub mod pins;
pub mod prover;
pub mod verifier;
pub mod wallet;

#[cfg(test)]
pub(crate) mod test_support;

pub use arxon_zk_primitives as primitives;
pub use error::{ProveError, VerifyError};
pub use field::{Curve, Fp};
pub use prover::prove;
pub use verifier::{verify, verify_by_id};
