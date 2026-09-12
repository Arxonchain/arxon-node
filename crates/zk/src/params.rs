//! IPA public parameters, generated once per circuit size.
//!
//! `Params::new(k)` is deterministic (hash-to-curve generators, no trusted
//! setup), so every node derives identical parameters.

use std::sync::OnceLock;

use halo2_proofs::poly::commitment::Params;

use crate::field::Curve;

/// Largest circuit size any Arxon circuit may use.
pub const MAX_K: u32 = 13;

static PARAMS: [OnceLock<Params<Curve>>; (MAX_K + 1) as usize] =
	[const { OnceLock::new() }; (MAX_K + 1) as usize];

/// Parameters for a circuit of `2^k` rows. Built on first use, shared afterwards.
///
/// # Panics
/// If `k > MAX_K`; circuit sizes are compile-time constants, so this is a programming error.
pub fn params(k: u32) -> &'static Params<Curve> {
	assert!(k <= MAX_K, "circuit size k={k} exceeds MAX_K={MAX_K}");
	PARAMS[k as usize].get_or_init(|| Params::new(k))
}
