//! Field and curve aliases.

pub use arxon_zk_primitives::poseidon::{fp_from_bytes, fp_to_bytes, Fp};
use arxon_zk_primitives::FieldBytes;

use crate::error::VerifyError;

/// Commitment curve. Circuits are arithmetised over its scalar field, which is
/// the Pallas base field [`Fp`] ("Pallas prove, Vesta recurse").
pub type Curve = pasta_curves::vesta::Affine;

/// Decodes one instance's rows, rejecting non-canonical bytes with the offending position.
pub fn rows_from_bytes(instance: usize, rows: &[FieldBytes]) -> Result<Vec<Fp>, VerifyError> {
	rows.iter()
		.enumerate()
		.map(|(row, bytes)| {
			fp_from_bytes(bytes).ok_or(VerifyError::NonCanonicalPublicInput { instance, row })
		})
		.collect()
}
