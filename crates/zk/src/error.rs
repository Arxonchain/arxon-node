//! Error types.

use halo2_proofs::plonk;

/// Proving failed.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
	/// No witness was supplied.
	#[error("a proof needs at least one instance")]
	NoInstances,
	/// More witnesses than the circuit folds into one proof.
	#[error("circuit accepts at most {max} instances, got {got}")]
	TooManyInstances {
		/// Allowed maximum.
		max: u32,
		/// Supplied count.
		got: usize,
	},
	/// The produced proof exceeds the hard cap of the on-chain contract.
	#[error("proof of {len} bytes exceeds MAX_PROOF_BYTES ({max})")]
	ProofTooLarge {
		/// Produced length.
		len: usize,
		/// Hard cap.
		max: u32,
	},
	/// halo2 refused to prove (unsatisfied witness, synthesis error).
	#[error("halo2 proving error: {0}")]
	Halo2(#[from] plonk::Error),
}

/// Verification failed. Every variant is a rejection; none is recoverable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
	/// Wire circuit id is not one of the six.
	#[error("unknown circuit id {0}")]
	UnknownCircuit(u8),
	/// No instance supplied.
	#[error("a proof carries at least one instance")]
	NoInstances,
	/// More instances than the circuit folds into one proof.
	#[error("circuit accepts at most {max} instances, got {got}")]
	TooManyInstances {
		/// Allowed maximum.
		max: u32,
		/// Supplied count.
		got: usize,
	},
	/// An instance has the wrong number of rows.
	#[error("instance {instance} has {got} public input rows, expected {expected}")]
	WrongRowCount {
		/// Instance position.
		instance: usize,
		/// Rows required by the layout.
		expected: usize,
		/// Rows supplied.
		got: usize,
	},
	/// A public input byte string is not a canonical field element.
	#[error("public input {row} of instance {instance} is not a canonical field element")]
	NonCanonicalPublicInput {
		/// Instance position.
		instance: usize,
		/// Row position.
		row: usize,
	},
	/// The proof length differs from the pinned length for this circuit and instance count.
	/// Checked before the transcript is read, because halo2 ignores trailing bytes.
	#[error("proof has {got} bytes, expected exactly {expected}")]
	WrongProofLength {
		/// Pinned length.
		expected: usize,
		/// Supplied length.
		got: usize,
	},
	/// The proof does not verify.
	#[error("invalid proof")]
	InvalidProof,
	/// This build's verifying key differs from the frozen hash: the node refuses
	/// every proof of the circuit rather than verify a different statement.
	#[error("verifying key does not match its frozen hash")]
	KeyMismatch,
}
