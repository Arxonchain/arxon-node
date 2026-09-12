//! Wire types for proofs and public inputs.

use bounded_collections::{BoundedVec, ConstU32};

use crate::{
	constants::{MAX_INSTANCES, MAX_PROOF_BYTES, MAX_PUBLIC_INPUTS},
	field_bytes::FieldBytes,
};

/// A serialized Halo2 IPA proof. Bounded by [`MAX_PROOF_BYTES`]; the exact
/// length per circuit and instance count is pinned in `arxon-zk` and checked
/// before the transcript is read (trailing bytes would otherwise be ignored).
pub type Proof = BoundedVec<u8, ConstU32<MAX_PROOF_BYTES>>;

/// Public input rows of one instance, in the circuit's frozen order.
pub type InstanceRows = BoundedVec<FieldBytes, ConstU32<MAX_PUBLIC_INPUTS>>;

/// Public inputs of one proof: one row vector per instance.
pub type PublicInputs = BoundedVec<InstanceRows, ConstU32<MAX_INSTANCES>>;
