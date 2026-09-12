//! Unit tests. One behaviour per test, Arrange / Act / Assert, no branching.

mod bundle;
mod circuit_id;
mod field_bytes;
mod mask;
#[cfg(feature = "poseidon")]
mod poseidon;
mod public_inputs;
