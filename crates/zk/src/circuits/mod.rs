//! The Arxon circuits.
//!
//! [`for_each_chain_circuit!`] and [`dispatch_chain_circuit!`] enumerate the
//! circuits that reach the chain; they grow as circuits land (plan Phase A5).

pub mod c0_dummy;

/// Runs `$body` once per chain circuit type, binding it to `$c`.
/// No chain circuit is implemented yet, so this expands to nothing.
#[macro_export]
macro_rules! for_each_chain_circuit {
	(|$c:ident| $body:block) => {{}};
}

/// Evaluates `$body` with `$c` bound to the circuit type of `$id`.
/// Every id errors until its circuit lands.
#[macro_export]
macro_rules! dispatch_chain_circuit {
	($id:expr, |$c:ident| $body:expr) => {{
		let id: ::arxon_zk_primitives::CircuitId = $id;
		Err($crate::error::VerifyError::UnknownCircuit(id.as_u8()))
	}};
}

pub use dispatch_chain_circuit;
pub use for_each_chain_circuit;
