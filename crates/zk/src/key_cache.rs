//! Process-wide proving and verifying keys, built once per circuit type.
//!
//! Key generation is deterministic (it depends only on the parameters and the
//! circuit's `configure`), so every node derives identical keys. Concurrent
//! first callers of the same circuit wait on one `OnceLock` instead of each
//! running keygen. The first call for a circuit still pays keygen (seconds at
//! K=12); nodes call [`warm_up`] at start-up so the first block does not.

use std::{
	any::TypeId,
	collections::HashMap,
	sync::{Arc, Mutex, OnceLock},
};

use halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey};

use crate::{circuit::ArxonCircuit, field::Curve, params::params};

/// Proving and verifying key of one circuit.
pub struct CircuitKeys {
	/// Verifying key.
	pub vk: VerifyingKey<Curve>,
	/// Proving key (contains a copy of the verifying key).
	pub pk: ProvingKey<Curve>,
}

type Slot = Arc<OnceLock<Arc<CircuitKeys>>>;

fn slots() -> &'static Mutex<HashMap<TypeId, Slot>> {
	static SLOTS: OnceLock<Mutex<HashMap<TypeId, Slot>>> = OnceLock::new();
	SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The slot of `C`, created empty on first sight. The map lock is held only
/// for the lookup, never during key generation.
fn slot_for<C: 'static>() -> Slot {
	Arc::clone(
		slots()
			.lock()
			.expect("key cache poisoned")
			.entry(TypeId::of::<C>())
			.or_default(),
	)
}

fn build<C: ArxonCircuit + 'static>() -> Arc<CircuitKeys> {
	let params = params(C::K);
	let empty = C::default();
	let vk = keygen_vk(params, &empty).expect("keygen_vk cannot fail for a well-formed circuit");
	let pk = keygen_pk(params, vk.clone(), &empty)
		.expect("keygen_pk cannot fail for a well-formed circuit");
	Arc::new(CircuitKeys { vk, pk })
}

/// Keys of circuit `C`, built on first use; every caller gets the same `Arc`.
pub fn keys<C: ArxonCircuit + 'static>() -> Arc<CircuitKeys> {
	Arc::clone(slot_for::<C>().get_or_init(build::<C>))
}

/// Number of circuit types whose keys are built.
pub fn cached_count() -> usize {
	slots()
		.lock()
		.expect("key cache poisoned")
		.values()
		.filter(|s| s.get().is_some())
		.count()
}

/// Builds the keys of every wired chain circuit ahead of time.
pub fn warm_up() {
	crate::circuits::for_each_chain_circuit!(|C| {
		let _ = keys::<C>();
	});
}
