//! Process-wide proving and verifying keys, built once per circuit type.
//!
//! Key generation is deterministic (it depends only on the parameters and the
//! circuit's `configure`), so every node derives identical keys. The first
//! call for a circuit pays keygen (seconds at K=12); nodes call [`warm_up`]
//! at start-up so the first block does not.

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

fn cache() -> &'static Mutex<HashMap<TypeId, Arc<CircuitKeys>>> {
	static CACHE: OnceLock<Mutex<HashMap<TypeId, Arc<CircuitKeys>>>> = OnceLock::new();
	CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn build<C: ArxonCircuit + 'static>() -> CircuitKeys {
	let params = params(C::K);
	let empty = C::default();
	let vk = keygen_vk(params, &empty).expect("keygen_vk cannot fail for a well-formed circuit");
	let pk = keygen_pk(params, vk.clone(), &empty)
		.expect("keygen_pk cannot fail for a well-formed circuit");
	CircuitKeys { vk, pk }
}

/// Keys of circuit `C`, built on first use.
pub fn keys<C: ArxonCircuit + 'static>() -> Arc<CircuitKeys> {
	let id = TypeId::of::<C>();
	if let Some(k) = cache().lock().expect("key cache poisoned").get(&id) {
		return Arc::clone(k);
	}
	// Build outside the lock: keygen is slow and other circuits must not wait.
	let built = Arc::new(build::<C>());
	let mut guard = cache().lock().expect("key cache poisoned");
	Arc::clone(guard.entry(id).or_insert(built))
}

/// Builds the keys of every chain circuit ahead of time.
pub fn warm_up() {
	crate::circuits::for_each_chain_circuit!(|C| {
		let _ = keys::<C>();
	});
}
