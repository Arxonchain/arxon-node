//! Process-wide verifying and proving keys, built once per circuit type.
//!
//! Key generation is deterministic (it depends only on the parameters and the
//! circuit's `configure`), so every node derives identical keys. Concurrent
//! first callers of the same circuit wait on one `OnceLock` instead of each
//! running keygen.
//!
//! Verifying and proving keys are cached separately: a node only verifies, so
//! it never pays for (or holds in memory) the proving keys. Every verifying key
//! is hashed on build and compared with the frozen `arxon_zk_primitives::VK_HASHES`;
//! a node whose circuits drifted from the pinned ones refuses every proof
//! instead of silently accepting a different statement than its peers.

use std::{
	any::TypeId,
	collections::HashMap,
	sync::{Arc, Mutex, OnceLock},
};

use arxon_zk_primitives::CircuitId;
use halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey};
use sp_crypto_hashing::blake2_256;

use crate::{circuit::ArxonCircuit, field::Curve, params::params};

/// Verifying key of one circuit and whether it matches the frozen hash.
pub struct VerifierKey {
	/// Verifying key.
	pub vk: VerifyingKey<Curve>,
	/// `blake2_256` of the `Debug` rendering of `vk.pinned()`.
	pub hash: [u8; 32],
	/// `true` iff `hash` equals the frozen hash of this circuit (always `true`
	/// for harness circuits without a chain id).
	pub matches_pin: bool,
}

type Slot<K> = Arc<OnceLock<Arc<K>>>;
type Slots<K> = Mutex<HashMap<TypeId, Slot<K>>>;

fn verifier_slots() -> &'static Slots<VerifierKey> {
	static SLOTS: OnceLock<Slots<VerifierKey>> = OnceLock::new();
	SLOTS.get_or_init(Default::default)
}

fn prover_slots() -> &'static Slots<ProvingKey<Curve>> {
	static SLOTS: OnceLock<Slots<ProvingKey<Curve>>> = OnceLock::new();
	SLOTS.get_or_init(Default::default)
}

/// The slot of `C`, created empty on first sight. The map lock is held only
/// for the lookup, never during key generation.
fn slot_for<C: 'static, K>(slots: &Slots<K>) -> Slot<K> {
	Arc::clone(
		slots
			.lock()
			.expect("key cache poisoned")
			.entry(TypeId::of::<C>())
			.or_default(),
	)
}

fn build_vk<C: ArxonCircuit + 'static>() -> Arc<VerifierKey> {
	let vk = keygen_vk(params(C::K), &C::default())
		.expect("keygen_vk cannot fail for a well-formed circuit");
	let hash = blake2_256(format!("{:?}", vk.pinned()).as_bytes());
	let matches_pin = C::ID.is_none_or(|id| hash == arxon_zk_primitives::vk_hash(id));
	Arc::new(VerifierKey {
		vk,
		hash,
		matches_pin,
	})
}

fn build_pk<C: ArxonCircuit + 'static>() -> Arc<ProvingKey<Curve>> {
	let vk = verifier_key::<C>().vk.clone();
	Arc::new(
		keygen_pk(params(C::K), vk, &C::default())
			.expect("keygen_pk cannot fail for a well-formed circuit"),
	)
}

/// Verifying key of circuit `C`, built on first use; every caller gets the same `Arc`.
pub fn verifier_key<C: ArxonCircuit + 'static>() -> Arc<VerifierKey> {
	Arc::clone(slot_for::<C, _>(verifier_slots()).get_or_init(build_vk::<C>))
}

/// Proving key of circuit `C`, built on first use (wallets and tests only).
pub fn proving_key<C: ArxonCircuit + 'static>() -> Arc<ProvingKey<Curve>> {
	Arc::clone(slot_for::<C, _>(prover_slots()).get_or_init(build_pk::<C>))
}

/// Number of circuit types whose verifying keys are built.
pub fn cached_count() -> usize {
	verifier_slots()
		.lock()
		.expect("key cache poisoned")
		.values()
		.filter(|s| s.get().is_some())
		.count()
}

/// Builds the verifying key of every wired chain circuit ahead of time and
/// returns the circuits whose key does not match its frozen hash.
pub fn warm_up() -> Result<(), Vec<CircuitId>> {
	let mut drifted = Vec::new();
	crate::circuits::for_each_chain_circuit!(|C| {
		if !verifier_key::<C>().matches_pin {
			drifted.push(C::ID.expect("chain circuit"));
		}
	});
	if drifted.is_empty() {
		Ok(())
	} else {
		Err(drifted)
	}
}
