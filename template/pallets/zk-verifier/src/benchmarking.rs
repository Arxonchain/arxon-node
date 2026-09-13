//! Benchmarks: one per circuit, verifying committed proof fixtures through the
//! configured backend (the `verify_halo2_ipa` host function in the runtime).
//! Fixtures live in `fixtures/` and are regenerated with
//! `cargo run --release -p arxon-zk --example gen_verifier_fixtures`; the
//! `arxon-zk-host` test `verifier_benchmark_fixtures_still_verify` guards them.

use arxon_zk_primitives::{CircuitId, Proof, PublicInputs};
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use scale_codec::Decode;

use super::*;

macro_rules! fixture {
	($name:literal) => {
		(
			&include_bytes!(concat!(
				env!("CARGO_MANIFEST_DIR"),
				"/fixtures/",
				$name,
				".proof"
			))[..],
			&include_bytes!(concat!(
				env!("CARGO_MANIFEST_DIR"),
				"/fixtures/",
				$name,
				".inputs"
			))[..],
		)
	};
}

fn load(bytes: (&[u8], &[u8])) -> (Proof, PublicInputs) {
	let proof = Proof::try_from(bytes.0.to_vec()).expect("fixture proof within the cap");
	let mut input = bytes.1;
	let inputs = PublicInputs::decode(&mut input).expect("fixture public inputs decode");
	(proof, inputs)
}

/// One untimed verification so the backend's key cache is warm (the first
/// verification of a circuit in a process builds its verifying key).
fn warm<T: Config>(id: CircuitId, proof: &Proof, inputs: &PublicInputs) {
	let _ = <Pallet<T> as VerifyProof>::check_proof(id, proof, inputs);
}

fn run<T: Config>(id: CircuitId, bytes: (&[u8], &[u8])) -> (Proof, PublicInputs) {
	let (proof, inputs) = load(bytes);
	warm::<T>(id, &proof, &inputs);
	(proof, inputs)
}

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn set_circuit_enabled() {
		let id = CircuitId::PrivacyFlagEnforcement;
		assert!(Circuits::<T>::get(id).map(|c| c.enabled).unwrap_or(false));

		#[extrinsic_call]
		_(RawOrigin::Root, id, false);

		assert!(!Circuits::<T>::get(id).expect("registered").enabled);
	}

	#[benchmark]
	fn verify_privacy_flag_enforcement(n: Linear<1, 2>) {
		let id = CircuitId::PrivacyFlagEnforcement;
		let bytes = if n == 1 {
			fixture!("c1_1")
		} else {
			fixture!("c1_2")
		};
		let (proof, inputs) = run::<T>(id, bytes);

		#[block]
		{
			<Pallet<T> as VerifyProof>::verify_proof(id, &proof, &inputs)
				.expect("fixture verifies");
		}
	}

	#[benchmark]
	fn verify_balance_integrity() {
		let id = CircuitId::BalanceIntegrity;
		let (proof, inputs) = run::<T>(id, fixture!("c2"));

		#[block]
		{
			<Pallet<T> as VerifyProof>::verify_proof(id, &proof, &inputs)
				.expect("fixture verifies");
		}
	}

	#[benchmark]
	fn verify_nullifier_derivation(n: Linear<1, 2>) {
		let id = CircuitId::NullifierDerivation;
		let bytes = if n == 1 {
			fixture!("c3_1")
		} else {
			fixture!("c3_2")
		};
		let (proof, inputs) = run::<T>(id, bytes);

		#[block]
		{
			<Pallet<T> as VerifyProof>::verify_proof(id, &proof, &inputs)
				.expect("fixture verifies");
		}
	}

	#[benchmark]
	fn verify_ptr_generation() {
		let id = CircuitId::PtrGeneration;
		let (proof, inputs) = run::<T>(id, fixture!("c4"));

		#[block]
		{
			<Pallet<T> as VerifyProof>::verify_proof(id, &proof, &inputs)
				.expect("fixture verifies");
		}
	}

	#[benchmark]
	fn verify_disclosure_proof() {
		let id = CircuitId::DisclosureProof;
		let (proof, inputs) = run::<T>(id, fixture!("c5"));

		#[block]
		{
			<Pallet<T> as VerifyProof>::verify_proof(id, &proof, &inputs)
				.expect("fixture verifies");
		}
	}

	#[benchmark]
	fn verify_trust_registry_membership() {
		let id = CircuitId::TrustRegistryMembership;
		let (proof, inputs) = run::<T>(id, fixture!("c6"));

		#[block]
		{
			<Pallet<T> as VerifyProof>::verify_proof(id, &proof, &inputs)
				.expect("fixture verifies");
		}
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
