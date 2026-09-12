//! One behaviour per test. Keys are ML-DSA-65 derived from fixed seeds, so every
//! signature is deterministic and the suite needs no randomness.

use codec::Encode;
use frame_support::{assert_noop, assert_ok, BoundedVec};
use ml_dsa::{signature::Verifier, Keypair, MlDsa65, Seed, SigningKey};
use sp_runtime::{traits::Dispatchable, DispatchError};

use crate::{
	mock::{
		new_test_ext, QuantumAccount, RuntimeCall, RuntimeEvent, RuntimeOrigin, System, Test,
		QUANTUM, RELAYER,
	},
	verify_mldsa65, Error, Event, QuantumAccountCount, QuantumKeys, QuantumNonces,
	ARXON_QUANTUM_DOMAIN, MLDSA65_PK_LEN, MLDSA65_SIG_LEN,
};

fn signing_key(seed_byte: u8) -> SigningKey<MlDsa65> {
	SigningKey::<MlDsa65>::from_seed(&Seed::from([seed_byte; 32]))
}

fn public_key_bytes(
	sk: &SigningKey<MlDsa65>,
) -> BoundedVec<u8, frame_support::traits::ConstU32<MLDSA65_PK_LEN>> {
	BoundedVec::truncate_from(sk.verifying_key().encode().to_vec())
}

/// `remark_with_event` emits `Remarked { sender }`, which proves the inner call ran as `QUANTUM`.
fn remark() -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::remark_with_event {
		remark: vec![1, 2, 3],
	})
}

/// `set_code` needs root; dispatched as `Signed(QUANTUM)` it fails with `BadOrigin`.
fn failing_inner_call() -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::set_code { code: vec![0] })
}

/// `domain || SCALE(nonce) || SCALE(call)`, exactly what the pallet reconstructs.
fn message(nonce: u64, call: &RuntimeCall) -> Vec<u8> {
	let mut m = ARXON_QUANTUM_DOMAIN.to_vec();
	m.extend(nonce.encode());
	m.extend(call.encode());
	m
}

fn sign(
	sk: &SigningKey<MlDsa65>,
	nonce: u64,
	call: &RuntimeCall,
) -> BoundedVec<u8, frame_support::traits::ConstU32<MLDSA65_SIG_LEN>> {
	let sig = sk
		.expanded_key()
		.sign_deterministic(&message(nonce, call), b"")
		.expect("signing succeeds");
	BoundedVec::truncate_from(sig.encode().to_vec())
}

fn register(sk: &SigningKey<MlDsa65>) {
	assert_ok!(QuantumAccount::register_quantum_key(
		RuntimeOrigin::signed(QUANTUM),
		public_key_bytes(sk)
	));
}

fn dispatch(
	nonce: u64,
	call: RuntimeCall,
	sig: BoundedVec<u8, frame_support::traits::ConstU32<MLDSA65_SIG_LEN>>,
) -> sp_runtime::DispatchResult {
	RuntimeCall::QuantumAccount(crate::Call::quantum_dispatch {
		quantum_signer: QUANTUM,
		nonce,
		call: Box::new(call),
		signature: sig,
	})
	.dispatch(RuntimeOrigin::signed(RELAYER))
	.map(|_| ())
	.map_err(|e| e.error)
}

// --- key sizes and the verifier ----------------------------------------------------------------

#[test]
fn ml_dsa_65_key_and_signature_have_the_documented_sizes() {
	let sk = signing_key(1);

	assert_eq!(sk.verifying_key().encode().len(), MLDSA65_PK_LEN as usize);
	assert_eq!(sign(&sk, 0, &remark()).len(), MLDSA65_SIG_LEN as usize);
}

#[test]
fn verify_mldsa65_accepts_a_valid_signature_and_rejects_a_flipped_bit() {
	let sk = signing_key(1);
	let msg = message(0, &remark());
	let pk = sk.verifying_key().encode();
	let sig = sk
		.expanded_key()
		.sign_deterministic(&msg, b"")
		.unwrap()
		.encode();
	assert!(sk
		.verifying_key()
		.verify(
			&msg,
			&sk.expanded_key().sign_deterministic(&msg, b"").unwrap()
		)
		.is_ok());

	assert!(verify_mldsa65(&pk, &msg, &sig));
	let mut bad = sig.to_vec();
	bad[10] ^= 1;
	assert!(!verify_mldsa65(&pk, &msg, &bad));
}

#[test]
fn verify_mldsa65_rejects_wrong_lengths() {
	let sk = signing_key(1);
	let msg = message(0, &remark());
	let pk = sk.verifying_key().encode();
	let sig = sk
		.expanded_key()
		.sign_deterministic(&msg, b"")
		.unwrap()
		.encode();

	assert!(!verify_mldsa65(&pk[..100], &msg, &sig));
	assert!(!verify_mldsa65(&pk, &msg, &sig[..100]));
}

// --- register / deregister --------------------------------------------------------------------

#[test]
fn register_quantum_key_stores_key_and_increments_count() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);

		register(&sk);

		assert_eq!(
			QuantumKeys::<Test>::get(QUANTUM).map(|k| k.into_inner()),
			Some(sk.verifying_key().encode().to_vec())
		);
		assert_eq!(QuantumAccountCount::<Test>::get(), 1);
		assert!(QuantumAccount::is_quantum_account(&QUANTUM));
		System::assert_last_event(RuntimeEvent::QuantumAccount(Event::QuantumKeyRegistered {
			who: QUANTUM,
		}));
	});
}

#[test]
fn register_quantum_key_fails_when_already_registered() {
	new_test_ext().execute_with(|| {
		register(&signing_key(1));

		assert_noop!(
			QuantumAccount::register_quantum_key(
				RuntimeOrigin::signed(QUANTUM),
				public_key_bytes(&signing_key(2))
			),
			Error::<Test>::KeyAlreadyRegistered
		);
	});
}

#[test]
fn register_quantum_key_fails_for_wrong_length() {
	new_test_ext().execute_with(|| {
		let short = BoundedVec::truncate_from(vec![7u8; 100]);

		assert_noop!(
			QuantumAccount::register_quantum_key(RuntimeOrigin::signed(QUANTUM), short),
			Error::<Test>::InvalidPublicKey
		);
	});
}

#[test]
fn deregister_quantum_key_removes_key_and_emits_event() {
	new_test_ext().execute_with(|| {
		register(&signing_key(1));

		assert_ok!(QuantumAccount::deregister_quantum_key(
			RuntimeOrigin::signed(QUANTUM)
		));

		assert!(!QuantumAccount::is_quantum_account(&QUANTUM));
		assert_eq!(QuantumAccountCount::<Test>::get(), 0);
		System::assert_last_event(RuntimeEvent::QuantumAccount(
			Event::QuantumKeyDeregistered { who: QUANTUM },
		));
	});
}

#[test]
fn deregister_quantum_key_fails_without_key() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			QuantumAccount::deregister_quantum_key(RuntimeOrigin::signed(QUANTUM)),
			Error::<Test>::NoQuantumKey
		);
	});
}

// --- quantum_dispatch --------------------------------------------------------------------------

#[test]
fn quantum_dispatch_runs_inner_call_as_signer_and_bumps_nonce() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);

		assert_ok!(dispatch(0, remark(), sign(&sk, 0, &remark())));

		assert_eq!(QuantumNonces::<Test>::get(QUANTUM), 1);
		System::assert_has_event(RuntimeEvent::System(frame_system::Event::Remarked {
			sender: QUANTUM,
			hash: sp_io::hashing::blake2_256(&[1, 2, 3]).into(),
		}));
		System::assert_has_event(RuntimeEvent::QuantumAccount(
			Event::QuantumDispatchSuccess {
				who: QUANTUM,
				nonce: 0,
			},
		));
	});
}

#[test]
fn quantum_dispatch_fails_when_signer_has_no_key() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);

		assert_noop!(
			dispatch(0, remark(), sign(&sk, 0, &remark())),
			Error::<Test>::NoQuantumKey
		);
	});
}

#[test]
fn quantum_dispatch_fails_with_invalid_nonce() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);

		assert_noop!(
			dispatch(1, remark(), sign(&sk, 1, &remark())),
			Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn quantum_dispatch_fails_with_signature_from_another_key() {
	new_test_ext().execute_with(|| {
		register(&signing_key(1));
		let other = signing_key(2);

		assert_noop!(
			dispatch(0, remark(), sign(&other, 0, &remark())),
			Error::<Test>::InvalidSignature
		);
	});
}

#[test]
fn quantum_dispatch_fails_when_signature_covers_a_different_call() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);
		let other_call = RuntimeCall::System(frame_system::Call::remark { remark: vec![9] });

		assert_noop!(
			dispatch(0, remark(), sign(&sk, 0, &other_call)),
			Error::<Test>::InvalidSignature
		);
	});
}

#[test]
fn quantum_dispatch_fails_with_short_signature() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);

		assert_noop!(
			dispatch(0, remark(), BoundedVec::truncate_from(vec![0u8; 100])),
			Error::<Test>::InvalidSignature
		);
	});
}

#[test]
fn quantum_dispatch_replay_after_success_fails_with_invalid_nonce() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);
		let sig = sign(&sk, 0, &remark());
		assert_ok!(dispatch(0, remark(), sig.clone()));

		assert_noop!(dispatch(0, remark(), sig), Error::<Test>::InvalidNonce);
	});
}

#[test]
fn quantum_dispatch_rolls_back_nonce_when_inner_call_fails() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);
		let call = failing_inner_call();

		let result = dispatch(0, call.clone(), sign(&sk, 0, &call));

		assert_eq!(result, Err(DispatchError::BadOrigin));
		assert_eq!(
			QuantumNonces::<Test>::get(QUANTUM),
			0,
			"nonce rolled back with the failed extrinsic"
		);
	});
}

#[test]
fn same_signature_can_be_retried_after_an_inner_failure() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);
		let call = failing_inner_call();
		let sig = sign(&sk, 0, &call);
		assert!(dispatch(0, call.clone(), sig.clone()).is_err());

		// Still nonce 0: the very same signature is accepted again (and fails again for the same reason).
		assert_eq!(dispatch(0, call, sig), Err(DispatchError::BadOrigin));
		assert_eq!(QuantumNonces::<Test>::get(QUANTUM), 0);
	});
}

#[test]
fn nonces_advance_independently_per_call() {
	new_test_ext().execute_with(|| {
		let sk = signing_key(1);
		register(&sk);

		assert_ok!(dispatch(0, remark(), sign(&sk, 0, &remark())));
		assert_ok!(dispatch(1, remark(), sign(&sk, 1, &remark())));

		assert_eq!(QuantumNonces::<Test>::get(QUANTUM), 2);
	});
}
