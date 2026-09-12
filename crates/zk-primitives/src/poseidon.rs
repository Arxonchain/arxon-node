//! Tagged Poseidon hashing over the Pallas base field (native, `no_std`).
//!
//! Every Arxon hash of an `L`-word message is a Poseidon sponge
//! (`P128Pow5T3`: width 3, rate 2, 8 full and 56 partial rounds, alpha 5,
//! the parameters fixed by the engineer briefing) whose initial capacity
//! element is `(L << 64) | tag` ([`ArxonDomain`]). The tag lives in the
//! capacity, not in the message, so a two-word hash still costs a single
//! permutation; a depth-32 Merkle path is 32 permutations, not 64.
//!
//! `halo2_poseidon` only exposes hashing for `ConstantLength<L>` natively
//! (its sponge is crate-private), so the permutation is ported here from its
//! public [`Spec`] constants. Tests prove the port equals upstream for the
//! plain domain and the in-circuit gadget (`arxon-zk`) equals this native
//! code for every Arxon domain.

use alloc::{format, string::String, vec::Vec};
use core::iter;

use ff::{Field, PrimeField};
use halo2_poseidon::{Domain, Mds, P128Pow5T3, Spec};

use crate::{constants::tags, field_bytes::FieldBytes};

/// The Pallas base field (the field every Arxon circuit is arithmetised over).
pub type Fp = pasta_curves::pallas::Base;

/// Sponge width.
pub const WIDTH: usize = 3;
/// Sponge rate.
pub const RATE: usize = 2;

/// Arxon Poseidon domain: `L`-word messages under `TAG`.
///
/// Implements `halo2_poseidon::Domain`, which is also what the in-circuit
/// sponge of `halo2_gadgets` is generic over, so both sides share this type.
#[derive(Clone, Copy, Debug)]
pub struct ArxonDomain<const TAG: u64, const L: usize>;

impl<F: PrimeField, const R: usize, const TAG: u64, const L: usize> Domain<F, R>
	for ArxonDomain<TAG, L>
{
	type Padding = iter::RepeatN<F>;

	fn name() -> String {
		format!("ArxonDomain<{TAG}, {L}>")
	}

	fn initial_capacity_element() -> F {
		F::from_u128(((L as u128) << 64) | TAG as u128)
	}

	fn padding(input_len: usize) -> Self::Padding {
		assert_eq!(
			input_len, L,
			"ArxonDomain<{TAG}, {L}> hashes exactly {L} words"
		);
		let words = L.div_ceil(R) * R;
		iter::repeat_n(F::ZERO, words - L)
	}
}

/// Decodes a canonical field element; `None` for non-canonical bytes.
pub fn fp_from_bytes(bytes: &FieldBytes) -> Option<Fp> {
	Option::from(Fp::from_repr(bytes.0))
}

/// Encodes a field element (`Fp::to_repr`, little endian).
pub fn fp_to_bytes(f: &Fp) -> FieldBytes {
	FieldBytes(f.to_repr())
}

/// The Poseidon permutation of `P128Pow5T3` over `Fp`, ported from `halo2_poseidon`.
pub fn permute(state: &mut [Fp; WIDTH]) {
	let (round_constants, mds, _) = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::constants();
	let r_f = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::full_rounds() / 2;
	let r_p = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::partial_rounds();
	let mut rounds = round_constants.iter();
	for _ in 0..r_f {
		full_round(state, rounds.next().expect("round constants"), &mds);
	}
	for _ in 0..r_p {
		partial_round(state, rounds.next().expect("round constants"), &mds);
	}
	for _ in 0..r_f {
		full_round(state, rounds.next().expect("round constants"), &mds);
	}
}

fn apply_mds(state: &mut [Fp; WIDTH], mds: &Mds<Fp, WIDTH>) {
	let mut out = [Fp::ZERO; WIDTH];
	for (i, row) in mds.iter().enumerate() {
		for (j, m) in row.iter().enumerate() {
			out[i] += *m * state[j];
		}
	}
	*state = out;
}

fn full_round(state: &mut [Fp; WIDTH], rcs: &[Fp; WIDTH], mds: &Mds<Fp, WIDTH>) {
	for (word, rc) in state.iter_mut().zip(rcs.iter()) {
		*word = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::sbox(*word + rc);
	}
	apply_mds(state, mds);
}

fn partial_round(state: &mut [Fp; WIDTH], rcs: &[Fp; WIDTH], mds: &Mds<Fp, WIDTH>) {
	for (word, rc) in state.iter_mut().zip(rcs.iter()) {
		*word += rc;
	}
	state[0] = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::sbox(state[0]);
	apply_mds(state, mds);
}

/// Sponge hash of `message` under `D`, output length one.
///
/// Same schedule as `halo2_poseidon::Hash`: absorb the padded message in
/// `RATE`-word chunks (one permutation per chunk) and squeeze the first rate word.
pub fn sponge_hash<D: Domain<Fp, RATE>>(message: &[Fp]) -> Fp {
	let mut state = [Fp::ZERO, Fp::ZERO, D::initial_capacity_element()];
	let padded: Vec<Fp> = message
		.iter()
		.copied()
		.chain(D::padding(message.len()))
		.collect();
	debug_assert_eq!(padded.len() % RATE, 0, "domain padding must fill the rate");
	for chunk in padded.chunks(RATE) {
		for (word, value) in state.iter_mut().zip(chunk.iter()) {
			*word += value;
		}
		permute(&mut state);
	}
	state[0]
}

/// Arxon hash of an `L`-word message under `TAG`.
pub fn hash_domain<const TAG: u64, const L: usize>(message: [Fp; L]) -> Fp {
	sponge_hash::<ArxonDomain<TAG, L>>(&message)
}

/// `pk = H_PK(sk)`.
pub fn hash_pk(sk: Fp) -> Fp {
	hash_domain::<{ tags::PK }, 1>([sk])
}

/// `nk = H_NK(sk)`.
pub fn hash_nk(sk: Fp) -> Fp {
	hash_domain::<{ tags::NK }, 1>([sk])
}

/// `cm = H_NOTE(pk, amount, rho)`.
pub fn hash_note(pk: Fp, amount: u64, rho: Fp) -> Fp {
	hash_domain::<{ tags::NOTE }, 3>([pk, Fp::from(amount), rho])
}

/// `nf = H_NF(nk, cm)`.
pub fn hash_nullifier(nk: Fp, cm: Fp) -> Fp {
	hash_domain::<{ tags::NULLIFIER }, 2>([nk, cm])
}

/// `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`.
pub fn hash_ptr(pk_s: Fp, pk_r: Fp, cv: Fp, nonce: Fp) -> Fp {
	hash_domain::<{ tags::PTR }, 4>([pk_s, pk_r, cv, nonce])
}

/// Note tree node hash.
pub fn hash_merkle_note(left: Fp, right: Fp) -> Fp {
	hash_domain::<{ tags::MERKLE_NOTE }, 2>([left, right])
}

/// Membership tree node hash.
pub fn hash_merkle_member(left: Fp, right: Fp) -> Fp {
	hash_domain::<{ tags::MERKLE_MEMBER }, 2>([left, right])
}

/// Membership tree leaf `H_MEMBER(pk_member)`.
pub fn hash_member_leaf(pk_member: Fp) -> Fp {
	hash_domain::<{ tags::MEMBER_LEAF }, 1>([pk_member])
}

/// Value commitment `cv = H_CV(amount, blinding)`.
pub fn hash_cv(amount: u64, blinding: Fp) -> Fp {
	hash_domain::<{ tags::CV }, 2>([Fp::from(amount), blinding])
}

/// The canonical dummy value commitment `H_CV(0, 0)` used for unused Circuit 2 slots.
pub fn cv_dummy() -> Fp {
	hash_cv(0, Fp::ZERO)
}

/// Which Merkle tree a node hash belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleDomain {
	/// The note commitment tree (tag [`tags::MERKLE_NOTE`]).
	Note,
	/// The trust registry membership tree (tag [`tags::MERKLE_MEMBER`]).
	Member,
}

/// Byte-level node hash for the runtime: `None` if either input is not canonical.
pub fn hash_two_bytes(
	domain: MerkleDomain,
	left: &FieldBytes,
	right: &FieldBytes,
) -> Option<FieldBytes> {
	let l = fp_from_bytes(left)?;
	let r = fp_from_bytes(right)?;
	let out = match domain {
		MerkleDomain::Note => hash_merkle_note(l, r),
		MerkleDomain::Member => hash_merkle_member(l, r),
	};
	Some(fp_to_bytes(&out))
}
