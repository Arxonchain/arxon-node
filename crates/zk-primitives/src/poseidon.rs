//! Tagged Poseidon hashing over the Pallas base field (native, `no_std`).
//!
//! Every Arxon hash is `Poseidon<P128Pow5T3, ConstantLength<L + 1>>(tag, m_1, ..., m_L)`.
//! The in-circuit gadget (`arxon-zk`) absorbs exactly the same array, so native
//! and circuit digests agree by construction; `arxon-zk` tests assert it per tag.
//!
//! `P128Pow5T3` is width 3, rate 2, 8 full and 56 partial rounds, alpha 5:
//! the parameters fixed by the engineer briefing.

use ff::{Field, PrimeField};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};

use crate::{constants::tags, field_bytes::FieldBytes};

/// The Pallas base field (the field every Arxon circuit is arithmetised over).
pub type Fp = pasta_curves::pallas::Base;

/// Decodes a canonical field element; `None` for non-canonical bytes.
pub fn fp_from_bytes(bytes: &FieldBytes) -> Option<Fp> {
	Option::from(Fp::from_repr(bytes.0))
}

/// Encodes a field element (`Fp::to_repr`, little endian).
pub fn fp_to_bytes(f: &Fp) -> FieldBytes {
	FieldBytes(f.to_repr())
}

fn hash_l2(tag: u64, a: Fp) -> Fp {
	Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([Fp::from(tag), a])
}

fn hash_l3(tag: u64, a: Fp, b: Fp) -> Fp {
	Hash::<Fp, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([Fp::from(tag), a, b])
}

fn hash_l4(tag: u64, a: Fp, b: Fp, c: Fp) -> Fp {
	Hash::<Fp, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([Fp::from(tag), a, b, c])
}

fn hash_l5(tag: u64, a: Fp, b: Fp, c: Fp, d: Fp) -> Fp {
	Hash::<Fp, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([Fp::from(tag), a, b, c, d])
}

/// `pk = H_PK(sk)`.
pub fn hash_pk(sk: Fp) -> Fp {
	hash_l2(tags::PK, sk)
}

/// `nk = H_NK(sk)`.
pub fn hash_nk(sk: Fp) -> Fp {
	hash_l2(tags::NK, sk)
}

/// `cm = H_NOTE(pk, amount, rho)`.
pub fn hash_note(pk: Fp, amount: u64, rho: Fp) -> Fp {
	hash_l4(tags::NOTE, pk, Fp::from(amount), rho)
}

/// `nf = H_NF(nk, cm)`.
pub fn hash_nullifier(nk: Fp, cm: Fp) -> Fp {
	hash_l3(tags::NULLIFIER, nk, cm)
}

/// `ptr_id = H_PTR(pk_s, pk_r, cv, nonce)`.
pub fn hash_ptr(pk_s: Fp, pk_r: Fp, cv: Fp, nonce: Fp) -> Fp {
	hash_l5(tags::PTR, pk_s, pk_r, cv, nonce)
}

/// Note tree node hash.
pub fn hash_merkle_note(left: Fp, right: Fp) -> Fp {
	hash_l3(tags::MERKLE_NOTE, left, right)
}

/// Membership tree node hash.
pub fn hash_merkle_member(left: Fp, right: Fp) -> Fp {
	hash_l3(tags::MERKLE_MEMBER, left, right)
}

/// Membership tree leaf `H_MEMBER(pk_member)`.
pub fn hash_member_leaf(pk_member: Fp) -> Fp {
	hash_l2(tags::MEMBER_LEAF, pk_member)
}

/// Value commitment `cv = H_CV(amount, blinding)`.
pub fn hash_cv(amount: u64, blinding: Fp) -> Fp {
	hash_l3(tags::CV, Fp::from(amount), blinding)
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
