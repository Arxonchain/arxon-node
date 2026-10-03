//! Frozen constants of the Arxon ZK contract (v2).

/// EVM chain id of every Arxon chain spec. Baked into every verifying key and
/// carried as a public input. Never 42 (that is the SS58 prefix, not a chain id).
pub const CHAIN_ID: u64 = 7171;

/// Depth of the note commitment tree (`2^32` notes).
pub const NOTE_TREE_DEPTH: usize = 32;

/// Depth of the trust registry membership tree (`2^16` regulated counterparties;
/// shallower than the note tree so Circuit 6 fits a smaller `K`).
pub const MEMBER_TREE_DEPTH: usize = 16;

/// Hard cap on the size of a single proof, in bytes. Anything larger is rejected
/// before the transcript is touched (DoS bound). The product target per single
/// instance proof is below 5 KB; that target is pinned per circuit in `arxon-zk`.
pub const MAX_PROOF_BYTES: u32 = 8192;

/// Maximum number of instances (input notes for Circuit 3, output notes for
/// Circuit 1) folded into one proof. Equal to Circuit 2's fixed arity: a
/// bundle with more inputs or outputs could never be balanced.
pub const MAX_INSTANCES: u32 = 2;

/// Maximum number of public input rows per instance, for any circuit.
pub const MAX_PUBLIC_INPUTS: u32 = 16;

/// Number of input value commitments consumed by Circuit 2.
pub const C2_INPUTS: usize = 2;

/// Number of output value commitments produced by Circuit 2.
pub const C2_OUTPUTS: usize = 2;

/// Shielded amounts are `u64` multiples of this many ARX base units (18 decimals).
/// 1 ARX = 10^9 shielded units; the total supply (10^9 ARX) fits in `u64`.
pub const SHIELDED_UNIT: u128 = 1_000_000_000;

/// Domain prefix of the bundle digest.
pub const BUNDLE_DOMAIN: &[u8] = b"arxon/bundle/v2";

/// Domain prefix of an ARX-20 bundle digest. Native ARX keeps [`BUNDLE_DOMAIN`]
/// so existing proofs and wallets stay valid. ARX-20 binds the token address
/// in front of the same field encoding, so a proof cannot be replayed onto
/// native ARX or another token.
pub const ARX20_BUNDLE_DOMAIN: &[u8] = b"arxon/arx20-bundle/v1";

/// Pallas base field modulus `p` as 32 little-endian bytes.
/// `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
pub const PALLAS_BASE_MODULUS_LE: [u8; 32] = [
	0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
];

/// Poseidon domain tags. Every Arxon hash of an `L`-word message runs the
/// sponge with initial capacity element `(L << 64) | tag` (see
/// `poseidon::ArxonDomain`), so messages of different purpose or length never
/// share a permutation, and no Arxon domain collides with a plain
/// `ConstantLength<L>` (whose low 64 capacity bits are zero). Tags are never 0.
pub mod tags {
	/// `pk = H(sk)`.
	pub const PK: u64 = 1;
	/// `nk = H(sk)`.
	pub const NK: u64 = 2;
	/// `cm = H(pk, amount, rho)`.
	pub const NOTE: u64 = 3;
	/// `nf = H(nk, cm)`.
	pub const NULLIFIER: u64 = 4;
	/// `ptr_id = H(pk_s, pk_r, cv, nonce)`.
	pub const PTR: u64 = 5;
	/// Note tree node: `H(left, right)`.
	pub const MERKLE_NOTE: u64 = 6;
	/// Membership tree node: `H(left, right)`.
	pub const MERKLE_MEMBER: u64 = 7;
	/// Membership leaf: `H(pk_member)`.
	pub const MEMBER_LEAF: u64 = 8;
	/// Value commitment: `cv = H(amount, blinding)`.
	pub const CV: u64 = 9;
}
