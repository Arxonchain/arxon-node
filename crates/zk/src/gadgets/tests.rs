//! Gadget tests: each gadget under MockProver through a minimal harness circuit.

use arxon_zk_primitives::{constants::tags, poseidon as native};
use ff::Field;
use halo2_proofs::{
	circuit::{Layouter, SimpleFloorPlanner, Value},
	dev::MockProver,
	plonk::{Circuit, ConstraintSystem, Error},
};
use proptest::prelude::*;

use super::{
	binding,
	mask::MaskConfig,
	merkle::{MerkleConfig, PathWitness},
	poseidon::PoseidonConfig,
	range64::Range64Config,
	reveal::RevealConfig,
	SharedColumns,
};
use crate::{
	field::Fp,
	merkle::{ReferenceTree, TreeKind},
	test_support::*,
};

// --- Poseidon ----------------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct PoseidonHarness {
	tag: u64,
	msg: Vec<Value<Fp>>,
}

#[derive(Clone, Debug)]
struct PoseidonHarnessConfig {
	shared: SharedColumns,
	poseidon: PoseidonConfig,
}

impl Circuit<Fp> for PoseidonHarness {
	type Config = PoseidonHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		PoseidonHarness {
			tag: self.tag,
			msg: vec![Value::unknown(); self.msg.len()],
		}
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		let shared = SharedColumns::configure(meta);
		let poseidon = PoseidonConfig::configure(meta, &shared);
		PoseidonHarnessConfig { shared, poseidon }
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		let cells: Vec<_> = self
			.msg
			.iter()
			.map(|m| binding::witness(&mut layouter, cfg.shared.advices[5], "m", *m))
			.collect::<Result<_, _>>()?;
		let out = match cells.as_slice() {
			[a] => cfg
				.poseidon
				.hash_tagged_1(layouter.namespace(|| "h"), self.tag, a.clone())?,
			[a, b] => cfg.poseidon.hash_tagged_2(
				layouter.namespace(|| "h"),
				self.tag,
				a.clone(),
				b.clone(),
			)?,
			[a, b, c] => cfg.poseidon.hash_tagged_3(
				layouter.namespace(|| "h"),
				self.tag,
				a.clone(),
				b.clone(),
				c.clone(),
			)?,
			[a, b, c, d] => cfg.poseidon.hash_tagged_4(
				layouter.namespace(|| "h"),
				self.tag,
				a.clone(),
				b.clone(),
				c.clone(),
				d.clone(),
			)?,
			_ => unreachable!("harness supports 1 to 4 message words"),
		};
		binding::expose(&mut layouter, &out, cfg.shared.instance, 0)
	}
}

fn poseidon_prover(tag: u64, msg: &[Fp], expected: Fp) -> MockProver<Fp> {
	let circuit = PoseidonHarness {
		tag,
		msg: msg.iter().map(|m| Value::known(*m)).collect(),
	};
	MockProver::run(7, &circuit, vec![vec![expected]]).unwrap()
}

#[test]
fn circuit_hash_matches_native_hash_for_each_tag_and_length() {
	let sk = Fp::from(7);
	let cases: Vec<(u64, Vec<Fp>, Fp)> = vec![
		(tags::PK, vec![sk], native::hash_pk(sk)),
		(tags::NK, vec![sk], native::hash_nk(sk)),
		(tags::MEMBER_LEAF, vec![sk], native::hash_member_leaf(sk)),
		(
			tags::NULLIFIER,
			vec![Fp::from(1), Fp::from(2)],
			native::hash_nullifier(Fp::from(1), Fp::from(2)),
		),
		(
			tags::MERKLE_NOTE,
			vec![Fp::from(1), Fp::from(2)],
			native::hash_merkle_note(Fp::from(1), Fp::from(2)),
		),
		(
			tags::MERKLE_MEMBER,
			vec![Fp::from(1), Fp::from(2)],
			native::hash_merkle_member(Fp::from(1), Fp::from(2)),
		),
		(
			tags::CV,
			vec![Fp::from(5), Fp::from(9)],
			native::hash_cv(5, Fp::from(9)),
		),
		(
			tags::NOTE,
			vec![Fp::from(1), Fp::from(10), Fp::from(3)],
			native::hash_note(Fp::from(1), 10, Fp::from(3)),
		),
		(
			tags::PTR,
			vec![Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4)],
			native::hash_ptr(Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4)),
		),
	];

	for (tag, msg, expected) in cases {
		assert_satisfied(&poseidon_prover(tag, &msg, expected));
	}
}

#[test]
fn circuit_hash_with_wrong_output_fails_permutation() {
	let sk = Fp::from(7);

	let failures = assert_unsatisfied(&poseidon_prover(
		tags::PK,
		&[sk],
		native::hash_pk(sk) + Fp::ONE,
	));

	assert_has_permutation_failure(&failures);
}

#[test]
fn circuit_hash_with_wrong_tag_does_not_match_native_hash_of_other_tag() {
	let sk = Fp::from(7);

	let failures = assert_unsatisfied(&poseidon_prover(tags::NK, &[sk], native::hash_pk(sk)));

	assert_has_permutation_failure(&failures);
}

// --- Mask --------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct MaskHarness {
	mask: Value<Fp>,
	bits: [Value<Fp>; 4],
}

#[derive(Clone, Debug)]
struct MaskHarnessConfig {
	shared: SharedColumns,
	mask: MaskConfig,
}

impl Circuit<Fp> for MaskHarness {
	type Config = MaskHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		let shared = SharedColumns::configure(meta);
		let mask = MaskConfig::configure(meta, &shared);
		MaskHarnessConfig { shared, mask }
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		cfg.mask.load(&mut layouter)?;
		let bits = cfg.mask.assign_raw(&mut layouter, self.mask, self.bits)?;
		binding::expose(&mut layouter, &bits.mask, cfg.shared.instance, 0)?;
		for (i, b) in bits.bits.iter().enumerate() {
			binding::expose(&mut layouter, b, cfg.shared.instance, i + 1)?;
		}
		Ok(())
	}
}

fn mask_prover(mask: u64, bits: [u64; 4]) -> MockProver<Fp> {
	let circuit = MaskHarness {
		mask: Value::known(Fp::from(mask)),
		bits: bits.map(|b| Value::known(Fp::from(b))),
	};
	let mut rows = vec![Fp::from(mask)];
	rows.extend(bits.map(Fp::from));
	MockProver::run(6, &circuit, vec![rows]).unwrap()
}

fn honest_bits(mask: u64) -> [u64; 4] {
	[0, 1, 2, 3].map(|i| (mask >> i) & 1)
}

#[test]
fn mask_table_accepts_every_mask_below_16_with_its_bits() {
	for mask in 0..16u64 {
		assert_satisfied(&mask_prover(mask, honest_bits(mask)));
	}
}

#[test]
fn mask_table_rejects_mask_16() {
	let failures = assert_unsatisfied(&mask_prover(16, honest_bits(16)));

	assert_has_lookup_failure(&failures);
}

#[test]
fn mask_table_rejects_mask_255() {
	let failures = assert_unsatisfied(&mask_prover(255, honest_bits(255)));

	assert_has_lookup_failure(&failures);
}

#[test]
fn mask_table_rejects_inconsistent_bit_decomposition() {
	let failures = assert_unsatisfied(&mask_prover(0b0001, [0, 0, 0, 0]));

	assert_has_lookup_failure(&failures);
}

#[test]
fn mask_table_rejects_non_boolean_bit_even_if_sum_matches() {
	// 2 = 2 * 1 with b0 = 2, b1 = 0: same weighted sum as (0, 1, 0, 0) but not a table row.
	let failures = assert_unsatisfied(&mask_prover(0b0010, [2, 0, 0, 0]));

	assert_has_lookup_failure(&failures);
}

// --- Range64 -----------------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct RangeHarness {
	value: Value<Fp>,
}

#[derive(Clone, Debug)]
struct RangeHarnessConfig {
	shared: SharedColumns,
	range: Range64Config,
}

impl Circuit<Fp> for RangeHarness {
	type Config = RangeHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		let shared = SharedColumns::configure(meta);
		let range = Range64Config::configure(meta, &shared);
		RangeHarnessConfig { shared, range }
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		cfg.range.load(&mut layouter)?;
		let value = binding::witness(&mut layouter, cfg.shared.advices[0], "value", self.value)?;
		cfg.range.check(&mut layouter, &value)?;
		binding::expose(&mut layouter, &value, cfg.shared.instance, 0)
	}
}

fn range_prover(value: Fp) -> MockProver<Fp> {
	MockProver::run(
		9,
		&RangeHarness {
			value: Value::known(value),
		},
		vec![vec![value]],
	)
	.unwrap()
}

#[test]
fn range64_accepts_zero_one_and_max_u64() {
	assert_satisfied(&range_prover(Fp::ZERO));
	assert_satisfied(&range_prover(Fp::ONE));
	assert_satisfied(&range_prover(Fp::from(u64::MAX)));
}

#[test]
fn range64_rejects_2_pow_64() {
	let two_pow_64 = Fp::from(u64::MAX) + Fp::ONE;

	let failures = assert_unsatisfied(&range_prover(two_pow_64));

	assert_has_lookup_failure(&failures);
}

#[test]
fn range64_rejects_field_modulus_minus_one() {
	let failures = assert_unsatisfied(&range_prover(-Fp::ONE));

	assert!(!failures.is_empty());
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(16))]

	#[test]
	fn range64_accepts_random_u64(v in any::<u64>()) {
		assert_satisfied(&range_prover(Fp::from(v)));
	}

	#[test]
	fn range64_rejects_random_value_above_u64(hi in 1u64..) {
		// value = hi * 2^64 + lo for any lo is out of range.
		let value = Fp::from(hi) * (Fp::from(u64::MAX) + Fp::ONE) + Fp::from(12345u64);
		prop_assert!(range_prover(value).verify().is_err());
	}
}

// --- Reveal ------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct RevealHarness {
	hide: Value<Fp>,
	value: Value<Fp>,
	revealed: Value<Fp>,
}

#[derive(Clone, Debug)]
struct RevealHarnessConfig {
	shared: SharedColumns,
	reveal: RevealConfig,
}

impl Circuit<Fp> for RevealHarness {
	type Config = RevealHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		let shared = SharedColumns::configure(meta);
		let reveal = RevealConfig::configure(meta, &shared);
		RevealHarnessConfig { shared, reveal }
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		let hide = binding::witness(&mut layouter, cfg.shared.advices[4], "hide", self.hide)?;
		let value = binding::witness(&mut layouter, cfg.shared.advices[5], "value", self.value)?;
		let revealed = cfg
			.reveal
			.reveal_raw(&mut layouter, &hide, &value, self.revealed)?;
		binding::expose(&mut layouter, &revealed, cfg.shared.instance, 0)
	}
}

fn reveal_prover(hide: u64, value: u64, revealed: u64) -> MockProver<Fp> {
	let circuit = RevealHarness {
		hide: Value::known(Fp::from(hide)),
		value: Value::known(Fp::from(value)),
		revealed: Value::known(Fp::from(revealed)),
	};
	MockProver::run(4, &circuit, vec![vec![Fp::from(revealed)]]).unwrap()
}

#[test]
fn reveal_gate_with_bit_clear_accepts_revealed_equal_to_value() {
	assert_satisfied(&reveal_prover(0, 42, 42));
}

#[test]
fn reveal_gate_with_bit_set_accepts_revealed_zero() {
	assert_satisfied(&reveal_prover(1, 42, 0));
}

#[test]
fn reveal_gate_with_bit_clear_rejects_wrong_revealed_value() {
	let failures = assert_unsatisfied(&reveal_prover(0, 42, 43));

	assert_has_gate_failure(&failures, "shown field equals value");
}

#[test]
fn reveal_gate_with_bit_set_rejects_leaked_value() {
	let failures = assert_unsatisfied(&reveal_prover(1, 42, 42));

	assert_has_gate_failure(&failures, "hidden field is zero");
}

#[test]
fn reveal_gate_hidden_zero_value_is_indistinguishable_from_shown_zero() {
	assert_satisfied(&reveal_prover(0, 0, 0));
	assert_satisfied(&reveal_prover(1, 0, 0));
}

// --- Merkle ------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MerkleHarness {
	kind: TreeKind,
	leaf: Value<Fp>,
	path: Value<PathWitness>,
}

impl Default for MerkleHarness {
	fn default() -> Self {
		MerkleHarness {
			kind: TreeKind::Note,
			leaf: Value::unknown(),
			path: Value::unknown(),
		}
	}
}

#[derive(Clone, Debug)]
struct MerkleHarnessConfig {
	shared: SharedColumns,
	merkle: MerkleConfig,
}

impl Circuit<Fp> for MerkleHarness {
	type Config = MerkleHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		MerkleHarness {
			kind: self.kind,
			..Self::default()
		}
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		let shared = SharedColumns::configure(meta);
		let poseidon = PoseidonConfig::configure(meta, &shared);
		let merkle = MerkleConfig::configure(meta, &shared, &poseidon);
		MerkleHarnessConfig { shared, merkle }
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		let leaf = binding::witness(&mut layouter, cfg.shared.advices[5], "leaf", self.leaf)?;
		let root = cfg
			.merkle
			.root(&mut layouter, self.kind.tag(), leaf, self.path.as_ref())?;
		binding::expose(&mut layouter, &root, cfg.shared.instance, 0)
	}
}

/// K for a bare depth-32 Poseidon Merkle path.
const MERKLE_K: u32 = 12;

fn merkle_prover(kind: TreeKind, leaf: Fp, path: PathWitness, root: Fp) -> MockProver<Fp> {
	let circuit = MerkleHarness {
		kind,
		leaf: Value::known(leaf),
		path: Value::known(path),
	};
	MockProver::run(MERKLE_K, &circuit, vec![vec![root]]).unwrap()
}

fn small_tree(kind: TreeKind, leaves: &[u64]) -> ReferenceTree {
	let mut tree = ReferenceTree::new(kind);
	for l in leaves {
		tree.insert(Fp::from(*l));
	}
	tree
}

#[test]
fn merkle_gadget_matches_native_root_for_first_leaf_of_empty_tree() {
	let tree = small_tree(TreeKind::Note, &[11]);
	let path = tree.path(0);

	assert_satisfied(&merkle_prover(
		TreeKind::Note,
		Fp::from(11),
		PathWitness::from(&path),
		tree.root(),
	));
}

#[test]
fn merkle_gadget_matches_native_root_for_every_leaf_of_a_five_leaf_tree() {
	let leaves = [11, 22, 33, 44, 55];
	let tree = small_tree(TreeKind::Note, &leaves);

	for (i, leaf) in leaves.iter().enumerate() {
		let path = tree.path(i as u64);
		assert_satisfied(&merkle_prover(
			TreeKind::Note,
			Fp::from(*leaf),
			PathWitness::from(&path),
			tree.root(),
		));
	}
}

#[test]
fn merkle_gadget_rejects_wrong_sibling_at_leaf_level() {
	let tree = small_tree(TreeKind::Note, &[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.siblings[0] += Fp::ONE;

	let failures = assert_unsatisfied(&merkle_prover(
		TreeKind::Note,
		Fp::from(11),
		path,
		tree.root(),
	));

	assert_has_permutation_failure(&failures);
}

#[test]
fn merkle_gadget_rejects_wrong_sibling_at_root_level() {
	let tree = small_tree(TreeKind::Note, &[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.siblings[31] += Fp::ONE;

	let failures = assert_unsatisfied(&merkle_prover(
		TreeKind::Note,
		Fp::from(11),
		path,
		tree.root(),
	));

	assert_has_permutation_failure(&failures);
}

#[test]
fn merkle_gadget_rejects_flipped_position_bit() {
	let tree = small_tree(TreeKind::Note, &[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.bits[0] = Fp::ONE;

	let failures = assert_unsatisfied(&merkle_prover(
		TreeKind::Note,
		Fp::from(11),
		path,
		tree.root(),
	));

	assert_has_permutation_failure(&failures);
}

#[test]
fn merkle_gadget_rejects_non_boolean_position_bit() {
	let tree = small_tree(TreeKind::Note, &[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.bits[3] = Fp::from(2);

	let failures = assert_unsatisfied(&merkle_prover(
		TreeKind::Note,
		Fp::from(11),
		path,
		tree.root(),
	));

	assert_has_gate_failure(&failures, "bit is boolean");
}

#[test]
fn merkle_gadget_with_member_tag_rejects_note_tree_root() {
	let tree = small_tree(TreeKind::Note, &[11]);
	let path = PathWitness::from(&tree.path(0));

	let failures = assert_unsatisfied(&merkle_prover(
		TreeKind::Member,
		Fp::from(11),
		path,
		tree.root(),
	));

	assert_has_permutation_failure(&failures);
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(4))]

	#[test]
	fn merkle_gadget_matches_native_root_for_random_position(
		leaves in prop::collection::vec(any::<u64>(), 1..8),
		pick in any::<prop::sample::Index>(),
	) {
		let tree = small_tree(TreeKind::Member, &leaves);
		let index = pick.index(leaves.len());
		let path = tree.path(index as u64);
		prop_assert_eq!(path.leaf_index(), index as u64);
		assert_satisfied(&merkle_prover(TreeKind::Member, Fp::from(leaves[index]), PathWitness::from(&path), tree.root()));
	}
}
