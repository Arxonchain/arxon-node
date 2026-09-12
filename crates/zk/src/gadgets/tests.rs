//! Gadget tests: each gadget under MockProver through a minimal harness circuit.

use arxon_zk_primitives::{
	constants::tags, poseidon as native, MEMBER_TREE_DEPTH, NOTE_TREE_DEPTH,
};
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
	merkle::{MemberTree, NoteTree, ReferenceTree, TreeKind},
	test_support::*,
};

// --- Poseidon ----------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PoseidonHarness<const TAG: u64, const L: usize> {
	msg: [Value<Fp>; L],
}

impl<const TAG: u64, const L: usize> Default for PoseidonHarness<TAG, L> {
	fn default() -> Self {
		PoseidonHarness {
			msg: [Value::unknown(); L],
		}
	}
}

#[derive(Clone, Debug)]
struct PoseidonHarnessConfig {
	shared: SharedColumns,
	poseidon: PoseidonConfig,
}

impl<const TAG: u64, const L: usize> Circuit<Fp> for PoseidonHarness<TAG, L> {
	type Config = PoseidonHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		let shared = SharedColumns::configure(meta);
		let poseidon = PoseidonConfig::configure(meta, &shared);
		PoseidonHarnessConfig { shared, poseidon }
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		let mut cells = Vec::with_capacity(L);
		for m in self.msg {
			cells.push(binding::witness(
				&mut layouter,
				cfg.shared.advices[5],
				"m",
				m,
			)?);
		}
		let cells: [_; L] = cells.try_into().expect("L cells");
		let out = cfg
			.poseidon
			.hash_domain::<TAG, L>(layouter.namespace(|| "h"), cells)?;
		binding::expose(&mut layouter, &out, cfg.shared.instance, 0)
	}
}

fn poseidon_prover<const TAG: u64, const L: usize>(msg: [Fp; L], expected: Fp) -> MockProver<Fp> {
	let circuit = PoseidonHarness::<TAG, L> {
		msg: msg.map(Value::known),
	};
	MockProver::run(7, &circuit, vec![vec![expected]]).unwrap()
}

#[test]
fn circuit_hash_matches_native_hash_for_each_tag_and_length() {
	let sk = Fp::from(7);
	let (a, b, c, d) = (Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4));

	assert_satisfied(&poseidon_prover::<{ tags::PK }, 1>(
		[sk],
		native::hash_pk(sk),
	));
	assert_satisfied(&poseidon_prover::<{ tags::NK }, 1>(
		[sk],
		native::hash_nk(sk),
	));
	assert_satisfied(&poseidon_prover::<{ tags::MEMBER_LEAF }, 1>(
		[sk],
		native::hash_member_leaf(sk),
	));
	assert_satisfied(&poseidon_prover::<{ tags::NULLIFIER }, 2>(
		[a, b],
		native::hash_nullifier(a, b),
	));
	assert_satisfied(&poseidon_prover::<{ tags::MERKLE_NOTE }, 2>(
		[a, b],
		native::hash_merkle_note(a, b),
	));
	assert_satisfied(&poseidon_prover::<{ tags::MERKLE_MEMBER }, 2>(
		[a, b],
		native::hash_merkle_member(a, b),
	));
	assert_satisfied(&poseidon_prover::<{ tags::CV }, 2>(
		[Fp::from(5), b],
		native::hash_cv(5, b),
	));
	assert_satisfied(&poseidon_prover::<{ tags::NOTE }, 3>(
		[a, Fp::from(10), c],
		native::hash_note(a, 10, c),
	));
	assert_satisfied(&poseidon_prover::<{ tags::PTR }, 4>(
		[a, b, c, d],
		native::hash_ptr(a, b, c, d),
	));
}

#[test]
fn circuit_hash_with_wrong_output_fails_permutation() {
	let sk = Fp::from(7);

	let failures = assert_unsatisfied(&poseidon_prover::<{ tags::PK }, 1>(
		[sk],
		native::hash_pk(sk) + Fp::ONE,
	));

	assert_has_permutation_failure(&failures);
}

#[test]
fn circuit_hash_under_one_tag_does_not_match_native_hash_of_another_tag() {
	let sk = Fp::from(7);

	let failures = assert_unsatisfied(&poseidon_prover::<{ tags::NK }, 1>(
		[sk],
		native::hash_pk(sk),
	));

	assert_has_permutation_failure(&failures);
}

#[test]
fn two_word_hash_uses_a_single_permutation() {
	// A Pow5 permutation is 37 rows plus a handful of sponge rows; two permutations would not fit K=6.
	let circuit = PoseidonHarness::<{ tags::CV }, 2> {
		msg: [Value::known(Fp::ONE), Value::known(Fp::ONE)],
	};

	let prover = MockProver::run(6, &circuit, vec![vec![native::hash_cv(1, Fp::ONE)]]);

	assert!(
		prover.is_ok(),
		"two-word tagged hash must fit a single permutation budget"
	);
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
			binding::expose(&mut layouter, b.cell(), cfg.shared.instance, i + 1)?;
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
fn mask_table_contains_the_all_zero_tuple() {
	// Rows without the mask selector look up (0, 0, 0, 0, 0); that must be a table row.
	assert_satisfied(&mask_prover(0, [0, 0, 0, 0]));
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
		let value = Fp::from(hi) * (Fp::from(u64::MAX) + Fp::ONE) + Fp::from(12345u64);
		prop_assert!(range_prover(value).verify().is_err());
	}
}

// --- Reveal ------------------------------------------------------------------------------------

/// Gate-level harness: feeds the gate an arbitrary hide cell and revealed witness.
#[derive(Clone, Debug, Default)]
struct RevealGateHarness {
	hide: Value<Fp>,
	value: Value<Fp>,
	revealed: Value<Fp>,
}

#[derive(Clone, Debug)]
struct RevealHarnessConfig {
	shared: SharedColumns,
	reveal: RevealConfig,
	mask: MaskConfig,
}

fn reveal_configure(meta: &mut ConstraintSystem<Fp>) -> RevealHarnessConfig {
	let shared = SharedColumns::configure(meta);
	let reveal = RevealConfig::configure(meta, &shared);
	let mask = MaskConfig::configure(meta, &shared);
	RevealHarnessConfig {
		shared,
		reveal,
		mask,
	}
}

impl Circuit<Fp> for RevealGateHarness {
	type Config = RevealHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		reveal_configure(meta)
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		cfg.mask.load(&mut layouter)?;
		let hide = binding::witness(&mut layouter, cfg.shared.advices[4], "hide", self.hide)?;
		let value = binding::witness(&mut layouter, cfg.shared.advices[5], "value", self.value)?;
		let revealed = cfg
			.reveal
			.reveal_raw(&mut layouter, &hide, &value, self.revealed)?;
		binding::expose(&mut layouter, &revealed, cfg.shared.instance, 0)
	}
}

fn reveal_gate_prover(hide: u64, value: u64, revealed: u64) -> MockProver<Fp> {
	let circuit = RevealGateHarness {
		hide: Value::known(Fp::from(hide)),
		value: Value::known(Fp::from(value)),
		revealed: Value::known(Fp::from(revealed)),
	};
	MockProver::run(6, &circuit, vec![vec![Fp::from(revealed)]]).unwrap()
}

#[test]
fn reveal_gate_with_bit_clear_accepts_revealed_equal_to_value() {
	assert_satisfied(&reveal_gate_prover(0, 42, 42));
}

#[test]
fn reveal_gate_with_bit_set_accepts_revealed_zero() {
	assert_satisfied(&reveal_gate_prover(1, 42, 0));
}

#[test]
fn reveal_gate_with_bit_clear_rejects_wrong_revealed_value() {
	let failures = assert_unsatisfied(&reveal_gate_prover(0, 42, 43));

	assert_has_gate_failure(&failures, "shown field equals value");
}

#[test]
fn reveal_gate_with_bit_set_rejects_leaked_value() {
	let failures = assert_unsatisfied(&reveal_gate_prover(1, 42, 42));

	assert_has_gate_failure(&failures, "hidden field is zero");
}

#[test]
fn reveal_gate_hidden_zero_value_is_indistinguishable_from_shown_zero() {
	assert_satisfied(&reveal_gate_prover(0, 0, 0));
	assert_satisfied(&reveal_gate_prover(1, 0, 0));
}

/// Production path: the hide bit comes from the mask lookup, so the exposed
/// mask and the reveal gate are tied to the same cell.
#[derive(Clone, Debug, Default)]
struct RevealViaMaskHarness {
	mask: Value<u8>,
	value: Value<Fp>,
}

impl Circuit<Fp> for RevealViaMaskHarness {
	type Config = RevealHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
		reveal_configure(meta)
	}

	fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
		cfg.mask.load(&mut layouter)?;
		let bits = cfg.mask.assign(&mut layouter, self.mask)?;
		let value = binding::witness(&mut layouter, cfg.shared.advices[5], "value", self.value)?;
		let revealed = cfg
			.reveal
			.reveal(&mut layouter, bits.hide_amount(), &value)?;
		binding::expose(&mut layouter, &bits.mask, cfg.shared.instance, 0)?;
		binding::expose(&mut layouter, &revealed, cfg.shared.instance, 1)
	}
}

fn reveal_via_mask_prover(mask: u8, value: u64, revealed_row: u64) -> MockProver<Fp> {
	let circuit = RevealViaMaskHarness {
		mask: Value::known(mask),
		value: Value::known(Fp::from(value)),
	};
	MockProver::run(
		6,
		&circuit,
		vec![vec![Fp::from(mask as u64), Fp::from(revealed_row)]],
	)
	.unwrap()
}

#[test]
fn reveal_via_mask_publishes_value_when_amount_bit_clear() {
	assert_satisfied(&reveal_via_mask_prover(0b0000, 42, 42));
}

#[test]
fn reveal_via_mask_publishes_zero_when_amount_bit_set() {
	assert_satisfied(&reveal_via_mask_prover(0b0100, 42, 0));
}

#[test]
fn reveal_via_mask_cannot_publish_value_while_mask_claims_it_is_hidden() {
	let failures = assert_unsatisfied(&reveal_via_mask_prover(0b0100, 42, 42));

	assert_has_permutation_failure(&failures);
}

// --- Merkle ------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MerkleHarness<const TAG: u64, const D: usize> {
	leaf: Value<Fp>,
	path: Value<PathWitness<D>>,
}

impl<const TAG: u64, const D: usize> Default for MerkleHarness<TAG, D> {
	fn default() -> Self {
		MerkleHarness {
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

impl<const TAG: u64, const D: usize> Circuit<Fp> for MerkleHarness<TAG, D> {
	type Config = MerkleHarnessConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
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
			.root::<TAG, D>(&mut layouter, leaf, self.path.as_ref())?;
		binding::expose(&mut layouter, &root, cfg.shared.instance, 0)
	}
}

/// K for a bare depth-32 Merkle path with one permutation per level.
const NOTE_MERKLE_K: u32 = 11;
/// K for a bare depth-16 path.
const MEMBER_MERKLE_K: u32 = 10;

fn note_prover(leaf: Fp, path: PathWitness<NOTE_TREE_DEPTH>, root: Fp) -> MockProver<Fp> {
	let circuit = MerkleHarness::<{ tags::MERKLE_NOTE }, NOTE_TREE_DEPTH> {
		leaf: Value::known(leaf),
		path: Value::known(path),
	};
	MockProver::run(NOTE_MERKLE_K, &circuit, vec![vec![root]]).unwrap()
}

fn member_prover(leaf: Fp, path: PathWitness<MEMBER_TREE_DEPTH>, root: Fp) -> MockProver<Fp> {
	let circuit = MerkleHarness::<{ tags::MERKLE_MEMBER }, MEMBER_TREE_DEPTH> {
		leaf: Value::known(leaf),
		path: Value::known(path),
	};
	MockProver::run(MEMBER_MERKLE_K, &circuit, vec![vec![root]]).unwrap()
}

fn note_tree(leaves: &[u64]) -> NoteTree {
	let mut tree = ReferenceTree::new(TreeKind::Note);
	for l in leaves {
		tree.insert(Fp::from(*l));
	}
	tree
}

fn member_tree(leaves: &[u64]) -> MemberTree {
	let mut tree = ReferenceTree::new(TreeKind::Member);
	for l in leaves {
		tree.insert(Fp::from(*l));
	}
	tree
}

#[test]
fn merkle_gadget_matches_native_root_for_first_leaf_of_empty_tree() {
	let tree = note_tree(&[11]);

	assert_satisfied(&note_prover(
		Fp::from(11),
		PathWitness::from(&tree.path(0)),
		tree.root(),
	));
}

#[test]
fn merkle_gadget_matches_native_root_for_every_leaf_of_a_five_leaf_tree() {
	let leaves = [11, 22, 33, 44, 55];
	let tree = note_tree(&leaves);

	for (i, leaf) in leaves.iter().enumerate() {
		assert_satisfied(&note_prover(
			Fp::from(*leaf),
			PathWitness::from(&tree.path(i as u64)),
			tree.root(),
		));
	}
}

#[test]
fn merkle_gadget_depth_32_fits_k_11() {
	// The tag lives in the sponge capacity, so each level is one permutation.
	let tree = note_tree(&[11]);
	let circuit = MerkleHarness::<{ tags::MERKLE_NOTE }, NOTE_TREE_DEPTH> {
		leaf: Value::known(Fp::from(11)),
		path: Value::known(PathWitness::from(&tree.path(0))),
	};

	assert!(MockProver::run(11, &circuit, vec![vec![tree.root()]]).is_ok());
}

#[test]
fn merkle_gadget_rejects_wrong_sibling_at_leaf_level() {
	let tree = note_tree(&[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.siblings[0] += Fp::ONE;

	let failures = assert_unsatisfied(&note_prover(Fp::from(11), path, tree.root()));

	assert_has_permutation_failure(&failures);
}

#[test]
fn merkle_gadget_rejects_wrong_sibling_at_root_level() {
	let tree = note_tree(&[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.siblings[NOTE_TREE_DEPTH - 1] += Fp::ONE;

	let failures = assert_unsatisfied(&note_prover(Fp::from(11), path, tree.root()));

	assert_has_permutation_failure(&failures);
}

#[test]
fn merkle_gadget_rejects_flipped_position_bit() {
	let tree = note_tree(&[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.bits[0] = Fp::ONE;

	let failures = assert_unsatisfied(&note_prover(Fp::from(11), path, tree.root()));

	assert_has_permutation_failure(&failures);
}

#[test]
fn merkle_gadget_rejects_non_boolean_position_bit() {
	let tree = note_tree(&[11, 22]);
	let mut path = PathWitness::from(&tree.path(0));
	path.bits[3] = Fp::from(2);

	let failures = assert_unsatisfied(&note_prover(Fp::from(11), path, tree.root()));

	assert_has_gate_failure(&failures, "bit is boolean");
}

#[test]
fn member_tree_gadget_matches_native_root_and_fits_k_10() {
	let tree = member_tree(&[11, 22, 33]);

	assert_satisfied(&member_prover(
		Fp::from(22),
		PathWitness::from(&tree.path(1)),
		tree.root(),
	));
}

#[test]
fn member_tree_gadget_rejects_a_note_tree_style_root() {
	// Same leaves hashed under the note tag give a different root.
	let tree = member_tree(&[11]);
	let wrong_root = native::hash_merkle_note(Fp::from(11), Fp::ZERO);

	let failures = assert_unsatisfied(&member_prover(
		Fp::from(11),
		PathWitness::from(&tree.path(0)),
		wrong_root,
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
		let tree = member_tree(&leaves);
		let index = pick.index(leaves.len());
		let path = tree.path(index as u64);
		prop_assert_eq!(path.leaf_index(), index as u64);
		assert_satisfied(&member_prover(Fp::from(leaves[index]), PathWitness::from(&path), tree.root()));
	}
}
