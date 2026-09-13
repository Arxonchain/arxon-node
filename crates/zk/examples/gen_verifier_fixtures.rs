//! Writes the proof fixtures `pallet-zk-verifier` benchmarks verify: one proof
//! per circuit and instance count, with its SCALE-encoded public inputs.
//!
//! Run with `cargo run --release -p arxon-zk --example gen_verifier_fixtures`
//! after any circuit change (the `arxon-zk-host` test
//! `verifier_benchmark_fixtures_still_verify` fails while they are stale).

use std::{
	fs,
	path::{Path, PathBuf},
};

use arxon_zk::{
	circuit::ArxonCircuit,
	circuits::{C1Circuit, C2Circuit, C3Circuit, C4Circuit, C5Circuit, C6Circuit},
	field::fp_to_bytes,
	merkle::{MemberTree, NoteTree, TreeKind},
	primitives::FieldBytes,
	prover::{prove, public_rows},
	wallet::{
		balance_witness, member_leaf, membership_witness, output_witnesses, spend_witnesses,
		BundleContext, Note, OutputNote, Receipt, SpendNote, SpendingKey,
	},
	Fp,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use scale_codec::Encode;

fn write<C: ArxonCircuit + 'static>(dir: &Path, name: &str, witnesses: &[C::Witness]) {
	let mut rng = ChaCha20Rng::seed_from_u64(0xa7c0);
	let proof = prove::<C>(witnesses, &mut rng).expect("honest witness proves");
	let inputs: Vec<Vec<FieldBytes>> = public_rows::<C>(witnesses)
		.iter()
		.map(|rows| rows.iter().map(fp_to_bytes).collect())
		.collect();
	fs::write(dir.join(format!("{name}.proof")), &proof).expect("write proof");
	fs::write(dir.join(format!("{name}.inputs")), inputs.encode()).expect("write inputs");
	println!(
		"{name}: {} proof bytes, {} instance(s) of {} rows",
		proof.len(),
		inputs.len(),
		inputs[0].len()
	);
}

fn main() {
	let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../../template/pallets/zk-verifier/fixtures");
	fs::create_dir_all(&dir).expect("fixtures dir");

	let mut rng = ChaCha20Rng::seed_from_u64(0xf1f7);
	let ctx = BundleContext {
		mask: 0b0111,
		bundle_digest: Fp::from(0xd1ce57u64),
		expiry_block: 1_000,
		transparent_in: 0,
		transparent_out: 0,
	};
	let alice = SpendingKey::random(&mut rng);
	let bob = SpendingKey::random(&mut rng);
	let mut tree = NoteTree::new(TreeKind::Note);
	let notes = [
		Note::new(alice.pk(), 30, &mut rng),
		Note::new(alice.pk(), 12, &mut rng),
	];
	let spends: Vec<SpendNote> = notes
		.iter()
		.map(|note| {
			let index = tree.insert(note.commitment());
			SpendNote::new(alice, *note, tree.path(index), &mut rng)
		})
		.collect();
	let outputs = [
		OutputNote::new(bob.pk(), 40, &mut rng),
		OutputNote::new(alice.pk(), 2, &mut rng),
	];
	let receipt = Receipt::new(&alice, outputs[0], &mut rng);
	let mut registry = MemberTree::new(TreeKind::Member);
	let member_index = registry.insert(member_leaf(bob.pk()));

	let c3 = spend_witnesses(&spends, &ctx);
	let c1 = output_witnesses(&outputs, &ctx);
	let c2 = balance_witness(&spends, &outputs, &ctx);
	let c4 = receipt.generation_witness(&ctx);
	let c5 = receipt.disclosure_witness(0b0011, Fp::from(99), ctx.expiry_block);
	let c6 = membership_witness(&outputs[0], registry.path(member_index), &ctx);

	write::<C1Circuit>(&dir, "c1_1", &c1[..1]);
	write::<C1Circuit>(&dir, "c1_2", &c1);
	write::<C2Circuit>(&dir, "c2", std::slice::from_ref(&c2));
	write::<C3Circuit>(&dir, "c3_1", &c3[..1]);
	write::<C3Circuit>(&dir, "c3_2", &c3);
	write::<C4Circuit>(&dir, "c4", std::slice::from_ref(&c4));
	write::<C5Circuit>(&dir, "c5", std::slice::from_ref(&c5));
	write::<C6Circuit>(&dir, "c6", std::slice::from_ref(&c6));
	println!("fixtures written to {}", dir.display());
}
