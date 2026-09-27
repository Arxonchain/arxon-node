//! Measures every chain circuit: proof sizes for one and the maximum number of
//! instances, proving and verification times (median of a few runs), and the
//! pinned metadata. Exits non-zero if any proof exceeds `MAX_PROOF_BYTES` or
//! differs from its pinned length.
//!
//! Run with `cargo run --release -p arxon-zk --example measure`.

use std::time::{Duration, Instant};

use arxon_zk::{
	circuit::ArxonCircuit,
	circuits::{C1Circuit, C2Circuit, C3Circuit, C4Circuit, C5Circuit, C6Circuit},
	merkle::{MemberTree, NoteTree, TreeKind},
	pins::measure,
	primitives::MAX_PROOF_BYTES,
	prover::{prove, public_rows},
	verifier::verify,
	wallet::{
		balance_witness, member_leaf, membership_witness, output_witnesses, spend_witnesses,
		BundleContext, Note, OutputNote, Receipt, SpendNote, SpendingKey,
	},
	Fp,
};
use rand_core::OsRng;

const RUNS: usize = 3;

fn median(mut samples: Vec<Duration>) -> Duration {
	samples.sort();
	samples[samples.len() / 2]
}

struct Row {
	name: &'static str,
	k: u32,
	instances: usize,
	proof_len: usize,
	pinned_len: usize,
	prove: Duration,
	verify: Duration,
}

fn bench<C: ArxonCircuit + 'static>(witnesses: &[C::Witness]) -> Row {
	let rows = public_rows::<C>(witnesses);
	let mut prove_times = Vec::with_capacity(RUNS);
	let mut verify_times = Vec::with_capacity(RUNS);
	let mut proof_len = 0;
	for _ in 0..RUNS {
		let start = Instant::now();
		let proof = prove::<C>(witnesses, OsRng).expect("honest witness proves");
		prove_times.push(start.elapsed());
		proof_len = proof.len();
		let start = Instant::now();
		verify::<C>(&proof, &rows).expect("honest proof verifies");
		verify_times.push(start.elapsed());
	}
	Row {
		name: C::NAME,
		k: C::K,
		instances: witnesses.len(),
		proof_len,
		pinned_len: C::PROOF_LENGTHS
			.get(witnesses.len() - 1)
			.copied()
			.unwrap_or(0),
		prove: median(prove_times),
		verify: median(verify_times),
	}
}

fn digest() -> Fp {
	Fp::from(0xd1ce57u64)
}

fn main() {
	let mut rng = OsRng;
	let ctx = BundleContext {
		mask: 0b0111,
		bundle_digest: digest(),
		expiry_block: 1_000,
		transparent_in: 0,
		transparent_out: 0,
	};

	// Two spends of 30 and 12 units paying 40 and 2.
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

	println!("warming up proving and verifying keys...");
	let start = Instant::now();
	arxon_zk::key_cache::warm_up();
	println!("keys ready in {:.1?}\n", start.elapsed());

	let rows = vec![
		bench::<C1Circuit>(&c1[..1]),
		bench::<C1Circuit>(&c1),
		bench::<C2Circuit>(std::slice::from_ref(&c2)),
		bench::<C3Circuit>(&c3[..1]),
		bench::<C3Circuit>(&c3),
		bench::<C4Circuit>(std::slice::from_ref(&c4)),
		bench::<C5Circuit>(std::slice::from_ref(&c5)),
		bench::<C6Circuit>(std::slice::from_ref(&c6)),
	];

	println!(
		"{:<30} {:>2} {:>4} {:>6} {:>6} {:>10} {:>10}",
		"circuit", "K", "inst", "bytes", "pinned", "prove", "verify"
	);
	let mut failed = false;
	for row in &rows {
		let ok = row.proof_len == row.pinned_len && row.proof_len <= MAX_PROOF_BYTES as usize;
		failed |= !ok;
		println!(
			"{:<30} {:>2} {:>4} {:>6} {:>6} {:>10.1?} {:>10.1?}{}",
			row.name,
			row.k,
			row.instances,
			row.proof_len,
			row.pinned_len,
			row.prove,
			row.verify,
			if ok { "" } else { "  <-- MISMATCH" }
		);
	}

	println!("\nverifying key hashes:");
	arxon_zk::circuits::for_each_chain_circuit!(|C| {
		let pins = measure::<C>();
		println!("  {:<30} {}", pins.name, hex::encode(pins.vk_hash));
	});

	if failed {
		eprintln!("\nsome proof exceeded MAX_PROOF_BYTES ({MAX_PROOF_BYTES}) or missed its pin");
		std::process::exit(1);
	}
}
