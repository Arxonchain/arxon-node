//! Wallet Halo2 proving (keys, shield, private transfer, unshield).
//! The HTTP binary and the browser WASM crate both call this.

use arxon_zk::circuits::{C1Circuit, C2Circuit, C3Circuit};
use arxon_zk::key_cache::proving_key;
use arxon_zk::merkle::{NoteTree as ReferenceNoteTree, TreeKind};
use arxon_zk::primitives::mask::{hides_amount, hides_receiver, hides_sender, is_valid_mask};
use arxon_zk::primitives::poseidon::{fp_from_bytes, fp_to_bytes};
use arxon_zk::primitives::{
	arx20_bundle_digest, bundle_digest, encrypted_notes_hash, BundleFields, FieldBytes, CHAIN_ID,
	SHIELDED_UNIT,
};
use arxon_zk::prove;
use arxon_zk::wallet::{
	balance_witness, output_witnesses, spend_witnesses, BundleContext, Note, OutputNote, SpendNote,
	SpendingKey,
};
use arxon_zk::Fp;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

const DUMMY_NOTE: &[u8] = b"arxon-note-v1";

/// Load C1/C2/C3 proving keys into the process cache.
pub fn warm_keys() {
	let _ = proving_key::<C1Circuit>();
	let _ = proving_key::<C2Circuit>();
	let _ = proving_key::<C3Circuit>();
}

#[derive(Deserialize)]
pub struct KeysReq {
	#[serde(default)]
	pub sk_hex: Option<String>,
}

#[derive(Serialize)]
pub struct KeysRes {
	pub sk_hex: String,
	pub pk_hex: String,
}

#[derive(Deserialize)]
pub struct ShieldReq {
	amount_wei: String,
	mask_bits: u8,
	expiry_block: u32,
	#[serde(default)]
	sk_hex: Option<String>,
	/// ARX-20 contract. Empty / omitted = native ARX digest.
	#[serde(default)]
	token: Option<String>,
}

#[derive(Deserialize)]
pub struct SpendNoteReq {
	amount_wei: String,
	rho: String,
	leaf_index: u64,
}

#[derive(Deserialize)]
pub struct TransferReq {
	amount_wei: String,
	mask_bits: u8,
	expiry_block: u32,
	sk_hex: String,
	recipient_pk: String,
	note: SpendNoteReq,
	leaves: Vec<String>,
	/// ARX-20 contract. Empty / omitted = native ARX digest.
	#[serde(default)]
	token: Option<String>,
}

#[derive(Deserialize)]
pub struct UnshieldReq {
	amount_wei: String,
	mask_bits: u8,
	expiry_block: u32,
	sk_hex: String,
	recipient: String,
	note: SpendNoteReq,
	leaves: Vec<String>,
	/// ARX-20 contract. Empty / omitted = native ARX digest.
	#[serde(default)]
	token: Option<String>,
}

#[derive(Serialize)]
pub struct ShieldRes {
	sk_hex: String,
	pk_hex: String,
	amount_wei: String,
	mask_bits: u8,
	expiry_block: u32,
	outputs: Vec<OutputJson>,
	proofs: ProofsJson,
	note: NoteSecrets,
}

#[derive(Serialize)]
pub struct SpendRes {
	anchor: String,
	mask_bits: u8,
	expiry_block: u32,
	amount_wei: String,
	inputs: Vec<InputJson>,
	outputs: Vec<OutputJson>,
	proofs: ProofsJson,
	notes: Vec<NoteSecrets>,
}

#[derive(Serialize)]
struct NoteSecrets {
	cm: String,
	cv: String,
	rho: String,
	amount_wei: String,
	pk_hex: String,
}

#[derive(Serialize)]
struct InputJson {
	nullifier: String,
	cv: String,
	revealed_sender: String,
}

#[derive(Serialize)]
struct OutputJson {
	cm: String,
	cv: String,
	revealed_receiver: String,
	revealed_amount: String,
	encrypted_note: String,
}

#[derive(Serialize)]
struct ProofsJson {
	spend: String,
	output: String,
	balance: String,
	receipt: String,
	compliance: String,
}

fn hex_field(b: &FieldBytes) -> String {
	format!("0x{}", hex::encode(b.0))
}

fn hex_bytes(b: &[u8]) -> String {
	format!("0x{}", hex::encode(b))
}

fn parse_hex32(hex_in: &str) -> Result<[u8; 32], String> {
	let raw = hex_in.trim().trim_start_matches("0x");
	let bytes = hex::decode(raw).map_err(|e| e.to_string())?;
	if bytes.len() != 32 {
		return Err("expected 32 bytes".into());
	}
	let mut arr = [0u8; 32];
	arr.copy_from_slice(&bytes);
	Ok(arr)
}

fn parse_fp(hex_in: &str) -> Result<Fp, String> {
	let arr = parse_hex32(hex_in)?;
	fp_from_bytes(&FieldBytes(arr)).ok_or_else(|| "not a field element".into())
}

fn parse_sk(hex_in: &str) -> Result<SpendingKey, String> {
	Ok(SpendingKey(parse_fp(hex_in)?))
}

fn parse_wei(s: &str) -> Result<u128, String> {
	s.parse().map_err(|_| "amount_wei is not an integer".into())
}

fn to_units(wei: u128) -> Result<u64, String> {
	if wei == 0 || wei % SHIELDED_UNIT != 0 {
		return Err(
			"amount must be a positive multiple of 1e9 base units (1 shielded unit)".into(),
		);
	}
	u64::try_from(wei / SHIELDED_UNIT).map_err(|_| "amount too large".into())
}

fn wei_of(units: u64) -> String {
	(units as u128 * SHIELDED_UNIT).to_string()
}

fn parse_h160(hex_in: &str) -> Result<[u8; 20], String> {
	let raw = hex_in.trim().trim_start_matches("0x");
	let bytes = hex::decode(raw).map_err(|e| e.to_string())?;
	if bytes.len() != 20 {
		return Err("expected a 20-byte EVM address".into());
	}
	let mut arr = [0u8; 20];
	arr.copy_from_slice(&bytes);
	Ok(arr)
}

fn digest_of(token: Option<&str>, fields: &BundleFields<'_>) -> Result<FieldBytes, String> {
	match token.map(str::trim).filter(|s| !s.is_empty()) {
		None => Ok(bundle_digest(fields)),
		Some(hex) => Ok(arx20_bundle_digest(&parse_h160(hex)?, fields)),
	}
}

fn output_json(out: &OutputNote, mask: u8) -> OutputJson {
	let revealed_receiver = if hides_receiver(mask) {
		FieldBytes::ZERO
	} else {
		fp_to_bytes(&out.note.pk)
	};
	let revealed_amount = if hides_amount(mask) {
		FieldBytes::ZERO
	} else {
		FieldBytes::from_u64(out.note.amount)
	};
	OutputJson {
		cm: hex_field(&out.cm_bytes()),
		cv: hex_field(&out.cv_bytes()),
		revealed_receiver: hex_field(&revealed_receiver),
		revealed_amount: hex_field(&revealed_amount),
		encrypted_note: hex_bytes(DUMMY_NOTE),
	}
}

fn secrets_of(out: &OutputNote) -> NoteSecrets {
	NoteSecrets {
		cm: hex_field(&out.cm_bytes()),
		cv: hex_field(&out.cv_bytes()),
		rho: hex_field(&fp_to_bytes(&out.note.rho)),
		amount_wei: wei_of(out.note.amount),
		pk_hex: hex_field(&fp_to_bytes(&out.note.pk)),
	}
}

fn empty_proofs() -> ProofsJson {
	ProofsJson {
		spend: "0x".into(),
		output: "0x".into(),
		balance: "0x".into(),
		receipt: "0x".into(),
		compliance: "0x".into(),
	}
}

pub fn keys(req: KeysReq) -> Result<KeysRes, String> {
	let mut rng = OsRng;
	let sk = match req.sk_hex.as_deref() {
		Some(h) if !h.is_empty() => parse_sk(h)?,
		_ => SpendingKey::random(&mut rng),
	};
	Ok(KeysRes {
		sk_hex: hex_field(&fp_to_bytes(&sk.0)),
		pk_hex: hex_field(&fp_to_bytes(&sk.pk())),
	})
}

pub fn shield(req: ShieldReq) -> Result<ShieldRes, String> {
	if !is_valid_mask(req.mask_bits) {
		return Err("mask_bits must be 0..=15".into());
	}
	let wei = parse_wei(&req.amount_wei)?;
	let units = to_units(wei)?;
	let mut rng = OsRng;
	let sk = match req.sk_hex.as_deref() {
		Some(h) if !h.is_empty() => parse_sk(h)?,
		_ => SpendingKey::random(&mut rng),
	};
	let out = OutputNote::new(sk.pk(), units, &mut rng);
	let cm = out.cm_bytes();
	let cv = out.cv_bytes();
	let encrypted = DUMMY_NOTE.to_vec();
	let digest = digest_of(
		req.token.as_deref(),
		&BundleFields {
			chain_id: CHAIN_ID,
			expiry_block: req.expiry_block,
			recipient: None,
			transparent_in: units,
			transparent_out: 0,
			fee: 0,
			nullifiers: &[],
			commitments: &[cm],
			cv_inputs: &[],
			cv_outputs: &[cv],
			mask_bits: req.mask_bits,
			encrypted_notes_hash: encrypted_notes_hash(&[encrypted.as_slice()]),
			receipt: None,
			compliance: None,
		},
	)?;
	let ctx = BundleContext {
		mask: req.mask_bits,
		bundle_digest: fp_from_bytes(&digest).ok_or("digest not canonical")?,
		expiry_block: req.expiry_block,
		transparent_in: units,
		transparent_out: 0,
	};
	let c1 = output_witnesses(&[out], &ctx);
	let c2 = balance_witness(&[], &[out], &ctx);
	let output_proof = prove::<C1Circuit>(&c1, OsRng).map_err(|e| e.to_string())?;
	let balance_proof = prove::<C2Circuit>(&[c2], OsRng).map_err(|e| e.to_string())?;
	let mut proofs = empty_proofs();
	proofs.output = hex_bytes(&output_proof);
	proofs.balance = hex_bytes(&balance_proof);
	Ok(ShieldRes {
		sk_hex: hex_field(&fp_to_bytes(&sk.0)),
		pk_hex: hex_field(&fp_to_bytes(&sk.pk())),
		amount_wei: wei.to_string(),
		mask_bits: req.mask_bits,
		expiry_block: req.expiry_block,
		outputs: vec![output_json(&out, req.mask_bits)],
		proofs,
		note: secrets_of(&out),
	})
}

fn tree_from_leaves(leaves: &[String]) -> Result<ReferenceNoteTree, String> {
	let mut tree = ReferenceNoteTree::new(TreeKind::Note);
	for leaf in leaves {
		tree.insert(parse_fp(leaf)?);
	}
	Ok(tree)
}

fn open_spend(
	sk: SpendingKey,
	req: &SpendNoteReq,
	leaves: &[String],
	rng: &mut impl rand_core::RngCore,
) -> Result<(SpendNote, FieldBytes), String> {
	let wei = parse_wei(&req.amount_wei)?;
	let units = to_units(wei)?;
	let rho = parse_fp(&req.rho)?;
	let note = Note {
		pk: sk.pk(),
		amount: units,
		rho,
	};
	if (req.leaf_index as usize) >= leaves.len() {
		return Err("leaf_index is past the leaves this wallet sent".into());
	}
	let tree = tree_from_leaves(leaves)?;
	let path = tree.path(req.leaf_index);
	if ReferenceNoteTree::root_from_path(TreeKind::Note, note.commitment(), &path) != tree.root() {
		return Err(
			"note does not sit at that leaf. The 0.1 ARX shielded before note secrets were stored cannot be spent. Shield a new amount after this prover restart."
				.into(),
		);
	}
	let spend = SpendNote::new(sk, note, path, rng);
	Ok((spend, fp_to_bytes(&tree.root())))
}

// Mirrors one bundle's fields; grouping them would only move the list into a struct.
#[allow(clippy::too_many_arguments)]
fn prove_spend_bundle(
	spends: &[SpendNote],
	outputs: &[OutputNote],
	anchor: FieldBytes,
	mask: u8,
	expiry_block: u32,
	transparent_in: u64,
	transparent_out: u64,
	recipient: Option<&[u8]>,
	token: Option<&str>,
) -> Result<SpendRes, String> {
	let nullifiers: Vec<FieldBytes> = spends.iter().map(|s| s.nullifier_bytes()).collect();
	let commitments: Vec<FieldBytes> = outputs.iter().map(|o| o.cm_bytes()).collect();
	let cv_inputs: Vec<FieldBytes> = spends.iter().map(|s| s.cv_bytes()).collect();
	let cv_outputs: Vec<FieldBytes> = outputs.iter().map(|o| o.cv_bytes()).collect();
	let enc: Vec<Vec<u8>> = outputs.iter().map(|_| DUMMY_NOTE.to_vec()).collect();
	let enc_refs: Vec<&[u8]> = enc.iter().map(|e| e.as_slice()).collect();
	let digest = digest_of(
		token,
		&BundleFields {
			chain_id: CHAIN_ID,
			expiry_block,
			recipient,
			transparent_in,
			transparent_out,
			fee: 0,
			nullifiers: &nullifiers,
			commitments: &commitments,
			cv_inputs: &cv_inputs,
			cv_outputs: &cv_outputs,
			mask_bits: mask,
			encrypted_notes_hash: encrypted_notes_hash(&enc_refs),
			receipt: None,
			compliance: None,
		},
	)?;
	let ctx = BundleContext {
		mask,
		bundle_digest: fp_from_bytes(&digest).ok_or("digest not canonical")?,
		expiry_block,
		transparent_in,
		transparent_out,
	};
	let mut proofs = empty_proofs();
	let spend_proof =
		prove::<C3Circuit>(&spend_witnesses(spends, &ctx), OsRng).map_err(|e| e.to_string())?;
	proofs.spend = hex_bytes(&spend_proof);
	if !outputs.is_empty() {
		let output_proof = prove::<C1Circuit>(&output_witnesses(outputs, &ctx), OsRng)
			.map_err(|e| e.to_string())?;
		proofs.output = hex_bytes(&output_proof);
	}
	let balance_proof = prove::<C2Circuit>(&[balance_witness(spends, outputs, &ctx)], OsRng)
		.map_err(|e| e.to_string())?;
	proofs.balance = hex_bytes(&balance_proof);

	let revealed_sender = if hides_sender(mask) {
		FieldBytes::ZERO
	} else {
		fp_to_bytes(&spends[0].sk.pk())
	};
	Ok(SpendRes {
		anchor: hex_field(&anchor),
		mask_bits: mask,
		expiry_block,
		amount_wei: wei_of(if transparent_out > 0 {
			transparent_out
		} else {
			outputs.first().map(|o| o.note.amount).unwrap_or(0)
		}),
		inputs: spends
			.iter()
			.map(|s| InputJson {
				nullifier: hex_field(&s.nullifier_bytes()),
				cv: hex_field(&s.cv_bytes()),
				revealed_sender: hex_field(&revealed_sender),
			})
			.collect(),
		outputs: outputs.iter().map(|o| output_json(o, mask)).collect(),
		proofs,
		notes: outputs.iter().map(secrets_of).collect(),
	})
}

pub fn transfer(req: TransferReq) -> Result<SpendRes, String> {
	if !is_valid_mask(req.mask_bits) {
		return Err("mask_bits must be 0..=15".into());
	}
	let pay_units = to_units(parse_wei(&req.amount_wei)?)?;
	let sk = parse_sk(&req.sk_hex)?;
	let recipient_pk = parse_fp(&req.recipient_pk)?;
	let mut rng = OsRng;
	let (spend, anchor) = open_spend(sk, &req.note, &req.leaves, &mut rng)?;
	if pay_units > spend.note.amount {
		return Err("amount is larger than the selected note".into());
	}
	let change = spend.note.amount - pay_units;
	let paid = OutputNote::new(recipient_pk, pay_units, &mut rng);
	let mut outputs = vec![paid];
	if change > 0 {
		outputs.push(OutputNote::new(sk.pk(), change, &mut rng));
	}
	prove_spend_bundle(
		std::slice::from_ref(&spend),
		&outputs,
		anchor,
		req.mask_bits,
		req.expiry_block,
		0,
		0,
		None,
		req.token.as_deref(),
	)
}

pub fn unshield(req: UnshieldReq) -> Result<SpendRes, String> {
	if !is_valid_mask(req.mask_bits) {
		return Err("mask_bits must be 0..=15".into());
	}
	let out_units = to_units(parse_wei(&req.amount_wei)?)?;
	let sk = parse_sk(&req.sk_hex)?;
	let recipient = parse_h160(&req.recipient)?;
	let mut rng = OsRng;
	let (spend, anchor) = open_spend(sk, &req.note, &req.leaves, &mut rng)?;
	if out_units > spend.note.amount {
		return Err("amount is larger than the selected note".into());
	}
	let change = spend.note.amount - out_units;
	let mut outputs = Vec::new();
	if change > 0 {
		outputs.push(OutputNote::new(sk.pk(), change, &mut rng));
	}
	prove_spend_bundle(
		std::slice::from_ref(&spend),
		&outputs,
		anchor,
		req.mask_bits,
		req.expiry_block,
		0,
		out_units,
		Some(&recipient),
		req.token.as_deref(),
	)
}
