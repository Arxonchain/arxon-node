//! Wallet Halo2 proving (keys, shield, private transfer, unshield).
//! The HTTP binary and the browser WASM crate both call this.
//!
//! Amounts are in base units (wei for ARX). A pool counts them in shielded
//! units: 10^9 base units for native ARX, and for an ARX-20 token the
//! `shieldedUnit(token)` the `0x802` precompile reports (send it as
//! `shielded_unit_wei`; omitted means 10^9, the unit of a token that never
//! fixed its own).
//!
//! A relayed transfer or unshield sets `fee_wei` and `fee_recipient`: the fee
//! comes out of the spent note, next to the payment and the change, and both
//! are bound into the proofs. A bundle with mask bit 3 (hide balance) never
//! unshields; the prover refuses to build one.

use arxon_zk::circuits::{C1Circuit, C2Circuit, C3Circuit};
use arxon_zk::key_cache::proving_key;
use arxon_zk::merkle::{NoteTree as ReferenceNoteTree, TreeKind};
use arxon_zk::primitives::mask::{
	hides_amount, hides_balance, hides_receiver, hides_sender, is_valid_mask,
};
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
	/// Base units per shielded unit of the pool. Omitted = 10^9.
	#[serde(default)]
	shielded_unit_wei: Option<String>,
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
	/// Base units per shielded unit of the pool. Omitted = 10^9.
	#[serde(default)]
	shielded_unit_wei: Option<String>,
	/// Relayer fee in base units, paid from the pool. Needs `fee_recipient`.
	#[serde(default)]
	fee_wei: Option<String>,
	/// EVM address the fee is paid to (for ARX-20, the token mints it there).
	#[serde(default)]
	fee_recipient: Option<String>,
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
	/// Base units per shielded unit of the pool. Omitted = 10^9.
	#[serde(default)]
	shielded_unit_wei: Option<String>,
	/// Relayer fee in base units, paid from the pool. Needs `fee_recipient`.
	#[serde(default)]
	fee_wei: Option<String>,
	/// EVM address the fee is paid to (for ARX-20, the token mints it there).
	#[serde(default)]
	fee_recipient: Option<String>,
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
	/// Relayer fee the proofs are bound to, `"0"` when unrelayed.
	fee_wei: String,
	/// Account the fee goes to, absent when unrelayed.
	#[serde(skip_serializing_if = "Option::is_none")]
	fee_recipient: Option<String>,
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

fn parse_unit(unit: Option<&str>) -> Result<u128, String> {
	match unit.map(str::trim).filter(|s| !s.is_empty()) {
		None => Ok(SHIELDED_UNIT),
		Some(s) => match s.parse::<u128>() {
			Ok(0) | Err(_) => Err("shielded_unit_wei must be a positive integer".into()),
			Ok(unit) => Ok(unit),
		},
	}
}

fn to_units(wei: u128, unit: u128) -> Result<u64, String> {
	if wei == 0 || wei % unit != 0 {
		return Err(format!(
			"amount must be a positive multiple of {unit} base units (1 shielded unit)"
		));
	}
	u64::try_from(wei / unit).map_err(|_| "amount too large".into())
}

fn wei_of(units: u64, unit: u128) -> String {
	(units as u128 * unit).to_string()
}

/// A relayer fee: shielded units and the 20-byte account it is paid to.
#[derive(Clone, Copy)]
struct Fee {
	units: u64,
	recipient: [u8; 20],
}

fn parse_fee(
	fee_wei: Option<&str>,
	recipient: Option<&str>,
	unit: u128,
) -> Result<Option<Fee>, String> {
	let fee_wei = fee_wei.map(str::trim).filter(|s| !s.is_empty());
	let recipient = recipient.map(str::trim).filter(|s| !s.is_empty());
	match (fee_wei, recipient) {
		(None, None) => Ok(None),
		(Some(wei), Some(to)) => Ok(Some(Fee {
			units: to_units(parse_wei(wei)?, unit)?,
			recipient: parse_h160(to)?,
		})),
		_ => Err("fee_wei and fee_recipient go together".into()),
	}
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

fn secrets_of(out: &OutputNote, unit: u128) -> NoteSecrets {
	NoteSecrets {
		cm: hex_field(&out.cm_bytes()),
		cv: hex_field(&out.cv_bytes()),
		rho: hex_field(&fp_to_bytes(&out.note.rho)),
		amount_wei: wei_of(out.note.amount, unit),
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
	let unit = parse_unit(req.shielded_unit_wei.as_deref())?;
	let wei = parse_wei(&req.amount_wei)?;
	let units = to_units(wei, unit)?;
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
			fee_recipient: None,
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
		fee: 0,
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
		note: secrets_of(&out, unit),
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
	unit: u128,
	rng: &mut impl rand_core::RngCore,
) -> Result<(SpendNote, FieldBytes), String> {
	let wei = parse_wei(&req.amount_wei)?;
	let units = to_units(wei, unit)?;
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
	fee: Option<Fee>,
	unit: u128,
) -> Result<SpendRes, String> {
	let fee_units = fee.map_or(0, |f| f.units);
	let fee_recipient = fee.map(|f| f.recipient);
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
			fee: fee_units,
			fee_recipient: fee_recipient.as_ref().map(|r| r.as_slice()),
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
		fee: fee_units,
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
		amount_wei: wei_of(
			if transparent_out > 0 {
				transparent_out
			} else {
				outputs.first().map(|o| o.note.amount).unwrap_or(0)
			},
			unit,
		),
		fee_wei: wei_of(fee_units, unit),
		fee_recipient: fee_recipient.map(|r| hex_bytes(&r)),
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
		notes: outputs.iter().map(|o| secrets_of(o, unit)).collect(),
	})
}

pub fn transfer(req: TransferReq) -> Result<SpendRes, String> {
	if !is_valid_mask(req.mask_bits) {
		return Err("mask_bits must be 0..=15".into());
	}
	let unit = parse_unit(req.shielded_unit_wei.as_deref())?;
	let fee = parse_fee(req.fee_wei.as_deref(), req.fee_recipient.as_deref(), unit)?;
	let pay_units = to_units(parse_wei(&req.amount_wei)?, unit)?;
	let sk = parse_sk(&req.sk_hex)?;
	let recipient_pk = parse_fp(&req.recipient_pk)?;
	let mut rng = OsRng;
	let (spend, anchor) = open_spend(sk, &req.note, &req.leaves, unit, &mut rng)?;
	let change = change_of(spend.note.amount, pay_units, fee)?;
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
		fee,
		unit,
	)
}

pub fn unshield(req: UnshieldReq) -> Result<SpendRes, String> {
	if !is_valid_mask(req.mask_bits) {
		return Err("mask_bits must be 0..=15".into());
	}
	if hides_balance(req.mask_bits) {
		return Err(
			"a hide-balance bundle (mask bit 3) cannot unshield; pay privately instead".into(),
		);
	}
	let unit = parse_unit(req.shielded_unit_wei.as_deref())?;
	let fee = parse_fee(req.fee_wei.as_deref(), req.fee_recipient.as_deref(), unit)?;
	let out_units = to_units(parse_wei(&req.amount_wei)?, unit)?;
	let sk = parse_sk(&req.sk_hex)?;
	let recipient = parse_h160(&req.recipient)?;
	let mut rng = OsRng;
	let (spend, anchor) = open_spend(sk, &req.note, &req.leaves, unit, &mut rng)?;
	let change = change_of(spend.note.amount, out_units, fee)?;
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
		fee,
		unit,
	)
}

/// What stays in the sender's change note after the payment and the fee.
fn change_of(note: u64, pay: u64, fee: Option<Fee>) -> Result<u64, String> {
	pay.checked_add(fee.map_or(0, |f| f.units))
		.and_then(|spent| note.checked_sub(spent))
		.ok_or_else(|| "amount plus fee is larger than the selected note".into())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn unshield_req(extra: serde_json::Value) -> UnshieldReq {
		let mut req = serde_json::json!({
			"amount_wei": "40000000000",
			"mask_bits": 0,
			"expiry_block": 100,
			"sk_hex": format!("0x01{}", "00".repeat(31)),
			"recipient": format!("0x{}", "22".repeat(20)),
			"note": { "amount_wei": "42000000000", "rho": format!("0x{}", "00".repeat(32)), "leaf_index": 0 },
			"leaves": [],
		});
		if let (Some(base), Some(extra)) = (req.as_object_mut(), extra.as_object()) {
			base.extend(extra.clone());
		}
		serde_json::from_value(req).expect("request shape")
	}

	#[test]
	fn a_hide_balance_bundle_is_never_unshielded() {
		let err = unshield(unshield_req(serde_json::json!({ "mask_bits": 0b1000 })))
			.err()
			.expect("refused");

		assert!(err.contains("hide-balance"), "{err}");
	}

	#[test]
	fn a_fee_needs_its_recipient() {
		let err = unshield(unshield_req(serde_json::json!({ "fee_wei": "2000000000" })))
			.err()
			.expect("refused");

		assert!(err.contains("go together"), "{err}");
	}

	#[test]
	fn the_fee_comes_out_of_the_note_with_the_payment() {
		let fee = Some(Fee {
			units: 2,
			recipient: [0x33; 20],
		});

		assert_eq!(change_of(42, 40, fee), Ok(0));
		assert_eq!(change_of(42, 30, fee), Ok(10));
		assert!(change_of(42, 41, fee).is_err());
	}

	#[test]
	fn a_token_unit_scales_amounts() {
		let six_decimals = parse_unit(Some("1")).unwrap();

		assert_eq!(to_units(5, six_decimals), Ok(5));
		assert_eq!(to_units(5, SHIELDED_UNIT).ok(), None);
		assert_eq!(wei_of(5, six_decimals), "5");
		assert!(parse_unit(Some("0")).is_err());
		assert_eq!(parse_unit(None), Ok(SHIELDED_UNIT));
	}
}
