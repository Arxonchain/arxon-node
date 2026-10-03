//! JSON in / JSON out, matching the local HTTP prover.

use wasm_bindgen::prelude::*;

fn wrap<T: serde::Serialize>(r: Result<T, String>) -> Result<String, JsError> {
	let v = r.map_err(|e| JsError::new(&e))?;
	serde_json::to_string(&v).map_err(|e| JsError::new(&e.to_string()))
}

/// Build C1/C2/C3 proving keys (slow the first time).
#[wasm_bindgen]
pub fn warm() {
	arxon_prove::warm_keys();
}

/// `POST /v1/keys`
#[wasm_bindgen]
pub fn keys(req_json: &str) -> Result<String, JsError> {
	let req = serde_json::from_str(req_json).map_err(|e| JsError::new(&e.to_string()))?;
	wrap(arxon_prove::keys(req))
}

/// `POST /v1/shield`
#[wasm_bindgen]
pub fn shield(req_json: &str) -> Result<String, JsError> {
	let req = serde_json::from_str(req_json).map_err(|e| JsError::new(&e.to_string()))?;
	wrap(arxon_prove::shield(req))
}

/// `POST /v1/transfer`
#[wasm_bindgen]
pub fn transfer(req_json: &str) -> Result<String, JsError> {
	let req = serde_json::from_str(req_json).map_err(|e| JsError::new(&e.to_string()))?;
	wrap(arxon_prove::transfer(req))
}

/// `POST /v1/unshield`
#[wasm_bindgen]
pub fn unshield(req_json: &str) -> Result<String, JsError> {
	let req = serde_json::from_str(req_json).map_err(|e| JsError::new(&e.to_string()))?;
	wrap(arxon_prove::unshield(req))
}
