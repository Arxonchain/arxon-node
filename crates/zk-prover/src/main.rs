//! Local HTTP front for [`arxon_prove`]. Listens on 127.0.0.1 only.
//!
//! * `POST /v1/keys` — spending key + shielded pk
//! * `POST /v1/shield` — C1 + C2 deposit into a note this wallet owns
//! * `POST /v1/transfer` — C3 + C1 + C2 note-to-note pay
//! * `POST /v1/unshield` — C3 + C2 (and C1 if change) pay a public 0x
//!
//! Browsers may only call it from the origins in `ARXON_PROVE_ORIGINS`
//! (comma separated, default: localhost pages). Any other web page gets no CORS
//! headers, so it cannot drive the prover and burn the user's CPU. Requests are
//! capped at [`MAX_REQUEST`] bytes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use arxon_prove::{keys, shield, transfer, unshield};
use serde::Serialize;

const BIND: &str = "127.0.0.1:17871";
/// Largest request accepted (headers and body). Proof requests are a few KiB plus
/// the note tree leaves the wallet sends.
const MAX_REQUEST: usize = 4 * 1024 * 1024;
/// Origins allowed when `ARXON_PROVE_ORIGINS` is unset.
const DEFAULT_ORIGINS: &str = "http://localhost,http://127.0.0.1";

/// `true` iff `origin` is allowed. An allowlist entry without a port matches
/// that scheme and host on any port.
fn origin_allowed(origin: &str, allowlist: &str) -> bool {
	allowlist
		.split(',')
		.map(str::trim)
		.filter(|o| !o.is_empty())
		.any(|allowed| {
			origin == allowed
				|| origin.strip_prefix(allowed).is_some_and(|rest| {
					rest.starts_with(':') && rest[1..].bytes().all(|b| b.is_ascii_digit())
				})
		})
}

fn allowlist() -> String {
	std::env::var("ARXON_PROVE_ORIGINS").unwrap_or_else(|_| DEFAULT_ORIGINS.to_string())
}

fn respond(
	stream: &mut TcpStream,
	origin: Option<&str>,
	status: &str,
	body: &str,
	content_type: &str,
) {
	let cors = match origin {
		Some(o) if origin_allowed(o, &allowlist()) => format!(
			"Access-Control-Allow-Origin: {o}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
		),
		_ => String::new(),
	};
	let _ = write!(
		stream,
		"HTTP/1.1 {status}\r\n{cors}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	);
}

fn json_err(e: impl ToString) -> String {
	serde_json::json!({ "error": e.to_string() }).to_string()
}

fn read_http(stream: &mut TcpStream) -> Option<String> {
	let mut buf = Vec::new();
	let mut tmp = [0u8; 4096];
	loop {
		let n = stream.read(&mut tmp).ok()?;
		if n == 0 {
			break;
		}
		buf.extend_from_slice(&tmp[..n]);
		if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
			let headers = std::str::from_utf8(&buf[..pos]).ok()?.to_ascii_lowercase();
			let want = headers
				.lines()
				.find_map(|l| l.strip_prefix("content-length:"))
				.and_then(|v| v.trim().parse::<usize>().ok())
				.unwrap_or(0);
			let start = pos + 4;
			let end = start.checked_add(want).filter(|end| *end <= MAX_REQUEST)?;
			while buf.len() < end {
				let n = stream.read(&mut tmp).ok()?;
				if n == 0 {
					break;
				}
				buf.extend_from_slice(&tmp[..n]);
			}
			break;
		}
		if buf.len() > MAX_REQUEST {
			return None;
		}
	}
	String::from_utf8(buf).ok()
}

fn handle_json<T: serde::de::DeserializeOwned, R: Serialize>(
	body: &str,
	f: impl FnOnce(T) -> Result<R, String>,
	stream: &mut TcpStream,
	origin: Option<&str>,
) {
	match serde_json::from_str::<T>(body) {
		Err(e) => respond(
			stream,
			origin,
			"400 Bad Request",
			&json_err(e),
			"application/json",
		),
		Ok(req) => match f(req) {
			Ok(res) => {
				let json = serde_json::to_string(&res).expect("json");
				respond(stream, origin, "200 OK", &json, "application/json");
			}
			Err(e) => respond(
				stream,
				origin,
				"400 Bad Request",
				&json_err(e),
				"application/json",
			),
		},
	}
}

/// Value of the `Origin` header, if any.
fn origin_of(head: &str) -> Option<&str> {
	head.lines().skip(1).find_map(|line| {
		let (name, value) = line.split_once(':')?;
		name.trim()
			.eq_ignore_ascii_case("origin")
			.then(|| value.trim())
	})
}

fn handle(mut stream: TcpStream) {
	let Some(req) = read_http(&mut stream) else {
		return;
	};
	let head = req.split("\r\n\r\n").next().unwrap_or("");
	let first = head.lines().next().unwrap_or("");
	let origin = origin_of(head);
	// A web page outside the allowlist must not make the prover do any work: a
	// "simple" text/plain POST skips the CORS preflight, so refuse it up front.
	if let Some(o) = origin {
		if !origin_allowed(o, &allowlist()) {
			respond(
				&mut stream,
				None,
				"403 Forbidden",
				"{\"error\":\"origin not allowed\"}",
				"application/json",
			);
			return;
		}
	}
	if first.starts_with("OPTIONS ") {
		respond(&mut stream, origin, "204 No Content", "", "text/plain");
		return;
	}
	if first.starts_with("GET /health") {
		respond(
			&mut stream,
			origin,
			"200 OK",
			"{\"ok\":true}",
			"application/json",
		);
		return;
	}
	let path = first.split_whitespace().nth(1).unwrap_or("");
	let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
	if path.starts_with("/v1/keys") && first.starts_with("POST ") {
		handle_json(body, keys, &mut stream, origin);
		return;
	}
	if path.starts_with("/v1/shield") && first.starts_with("POST ") {
		handle_json(body, shield, &mut stream, origin);
		return;
	}
	if path.starts_with("/v1/transfer") && first.starts_with("POST ") {
		handle_json(body, transfer, &mut stream, origin);
		return;
	}
	if path.starts_with("/v1/unshield") && first.starts_with("POST ") {
		handle_json(body, unshield, &mut stream, origin);
		return;
	}
	respond(
		&mut stream,
		origin,
		"404 Not Found",
		"{\"error\":\"not found\"}",
		"application/json",
	);
}

fn main() {
	eprintln!("warming Halo2 proving keys (C1, C2, C3) — first run can take several minutes");
	arxon_prove::warm_keys();
	let listener = TcpListener::bind(BIND).expect("bind 127.0.0.1:17871");
	eprintln!("arxon-prove listening on http://{BIND}");
	for stream in listener.incoming() {
		match stream {
			Ok(s) => {
				thread::spawn(move || handle(s));
			}
			Err(e) => eprintln!("accept: {e}"),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{origin_allowed, origin_of};

	const LIST: &str = "http://localhost, https://app.arxon.io";

	#[test]
	fn allowlisted_origins_pass_with_or_without_a_port() {
		assert!(origin_allowed("http://localhost", LIST));
		assert!(origin_allowed("http://localhost:5173", LIST));
		assert!(origin_allowed("https://app.arxon.io", LIST));
	}

	#[test]
	fn other_origins_and_lookalikes_are_refused() {
		assert!(!origin_allowed("https://evil.example", LIST));
		assert!(!origin_allowed("http://localhost.evil.example", LIST));
		assert!(!origin_allowed("http://localhost:80abc", LIST));
		assert!(!origin_allowed("https://app.arxon.io.evil.example", LIST));
		assert!(!origin_allowed("http://localhost", ""));
	}

	#[test]
	fn origin_header_is_read_case_insensitively() {
		let head = "POST /v1/keys HTTP/1.1\r\nHost: x\r\nORIGIN: https://evil.example";
		assert_eq!(origin_of(head), Some("https://evil.example"));
		assert_eq!(origin_of("GET /health HTTP/1.1\r\nHost: x"), None);
	}
}
