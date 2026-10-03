//! Local HTTP front for [`arxon_prove`]. Listens on 127.0.0.1 only.
//!
//! * `POST /v1/keys` — spending key + shielded pk
//! * `POST /v1/shield` — C1 + C2 deposit into a note this wallet owns
//! * `POST /v1/transfer` — C3 + C1 + C2 note-to-note pay
//! * `POST /v1/unshield` — C3 + C2 (and C1 if change) pay a public 0x

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use arxon_prove::{keys, shield, transfer, unshield};
use serde::Serialize;

const BIND: &str = "127.0.0.1:17871";

fn respond(stream: &mut TcpStream, status: &str, body: &str, content_type: &str) {
	let _ = write!(
		stream,
		"HTTP/1.1 {status}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
			while buf.len() < start + want {
				let n = stream.read(&mut tmp).ok()?;
				if n == 0 {
					break;
				}
				buf.extend_from_slice(&tmp[..n]);
			}
			break;
		}
		if buf.len() > 512 * 1024 {
			return None;
		}
	}
	String::from_utf8(buf).ok()
}

fn handle_json<T: serde::de::DeserializeOwned, R: Serialize>(
	body: &str,
	f: impl FnOnce(T) -> Result<R, String>,
	stream: &mut TcpStream,
) {
	match serde_json::from_str::<T>(body) {
		Err(e) => respond(stream, "400 Bad Request", &json_err(e), "application/json"),
		Ok(req) => match f(req) {
			Ok(res) => {
				let json = serde_json::to_string(&res).expect("json");
				respond(stream, "200 OK", &json, "application/json");
			}
			Err(e) => respond(stream, "400 Bad Request", &json_err(e), "application/json"),
		},
	}
}

fn handle(mut stream: TcpStream) {
	let Some(req) = read_http(&mut stream) else {
		return;
	};
	let head = req.split("\r\n\r\n").next().unwrap_or("");
	let first = head.lines().next().unwrap_or("");
	if first.starts_with("OPTIONS ") {
		respond(&mut stream, "204 No Content", "", "text/plain");
		return;
	}
	if first.starts_with("GET /health") {
		respond(&mut stream, "200 OK", "{\"ok\":true}", "application/json");
		return;
	}
	let path = first.split_whitespace().nth(1).unwrap_or("");
	let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
	if path.starts_with("/v1/keys") && first.starts_with("POST ") {
		handle_json(body, keys, &mut stream);
		return;
	}
	if path.starts_with("/v1/shield") && first.starts_with("POST ") {
		handle_json(body, shield, &mut stream);
		return;
	}
	if path.starts_with("/v1/transfer") && first.starts_with("POST ") {
		handle_json(body, transfer, &mut stream);
		return;
	}
	if path.starts_with("/v1/unshield") && first.starts_with("POST ") {
		handle_json(body, unshield, &mut stream);
		return;
	}
	respond(
		&mut stream,
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
