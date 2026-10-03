# Build browser Halo2 prover into arxon-mobile/public/prove (and arxon-wallet if present).
# Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli matching crates.io wasm-bindgen 0.2

param(
	[string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Repos = Split-Path $Root
$Targets = @()
if ($OutDir) {
	$Targets += $OutDir
} else {
	$Mobile = Join-Path $Repos "arxon-mobile\public\prove"
	$Wallet = Join-Path $Repos "arxon-wallet\public\prove"
	if (Test-Path (Split-Path $Mobile)) { $Targets += $Mobile }
	if (Test-Path (Split-Path $Wallet)) { $Targets += $Wallet }
	if ($Targets.Count -eq 0) {
		throw "no arxon-mobile or arxon-wallet public/ next to this repo"
	}
}

rustup target add wasm32-unknown-unknown | Out-Null
cargo build -p arxon-prove-wasm --target wasm32-unknown-unknown --release
$Wasm = Join-Path $Root "target\wasm32-unknown-unknown\release\arxon_prove_wasm.wasm"
if (-not (Test-Path $Wasm)) {
	throw "missing $Wasm"
}

foreach ($Out in $Targets) {
	New-Item -ItemType Directory -Force -Path $Out | Out-Null
	wasm-bindgen $Wasm --target no-modules --out-dir $Out --out-name arxon_prove
	# Classic-script `let` is not window.wasm_bindgen; the Vite app is an ES module and cannot see it.
	$Js = Join-Path $Out "arxon_prove.js"
	$Glue = Get-Content -Raw $Js
	$Glue = $Glue -replace '(?m)^let wasm_bindgen;','var wasm_bindgen;'
	Set-Content -Path $Js -Value $Glue -NoNewline
	Write-Host "wrote $Out"
}
