.PHONY: setup
# Setup development environment
setup:
	bash ./scripts/setup-dev.sh

.PHONY: clean
# Cleanup compilation outputs
clean:
	cargo clean

.PHONY: fmt-check fmt
# Check the code format
fmt-check:
	taplo fmt --check
	cargo fmt --all -- --check
# Format the code
fmt:
	taplo fmt
	cargo fmt --all

.PHONY: clippy clippy-release
# Run rust clippy with debug profile
clippy:
	SKIP_WASM_BUILD=1 cargo clippy --all --all-targets --features=runtime-benchmarks,try-runtime -- -D warnings
# Run rust clippy with release profile
clippy-release:
	SKIP_WASM_BUILD=1 cargo clippy --release --all --all-targets --features=runtime-benchmarks,try-runtime -- -D warnings

.PHONY: check check-release
# Check code with debug profile
check:
	cargo check
# Check code with release profile
check-release:
	cargo check --release

.PHONY: build build-release
# Build all binaries with debug profile
build:
	WASM_BUILD_TYPE=debug cargo build
# Build all binaries with release profile
build-release:
	WASM_BUILD_TYPE=release cargo build --release

.PHONY: test test-release
# Run all unit tests with debug profile
test:
	cargo test --lib --all
	cargo test --lib --all --features=runtime-benchmarks
	# Run fc-mapping-sync tests with SQL feature to ensure both backends are tested
	cargo test --lib -p fc-mapping-sync --features=sql
# Run all unit tests with release profile
test-release:
	cargo test --release --lib --all
	cargo test --release --lib --all --features=runtime-benchmarks
	# Run fc-mapping-sync tests with SQL feature to ensure both backends are tested
	cargo test --release --lib -p fc-mapping-sync --features=sql

.PHONY: test-zk test-zk-e2e measure-zk check-wasm
# Run the Halo2 circuit, host function and primitives tests in release (real IPA proofs)
test-zk:
	cargo test --release -p arxon-zk-primitives -p arxon-zk -p arxon-zk-host
# Run the runtime end to end privacy tests (real proofs through the pallets) in release
test-zk-e2e:
	SKIP_WASM_BUILD=1 cargo test --release -p arxon-runtime --lib -- zk_integration
# Print proof sizes, proving and verifying times and VK hashes of every circuit
measure-zk:
	cargo run --release -p arxon-zk --example measure
# Type check the no_std crates the runtime embeds against the Wasm target
check-wasm:
	RUSTFLAGS="--cfg substrate_runtime" cargo check --target wasm32v1-none --no-default-features \
		-p arxon-zk-primitives --features arxon-zk-primitives/poseidon \
		-p arxon-zk-host -p arxon-zk-runtime-api \
		-p pallet-zk-verifier -p pallet-nullifier-registry -p pallet-note-tree \
		-p pallet-privacy -p pallet-ptr -p pallet-evm-precompile-arxon-zk

.PHONY: integration-test integration-test-lint
# Check code format and lint of integration tests
integration-test-lint:
	cd ts-tests && npm install && npm run fmt-check
# Run all integration tests
integration-test: build-release integration-test-lint
	cd ts-tests && npm run build && npm run test && npm run test-sql

.PHONY: help
# Show help
help:
	@echo ''
	@echo 'Usage:'
	@echo ' make [target]'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
	helpMessage = match(lastLine, /^# (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")); \
			helpMessage = substr(lastLine, RSTART + 2, RLENGTH); \
			printf "\033[36m%-30s\033[0m %s\n", helpCommand,helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
