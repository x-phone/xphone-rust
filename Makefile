.PHONY: fmt clippy build test test-integration lint sipcli check

fmt:
	cargo fmt

clippy:
	cargo clippy -- -D warnings

build:
	cargo build

test:
	cargo test

test-integration:
	cargo test --features integration --test integration_test -- --nocapture --test-threads=1

lint: fmt clippy

sipcli:
	cargo build --example sipcli --features cli --release
	@echo "Binary: target/release/examples/sipcli"

install-sipcli:
	cargo build --example sipcli --features cli --release
	cp target/release/examples/sipcli $(HOME)/bin/sipcli
	@echo "Installed to $(HOME)/bin/sipcli"

# Full verification gate — run before committing.
check: fmt clippy test
