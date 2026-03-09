.PHONY: fmt clippy build test test-g729 test-integration test-docker test-all docker-up docker-down lint sipcli check

fmt:
	cargo fmt

clippy:
	cargo clippy -- -D warnings

build:
	cargo build

test:
	cargo test

test-g729:
	cargo test --features g729-codec -- g729

test-integration:
	cargo test --features integration --test integration_test -- --nocapture --test-threads=1

test-docker: docker-up test-integration docker-down

docker-up:
	docker compose -f testutil/docker/docker-compose.yml up -d --wait

docker-down:
	docker compose -f testutil/docker/docker-compose.yml down

test-all: test test-docker

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
