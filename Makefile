.PHONY: build test lint clean

build:
	cargo build --release

test:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
