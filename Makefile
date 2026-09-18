export RUSTFLAGS := -D warnings $(RUSTFLAGS)
export RUSTDOCFLAGS := -D warnings $(RUSTDOCFLAGS)

.DEFAULT_GOAL := check

.PHONY: nextest-prerequisite feature-prerequisites doc check test test-fast lint check-features

nextest-prerequisite:
	@command -v cargo-nextest >/dev/null || { echo "missing cargo-nextest" >&2; exit 1; }

feature-prerequisites:
	@command -v cargo-hack >/dev/null || { echo "missing cargo-hack" >&2; exit 1; }
	@command -v rustup >/dev/null || { echo "missing rustup" >&2; exit 1; }
	@rustup target list --installed | grep -qx wasm32-unknown-unknown || { echo "missing rustup target wasm32-unknown-unknown" >&2; exit 1; }

doc:
	cargo doc --no-deps --workspace --exclude bulletproofs-cycle
	cargo doc --no-deps -p golden-rustcrypto --features p256,k256
	cargo doc --no-deps -p golden-evrf --features halo2curves-secp256k1
	cargo doc --no-deps -p golden-evrf --features bls12-381-jubjub
	cargo doc --no-deps -p bulletproofs-cycle
	cargo doc --no-deps -p bulletproofs-cycle --no-default-features --features bulletproofs-compat

check: doc
	cargo fmt --all --check
	cargo check --all-targets --workspace

test: nextest-prerequisite
	cargo nextest run -p golden-core
	cargo nextest run -p golden-core --features serde,miden-serde
	cargo nextest run -p golden-rustcrypto --features p256
	cargo nextest run -p golden-rustcrypto --features k256
	cargo nextest run -p golden-evrf --features golden-rustcrypto/p256
	cargo nextest run -p golden-ehtdh1 --features prototype-bridge
	cargo nextest run -p golden-halo2curves --features halo2curves-secp256k1
	cargo nextest run -p golden-bls-jubjub
	cargo nextest run -p bulletproofs-cycle --no-default-features --features bulletproofs-compat
	cargo nextest run -p golden-ehtdh1 --features serde,miden-serde
	cargo nextest run -p bulletproofs-cycle --features ristretto
	cargo nextest run -p golden-evrf --features serde,miden-serde,halo2curves-secp256k1
	cargo nextest run -p bulletproofs-cycle --features ristretto,parallel
	cargo nextest run -p golden-evrf --features halo2curves-secp256k1,parallel
	cargo nextest run -p golden-evrf --features bls12-381-jubjub
	cargo nextest run -p golden-evrf --features bls12-381-jubjub,parallel
	cargo test --workspace --doc

test-fast: nextest-prerequisite
	cargo nextest run --workspace --features golden-rustcrypto/p256,golden-rustcrypto/k256,golden-ehtdh1/prototype-bridge,golden-evrf/halo2curves-secp256k1,golden-halo2curves/halo2curves-secp256k1,golden-evrf/bls12-381-jubjub
	cargo nextest run -p bulletproofs-cycle --no-default-features --features bulletproofs-compat
	cargo test --workspace --doc

lint:
	cargo clippy --all --benches --tests --examples --all-features --exclude bulletproofs-cycle -- -D warnings
	cargo clippy -p bulletproofs-cycle --benches --tests -- -D warnings
	cargo clippy -p bulletproofs-cycle --benches --tests --no-default-features --features bulletproofs-compat -- -D warnings

check-features: feature-prerequisites
	cargo hack check --workspace --each-feature --exclude-features default,bulletproofs-compat --all-targets
	cargo check -p golden-ehtdh1 --example threshold_records --features prototype-bridge
	cargo check --target wasm32-unknown-unknown -p golden-core -p golden-ehtdh1 -p golden-halo2curves --features golden-halo2curves/halo2curves-secp256k1
	@tree_file=$$(mktemp) || exit 1; trap 'rm -f "$$tree_file"' EXIT HUP INT TERM; \
		cargo tree -p golden-core > "$$tree_file" || exit 1; \
		if grep -E '(^|[[:space:]])(p256|k256|ark-|bls|frost|pairing)' "$$tree_file"; then \
			exit 1; \
		else \
			status=$$?; test "$$status" -eq 1; \
		fi
