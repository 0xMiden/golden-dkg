export RUSTFLAGS := -D warnings $(RUSTFLAGS)
export RUSTDOCFLAGS := -D warnings $(RUSTDOCFLAGS)

.DEFAULT_GOAL := check

PROOF_FEATURES := secp-secq,jubjub-bls12-381,serde
NATIVE_FEATURES := golden-core/insecure-revealed-witness,golden-core/serde,golden-core/miden-serde,golden-curves/secp256k1,golden-curves/jubjub,golden-bulletproofs/secp-secq,golden-bulletproofs/jubjub-bls12-381,golden-bulletproofs/serde,golden-ehtdh1/serde,golden-ehtdh1/miden-serde

.PHONY: nextest-prerequisite feature-prerequisites doc check test test-fast test-slow lint check-features fixtures

nextest-prerequisite:
	@command -v cargo-nextest >/dev/null || { echo "missing cargo-nextest" >&2; exit 1; }

feature-prerequisites:
	@command -v cargo-hack >/dev/null || { echo "missing cargo-hack" >&2; exit 1; }
	@rustup target list --installed | grep -qx wasm32-unknown-unknown || { echo "missing rustup target wasm32-unknown-unknown" >&2; exit 1; }

doc:
	cargo doc --no-deps --workspace --features $(NATIVE_FEATURES)
	cargo doc --no-deps -p bulletproofs-cycle --no-default-features --features bulletproofs-compat

check:
	cargo fmt --all --check
	cargo check --workspace --all-targets
	cargo check --workspace --all-targets --features $(NATIVE_FEATURES)

lint:
	cargo clippy --workspace --all-targets --exclude bulletproofs-cycle --features $(NATIVE_FEATURES),golden-bulletproofs/parallel -- -D warnings
	cargo clippy -p bulletproofs-cycle --all-targets --features ristretto,serde,parallel -- -D warnings
	cargo clippy -p bulletproofs-cycle --all-targets --no-default-features --features bulletproofs-compat -- -D warnings

test: nextest-prerequisite
	cargo nextest run -p golden-core --features insecure-revealed-witness,serde,miden-serde
	cargo nextest run -p golden-curves --features secp256k1,jubjub
	cargo nextest run -p golden-ehtdh1 --features serde,miden-serde
	cargo nextest run -p golden-bulletproofs --features $(PROOF_FEATURES)
	cargo nextest run -p golden-bulletproofs --features $(PROOF_FEATURES),parallel
	cargo nextest run -p bulletproofs-cycle --features ristretto,serde
	cargo nextest run -p bulletproofs-cycle --features ristretto,parallel
	cargo nextest run -p bulletproofs-cycle --no-default-features --features bulletproofs-compat
	cargo test --workspace --doc --features $(NATIVE_FEATURES)

test-fast: nextest-prerequisite
	cargo nextest run --workspace --features $(NATIVE_FEATURES)

test-slow: nextest-prerequisite
	cargo nextest run -p golden-bulletproofs --profile release --features $(PROOF_FEATURES) --run-ignored only
	cargo nextest run -p golden-ehtdh1 --profile release --run-ignored only
	cargo run -p golden-ehtdh1 --profile optimized --example threshold_records

check-features: feature-prerequisites
	cargo hack check --workspace --each-feature --exclude-features default,bulletproofs-compat --all-targets
	cargo check --target wasm32-unknown-unknown -p golden-core -p golden-ehtdh1 -p golden-curves --features golden-core/serde,golden-core/miden-serde,golden-ehtdh1/serde,golden-ehtdh1/miden-serde,golden-curves/secp256k1,golden-curves/jubjub
	@tree_file=$$(mktemp) || exit 1; trap 'rm -f "$$tree_file"' EXIT HUP INT TERM; \
		cargo tree -p golden-core --edges normal > "$$tree_file" || exit 1; \
		! grep -E '(^|[[:space:]])(halo2curves|jubjub|bls12_381|bulletproofs)' "$$tree_file"

fixtures:
	cargo run -p golden-bulletproofs --profile optimized --features secp-secq,jubjub-bls12-381 --example check_fixtures
