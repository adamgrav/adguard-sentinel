set shell := ["bash", "-euo", "pipefail", "-c"]

fmt:
  cargo fmt --all
  nixfmt flake.nix

fmt-check:
  cargo fmt --all -- --check
  nixfmt --check flake.nix

lint:
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test:
  cargo test --locked --workspace --all-features

build:
  cargo build --locked --workspace --all-targets --all-features

schema-check:
  bash tools/check-schemas.sh

# Requires network access to refresh the RustSec advisory database.
supply-chain:
  cargo deny --locked check advisories licenses bans sources

check: fmt-check lint test build schema-check supply-chain
