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

licenses:
  cargo deny --locked check licenses bans sources

check: fmt-check lint test build schema-check licenses
