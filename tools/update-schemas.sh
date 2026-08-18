#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT

cargo run --quiet --locked -p sentinel-cli -- print-schema config --version 1 \
  > "$temporary_directory/config-v1.schema.json"
cargo run --quiet --locked -p sentinel-cli -- print-schema run-report --version 1 \
  > "$temporary_directory/run-report-v1.schema.json"
cargo run --quiet --locked -p sentinel-cli -- print-schema state --version 1 \
  > "$temporary_directory/state-v1.sql"

mv -- "$temporary_directory/config-v1.schema.json" "$repository_root/schemas/config-v1.schema.json"
mv -- "$temporary_directory/run-report-v1.schema.json" "$repository_root/schemas/run-report-v1.schema.json"
mv -- "$temporary_directory/state-v1.sql" "$repository_root/schemas/state-v1.sql"
