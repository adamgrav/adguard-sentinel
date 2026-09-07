#!/usr/bin/env bash
# Linux-only, synthetic credential validation. No observations or notifications.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo "Run this check on a Linux host with systemd and Sentinel installed." >&2
  exit 2
fi

sentinel_binary="${1:-$(command -v adguard-sentinel || true)}"
if [[ -z "$sentinel_binary" || ! -x "$sentinel_binary" ]]; then
  echo "Pass the absolute path to an installed adguard-sentinel binary." >&2
  exit 2
fi
sentinel_binary="$(readlink -f -- "$sentinel_binary")"
for dependency in sudo systemd-run; do
  command -v "$dependency" > /dev/null || {
    echo "Missing required command: $dependency" >&2
    exit 2
  }
done

umask 077
sentinel_probe_dir="$(mktemp -d)"
sentinel_probe_unit="adguard-sentinel-credentials-$$"
trap 'rm -rf -- "$sentinel_probe_dir"' EXIT

for credential in resolver-password pushover-application-token pushover-user-key; do
  printf 'synthetic-secret\n' > "$sentinel_probe_dir/$credential"
done
cat > "$sentinel_probe_dir/config.toml" <<EOF
schema_version = 1

[notifications]
provider = "pushover"

[notifications.pushover]
application_token_file = "/run/credentials/$sentinel_probe_unit.service/pushover-application-token"
user_key_file = "/run/credentials/$sentinel_probe_unit.service/pushover-user-key"

[[targets]]
id = "resolver"
name = "Synthetic resolver"
base_url = "https://resolver.example.invalid"
auth = "basic"
username = "synthetic-user"
password_file = "/run/credentials/$sentinel_probe_unit.service/resolver-password"
EOF

sudo systemd-run --unit="$sentinel_probe_unit" --wait --pipe --collect \
  --property=DynamicUser=yes \
  --property="LoadCredential=config:$sentinel_probe_dir/config.toml" \
  --property="LoadCredential=resolver-password:$sentinel_probe_dir/resolver-password" \
  --property="LoadCredential=pushover-application-token:$sentinel_probe_dir/pushover-application-token" \
  --property="LoadCredential=pushover-user-key:$sentinel_probe_dir/pushover-user-key" \
  "$sentinel_binary" validate-config \
  --config "/run/credentials/$sentinel_probe_unit.service/config"

echo "PASS: the dynamic user validated private configuration and three synthetic credential files."
