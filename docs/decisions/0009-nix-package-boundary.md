# ADR 0009: Nix package boundary

Status: accepted.

The repository exports the binary package, checks, formatter, and development
shell. It does not export a NixOS service module, so the flake stays free of
site-specific service opinions. Host integration — systemd credentials, timers,
external job-health reporting, hardening, deployment, cutover, and rollback — is
owned by the operator's own configuration.
