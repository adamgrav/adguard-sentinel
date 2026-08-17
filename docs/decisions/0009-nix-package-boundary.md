# ADR 0009: Nix package boundary

Status: accepted.

The repository exports the binary package, checks, formatter, and development
shell. It does not export a public NixOS service module. The dotfiles repository
continues to own systemd credentials, timers, Healthchecks, hardening,
deployment, cutover, and rollback.
