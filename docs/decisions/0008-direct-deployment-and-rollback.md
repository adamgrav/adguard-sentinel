# ADR 0008: Direct deployment and rollback

Status: accepted.

Deployment installs the packaged Linux binary directly. Acceptance is judged
against this repository's documented behavior contract, not against any other
monitor's output: one real read-only smoke observation, an isolated
alert/recovery exercise, and twelve successful timer runs. Where Sentinel
replaces an existing monitor, that monitor remains disabled but available
during an initial rollback window.
