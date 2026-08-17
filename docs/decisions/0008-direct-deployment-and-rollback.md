# ADR 0008: Direct deployment and rollback

Status: accepted.

Deployment uses the packaged Linux binary directly rather than comparing it to
another implementation. Acceptance is one real read-only smoke observation, an
isolated alert/recovery exercise, and twelve successful timer runs. The previous
monitor remains disabled but available during the initial rollback window.
