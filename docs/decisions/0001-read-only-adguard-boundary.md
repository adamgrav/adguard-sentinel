# ADR 0001: Read-only AdGuard boundary

Status: accepted.

The AdGuard adapter exposes only six typed GET methods. Endpoint construction is
private, accepts no arbitrary path or HTTP method, never builds a request body,
and disables redirects. Query logs and mutation APIs are absent. Pushover POST
delivery is isolated in the CLI notification adapter.
