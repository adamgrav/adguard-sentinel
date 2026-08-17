# Fixture provenance

All API fixtures are synthetic and use RFC 5737 addresses and reserved
`.invalid` names. Their shapes were authored against AdGuard Home v0.107.78's
tagged OpenAPI specification. They contain no query-log records, real client
identities, credentials, private hostnames, or copied UI content.

The Python oracle under `legacy/python-v1/` is a frozen copy of Adam's current
dotfiles monitor. It is original project source, is test-only, and is not linked
into the runtime binary.
