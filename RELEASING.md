# Versioning and releases

Release tags use `vMAJOR.MINOR.PATCH`. [CHANGELOG.md](CHANGELOG.md) records
changes and upgrade requirements; an `Unreleased` entry has not shipped.

## Compatibility

Sentinel is pre-1.0 with no external users. Run-report fields may be removed,
renamed, retyped, or change vocabulary or meaning in a patch or minor release
without a schema-version bump. This flexibility is intentional. Record each
change in the changelog and update generated schemas when types change; do not
introduce report versions solely to enforce a compatibility promise that begins
at 1.0.

The current report changes follow this policy. Existing SQLite v1 databases
require explicit migration to v2 before this checkout can read them. Historical
report interpretation is documented in
[SCHEMAS](docs/SCHEMAS.md#historical-reports).

At 1.0, report compatibility becomes a commitment: additive changes may retain
a schema version; incompatible changes require a new one. The binary/CLI follows
pre-1.0 semantic versioning, where a minor bump may break compatibility.
Configuration uses its own `schema_version`; a new configuration schema gets a
new number. SQLite uses `PRAGMA user_version`. These versions are independent
of the binary release.

SQLite upgrades are always explicit. `check` never migrates existing state;
[MIGRATION](docs/MIGRATION.md) describes the current command. A supported
AdGuard Home range must have evidence recorded in [SUPPORT](docs/SUPPORT.md).
The operator's explicit untested-range override is not a support claim.

## Release checklist

1. Finish and date the changelog entry for the planned release. Update any
   configuration, behavior, schema, or support documentation affected. For the
   current v2 state change, review migration and rollback acceptance.
2. Set the release version in the workspace, internal crate requirements, and
   `flake.nix`, and update the pinned installation examples. Regenerate
   `Cargo.lock` with Cargo; do not edit it by hand.
3. Run `nix develop -c just check`. Review the diff and any deployment acceptance
   needed for changed runtime or installation behavior.
4. After the release changes are merged, verify that CI passes on that `main`
   commit: both native Linux Nix jobs and the rustup source-build job.
5. With explicit authorization, create the tag and release from the reviewed
   release commit. Verify its version, date, commit, and notes before publishing.

A green build establishes package and test results, not live resolver, timer,
or notification acceptance. Releases currently contain source only.
