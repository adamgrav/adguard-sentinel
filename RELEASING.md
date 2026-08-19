# Versioning and releases

How AdGuard Sentinel is versioned and released. For what changed in each
release, see [CHANGELOG.md](CHANGELOG.md).

Sentinel follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with
the pre-1.0 caveat that a minor bump may break compatibility. Read the changelog
before upgrading.

Four things are versioned independently, and only the first is the release
number:

| Surface | Versioned by | Compatibility rule |
| --- | --- | --- |
| The binary and CLI | The release tag | Pre-1.0: a minor bump may change flags or output |
| Configuration | `schema_version` in the TOML | A new schema version is a breaking change and gets a new number |
| Run report JSON | `schema_version` in the report | Additive fields may appear in a patch release; removals and type changes require a new version. Pre-1.0 caveat: a field may also be renamed or its value vocabulary changed in a patch, called out in the changelog, because the alternative is carrying a known-wrong interface to 1.0 |
| SQLite state | `PRAGMA user_version` | Upgraded only by `migrate-state`, never implicitly by `check` |

Consequences worth knowing:

- `check` never migrates state. A newer binary meeting older state exits `5` and
  tells you to run `migrate-state`, so an upgrade cannot silently rewrite
  history.
- The supported AdGuard Home API range is part of the compatibility surface.
  Widening it needs evidence against the new version and is at least a minor
  bump.
- Anything `docs/SUPPORT.md` marks **Pending** or **Expected** is not a
  compatibility promise.

### Release process

Releases are tagged `vMAJOR.MINOR.PATCH` from `main` after both CI jobs pass. A
tag is only created once its acceptance evidence exists, so a green tag means the
package built and the suite ran, not that a deployment was validated.

The release date is filled in at tag time; an entry marked "unreleased" has not
shipped.
