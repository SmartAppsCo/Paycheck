# Versioning

Paycheck follows [Semantic Versioning](https://semver.org/) (SemVer).

## Version Format

`MAJOR.MINOR.PATCH[-PRERELEASE]`

- **MAJOR** - Breaking changes to the public API
- **MINOR** - New features, backward compatible
- **PATCH** - Bug fixes, backward compatible
- **PRERELEASE** - Optional suffix for pre-release versions

### Prerelease Labels

- `1.0.0-alpha.1` - Early testing, incomplete features, expect breakage
- `1.0.0-beta.1` - Feature complete, needs real-world testing
- `1.0.0-rc.1` - Release candidate, final testing before stable

Prerelease versions sort before their release counterpart: `1.0.0-alpha.1 < 1.0.0-beta.1 < 1.0.0-rc.1 < 1.0.0`

## What Constitutes the Public API

- HTTP API endpoints (paths, methods, request/response shapes)
- JWT claim structure
- SDK public interfaces
- CLI arguments and behavior
- Configuration environment variables

## What Is NOT Part of the Public API

- Internal database schema
- Log message formats
- Undocumented behavior
- Private/internal code structure

## Pre-1.0

While the version is `0.x.y`, the API is considered unstable. Minor versions may include breaking changes. We'll document these in the changelog.

## Changelog

All notable changes are documented in [CHANGELOG.md](CHANGELOG.md).
