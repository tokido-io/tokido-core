# ADR-0010: Versioning strategy for the OIDC extension module set

**Status:** Accepted
**Date:** 2026-04-27

## Context

`tokido-core` is gaining a new module set (`tokido-core-identity-*`) whose maturity is alpha while the existing modules are at `1.2.0-SNAPSHOT` and stable. Maven multi-module projects typically share one version across all children, but mixing alpha-quality and stable artifacts under one version line conflates very different signals to consumers.

## Decision

Split-version scheme:

- Parent POM: `2.0.0-MX-SNAPSHOT` during a milestone, released as `2.0.0-MX` at the milestone tag (e.g., `2.0.0-M0`, `2.0.0-M1`, …, `2.0.0-alpha` at M5).
- Existing modules (`tokido-core-api`, `-test`, `-engine`, `-totp`, `-recovery`) inherit the parent version. They republish unchanged each milestone — a few KB per artifact on Maven Central, accepted cost.
- New identity modules (`tokido-core-identity-api`, `-engine`, `-jwt`, `-broker`, `-mfa`) carry an explicit `<version>0.1.0-MX-SNAPSHOT</version>` that overrides the parent. They release as `0.1.0-MX` per milestone.
- The conformance module (`tokido-core-identity-conformance`) is test-only and never published.
- Git tag: `0.1.0-MX` (the identity headline). Existing modules at `2.0.0-MX` ride along.

## Consequences

- Two version lines coexist in the repo. Maven supports this via explicit `<version>` overrides on children.
- Release tooling (the `release` profile) must be exercised against a `0.1.0-M0` tag at M0 to confirm the split-publish works end-to-end.
- Future major version bumps to existing modules (e.g., `2.0.0` GA) decouple naturally from identity-line bumps.

## Alternatives rejected

- Single version (everything at `2.0.0-MX`): conflates alpha and stable maturity signals.
- Identity-only release with parent stuck at SNAPSHOT: Maven requires resolvable parent at release time, blocks the approach.

## Release tooling

The CI release workflow (`.github/workflows/release.yml`) does **not** auto-bump versions from the tag. The maintainer bumps versions manually before tagging:

- Parent: `2.0.0-MX-SNAPSHOT` → `2.0.0-MX`
- Identity children: `0.1.0-MX-SNAPSHOT` → `0.1.0-MX`
- All `<parent><version>` references in children: bumped to match
- The `<tokido.core.version>` property in parent (used by `dependencyManagement` for existing-modules cross-deps): bumped to match the parent

The release workflow runs `mvn deploy -P release` and trusts the tagged commit's poms to be release-ready. A guard step fails the workflow fast if any pom still has `-SNAPSHOT`.

Why manual: Maven's `versions:set` plugin operates on the whole reactor with one version, which is incompatible with the split-version scheme. Custom shell-XML editing in CI to handle the split would be brittle. Manual maintainer edits are deterministic and reviewable in the release PR.
