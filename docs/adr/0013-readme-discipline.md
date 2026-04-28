# ADR-0013: README is part of the release

**Status:** Accepted
**Date:** 2026-04-27

## Context

A library's README is the first artifact a prospective adopter reads. If it lags reality, every adopter is misled until someone notices.

## Decision

Each release tag (`0.1.0-MX`) is preceded by a README sync. The README at all times reflects:

1. Current capability — what works, what's stubbed, what's not yet implemented.
2. Module status table — per module: introduced-at, locked-at, current `@API` status, current line coverage. (Template in `project-a-detailed-plan.md` Appendix C.)
3. Conformance pass-rate and link to the latest CI report.
4. Three badges at the top:
   - CI status — GitHub Actions `mvn verify` workflow.
   - Codecov — line coverage (added in commit `9bf134d`, retained and extended to identity modules).
   - OIDC conformance — pass-rate from the latest `oidc-conformance` job.

## Consequences

- A release PR that doesn't update the README is a release that doesn't go out.
- CONTRIBUTING.md gets a "README is part of the release" line.
- Reviewer-enforced; the only automated check is markdown link-check in CI.
- Mid-milestone PRs refresh the README only if they change surface a downstream consumer would care about.
