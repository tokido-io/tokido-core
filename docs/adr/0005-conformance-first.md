# ADR-0005: OIDF conformance suite wired in CI from M0

**Status:** Accepted
**Date:** 2026-04-27

## Context

The OpenID Foundation publishes a conformance suite at `gitlab.com/openid/conformance-suite`. It is the executable spec for OIDC. Standing it up against a partial implementation late in the project means the first PR that wires it is huge and entangled with engine logic.

## Decision

Wire the suite into CI at M0, against a stub adapter that returns `501 Not Implemented` for every OIDC endpoint. The suite reports `0/47` on the basic certification test plan at M0. The number is the burn-up chart.

Concretely:

- `tokido-core-identity-conformance` module exists from M0.
- A JDK `HttpServer` stub adapter returns 501 for every OIDC endpoint.
- `OidcConformanceIT` boots the OIDF container via docker-compose, drives its REST API, asserts the pass-rate matches a per-milestone floor.
- A `oidc-conformance` GitHub Actions job runs every PR, in parallel with `mvn verify`.
- README badge shows the latest pass-rate.

## Consequences

- Every PR, from PR #1, is graded against the spec.
- Pass-rate must not regress on any PR (strict gate). Refactor PRs that move tests must update fixtures within the same PR.
- Pinning the OIDF Docker image SHA in `docker-compose.yml` insulates against upstream drift.
