# ADR-0004: Six-release cadence (one tag per milestone)

**Status:** Accepted
**Date:** 2026-04-27

## Context

The high-level project-A plan listed one public release at M5 (`0.1.0-alpha`). That denies downstream Projects B and C any release-pinned dependency target until the entire 18–22 week effort completes. It also denies the project a public heartbeat.

## Decision

Six releases, one per milestone, all published to Maven Central:

| Tag | Milestone |
|---|---|
| `0.1.0-M0` | Scaffolding + conformance harness (this milestone) |
| `0.1.0-M1` | Core SPI lock — public unblock event for Projects B and C |
| `0.1.0-M2` | Engine MVP — conformance ≥ 80% |
| `0.1.0-M3` | Broker MVP + broker SPI lock — second unblock event |
| `0.1.0-M4` | MFA bridge — conformance ≥ 85% |
| `0.1.0-alpha` | Capstone — conformance ≥ 95%, native-image PR-blocking |

Work proceeds in a single linear track on `main` (squash-merge). One PR at a time.

## Consequences

- Release ceremony every 2–10 weeks. Acceptable overhead for the public signal it provides.
- M1 and M3 are explicit downstream-unblock announcements (release notes, pinned issue).
- M2 is the longest milestone; it carries internal-only sub-tags `0.1.0-M2.RC1`, `0.1.0-M2.RC2` (git tags, not Central-published) to give it a beat.
