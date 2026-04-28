# ADR-0001: Duende IdentityServer as design reference; no source/binary dependency

**Status:** Accepted
**Date:** 2026-04-27

## Context

The OIDC extension to `tokido-core` needs a domain model (Client, scopes, persisted grants, refresh-token policies) that has been validated by production use. Re-deriving every shape from RFCs would burn weeks and likely converge on shapes Duende IdentityServer has already shipped for years.

## Decision

- Duende IdentityServer is a **design reference** for SPI shapes, value-type fields, and storage contracts.
- No source code is copied. No binary or transitive dependency on Duende artifacts at any scope.
- Class names that carry distinctive Duende vocabulary are renamed before M1 lock. Concretely:
  - `PersistedGrantStore` → `TokenStore` (already in scope).
  - `IdentityResource` → `IdentityScope`.
  - `ApiResource` → `ProtectedResource`.
  - `ApiScope` → `ResourceScope`.
- Field shapes (sets, durations, enums) follow Duende's where battle-tested. Java idiom adjustments (records, `Set<>`, `Duration`) are applied without further justification.

## Consequences

- No license-attribution obligation to Duende. Apache 2.0 grants of `tokido-core` apply unchanged.
- Java developers familiar with Duende will recognize the model with native names.
- ADR-0006 governs which SPIs lock when; this ADR governs naming and shape inheritance.
