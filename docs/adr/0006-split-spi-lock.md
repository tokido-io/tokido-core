# ADR-0006: Split SPI lock — core at M1, broker at M3

**Status:** Accepted
**Date:** 2026-04-27

## Context

Locking all seven storage SPIs at M1 forces decisions about `IdentityProviderStore` and `IdpHttpTransport` before the broker module has been driven against a real federation flow. Locking nothing until M3 leaves Projects B and C without a target.

## Decision

- M1 locks: `ClientStore`, `ResourceStore`, `TokenStore`, `UserStore`, `ConsentStore`, `KeyStore`. These are exercised by the engine MVP at M2 — locking them at M1 means Projects B and C can implement against frozen contracts while the engine is still in flight.
- M3 locks: `IdentityProviderStore`, `IdpHttpTransport`, and any other broker-side SPI (`AuthenticationStrategy` graduates at M4).
- Lock semantics: `apiguardian-api` `@API(STABLE)` on the type and its public members. `revapi-maven-plugin` enforces the lock — breaking changes fail CI.

## Consequences

- M1 unblocks Projects B and C for engine-side work.
- M3 unblocks Projects B and C for federation work.
- A second `revapi` baseline is set at M3 for the broker SPIs.
