# ADR-0007: Signing key rotation policy

**Status:** Accepted
**Date:** 2026-05-01

## Context

The OIDC engine signs access tokens and ID tokens with a `SigningKey` from the configured `KeyStore`. Tokens have lifetimes measured in minutes; signing keys must rotate without invalidating in-flight tokens.

## Decision

- **One active key per algorithm at a time.** New tokens are signed with whatever `KeyStore.activeSigningKey(alg)` returns at the moment of signing.
- **Retired keys remain in JWKS** for the duration of the longest issued token. Concretely, when a key transitions from `ACTIVE` to `RETIRED`, it stays in `KeyStore.allKeys()` for at least `max(client.accessTokenLifetime)` across all clients.
- **`kid` is always set** in the JWS header so verifiers can pick the right key from JWKS.
- **The engine never rotates keys itself.** Rotation is an admin op outside the engine's surface; an admin-side API (e.g., `RotatableKeyStore` extending `KeyStore`) may land in a future milestone. M2.RC1 ships with `InMemoryKeyStore` that generates one key on construction; rotation in production happens via the `KeyStore` implementation supplied by the framework adapter (Project B/C).
- **`KeyRotationPolicy`** is a value-type record (in `tokido-core-identity-jwt`, since it's signing-side) holding `gracePeriod` (`Duration`) and `algorithms` (`Set<SignatureAlgorithm>`). Stays out of the M1 SPI lock; engine reads it via `JwksRenderer` to filter what's published. Lands at M2.RC2 alongside refresh-token rotation; M2.RC1 ships JwksRenderer without filtering.

## Consequences

- Any verifier that checks JWS signatures can do so against the JWKS endpoint, picking the key by `kid`.
- Forced key compromise requires a coordinated `KeyStore` swap + revocation; the engine does not expose a "kill key" admin op at M2.RC1.
- The M0-era hard-coded RS256 stays the default at M2.RC1; ES256 and EdDSA support is exercised by `NimbusTokenSigner` round-trip tests but not yet driven through the engine.
