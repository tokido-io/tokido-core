# ADR-0008: Refresh token rotation policy

**Status:** Accepted
**Date:** 2026-05-01

## Context

OAuth 2.0 refresh tokens trade short-lived access tokens for new ones. Without rotation, a leaked refresh token grants long-lived access. With naive rotation, replay attacks are detectable.

## Decision

- **Default policy: `RefreshTokenUsage.ONE_TIME`** per client (set on `Client.refreshTokenUsage`). Each `/token` call with `grant_type=refresh_token` consumes the prior refresh token and issues a new one.
- **Theft detection:** If a `ONE_TIME` refresh token is presented after it has been consumed (i.e., its `consumedTime` is non-null in `TokenStore`), the engine MUST revoke every refresh token in the same family — implemented by calling `TokenStore.removeAll(subjectId, clientId, GrantType.REFRESH_TOKEN)`. The `/token` call returns `invalid_grant`. Project A doc §11 defers refresh-token-family tracking to a future milestone; M2.RC2 (where refresh handling first lands) ships the simple "revoke all by (subject, client)" rule.
- **Optional `RefreshTokenUsage.REUSE`** behavior: each refresh keeps the existing handle. No theft detection. Only intended for very specific compatibility scenarios.
- **Refresh token format: opaque handle.** Stored as a `PersistedGrant` with type `REFRESH_TOKEN`. Refresh token handles are never JWTs.
- **Refresh token lifetime** is per-client (`Client.refreshTokenLifetime`).

## Consequences

- The conformance suite's refresh-related modules (RC2 work) test ONE_TIME by default.
- Implementations of `TokenStore.removeAll(subject, client, type)` MUST be atomic for theft detection to be sound.
- Refresh tokens cannot be introspected via JWT-decode at the resource server; introspection MUST go through the engine's `introspect()` endpoint (M2 final).
