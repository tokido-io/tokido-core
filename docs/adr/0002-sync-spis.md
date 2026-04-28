# ADR-0002: Synchronous blocking SPIs

**Status:** Accepted
**Date:** 2026-04-27

## Context

The OIDC engine calls into storage SPIs (`ClientStore`, `TokenStore`, etc.) on every request. A choice between synchronous (blocking) and asynchronous (`CompletableFuture` / reactive) signatures affects every implementer downstream in Projects B and C.

## Decision

All SPIs are synchronous and blocking. They throw checked exceptions where appropriate; they do not return `CompletableFuture` / `Mono` / `Flux`.

## Rationale

- Matches the existing `tokido-core` SPI style (`SecretStore`, `FactorProvider`, `AuditSink` are all sync).
- On JDK 21, virtual threads make blocking I/O essentially free at the framework adapter layer (Tomcat 11+, Quarkus 3+).
- A reactive variant can be added later as a separate `tokido-core-identity-reactive` module that wraps the sync SPIs.
- The OIDF conformance suite drives the engine via HTTP — synchronous semantics are easier to reason about in a conformance harness.

## Consequences

- Implementers in Projects B/C wrap blocking calls in virtual threads or worker pools as native to their framework.
- The engine is free to use straightforward Java without the cognitive overhead of reactive composition.
