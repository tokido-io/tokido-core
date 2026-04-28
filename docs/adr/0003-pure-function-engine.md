# ADR-0003: Engine as pure-function façade

**Status:** Accepted
**Date:** 2026-04-27

## Context

Frameworks like Spring and Quarkus each have their own HTTP request/response abstractions. A protocol library that imports either is locked to that framework. A protocol library that owns its own HTTP layer reinvents Servlet/JAX-RS poorly.

## Decision

`IdentityEngine` exposes pure-function methods: `(request value type, AuthenticationState) → result value type`. The engine never reads from a socket, never writes to a socket, never sleeps, never owns a thread pool.

Framework adapters (Project B `tokido-spring`, Project C `tokido-quarkus`) translate HTTP requests into engine value types and engine results back into HTTP responses. That is their entire job.

## Consequences

- The engine is testable without a server.
- Native-image friendly — no reflection, no proxies, no `ServiceLoader`.
- The `tokido-core-identity-conformance` module pairs the engine with a JDK `HttpServer` adapter for testing only; this is not the production adapter.
- ArchUnit tests in every identity module assert no Spring/Quarkus/Jakarta/Servlet/JAX-RS imports.
