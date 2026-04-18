# Contributing to tokido-core

## Building

```bash
mvn verify
```

This runs compilation, tests, and the JaCoCo coverage gate (90% minimum).

## Adding a new FactorProvider

1. Create a new module: `tokido-core-yourfactor/`
2. Add `pom.xml` with parent reference and `tokido-core-api` dependency
3. Implement `FactorProvider<YourEnrollmentResult, YourVerificationResult>`
4. Write tests using `InMemorySecretStore` and `CollectingAuditSink` from `tokido-core-test`
5. Ensure coverage meets the 90% gate
6. Add the module to the parent `pom.xml` `<modules>` list
7. Open a PR

## PR requirements

- All tests pass (`mvn verify`)
- Coverage stays at or above 90%
- No new runtime dependencies without prior discussion (open an issue first)
- Code follows existing patterns (records for value types, fluent builders for config)

## Code style

- Java records for all value types and results
- No Lombok
- No framework annotations in core modules
- `final` fields, immutable collections where possible
- Package-private visibility by default; `public` only for API surface

## Reporting issues

Use GitHub Issues. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
