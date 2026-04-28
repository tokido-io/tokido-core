# tokido-core

Production-grade MFA toolkit for Java. TOTP, recovery codes, extensible factors. GraalVM native-image ready.

[![CI](https://github.com/tokido-io/tokido-core/actions/workflows/ci.yml/badge.svg)](https://github.com/tokido-io/tokido-core/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/tokido-io/tokido-core/graph/badge.svg)](https://codecov.io/gh/tokido-io/tokido-core)
[![OIDC conformance](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/tokido-io/tokido-core/gh-pages/badges/conformance.json)](https://github.com/tokido-io/tokido-core/actions/workflows/oidc-conformance.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Why tokido-core?

- **Full enrollment lifecycle** — not just code verification, but enroll, confirm, verify, recover, and unenroll with audit events on every transition
- **Pluggable secret storage** — you choose how secrets are stored and encrypted (KMS, Vault, local keystore). The library never makes that decision for you.
- **GraalVM native-image ready** — no AWT, no runtime reflection. QR codes generated with pure `java.util.zip`.
- **Zero framework dependencies** — works with Quarkus, Spring Boot, Micronaut, or plain Java
- **Extensible factors** — TOTP and recovery codes ship in v1. Add WebAuthn, email OTP, or SMS by implementing `FactorProvider`.

## OIDC extension status (in development — alpha)

The OIDC extension is being built across six releases (M0 → M5). The current release is **`0.1.0-M0`** — scaffolding and conformance harness only; no engine code yet.

**OIDC basic conformance: 0/N** (M0 baseline — stub adapter returns `501 Not Implemented` for all endpoints; conformance pass-rate climbs as the engine implementation lands at M2 onward.)

| Module | Introduced | API status | Coverage | Notes |
|---|---|---|---|---|
| `tokido-core-identity-api` | M0 | empty skeleton | n/a | SPIs and protocol value types land at M1 |
| `tokido-core-identity-engine` | M0 | empty skeleton | n/a | Engine façade and handlers land at M1–M2 |
| `tokido-core-identity-jwt` | M2 (placeholder pom in M0) | not yet introduced | n/a | Nimbus-backed JWT signing; lands at M2 |
| `tokido-core-identity-broker` | M3 (placeholder pom in M0) | not yet introduced | n/a | OIDC RP federation; lands at M3 |
| `tokido-core-identity-mfa` | M4 (placeholder pom in M0) | not yet introduced | n/a | Bridge to existing MFA modules; lands at M4 |

See `docs/adr/` for architectural decisions.

## Quick start

```xml
<dependency>
    <groupId>io.tokido</groupId>
    <artifactId>tokido-core-engine</artifactId>
    <version>1.0.0</version>
</dependency>
<dependency>
    <groupId>io.tokido</groupId>
    <artifactId>tokido-core-totp</artifactId>
    <version>1.0.0</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.tokido</groupId>
    <artifactId>tokido-core-recovery</artifactId>
    <version>1.0.0</version>
    <scope>runtime</scope>
</dependency>
```

```java
// 1. Plug in your secret store
SecretStore store = new YourKmsSecretStore();

// 2. Build the MFA manager
MfaManager mfa = MfaManager.builder()
    .secretStore(store)
    .auditSink(event -> log.info("mfa: {}", event))
    .factor(new TotpFactorProvider(TotpConfig.defaults().issuer("MyApp"), store))
    .factor(new RecoveryCodeProvider(store))
    .build();

// 3. Enroll a user
TotpEnrollmentResult totp = mfa.enroll(userId, "totp", EnrollmentContext.empty());
// totp.secretUri()    → otpauth://totp/...
// totp.qrCodeBase64() → PNG QR code

// 4. Confirm enrollment (user proves they scanned the QR)
mfa.confirmEnrollment(userId, "totp", codeFromAuthenticatorApp);

// 5. Generate recovery codes
RecoveryEnrollmentResult recovery = mfa.enroll(userId, "recovery", EnrollmentContext.empty());
// recovery.codes() → ["04819237", "91847203", ...] — show once

// 6. Verify
VerificationResult result = mfa.verify(userId, "totp", codeFromUser);
if (!result.valid()) {
    // Try recovery code
    result = mfa.verify(userId, "recovery", recoveryCodeFromUser);
}
```

## Modules

| Module | Description | Dependencies |
|--------|-------------|--------------|
| `tokido-core-api` | SPIs and value types | none |
| `tokido-core-engine` | `MfaManager` — enrollment lifecycle coordinator | `tokido-core-api` |
| `tokido-core-totp` | TOTP factor with replay protection and QR generation | `tokido-core-api`, ZXing core |
| `tokido-core-recovery` | Recovery codes with bcrypt hashing | `tokido-core-api`, jBCrypt |
| `tokido-core-test` | `InMemorySecretStore` and `CollectingAuditSink` for testing | `tokido-core-api` |

## Security model

tokido-core **never stores or encrypts secrets**. You must provide a `SecretStore` implementation that handles encryption and persistence. This is a deliberate design choice:

- The library can't accidentally leak plaintext secrets
- You choose the encryption strategy (KMS envelope, Vault transit, local PKCS#12)
- You choose the storage backend (database, S3, file system)
- You own the key management lifecycle

For testing, use `InMemorySecretStore` from `tokido-core-test`.

## Building

```bash
git clone https://github.com/tokido-io/tokido-core.git
cd tokido-core
mvn verify
```

Requires Java 21+.

## Coverage

Line coverage is measured with [JaCoCo](https://www.jacoco.org/jacoco/) during `mvn verify` (minimum **90%** per module bundle). HTML reports are written under each module, for example `tokido-core-engine/target/site/jacoco/index.html`.

CI publishes reports to [Codecov](https://codecov.io/gh/tokido-io/tokido-core) (interactive tree and history). The badge above tracks default-branch coverage; PRs get a diff once the repository is connected to Codecov.

## Used in production by

[Tokido](https://tokido.io) — MFA-as-a-Service platform

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
