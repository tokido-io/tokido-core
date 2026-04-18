# tokido-core

Production-grade MFA toolkit for Java. TOTP, recovery codes, extensible factors. GraalVM native-image ready.

[![CI](https://github.com/ozimakov/tokido-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ozimakov/tokido-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Why tokido-core?

- **Full enrollment lifecycle** — not just code verification, but enroll, confirm, verify, recover, and unenroll with audit events on every transition
- **Pluggable secret storage** — you choose how secrets are stored and encrypted (KMS, Vault, local keystore). The library never makes that decision for you.
- **GraalVM native-image ready** — no AWT, no runtime reflection. QR codes generated with pure `java.util.zip`.
- **Zero framework dependencies** — works with Quarkus, Spring Boot, Micronaut, or plain Java
- **Extensible factors** — TOTP and recovery codes ship in v1. Add WebAuthn, email OTP, or SMS by implementing `FactorProvider`.

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
git clone https://github.com/ozimakov/tokido-core.git
cd tokido-core
mvn verify
```

Requires Java 21+.

## Used in production by

[Tokido](https://tokido.io) — MFA-as-a-Service platform

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
