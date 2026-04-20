package io.tokido.core.engine;

import io.tokido.core.*;
import io.tokido.core.spi.AuditSink;
import io.tokido.core.spi.FactorProvider;
import io.tokido.core.spi.SecretStore;

import java.time.Instant;
import java.util.*;

/**
 * Central entry point for MFA operations. Coordinates factor providers,
 * enforces enrollment lifecycle rules, and emits audit events.
 *
 * <h2>Enrollment lifecycle</h2>
 *
 * <p>Factors that require confirmation (e.g., TOTP) follow a two-step enrollment:
 * <ol>
 *   <li>{@link #enroll} — generates and stores the secret, returns setup data (URI, QR code).
 *       The factor is inactive until confirmed. The engine sets {@code confirmed=false} in the
 *       store immediately after the provider's {@code store()} call.</li>
 *   <li>{@link #confirmEnrollment} — the user supplies a credential generated from the new factor.
 *       On success, the engine sets {@code confirmed=true}. Only then will {@link #verify} accept
 *       credentials for this factor.</li>
 * </ol>
 *
 * <p>Factors that do not require confirmation (e.g., recovery codes) are active immediately
 * after {@link #enroll}.
 *
 * <h2>SecretStore interaction</h2>
 *
 * <p>The engine interacts with {@link SecretStore} as documented on that interface — see its
 * class-level Javadoc for the exact callback sequence per operation. Key rules:
 * <ul>
 *   <li>The engine is the sole owner of the {@code confirmed} flag
 *       ({@link SecretStore.Metadata#CONFIRMED}). Factor providers must not set it.</li>
 *   <li>The engine calls {@link SecretStore#update} with partial metadata — implementations
 *       must merge, not replace.</li>
 * </ul>
 *
 * <h2>Setup</h2>
 * <pre>{@code
 * MfaManager mfa = MfaManager.builder()
 *     .secretStore(store)
 *     .auditSink(sink)
 *     .factor(new TotpFactorProvider(config, store))
 *     .factor(new RecoveryCodeProvider(config, store))
 *     .build();
 * }</pre>
 */
public class MfaManager {

    private final SecretStore secretStore;
    private final AuditSink auditSink;
    private final Map<String, FactorProvider<?, ?>> factors;

    private MfaManager(Builder builder) {
        this.secretStore = Objects.requireNonNull(builder.secretStore, "secretStore is required");
        this.auditSink = builder.auditSink != null ? builder.auditSink : AuditSink.noop();
        if (builder.factors.isEmpty()) {
            throw new IllegalArgumentException("At least one FactorProvider must be registered");
        }
        this.factors = Map.copyOf(builder.factors);
    }

    /**
     * Enroll a user in a factor.
     *
     * <p>SecretStore calls made during this operation:
     * <ol>
     *   <li>{@code exists()} — throws {@link AlreadyEnrolledException} if already enrolled</li>
     *   <li>Provider calls {@code store()} with the initial secret and metadata</li>
     *   <li>If {@code requiresConfirmation()}: {@code update({confirmed: false})} — the engine
     *       sets this flag; the factor is inactive until {@link #confirmEnrollment} succeeds</li>
     * </ol>
     *
     * @return factor-specific enrollment data (e.g., {@code TotpEnrollmentResult} for TOTP)
     * @throws AlreadyEnrolledException if the user is already enrolled in this factor
     * @throws FactorNotRegisteredException if the factor type is not registered with this manager
     */
    @SuppressWarnings("unchecked")
    public <E extends EnrollmentResult> E enroll(String userId, String factorType, EnrollmentContext ctx) {
        FactorProvider<E, ?> provider = (FactorProvider<E, ?>) requireFactor(factorType);

        if (secretStore.exists(userId, factorType)) {
            throw new AlreadyEnrolledException(userId, factorType);
        }

        E result = provider.enroll(userId, ctx);

        if (provider.requiresConfirmation()) {
            // The engine owns the confirmed lifecycle. Setting confirmed=false here marks the
            // enrollment as pending. The provider must NOT set this flag in its store() call.
            secretStore.update(userId, factorType, Map.of(SecretStore.Metadata.CONFIRMED, false));
        }

        audit(userId, factorType, "enrolled");
        return result;
    }

    /**
     * Confirm a pending enrollment by verifying a credential generated from the new factor.
     *
     * <p>Only applicable to factors where {@code requiresConfirmation()} is true (e.g., TOTP).
     * The user must supply a valid credential (e.g., a 6-digit TOTP code) produced by the
     * authenticator app after scanning the QR code returned by {@link #enroll}.
     *
     * <p>SecretStore calls made during this operation:
     * <ol>
     *   <li>{@code load()} — reads current state including {@code confirmed} flag</li>
     *   <li>Provider verifies credential internally without persisting verification progress
     *       (e.g. TOTP does not advance {@code lastCounter} / {@code lastUsedAt} here)</li>
     *   <li>On success: {@code update({confirmed: true})}</li>
     * </ol>
     *
     * @throws NotEnrolledException if the user has no enrollment record for this factor
     * @throws MfaException if the factor does not require confirmation, or is already confirmed
     */
    public VerificationResult confirmEnrollment(String userId, String factorType, String credential) {
        FactorProvider<?, ?> provider = requireFactor(factorType);

        StoredSecret stored = secretStore.load(userId, factorType);
        if (stored == null) {
            throw new NotEnrolledException(userId, factorType);
        }

        if (!provider.requiresConfirmation()) {
            throw new MfaException("Factor '%s' does not require confirmation".formatted(factorType));
        }

        Boolean confirmed = (Boolean) stored.metadata().get(SecretStore.Metadata.CONFIRMED);
        if (confirmed != null && confirmed) {
            throw new MfaException("Enrollment for user '%s' factor '%s' is already confirmed"
                    .formatted(userId, factorType));
        }

        VerificationResult result = provider.verify(userId, credential, VerificationContext.enrollmentConfirmation());
        if (result.valid()) {
            secretStore.update(userId, factorType, Map.of(SecretStore.Metadata.CONFIRMED, true));
            audit(userId, factorType, "confirmed");
        } else {
            audit(userId, factorType, "confirmation_failed");
        }
        return result;
    }

    /**
     * Verify a credential for an enrolled, confirmed factor.
     *
     * <p>If the factor requires confirmation and the enrollment is not yet confirmed,
     * returns an invalid result with reason {@code "unconfirmed"} without throwing.
     *
     * <p>SecretStore calls made during this operation:
     * <ol>
     *   <li>{@code load()} — reads current state</li>
     *   <li>If unconfirmed: returns failure immediately, no further calls</li>
     *   <li>Provider verifies and — on success — calls {@code update()} with progress metadata
     *       (e.g., {@code lastCounter} for TOTP, consumed {@code hashedCodes} for recovery)</li>
     * </ol>
     *
     * @throws NotEnrolledException if the user has no enrollment record for this factor
     */
    public VerificationResult verify(String userId, String factorType, String credential) {
        FactorProvider<?, ?> provider = requireFactor(factorType);

        StoredSecret stored = secretStore.load(userId, factorType);
        if (stored == null) {
            throw new NotEnrolledException(userId, factorType);
        }

        if (provider.requiresConfirmation()) {
            Boolean confirmed = (Boolean) stored.metadata().get(SecretStore.Metadata.CONFIRMED);
            if (confirmed == null || !confirmed) {
                audit(userId, factorType, "verification_failed");
                return new SimpleVerificationResult(false, "unconfirmed");
            }
        }

        VerificationResult result = provider.verify(userId, credential, VerificationContext.empty());
        audit(userId, factorType, result.valid() ? "verified" : "verification_failed");
        return result;
    }

    /**
     * Remove a user's enrollment in a factor.
     *
     * <p>SecretStore calls made during this operation:
     * <ol>
     *   <li>{@code exists()} — throws {@link NotEnrolledException} if not enrolled</li>
     *   <li>Provider performs internal cleanup (built-in providers make no store calls)</li>
     *   <li>{@code delete()}</li>
     * </ol>
     *
     * @throws NotEnrolledException if the user is not enrolled in this factor
     */
    public void unenroll(String userId, String factorType) {
        FactorProvider<?, ?> provider = requireFactor(factorType);

        if (!secretStore.exists(userId, factorType)) {
            throw new NotEnrolledException(userId, factorType);
        }

        provider.unenroll(userId);
        secretStore.delete(userId, factorType);
        audit(userId, factorType, "unenrolled");
    }

    /**
     * Query the enrollment status for a user and factor.
     *
     * <p>SecretStore calls: {@code load()}.
     *
     * @throws FactorNotRegisteredException if the factor type is not registered
     */
    public FactorStatus status(String userId, String factorType) {
        FactorProvider<?, ?> provider = requireFactor(factorType);
        return provider.status(userId);
    }

    /**
     * Query enrollment status for all registered factors for a user.
     *
     * <p>SecretStore calls: {@code load()} once per registered factor.
     */
    public Map<String, FactorStatus> allFactors(String userId) {
        Map<String, FactorStatus> result = new LinkedHashMap<>();
        for (String factorType : factors.keySet()) {
            result.put(factorType, status(userId, factorType));
        }
        return result;
    }

    private FactorProvider<?, ?> requireFactor(String factorType) {
        FactorProvider<?, ?> provider = factors.get(factorType);
        if (provider == null) {
            throw new FactorNotRegisteredException(factorType);
        }
        return provider;
    }

    private void audit(String userId, String factorType, String action) {
        auditSink.emit(new AuditEvent(userId, factorType, action, Instant.now(), Map.of()));
    }

    // --- Builder ---

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private SecretStore secretStore;
        private AuditSink auditSink;
        private final Map<String, FactorProvider<?, ?>> factors = new LinkedHashMap<>();

        public Builder secretStore(SecretStore secretStore) {
            this.secretStore = secretStore;
            return this;
        }

        public Builder auditSink(AuditSink auditSink) {
            this.auditSink = auditSink;
            return this;
        }

        public Builder factor(FactorProvider<?, ?> provider) {
            this.factors.put(provider.factorType(), provider);
            return this;
        }

        public MfaManager build() {
            return new MfaManager(this);
        }
    }

    /**
     * Simple verification result used internally for lifecycle rejections (e.g., unconfirmed).
     */
    record SimpleVerificationResult(boolean valid, String reason) implements VerificationResult {
        @Override
        public java.util.Optional<String> failureReason() {
            return java.util.Optional.ofNullable(reason);
        }
    }
}
