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
 * <p>
 * Create via the {@link Builder}:
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

    @SuppressWarnings("unchecked")
    public <E extends EnrollmentResult> E enroll(String userId, String factorType, EnrollmentContext ctx) {
        FactorProvider<E, ?> provider = (FactorProvider<E, ?>) requireFactor(factorType);

        if (secretStore.exists(userId, factorType)) {
            throw new AlreadyEnrolledException(userId, factorType);
        }

        E result = provider.enroll(userId, ctx);

        if (provider.requiresConfirmation()) {
            secretStore.update(userId, factorType, Map.of("confirmed", false));
        }

        audit(userId, factorType, "enrolled");
        return result;
    }

    public VerificationResult confirmEnrollment(String userId, String factorType, String credential) {
        FactorProvider<?, ?> provider = requireFactor(factorType);

        StoredSecret stored = secretStore.load(userId, factorType);
        if (stored == null) {
            throw new NotEnrolledException(userId, factorType);
        }

        if (!provider.requiresConfirmation()) {
            throw new MfaException("Factor '%s' does not require confirmation".formatted(factorType));
        }

        Boolean confirmed = (Boolean) stored.metadata().get("confirmed");
        if (confirmed != null && confirmed) {
            throw new MfaException("Enrollment for user '%s' factor '%s' is already confirmed"
                    .formatted(userId, factorType));
        }

        VerificationResult result = provider.verify(userId, credential, VerificationContext.empty());
        if (result.valid()) {
            secretStore.update(userId, factorType, Map.of("confirmed", true));
            audit(userId, factorType, "confirmed");
        } else {
            audit(userId, factorType, "confirmation_failed");
        }
        return result;
    }

    public VerificationResult verify(String userId, String factorType, String credential) {
        FactorProvider<?, ?> provider = requireFactor(factorType);

        StoredSecret stored = secretStore.load(userId, factorType);
        if (stored == null) {
            throw new NotEnrolledException(userId, factorType);
        }

        if (provider.requiresConfirmation()) {
            Boolean confirmed = (Boolean) stored.metadata().get("confirmed");
            if (confirmed == null || !confirmed) {
                audit(userId, factorType, "verification_failed");
                return new SimpleVerificationResult(false, "unconfirmed");
            }
        }

        VerificationResult result = provider.verify(userId, credential, VerificationContext.empty());
        audit(userId, factorType, result.valid() ? "verified" : "verification_failed");
        return result;
    }

    public void unenroll(String userId, String factorType) {
        FactorProvider<?, ?> provider = requireFactor(factorType);

        if (!secretStore.exists(userId, factorType)) {
            throw new NotEnrolledException(userId, factorType);
        }

        provider.unenroll(userId);
        secretStore.delete(userId, factorType);
        audit(userId, factorType, "unenrolled");
    }

    public FactorStatus status(String userId, String factorType) {
        requireFactor(factorType);

        StoredSecret stored = secretStore.load(userId, factorType);
        if (stored == null) {
            return FactorStatus.notEnrolled();
        }

        FactorProvider<?, ?> provider = factors.get(factorType);
        return provider.status(userId);
    }

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
