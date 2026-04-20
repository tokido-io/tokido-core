package io.tokido.core;

import io.tokido.core.spi.FactorProvider;

import java.util.Map;

/**
 * Context passed to factor verification, carrying factor-specific properties for the
 * {@link FactorProvider#verify(String, String, VerificationContext)} SPI.
 * <p>
 * <strong>Built-in providers:</strong> the TOTP factor reads
 * {@link #SKIP_VERIFICATION_PROGRESS_PERSISTENCE} when set by the engine for
 * {@code MfaManager.confirmEnrollment}. Other built-in factors ignore {@code properties};
 * pass {@link #empty()} unless you are using a custom {@link FactorProvider} that documents
 * supported keys.
 * <p>
 * This type exists so custom factors can accept structured verification-time inputs in a
 * forward-compatible way without changing the SPI signature.
 *
 * @param properties factor-specific key-value pairs
 */
public record VerificationContext(Map<String, Object> properties) {

    /**
     * Property key. When {@link Boolean#TRUE}, successful verification must validate the
     * credential but must not persist replay / usage progress (e.g. TOTP {@code lastCounter}).
     * The MFA engine sets this for {@code MfaManager.confirmEnrollment}; {@code MfaManager.verify}
     * always uses a context where this flag is absent or false.
     */
    public static final String SKIP_VERIFICATION_PROGRESS_PERSISTENCE =
            "io.tokido.skipVerificationProgressPersistence";

    public static VerificationContext empty() {
        return new VerificationContext(Map.of());
    }

    /**
     * Context used by {@code MfaManager.confirmEnrollment} so factors can validate a credential
     * without advancing replay state that must apply only after enrollment is confirmed.
     */
    public static VerificationContext enrollmentConfirmation() {
        return new VerificationContext(Map.of(SKIP_VERIFICATION_PROGRESS_PERSISTENCE, Boolean.TRUE));
    }

    /**
     * Whether successful verification should persist factor progress (replay counters, etc.).
     * Returns false only when {@link #SKIP_VERIFICATION_PROGRESS_PERSISTENCE} is {@code true}.
     */
    public static boolean shouldPersistVerificationProgress(VerificationContext ctx) {
        return !Boolean.TRUE.equals(ctx.properties().get(SKIP_VERIFICATION_PROGRESS_PERSISTENCE));
    }
}
