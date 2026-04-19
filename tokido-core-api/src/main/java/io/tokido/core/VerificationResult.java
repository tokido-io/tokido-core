package io.tokido.core;

import java.util.Optional;

/**
 * Marker interface for factor-specific verification results.
 * All implementations must report whether verification succeeded.
 * <p>
 * Factor-specific results may also expose a {@link #failureReason()} string
 * (e.g. "invalid", "replay") to aid error handling by callers.
 */
public interface VerificationResult {
    boolean valid();

    /**
     * Optional machine-readable failure reason.
     * Present when {@link #valid()} is {@code false} and the factor provides one.
     * Examples: {@code "invalid"}, {@code "replay"}, {@code "unconfirmed"}.
     */
    default Optional<String> failureReason() {
        return Optional.empty();
    }
}
