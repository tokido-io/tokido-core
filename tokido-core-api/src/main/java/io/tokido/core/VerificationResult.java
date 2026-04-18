package io.tokido.core;

/**
 * Marker interface for factor-specific verification results.
 * All implementations must report whether verification succeeded.
 */
public interface VerificationResult {
    boolean valid();
}
