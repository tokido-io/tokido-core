package io.tokido.core;

/**
 * Marker interface for factor-specific enrollment results.
 * Each {@link io.tokido.core.spi.FactorProvider} defines its own result type
 * carrying factor-specific data (e.g., secret URI, QR code, recovery codes).
 */
public interface EnrollmentResult {
}
