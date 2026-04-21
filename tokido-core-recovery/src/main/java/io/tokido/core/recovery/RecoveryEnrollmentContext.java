package io.tokido.core.recovery;

/**
 * Type-safe enrollment input for {@link RecoveryCodeProvider}.
 *
 * <p>Recovery enrollment currently has no additional inputs, but this record provides
 * a stable, extensible shape for future enrollment options without relying on untyped maps.
 */
public record RecoveryEnrollmentContext() {
}

