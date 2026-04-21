package io.tokido.core.recovery;

import io.tokido.core.EnrollmentContext;

import java.util.Objects;

/**
 * Boundary helpers for converting typed recovery enrollment inputs into the SPI {@link EnrollmentContext}.
 */
public final class RecoveryEnrollmentContexts {

    private RecoveryEnrollmentContexts() {}

    public static EnrollmentContext enrollment() {
        return EnrollmentContext.empty();
    }

    public static EnrollmentContext enrollment(RecoveryEnrollmentContext ctx) {
        Objects.requireNonNull(ctx, "ctx");
        return enrollment();
    }
}

