package io.tokido.core.engine;

import io.tokido.core.EnrollmentContext;

import java.util.Objects;

/**
 * One factor enrollment request used by {@link MfaManager#enroll(String, java.util.List)}.
 *
 * @param factorType factor identifier (e.g. {@code "totp"}, {@code "recovery"})
 * @param ctx        enrollment context for the factor
 */
public record FactorEnrollment(String factorType, EnrollmentContext ctx) {

    public FactorEnrollment {
        Objects.requireNonNull(factorType, "factorType");
        Objects.requireNonNull(ctx, "ctx");
    }
}

