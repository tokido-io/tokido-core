package io.tokido.core;

import java.util.Map;

/**
 * Status of a user's enrollment in a specific factor.
 *
 * @param enrolled   whether the user has an enrollment record
 * @param confirmed  whether the enrollment has been confirmed (always true for factors that don't require confirmation)
 * @param attributes factor-specific attributes (e.g., backup codes remaining, last used timestamp)
 */
public record FactorStatus(boolean enrolled, boolean confirmed, Map<String, Object> attributes) {

    public static FactorStatus notEnrolled() {
        return new FactorStatus(false, false, Map.of());
    }
}
