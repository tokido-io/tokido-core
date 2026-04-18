package io.tokido.core;

import java.util.Map;

/**
 * Context passed to factor enrollment, carrying factor-specific properties.
 * For example, a TOTP factor might accept an account name for the otpauth URI.
 *
 * @param properties factor-specific key-value pairs
 */
public record EnrollmentContext(Map<String, Object> properties) {

    public static EnrollmentContext empty() {
        return new EnrollmentContext(Map.of());
    }

    public static EnrollmentContext of(String key, Object value) {
        return new EnrollmentContext(Map.of(key, value));
    }
}
