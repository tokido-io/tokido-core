package io.tokido.core;

import java.util.Map;

/**
 * Context passed to factor verification, carrying factor-specific properties.
 *
 * @param properties factor-specific key-value pairs
 */
public record VerificationContext(Map<String, Object> properties) {

    public static VerificationContext empty() {
        return new VerificationContext(Map.of());
    }
}
