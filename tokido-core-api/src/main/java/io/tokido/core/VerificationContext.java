package io.tokido.core;

import io.tokido.core.spi.FactorProvider;

import java.util.Map;

/**
 * Context passed to factor verification, carrying factor-specific properties for the
 * {@link FactorProvider#verify(String, String, VerificationContext)} SPI.
 * <p>
 * <strong>Built-in providers:</strong> the built-in Tokido factor providers do not read
 * {@code properties}; all verification inputs come from the credential string and persisted
 * secrets. Pass {@link #empty()} unless you are using a custom {@link FactorProvider} that
 * documents supported keys.
 * <p>
 * This type exists so custom factors can accept structured verification-time inputs in a
 * forward-compatible way without changing the SPI signature.
 *
 * @param properties factor-specific key-value pairs
 */
public record VerificationContext(Map<String, Object> properties) {

    public static VerificationContext empty() {
        return new VerificationContext(Map.of());
    }
}
