package io.tokido.core.spi;

import io.tokido.core.StoredSecret;

import java.util.Map;

/**
 * Pluggable secret persistence.
 * <p>
 * The library never encrypts or decrypts secrets — that is the implementation's
 * responsibility. A production implementation might wrap secrets with KMS envelope
 * encryption, HashiCorp Vault, or a local keystore before persisting.
 * <p>
 * An in-memory implementation for testing is provided in {@code tokido-core-test}.
 */
public interface SecretStore {

    /**
     * Store a secret and its metadata for a user + factor combination.
     *
     * @param userId     the user identifier
     * @param factorType the factor type (e.g., "totp", "recovery")
     * @param secret     the raw secret bytes (may be empty for factors that don't use a shared secret)
     * @param metadata   factor-specific metadata to persist alongside the secret
     */
    void store(String userId, String factorType, byte[] secret, Map<String, Object> metadata);

    /**
     * Load a stored secret and its metadata.
     *
     * @return the stored secret, or null if not found
     */
    StoredSecret load(String userId, String factorType);

    /**
     * Merge updated metadata into an existing stored secret.
     * Only the provided keys are updated; existing keys not in the map are preserved.
     */
    void update(String userId, String factorType, Map<String, Object> metadata);

    /**
     * Delete a stored secret and all its metadata.
     */
    void delete(String userId, String factorType);

    /**
     * Check whether a secret exists for the given user + factor combination.
     */
    boolean exists(String userId, String factorType);
}
